use std::{mem::size_of, sync::{Arc, Mutex}, time::Instant};

use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_bls12_381::Bls12_381;
use ark_poly_commit::{kzg10::{Commitment, Powers, Randomness, UniversalParams, VerifierKey, KZG10}, PCRandomness};
use ark_std::{rand::RngCore, test_rng, One};
use crossbeam::{channel::bounded, thread};

use crate::{types::{BlsScalarField, UniPoly_381}, utils::{batch_open, OpenEval}};

use self::intermediate::{Intermediate, IntermediateProof};

#[cfg(test)]
mod test_intermediate;

#[cfg(test)]
mod test_prover;

pub mod intermediate;

#[derive(Clone)]
pub struct LiabilityProof {
    pub witness_sigma_p0: <Bls12_381 as Pairing>::G1,
    pub sigma_p0_eval: OpenEval<Bls12_381>,
    pub intermediate_proofs: Vec<IntermediateProof<Bls12_381>>,
}

impl LiabilityProof {
    pub fn deep_size(&self) -> usize {
        let size_of_proofs: usize = self.intermediate_proofs.iter().map(| child | child.deep_size()).sum();
        size_of::<<Bls12_381 as Pairing>::G1>() + 
        size_of::<OpenEval<Bls12_381>>() +
        size_of_proofs
    }
}

pub struct Prover<'a> {
    pub vk: VerifierKey<Bls12_381>,
    pub pp: UniversalParams<Bls12_381>,
    pub powers: Powers<'a, Bls12_381>,
    balances: Vec<Vec<u64>>,
    // group_size: usize,
}

impl Prover<'_> {
    pub fn setup(
        balances: &Vec<u64>,
        group_size: usize,
        max_degree: usize,
    ) -> Self {
        assert!(group_size < max_degree);
        let rng = &mut test_rng();
        let pp = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, true, rng).expect("KZG setup failed");
        let powers_of_g = pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };

        let balances = balances.chunks(group_size).map(| bal | bal.into()).collect();
        Self {
            vk,
            pp,
            powers,
            balances,
            // group_size,
        }
    }

    pub fn run<R: RngCore>(
        &self, max_bits: usize, gamma: BlsScalarField, rng: &mut R
    ) -> (Vec<Intermediate<Bls12_381>>, Vec<Vec<Commitment<Bls12_381>>>, Vec<Vec<Randomness<BlsScalarField, UniPoly_381>>>) {
        let now = Instant::now();
        println!("Start building the intermediate polynomials");
        let mut inters = Vec::<Intermediate<Bls12_381>>::new();
        let mut comms = Vec::<Vec<Commitment<Bls12_381>>>::new();
        let mut rands = Vec::<Vec<Randomness<BlsScalarField, DensePolynomial<BlsScalarField>>>>::new();
        for bals in self.balances.as_slice() {
            let inter = Intermediate::<Bls12_381>::new(bals, max_bits, gamma, rng);
            let (cms, randoms) = inter.compute_commitments(&self.powers, rng);
            inters.push(inter);
            comms.push(cms);
            rands.push(randoms);
        }
        let elapsed = now.elapsed();
        println!("The intermediate polynomials are built: {:.2?}", elapsed);
        (inters, comms, rands)
    }

    pub fn concurrent_run(
        &self, max_bits: usize, gamma: BlsScalarField
    ) -> (Vec<Intermediate<Bls12_381>>, Vec<Vec<Commitment<Bls12_381>>>, Vec<Vec<Randomness<BlsScalarField, UniPoly_381>>>) {
        let now = Instant::now();
        println!("Start building the intermediate polynomials");
        
        let bound = self.balances.len();
        let (tx, rx) = bounded(bound);
        let binding = Mutex::new(self.powers.clone());
        let powers = Arc::new(&binding);

        thread::scope(| s | {
            let mut i = 0;
            for bals in self.balances.as_slice() {
                let tx_clone = tx.clone();
                let powers = powers.clone();
                s.spawn(move | _ | {
                    let rng = &mut test_rng();
                    let inter = Intermediate::<Bls12_381>::new(bals, max_bits, gamma, rng);
                    let commitments = Intermediate::<Bls12_381>::concurrent_compute_commitments(&inter.polys, &inter.q_w, powers);
                    tx_clone.send((i, inter, commitments)).unwrap();
                });
                i += 1;
            }
        })
        .unwrap();

        drop(tx);

        let mut inters_and_comms = vec![None; bound];
        for (i, inter, commitments) in rx {
            inters_and_comms[i] = Some((inter, commitments));
        }
        let inters_and_comms: Vec<_> = inters_and_comms.into_iter().map(|x| x.unwrap()).collect();

        let elapsed = now.elapsed();
        println!("The intermediate polynomials are built: {:.2?}", elapsed);

        let mut inters = Vec::<Intermediate<Bls12_381>>::new();
        let mut comms = Vec::<Vec<Commitment<Bls12_381>>>::new();
        let mut rands = Vec::<Vec<Randomness<BlsScalarField, DensePolynomial<BlsScalarField>>>>::new();
        for (inter, commitment) in inters_and_comms {
            inters.push(inter);
            let mut cms = Vec::<Commitment<Bls12_381>>::new();
            let mut randoms = Vec::<Randomness<BlsScalarField, UniPoly_381>>::new();
            for (comm, rand) in commitment {
                cms.push(comm);
                randoms.push(rand);
            }
            comms.push(cms);
            rands.push(randoms);
        }

        (inters, comms, rands)
    }

    // return Randomness only for DEBUG to verify the correctness of liability
    pub fn generate_proof<R: RngCore>(
        &self,
        inters: &Vec<Intermediate<Bls12_381>>,
        comms: &Vec<Vec<Commitment<Bls12_381>>>,
        rands: &Vec<Vec<Randomness<BlsScalarField, DensePolynomial<BlsScalarField>>>>,
        taus: &Vec<BlsScalarField>,
        rng: &mut R,
    ) -> (LiabilityProof, Randomness<BlsScalarField, UniPoly_381>) {
        let now = Instant::now();
        println!("Start generating the liability proof");
        let mut sigma_p0 = DensePolynomial::zero();
        let mut rand_sigma_p0 = Randomness::<BlsScalarField, DensePolynomial<BlsScalarField>>::empty();
        
        let mut proofs = Vec::<IntermediateProof<Bls12_381>>::new();
        let mut i = 0usize;
        for inter in inters {
            let cms = &comms[i];
            let randoms = &rands[i];
            let tau = taus[i];
            let proof = inter.generate_proof(&self.powers, cms, randoms, tau, rng);
            proofs.push(proof);
            sigma_p0 = &sigma_p0 + &inter.polys[0];
            rand_sigma_p0 = rand_sigma_p0 + &randoms[0];

            i += 1;
        }

        let (h_sigma_p0, sigma_p0_eval, _) = batch_open(&self.powers, &vec![sigma_p0], &vec![rand_sigma_p0.clone()], BlsScalarField::one(), true, rng);
        
        let elapsed = now.elapsed();
        println!("Liability proof is generated: {:.2?}", elapsed);

        (LiabilityProof {
            witness_sigma_p0: h_sigma_p0,
            sigma_p0_eval: sigma_p0_eval[0].clone(),
            intermediate_proofs: proofs,
        },
        rand_sigma_p0.clone())
    }

    pub fn concurrent_generate_proof(
        &self,
        inters: &Vec<Intermediate<Bls12_381>>,
        comms: &Vec<Vec<Commitment<Bls12_381>>>,
        rands: &Vec<Vec<Randomness<BlsScalarField, DensePolynomial<BlsScalarField>>>>,
        taus: &Vec<BlsScalarField>,
    ) -> (LiabilityProof, Randomness<BlsScalarField, UniPoly_381>) {
        let now = Instant::now();
        println!("Start generating the liability proof");

        let mut sigma_p0 = UniPoly_381::zero();
        let mut rand_sigma_p0 = Randomness::<BlsScalarField, DensePolynomial<BlsScalarField>>::empty();
        for (inter, randoms) in inters.into_iter().zip(rands) {
            sigma_p0 = &sigma_p0 + &inter.polys[0];
            rand_sigma_p0 = rand_sigma_p0 + &randoms[0];
        }

        let bound = inters.len();
        let (tx, rx) = bounded(bound);

        thread::scope(| s | {
            let mut i = 0usize;
            for inter in inters {
                let cms = &comms[i];
                let randoms = &rands[i];
                let tau = taus[i];
                let tx_clone = tx.clone();
                s.spawn(move | _ | {
                    let rng = &mut test_rng();
                    let proof = inter.generate_proof(&self.powers, cms, randoms, tau, rng);
                    tx_clone.send((i, proof)).unwrap();
                });
                i += 1;
            }
        })
        .unwrap();

        drop(tx);

        let mut proofs = vec![None; bound];
        for (i, proof) in rx {
            proofs[i] = Some(proof);
        }
        let proofs: Vec<_> = proofs.into_iter().map(|x| x.unwrap()).collect();

        let rng = &mut test_rng();
        let (h_sigma_p0, sigma_p0_eval, _) = batch_open(&self.powers, &vec![sigma_p0], &vec![rand_sigma_p0.clone()], BlsScalarField::one(), true, rng);
        
        let elapsed = now.elapsed();
        println!("Liability proof is generated: {:.2?}", elapsed);

        (
            LiabilityProof {
                witness_sigma_p0: h_sigma_p0,
                sigma_p0_eval: sigma_p0_eval[0].clone(),
                intermediate_proofs: proofs,
            },
            rand_sigma_p0.clone()
        )
    }
}
