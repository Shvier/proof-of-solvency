use ark_bls12_381::{Bls12_381, Fq, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{FftField, Field, PrimeField, QuadExtField};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, EvaluationDomain, Evaluations, Polynomial, Radix2EvaluationDomain};
use ark_poly_commit::{kzg10::{Commitment, Powers, Randomness, UniversalParams, VerifierKey, KZG10}, PCRandomness};
use ark_std::{rand::RngCore, test_rng, Zero, One};
use ark_test_curves::secp256k1;
use num_bigint::BigUint;

use std::{borrow::Borrow, collections::BTreeMap, fs::File, io::Read, mem::size_of, ops::Mul, sync::{Arc, Mutex}, thread, time::Instant};

use crate::{benchmark::{AffinePoint, AffineQuadExt, AffineQuadExtPoint, PoAProverJSON, SelectorPoly, TrustSetupParams}, types::{BlsScalarField, UniPoly_381}, utils::{average, batch_open, calculate_hash, convert_to_bigints, linear_combine_polys, skip_leading_zeros_and_convert_to_bigints, BatchCheckProof, HashBox}};

use super::sigma::{SigmaProtocol, SigmaProtocolProof};

#[cfg(test)]
mod test_prover;

#[derive(Clone)]
pub struct PolyCommitProof {
    pub witness: <Bls12_381 as Pairing>::G1Affine,
    rand: BlsScalarField,
    pub committed_eval: <Bls12_381 as Pairing>::G1Affine,
}

impl PolyCommitProof {
    pub fn deep_size() -> usize {
        size_of::<<Bls12_381 as Pairing>::G1Affine>() * 2
    }
}

pub struct AssetsProof {
    pub batch_check_proof: BatchCheckProof<Bls12_381>,
    pub committed_assets: <Bls12_381 as Pairing>::G1Affine,
    pub omega: BlsScalarField,
    pub domain_size: usize,
    pub randomness_bal_poly: Randomness<BlsScalarField, UniPoly_381>,
}

impl AssetsProof {
    pub fn deep_size(&self) -> usize {
        self.batch_check_proof.deep_size()
            + size_of::<<Bls12_381 as Pairing>::G1Affine>()
            + size_of::<Randomness<BlsScalarField, UniPoly_381>>()
    }
}

pub struct Prover<'a> {
    pub sigma: SigmaProtocol,
    pub omega: BlsScalarField,
    pub vk: VerifierKey<Bls12_381>,
    pub pp: UniversalParams<Bls12_381>,
    pub domain_size: usize,
    poly: DensePolynomial<<Bls12_381 as Pairing>::ScalarField>,
    selector: Vec<bool>,
    max_degree: usize,
    randomness: Option<Randomness<BlsScalarField, UniPoly_381>>,
    pub powers: Powers<'a, Bls12_381>,
}

impl Prover<'_> {
    pub fn setup(selector: &Vec<bool>) -> Self {
        let domain_size = selector.len().checked_next_power_of_two().expect("Unsupported domain size");
        let max_degree: usize = domain_size * 2;
        let omega = BlsScalarField::get_root_of_unity(domain_size.try_into().unwrap()).unwrap();
        let domain = Radix2EvaluationDomain::<BlsScalarField>::new(domain_size).unwrap();
        let evals = selector.into_iter().map(| s | Fr::from(*s)).collect();
        let evaluations = Evaluations::from_vec_and_domain(evals, domain);
        let poly = evaluations.interpolate();
        let rng = &mut test_rng();
        let pp = KZG10::<Bls12_381, UniPoly_381>::setup(max_degree, false, rng).unwrap();
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
        let sigma = SigmaProtocol::setup(secp256k1::G1Affine::generator(), vk.g, vk.gamma_g);
        Self {
            sigma,
            omega,
            vk,
            pp,
            domain_size,
            poly,
            selector: selector.to_vec(),
            max_degree,
            randomness: None,
            powers,
        }
    }

    pub fn serialize_to_json(&self) -> PoAProverJSON {
        let pp = self.pp.borrow();
        let powers_of_g: Vec<AffinePoint> = pp.powers_of_g.iter()
        .map(| g | {
            AffinePoint { x: g.x.to_string(), y: g.y.to_string() }
        })
        .collect();
        let powers_of_gamma_g: Vec<AffinePoint> = (0..=self.max_degree)
        .map(|i| {
            let point = pp.powers_of_gamma_g[&i];
            AffinePoint { x: point.x.to_string(), y: point.y.to_string() }
        })
        .collect();
        let h = AffineQuadExtPoint {
            x: AffineQuadExt {
                c0: pp.h.x.c0.to_string(),
                c1: pp.h.x.c1.to_string(),
            },
            y: AffineQuadExt {
                c0: pp.h.y.c0.to_string(),
                c1: pp.h.y.c1.to_string(),
            },
        };
        let beta_h = AffineQuadExtPoint {
            x: AffineQuadExt {
                c0: pp.beta_h.x.c0.to_string(),
                c1: pp.beta_h.x.c1.to_string(),
            },
            y: AffineQuadExt {
                c0: pp.beta_h.y.c0.to_string(),
                c1: pp.beta_h.y.c1.to_string(),
            },
        };
        let randomness = self.randomness.as_ref().unwrap().blinding_polynomial
            .coeffs
            .iter()
            .map(| c | {
                c.to_string()
            })
            .collect();
        PoAProverJSON {
            params: TrustSetupParams {
                powers_of_g,
                powers_of_gamma_g,
                h,
                beta_h,
            },
            selector: SelectorPoly {
                values: self.selector.clone(),
                coeffs: self.poly.coeffs.iter().map(| x | x.to_string()).collect(),
                randomness,
            },
        }
    }

    pub fn deserialize_from_json(file_path: &str) -> Self {
        use std::str::FromStr;

        let mut file = File::open(file_path).unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        let prover_json: PoAProverJSON = serde_json::from_str(&buffer).unwrap();
        let params_json = prover_json.params;
        let powers_of_g: Vec<_> = params_json.powers_of_g.iter()
            .map(| point | {
                let x = Fq::from_str(&point.x).unwrap();
                let y = Fq::from_str(&point.y).unwrap();
                <Bls12_381 as Pairing>::G1Affine::new_unchecked(x, y)
            })
            .collect();
        let powers_of_gamma_g: Vec<_> = params_json.powers_of_gamma_g.iter()
            .map(| point | {
                let x = Fq::from_str(&point.x).unwrap();
                let y = Fq::from_str(&point.y).unwrap();
                <Bls12_381 as Pairing>::G1Affine::new_unchecked(x, y).into_group()
            })
            .collect();
        let powers_of_gamma_g: BTreeMap::<usize, <Bls12_381 as Pairing>::G1Affine> = <Bls12_381 as Pairing>::G1::normalize_batch(&powers_of_gamma_g)
            .into_iter()
            .enumerate()
            .collect();
        let h = {
            let c0 = Fq::from_str(&params_json.h.x.c0).unwrap();
            let c1 = Fq::from_str(&params_json.h.x.c1).unwrap();
            let x = QuadExtField::new(c0, c1);
            let c0 = Fq::from_str(&params_json.h.y.c0).unwrap();
            let c1 = Fq::from_str(&params_json.h.y.c1).unwrap();
            let y = QuadExtField::new(c0, c1);
            <Bls12_381 as Pairing>::G2Affine::new_unchecked(x, y)
        };
        let beta_h = {
            let c0 = Fq::from_str(&params_json.beta_h.x.c0).unwrap();
            let c1 = Fq::from_str(&params_json.beta_h.x.c1).unwrap();
            let x = QuadExtField::new(c0, c1);
            let c0 = Fq::from_str(&params_json.beta_h.y.c0).unwrap();
            let c1 = Fq::from_str(&params_json.beta_h.y.c1).unwrap();
            let y = QuadExtField::new(c0, c1);
            <Bls12_381 as Pairing>::G2Affine::new_unchecked(x, y)
        };
        let pp: UniversalParams<Bls12_381> = UniversalParams {
            powers_of_g,
            powers_of_gamma_g,
            h,
            beta_h,
            neg_powers_of_h: BTreeMap::new(),
            prepared_h: h.into(),
            prepared_beta_h: beta_h.into(),
        };
        let vk = VerifierKey {
            g: pp.powers_of_g[0],
            gamma_g: pp.powers_of_gamma_g[&0],
            h: pp.h,
            beta_h: pp.beta_h,
            prepared_h: pp.prepared_h.clone(),
            prepared_beta_h: pp.prepared_beta_h.clone(),
        };
        let sigma = SigmaProtocol::setup(secp256k1::G1Affine::generator(), vk.g, vk.gamma_g);
        let coeffs: Vec<BlsScalarField> = prover_json.selector.coeffs.iter()
            .map(| c | {
                BlsScalarField::from_str(c).unwrap()
            })
            .collect();
        let poly = UniPoly_381::from_coefficients_vec(coeffs);
        let domain_size = prover_json.selector.values.len().checked_next_power_of_two().expect("Unsupported domain size");
        let omega = BlsScalarField::get_root_of_unity(domain_size.try_into().unwrap()).unwrap();
        let max_degree: usize = domain_size * 2;
        let coeffs: Vec<_> = prover_json.selector.randomness
            .iter()
            .map(| c | {
                BlsScalarField::from_str(c).unwrap()
            })
            .collect();
        let blinding_poly = UniPoly_381::from_coefficients_vec(coeffs);
        let mut randomness = Randomness::empty();
        randomness.blinding_polynomial = blinding_poly;
        let powers_of_g = pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };
        Self {
            sigma,
            omega,
            vk,
            pp,
            domain_size,
            poly,
            selector: prover_json.selector.values,
            max_degree,
            randomness: Some(randomness),
            powers,
        }
    }

    pub fn commit_to_selector(&mut self) -> (Commitment<Bls12_381>, Randomness<BlsScalarField, UniPoly_381>) {
        let powers = &self.powers;

        let rng = &mut test_rng();
        let (cm, rand) = KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &self.poly, Some(self.poly.degree()), Some(rng)).unwrap();
        self.randomness = Some(rand.clone());
        (cm, rand)
    }

    pub fn commit<R: RngCore>(&self, poly: &DensePolynomial<BlsScalarField>, rng: &mut R) -> (Commitment<Bls12_381>, Randomness<BlsScalarField, UniPoly_381>) {
        let max_degree = self.max_degree;
        let powers_of_g = self.pp.powers_of_g[..=max_degree].to_vec();
        let powers_of_gamma_g = (0..=max_degree)
            .map(|i| self.pp.powers_of_gamma_g[&i])
            .collect();
        let powers: Powers<Bls12_381> = Powers {
            powers_of_g: ark_std::borrow::Cow::Owned(powers_of_g),
            powers_of_gamma_g: ark_std::borrow::Cow::Owned(powers_of_gamma_g),
        };

        KZG10::<Bls12_381, UniPoly_381>::commit(&powers, &poly, Some(poly.degree()), Some(rng)).unwrap()
    }

    pub fn open_selector(&self, point: BlsScalarField, randomness: &Randomness<BlsScalarField, UniPoly_381>) -> PolyCommitProof {
        self.open(&self.poly, point, randomness)
    }

    pub fn open(&self, poly: &UniPoly_381, point: BlsScalarField, randomness: &Randomness<BlsScalarField, UniPoly_381>) -> PolyCommitProof {
        let powers = &self.powers;

        let (witness_polynomial, random) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(poly, point, randomness).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        let mut w = <Bls12_381 as Pairing>::G1::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        let blinding_p = &randomness.blinding_polynomial;
        let blinding_evaluation = blinding_p.evaluate(&point);

        let random_witness_coeffs = convert_to_bigints(&random.unwrap().coeffs());
        w += &<<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_gamma_g,
            &random_witness_coeffs,
        );

        let eval = poly.evaluate(&point);
        let committed_eval = self.sigma.gb.mul(eval) + self.sigma.hb.mul(blinding_evaluation);

        PolyCommitProof {
            witness: w.into_affine(),
            rand: blinding_evaluation,
            committed_eval: committed_eval.into_affine(),
        }
    }

    pub fn concurrent_open<'a>(
        powers: Arc<&'a Mutex<Powers<'a, Bls12_381>>>, 
        poly: &Arc<UniPoly_381>, 
        sigma: &Arc<Mutex<SigmaProtocol>>, 
        point: BlsScalarField, 
        randomness: &Arc<Randomness<BlsScalarField, UniPoly_381>>,
    ) -> PolyCommitProof {
        let (witness_polynomial, random) = KZG10::<Bls12_381, UniPoly_381>::compute_witness_polynomial(poly, point, randomness).unwrap();
        let (num_leading_zeros, witness_coeffs) = skip_leading_zeros_and_convert_to_bigints(&witness_polynomial);

        let powers = powers.lock().unwrap();
        let mut w = <Bls12_381 as Pairing>::G1::msm_bigint(
            &powers.powers_of_g[num_leading_zeros..],
            &witness_coeffs,
        );

        let blinding_p = &randomness.blinding_polynomial;
        let blinding_evaluation = blinding_p.evaluate(&point);

        let random_witness_coeffs = convert_to_bigints(&random.unwrap().coeffs());
        w += &<<Bls12_381 as Pairing>::G1 as VariableBaseMSM>::msm_bigint(
            &powers.powers_of_gamma_g,
            &random_witness_coeffs,
        );

        drop(powers);

        let eval = poly.evaluate(&point);
        let sigma = sigma.lock().unwrap();
        let committed_eval = sigma.gb.mul(eval) + sigma.hb.mul(blinding_evaluation);
        drop(sigma);

        PolyCommitProof {
            witness: w.into_affine(),
            rand: blinding_evaluation,
            committed_eval: committed_eval.into_affine(),
        }
    }

    pub fn generate_proof(&mut self, pks: &Vec<secp256k1::G1Affine>, sks: &Vec<BigUint>) -> Vec<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof, usize)> {
        let (cm, randomness) = self.commit_to_selector();
        let omega = &self.omega;
        let selector = &self.selector;
        let mut proofs = Vec::<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof, usize)>::new();
        let mut times = Vec::<u128>::new();
        for i in 0..selector.len() {
            let now = Instant::now();
            println!("Generate proof {}", i);
            let s = selector[i];
            let pk = pks[i];
            let sk = &sks[i];
            let point = omega.pow(&[i as u64]);
            let pc_proof = self.open(&self.poly, point, &randomness);
            let sigma_proof = self.sigma.generate_proof(pk, pc_proof.rand.into_bigint().into(), s, sk.clone());
            let elapsed = now.elapsed().as_micros();
            println!("Proof {} is generated: {}", i, elapsed);
            times.push(elapsed);
            proofs.push((cm, pc_proof, sigma_proof, i))
        }
        println!("average time: {}", average(&times));
        proofs
    }

    pub fn concurrent_generate_proof(&mut self, pks: &Vec<secp256k1::G1Affine>, sks: &Vec<BigUint>) -> Vec<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof, usize)> {
        let (cm, randomness) = self.commit_to_selector();
        let omega = self.omega.clone();
        let selector = self.selector.clone();
        let proofs = Arc::new(Mutex::new(Vec::<(Commitment<Bls12_381>, PolyCommitProof, SigmaProtocolProof, usize)>::new()));

        let now = Instant::now();
        println!("Start generating the sigma proofs");

        let sigma = Arc::new(Mutex::new(self.sigma.clone()));
        let poly = Arc::new(self.poly.clone());
        let randomness = Arc::new(randomness);

        let binding = Mutex::new(self.powers.clone());
        let powers = Arc::new(&binding);

        thread::scope(| s | {
            for i in 0..selector.len() {
                let sel = selector[i];
                let pk = pks[i];
                let sk = &sks[i];
                
                let sigma = sigma.clone();
                let poly = poly.clone();
                let randomness = randomness.clone();
                let proofs = proofs.clone();
                let powers = powers.clone();

                s.spawn(move || {
                    let point = omega.pow(&[i as u64]);
                    let pc_proof = Prover::concurrent_open(powers, &poly, &sigma, point, &randomness);
                    let sigma_proof = sigma.lock().unwrap().generate_proof(pk, pc_proof.rand.into_bigint().into(), sel, sk.clone());
                    proofs.lock().unwrap().push((cm, pc_proof, sigma_proof, i));
                    println!("Sigma proof {} is generated", i);
                });
            }
        });
        let elapsed = now.elapsed();
        println!("The sigma proofs are generated: {:.2?}", elapsed);
        let proofs = proofs.lock().unwrap()
            .iter()
            .map(| proof | { 
                (proof.0, proof.1.clone(), proof.2.clone(), proof.3)
             })
            .collect();
        proofs
    }

    pub fn construct_accumulator(&self, bal_poly: &DensePolynomial<BlsScalarField>, domain: Radix2EvaluationDomain<BlsScalarField>) -> UniPoly_381 {
        let bal_poly_degree = &bal_poly.degree();
        let degree = self.poly.degree();
        assert_eq!(*bal_poly_degree, degree);
        let balances = bal_poly.clone().evaluate_over_domain(domain).evals;
        let mut accum_evals = vec![BlsScalarField::zero(); self.selector.len()];
        let upper_bound = self.selector.len() - 1;
        accum_evals[upper_bound] = match self.selector[upper_bound] {
            true => balances[upper_bound],
            false => BlsScalarField::zero(),
        };
        for i in (0..upper_bound).rev() {
            let s = self.selector[i];
            let bal = balances[i];
            match s {
                true => {
                    accum_evals[i] = accum_evals[i + 1] + bal
                }
                false => {
                    accum_evals[i] = accum_evals[i + 1]
                }
            }
        }

        Evaluations::from_vec_and_domain(accum_evals, domain).interpolate()
    }

    pub fn compute_w1_w2(&self, accum_poly: &UniPoly_381, bal_poly: &UniPoly_381, domain: Radix2EvaluationDomain<BlsScalarField>) -> (UniPoly_381, UniPoly_381) {
        let mut accum_evals = accum_poly.clone().evaluate_over_domain(domain).evals;
        accum_evals.rotate_left(1);
        let accum_plus_one = Evaluations::from_vec_and_domain(accum_evals, domain).interpolate();
        let selector_times_bal = &self.poly * bal_poly;

        let mut w_1 = accum_poly - &accum_plus_one;
        w_1 -= &selector_times_bal;
        let last = self.omega.pow(&[(self.domain_size - 1) as u64]);
        let x_minus_last_omega = DensePolynomial::<BlsScalarField>::from_coefficients_vec(vec![-last, BlsScalarField::one()]);
        w_1 = &w_1 * &x_minus_last_omega;

        let mut w_2 = accum_poly - &selector_times_bal;
        let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());
        let (quotient, remainder) = zed.divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_last_omega)).unwrap();
        assert!(remainder.is_zero());
        w_2 = &w_2 * &quotient;

        (w_1, w_2)
    }

    // return Randomness only for DEBUG to verify the correctness of assets
    pub fn prove_accumulator(&self, bal_poly: &DensePolynomial<BlsScalarField>, gamma: BlsScalarField, cm_selector: &Commitment<Bls12_381>) -> (AssetsProof, Randomness<BlsScalarField, UniPoly_381>) {
        let domain = Radix2EvaluationDomain::<BlsScalarField>::new(self.selector.len()).unwrap();
        let accum_poly = self.construct_accumulator(bal_poly, domain);
        let rng = &mut test_rng();
        let (cm_accum, random_accum) = self.commit(&accum_poly, rng);
        let (cm_bal, random_bal) = self.commit(&bal_poly, rng);
        let random_selector = self.randomness.as_ref().unwrap();

        let (w_1, w_2) = self.compute_w1_w2(&accum_poly, bal_poly, domain);
        let w = linear_combine_polys::<Bls12_381>(&vec![w_1, w_2], gamma);

        let zed = DenseOrSparsePolynomial::from(domain.vanishing_polynomial());
        let (quotient, remainder) = DenseOrSparsePolynomial::from(w).divide_with_q_and_r(&zed).unwrap();
        assert!(remainder.is_zero());
        let (cm_q, random_q) = self.commit(&quotient, rng);

        let challenge = calculate_hash(&vec![
            HashBox::Bls(cm_accum.0.into_group()), 
            HashBox::Bls(cm_bal.0.into_group()),
            HashBox::Bls(cm_selector.0.into_group()),
            HashBox::Bls(cm_q.0.into_group()),
        ]);
        let challenge_point = BlsScalarField::from(challenge);

        let powers = self.powers.clone();
        let (h_1, open_evals_1, gamma_1) = batch_open(
            &powers, 
            &vec![&accum_poly, bal_poly, &self.poly, &quotient], 
            &vec![&random_accum, &random_bal, &random_selector, &random_q], 
            challenge_point, 
            false, 
            rng
        );

        let (h_2, open_evals_2, gamma_2) = batch_open(
            &powers, 
            &vec![&accum_poly], 
            &vec![&random_accum], 
            challenge_point * self.omega, 
            false, 
            rng
        );
        let (h_3, open_evals_3, gamma_3) = batch_open(
            &powers, 
            &vec![&accum_poly], 
            &vec![&random_accum], 
            BlsScalarField::one(), 
            true, 
            rng
        );
        (AssetsProof {
            batch_check_proof: BatchCheckProof { 
                commitments: vec![
                    vec![cm_accum, cm_bal, *cm_selector, cm_q],
                    vec![cm_accum],
                    vec![cm_accum],
                ], 
                witnesses: vec![
                    h_1,
                    h_2,
                    h_3,
                ], 
                points: vec![
                    challenge_point,
                    challenge_point * self.omega,
                    BlsScalarField::one(),
                ], 
                open_evals: vec![
                    open_evals_1,
                    open_evals_2,
                    open_evals_3.clone(),
                ], 
                gammas: vec![
                    gamma_1,
                    gamma_2,
                    gamma_3,
                ],
            },
            committed_assets: open_evals_3[0].borrow().into_committed_value(),
            omega: self.omega,
            domain_size: self.domain_size,
            randomness_bal_poly: random_bal,
        },
        random_accum)
    }

    pub fn prove_balance_poly(
        &self, 
        bal_poly: &DensePolynomial<BlsScalarField>, 
        randomness: &Randomness<BlsScalarField, UniPoly_381>, 
        num_of_keys: usize
    ) -> Vec<PolyCommitProof> {
        let proofs: Vec<PolyCommitProof> = (0..num_of_keys).into_iter()
            .map(| i | {
                let point = self.omega.pow(&[i as u64]);
                self.open(bal_poly, point, randomness)
            })
            .collect();
        proofs
    }
}
