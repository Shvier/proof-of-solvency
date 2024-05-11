use std::{fs::{self, File}, io::{BufWriter, Read, Write}, mem::size_of, str::FromStr, time::Instant};

use ark_bls12_381::{Bls12_381, G1Affine};
use ark_poly_commit::kzg10::Commitment;
use ark_std::{rand::Rng, test_rng, UniformRand};
use ark_test_curves::secp256k1::{self, Fq};
use num_bigint::BigUint;

use crate::{benchmark::{AffinePoint, KeyPair, PoAPrecompute, PoAReport}, proof_of_assets::{prover::{PolyCommitProof, Prover}, sigma::SigmaProtocolProof, verifier::Verifier}, types::BlsScalarField, utils::read_balances};

pub fn run_poa(bal_path: &str, num_of_keys: usize) {
    let prover = precompute_poa(num_of_keys);
    post_precompute(&prover, bal_path, num_of_keys);
}

pub fn post_precompute(prover: &Prover, bal_path: &str, num_of_keys: usize) {
    let rng = &mut test_rng();

    let balances = read_balances(&bal_path);
    let balances: Vec<_> = balances[0..num_of_keys].to_vec()
        .iter()
        .map(| b | {
            BlsScalarField::from(*b)
        })
        .collect();
    let now = Instant::now();
    let bal_poly = Verifier::generate_balance_poly(&balances);
    let interpolate_cost = now.elapsed();
    println!("interpolate balances: {:.2?}", interpolate_cost);

    let mut file = File::open(format!("./bench_data/proof_of_assets/{}keys/selector_commitment.json", num_of_keys)).unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    let comm_str: AffinePoint = serde_json::from_str(&buffer).unwrap();
    let cm_selector = {
        let x = ark_bls12_381::Fq::from_str(&comm_str.x).unwrap();
        let y = ark_bls12_381::Fq::from_str(&comm_str.y).unwrap();
        Commitment {
            0: G1Affine::new_unchecked(x, y)
        }
    };

    let gamma = BlsScalarField::rand(rng);

    let now = Instant::now();
    let (assets_proof, _) = prover.prove_accumulator(&bal_poly, gamma, &cm_selector);
    let prove_accumulator = now.elapsed();
    println!("prove accumulator: {:.2?}", prove_accumulator);

    let now = Instant::now();
    Verifier::validate_assets_proof(&prover.vk, &assets_proof, gamma, rng);
    let verify_cost = now.elapsed();
    println!("verifying proof time: {:.2?}", verify_cost);

    let cm_bal = &assets_proof.batch_check_proof.commitments[0][1];

    let now = Instant::now();
    Verifier::validate_balance_poly(&prover.powers, cm_bal, &bal_poly, &assets_proof.randomness_bal_poly);
    let validating_bal_cost = now.elapsed();
    println!("validate balances time: {:.2?}", validating_bal_cost);

    let setup = PoAReport {
        interpolate_balance_time: interpolate_cost.as_micros(),
        accumulator_proving_time: prove_accumulator.as_micros(),
        verifying_proof_time: verify_cost.as_micros(),
        validating_balance_time: validating_bal_cost.as_micros(),
        proof_size: assets_proof.deep_size() / 1000,
    };
    let dir = format!("./bench_data/proof_of_assets/{}keys/protocol", num_of_keys);
    let _ = fs::create_dir_all(dir.clone());
    let json_path = dir.clone() + &format!("/{}.json", chrono::offset::Local::now()).replace(":", "-");
    let file = File::create(json_path).unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &setup).unwrap();
    writer.flush().unwrap();
}

pub fn precompute_poa(num_of_keys: usize) -> Prover<'static> {
    let (pks, sks) = read_key_pairs();
    let rng = &mut test_rng();
    let selector: Vec<bool> = (0..num_of_keys).into_iter().map(| _ | {
        let rand = rng.gen_range(0..=1);
        rand == 1
    })
    .collect();

    let now = Instant::now();
    let mut prover = Prover::setup(&selector);
    let setup_cost = now.elapsed();
    println!("interpolate selector: {:.2?}", setup_cost);
    let now = Instant::now();
    let proofs = prover.generate_proof(&pks, &sks);
    let setup_prove_cost = now.elapsed();
    println!("proving time: {:.2?}", setup_prove_cost);
    let vk = &prover.vk;
    let omega = prover.omega;
    let now = Instant::now();
    Verifier::batch_check(
        vk, 
        &proofs,
        pks, 
        omega,
    );

    let setup_verify_cost = now.elapsed();
    println!("verifying time: {:.2?}", setup_verify_cost);
    let proof_size = (size_of::<Commitment<Bls12_381>>()
                                + PolyCommitProof::deep_size() 
                                + SigmaProtocolProof::deep_size() 
                                + size_of::<usize>())
                                * proofs.len();
    let setup = PoAPrecompute {
        interpolate_selector: setup_cost.as_micros(),
        proving_time: setup_prove_cost.as_micros(),
        verifying_time: setup_verify_cost.as_micros(),
        proof_size: proof_size / 1000,
    };
    let dir = format!("./bench_data/proof_of_assets/{}keys", num_of_keys);
    let precompute_dir = dir.clone() + "/precompute";
    let _ = fs::create_dir_all(precompute_dir.clone());
    let json_path = precompute_dir.clone() + &format!("/{}.json", chrono::offset::Local::now()).replace(":", "-");
    let file = File::create(json_path).unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &setup).unwrap();
    writer.flush().unwrap();

    let comm: AffinePoint = {
        let proof = proofs[0].0;
        AffinePoint { x: proof.0.x.to_string(), y: proof.0.y.to_string() }
    };
    let json_path = dir.clone() + "/selector_commitment.json";
    let file = File::create(json_path).unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &comm).unwrap();
    writer.flush().unwrap();

    let prover_json = prover.serialize_to_json();
    let json_path = dir.clone() + "/prover.json";
    let file = File::create(json_path).unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &prover_json).unwrap();
    writer.flush().unwrap();
    prover
}

fn read_key_pairs() -> (Vec<secp256k1::G1Affine>, Vec<BigUint>) {
    let mut file = File::open("./bench_data/proof_of_assets/key_pairs.json").unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    let key_pairs: Vec<KeyPair> = serde_json::from_str(&buffer).unwrap();
    let mut pks = Vec::<secp256k1::G1Affine>::new();
    let mut sks = Vec::<BigUint>::new();
    for key_pair in key_pairs {
        let x = Fq::from_str(&key_pair.pk.x).unwrap();
        let y = Fq::from_str(&key_pair.pk.y).unwrap();
        let pk = secp256k1::G1Affine::new_unchecked(x, y);
        let sk = BigUint::from_str(&key_pair.sk).unwrap();
        // let generator = secp256k1::G1Affine::generator();
        // assert_eq!(generator.mul_bigint(sk.to_u64_digits()).into_affine(), pk);
        pks.push(pk);
        sks.push(sk);
    }
    (pks, sks)
}
