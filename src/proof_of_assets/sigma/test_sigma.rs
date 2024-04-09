use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_test_curves::secp256k1;
use ark_std::{rand::Rng, test_rng, UniformRand};
use ark_ff::{One, PrimeField, Zero};

use num_bigint::{RandomBits, BigUint};

use crate::{proof_of_assets::sigma::SigmaProtocol, utils::pedersen_commit};

fn hex_string_to_binary_vector(hex_str: &str) -> Vec<u8> {
    use hex::FromHex;
    // Remove the "0x" prefix if present
    let clean_hex_str = if hex_str.starts_with("0x") {
        &hex_str[2..]
    } else {
        hex_str
    };

    // Parse the hexadecimal string into a Vec<u8>
    let hex_bytes = Vec::from_hex(clean_hex_str).expect("Invalid hexadecimal string");
    hex_bytes
}

#[test]
fn test_sigma_fixed_proof() {
    /* validate the generator
    Public key: 0xaa931f5ee58735270821b3722866d8882d1948909532cf8ac2b3ef144ae80433
    63d1d3728b49f10c7cd78c38289c8012477473879f3b53169f2a677b7fbed0c7
    Private key: 
    0x227dbb8586117d55284e26620bc76534dfbd2394be34cf4a09cb775d593b6f2b
     */
    const SK: &str = "0x227dbb8586117d55284e26620bc76534dfbd2394be34cf4a09cb775d593b6f2b";
    let sk_hex = hex_string_to_binary_vector(SK);
    let private_key = BigUint::from_bytes_be(&sk_hex);
    println!("private key: {}", private_key);
    let public_key = secp256k1::G1Affine::generator().mul_bigint(private_key.to_u64_digits());
    println!("public key: {}", public_key);

    let secp_g = secp256k1::G1Affine::generator();
    let h_power: BigUint = BigUint::from(32u32);
    let bls_g = <Bls12_381 as Pairing>::G1Affine::generator();
    let bls_h = bls_g.mul_bigint(h_power.to_u64_digits()).into_affine();

    let sigma = SigmaProtocol::setup(secp_g, bls_g, bls_h);

    let rng = &mut test_rng();

    let r: BigUint = Fr::rand(rng).into_bigint().into();
    let p = pedersen_commit::<<Bls12_381 as Pairing>::G1Affine>(sigma.gb, sigma.hb, BigUint::zero().to_u64_digits(), &r.to_u64_digits());

    let proof = sigma.generate_proof(public_key.into_affine(), r.clone(), false, BigUint::zero());
    SigmaProtocol::validate(sigma.gs, sigma.gb, sigma.hb, proof, public_key.into_affine(), p.into_affine());

    let p = pedersen_commit::<<Bls12_381 as Pairing>::G1Affine>(sigma.gb, sigma.hb, BigUint::one().to_u64_digits(), &r.to_u64_digits());

    let proof = sigma.generate_proof(public_key.into_affine(), r.clone(), true, private_key);
    SigmaProtocol::validate(sigma.gs, sigma.gb, sigma.hb, proof, public_key.into_affine(), p.into_affine());
}

#[test]
fn test_sigma_random_proof() {
    let secp_g = secp256k1::G1Affine::generator();
    let h_power: BigUint = BigUint::from(32u32);
    let bls_g = <Bls12_381 as Pairing>::G1Affine::generator();
    let bls_h = bls_g.mul_bigint(h_power.to_u64_digits()).into_affine();

    let sigma = SigmaProtocol::setup(secp_g, bls_g, bls_h);

    let rng = &mut test_rng();

    for i in 0..1000 {
        let private_key: BigUint = rng.sample(RandomBits::new(256u64));
        let public_key = sigma.gs.mul_bigint(private_key.to_u64_digits());

        let r: BigUint = Fr::rand(rng).into_bigint().into();
        let p = pedersen_commit::<<Bls12_381 as Pairing>::G1Affine>(sigma.gb, sigma.hb, BigUint::zero().to_u64_digits(), &r.to_u64_digits());

        println!("Job {} - Generate fake proof", i);
        let proof = sigma.generate_proof(public_key.into_affine(), r.clone(), false, BigUint::zero());
        println!("        - Fake proof generated");
        SigmaProtocol::validate(sigma.gs, sigma.gb, sigma.hb, proof, public_key.into_affine(), p.into_affine());
        println!("        - Fake proof validated");

        let p = pedersen_commit::<<Bls12_381 as Pairing>::G1Affine>(sigma.gb, sigma.hb, BigUint::one().to_u64_digits(), &r.to_u64_digits());

        println!("        - Generate real proof");
        let proof = sigma.generate_proof(public_key.into_affine(), r.clone(), true, private_key);
        println!("        - Real proof generated");
        SigmaProtocol::validate(sigma.gs, sigma.gb, sigma.hb, proof, public_key.into_affine(), p.into_affine());
        println!("        - Real proof validated");
    }
}
