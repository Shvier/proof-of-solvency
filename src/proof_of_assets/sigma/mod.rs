use std::fmt;

use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::{pairing::Pairing, short_weierstrass::Projective, AffineRepr, CurveGroup};
use ark_test_curves::secp256k1;
use ark_std::{test_rng, UniformRand};
use ark_ff::PrimeField;

use num_bigint::BigUint;

use crate::utils::{calculate_hash, HashBox};

#[cfg(test)]
mod test_sigma;

pub struct SigmaProtocolProof {
    t1: secp256k1::G1Projective,
    t2: Projective<ark_bls12_381::g1::Config>,
    t3: Projective<ark_bls12_381::g1::Config>,
    e1: BigUint,
    e2: BigUint,
    e: BigUint,
    z1: BigUint,
    z2: BigUint,
    z3: BigUint,
}

impl fmt::Display for SigmaProtocolProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t1: {}, t2: {}, t3: {}, e1: {}, e2: {}, e: {}, z1: {}, z2: {}, z3: {})", self.t1, self.t2, self.t3, self.e1, self.e2, self.e, self.z1, self.z2, self.z3)
    }
}

pub struct SigmaProtocol {
    gs: secp256k1::G1Affine,
    gb: <Bls12_381 as Pairing>::G1Affine,
    hb: <Bls12_381 as Pairing>::G1Affine,
}

impl SigmaProtocol {
    pub fn setup(
        gs: secp256k1::G1Affine,
        gb: <Bls12_381 as Pairing>::G1Affine,
        hb: <Bls12_381 as Pairing>::G1Affine,
    ) -> Self {
        Self {
            gs,
            gb,
            hb,
        }
    }

    pub fn generate_proof(
        &self,
        y: secp256k1::G1Affine,
        r: BigUint,
        s: bool,
        x: BigUint,
    ) -> SigmaProtocolProof {
        let t1: secp256k1::G1Projective;
        let t2: Projective<ark_bls12_381::g1::Config>;
        let t3: Projective<ark_bls12_381::g1::Config>;
        let e1: BigUint;
        let e2: BigUint;
        let e: BigUint;
        let z1: BigUint;
        let z2: BigUint;
        let z3: BigUint;

        let rng = &mut test_rng();
        match s {
            false => {
                e1 = secp256k1::Fr::rand(rng).into_bigint().into();
                z1 = secp256k1::Fr::rand(rng).into_bigint().into();
                t1 = (self.gs.mul_bigint(z1.to_u64_digits())) - y.mul_bigint(&e1.to_u64_digits());
                z2 = Fr::rand(rng).into_bigint().into();
                let r_times_e1 = &r * &e1;
                if z2 >= r_times_e1 {
                    let t2_hiding = &z2 - &r * &e1;
                    t2 = self.gb.mul_bigint(&e1.to_u64_digits()) + (self.hb.mul_bigint(t2_hiding.to_u64_digits()));
                } else {
                    let t2_hiding = &r * &e1 - &z2;
                    t2 = self.gb.mul_bigint(&e1.to_u64_digits()) - (self.hb.mul_bigint(t2_hiding.to_u64_digits()));
                }
                let alpha: BigUint = Fr::rand(rng).into_bigint().into();
                t3 = self.hb.mul_bigint(alpha.to_u64_digits());
                e = calculate_hash(&vec![HashBox::Secp(t1), HashBox::Bls(t2), HashBox::Bls(t3)]);
                e2 = &e ^ &e1;
                z3 = &e2 * &r + alpha;
            },
            true => {
                e2 = Fr::rand(rng).into_bigint().into();
                z3 = Fr::rand(rng).into_bigint().into();
                let alpha: BigUint = secp256k1::Fr::rand(rng).into_bigint().into();
                let beta: BigUint = Fr::rand(rng).into_bigint().into();
                t1 = self.gs.mul_bigint(alpha.to_u64_digits());
                t2 = self.hb.mul_bigint(beta.to_u64_digits());
                let r_times_e2 = &r *&e2;
                if z3 >= r_times_e2 {
                    let t3_hiding = &z3 - &r *&e2;
                    t3 = self.hb.mul_bigint(t3_hiding.to_u64_digits()) - self.gb.mul_bigint(&e2.to_u64_digits());
                } else {
                    let t3_hiding = &r *&e2 - &z3;
                    t3 = - self.hb.mul_bigint(t3_hiding.to_u64_digits()) - self.gb.mul_bigint(&e2.to_u64_digits());
                }
                e = calculate_hash(&vec![HashBox::Secp(t1), HashBox::Bls(t2), HashBox::Bls(t3)]);
                e1 = &e ^ &e2;
                z1 = &e1 * &x + alpha;
                z2 = &e1 * &r + beta;
            },
        }
        SigmaProtocolProof {
            t1, t2, t3, e1, e2, e, z1, z2, z3,
        }
    }

    pub fn validate(
        &self, 
        proof: SigmaProtocolProof,
        y: secp256k1::G1Affine,
        p: <Bls12_381 as Pairing>::G1Affine,
    ) {
        let SigmaProtocolProof { t1, t2, t3, e1, e2, e, z1, z2, z3 } = proof;
        assert_eq!(e, calculate_hash(&vec![HashBox::Secp(t1), HashBox::Bls(t2), HashBox::Bls(t3)]));
        let e1_xor_e2 = &e1 ^ &e2;
        assert_eq!(e, e1_xor_e2);
        let lhs = self.gs.mul_bigint(z1.to_u64_digits());
        let rhs = y.mul_bigint(e1.to_u64_digits()) + t1;
        assert_eq!(lhs, rhs);
        let lhs = self.gb.mul_bigint(e1.to_u64_digits()) + self.hb.mul_bigint(z2.to_u64_digits());
        let rhs = p.mul_bigint(e1.to_u64_digits()) + t2;
        assert_eq!(lhs, rhs);
        let lhs = self.hb.mul_bigint(z3.to_u64_digits());
        let rhs = p.mul_bigint(e2.to_u64_digits()) + t3;
        assert_eq!(lhs, rhs);
    }
}
