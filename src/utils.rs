use ark_ec::AffineRepr;
use ark_test_curves::{bls12_381, secp256k1};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

pub enum HashBox {
    Secp(secp256k1::G1Projective),
    Bls(bls12_381::G1Projective),
}

pub fn calculate_hash(objects: &Vec<HashBox>) -> BigUint {
    let mut hasher = Sha256::default();
    let mut msg: String = "".to_owned();
    for obj in objects {
        match obj {
            HashBox::Secp(g) => msg.push_str(&format!("{}", g)),
            HashBox::Bls(g) => msg.push_str(&format!("{}", g)),
        }
    }
    hasher.update(msg);
    let digest = hasher.finalize();
    BigUint::from_bytes_le(&digest)
}

pub fn pedersen_commit<G: AffineRepr>(
    g: G,
    h: G,
    s: impl AsRef<[u64]>,
    t: impl AsRef<[u64]>,
)  -> G::Group {
    g.mul_bigint(s) + h.mul_bigint(t)
}
