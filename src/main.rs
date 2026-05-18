use std::{
    env, fs::{self, File}, io::{self, BufWriter, Write}, path::Path
};

use ark_bls12_381::Bls12_381;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial, Radix2EvaluationDomain, univariate::DensePolynomial};
use ark_poly_commit::kzg10::{KZG10, Powers};
use ark_std::{test_rng, Zero, One};
use proof_of_solvency::{benchmark::AffinePoint, main_poa::{post_precompute, precompute_poa, run_poa}, main_pol::run_pol, proof_of_assets::prover::Prover, types::{BlsScalarField, UniPoly_381}, utils::{generate_pk_sk_pairs, lagrange_basis_i}}
;
use proof_of_solvency::main_poa::lagrange_poa;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

fn main() {
    println!("Operation:");
    println!("1. Run Proof-of-Liability");
    println!("2. Run whole Proof-of-Assets");
    println!("3. Run pi_keys for Proof-of-Assets");
    println!("4. Run pi_assets Proof-of-Assets");
    println!("5. Generate secp256k1 key pairs for Proof-of-Assets");
    println!("6. Run pi_keys using Lagrange bases");
    println!("7. Generate Lagrange basis comms");
    println!("8. Exit");

    println!("Enter your choice:");

    let mut choice = String::new();

    io::stdin()
        .read_line(&mut choice)
        .expect("Failed to read line");

    let choice: u32 = match choice.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Please enter a valid number!");
            return;
        }
    };

    let args: Vec<String> = env::args().collect();
    
    match choice {
        1 => {
            println!("You chose Option 1");
            let bal_path = &args[1];
            let output_dir = &args[2];
            assert!(Path::new(bal_path).exists());
            run_pol(bal_path.to_string(), output_dir.to_string());
        }
        2 => {
            println!("You chose Option 2");
            let bal_path = &args[1];
            let num_of_keys: usize = match &args[2].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    println!("Unsupported number of keys!");
                    return;
                }
            };
            run_poa(bal_path, num_of_keys);
        }
        3 => {
            println!("You chose Option 3");
            let num_of_keys: usize = match &args[1].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    println!("Unsupported number of keys!");
                    return;
                }
            };
            let _ = precompute_poa(num_of_keys);
        }
        4 => {
            println!("You chose Option 4");
            let bal_path = &args[1];
            let num_of_keys: usize = match &args[2].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    println!("Unsupported number of keys!");
                    return;
                }
            };
            let prover_json_path = &args[3];
            let prover = Prover::deserialize_from_json(&prover_json_path);
            post_precompute(&prover, bal_path, num_of_keys);
        }
        5 => {
            println!("You chose Option 5");
            let num_of_keys: usize = match &args[1].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    println!("Unsupported number of keys!");
                    return;
                }
            };
            generate_pk_sk_pairs(num_of_keys);
        }
        6 => {
            println!("You chose Option 6");
            let num_of_keys: usize = match &args[1].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    println!("Unsupported number of keys!");
                    return;
                }
            };
            let num_assets: usize = match &args[2].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    return;
                }
            };
            let _ = lagrange_poa(num_of_keys, num_assets);
        }
        7 => {
            println!("You chose Option 7");
            let num_of_keys: usize = match &args[1].trim().parse() {
                Ok(num) => *num,
                Err(_) => {
                    println!("Unsupported number of keys!");
                    return;
                }
            };
            let domain = Radix2EvaluationDomain::<BlsScalarField>::new(num_of_keys).unwrap();
            let max_degree: usize = num_of_keys * 2;
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
            let points: Vec<_> = (0..num_of_keys).map(|j| domain.element(j)).collect();

            let total_poly = points.iter().fold(
                DensePolynomial::from_coefficients_vec(vec![BlsScalarField::one()]),
                |poly, xj| {
                    let factor = DensePolynomial::from_coefficients_vec(vec![-*xj, BlsScalarField::one()]);
                    &poly * &factor
                },
            );
            (0..num_of_keys)
            .into_par_iter()
            .for_each(|i| {
                let poly = lagrange_basis_i(&total_poly, points.as_slice(), i);

                if cfg!(test) {
                    for (j, point) in points.iter().enumerate() {
                        let eval = poly.evaluate(point);
                        if i == j {
                            assert_eq!(eval, BlsScalarField::one());
                        } else {
                            assert_eq!(eval, BlsScalarField::zero());
                        }
                    }
                }

                let (commitment, _) = KZG10::<Bls12_381, _>::commit(&powers, &poly, None, None).unwrap();
                let affine = AffinePoint { x: commitment.0.x.to_string(), y: commitment.0.y.to_string() };
                let cache_path = format!("./bench_data/proof_of_assets/cache/lag_comms_{}.json", i);
                let _ = fs::create_dir_all("./bench_data/proof_of_assets/cache");
                let cache_file = File::create(cache_path).unwrap();
                let mut writer = BufWriter::new(cache_file);
                serde_json::to_writer(&mut writer, &affine).unwrap();
                writer.flush().unwrap();
            });
        }
        8 => {
            println!("Exiting...");
            return;
        }
        _ => println!("Invalid choice!"),
    }
}

// fn to_disk<T: Sized>(path: &str, data: &T) {
//     unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
//         ::core::slice::from_raw_parts(
//             (p as *const T) as *const u8,
//             ::core::mem::size_of::<T>(),
//         )
//     }
//     let mut fs = File::create(path).expect("failed to create pol");
//     fs.write_all(unsafe { &any_as_u8_slice(data) }).expect("failed to write pol");
// }
