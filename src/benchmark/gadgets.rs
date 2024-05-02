use std::{
    fs::{self, File},
    io::{BufWriter, Write},
};

use ark_ec::{AffineRepr, CurveGroup};
use ark_std::{rand::{self, Rng}, test_rng};
use ark_test_curves::secp256k1;
use csv::Writer;
use num_bigint::{BigUint, RandomBits};

use crate::benchmark::{AffinePoint, KeyPair};

use super::{BenchConfig, CSVRecord};

#[test]
fn generate_balances() {
    let num_of_users: u32 = 2u32.pow(20);
    let upper_bound = u64::MAX;
    let mut rng = rand::thread_rng();
    let balances: Vec<u64> = (0..num_of_users)
        .map(|_| rng.gen_range(1..upper_bound))
        .collect();

    let path = "./bench_data/balance.csv";
    let mut wtr = Writer::from_path(path).expect("Failed to create file");
    for bal in balances {
        wtr.serialize(bal).expect("Failed to serialize");
    }
    wtr.flush().expect("Failed to write");
}

#[cfg(test)]
const NUM_OF_KEYS: u32 = 2u32.pow(28);

#[test]
fn generate_pk_sk_pairs() {
    let mut key_pairs = Vec::<KeyPair>::new();
    let rng = &mut test_rng();
    for _ in 0..NUM_OF_KEYS {
        let private_key: BigUint = rng.sample(RandomBits::new(256u64));
        let public_key = secp256k1::G1Affine::generator().mul_bigint(private_key.to_u64_digits()).into_affine();
        let pair = KeyPair {
            sk: private_key.to_string(),
            pk: AffinePoint {
                x: public_key.x.to_string(),
                y: public_key.y.to_string(),
            },
        };
        key_pairs.push(pair);
    }
    let dir = "./bench_data/proof_of_assets";
    let _ = fs::create_dir_all(dir);
    let file = File::create(format!("{}/key_pairs.json", dir)).expect("Failed to create key_pairs json file");
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &key_pairs).expect("Failed to serialize key_pairs json");
    writer.flush().expect("Failed to write key_pairs json file");
}

#[test]
fn generate_config_for_pol() {
    let power = 18;
    let configs = vec![
        BenchConfig {
            num_of_users: 2usize.pow(power),
            num_of_bits: 64,
            num_of_groups: 2048,
        },
        BenchConfig {
            num_of_users: 2usize.pow(power),
            num_of_bits: 64,
            num_of_groups: 512,
        },
        BenchConfig {
            num_of_users: 2usize.pow(power),
            num_of_bits: 64,
            num_of_groups: 128,
        },
        BenchConfig {
            num_of_users: 2usize.pow(power),
            num_of_bits: 64,
            num_of_groups: 8,
        },
        BenchConfig {
            num_of_users: 2usize.pow(power),
            num_of_bits: 64,
            num_of_groups: 2,
        },
    ];
    let file = File::create("./bench_data/proof_of_liability/config.json").expect("Failed to create config json file");
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &configs).expect("Failed to serialize config json");
    writer.flush().expect("Failed to write config json file");
}

#[test]
fn generate_csv_report_for_pol() {
    let prefix = &mut vec![];
    let records = &mut vec![];
    _generate_csv_report_for_pol(
        "./bench_data/proof_of_liability",
        0,
        &vec!["users", "bits", "groups"],
        prefix,
        records,
    );
    records.sort_by(|a, b| a.num_of_groups.cmp(&b.num_of_groups));
    let path = "./bench_data/proof_of_liability/report.csv";
    let mut wtr = Writer::from_path(path).expect("Failed to create file");
    for record in records {
        wtr.serialize(record).expect("Failed to serialize");
    }
    wtr.flush().expect("Failed to write");
}

#[cfg(test)]
fn _generate_csv_report_for_pol(
    path: &str,
    depth: usize,
    levels: &Vec<&str>,
    prefix: &mut Vec<usize>,
    records: &mut Vec<CSVRecord>,
) {
    use std::io::Read;

    use crate::benchmark::PoLReport;

    if depth == levels.len() {
        assert_eq!(prefix.len(), levels.len());
        let paths = fs::read_dir(path).unwrap();
        for path in paths {
            if let Some(path) = path.ok() {
                assert!(path.path().is_file());
                let file_name = path.file_name().into_string().unwrap();
                let mut split = file_name.split(".json");
                let timestamp = split.next().unwrap();
                let mut file = File::open(path.path()).unwrap();
                let mut buffer = String::new();
                file.read_to_string(&mut buffer).unwrap();
                let report: PoLReport = serde_json::from_str(&buffer).unwrap();
                let record = CSVRecord {
                    num_of_users: prefix[0],
                    num_of_bits: prefix[1],
                    num_of_groups: prefix[2],
                    interpolation_time: report.interpolation_time,
                    proving_time: report.proving_time,
                    verifying_time: report.verifying_time,
                    proof_size: report.proof_size,
                    timestamp: timestamp.to_string(),
                };
                records.push(record);
            }
        }
        return;
    }
    let paths = fs::read_dir(path).unwrap();
    for path in paths {
        if let Some(path) = path.ok() {
            if !path.path().is_dir() {
                continue;
            }
            let path_str = path.path().into_os_string().into_string().unwrap().clone();
            let folder = path.file_name().into_string().unwrap();
            let mut split = folder.split(levels[depth]);
            let pre = split.next().unwrap();
            if let Some(num_of_groups) = pre.parse::<usize>().ok() {
                prefix.push(num_of_groups);
                _generate_csv_report_for_pol(&path_str, depth + 1, &levels, prefix, records);
                prefix.pop();
            }
        }
    }
}