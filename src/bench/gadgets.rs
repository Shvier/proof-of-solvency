use std::{fs::File, io::{BufWriter, Write}};

use ark_std::rand::{self, Rng};
use csv::Writer;

use super::BenchConfig;

#[test]
fn generate_balances() {
    let num_of_users: u32 = 2u32.pow(20);
    let upper_bound = u64::MAX;
    let mut rng = rand::thread_rng();
    let balances: Vec<u64> = (0..num_of_users).map(| _ | rng.gen_range(1..upper_bound)).collect();

    let path = "./bench_data/balance.csv";
    let mut wtr = Writer::from_path(path).expect("Failed to create file");
    for bal in balances {
        wtr.serialize(bal).expect("Failed to serialize");
    }
    wtr.flush().expect("Failed to write");
}

#[test]
fn generate_config() {
    let configs = vec![
        BenchConfig {
            num_of_users: 2usize.pow(20),
            num_of_bits: 64,
            num_of_groups: 1024,
        },
    ];
    let file = File::create("./bench_data/config.json").expect("Failed to create config json file");
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &configs).expect("Failed to serialize config json");
    writer.flush().expect("Failed to write config json file");
}
