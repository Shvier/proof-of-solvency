use std::{
    fs::{self, File}, io::{BufWriter, Read, Write}, time::{Duration, Instant}
};

use ark_poly::domain::EvaluationDomain;
use ark_std::{test_rng, UniformRand};

use crate::{benchmark::{BenchConfig, PoLReport}, proof_of_liability::{prover::Prover, verifier::Verifier}, types::BlsScalarField, utils::read_balances};

pub fn run_pol(bal_path: String, output_dir: String) {
    let (configs, balances) = read_config(bal_path);
    for config in configs {
        let dir = format!(
            "{}/{}users/{}bits/{}groups",
            output_dir, config.num_of_users, config.num_of_bits, config.num_of_groups
        );
        let _ = fs::create_dir_all(dir.clone());
        let bals = balances[0..config.num_of_users].to_vec();
        let (proof_size, time1, time2, time3) = _run_pol(&config, &bals);
        let report = PoLReport {
            interpolation_time: format!("{:.2?}", time1.as_millis()),
            proving_time: format!("{:.2?}", time2.as_millis()),
            verifying_time: format!("{:.2?}", time3.as_millis()),
            proof_size: format!("{}", proof_size / 1000),
        };
        let json_path =
            dir.clone() + &format!("/{}.json", chrono::offset::Local::now()).replace(":", "-");
        let file = File::create(json_path).unwrap();
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &report).unwrap();
        writer.flush().unwrap();
    }
}

fn _run_pol(config: &BenchConfig, balances: &Vec<u64>) -> (usize, Duration, Duration, Duration) {
    let group_size: usize = config.num_of_users / config.num_of_groups;
    let max_degree = group_size * 2;
    let prover = Prover::setup(&balances, group_size, max_degree);
    let rng = &mut test_rng();
    let gamma = BlsScalarField::rand(rng);
    match config.num_of_groups {
        1 => {
            let now = Instant::now();
            let (inters, comms, rands) = prover.run(config.num_of_bits, gamma, rng);
            let elapsed1 = now.elapsed();
            let taus = inters.iter().map(| inter | inter.domain.sample_element_outside_domain(rng)).collect();
            let now = Instant::now();
            let (proof, _) = prover.generate_proof(&inters, &comms, &rands, &taus, rng);
            let proof_size = proof.deep_size();
            let elapsed2 = now.elapsed();
            let now = Instant::now();
            Verifier::validate_liability_proof(&prover.vk, proof.clone(), &taus, gamma, rng);
            let elapsed3 = now.elapsed();
            (proof_size, elapsed1, elapsed2, elapsed3)
        }
        _ => {
            let now = Instant::now();
            let (inters, comms, rands) = prover.concurrent_run(config.num_of_bits, gamma);
            let elapsed1 = now.elapsed();
            let taus = inters
                .iter()
                .map(|inter| inter.domain.sample_element_outside_domain(rng))
                .collect();
            let now = Instant::now();
            let (proof, _) = prover.concurrent_generate_proof(&inters, &comms, &rands, &taus);
            let proof_size = proof.deep_size();
            let elapsed2 = now.elapsed();
            let now = Instant::now();
            Verifier::validate_liability_proof(&prover.vk, proof, &taus, gamma, rng);
            let elapsed3 = now.elapsed();
            (proof_size, elapsed1, elapsed2, elapsed3)
        }
    }
}

fn read_config(bal_path: String) -> (Vec<BenchConfig>, Vec<u64>) {
    let mut file = File::open("./bench_data/proof_of_liability/config.json").unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    let configs: Vec<BenchConfig> = serde_json::from_str(&buffer).unwrap();

    let balances = read_balances(&bal_path);
    (configs, balances)
}
