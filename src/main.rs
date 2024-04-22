use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    time::{Duration, Instant},
};

use ark_poly::domain::EvaluationDomain;
use ark_std::{test_rng, UniformRand};

use proof_of_solvency::{
    bench::{BenchConfig, PoLReport},
    proof_of_liability::{prover::Prover, verifier::Verifier},
    types::BlsScalarField,
};

fn main() {
    run_pol();
}

fn run_pol() {
    let (configs, balances) = read_config();
    for config in configs {
        let dir = format!(
            "./bench_data/{}users/{}bits/{}groups",
            config.num_of_users, config.num_of_bits, config.num_of_groups
        );
        let _ = fs::create_dir_all(dir.clone());
        let bals = balances[0..config.num_of_users].to_vec();
        let (proof_size, time1, time2, time3) = _run_pol(&config, &bals);
        let report = PoLReport {
            interpolation_time: format!("{:.2?}", time1.as_secs_f64()),
            proving_time: format!("{:.2?}", time2.as_secs_f64()),
            verifying_time: format!("{:.2?}", time3.as_secs_f64()),
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

fn read_config() -> (Vec<BenchConfig>, Vec<u64>) {
    let mut file = File::open("./bench_data/config.json").unwrap();
    let mut buffer = String::new();
    file.read_to_string(&mut buffer).unwrap();
    let configs: Vec<BenchConfig> = serde_json::from_str(&buffer).unwrap();

    let file = File::open("./bench_data/balance.csv").unwrap();
    let mut reader = csv::Reader::from_reader(file);
    let mut balances = Vec::<u64>::new();
    for result in reader.deserialize() {
        let record: u64 = result.unwrap();
        balances.push(record);
    }
    (configs, balances)
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
