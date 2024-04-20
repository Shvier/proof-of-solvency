use std::{fs::{self, File}, io::{BufWriter, Write}};

use ark_std::rand::{self, Rng};
use csv::Writer;

use super::{BenchConfig, CSVRecord};

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

#[test]
fn generate_csv_report() {
    let prefix = &mut vec![];
    let records = &mut vec![];
    _generate_csv_report("./bench_data", 0, &vec!["users", "bits", "groups"], prefix, records);
    println!("{:?}", records);
    let path = "./bench_data/report.csv";
    let mut wtr = Writer::from_path(path).expect("Failed to create file");
    for record in records {
        wtr.serialize(record).expect("Failed to serialize");
    }
    wtr.flush().expect("Failed to write");
}

#[cfg(test)]
fn _generate_csv_report(
    path: &str,
    depth: usize,
    levels: &Vec<&str>,
    prefix: &mut Vec<usize>,
    records: &mut Vec<CSVRecord>,
) {
    use std::io::Read;

    use crate::bench::PoLReport;

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
            if !path.path().is_dir() { continue; }
            let path_str = path.path().into_os_string().into_string().unwrap().clone();
            let folder = path.file_name().into_string().unwrap();
            let mut split = folder.split(levels[depth]);
            let pre = split.next().unwrap();
            prefix.push(pre.parse::<usize>().unwrap());
            _generate_csv_report(&path_str, depth + 1, &levels, prefix, records);
            prefix.pop();
        }
    }
}
