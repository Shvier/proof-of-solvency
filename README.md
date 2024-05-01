# proof-of-solvency

This implementation is for the demonstration purpose of the paper []().

# Structure

The proof-of-solvency is divided into two parts, proof-of-assets (PoA) and proof-of-liability (PoL) as defined in [Provisions](https://eprint.iacr.org/2015/1008#:~:text=A%20proof%20of%20solvency%20demonstrates,any%20information%20about%20its%20customers). Each protocol consists of the implementations of proving and verifying, under the directories "prover" and "verifier" respectively.

## src

In PoA, there is a folder named sigma, which is the implementation of our sigma protocol; in PoL, there is a `struct` named `Intermediate`, which is the implementation of proving liabilities for each group.

## utils

We simply implemented some operations like the Pedersen commitment, linearly combining polynomials, etc and the batched KZG in [PLONK](https://eprint.iacr.org/2019/953).

## bench

In this directory, the `gadgets.rs` consists of scripts for tests such as generating balances and the CSV report; the `mod.rs` consists of the structs used for tests.

## bench_data

Our experimental data. The experiments were conducted on a PC with i9-13900KF and 32GB of memory. We also ran the program on a MacBook with the M1 Pro chip and 16GB of memory to fix the experimental error.

# Verify the Experiment

For PoA, run the test function named `test_poa` in the file `test_poa.rs`.

For PoL, execute the following steps:

1. (**optional**) Delete the folder `bench_data` (our test data).
2. Run the function `generate_balances` in `gadgets.rs`. Remember to modify `num_of_users` and `upper_bound` (the maximum allowed balance) to the desired values.
3. Modify `configs` in `generate_config` and run this function, which will output a configuration JSON file. Our implementation supports dynamic configuration for `num_of_users`, `num_of_bits` (this should correspond to `upper_bound`), and `num_of_groups`.
4. Execute `cargo build --release` to build the execution file. Make sure all the dependencies are installed correctly.
5. On Windows, run the symbolic file `proof_of_solvency.exe`; on Unix-like systems, run the symbolic file `pos`. The binary needs two inputs:
   - the file path of `balance.csv` generated in step 2
   - the output directory, e.g., `./bench_data` in our experiments
6. After getting enough test data, run `generate_csv_report` in `gadgets.rs`, which will output a CSV file recording all the test data from step 5.
7. (**optional**) We provide a simple visualization script, `visualize_report.py`. It requires the file path of the CSV report from step 6 as the input.
