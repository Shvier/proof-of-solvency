# proof-of-solvency

This implementation is for the demonstration purpose of the paper, [Xiezhi]().

# Project Structure

The proof-of-solvency is broken into two protocols, proof-of-assets (PoA) and proof-of-liability (PoL), as defined in [Provisions](https://eprint.iacr.org/2015/1008#:~:text=A%20proof%20of%20solvency%20demonstrates,any%20information%20about%20its%20customers). The implementation of each protocol consists of proving and verifying, under the folders "prover" and "verifier" respectively.

## proof of assets
   * prover - $\pi_\mathsf{assets}$
   * sigma - $\pi_\mathsf{keys}$

## proof of liability
   * prover - $\pi_\mathsf{liability}$ and $\pi_\mathsf{users}$

## utils

We simply implemented some operations like the Pedersen commitment, linearly combining polynomials, etc, and the batched KZG in [PLONK](https://eprint.iacr.org/2019/953).

## benchmark

In this directory, the `gadgets.rs` features functionalities for testing such as generating balances and the CSV report; the `mod.rs` consists of the structs used for testing.

## bench_data

Our experimental data. The experiments were conducted on a PC with i9-13900KF and 32GB of memory. We also ran the program on a MacBook with the M1 Pro chip and 16GB of memory.

# Verify the Experiment

## Run the Protocol

1. Compile and build the program `main.rs` by executing `cargo build --release` to build the execution file. Make sure all the dependencies are installed correctly.
2. On Windows, run the symbolic file `proof_of_solvency.exe`; on Unix-like systems, run the symbolic file `pos` (the program requires some input arguments, the explanation is followed).
3. Input the desired option as the program's menu displays
   - Option 1 requires two parameters, one is the file path of the balance CSV, and the other is the output directory, e.g., `./bench_data/proof_of_liability` in our experiments;
   - Option 2 requires two parameters, one is the file path of the balance CSV, and the other is the number of keys that we want to prove. The file path of the $\texttt{secp256k1}$ key pairs is fixed, so make sure it exists before running the program.
   - Option 3 requires one parameter, the number of keys. The program will stop after precomputing is done and output two JSON files, `prover.json` and `selector_commitment.json`. The prover should use these two validated JSON files to run the main protocol.
   - Option 4 requires three parameters, the file path of the balance CSV, the number of keys, and the file path of `prover.json`.
   - Option 5 requires one parameter, the number of keys. It will randomly generate some $\texttt{secp256k1}$ key pairs for test.

## Prepare the Experiment Configurations

For PoA
- Choose `Option 5` after running the program to generate the key pairs
- Run the function `generate_balances` in `gadgets.rs`. Remember to modify `num_of_users` and `upper_bound` (the maximum allowed balance) to the desired values.

For PoL
- Run the function `generate_balances` in `gadgets.rs` to generate `balance.csv`.
- Modify `configs` in `generate_config_for_pol` and run this function, which will output a configuration JSON file. Our implementation supports dynamic configuration for `num_of_users`, `num_of_bits` (this should correspond to `upper_bound`), and `num_of_groups`.

## Generate the Report
We provide a way to aggregate the output JSON files into a CSV, by simply running the function `generate_csv_report` in `gadgets.rs`. Also, there are two visualization scripts, `visualize_poa.py` and `visualize_pol.py`, to interpolate the figures from the CSV.
