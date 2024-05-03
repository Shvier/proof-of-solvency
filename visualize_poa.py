import pandas as pd
import matplotlib.pyplot as plt
import argparse

parser = argparse.ArgumentParser(description='path of the csv')
parser.add_argument('csv_path')
args = parser.parse_args()
csv = pd.read_csv(args.csv_path)
df = pd.DataFrame(csv)

def show_precomputing():
    keys_df = df['num_of_keys']
    proving_time_df = df['pre_proving_time']
    verifying_time_df = df['pre_verifying_time']
    fig, axs = plt.subplots(1, 2, figsize=(12, 6))
    axs[0].plot(keys_df, proving_time_df)
    axs[0].set_xlabel('# of Keys')
    axs[0].set_ylabel('Proving Time (ms)')
    axs[1].plot(keys_df, verifying_time_df)
    axs[1].set_xlabel('# of Keys')
    axs[1].set_ylabel('Verifying Time (ms)')
    fig.suptitle('Precomputing Stage')
    plt.show()

def show_post_precomputing():
    keys_df = df['num_of_keys']
    proving_time_df = df['post_proving_time']
    verifying_time_df = df['post_verifying_proof_time']
    validating_balance_df = df['post_validating_balance_time']

    fig, axs = plt.subplots(1, 3, figsize=(18, 6))

    axs[0].plot(keys_df, proving_time_df)
    axs[0].set_xlabel('# of Keys')
    axs[0].set_ylabel('Proving Time (ms)')

    axs[1].set_ylim([1, 10])
    axs[1].plot(keys_df, verifying_time_df)
    axs[1].set_xlabel('# of Keys')
    axs[1].set_ylabel('Verifying Proof Time (ms)')

    axs[2].plot(keys_df, validating_balance_df)
    axs[2].set_xlabel('# of Keys')
    axs[2].set_ylabel('Validating Balance Time (ms)')

    fig.suptitle('Post-Precomputing Stage')
    plt.show()

show_precomputing()
show_post_precomputing()
