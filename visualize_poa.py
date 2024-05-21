import pandas as pd
import matplotlib.pyplot as plt
import argparse
import numpy as np

parser = argparse.ArgumentParser(description='path of the csv')
parser.add_argument('csv_path')
args = parser.parse_args()
csv = pd.read_csv(args.csv_path)
df = pd.DataFrame(csv)
df = df[df['num_of_keys'].isin([256, 512, 1024, 2048, 4096, 8192, 16384])]

def add_vec(a, b):
    a = np.array(a)
    b = np.array(b)
    return a + b

def average(df):
    new_df = pd.DataFrame(columns=df.columns)
    for column in df.columns:
        if len(df[column].values) <= 1:
            new_df[column] = df[column]
            continue
        idxmax = df[column].idxmax()
        idxmin = df[column].idxmin()
        new_df[column] = df[column].drop([idxmax, idxmin])
    average = new_df.mean()
    return average

def show_precomputing():
    keys_df = df['num_of_keys'].drop_duplicates().sort_values()
    proving_time_df = []
    verifying_time_df = []
    proof_size_df = []
    for num_of_key in keys_df.values:
        filtered_df = df.query('num_of_keys == {}'.format(num_of_key)).drop('num_of_keys', axis=1)
        filtered_df = average(filtered_df)
        proving_time_df.append((filtered_df['pre_proving_time'] / 1000).round(2))
        verifying_time_df.append((filtered_df['pre_verifying_time'] / 1000).round(2))
        proof_size_df.append(filtered_df['pre_proof_size'])

    print('precomputing\n================\nproving time:')
    for num, pt in zip(keys_df, proving_time_df):
        print('({},{})'.format(num, (pt / 1000).round(2)), end="")
    print('\nverifying time:')
    for num, vt in zip(keys_df, verifying_time_df):
        print('({},{})'.format(num, (vt / 1000).round(2)), end="")
    print('\nproof size:')
    for num, ps in zip(keys_df, proof_size_df):
        print('({},{})'.format(num, ps), end="")
    print('\n================')
    fig, axs = plt.subplots(1, 3, figsize=(18, 6))
    axs[0].plot(keys_df, proving_time_df)
    axs[0].set_xlabel('# Keys')
    axs[0].set_ylabel('Proving Time (ms)')
    axs[1].plot(keys_df, verifying_time_df)
    axs[1].set_xlabel('# Keys')
    axs[1].set_ylabel('Verifying Time (ms)')
    axs[2].plot(keys_df, proof_size_df)
    axs[2].set_xlabel('# Keys')
    axs[2].set_ylabel('Proof Size (KB)')
    fig.suptitle('Precomputing Stage')
    plt.show()

def show_post_precomputing():
    keys_df = df['num_of_keys'].drop_duplicates().sort_values()
    interpolating_balance_df = []
    proving_time_df = []
    verifying_time_df = []
    validating_balance_df = []
    proof_size_df = []

    for num_of_key in keys_df.values:
        filtered_df = df.query('num_of_keys == {}'.format(num_of_key)).drop('num_of_keys', axis=1)
        filtered_df = average(filtered_df)
        interpolating_balance_df.append((filtered_df['interpolating_balance_time'] / 1000).round(2))
        proving_time_df.append((filtered_df['post_proving_time'] / 1000).round(2))
        verifying_time_df.append((filtered_df['post_verifying_proof_time'] / 1000).round(2))
        validating_balance_df.append((filtered_df['post_validating_balance_time'] / 1000).round(2))
        proof_size_df.append(filtered_df['post_proof_size'])

    print('proving assets\n================\nproving time:')
    for num, pt in zip(keys_df, proving_time_df):
        print('({},{})'.format(num, pt), end="")
    print('\nverifying time:')
    for num, vt in zip(keys_df, verifying_time_df):
        print('({},{})'.format(num, vt.round(2)), end="")
    print('\nvalidating balance poly:')
    for num, vt in zip(keys_df, validating_balance_df):
        print('({},{})'.format(num, vt.round(2)), end="")
    print('\nproof size:')
    for num, ps in zip(keys_df, proof_size_df):
        print('({},{})'.format(num, ps), end="")
    print('\n================')

    fig, axs = plt.subplots(1, 4, figsize=(24, 6))

    axs[0].plot(keys_df, proving_time_df)
    axs[0].set_xlabel('# Keys')
    axs[0].set_ylabel('Proving Time (ms)')

    axs[1].set_ylim([0, 10])
    axs[1].plot(keys_df, verifying_time_df)
    axs[1].set_xlabel('# Keys')
    axs[1].set_ylabel('Verifying Proof Time (ms)')

    axs[2].set_ylim([0, 10])
    axs[2].plot(keys_df, interpolating_balance_df)
    axs[2].set_xlabel('# Keys')
    axs[2].set_ylabel('Interpolating Balance Time (ms)')

    axs[3].plot(keys_df, validating_balance_df)
    axs[3].set_xlabel('# Keys')
    axs[3].set_ylabel('Validating Commitment to Balance Time (ms)')

    fig.suptitle('Proving Assets Stage')
    plt.show()

# show_precomputing()
show_post_precomputing()
