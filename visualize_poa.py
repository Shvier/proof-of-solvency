import pandas as pd
import matplotlib.pyplot as plt
import argparse

parser = argparse.ArgumentParser(description='path of the csv')
parser.add_argument('csv_path')
args = parser.parse_args()
csv = pd.read_csv(args.csv_path)
df = pd.DataFrame(csv)
df = df[df['num_of_keys'].isin([256, 512, 1024, 2048, 4096, 8192, 16384])]

def average(df):
    new_df = pd.DataFrame(columns=df.columns)
    for column in df.columns:
        if len(df[column].values) <= 1:
            new_df[column] = df[column]
            continue
        idxmax = df[column].idxmax()
        idxmin = df[column].idxmin()
        new_df[column] = df[column].drop([idxmax, idxmin])
    average = (new_df.mean() / 1000).round(2)
    return average

def show_precomputing():
    keys_df = df['num_of_keys']
    proving_time_df = []
    verifying_time_df = []
    for num_of_key in keys_df.values:
        filtered_df = df.query('num_of_keys == {}'.format(num_of_key)).drop('num_of_keys', axis=1)
        filtered_df = average(filtered_df)
        proving_time_df.append(filtered_df['pre_proving_time'])
        verifying_time_df.append(filtered_df['pre_verifying_time'])

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
    interpolating_balance_df = []
    proving_time_df = []
    verifying_time_df = []
    validating_balance_df = []

    for num_of_key in keys_df.values:
        filtered_df = df.query('num_of_keys == {}'.format(num_of_key)).drop('num_of_keys', axis=1)
        filtered_df = average(filtered_df)
        interpolating_balance_df.append(filtered_df['interpolating_balance_time'])
        proving_time_df.append(filtered_df['post_proving_time'])
        verifying_time_df.append(filtered_df['post_verifying_proof_time'])
        validating_balance_df.append(filtered_df['post_validating_balance_time'])

    fig, axs = plt.subplots(1, 4, figsize=(24, 6))

    axs[0].plot(keys_df, proving_time_df)
    axs[0].set_xlabel('# of Keys')
    axs[0].set_ylabel('Proving Time (ms)')

    axs[1].set_ylim([1, 10])
    axs[1].plot(keys_df, verifying_time_df)
    axs[1].set_xlabel('# of Keys')
    axs[1].set_ylabel('Verifying Proof Time (ms)')

    axs[2].set_ylim([0, 100])
    axs[2].plot(keys_df, interpolating_balance_df)
    axs[2].set_xlabel('# of Keys')
    axs[2].set_ylabel('Interpolating Balance Time (ms)')

    axs[3].plot(keys_df, validating_balance_df)
    axs[3].set_xlabel('# of Keys')
    axs[3].set_ylabel('Validating Commitment to Balance Time (ms)')

    fig.suptitle('Post-Precomputing Stage')
    plt.show()

show_precomputing()
show_post_precomputing()
