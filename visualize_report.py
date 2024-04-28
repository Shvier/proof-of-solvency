import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline

csv = pd.read_csv('./bench_data/report.csv')
df = pd.DataFrame(csv)

powers_range = range(14, 19)
max_allowed_bits = 64

def add_vec(a, b):
    a = np.array(a)
    b = np.array(b)
    return a + b

def query_df(power):
    num_of_users = 2**power
    filtered_df = df.query('num_of_users == {}'.format(num_of_users)).sort_values(by="num_of_groups")
    return filtered_df

def query_proof_size(df, num_of_bits):
    num_of_groups_df = df.query('num_of_bits == {}'.format(num_of_bits))['num_of_groups']
    proof_size_df = df.query('num_of_bits == {}'.format(num_of_bits))['proof_size']
    return (num_of_groups_df, proof_size_df)

def query_proof_time(df, num_of_bits):
    filtered_df = df.query('num_of_bits == {}'.format(num_of_bits))
    proving_time_df = add_vec(filtered_df['interpolation_time'], filtered_df['proving_time'])
    return (filtered_df['num_of_groups'], proving_time_df, filtered_df['verifying_time'])

def query_proof_time_for_threads(num_of_bits):
    st_pt_list = []
    st_vt_list = []
    mt_pt_list = []
    mt_vt_list = []
    for power in powers_range:
        filtered_df = query_df(power).query('num_of_bits == {}'.format(num_of_bits))

        single_thread_df = filtered_df.query('num_of_groups == 1')
        st_pt = add_vec(single_thread_df['interpolation_time'], single_thread_df['proving_time'])[0]
        st_vt = single_thread_df['verifying_time'].values[0]

        multi_thread_df = filtered_df.query('num_of_groups != 1')
        mt_df_by_bits = multi_thread_df.query('num_of_bits == {}'.format(num_of_bits))
        mt_proving_time = add_vec(mt_df_by_bits['interpolation_time'], mt_df_by_bits['proving_time'])

        fastest_proving_time = min(mt_proving_time)
        index = np.where(mt_proving_time == fastest_proving_time)[0]
        verifying_time = mt_df_by_bits['verifying_time'].values[index][0]

        st_pt_list.append(st_pt)
        st_vt_list.append(st_vt)
        mt_pt_list.append(fastest_proving_time)
        mt_vt_list.append(verifying_time)
    return (st_pt_list, st_vt_list, mt_pt_list, mt_vt_list)

def show_comparison_by(num_of_bits):
    (st_pt_list, st_vt_list, mt_pt_list, mt_vt_list) = query_proof_time_for_threads(num_of_bits)

    fig, axs = plt.subplots(1, 2, figsize=(12, 6))
    width = 0.25

    xs = np.arange(len(st_pt_list))
    num_of_users_range = list(map(lambda i: 2**i, powers_range))
    axs[0].bar(xs, st_pt_list, width, label='Single Thread')
    axs[0].bar(xs + width, mt_pt_list, width, label='Multi Thread')
    axs[0].set_xticks(xs + width, num_of_users_range)
    axs[0].set_xlabel('# of Users')
    axs[0].set_ylabel('Proving Time (s)')
    axs[0].legend(loc='upper left')

    axs[1].bar(xs, st_vt_list, width, label='Single Thread')
    axs[1].bar(xs + width, mt_vt_list, width, label='Multi Thread')
    axs[1].set_xticks(xs + width, num_of_users_range)
    axs[1].set_xlabel('# of Users')
    axs[1].set_ylabel('Verifying Time (s)')
    axs[1].legend(loc='upper left')
    fig.suptitle('# of Bits = 2^{}'.format(num_of_bits))

    plt.show()

def show_performance_by(power):
    fig, axs = plt.subplots(1, 3, figsize=(18, 6))
    filtered_df = query_df(power).query('num_of_groups != 2048')
    num_of_bits = list(set(filtered_df['num_of_bits']))
    for num in num_of_bits:
        (num_of_groups_df, proof_size_df) = query_proof_size(filtered_df, num)
        axs[0].plot(num_of_groups_df, proof_size_df, label='{}bits'.format(num))
        axs[0].set_xlabel('# of Groups')
        axs[0].set_ylabel('Proof Size (KB)')
        (_, proving_time_df, verifying_time_df) = query_proof_time(filtered_df, num)
        axs[1].plot(num_of_groups_df, proving_time_df, label='{}bits'.format(num))
        axs[1].legend()
        axs[1].set_xlabel('# of Groups')
        axs[1].set_ylabel('Proving Time (s)')
        axs[2].plot(num_of_groups_df, verifying_time_df, label='{}bits'.format(num))
        axs[2].legend()
        axs[2].set_xlabel('# of Groups')
        axs[2].set_ylabel('Verifying Time (s)')
        for i in range(3):
            handles, labels = axs[i].get_legend_handles_labels()
            labels, handles = zip(*sorted(zip(labels, handles), key=lambda t: t[0]))
            axs[i].legend(handles, labels)
    fig.suptitle('# of Users = 2^{}'.format(power))
    plt.show()

def compare_proof_time(num_of_bits):
    proof_time_table = {}
    for power in powers_range:
        filtered_df = query_df(power).query('num_of_groups != 2048 and num_of_users != 524288')
        (num_of_groups_df, proving_time_df, verifying_time_df) = query_proof_time(filtered_df, num_of_bits)
        proof_time_table[power] = (num_of_groups_df, proving_time_df, verifying_time_df)

    range_proof_size = list(map(lambda i: 2**i, range(0, 11)))
    xs = np.arange(len(range_proof_size))
    width = 0.8 / len(proof_time_table)
    multiplier = 0

    fig, axs = plt.subplots(1, 2, figsize=(12, 6))

    for power, values in proof_time_table.items():
        offset = width * multiplier
        axs[0].bar(xs + offset, values[1], width, label='2^{}'.format(power))
        axs[1].bar(xs + offset, values[2], width, label='2^{}'.format(power))
        multiplier += 1

    axs[0].set_xticks(xs + width, range_proof_size)
    axs[0].set_xlabel('# of Groups')
    axs[0].set_ylabel('Proving Time (s)')
    axs[0].legend(loc='upper right', ncols=3, title='# of Users')

    axs[1].set_xticks(xs + width, range_proof_size)
    axs[1].set_xlabel('# of Groups')
    axs[1].set_ylabel('Verifying Time (s)')
    axs[1].legend(loc='upper left', ncols=3, title='# of Users')
    fig.suptitle('# of Bits = 2^{}'.format(num_of_bits))
    plt.show()

show_comparison_by(32)

show_performance_by(17)

compare_proof_time(32)
