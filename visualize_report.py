import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline

csv = pd.read_csv('./bench_data/report.csv')
df = pd.DataFrame(csv)

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

# def query_proof_time_for_threads(power):
#     num_of_users = 2**power
#     filtered_df = df.query('num_of_users == {}'.format(num_of_users))

#     single_thread_df = filtered_df.query('num_of_groups == 1').sort_values(by='num_of_bits')
#     st_proving_time = add_vec(single_thread_df['interpolation_time'], single_thread_df['proving_time'])

#     multi_thread_df = filtered_df.query('num_of_groups != 1').sort_values(by='num_of_bits')
#     for num_of_bits in range(1, max_allowed_bits + 1):
#         mt_df_by_bits = multi_thread_df.query('num_of_bits == {}'.format(num_of_bits))
#         print(mt_df_by_bits)
#         mt_proving_time = add_vec(mt_df_by_bits['interpolation_time'], mt_df_by_bits['proving_time'])
#         if len(mt_proving_time) == 0:
#             continue
#         fastest_proving_time = min(mt_proving_time)
#         index = np.where(mt_proving_time == fastest_proving_time)[0]
#         verifying_time = mt_df_by_bits['verifying_time'][index]
#         print('index: {}\npt: {:.2f}\nvt: {}\n'.format(index, fastest_proving_time, verifying_time))

def show_performance_by(power):
    fig, axs = plt.subplots(1, 3, figsize=(18, 6))
    df = query_df(power)
    df = df.query('num_of_groups != 2048')
    num_of_bits = list(set(df['num_of_bits']))
    for num in num_of_bits:
        (num_of_groups_df, proof_size_df) = query_proof_size(df, num)
        axs[0].plot(num_of_groups_df, proof_size_df, label='{}bits'.format(num))
        axs[0].set_xlabel('# of Groups')
        axs[0].set_ylabel('Proof Size (KB)')
        (_, proving_time_df, verifying_time_df) = query_proof_time(df, num)
        axs[1].plot(num_of_groups_df, proving_time_df, label='{}bits'.format(num))
        axs[1].legend()
        axs[1].set_xlabel('# of Groups')
        axs[1].set_ylabel('Proving Time (S)')
        axs[2].plot(num_of_groups_df, verifying_time_df, label='{}bits'.format(num))
        axs[2].legend()
        axs[2].set_xlabel('# of Groups')
        axs[2].set_ylabel('Verifying Time (S)')
        for i in range(3):
            handles, labels = axs[i].get_legend_handles_labels()
            labels, handles = zip(*sorted(zip(labels, handles), key=lambda t: t[0]))
            axs[i].legend(handles, labels)
    fig.suptitle('# of Users = 2^{}'.format(power))
    plt.show()

show_performance_by(18)

proof_time_table = {}
powers_range = range(16, 19)
for power in powers_range:
    (num_of_groups_df, proving_time_df, verifying_time_df) = query_proof_time(power)
    proof_time_table[power] = (num_of_groups_df, proving_time_df, verifying_time_df)

range_proof_size = list(map(lambda i: 2**i, range(0, 12)))
x_l = np.arange(len(range_proof_size))
width = 0.25
multiplier = 0

fig, axs = plt.subplots(1, 2, figsize=(12, 6))

for power, values in proof_time_table.items():
    offset = width * multiplier
    axs[0].bar(x_l + offset, values[1], width, label='2^{}'.format(power))
    axs[1].bar(x_l + offset, values[2], width, label='2^{}'.format(power))
    multiplier += 1

axs[0].set_xticks(x_l + width, range_proof_size)
axs[0].set_xlabel('# of Groups')
axs[0].set_ylabel('Proving Time (S)')
axs[0].legend(loc='upper right', ncols=3, title='# of Users')

axs[1].set_xticks(x_l + width, range_proof_size)
axs[1].set_xlabel('# of Groups')
axs[1].set_ylabel('Verifying Time (S)')
axs[1].legend(loc='upper left', ncols=3, title='# of Users')

plt.show()
