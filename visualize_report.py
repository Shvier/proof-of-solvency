import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.interpolate import make_interp_spline

csv = pd.read_csv('./bench_data/report.csv')
df = pd.DataFrame(csv)

def query_df(power):
    num_of_users = 2**power
    filtered_df = df.query('num_of_users == {}'.format(num_of_users)).sort_values(by="num_of_groups")
    return filtered_df

def query_proof_size(power):
    filtered_df = query_df(power)
    num_of_groups_df = filtered_df['num_of_groups']
    proof_size_df = filtered_df['proof_size']
    return (num_of_groups_df, proof_size_df)

def query_proof_time(power):
    num_of_users = 2**power
    filtered_df = df.query('num_of_users == {}'.format(num_of_users)).sort_values(by="num_of_groups")
    a = np.array(filtered_df['interpolation_time'])
    b = np.array(filtered_df['proving_time'])
    ab = a + b
    return (filtered_df['num_of_groups'], ab, filtered_df['verifying_time'])

power = 19
fig, axs = plt.subplots(1, 3, figsize=(18, 6))
(num_of_groups_df, proof_size_df) = query_proof_size(power)
axs[0].plot(num_of_groups_df, proof_size_df)
axs[0].set_xlabel('# of Groups')
axs[0].set_ylabel('Proof Size (KB)')
(_, proving_time_df, verifying_time_df) = query_proof_time(power)
axs[1].plot(num_of_groups_df, proving_time_df)
axs[1].set_xlabel('# of Groups')
axs[1].set_ylabel('Proving Time (S)')
axs[2].plot(num_of_groups_df, verifying_time_df)
axs[2].set_xlabel('# of Groups')
axs[2].set_ylabel('Verifying Time (S)')
fig.suptitle('# of Users = 2^{}'.format(power))
plt.show()

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
