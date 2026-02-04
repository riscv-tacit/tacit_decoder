# Given a sequence of iter: time pairs, plot the distribution of the times.

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import argparse
import re

pattern = r'(\d+): (\d+)'

def plot_distribution(input_file: str) -> None:
    with open(input_file, 'r') as f:
        content = f.read()
    matches = re.findall(pattern, content)
    times = [int(match[1]) for match in matches]
    plt.hist(times, bins=100)

    print(f'{input_file}: {min(times)} to {max(times)}')
    print(f'{input_file}: {sum(times) / len(times)} average')
    print(f'{input_file}: {np.median(times)} median')
    print(f'{input_file}: {np.percentile(times, 25)} 25th percentile')
    print(f'{input_file}: {np.percentile(times, 75)} 75th percentile')
    print(f'{input_file}: {np.percentile(times, 90)} 90th percentile')
    print(f'{input_file}: {np.percentile(times, 95)} 95th percentile')
    print(f'{input_file}: {np.percentile(times, 99)} 99th percentile')

    plt.savefig(f'{input_file}.png')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=str, required=True)
    args = parser.parse_args()
    plot_distribution(args.input)