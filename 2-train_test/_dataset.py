import pandas as pd
import os


def read_single_csv(path):
    col = range(618)[5:]
    if 'malware' not in path:
        return pd.read_csv(path, nrows=3000, skiprows=0, usecols=col)
    return pd.read_csv(path, skiprows=0, usecols=col)


def read_all_csv(d):
    chunk = []
    for root, dirs, files in os.walk(d):
        cnt = 0
        for file in files:
            print('reading file: ', file)
            chunk.append(read_single_csv(os.path.join(root, file)))
    return pd.concat(chunk)
