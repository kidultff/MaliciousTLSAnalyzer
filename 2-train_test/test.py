import pickle
import _dataset
import numpy as np
import os

all_data = _dataset.read_all_csv('./pcap_csvs_new')
all_Y = all_data['label']
all_X = all_data.drop(labels='label', axis=1)

with open('model.pickle', 'rb') as f:
    model = pickle.load(f)
    y_ = model.predict(all_X)
    print(np.sum(np.abs(y_ - all_Y)))
    print(model.score(all_X, all_Y))