from sklearn.utils import shuffle
from sklearn import ensemble
from sklearn.model_selection import train_test_split
import pickle
import _dataset
import numpy as np
import csv

all_data = shuffle(_dataset.read_all_csv('../dataset/csvs/'))
all_Y = all_data['label']
all_X = all_data.drop(labels='label', axis=1)

print("length(X, Y)=", len(all_X), len(all_Y))
all_X = np.nan_to_num(all_X)
print(all_X)
print(all_Y)

X_train, X_test, y_train, y_test = train_test_split(all_X, all_Y, test_size=0.2)
model = ensemble.RandomForestClassifier(n_estimators=150, random_state=0, n_jobs=-1)
model.fit(X_train, y_train)

with open('model.h5', 'wb') as f:
    pickle.dump(model, f)

print(model.score(X_train, y_train))
print(model.score(X_test, y_test))

importances = model.feature_importances_

with open('feature_importance.csv', 'w', newline='') as c:
    f_csv = csv.writer(c)
    for i in range(len(importances)):
        f_csv.writerow((all_data.columns[i], importances[i]))
