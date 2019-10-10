#!/usr/bin/env python3
# Used to merge old-format pickled dataset and separate log file hashes
# into the newer joined format.

import pickle
import pandas as pd

datfile = 'dataframe.dat'
hashfile = 'parsed_files.dat'

# Read dataframe
frame = pd.read_pickle(datfile)

# Read MD5 list
with open(hashfile, 'r') as f:
    hashes = f.readlines()

# Store both in a dict and pickle that dict.
data = {'file_hashes': hashes,
        'dataframe': frame}

print(data)
print('Pickling dict...')
pickle.dump(data, open('data.p', 'wb'))
