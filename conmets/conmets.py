#!/usr/bin/env python3
import os
import sys
import re
from glob import glob
import pickle
from math import ceil
import hashlib
import gzip
import socket
import pandas as pd
import datetime as dt
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from dateutil import parser as dpar
from collections import OrderedDict


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


# regex pattern to extract key values from each line of an apache/nginx access log
# Accommodate PUTs as well as second URLs (normally "-")
patt = '(?P<ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) .* .* \\[(?P<date>\\d{2}\\/[a-zA-Z]{3}\\/\\d{4}):(?P<time>\\d{2}:\\d{2}:\\d{2}) (\\+|\\-)\\d{4}] ".* (?P<path>.*?) .*" (?P<status>\\d*) (?P<size>\\d*)'
        
logpattern = re.compile(patt)

class LogData():

    columns = {
        'ipaddress': {},
        'hostname': {},
        'date': {},
        'time': {},
        'path': {},
        'status': {},
        'size': {},
        'name': {}, # derived
    }

    def __init__(self,
                 dataset_name,
                 gethostnames=False,
                 ignore_hosts=[]):
        '''dataset is a dict
            dataframe - pandas dataframe containing digested log data
            file_hashes - MD5 hashes of each file that was read to compose the dataframe'''
        self.dataset_name = dataset_name
        self.dataset = None
        self.data = None
        self.digest_path = 'digests'
        self.gethostnames = gethostnames
        self.hostnames = {}
        self.ignore_hosts = ignore_hosts

        try:
            print('reading dataset...')
            with open(self.dataset_name, 'rb')  as f:
                self.dataset = pickle.load(f)
        except:
            print(f'{self.dataset_name} not found. Creating empty dataset.')
            with open(self.dataset_name, 'a') as f:
                self.dataset = {'dataframe':pd.DataFrame(self.columns),
                                'file_hashes': []}
        self.data = self.dataset['dataframe']
        self.hashes = self.dataset['file_hashes']

    def poll_hostnames(self):
        if ipaddress not in self.hostnames.keys():
            try:
                hostname = socket.gethostbyaddr(ipaddress)
            except:
                hostname = 'offline'
            self.hostnames[ipaddress] = hostname
        else:
            hostname = self.hostnames[ipaddress]

    def process_lines(self, f):
        df = pd.DataFrame(self.columns)
        unparseable = 0
        for line in f.readlines():
            try:
                line = str(line.decode("utf-8"))
            except(AttributeError):
                pass
            # Ignore transactions from particular IP addresses as requested.
            try:
                for host in self.ignore_hosts:
                    if host in line:
                        continue
            except(TypeError):
                pass

            try:
                match = logpattern.match(line)
                #print(f'logpattern.match(line): {match}')
            except:
                line_errors += 1
                print(f'Line parse error: {line}')
                continue
            try:
                ipaddress = match.group('ipaddress')
                date = match.group('date')
                dateobj = dpar.parse(date)
                time = match.group('time')
                path = match.group('path')

                # Extract simple package titles from 'path' column of data frame.
                patt0 = re.compile('/.*/.*/')
                patt1 = re.compile('(?P<simplename>.*)-.*-.*\.tar\.bz2$')
                tarball = re.sub(patt0, '', path)
                namematch = patt1.match(tarball)
                name = namematch.group('simplename')
                status = match.group('status')
                size = int(match.group('size'))
                hostname = ''
                df = df.append({'ipaddress':ipaddress,
                                'hostname':hostname,
                                'date':dateobj,
                                'time':time,
                                'path':path,
                                'status':status,
                                'size':size,
                                'name':name},
                                ignore_index=True)
            except(AttributeError):
                unparseable += 1
        print(f'unparseable lines : {unparseable}')
        return(df)
    
    def read_logs(self, logs):
        '''Accepts:
    
        a list of apache/nginx access log files, either raw or .gz,
        and parses each that has not already been ingested.'''
    
        # Create data frame for receiving all log data.
        newdata = pd.DataFrame(self.columns)

        for log in sorted(logs):
            # Compute MD5 hash of file and compare to list of files that
            # have already been parsed. If new, parse, if not, skip.
            hashval = md5(log)
            if hashval in self.hashes:
                print(f'File {log} already parsed.')
                continue
            df = pd.DataFrame(self.columns)
            setname = re.sub('\.gz$', '', log)
            setpath = os.path.join(self.digest_path, setname)
            pklpath = os.path.join(self.digest_path, f'{setname}.pkl')
            print(f'Reading log file {log}...')
            if '.gz' in log:
                with gzip.open(log, 'r') as f:
                    df = self.process_lines(f)
            else:
                with open(log, 'r') as f:
                    df = self.process_lines(f)
            print(f'Added {df.index} transations to dataset. {newdata.shape} for this session.')
            newdata = newdata.append(df, ignore_index=True)
            print(newdata.shape)
            self.hashes.append(hashval)

        # If any new log files were read, filter down to only conda package downloads
        # Then sort by date.
        if len(newdata.index) != 0:
            newdata = self.filter_pkgs(newdata)
            newdata = newdata.sort_values(by='date')
            newdata = newdata.drop_duplicates()
            # Normalize any 'conda-dev' channel names to 'astroconda-dev'
            newdata = newdata.replace('/conda-dev', '/astroconda-dev', regex=True)
            # Add newdata to (potentially empty) existing data
            self.data = self.data.append(newdata, ignore_index=True)
            self.dataset['dataframe'] = self.data

    def filter_pkgs(self, df):
        '''Filter dataframe df down to just the rows the represent
        successful (HTTP 200) conda package (.bz2 files) downloads.'''
        inlen = len(df)
        out = df.loc[df['path'].str.contains('bz2')]
        out = out.loc[(out['status'] == '200') | (out['status'] == '302')]
        outlen = len(out)
        print(f'{inlen-outlen} rows removed to leave conda txns only')
        return(out)

    def write_dataset(self, dataset_name=None):
        '''Serialize working dataset and write it to disk using a filename
        provided, if requested.

	Parameters
	----------
	dataset_name : string
	    Optional name to use for file when writing working dataset to disk.
	    If not provided, the current name of the working dataset file will
            be used.'''
        if dataset_name:
            dsname = dataset_name
        else:
            dsname = self.dataset_name
        pickle.dump(self.dataset, open(dsname, 'wb'))

