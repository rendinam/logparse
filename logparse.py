#!/usr/bin/env python3

import os
import sys
import re
from glob import glob
import argparse
from math import ceil
import gzip
import socket
import pandas as pd
import datetime as dt
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from dateutil import parser as dpar
from collections import OrderedDict

# regex pattern to extract key values from each line of an apache/nginx access log
# Accommodate PUTs as well as second URLs (normally "-")
patt = '(?P<ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) .* .* \\[(?P<date>\\d{2}\\/[a-zA-Z]{3}\\/\\d{4}):(?P<time>\\d{2}:\\d{2}:\\d{2}) (\\+|\\-)\\d{4}] ".* (?P<path>.*?) .*" (?P<status>\\d*) \\d* ".*" "(?P<agent>.*)"'
        
p = re.compile(patt)


class logData():

    def __init__(self,
                 gethostnames=False,
                 ignore_hosts=[]):
        self.columns = {
                'ipaddress': {},
                'hostname': {},
                'date': {},
                'time': {},
                'path': {},
                'status': {},
                'agent': {},
               }
        self.dframe = pd.DataFrame(self.columns)
        self.digest_path = 'digests'
        self.gethostnames = gethostnames
        self.ignore_hosts = ignore_hosts

    def process_lines(self, f):
        print('process lines')
        df = pd.DataFrame(self.columns)
        unparseable = 0
        for line in f.readlines():
            print(line)
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
                continue
            try:
                match = p.match(line)
            except:
                line_errors += 1
                pass
            print(match)
            try:
                ipaddress = match.group('ipaddress')
                date = match.group('date')
                dateobj = dpar.parse(date)
                time = match.group('time')
                path = match.group('path')
                status = match.group('status')
                agent = match.group('agent')
            except(AttributeError):
                unparseable += 1
            # Selective polling of hostnames here.
            hostname = '?'
            df = df.append({'ipaddress':ipaddress,
                            'hostname':hostname,
                            'date':dateobj,
                            'time':time,
                            'path':path, 
                            'status':status, 
                            'agent':agent}, ignore_index=True)
        print(f'unparseable lines : {unparseable}')
        return(df)
    
    def read_logs(self, logs):
        '''Accepts:
    
        a list of apache/nginx access log files, either raw or .gz,
        and parses each that does not already have a corresponding digested
        data frame in the 'digests' subdir.'''
    
        # Create data frame for receiving log data
        df = pd.DataFrame(self.columns)
        locframe = pd.DataFrame(self.columns)
    
        # Sort list of logs before processing so data will be appended in
        # chronological order.
        for log in sorted(logs):
            setname = re.sub('\.gz$', '', log)
            setpath = os.path.join(self.digest_path, setname)
            pklpath = os.path.join(self.digest_path, f'{setname}.pkl')
            print(f'ingesting dataset = {setname}')
            if os.path.isfile(pklpath):
                df = pd.read_pickle(pklpath)
            else:
                print('parsing log file')
                if '.gz' in log:
                    with gzip.open(log, 'r') as f:
                        df = self.process_lines(f)
                else:
                    with open(log, 'r') as f:
                        df = self.process_lines(f)
                print(f'df shape = {df.shape}')
            # Dump digested log data to disk for more efficient repeated use.
            df.to_pickle(f'{setpath}.pkl')
            locframe = locframe.append(df, ignore_index=True)
            print(locframe.shape)
        return(locframe)



def filter_pkgs(df):
    '''Filter dataframe df down to just the rows the represent
    successful (HTTP 200) conda package (.bz2 files) downloads.'''
    inlen = len(df)
    out = df.loc[df['agent'].str.contains('conda')]
    print(out)
    out = out.loc[out['path'].str.contains('bz2')]
    out = out.loc[out['status'].str.contains('200')]
    outlen = len(out)
    print(f'{inlen-outlen} rows removed to leave conda txns only')
    return(out)




def main():
    ap = argparse.ArgumentParser(
            prog='logparse.py',
            description='Parse and digest apache/nginx access logs in either'
            ' raw or .gz format.')
    ap.add_argument('--files',
                    '-f',
                    help='List of log files to parse, raw or .gz are accepted.'
                    ' glob syntax is also honored.',
                    nargs='+')
    ap.add_argument('--ignorehosts',
                    '-i',
                    help='IP addresses of hosts to ignore when parsing logs.'
                    ' Useful for saving time by not reading in transactions '
                    'from security scans, etc.',
                    nargs='+')
    args = ap.parse_args()

    files = []
    for filespec in args.files:
        expanded =  glob(filespec)
        expanded.sort()
        if isinstance(expanded, list):
            for name in expanded:
                files.append(name)
        else:
            files.append(expanded)

    # TODO: Should host filtering take place here?
    #       It leaves a disconnect between the pickled data which _may_ have been
    #       culled and the actual data being referenced by the inclusion of a file
    #       that has data from an exluded host within it.
    logproc = logData(ignore_hosts=args.ignorehosts)
    data = logproc.read_logs(files)

    allpkgs = filter_pkgs(data)
    allpkgs = allpkgs.sort_values(by='date')

    start_date = allpkgs.iloc[0]['date']
    end_date = allpkgs.iloc[-1]['date']
    time_range = end_date - start_date
    days_elapsed = time_range.days
    if days_elapsed == 0:
        days_elapsed = 1
    
    print(f'Over the period {start_date.strftime("%m-%d-%Y")} '
          f'to {end_date.strftime("%m-%d-%Y")}')
    print(f'{days_elapsed} days')

    # Normalize all conda-dev channel names to astroconda-dev
    allpkgs = allpkgs.replace('/conda-dev', '/astroconda-dev', regex=True)

    # All packages in a dictionary by channel.
    chans = [path.split('/')[1] for path in allpkgs['path']]
    chans = set(chans)
    chan_pkgs = {}
    for chan in chans:
        # Trailing '/' added to ensure only a single channel gets stored for each
        # due to matching overlap depending on length of substring.
        chan_pkgs[chan] = allpkgs[allpkgs['path'].str.contains(chan+'/')]

    # For each channel, generate summary report of the download activity.
    for chan in chan_pkgs.keys():
        print(f'\n\nSummary for channel: {chan}')
        print('-----------------------------')

        pkgs = chan_pkgs[chan]
        # Unique days
        dates = set(pkgs['date'])
        dates = list(dates)
        dates.sort()
        bydate = OrderedDict()

        # Downloads per day over time frame
        for date in dates:
            bydate[date] = len(pkgs[pkgs['date'] == date])
        #for date in bydate:
        #    print(f'{date} : {bydate[date]}')

        total_downloads = len(pkgs.index)
        print(f'Total downloads: {total_downloads}')
        # Downloads per week over time frame

        print(f'Average downloads per day: {ceil(total_downloads / days_elapsed)}')

        # Number of unique hosts and geographic location
        unique_hosts = set(pkgs['ipaddress'])
        print(f'Unique hosts {len(unique_hosts)}')

        ## Unique packages
        unique_pkgs = set(pkgs['path'])
        print(f'Unique packages {len(unique_pkgs)}')

        # Totals of unique package files
        #pkg_totals = []
        #for pkg in unique_pkgs:
        #    total = len(pkgs[pkgs['path'] == pkg].index)
        #    pkg_totals.append([pkg, total])
        #pkg_totals.sort(key=lambda x: x[1], reverse=True)
        #if len(unique_pkgs) > 5:
        #    top = 10
        #else:
        #    top = len(unique_pkgs)
        #print(f'Top {top} {chan} package filenames:')
        #for i in range(top):
        #    print(pkg_totals[i])

        # Totals of unique software names
        # i.e. name without version, hash, py or build iteration values
        # Extract simple package titles from 'path' column of data frame.
        names = pkgs['path'].str.replace('/.*/.*/', '', regex=True)
        repl = lambda m: m.group('simplename')
        names = list(names.str.replace('(?P<simplename>.*)-.*-.*\.tar\.bz2$',
                repl,
                regex=True))
        unique_names = set(names)
        print(f'Number of unique {chan} titles downloaded: {len(unique_names)}')
        name_totals = []
        for name in unique_names:
            total = names.count(name)
            name_totals.append([name, total])
        name_totals.sort(key=lambda x: x[1], reverse=True)
        for total in name_totals:
            print(f'{total[0]}: {total[1]}')


if __name__ == "__main__":
    main()

