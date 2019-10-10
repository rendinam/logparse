#!/usr/bin/env python3

import os
import sys
import re
from glob import glob
import pickle
import argparse
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
import urllib.request
from urllib.error import HTTPError
import yaml


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


def main():
    ap = argparse.ArgumentParser(
            prog='logparse.py',
            description='Parse and digest apache/nginx access logs in either'
            ' raw or .gz format.')
    ap.add_argument('dataset_name', type=str,
                    help='Name of dataset file. If file does not exist and'
                    ' log data file names are provided for parsing, this '
                    'file will be created.')
    ap.add_argument('--config',
                    '-c',
                    help='Configuration file used to adjust behavior of the '
                    'program',
                    required=True)
    ap.add_argument('--files',
                    '-f',
                    help='List of log files to parse, raw or .gz are accepted.'
                    ' glob syntax is also honored.',
                    nargs='+')
    ap.add_argument('--window',
                    '-w',
                    help='Restrict examination of data to the window of dates'
                    ' provided.\n'
                    ' Format: YYYY.MM.DD-YYYY.MM.DD'
		    ' Omitting a date window will operate on all data contained'
		    ' within the given dataset.')
    ap.add_argument('--ignorehosts',
                    '-i',
                    help='IP addresses of hosts to ignore when parsing logs.'
                    ' Useful for saving time by not reading in transactions '
                    'from security scans, etc.',
                    nargs='+')
    args = ap.parse_args()

    # Dataset filename
    dataset_name = args.dataset_name

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    files = []
    try:
        for filespec in args.files:
            expanded =  glob(filespec)
            expanded.sort()
            if isinstance(expanded, list):
                for name in expanded:
                    files.append(name)
            else:
                files.append(expanded)
    except(TypeError):
        print('No log files provided.')
        print(f'Importing existing dataset {dataset_name}.')
        pass

    inf_hosts = config['infrastructure_hosts']
    num_inf_hosts = len(inf_hosts)

    # TODO: Should host filtering take place here?
    #       It leaves a disconnect between the pickled data which _may_ have
    #       been culled and the actual data being referenced.
    logproc = LogData(dataset_name, ignore_hosts=args.ignorehosts)
    logproc.read_logs(files)

    print('writing (potentially updated) dataset')
    logproc.write_dataset()

    # Filtering and analysis begins here
    data = logproc.data
    print(f'num full data rows = {len(data.index)}')

    # Filter out a particular time period for examination
    # Set limits on a time period to examine
    if args.window:
        start = args.window.split('-')[0].replace('.', '-')
        end = args.window.split('-')[1].replace('.', '-')
        window_start = pd.to_datetime(start)
        window_end = pd.to_datetime(end)
        print(f'Filtering based on window {window_start} - {window_end}.')
        data = data[pd.to_datetime(data['date']) >= window_start]
        data = data[pd.to_datetime(data['date']) <= window_end]
        print(f'num windowed data rows = {len(data.index)}')

    all_unique_hosts = list(set(data['ipaddress']))
    #for host in all_unique_hosts:
    #    try:
    #        print(f'{host} {socket.gethostbyaddr(host)[0]}')
    #    except:
    #        print(f'{host} offline?')

    # All packages in a dictionary by channel.
    chans = [path.split('/')[1] for path in data['path']]
    chans = list(set(chans))
    chans.sort()
    chan_pkgs = OrderedDict()
    for chan in chans:
        # Trailing '/' added to ensure only a single channel gets stored for each
        # due to matching overlap depending on length of substring.
        chan_pkgs[chan] = data[data['path'].str.contains(chan+'/')]

    total_downloads = 0
    for chan in chan_pkgs.keys():
        total_downloads += len(chan_pkgs[chan].index)
    print(f'TOTAL downloads = {total_downloads}')

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

        start_date = dates[0]
        end_date = dates[-1]
        time_range = end_date - start_date
        days_elapsed = time_range.days
        if days_elapsed == 0:
            days_elapsed = 1
        print(f'\nOver the period {start_date.strftime("%m-%d-%Y")} '
              f'to {end_date.strftime("%m-%d-%Y")}')
        print(f'{days_elapsed} days')

        # Downloads per day over time frame
        for date in dates:
            bydate[date] = len(pkgs[pkgs['date'] == date])

        chan_downloads = len(pkgs.index)
        print(f'Downloads: {chan_downloads}')

        print(f'Average downloads per day: {ceil(chan_downloads / days_elapsed)}')

        # Total bandwidth consumed by this channel's use over time frame.
        bytecount = pkgs['size'].sum()
        gib = bytecount / 1e9
        print(f'Channel bytecount = {bytecount}')

        # Number of unique hosts and geographic location
        unique_hosts = set(pkgs['ipaddress'])
        num_unique_hosts = len(unique_hosts)
        print(f'Unique hosts {num_unique_hosts}')

        ## Unique packages
        unique_pkgs = set(pkgs['path'])
        print(f'Unique full package names {len(unique_pkgs)}')

        # What is the fraction of downloads for each OS?
        num_linux_txns = len(pkgs[pkgs['path'].str.contains('linux-64')].index)
        num_osx_txns = len(pkgs[pkgs['path'].str.contains('osx-64')].index)
        pcnt_linux_txns = (num_linux_txns / float(chan_downloads))*100
        pcnt_osx_txns = (num_osx_txns / float(chan_downloads))*100

        # What fraction of total downloads come from non-infrastructure on-site hosts?
        noninf = pkgs[~pkgs['ipaddress'].isin(config['infrastructure_hosts'])]
        total_noninf = len(noninf.index)
        print(f'Non-infrastructure downloads: {total_noninf}')
        print(f'Percentage noninf downloads: {(total_noninf/chan_downloads)*100:.1f}%')

        # What fraction of total downloads come from off-site hosts?
        int_host_patterns = ['^'+s for s in config['internal_host_specs']]
        offsite = pkgs[~pkgs['ipaddress'].str.contains(
            '|'.join(int_host_patterns), regex=True)]
        num_offsite_hosts = len(set(offsite['ipaddress']))
        print(f'num unique off-site hosts: {num_offsite_hosts}')
        onsite = pkgs[pkgs['ipaddress'].str.contains(
            '|'.join(int_host_patterns), regex=True)]
        num_onsite_hosts = len(set(onsite['ipaddress']))
        print(f'num unique on-site hosts: {num_onsite_hosts}')

        infra = pkgs[pkgs['ipaddress'].str.contains('|'.join(inf_hosts))]

        # Totals of unique software titles
        # i.e. name without version, hash, py or build iteration values
        # Extract simple package titles from 'path' column of data frame.
        names = list(pkgs['name'])
        unique_names = list(set(names))
        name_statsums = []
        for name in unique_names:
            statsum = {}
            statsum['name'] = name
            statsum['total'] = names.count(name)
            # Sum on- and off-site transactions for each package name
            # 'on-site' means transactions to non-infrastructure hosts.
            name_txns = pkgs[pkgs['name'] == name]

            on_txns = name_txns[name_txns['ipaddress'].str.contains(
            '|'.join(int_host_patterns), regex=True)]
            # Filter out hosts designated as infrastructure hosts in config file.
            on_txns = on_txns[~on_txns['ipaddress'].str.contains(
            '|'.join(inf_hosts))]

            num_onsite_txns = len(on_txns.index)
            statsum['onsite'] = num_onsite_txns

            off_txns = name_txns[~name_txns['ipaddress'].str.contains(
            '|'.join(int_host_patterns), regex=True)]
            num_offsite_txns = len(off_txns.index)
            statsum['offsite'] = num_offsite_txns

            infra_txns = name_txns[name_txns['ipaddress'].str.contains(
            '|'.join(inf_hosts))]
            num_infra_txns = len(infra_txns.index)
            statsum['infra'] = num_infra_txns

            ## Determine which packages are also available via PyPI
            url = f'https://pypi.org/pypi/{name}/json'
            try:
                rq = urllib.request.urlopen(url)
                #pl = f.read().decode('utf-8')
                #piinfo = json.loads(pl)
                statsum['pypi'] = True
            except(HTTPError):
                statsum['pypi'] = False
            #statsum['pypi'] = False

            name_statsums.append(statsum)

        name_statsums.sort(key=lambda x: x['total'], reverse=True)
        x_onsite = [i['onsite'] for i in name_statsums]
        x_infra = [i['infra'] for i in name_statsums]
        x_offsite = [i['offsite'] for i in name_statsums]
        y = [i['name'] for i in name_statsums]

        print(f'Number of unique {chan} titles downloaded: {len(unique_names)}')
        # For each unique softare name, sum the number of transactions from internal hosts.
        fig, axes = plt.subplots(figsize=(10,25))
        plt.grid(which='major', axis='x')
        plt.title(f'{chan} -- {start_date.strftime("%m-%d-%Y")} - {end_date.strftime("%m-%d-%Y")}')
        plt.xlabel('Downloads')
        axes.set_ylim(-1,len(name_statsums))
        axes.tick_params(labeltop=True)

        plt.gca().invert_yaxis()
        width = 1
        from operator import add
        barlists = []
        # Horizontal stacked bar chart with off-site, on-site, and infrastructure transactions.
        barlists.append(axes.barh(y, x_offsite, width, edgecolor='white', color='tab:blue'))
        barlists.append(axes.barh(y, x_onsite, width, left=x_offsite, edgecolor='white', color='tab:green'))
        # Sum bars up to this point to correctly stack the subsequent one(s).
        offset = list(map(add, x_offsite, x_onsite))
        barlists.append(axes.barh(y, x_infra, width, left=offset, edgecolor='white', color='tab:olive'))

        for i,statsum in enumerate(name_statsums):
            if statsum['pypi'] == True:
                axes.get_yticklabels()[i].set_color('orange')
                axes.get_yticklabels()[i].set_weight('bold')

        # Annotate plot with additional stats
        props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
        plural = ''
        if days_elapsed > 1:
            plural = 's'
        stats_text = (f'{days_elapsed} day{plural}\n'
                     f'Total Downloads: {chan_downloads}\n'
                     f'Average downloads per day: {ceil(chan_downloads / days_elapsed)}\n'
                     f'Unique titles: {len(unique_names)}\n'
                     f'Data transferred: {gib:.2f} GiB\n'
                     f'Linux transactions: {pcnt_linux_txns:.1f}%\n'
                     f'Macos transactions: {pcnt_osx_txns:.1f}%\n'
                     f'Unique on-site hosts: {num_onsite_hosts}\n'
                     f'Unique off-site hosts: {num_offsite_hosts}\n')
        axes.text(0.45, 0.05, stats_text, transform=axes.transAxes, fontsize=14, bbox=props)
        axes.legend(['off-site', 'on-site', 'on-site infrastructure'])

        plt.tight_layout()
        short_startdate = start_date.strftime('%Y%m%d')
        short_enddate = end_date.strftime('%Y%m%d')
        plt.savefig(f'{chan}-{short_startdate}-{short_enddate}.png')


if __name__ == "__main__":
    main()

