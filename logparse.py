#!/usr/bin/env python3

import os
import sys
import re
from glob import glob
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

class logData():

    columns = {
        'ipaddress': {},
        'hostname': {},
        'date': {},
        'time': {},
        'path': {},
        'status': {},
        'name': {}, # derived
    }

    def __init__(self,
                 gethostnames=False,
                 ignore_hosts=[]):
        self.digest_path = 'digests'
        self.gethostnames = gethostnames
        self.hostnames = {}
        self.ignore_hosts = ignore_hosts

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
        print('process lines')
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
                print(f'logpattern.match(line): {match}')
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
                hostname = ''
                df = df.append({'ipaddress':ipaddress,
                                'hostname':hostname,
                                'date':dateobj,
                                'time':time,
                                'path':path,
                                'status':status,
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
        locframe = pd.DataFrame(self.columns)

        # Track which files have been parsed by storing the MD5 hash of each
        # once it's been read.
        pfile = 'parsed_files.dat'
        if not os.path.exists(pfile):
            open(pfile, 'a').close()
        with open(pfile, 'r') as f:
            already_parsed = f.read().split()
        parsed = open(pfile, 'a')

        for log in sorted(logs):
            # Compute MD5 hash of file and compare to list of files that
            # have already been parsed. If new, parse, if not, skip.
            hashval = md5(log)
            if hashval in already_parsed:
                print(f'File {log} already parsed.')
                continue
            df = pd.DataFrame(self.columns)
            setname = re.sub('\.gz$', '', log)
            setpath = os.path.join(self.digest_path, setname)
            pklpath = os.path.join(self.digest_path, f'{setname}.pkl')
            print(f'ingesting dataset = {setname}')
            if '.gz' in log:
                with gzip.open(log, 'r') as f:
                    df = self.process_lines(f)
            else:
                with open(log, 'r') as f:
                    df = self.process_lines(f)
            print(f'df shape = {df.shape}')
            locframe = locframe.append(df, ignore_index=True)
            print(locframe.shape)
            parsed.write(f'{hashval}\n')

        parsed.close()
        return(locframe)



def filter_pkgs(df):
    '''Filter dataframe df down to just the rows the represent
    successful (HTTP 200) conda package (.bz2 files) downloads.'''
    print(df)
    inlen = len(df)
    out = df.loc[df['path'].str.contains('bz2')]
    out = out.loc[(out['status'] == '200') | (out['status'] == '302')]
    outlen = len(out)
    print(f'{inlen-outlen} rows removed to leave conda txns only')
    return(out)



def main():
    # TODO: Allow specification of a digested data file with fallback to a default.
    ap = argparse.ArgumentParser(
            prog='logparse.py',
            description='Parse and digest apache/nginx access logs in either'
            ' raw or .gz format.')
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
                    ' Format: YYYY.MM.DD-YYYY.MM.DD')
    ap.add_argument('--ignorehosts',
                    '-i',
                    help='IP addresses of hosts to ignore when parsing logs.'
                    ' Useful for saving time by not reading in transactions '
                    'from security scans, etc.',
                    nargs='+')
    args = ap.parse_args()

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
        pass

    inf_hosts = config['infrastructure_hosts']
    num_inf_hosts = len(inf_hosts)

    # Read in any pre-existing parsed data.
    datfile = 'dataframe.dat'
    if not os.path.exists(datfile):
        open(datfile, 'a').close()

    with open(datfile, 'r') as f:
        try:
            data = pd.read_pickle(datfile)
        except:
            data = pd.DataFrame(logData.columns)

    # TODO: Should host filtering take place here?
    #       It leaves a disconnect between the pickled data which _may_ have
    #       been culled and the actual data being referenced.
    logproc = logData(ignore_hosts=args.ignorehosts)
    newdata = logproc.read_logs(files)

    # If any new log files were read, filter down to only conda package downloads
    # Then sort by date.
    if len(newdata.index) != 0:
        newdata = filter_pkgs(newdata)
        newdata = newdata.sort_values(by='date')
        # Add newdata to existing data (potentially empty)
        data = data.append(newdata, ignore_index=True)
    print('.0')

    # Remove any duplicate rows in data:
    data = data.drop_duplicates()
    print('.2')

    # Normalize all conda-dev channel names to astroconda-dev
    data = data.replace('/conda-dev', '/astroconda-dev', regex=True)
    print(data)
    print('.3')

    # Dump data to disk for use during subsequent runs.
    data.to_pickle(datfile)

    print(f'num full data rows = {len(data.index)}')

    # Filter out a particular time period for examination
    window_start = pd.to_datetime('2019-09-15')
    window_end = pd.to_datetime('2019-09-21')
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
        # Downloads per week over time frame

        print(f'Average downloads per day: {ceil(chan_downloads / days_elapsed)}')

        # Number of unique hosts and geographic location
        unique_hosts = set(pkgs['ipaddress'])
        num_unique_hosts = len(unique_hosts)
        print(f'Unique hosts {num_unique_hosts}')

        ## Unique packages
        unique_pkgs = set(pkgs['path'])
        print(f'Unique full package names {len(unique_pkgs)}')

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

        # What is the fraction of downloads for each OS?

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

        # Fraction of downloads to off-site hosts

        # Totals of unique software titles
        # i.e. name without version, hash, py or build iteration values
        # Extract simple package titles from 'path' column of data frame.
        #names = pkgs['path'].str.replace('/.*/.*/', '', regex=True)
        #repl = lambda m: m.group('simplename')
        #names = list(names.str.replace('(?P<simplename>.*)-.*-.*\.tar\.bz2$',
        #        repl,
        #        regex=True))
        names = list(pkgs['name'])
        unique_names = list(set(names))
        name_statsums = []
        for name in unique_names:
            statsum = {}
            statsum['name'] = name
            statsum['total'] = names.count(name)

            # Sum on- and off-site transactions for each package name
            name_txns = pkgs[pkgs['name'] == name]

            on_txns = name_txns[name_txns['ipaddress'].str.contains(
            '|'.join(int_host_patterns), regex=True)]
            num_onsite_txns = len(on_txns.index)
            statsum['onsite'] = num_onsite_txns

            off_txns = name_txns[~name_txns['ipaddress'].str.contains(
            '|'.join(int_host_patterns), regex=True)]
            num_offsite_txns = len(off_txns.index)
            statsum['offsite'] = num_offsite_txns

            name_statsums.append(statsum)

        name_statsums.sort(key=lambda x: x['total'], reverse=True)
        y = []
        y = [i['total'] for i in name_statsums]
        y_onsite = [i['onsite'] for i in name_statsums]
        print(f'y_onsite: {y_onsite}')
        y_offsite = [i['offsite'] for i in name_statsums]
        print(f'y_offisite: {y_offsite}')
        x = [i['name'] for i in name_statsums]
        print('name_statsums')
        print(name_statsums)

        # Calculate fractions of properties of each unique package title
        #  for stacked bar plot purposes.


        print(f'Number of unique {chan} titles downloaded: {len(unique_names)}')
        # For each unique softare name, sum the number of transactions from internal hosts.
        width = 5.0
        fig, axes = plt.subplots(figsize=(10,25))
        plt.grid(which='major', axis='x')
        plt.title(f'{start_date.strftime("%m-%d-%Y")} - {end_date.strftime("%m-%d-%Y")}')
        plt.xlabel('Number of downloads')
        axes.set_ylim(0,len(name_statsums))

        plt.gca().invert_yaxis()
        width = 1
        barlist = axes.barh(x, y_onsite, width, edgecolor='black')
        barlist = axes.barh(x, y_offsite, width, left=y_onsite, edgecolor='black')
        #for id in iraf_ids:
        #    barlist[id].set_color('grey')
        plt.tight_layout()
        plt.savefig(f'{chan}.png')


if __name__ == "__main__":
    main()

