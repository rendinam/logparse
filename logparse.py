#!/usr/bin/env python3

import re
import gzip
import socket
import pandas as pd
import datetime as dt
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# Notes
# df.to_pickle(filename) for serializing a pandas data frame to disk.
# df.read_pickle(filename) to get it back.

# regex pattern to extract key values from each line of an apache/nginx access log
# Accommodate PUTs as well as second URLs (normally "-")
patt = '(?P<ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}) - - \\[(?P<date>\\d{2}\\/[a-zA-Z]{3}\\/\\d{4}):(?P<time>\\d{2}:\\d{2}:\\d{2}) (\\+|\\-)\\d{4}] ("(GET|POST|PUT) )(?P<path>.*?) HTTP/1.1" (?P<status>\\d*) \\d* ".*" "(?P<agent>.*)"'
        
p = re.compile(patt)

columns = {
        'ipaddress': {},
        'date': {},
        'time': {},
        'path': {},
        'status': {},
        'agent': {},
       }

df = pd.DataFrame(columns)

#files = [
#        'astroconda_access.log'
#        ]

files = [
        'ssb.stsci.edu.access.log-20190715.gz',
        #'ssb.stsci.edu.access.log-20190716.gz',
        #'ssb.stsci.edu.access.log-20190717.gz',
        #'ssb.stsci.edu.access.log-20190718.gz',
        #'ssb.stsci.edu.access.log-20190719.gz',
        #'ssb.stsci.edu.access.log-20190720.gz',
        #'ssb.stsci.edu.access.log-20190721.gz',
        #'ssb.stsci.edu.access.log-20190722.gz',
        #'ssb.stsci.edu.access.log',
        ]

# Addresses for hosts that should be ignored, such
# as those from which security scan connections come.
ignore_address = '10.128.19.7'  # Security scan host.


class logData():

    def __init__(self, hostnames=False):
        self.columns = {
                'ipaddress': {},
                'hostname': {},
                'date': {},
                'time': {},
                'path': {},
                'status': {},
                'agent': {},
               }
        self.df = pd.DataFrame(columns)
        self.digest_path = 'digests'


    def process_lines(f):
        for line in f.readlines():
            try:
                line = str(line.decode("utf-8"))
            except(AttributeError):
                pass
            if ignore_address in line:
                continue
            try:
                match = p.match(line)
            except:
                pass
            ipaddress = match.group('ipaddress')
            date = match.group('date')
            time = match.group('time')
            path = match.group('path')
            status = match.group('status')
            agent = match.group('agent')
            # Selective polling of hostnames here.
            hostname = '?'
            self.df = df.append({'ipaddress':ipaddress,
                            'hostname':hostname,
                            'date':date,
                            'time':time,
                            'path':path, 
                            'status':status, 
                            'agent':agent}, ignore_index=True)
        return(df)
    
    
    def digest_log(logfile):
        '''Read in either a text log file or a gzipped log file, extract key values
        and store them in a pandas data frame, which is returned.'''
        if '.gz' in fname:
            with gzip.open(fname, 'r') as f:
                df = process_lines(df, f)
        else:
            with open(fname, 'r') as f:
                df = process_lines(df, f)
        return(df)
    
    
    def read_logs(logs):
        '''Accepts:
        a pandas dataframe to which the log data will be appended.
    
        a list of apache/nginx access log files, either raw or .gz,
        and parses each that does not already have a corresponding digested
        data frame in the 'digests' subdir.'''
    
        # Create data frame for receiving log data
        columns = {
                'ipaddress': {},
                'hostname': {},
                'date': {},
                'time': {},
                'path': {},
                'status': {},
                'agent': {},
               }
        dframe = pd.DataFrame(columns)
    
        # Sort list of logs before processing so data will be appended in
        # chronological order.
        for log in logs:
            print(log)
            setname = re.sub(log, '\.gz$', '')
            try:
                dframe = pd.read_pickle(f'digests/{setname}')
            except(FileNotFoundError):
                if '.gz' in log:
                    with gzip.open(log, 'r') as f:
                        dframe = process_lines(df, f)
                else:
                    with open(log, 'r') as f:
                        dframe = process_lines(df, f)
            dframe.append(df, ignore_index=True)
        return(dframe)
        

"""
# If a stored data frame already exists, load it, otherwise set about
# parsing the log files and creating one.
try:
    print('Looking for pickled data frame...')
    raise(FileNotFoundError)
    #pkg_txns = pd.read_pickle('data.pkl')
    #pkg_txns = pd.read_pickle('astroconda.org.pkl')
except(FileNotFoundError):
    # iterate over log files and read in values to a master data frame.
    for fname in files:
        print(fname)
        if '.gz' in fname:
            with gzip.open(fname, 'r') as f:
                df = process_lines(df, f)
        else:
            with open(fname, 'r') as f:
                df = process_lines(df, f)
    
    # Create frame with only package downloads from conda.
    
    # Conda transactions
    conda_txns = df.loc[df['agent'].str.contains('conda')]
    
    # Package transactions
    pkg_txns = conda_txns.loc[conda_txns['path'].str.contains('bz2')]
    pkg_txns = pkg_txns.loc[pkg_txns['status'].str.contains('200')]


df = pkg_txns

# Of package downloads, compile a list of downloads/day

totals = []
dates = list(set(df['date']))
dates.sort()
x = [dt.datetime.strptime(d, '%d/%b/%Y').date() for d in dates]
y = []
print(f'length of x list {len(x)}')
for date in dates:
    num = len(pkg_txns[pkg_txns.date == date])
    total = {date:num}
    totals.append(total)
    y.append(num)

#plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%m/%d/%Y'))
#plt.gca().xaxis.set_major_locator(mdates.DayLocator())
#plt.gca().xaxis.set_major_locator(mdates.DayLocator(interval=7))
plt.plot(x,y)
plt.figure(figsize=(2,2))
plt.savefig('astroconda_org.png')
##plt.show()
###plt.gcf().autofmt_xdate()

internal = pkg_txns[pkg_txns.ipaddress.str.startswith('10.') | pkg_txns.ipaddress.str.startswith('172.')]
external = pkg_txns[~(pkg_txns.ipaddress.str.startswith('10.') | pkg_txns.ipaddress.str.startswith('172.'))]


    


def downloads_by_host(downloads):
    '''Show hostnames of all currently online hosts whose address appears in
    the logs.'''
    dls_by_host = []
    for addy in set(downloads.ipaddress):
        tmp = {}
        pkgs = downloads.path[downloads.ipaddress == addy]
        tmp['ipaddress'] = addy
        tmp['downloads'] = len(pkgs)
        path = pkgs.iloc[0]  # Assuming all packages requested by a given host are for the same platform.
        if 'linux-64' in path:  # index here is not the right way to do it
            tmp['os'] = 'linux'
        elif 'osx-64' in path:
            tmp['os'] = 'osx'
        else:
            tmp['os'] = 'os?'
        try:
            tmp['hostname'] = socket.gethostbyaddr(addy)[0]
            #tmp['hostname'] = '?'
        except:
            tmp['hostname'] = 'Not online?'
        dls_by_host.append(tmp)
    return(dls_by_host)

internal_by_host = downloads_by_host(internal)
internal_by_host = sorted(internal_by_host, key = lambda k: k['downloads'])
internal_by_host.reverse()
print('Internal')
for host in internal_by_host:
    print(f"{host['downloads']:<6} {host['ipaddress']:<17} {host['os']:<5} {host['hostname']}")


external_by_host = downloads_by_host(external)
external_by_host = sorted(external_by_host, key = lambda k: k['downloads'])
external_by_host.reverse()
print('External')
for host in external_by_host:
    print(f"{host['downloads']:<6} {host['ipaddress']:<17} {host['os']:<5} {host['hostname']}")
"""
