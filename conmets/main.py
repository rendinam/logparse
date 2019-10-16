import argparse
from conmets.conmets import *
import yaml
import urllib.request
from urllib.error import HTTPError

def main():
    ap = argparse.ArgumentParser(
            prog='conmets',
            description='Parse and digest apache/nginx access logs in either'
            ' raw or .gz format and produce conda package download stats '
            'summaries.')
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
        days_elapsed += 1
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
        print(f'Data transferred: {gib:.2f} GiB')

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
        plt.title(f'{chan} -- {start_date.strftime("%Y%m%d")} - {end_date.strftime("%Y%m%d")}')
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
                     f'Unique off-site hosts: {num_offsite_hosts}\n\n'
                     f'   Orange titles are available on PyPI.')
        axes.text(0.45, 0.05, stats_text, transform=axes.transAxes, fontsize=14, bbox=props)
        axes.legend(['off-site', 'on-site', 'on-site infrastructure'])

        plt.tight_layout()
        short_startdate = start_date.strftime('%Y%m%d')
        short_enddate = end_date.strftime('%Y%m%d')
        plt.savefig(f'{chan}-{short_startdate}-{short_enddate}.png')
