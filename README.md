# conmets - Conda metrics

A tool for parsing web server log files in standard Apache/nginx format to extract and plot potentially interesting statistics, including package download frequencies, segmenting by package download destination, and calculation of bandwidth consumed.

## Configuration

An example YAML format config file is provided (`lpconfig.yml`) which may be edited to specify:
  * `infrastructure_hosts` - Which are IP addresses that will be classified as "infrastructure" hosts if they are found in the logs.
  * `internal_host_specs` - Regex expressions to classify certain IP addresses found in the log files as belonging to the 'internal network'. Downloads are grouped by internal and external hosts in the output plot(s).

## Usage:
Available options are described by:
```
$ conmets --help
usage: conmets [-h] --config CONFIG [--files FILES [FILES ...]]
               [--window WINDOW] [--ignorehosts IGNOREHOSTS [IGNOREHOSTS ...]]
               dataset_name

Parse and digest apache/nginx access logs in either raw or .gz format and
produce conda package download stats summaries.

positional arguments:
  dataset_name          Name of dataset file. If file does not exist and log
                        data file names are provided for parsing, this file
                        will be created.

optional arguments:
  -h, --help            show this help message and exit
  --config CONFIG, -c CONFIG
                        Configuration file used to adjust behavior of the
                        program
  --files FILES [FILES ...], -f FILES [FILES ...]
                        List of log files to parse, raw or .gz are accepted.
                        glob syntax is also honored.
  --window WINDOW, -w WINDOW
                        Restrict examination of data to the window of dates
                        provided. Format: YYYY.MM.DD-YYYY.MM.DD Omitting a
                        date window will operate on all data contained within
                        the given dataset.
  --ignorehosts IGNOREHOSTS [IGNOREHOSTS ...], -i IGNOREHOSTS [IGNOREHOSTS ...]
                        IP addresses of hosts to ignore when parsing logs.
                        Useful for saving time by not reading in transactions
                        from security scans, etc.
```
A dataset name is required. If no dataset of the given name exists, one will be created and populated with the data extracted from log files given by name via `--files`. Hashes of files are produced and stored upon reading log files so that files are not read multiple times such that the same glob expression may be used to select multiple log files and only new files will parsed and their data added to the datasaet. If log file names are not provided, the given dataset will simply be read and plots produced from the data it contains.

```
$ python setup.py install
$ conmets -c lpconfig.yml.example --files logfile-2019* dataset
```

## Output
One plot per conda channel identified in the web server transaction log will be produced summarizing the software titles downloaded, ordered by total transactions along with some other relevant statistics. Titles that are also available via PyPI are shown in bold orange text.
