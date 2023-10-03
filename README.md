# Python Log Retrieval Script

This is a Python script that allows for retrieval of log data from an Elasticsearch cluster. The script takes various input parameters through command-line arguments and performs an Elasticsearch query to fetch the desired logs.

## Prerequisites

- Python 3
- `elasticsearch` library
- Elasticsearch cluster with valid authentication credentials
- Basic knowledge of Elasticsearch query syntax

## Usage

### Setup

1. Install the necessary libraries by running the following command:
   ```
   pip install elasticsearch
   ```

2. Update the configurable variables in the script according to your environment:
   - `output_dir`: The directory to store the retrieved logs.
   - `auth_file`: The file containing the authentication credentials for Elasticsearch.
   - `last_server_cache_file`: The file to cache the last Elasticsearch server used.
   - `server_pattern`: The pattern used to generate the Elasticsearch server URLs.
   - `server_count`: The number of Elasticsearch servers in the cluster.
   - `port`: The port number used to access Elasticsearch.

### Running the Script

To retrieve logs from the Elasticsearch cluster, use the following command-line arguments:

```
usage: elkpull.py [-h] -i INDEX -H HOST -s START [-e END] [-l LOGS] [-d DOMAINS] [-c CONTAINERS] -t TICKET

Utility to simplify retrieval of log data from elk.

optional arguments:
  -h, --help            show this help message and exit
  -i INDEX, --index INDEX
                        Comma separated list of indices to open.
  -H HOST, --host HOST  Hostname or hostname prefix to retrieve logs for.
  -s START, --start START
                        Mandatory. Start day or only day that you want log data for. Must
                        be in the format of YYYY-MM-DD.
  -e END, --end END     Optional. Last day of logs to retrieve. Must be in the format
                        of YYYY-MM-DD.
  -l LOGS, --logs LOGS  Comma separated list of logs to retrieve. Currently only valid values
                        are: apf_log, audit, clamd, cron, fail2ban, freshclam,
                        modsec_debug, kern, maillog, messages, mysqld, procreaper,
                        proftpd_auth, proftpd_sftp, proftpd_tls, proftpd_xfer, secure,
                        send, sftp, smtp2, smtp, spooler, yum.
  -d DOMAINS, --domains DOMAINS
                        Mandatory for webtransfer and weberror. Comma separated
                        list of domains to retrieve log data for when pulling from webtransfer
                        or weberror indices.
  -c CONTAINERS, --containers CONTAINERS
                        Mandatory for container index. Comma separated list of containers
                        to retrieve log data for.
  -t TICKET, --ticket TICKET
                        Ticket number to use for subdirectory name that logs should be placed in.
```

Ensure that the Elasticsearch cluster and authentication credentials in the `auth_file` are properly configured.

## Note

This script relies on the `elasticsearch` library to connect and query the Elasticsearch cluster. It is important to handle sensitive information, such as authentication credentials and output directories, with caution and ensure appropriate permissions are set.
