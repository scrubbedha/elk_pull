#!/usr/bin/env python3
import json
import os
import argparse
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError

# Configurable Variables
output_dir = "/var/esgrep-scratch"
auth_file = os.path.expanduser("~/.elk.auth")
last_server_cache_file = os.path.expanduser("~/.last_elk")

server_pattern = "elk-es%02d.us-midwest-1.int.local"
server_count = 17
port = 9200

# Necessary Global Variables
query_file = os.path.join(output_dir, "query.json")
active_index = ""

# Read basic auth credentials from auth_file
with open(auth_file, "r") as f:
    auth_credentials = f.read().strip().split(":")

# Define Elasticsearch configuration with basic auth
es = Elasticsearch(
    ["https://{}:{}@{}:{}".format(auth_credentials[0], auth_credentials[1], server_pattern % i, port) for i in range(1, server_count + 1)]
)
index = 'index'
scroll_time = '1m'


def query_index(server, output_file, index, start_time, end_time, host, logs, domains, containers):
    try:
        # Check if the server is up by performing a health check
        es.cluster.health(wait_for_status='yellow')
    except ConnectionError:
        print('Server {} is down'.format(server))
        return 1

    print('Running query on {}...'.format(server))

    # Construct Elasticsearch query
    query = built_query(index, start_time, end_time, host, logs, domains, containers)

    # Execute Elasticsearch scroll query
    response = es.search(
        index=index,
        scroll=scroll_time,
        body=json.dumps(query)  # Convert query dictionary to JSON object
    )

    # Parse Elasticsearch response with Python json
    scroll_id = response['_scroll_id']
    hits_count = len(response['hits']['hits'])
    message = '\n'.join([hit['_source']['message'] for hit in response['hits']['hits']])

    with open(output_file, 'a') as f:
        f.write(message)

    print('Done')

    # Execute additional scroll queries if necessary
    scroll_count = 0
    while hits_count > 0 and scroll_id is not None:
        print('{} scroll {}...'.format(index, scroll_count + 1))

        response = es.scroll(
            scroll_id=scroll_id,
            scroll=scroll_time
        )

        scroll_id = response['_scroll_id']
        hits_count = len(response['hits']['hits'])
        message = '\n'.join([hit['_source']['message'] for hit in response['hits']['hits']])

        with open(output_file, 'a') as f:
            f.write(message)

        scroll_count += 1

    print('Done')

    # Clear scroll ID
    es.clear_scroll(scroll_id=scroll_id)

    return 0


def built_query(index, start_time, end_time, host, logs, domains, containers):
    must_conditions = [
        {"wildcard": {"host.name": host + "*"}},
        {"range": {"@timestamp": {"lte": end_time, "gte": start_time}}}
    ]

    if logs:
        path_conditions = []
        for log in logs.split(","):
            if log in ["apf_log", "clamd", "cron", "freshclam", "kern", "maillog", "messages", "secure", "spooler", "mysqld"]:
                path_conditions.append({"term": {"log.file.path": "/var/log/" + log}})
            elif log in ["fail2ban", "procreaper", "sftp", "yum"]:
                path_conditions.append({"term": {"log.file.path": "/var/log/" + log + ".log"}})
            elif log in ["send", "smtp", "smtp2"]:
                path_conditions.append({"term": {"log.file.path": "/var/log/" + log + "/current"}})
            elif log == "modsec_debug":
                path_conditions.append({"term": {"log.file.path": "/var/log/httpd/modsec_debug.log"}})
            elif log == "audit":
                path_conditions.append({"term": {"log.file.path": "/var/log/audit/audit.log"}})
            elif log in ["proftpd_auth", "proftpd_sftp", "proftpd_tls", "proftpd_xfer"]:
                path_conditions.append({"term": {"log.file.path": "/var/log/" + log.replace("_", "/") + ".log"}})
            elif log == "web.all":
                path_conditions.append({"regexp": {"log.file.path": "/(home/.*/var|var/log/interworx)/.*/logs/.*log"}})
            else:
                if index == "container":
                    must_conditions.append({"term": {"container": log}})
                else:
                    path_conditions.append({"regexp": {"log.file.path": "/(home/.*/var|var/log/interworx)/" + log + "/logs/.*log"}})

        if path_conditions:
            must_conditions.append({"bool": {"should": path_conditions}})

    if domains:
        domain_conditions = []
        for domain in domains.split(","):
            domain_conditions.append({"wildcard": {"log.file.path": "*/" + domain + "/logs/*"}})

        if domain_conditions:
            must_conditions.append({"bool": {"should": domain_conditions}})

    if containers:
        container_conditions = []
        for container in containers.split(","):
            container_conditions.append({"wildcard": {"log.file.path": "*/" + container + "/logs/*"}})

        if container_conditions:
            must_conditions.append({"bool": {"should": container_conditions}})

    query = {
        "size": 10000,
        "query": {
            "bool": {
                "filter": [
                    {
                        "bool": {
                            "must": must_conditions
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ]
    }

    return query


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Utility to simplify retrieval of log data from elk.")
    parser.add_argument("-i", "--index", help="Comma separated list of indices to open.", required=True)
    parser.add_argument("-H", "--host", help="int.local or int.local prefix to retrieve logs for.", required=True)
    parser.add_argument("-s", "--start", help="Mandatory. Start day or only day that you want log data for. Must be in the format of YYYY-MM-DD.", required=True)
    parser.add_argument("-e", "--end", help="Optional. Last day of logs to retrieve. Must be in the format of YYYY-MM-DD.")
    parser.add_argument("-l", "--logs", help="Comma separated list of logs to retrieve. Currently only valid values are: apf_log, audit, clamd, cron, fail2ban, freshclam, modsec_debug, kern, maillog, messages, mysqld, procreaper, proftpd_auth, proftpd_sftp, proftpd_tls, proftpd_xfer, secure, send, sftp, smtp2, smtp, spooler, yum.")
    parser.add_argument("-d", "--domains", help="Mandatory for webtransfer and weberror. Comma separated list of domains to retrieve log data for when pulling from webtransfer or weberror indices.")
    parser.add_argument("-c", "--containers", help="Mandatory for container index. Comma separated list of containers to retrieve log data for.")
    parser.add_argument("-t", "--ticket", help="Ticket number to use for subdirectory name that logs should be placed in.", required=True)
    args = parser.parse_args()

    output_dir = os.path.join(output_dir, str(args.ticket))
    if args.logs:
        output_dir = os.path.join(output_dir, args.logs.strip('*'))

    if args.domains:
        output_file = os.path.join(output_dir, "{}.log".format(args.domains.replace("*", "")))
    else:
        output_file = os.path.join(output_dir, "{}.log".format(args.host.split("-")[0]))

    query = built_query(args.index, args.start, args.end, args.host, args.logs, args.domains, args.containers)
    server = "elk-es01.us-midwest-1.int.local"
    #output_file = os.path.join(output_dir, args.index, "{}.log".format(args.host))
    print('Output going to {}...'.format(output_file))
