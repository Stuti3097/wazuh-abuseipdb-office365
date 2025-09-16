#!/var/ossec/framework/python/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.

import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception as e:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        with open(log_file, "a") as f:
            f.write(msg)

def collect(data):
    abuse_confidence_score = data['abuseConfidenceScore']
    country_code = data['countryCode']
    usage_type = data['usageType']
    isp = data['isp']
    domain = data['domain']
    total_reports = data['totalReports']
    last_reported_at = data['lastReportedAt']
    return abuse_confidence_score, country_code, usage_type, isp, domain, total_reports, last_reported_at

def in_database(data, srcip):
    return data['totalReports'] > 0

def query_api(srcip, apikey):
    params = {'maxAgeInDays': '90', 'ipAddress': srcip}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        'Accept': 'application/json',
        "Key": apikey
    }
    response = requests.get('https://api.abuseipdb.com/api/v2/check', params=params, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        return json_response["data"]
    else:
        alert_output = {
            "abuseipdb": {
                "error": response.status_code,
                "description": response.json().get("errors", [{}])[0].get("detail", "Unknown error")
            },
            "integration": "custom-abuseipdb"
        }
        send_event(alert_output)
        sys.exit(0)

def request_abuseipdb_info(alert, apikey):
    alert_output = {}

    # Try to get the source IP from the default field
    srcip = alert.get("data", {}).get("srcip")

    # If not found, try Office 365 fields
    office365_data = alert.get("data", {}).get("office365", {})
    if not srcip and office365_data:
        srcip = office365_data.get("ClientIPAddress") or office365_data.get("ClientIP")

    if not srcip:
        debug("# No source IP found, exiting.")
        return 0

    # Request info using AbuseIPDB API
    data = query_api(srcip, apikey)

    # Build alert output
    alert_output["abuseipdb"] = {}
    alert_output["integration"] = "custom-abuseipdb"
    alert_output["abuseipdb"]["found"] = 0
    alert_output["abuseipdb"]["source"] = {
        "alert_id": alert.get("id", "0"),
        "rule": alert.get("rule", {}).get("id", "0"),
        "description": alert.get("rule", {}).get("description", ""),
        "full_log": alert.get("full_log", ""),
        "srcip": srcip
    }

    # If AbuseIPDB has info, populate
    if in_database(data, srcip):
        alert_output["abuseipdb"]["found"] = 1
        abuse_confidence_score, country_code, usage_type, isp, domain, total_reports, last_reported_at = collect(data)
        alert_output["abuseipdb"].update({
            "abuse_confidence_score": abuse_confidence_score,
            "country_code": country_code,
            "usage_type": usage_type,
            "isp": isp,
            "domain": domain,
            "total_reports": total_reports,
            "last_reported_at": last_reported_at
        })

    debug(alert_output)
    return alert_output

def send_event(msg, agent=None):
    if not agent or agent.get("id") == "000":
        string = '1:abuseipdb:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->abuseipdb:{3}'.format(
            agent.get("id"),
            agent.get("name"),
            agent.get("ip", "any"),
            json.dumps(msg)
        )

    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

def main(args):
    global debug_enabled

    if len(args) < 3:
        debug("# Usage: script.py <alert_file> <api_key> [debug]")
        sys.exit(1)

    alert_file_location = args[1]
    apikey = args[2]
    debug_enabled = (len(args) > 3 and args[3] == 'debug')

    debug(f"# File location: {alert_file_location}")
    debug(f"# API Key: {apikey}")

    # Load JSON alert
    with open(alert_file_location) as alert_file:
        # For multiple JSON objects per file, parse first non-empty line
        for line in alert_file:
            line = line.strip()
            if line:
                json_alert = json.loads(line)
                break

    debug("# Processing alert")
    debug(json_alert)

    # Request AbuseIPDB info
    msg = request_abuseipdb_info(json_alert, apikey)

    # Send event to Wazuh manager if AbuseIPDB found info
    if msg:
        send_event(msg, json_alert.get("agent"))

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(str(e))
        raise

