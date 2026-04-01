import re
import json
import time
import os
import syslog
from datetime import datetime

INPUT_LOG = '/var/log/conpot.log'

def parse_line(line):
    entry = {}
    ts_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)', line)
    if ts_match:
        entry['conpot_timestamp'] = ts_match.group(1)

    if 'Modbus traffic from' in line:
        ip_match = re.search(r'Modbus traffic from (\d+\.\d+\.\d+\.\d+)', line)
        fc_match = re.search(r"'function_code': (\w+)", line)
        req_match = re.search(r"'request': b'([^']+)'", line)
        entry['event_type'] = 'modbus_traffic'
        entry['srcip'] = ip_match.group(1) if ip_match else 'unknown'
        entry['function_code'] = fc_match.group(1) if fc_match else 'unknown'
        entry['raw_request'] = req_match.group(1) if req_match else ''
        return entry

    if 'Modbus connection terminated' in line:
        ip_match = re.search(r'terminated with client (\d+\.\d+\.\d+\.\d+)', line)
        entry['event_type'] = 'modbus_terminated'
        entry['srcip'] = ip_match.group(1) if ip_match else 'unknown'
        return entry

    if 'New s7comm session from' in line:
        ip_match = re.search(r'New s7comm session from (\d+\.\d+\.\d+\.\d+)', line)
        entry['event_type'] = 's7comm_session'
        entry['srcip'] = ip_match.group(1) if ip_match else 'unknown'
        return entry

    if 'bad magic number' in line:
        ip_match = re.search(r'remote: (\d+\.\d+\.\d+\.\d+)', line)
        entry['event_type'] = 's7comm_bad_magic'
        entry['srcip'] = ip_match.group(1) if ip_match else 'unknown'
        return entry

    if 'New http session from' in line:
        ip_match = re.search(r'New http session from (\d+\.\d+\.\d+\.\d+)', line)
        entry['event_type'] = 'http_session'
        entry['srcip'] = ip_match.group(1) if ip_match else 'unknown'
        return entry

    if 'HTTP/1.1 GET request from' in line:
        ip_match = re.search(r"GET request from \('(\d+\.\d+\.\d+\.\d+)'", line)
        path_match = re.search(r"\('(/[^']*)'", line)
        ua_match = re.search(r"'User-Agent', '([^']+)'", line)
        entry['event_type'] = 'http_get_request'
        entry['srcip'] = ip_match.group(1) if ip_match else 'unknown'
        entry['path'] = path_match.group(1) if path_match else '/'
        entry['user_agent'] = ua_match.group(1) if ua_match else 'unknown'
        return entry

    return None

def main():
    syslog.openlog("conpot-enriched", syslog.LOG_PID, syslog.LOG_LOCAL0)
    print(f"[*] Starting enricher, monitoring {INPUT_LOG}")

    # Track file position
    inode = os.stat(INPUT_LOG).st_ino
    f = open(INPUT_LOG, 'r')
    f.seek(0, 2)  # seek to end

    while True:
        try:
            # Check if file was rotated
            try:
                new_inode = os.stat(INPUT_LOG).st_ino
                if new_inode != inode:
                    f.close()
                    f = open(INPUT_LOG, 'r')
                    inode = new_inode
            except:
                pass

            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            line = line.strip()
            if not line:
                continue

            entry = parse_line(line)
            if entry:
                log_line = json.dumps(entry)
                syslog.syslog(syslog.LOG_INFO, log_line)
                print(f"[+] {entry.get('event_type')} from {entry.get('srcip')}", flush=True)

        except Exception as e:
            print(f"[!] Error: {e}", flush=True)
            time.sleep(1)

if __name__ == '__main__':
    main()
