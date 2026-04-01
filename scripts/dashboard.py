from flask import Flask, render_template_string
import subprocess
import re
from collections import defaultdict
from datetime import datetime

app = Flask(__name__)

def get_logs():
    result = subprocess.run(
        ['docker', 'logs', 'conpot'],
        capture_output=True, text=True
    )
    return result.stdout + result.stderr

def parse_logs(logs):
    data = {
        'total_sessions': 0,
        'total_timeouts': 0,
        'ip_counts': defaultdict(int),
        'protocol_counts': defaultdict(int),
        'recent_events': [],
        'http_requests': [],
        'modbus_requests': []
    }

    for line in logs.splitlines():
        # Count sessions
        if 'New http session' in line:
            data['total_sessions'] += 1
            data['protocol_counts']['HTTP'] += 1
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                data['ip_counts'][ip.group(1)] += 1

        elif 'New modbus session' in line or 'modbus request' in line.lower():
            data['total_sessions'] += 1
            data['protocol_counts']['Modbus'] += 1
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                data['ip_counts'][ip.group(1)] += 1

        elif 'New s7comm session' in line:
            data['total_sessions'] += 1
            data['protocol_counts']['S7Comm'] += 1
            ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip:
                data['ip_counts'][ip.group(1)] += 1

        elif 'Session timed out' in line:
            data['total_timeouts'] += 1

        # HTTP requests
        if 'HTTP/' in line and 'GET' in line or 'POST' in line:
            ip = re.search(r"from \('(\d+\.\d+\.\d+\.\d+)'", line)
            path = re.search(r"'(\/[^']*)'", line)
            ts = line[:23] if len(line) > 23 else ''
            if ip:
                data['http_requests'].append({
                    'time': ts,
                    'ip': ip.group(1),
                    'path': path.group(1) if path else '/'
                })

    # Top 10 IPs
    data['top_ips'] = sorted(
        data['ip_counts'].items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]

    # Filter out internal IPs from top IPs display
    data['top_ips'] = [
        (ip, count) for ip, count in data['top_ips']
        if not ip.startswith('127.') and not ip.startswith('0.')
    ]

    # Recent HTTP requests (last 20)
    data['http_requests'] = data['http_requests'][-20:]

    return data

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Conpot Honeypot Dashboard</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: monospace; background: #0d0d0d; color: #00ff41; margin: 0; padding: 20px; }
        h1 { color: #00ff41; border-bottom: 1px solid #00ff41; padding-bottom: 10px; }
        h2 { color: #ffaa00; margin-top: 30px; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }
        .card { background: #1a1a1a; border: 1px solid #00ff41; padding: 20px; text-align: center; }
        .card .number { font-size: 2em; color: #00ff41; font-weight: bold; }
        .card .label { color: #888; font-size: 0.85em; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { background: #1a1a1a; color: #ffaa00; padding: 8px; text-align: left; border: 1px solid #333; }
        td { padding: 8px; border: 1px solid #222; color: #ccc; }
        tr:hover { background: #1a1a1a; }
        .bar { background: #00ff41; height: 16px; display: inline-block; }
        .updated { color: #555; font-size: 0.8em; margin-top: 20px; }
        .tag { background: #1a1a1a; border: 1px solid #ffaa00; color: #ffaa00; 
               padding: 2px 8px; margin: 2px; display: inline-block; font-size: 0.85em; }
    </style>
</head>
<body>
    <h1>Conpot ICS Honeypot — Live Dashboard</h1>
    <p>Monitoring: 68.183.111.107 &nbsp;|&nbsp; Auto-refreshes every 30 seconds</p>

    <div class="grid">
        <div class="card">
            <div class="number">{{ data.total_sessions }}</div>
            <div class="label">Total Sessions</div>
        </div>
        <div class="card">
            <div class="number">{{ data.total_timeouts }}</div>
            <div class="label">Timed Out Sessions</div>
        </div>
        <div class="card">
            <div class="number">{{ data.top_ips|length }}</div>
            <div class="label">Unique Source IPs</div>
        </div>
        <div class="card">
            <div class="number">{{ data.http_requests|length }}</div>
            <div class="label">Recent HTTP Requests</div>
        </div>
    </div>

    <h2>Protocol Distribution</h2>
    <table>
        <tr><th>Protocol</th><th>Connections</th><th>Distribution</th></tr>
        {% for proto, count in data.protocol_counts.items() %}
        <tr>
            <td>{{ proto }}</td>
            <td>{{ count }}</td>
            <td><span class="bar" style="width: {{ [count * 10, 400]|min }}px"></span></td>
        </tr>
        {% endfor %}
    </table>

    <h2>Top Source IPs</h2>
    <table>
        <tr><th>IP Address</th><th>Connections</th><th>Activity</th></tr>
        {% for ip, count in data.top_ips %}
        <tr>
            <td>{{ ip }}</td>
            <td>{{ count }}</td>
            <td><span class="bar" style="width: {{ [count * 20, 400]|min }}px"></span></td>
        </tr>
        {% endfor %}
    </table>

    <h2>Recent HTTP Requests</h2>
    <table>
        <tr><th>Timestamp</th><th>Source IP</th><th>Path</th></tr>
        {% for req in data.http_requests %}
        <tr>
            <td>{{ req.time }}</td>
            <td>{{ req.ip }}</td>
            <td>{{ req.path }}</td>
        </tr>
        {% endfor %}
    </table>

    <p class="updated">Last updated: {{ updated }}</p>
</body>
</html>
"""

@app.route('/')
def index():
    logs = get_logs()
    data = parse_logs(logs)
    updated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    return render_template_string(TEMPLATE, data=data, updated=updated)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False)
