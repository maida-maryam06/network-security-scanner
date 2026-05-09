from flask import Flask, request, jsonify
from flask_cors import CORS
import nmap
import socket
import re

app = Flask(__name__)
CORS(app)

# ── Helpers ────────────────────────────────────────────────────

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 5900: "VNC",
    161: "SNMP", 389: "LDAP", 636: "LDAPS",
}

def resolve_host(target):
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None

def validate_ip_or_host(target):
    target = target.strip()
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
    host_pattern = re.compile(r'^[a-zA-Z0-9\-\.]+$')
    if ip_pattern.match(target) or host_pattern.match(target):
        return True
    return False


# ── Routes ─────────────────────────────────────────────────────

@app.route('/scan', methods=['POST'])
def scan():
    data        = request.json
    target      = data.get('target', '').strip()
    scan_type   = data.get('scan_type', 'tcp_connect')
    port_range  = data.get('port_range', '1-1024')

    if not target:
        return jsonify({'error': 'Target IP or hostname is required.'}), 400
    if not validate_ip_or_host(target):
        return jsonify({'error': 'Invalid IP address or hostname.'}), 400

    # Resolve hostname to IP for display
    resolved_ip = resolve_host(target)
    if not resolved_ip:
        return jsonify({'error': f'Cannot resolve hostname: {target}'}), 400

    nm = nmap.PortScanner()

    # Build nmap arguments
    # Note: TCP SYN (-sS) requires admin/root on Windows. Fall back to TCP connect.
    scan_args = {
        'tcp_syn':     '-sS --open',        # requires admin
        'tcp_connect': '-sT --open',        # no admin needed
        'udp':         '-sU --open',        # requires admin
        'comprehensive': '-sT -sV --open',  # service version detection
    }

    args = scan_args.get(scan_type, '-sT --open')

    try:
        nm.scan(hosts=target, ports=port_range, arguments=args, timeout=120)
    except nmap.PortScannerError as e:
        err = str(e)
        if 'requires root' in err.lower() or 'winpcap' in err.lower() or 'npcap' in err.lower():
            return jsonify({
                'error': (
                    'This scan type requires Administrator privileges or Npcap. '
                    'Try "TCP Full Connect" which works without admin rights, '
                    'or run as Administrator.'
                )
            }), 403
        return jsonify({'error': f'Nmap error: {err}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    results = []
    all_hosts = nm.all_hosts()

    if not all_hosts:
        return jsonify({
            'target': target,
            'resolved_ip': resolved_ip,
            'scan_type': scan_type,
            'port_range': port_range,
            'results': [],
            'summary': 'Host appears to be down or all ports are filtered.'
        })

    for host in all_hosts:
        host_info = nm[host]
        hostname  = host_info.hostname() or target
        state     = host_info.state()

        for proto in host_info.all_protocols():
            ports = host_info[proto].keys()
            for port in sorted(ports):
                port_data  = host_info[proto][port]
                port_state = port_data.get('state', 'unknown')
                service    = port_data.get('name', '') or COMMON_SERVICES.get(port, 'Unknown')
                version    = port_data.get('version', '')
                product    = port_data.get('product', '')

                service_full = service
                if product:
                    service_full = f"{product} {version}".strip() if version else product

                results.append({
                    'ip':       host,
                    'hostname': hostname,
                    'port':     port,
                    'protocol': proto.upper(),
                    'service':  service_full or 'Unknown',
                    'status':   port_state,
                    'risk':     assess_risk(port, service)
                })

    return jsonify({
        'target':      target,
        'resolved_ip': resolved_ip,
        'scan_type':   scan_type,
        'port_range':  port_range,
        'results':     results,
        'summary':     f'{len(results)} open port(s) found on {resolved_ip}'
    })


def assess_risk(port, service):
    """Simple risk assessment based on port/service."""
    high_risk = {21, 23, 445, 3389, 5900, 161, 23}
    med_risk  = {22, 25, 110, 143, 3306, 5432, 6379, 27017, 389}
    low_risk  = {80, 8080}
    safe      = {443, 8443}

    s = service.lower()
    if port in high_risk or 'telnet' in s or 'ftp' in s or 'rdp' in s or 'vnc' in s:
        return 'HIGH'
    if port in med_risk or 'mysql' in s or 'redis' in s or 'mongo' in s:
        return 'MEDIUM'
    if port in safe or 'https' in s:
        return 'LOW'
    if port in low_risk or 'http' in s:
        return 'MEDIUM'
    return 'LOW'


# ── Firewall Simulation ────────────────────────────────────────

firewall_rules = []

@app.route('/firewall/rules', methods=['GET'])
def get_rules():
    return jsonify({'rules': firewall_rules})

@app.route('/firewall/rules', methods=['POST'])
def add_rule():
    data     = request.json
    action   = data.get('action', 'deny').lower()
    ip       = data.get('ip', '').strip()
    port     = data.get('port', '').strip()
    protocol = data.get('protocol', 'TCP').upper()
    priority = data.get('priority', len(firewall_rules) + 1)

    if not ip:
        return jsonify({'error': 'IP or subnet is required.'}), 400
    if action not in ('allow', 'deny'):
        return jsonify({'error': 'Action must be allow or deny.'}), 400

    rule = {
        'id':       len(firewall_rules) + 1,
        'priority': int(priority),
        'action':   action,
        'ip':       ip,
        'port':     port or 'Any',
        'protocol': protocol,
    }
    firewall_rules.append(rule)
    firewall_rules.sort(key=lambda r: r['priority'])

    return jsonify({'message': 'Rule added.', 'rule': rule, 'rules': firewall_rules})

@app.route('/firewall/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    global firewall_rules
    firewall_rules = [r for r in firewall_rules if r['id'] != rule_id]
    return jsonify({'message': 'Rule deleted.', 'rules': firewall_rules})

@app.route('/firewall/rules', methods=['DELETE'])
def clear_rules():
    global firewall_rules
    firewall_rules = []
    return jsonify({'message': 'All rules cleared.'})

@app.route('/firewall/simulate', methods=['POST'])
def simulate():
    """
    Given scan results and current firewall rules, determine
    which traffic would be allowed or blocked.
    """
    data    = request.json
    packets = data.get('packets', [])   # list of {ip, port, protocol}

    if not packets:
        return jsonify({'error': 'No packets to simulate.'}), 400
    if not firewall_rules:
        return jsonify({'error': 'No firewall rules defined.'}), 400

    results = []
    for pkt in packets:
        pkt_ip   = pkt.get('ip', '')
        pkt_port = str(pkt.get('port', ''))
        pkt_proto= pkt.get('protocol', 'TCP').upper()

        verdict = 'ALLOW'   # default: allow if no rule matches
        matched_rule = None

        # Evaluate rules in priority order
        for rule in sorted(firewall_rules, key=lambda r: r['priority']):
            # IP match: exact or wildcard (*)
            ip_match   = (rule['ip'] == '*' or rule['ip'] == pkt_ip or pkt_ip.startswith(rule['ip'].rstrip('*')))
            # Port match
            port_match = (rule['port'] == 'Any' or rule['port'] == '' or str(rule['port']) == pkt_port)
            # Protocol match
            proto_match= (rule['protocol'] == 'ANY' or rule['protocol'] == pkt_proto)

            if ip_match and port_match and proto_match:
                verdict      = rule['action'].upper()
                matched_rule = rule
                break   # first matching rule wins (priority-based)

        results.append({
            'ip':           pkt_ip,
            'port':         pkt_port,
            'protocol':     pkt_proto,
            'service':      pkt.get('service', 'Unknown'),
            'verdict':      verdict,
            'matched_rule': matched_rule,
        })

    allowed = sum(1 for r in results if r['verdict'] == 'ALLOW')
    blocked = sum(1 for r in results if r['verdict'] == 'DENY')

    return jsonify({
        'results': results,
        'summary': {'allowed': allowed, 'blocked': blocked, 'total': len(results)}
    })


if __name__ == '__main__':
    app.run(debug=True, port=5001)
