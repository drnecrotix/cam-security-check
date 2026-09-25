"""Bounded local ONVIF WS-Discovery and Windows neighbor inventory."""
import ipaddress
import json
import os
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


def discover_onvif(network, timeout=3):
    subnet = ipaddress.ip_network(network, strict=False)
    if subnet.version != 4 or not subnet.is_private or subnet.num_addresses > 256:
        raise ValueError('Only a private IPv4 LAN up to /24 is allowed.')
    probe = (f'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
             f'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
             f'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
             f'<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>'
             f'<a:MessageID>urn:uuid:{uuid.uuid4()}</a:MessageID>'
             f'<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>'
             f'<s:Body><d:Probe/></s:Body></s:Envelope>').encode()
    results = set()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.settimeout(0.3)
        sock.sendto(probe, ('239.255.255.250', 3702))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data, source = sock.recvfrom(65535)
                address = ipaddress.ip_address(source[0])
                if address not in subnet:
                    continue
                root = ET.fromstring(data)
                for element in root.iter():
                    if element.tag.endswith('}XAddrs') and element.text:
                        for uri in element.text.split():
                            parsed = urlparse(uri)
                            try:
                                if (parsed.scheme in ('http', 'https') and
                                        ipaddress.ip_address(parsed.hostname) == address):
                                    results.add((str(address), parsed.port or (443 if parsed.scheme == 'https' else 80)))
                            except (ValueError, TypeError):
                                continue
            except socket.timeout:
                continue
            except (OSError, ET.ParseError):
                continue
    return sorted(results, key=lambda row: (ipaddress.ip_address(row[0]), row[1]))


def parse_neighbors(data, network):
    subnet = ipaddress.ip_network(network, strict=False)
    records = json.loads(data) if data.strip() else []
    if isinstance(records, dict):
        records = [records]
    results = set()
    for item in records:
        try:
            ip = ipaddress.ip_address(item['IPAddress'])
            mac = str(item.get('LinkLayerAddress') or '').strip()
            state = str(item.get('State') or '')
            if ip.version == 4 and ip in subnet and mac and state not in ('Unreachable', 'Incomplete'):
                results.add((str(ip), mac))
        except (ValueError, KeyError, TypeError):
            continue
    return sorted(results, key=lambda row: ipaddress.ip_address(row[0]))


def windows_neighbors(network):
    if os.name != 'nt':
        return []
    command = ('[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; '
               'Get-NetNeighbor -AddressFamily IPv4 | '
               'Select-Object IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress')
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', command],
                                capture_output=True, timeout=8)
        if result.returncode == 0:
            return parse_neighbors(result.stdout.decode('utf-8-sig', errors='replace'), network)
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        pass
    return []
