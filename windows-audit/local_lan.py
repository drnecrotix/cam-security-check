"""Discover active physical Ethernet IPv4 networks on Windows."""
import ipaddress
import json
import os
import subprocess


POWERSHELL = (
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    "Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' -and "
    "($_.MediaType -match '802.3|Ethernet') } | ForEach-Object { "
    "$a=$_; Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | "
    "Where-Object { $_.AddressState -eq 'Preferred' } | ForEach-Object { "
    "[PSCustomObject]@{Name=$a.Name; IP=$_.IPAddress; Prefix=$_.PrefixLength} "
    "} } | ConvertTo-Json -Compress"
)


def parse_adapters(output):
    records = json.loads(output) if output.strip() else []
    if isinstance(records, dict):
        records = [records]
    found = []
    for record in records:
        try:
            ip = ipaddress.ip_address(record['IP'])
            network = ipaddress.ip_network(f"{ip}/{int(record['Prefix'])}", strict=False)
            if (ip.version == 4 and ip.is_private and not ip.is_loopback and not ip.is_link_local
                    and not ip.is_reserved and network.num_addresses <= 256):
                found.append((str(record['Name']), str(ip), str(network)))
        except (ValueError, KeyError, TypeError):
            continue
    return found


def ethernet_networks():
    if os.name != 'nt':
        raise RuntimeError('Автоматичното откриване на LAN е само за Windows.')
    try:
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', POWERSHELL],
                                capture_output=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError('Windows не върна информация за Ethernet адаптера.')
        networks = parse_adapters(result.stdout.decode('utf-8-sig', errors='replace'))
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        raise RuntimeError('Не мога да открия LAN мрежата автоматично.') from error
    if not networks:
        raise RuntimeError('Няма активен физически Ethernet адаптер с частен IPv4 адрес и мрежа до /24.')
    return networks
