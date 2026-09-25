"""Bounded, single-host ONVIF and RTSP port discovery."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket

from audit import DEV, call

DEFAULT_PORTS = '80,554,8000,8080,8081,8899,9000'


def parse_ports(value):
    ports = set()
    for part in value.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            bounds = part.split('-')
            if len(bounds) != 2:
                raise ValueError('Невалиден диапазон от портове.')
            start, end = map(int, bounds)
            if end < start or end - start > 31:
                raise ValueError('Един диапазон може да съдържа най-много 32 порта.')
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or len(ports) > 32 or any(not 1 <= x <= 65535 for x in ports):
        raise ValueError('Въведи от 1 до 32 порта между 1 и 65535.')
    return sorted(ports)


def probe(ip, port):
    with socket.create_connection((ip, port), timeout=1.2) as sock:
        sock.settimeout(1.2)
        sock.sendall(f'OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n'.encode('ascii'))
        response = sock.recv(128)
    return response.startswith(b'RTSP/')


def check(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.7):
            pass
    except OSError:
        return None
    url = f'http://{ip}:{port}/onvif/device_service'
    result = call(url, f'<d:GetCapabilities xmlns:d="{DEV}"><d:Category>All</d:Category></d:GetCapabilities>', 1.2)
    if result['ok']:
        service = 'ONVIF - достъп без парола'
    elif result['status'] in (401, 403) or result['error'] == 'SOAP Fault':
        service = 'ONVIF - вероятно изисква удостоверяване'
    else:
        try:
            service = 'RTSP' if probe(ip, port) else 'Отворен порт - непозната услуга'
        except OSError:
            service = 'Отворен порт - непозната услуга'
    return (str(ip), port, service)


def scan_hosts(addresses, ports):
    if len(addresses) > 254 or len(ports) > 32 or len(addresses) * len(ports) > 2048:
        raise ValueError('Най-много 254 адреса, 32 порта и 2048 проверки наведнъж.')

    results = []
    with ThreadPoolExecutor(max_workers=64) as executor:
        for future in as_completed([executor.submit(check, ip, p) for ip in addresses for p in ports]):
            result = future.result()
            if result:
                results.append(result)
    return sorted(results, key=lambda row: (ipaddress.ip_address(row[0]), row[1]))


def scan(ip, ports):
    return scan_hosts([ip], ports)
