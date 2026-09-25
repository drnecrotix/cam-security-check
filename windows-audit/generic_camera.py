#!/usr/bin/env python3
"""Single private-IP RTSP and HTTP audit for cameras without ONVIF."""
import argparse
import getpass
import ipaddress
import json
import sys
import urllib.error
import urllib.request
from audit import NoRedirect, rtsp_describe
from password_audit import assess
from reporting import checklist


def http_check(ip, port, timeout):
    url = f'http://{ip}:{port}/'
    request = urllib.request.Request(url, method='HEAD')
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def run(ip, http_port, rtsp_port, rtsp_path, timeout, credentials=None):
    address = ipaddress.ip_address(ip)
    if (address.version != 4 or not address.is_private or address.is_loopback or
            address.is_link_local or address.is_reserved or address.is_multicast):
        raise ValueError('Only a private LAN IPv4 address is accepted.')
    if any(not 1 <= port <= 65535 for port in (http_port, rtsp_port)) or not 0 < timeout <= 15:
        raise ValueError('Invalid port or timeout.')
    if rtsp_path and (not rtsp_path.startswith('/') or len(rtsp_path) > 256 or
                      any(c in rtsp_path for c in '\r\n?#@') or '..' in rtsp_path):
        raise ValueError('RTSP path must start with / and contain no query, credentials or traversal.')
    http_status = http_check(address, http_port, timeout)
    uri = f'rtsp://{address}:{rtsp_port}{rtsp_path}' if rtsp_path else None
    anonymous = rtsp_describe(uri, address, timeout) if uri else None
    authenticated = rtsp_describe(uri, address, timeout, credentials) if uri and credentials else None
    result = {'target': str(address), 'port': http_port, 'camera_type': 'RTSP/HTTP (non-ONVIF)',
              'http_status_generic': http_status, 'rtsp_port': rtsp_port, 'rtsp_path_supplied': bool(rtsp_path),
              'rtsp_describe': anonymous, 'authenticated_rtsp_describe': authenticated,
              'authenticated': bool(credentials),
              'password_assessment': assess(credentials[1], credentials[0]) if credentials else {'checked': False},
              'video_profiles': []}
    result['checklist'] = checklist(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ip')
    parser.add_argument('--http-port', type=int, default=80)
    parser.add_argument('--rtsp-port', type=int, default=554)
    parser.add_argument('--rtsp-path', default='')
    parser.add_argument('--timeout', type=float, default=4)
    parser.add_argument('--username')
    parser.add_argument('--password-stdin', action='store_true')
    args = parser.parse_args()
    if args.password_stdin and not args.username:
        parser.error('--password-stdin requires --username')
    credentials = ((args.username, sys.stdin.readline().rstrip('\r\n') if args.password_stdin else getpass.getpass())
                   if args.username else None)
    try:
        result = run(args.ip, args.http_port, args.rtsp_port, args.rtsp_path, args.timeout, credentials)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
