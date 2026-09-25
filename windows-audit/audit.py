#!/usr/bin/env python3
"""Single-camera, local-network ONVIF exposure check (standard library only)."""
import argparse
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from xml.sax.saxutils import escape

SOAP = 'http://www.w3.org/2003/05/soap-envelope'
DEV = 'http://www.onvif.org/ver10/device/wsdl'
MEDIA = 'http://www.onvif.org/ver10/media/wsdl'
PTZ = 'http://www.onvif.org/ver20/ptz/wsdl'


def envelope(body):
    return (f'<s:Envelope xmlns:s="{SOAP}"><s:Body>{body}</s:Body></s:Envelope>').encode()


def call(url, body, timeout):
    req = urllib.request.Request(url, envelope(body), {'Content-Type': 'application/soap+xml; charset=utf-8'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = response.read(1024 * 1024)
            status = response.status
    except urllib.error.HTTPError as error:
        data = error.read(1024 * 1024)
        status = error.code
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return {'ok': False, 'status': None, 'error': str(error), 'root': None}
    try:
        root = ET.fromstring(data)
        fault = next((x for x in root.iter() if x.tag.endswith('}Fault')), None)
        return {'ok': 200 <= status < 300 and fault is None, 'status': status,
                'error': 'SOAP Fault' if fault is not None else None, 'root': root}
    except ET.ParseError:
        return {'ok': False, 'status': status, 'error': 'Non-XML response', 'root': None}


def first_text(root, local):
    if root is None:
        return None
    return next((e.text for e in root.iter() if e.tag.endswith('}' + local) and e.text), None)


def service_url(root, service, fallback, ip):
    if root is not None:
        for node in root.iter():
            if node.tag.endswith('}' + service):
                url = first_text(node, 'XAddr')
                if url:
                    parsed = urlparse(url)
                    try:
                        if parsed.scheme == 'http' and ipaddress.ip_address(parsed.hostname) == ip:
                            return url
                    except (ValueError, TypeError):
                        pass
    return fallback


def rtsp_describe(uri, ip, timeout):
    parsed = urlparse(uri)
    try:
        if parsed.scheme != 'rtsp' or parsed.username or parsed.password or ipaddress.ip_address(parsed.hostname) != ip:
            return 'unsafe_or_different_host'
        port = parsed.port or 554
    except (ValueError, TypeError):
        return 'invalid_uri'
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = f'DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\nUser-Agent: LocalCameraAudit/1.0\r\n\r\n'
            sock.sendall(request.encode('ascii'))
            header = b''
            while b'\r\n\r\n' not in header and len(header) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                header += chunk
            line = header.split(b'\r\n', 1)[0].decode('ascii', 'replace')
            return line if line.startswith('RTSP/') else 'invalid_response'
    except (OSError, UnicodeEncodeError) as error:
        return 'connection_failed: ' + str(error)


def find_vlc():
    candidates = [shutil.which('vlc')]
    for key in ('PROGRAMFILES', 'PROGRAMFILES(X86)'):
        if os.environ.get(key):
            candidates.append(os.path.join(os.environ[key], 'VideoLAN', 'VLC', 'vlc.exe'))
    return next((x for x in candidates if x and os.path.isfile(x)), None)


def main():
    p = argparse.ArgumentParser(description='Check one camera on a private IPv4 address for unauthenticated ONVIF/PTZ access.')
    p.add_argument('ip', help='Private IPv4 address of your camera')
    p.add_argument('--port', type=int, default=80)
    p.add_argument('--timeout', type=float, default=4)
    p.add_argument('--move-test', action='store_true', help='Opt in to a short unauthenticated PTZ movement, then Stop')
    p.add_argument('--video-test', action='store_true', help='Check whether the RTSP video stream accepts an anonymous DESCRIBE')
    p.add_argument('--view-video', action='store_true', help='Open an anonymously accessible stream in VLC (implies --video-test)')
    a = p.parse_args()
    try:
        ip = ipaddress.ip_address(a.ip)
    except ValueError:
        p.error('Enter a numeric IPv4 address.')
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        p.error('Only one private LAN IPv4 camera address is accepted.')
    if not 1 <= a.port <= 65535 or not 0 < a.timeout <= 15:
        p.error('Port or timeout out of range.')
    base = f'http://{ip}:{a.port}'
    device = base + '/onvif/device_service'
    caps = call(device, f'<d:GetCapabilities xmlns:d="{DEV}"><d:Category>All</d:Category></d:GetCapabilities>', a.timeout)
    media_url = service_url(caps['root'], 'Media', base + '/onvif/media_service', ip)
    ptz_url = service_url(caps['root'], 'PTZ', base + '/onvif/ptz_service', ip)
    profiles = call(media_url, f'<m:GetProfiles xmlns:m="{MEDIA}"/>', a.timeout)
    token = None
    if profiles['ok']:
        for node in profiles['root'].iter():
            if node.tag.endswith('}Profiles') and node.attrib.get('token'):
                token = node.attrib['token']
                break
    if token:
        token = escape(token, {'"': '&quot;', "'": '&apos;'})
    status = None
    if token:
        status = call(ptz_url, f'<p:GetStatus xmlns:p="{PTZ}"><p:ProfileToken>{token}</p:ProfileToken></p:GetStatus>', a.timeout)
    result = {'target': str(ip), 'port': a.port, 'anonymous_capabilities': caps['ok'],
              'anonymous_profiles': profiles['ok'], 'anonymous_ptz_status': status['ok'] if status else None,
              'http_status': {'capabilities': caps['status'], 'profiles': profiles['status'], 'ptz': status['status'] if status else None},
              'movement_attempted': False, 'movement_accepted': None, 'stop_accepted': None,
              'anonymous_stream_uri': False, 'rtsp_describe': None, 'viewer_started': False}
    if a.video_test or a.view_video:
        if token:
            request = (f'<m:GetStreamUri xmlns:m="{MEDIA}" xmlns:t="http://www.onvif.org/ver10/schema">'
                       f'<m:StreamSetup><t:Stream>RTP-Unicast</t:Stream>'
                       f'<t:Transport><t:Protocol>RTSP</t:Protocol></t:Transport></m:StreamSetup>'
                       f'<m:ProfileToken>{token}</m:ProfileToken></m:GetStreamUri>')
            stream = call(media_url, request, a.timeout)
            uri = first_text(stream['root'], 'Uri') if stream['ok'] else None
            result['anonymous_stream_uri'] = bool(uri)
            if uri:
                result['rtsp_describe'] = rtsp_describe(uri, ip, a.timeout)
                if a.view_video and result['rtsp_describe'].startswith('RTSP/1.0 200 '):
                    vlc = find_vlc()
                    if vlc:
                        subprocess.Popen([vlc, uri], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        result['viewer_started'] = True
                    else:
                        print('VLC was not found. Install VLC, then run --view-video again.')
        else:
            print('Video skipped: no accessible ONVIF profile token.')
    if a.move_test:
        if not token:
            print('Movement skipped: no accessible profile token.')
        else:
            print('Camera may move briefly. Keep its field of view clear.')
            move = (f'<p:ContinuousMove xmlns:p="{PTZ}" xmlns:t="http://www.onvif.org/ver10/schema">'
                    f'<p:ProfileToken>{token}</p:ProfileToken><p:Velocity><t:PanTilt x="0.15" y="0"/></p:Velocity>'
                    f'<p:Timeout>PT0.3S</p:Timeout></p:ContinuousMove>')
            stop = (f'<p:Stop xmlns:p="{PTZ}"><p:ProfileToken>{token}</p:ProfileToken>'
                    f'<p:PanTilt>true</p:PanTilt><p:Zoom>true</p:Zoom></p:Stop>')
            result['movement_attempted'] = True
            try:
                result['movement_accepted'] = call(ptz_url, move, a.timeout)['ok']
                time.sleep(0.3)
            finally:
                result['stop_accepted'] = call(ptz_url, stop, a.timeout)['ok']
    print(json.dumps(result, indent=2))
    if result['movement_accepted']:
        print('WARNING: camera accepted an unauthenticated PTZ move command. Verify physical movement and restrict ONVIF access.')
    elif result['anonymous_ptz_status']:
        print('Anonymous PTZ status is readable. This alone does not prove anonymous movement is possible.')
    else:
        print('No unauthenticated PTZ access confirmed. This is not proof that the camera is secure.')
    if result['rtsp_describe'] and result['rtsp_describe'].startswith('RTSP/1.0 200 '):
        print('WARNING: RTSP DESCRIBE returned 200 without credentials. If VLC plays video, anonymous viewing is confirmed.')


if __name__ == '__main__':
    main()
