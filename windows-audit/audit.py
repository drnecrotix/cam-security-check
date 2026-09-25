#!/usr/bin/env python3
"""Single-camera, local-network ONVIF exposure check (standard library only)."""
import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def envelope(body, credentials=None):
    header = ''
    if credentials:
        username, password = credentials
        nonce = os.urandom(16)
        created = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + password.encode()).digest()).decode()
        nonce64 = base64.b64encode(nonce).decode()
        header = (f'<s:Header><wsse:Security s:mustUnderstand="1" '
                  f'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" '
                  f'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
                  f'<wsse:UsernameToken><wsse:Username>{escape(username)}</wsse:Username>'
                  f'<wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>'
                  f'<wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce64}</wsse:Nonce>'
                  f'<wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>')
    return (f'<s:Envelope xmlns:s="{SOAP}">{header}<s:Body>{body}</s:Body></s:Envelope>').encode()


def call(url, body, timeout, credentials=None):
    req = urllib.request.Request(url, envelope(body, credentials), {'Content-Type': 'application/soap+xml; charset=utf-8'}, method='POST')
    opener = urllib.request.build_opener(NoRedirect)
    if credentials:
        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, url, *credentials)
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPDigestAuthHandler(manager))
    try:
        with opener.open(req, timeout=timeout) as response:
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


def profile_list(root):
    items = []
    if root is None:
        return items
    for node in root.iter():
        if not node.tag.endswith('}Profiles'):
            continue
        config = next((e for e in node if e.tag.endswith('}VideoEncoderConfiguration')), None)
        res = next((e for e in config.iter() if e.tag.endswith('}Resolution')), None) if config is not None else None
        items.append({'name': first_text(node, 'Name'), 'token': node.attrib.get('token'),
                      'codec': first_text(config, 'Encoding'),
                      'width': first_text(res, 'Width'), 'height': first_text(res, 'Height')})
    return items


def discover_usernames(ip, port, timeout=4):
    """Read an anonymously exposed ONVIF user list; never guess usernames."""
    address = ipaddress.ip_address(ip)
    if (address.version != 4 or not address.is_private or address.is_loopback or
            address.is_link_local or address.is_reserved or not 1 <= int(port) <= 65535):
        raise ValueError('Only a private camera IPv4 address and valid port are allowed.')
    response = call(f'http://{address}:{port}/onvif/device_service',
                    f'<d:GetUsers xmlns:d="{DEV}"/>', timeout)
    if not response['ok'] or response['root'] is None:
        return []
    names = []
    for node in response['root'].iter():
        if node.tag.endswith('}User'):
            name = first_text(node, 'Username')
            if name and name not in names:
                names.append(name)
    return names


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


def rtsp_describe(uri, ip, timeout, credentials=None):
    parsed = urlparse(uri)
    try:
        if parsed.scheme != 'rtsp' or parsed.username or parsed.password or ipaddress.ip_address(parsed.hostname) != ip:
            return 'unsafe_or_different_host'
        port = parsed.port or 554
    except (ValueError, TypeError):
        return 'invalid_uri'
    def send(authorization=None):
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (f'DESCRIBE {uri} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n'
                       f'User-Agent: LocalCameraAudit/1.0\r\n')
            if authorization:
                request += f'Authorization: {authorization}\r\n'
            sock.sendall((request + '\r\n').encode('ascii'))
            header = b''
            while b'\r\n\r\n' not in header and len(header) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                header += chunk
            return header.decode('latin-1', 'replace')
    try:
        response = send()
        line = response.split('\r\n', 1)[0]
        if not credentials or ' 401 ' not in line:
            return line if line.startswith('RTSP/') else 'invalid_response'
        challenge = next((x.split(':', 1)[1].strip() for x in response.split('\r\n')
                          if x.lower().startswith('www-authenticate:') and 'digest ' in x.lower()), None)
        if not challenge:
            return 'RTSP authentication scheme not supported'
        params = {key.lower(): quoted or unquoted for key, quoted, unquoted in
                  re.findall(r'(\w+)=(?:"([^"]*)"|([^,\s]+))', challenge)}
        realm, nonce = params.get('realm'), params.get('nonce')
        algorithm = params.get('algorithm', 'MD5').upper()
        if not realm or not nonce or algorithm not in ('MD5', 'SHA-256'):
            return 'RTSP Digest challenge not supported'
        hasher = hashlib.md5 if algorithm == 'MD5' else hashlib.sha256
        username, password = credentials
        if any(any(c in value for c in '\r\n"') for value in (username, realm, nonce, uri)):
            return 'Invalid RTSP Digest field'
        digest = lambda value: hasher(value.encode('utf-8')).hexdigest()
        ha1 = digest(f'{username}:{realm}:{password}')
        ha2 = digest(f'DESCRIBE:{uri}')
        fields = [f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"',
                  f'uri="{uri}"', f'algorithm={algorithm}']
        if 'auth' in params.get('qop', '').split(','):
            cnonce = os.urandom(8).hex()
            fields += ['qop=auth', 'nc=00000001', f'cnonce="{cnonce}"']
            response_hash = digest(f'{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}')
        elif params.get('qop'):
            return 'RTSP Digest qop not supported'
        else:
            response_hash = digest(f'{ha1}:{nonce}:{ha2}')
        fields.append(f'response="{response_hash}"')
        authenticated = send('Digest ' + ', '.join(fields))
        auth_line = authenticated.split('\r\n', 1)[0]
        return auth_line if auth_line.startswith('RTSP/') else 'invalid_response'
    except (OSError, UnicodeEncodeError) as error:
        return 'connection_failed: ' + str(error)


def find_vlc():
    candidates = [shutil.which('vlc')]
    for key in ('PROGRAMFILES', 'PROGRAMFILES(X86)'):
        if os.environ.get(key):
            candidates.append(os.path.join(os.environ[key], 'VideoLAN', 'VLC', 'vlc.exe'))
    return next((x for x in candidates if x and os.path.isfile(x)), None)


def snapshot(uri, destination):
    ffmpeg = shutil.which('ffmpeg')
    if not ffmpeg:
        return 'FFmpeg is not installed or not on PATH.'
    try:
        result = subprocess.run([ffmpeg, '-nostdin', '-loglevel', 'error', '-rtsp_transport', 'tcp',
                                 '-i', uri, '-frames:v', '1', '-y', destination],
                                capture_output=True, timeout=25)
        if result.returncode == 0 and os.path.isfile(destination):
            return None
        return 'FFmpeg could not capture a frame.'
    except (OSError, subprocess.TimeoutExpired):
        return 'FFmpeg could not complete the capture.'


def snapshot_image(uri, ip, timeout, credentials, destination):
    parsed = urlparse(uri)
    try:
        if parsed.scheme != 'http' or parsed.username or parsed.password or ipaddress.ip_address(parsed.hostname) != ip:
            return 'Snapshot address is not a safe HTTP URL on this camera IP.'
    except (ValueError, TypeError):
        return 'Invalid snapshot address.'
    opener = urllib.request.build_opener(NoRedirect)
    if credentials:
        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, uri, *credentials)
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPDigestAuthHandler(manager))
    try:
        with opener.open(urllib.request.Request(uri, headers={'Accept': 'image/jpeg'}), timeout=timeout) as response:
            image = response.read(8 * 1024 * 1024 + 1)
        if len(image) > 8 * 1024 * 1024 or not image.startswith(b'\xff\xd8') or not image.endswith(b'\xff\xd9'):
            return 'Camera did not return a valid JPEG under 8 MB.'
        with open(destination, 'wb') as file:
            file.write(image)
        return None
    except (urllib.error.URLError, OSError, TimeoutError):
        return 'Could not retrieve the JPEG snapshot.'


def main():
    p = argparse.ArgumentParser(description='Check one camera on a private IPv4 address for unauthenticated ONVIF/PTZ access.')
    p.add_argument('ip', help='Private IPv4 address of your camera')
    p.add_argument('--port', type=int, default=80)
    p.add_argument('--timeout', type=float, default=4)
    p.add_argument('--move-test', action='store_true', help='Opt in to a short unauthenticated PTZ movement, then Stop')
    p.add_argument('--video-test', action='store_true', help='Check whether the RTSP video stream accepts an anonymous DESCRIBE')
    p.add_argument('--view-video', action='store_true', help='Open an anonymously accessible stream in VLC (implies --video-test)')
    p.add_argument('--username', help='ONVIF username for comparison with anonymous access')
    p.add_argument('--password-stdin', action='store_true', help='Read password from standard input (GUI use)')
    p.add_argument('--snapshot', help='Save a JPEG snapshot via ONVIF; FFmpeg fallback for anonymous RTSP')
    p.add_argument('--report', help='Save JSON report without credentials')
    a = p.parse_args()
    if a.password_stdin and not a.username:
        p.error('--password-stdin requires --username')
    credentials = None
    if a.username:
        password = sys.stdin.readline().rstrip('\r\n') if a.password_stdin else getpass.getpass('ONVIF password: ')
        credentials = (a.username, password)
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
    auth_caps = call(device, f'<d:GetCapabilities xmlns:d="{DEV}"><d:Category>All</d:Category></d:GetCapabilities>', a.timeout, credentials) if credentials else None
    service_root = auth_caps['root'] if auth_caps and auth_caps['ok'] else caps['root']
    media_url = service_url(service_root, 'Media', base + '/onvif/media_service', ip)
    ptz_url = service_url(service_root, 'PTZ', base + '/onvif/ptz_service', ip)
    profiles = call(media_url, f'<m:GetProfiles xmlns:m="{MEDIA}"/>', a.timeout)
    auth_profiles = call(media_url, f'<m:GetProfiles xmlns:m="{MEDIA}"/>', a.timeout, credentials) if credentials else None
    anonymous_items = profile_list(profiles['root']) if profiles['ok'] else []
    auth_items = profile_list(auth_profiles['root']) if auth_profiles and auth_profiles['ok'] else []
    token = anonymous_items[0]['token'] if anonymous_items else None
    auth_token = auth_items[0]['token'] if auth_items else None
    if token:
        token = escape(token, {'"': '&quot;', "'": '&apos;'})
    status = None
    if token:
        status = call(ptz_url, f'<p:GetStatus xmlns:p="{PTZ}"><p:ProfileToken>{token}</p:ProfileToken></p:GetStatus>', a.timeout)
    auth_status = call(ptz_url, f'<p:GetStatus xmlns:p="{PTZ}"><p:ProfileToken>{escape(auth_token)}</p:ProfileToken></p:GetStatus>', a.timeout, credentials) if auth_token else None
    result = {'target': str(ip), 'port': a.port, 'anonymous_capabilities': caps['ok'],
              'anonymous_profiles': profiles['ok'], 'anonymous_ptz_status': status['ok'] if status else None,
              'http_status': {'capabilities': caps['status'], 'profiles': profiles['status'], 'ptz': status['status'] if status else None},
              'movement_attempted': False, 'movement_accepted': None, 'stop_accepted': None,
              'anonymous_stream_uri': False, 'rtsp_describe': None, 'viewer_started': False,
              'authenticated': bool(credentials),
              'authenticated_capabilities': auth_caps['ok'] if auth_caps else None,
              'authenticated_profiles': auth_profiles['ok'] if auth_profiles else None,
              'authenticated_ptz_status': auth_status['ok'] if auth_status else None,
              'video_profiles': [{k: v for k, v in item.items() if k != 'token'}
                                 for item in (auth_items if auth_items else anonymous_items)],
              'authenticated_stream_uri': None, 'authenticated_rtsp_describe': None,
              'snapshot_saved': False, 'snapshot_error': None}
    uri = None
    if a.video_test or a.view_video or a.snapshot or credentials:
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
        if auth_token:
            request = (f'<m:GetStreamUri xmlns:m="{MEDIA}" xmlns:t="http://www.onvif.org/ver10/schema">'
                       f'<m:StreamSetup><t:Stream>RTP-Unicast</t:Stream><t:Transport>'
                       f'<t:Protocol>RTSP</t:Protocol></t:Transport></m:StreamSetup>'
                       f'<m:ProfileToken>{escape(auth_token)}</m:ProfileToken></m:GetStreamUri>')
            auth_stream = call(media_url, request, a.timeout, credentials)
            auth_uri = first_text(auth_stream['root'], 'Uri') if auth_stream['ok'] else None
            result['authenticated_stream_uri'] = bool(auth_uri)
            if auth_uri:
                result['authenticated_rtsp_describe'] = rtsp_describe(auth_uri, ip, a.timeout, credentials)
        if a.snapshot:
            if not a.snapshot.lower().endswith(('.jpg', '.jpeg')):
                p.error('Snapshot path must end with .jpg or .jpeg')
            chosen_token = auth_token or (anonymous_items[0]['token'] if anonymous_items else None)
            if chosen_token:
                request = (f'<m:GetSnapshotUri xmlns:m="{MEDIA}">'
                           f'<m:ProfileToken>{escape(chosen_token)}</m:ProfileToken></m:GetSnapshotUri>')
                snap_response = call(media_url, request, a.timeout, credentials if auth_token else None)
                snap_uri = first_text(snap_response['root'], 'Uri') if snap_response['ok'] else None
                if snap_uri:
                    result['snapshot_error'] = snapshot_image(snap_uri, ip, a.timeout, credentials if auth_token else None, a.snapshot)
                elif uri and result['rtsp_describe'] and result['rtsp_describe'].startswith('RTSP/1.0 200 '):
                    result['snapshot_error'] = snapshot(uri, a.snapshot)
                else:
                    result['snapshot_error'] = 'No accessible snapshot URI or anonymous video stream.'
                result['snapshot_saved'] = result['snapshot_error'] is None
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
    if a.report:
        with open(a.report, 'w', encoding='utf-8') as file:
            json.dump(result, file, indent=2, ensure_ascii=False)
    print(json.dumps(result, indent=2, ensure_ascii=False))
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
