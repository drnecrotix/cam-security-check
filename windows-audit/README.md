# Windows ONVIF/PTZ camera check

This small tool checks one camera on your private LAN for anonymous ONVIF access. It needs Python 3.10+ on Windows and uses no third-party packages. It is a fresh diagnostic implementation, not a conversion of the repository's Linux binary.

## Easy Windows interface

Install Python 3 for Windows and double-click `START-WINDOWS.bat`. Enter the camera's private IP address and ONVIF port, then use the buttons. Install VLC if you want to view video. The interface uses only built-in Python modules.

If you do not know the ONVIF port, enter the camera's IP and press **Намери портове**. It checks the listed ports on that one IP and displays ONVIF, RTSP, or unknown open services. You can edit the comma-separated port list or use a short range such as `8000-8010`; the total is limited to 32 ports. Select an ONVIF result to fill the ONVIF port. An open port or authentication response is not proof of a particular vulnerability.

If you do not know the camera IP, enter an **explicit private CIDR network** such as `192.168.1.0/26` and press **Намери IP адреси**. The result lists IP, port, and service; choosing an ONVIF row fills both fields. A search is capped at 64 addresses and 512 IP/port checks. The tool does not determine your network automatically. Check your router's LAN range before entering it and scan only networks you control.

If Windows cannot find Python, install it from [python.org](https://www.python.org/downloads/windows/) with the Python launcher enabled. Alternatively open PowerShell in this folder and run:

```powershell
py -3 gui.py
```

## PowerShell commands

Open PowerShell in this folder and run:

```powershell
py -3 audit.py 192.168.1.50 --port 80
```

Replace the IP and port with your camera's local ONVIF address and port. To explicitly test whether the camera accepts an unauthenticated PTZ move command:

```powershell
py -3 audit.py 192.168.1.50 --port 80 --move-test
```

The optional move is a short horizontal command with a 0.3 second timeout, followed by Stop. Watch the camera directly. Some devices may ignore the timeout or move unexpectedly; keep its view clear and be ready to stop it through its own app. Run only against cameras you own or are authorized to test.

## Video

To test whether the camera exposes its RTSP video stream without credentials:

```powershell
py -3 audit.py 192.168.1.50 --port 80 --video-test
```

To view the stream, install [VLC for Windows](https://www.videolan.org/vlc/) and run:

```powershell
py -3 audit.py 192.168.1.50 --port 80 --view-video
```

The tool asks ONVIF for a stream URI, sends an anonymous RTSP `DESCRIBE`, and opens VLC only when it receives `RTSP/1.0 200`. It does not print or save the URI, which may contain a temporary access token. It rejects a URI with embedded credentials or a different IP. If the camera advertises a hostname or a second local IP for its stream, this conservative check will decline it. ONVIF and RTSP ports may differ; `--port` is the ONVIF port.

## Interpreting results

- `anonymous_capabilities` or `anonymous_profiles: true` means information is available without credentials; it does not by itself prove that PTZ control is exposed.
- `anonymous_ptz_status: true` means PTZ status is readable without credentials.
- `movement_accepted: true` means the camera accepted a move SOAP response without credentials. Check that the camera actually moved to confirm impact.
- `anonymous_stream_uri: true` means ONVIF provided a stream address; that alone does not prove video is open.
- `rtsp_describe: RTSP/1.0 200 OK` means the RTSP server accepted an anonymous description request. Successful playback in VLC confirms actual viewing.
- HTTP 401/403 generally means authentication was required for that request. A network error, another ONVIF path, or a different port can also explain a negative result.
- A failed test is not a comprehensive security assessment.

If movement is exposed, update camera firmware, enable ONVIF authentication where supported, disable ONVIF if unused, block Internet exposure and restrict access to trusted LAN devices. Change default credentials.
