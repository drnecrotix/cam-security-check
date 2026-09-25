# Windows ONVIF/PTZ camera check

This small tool checks one camera on your private LAN for anonymous ONVIF access. It needs Python 3.10+ on Windows and uses no third-party packages. It is a fresh diagnostic implementation, not a conversion of the repository's Linux binary.

## Easy Windows interface

Install Python 3 for Windows and double-click `START-WINDOWS.bat`. Enter the camera's private IP address and ONVIF port, then use the buttons. Install VLC if you want to view video. The interface uses only built-in Python modules.

The interface uses a dark theme and three tabs: Cameras, Discovery and Results. Switch **BG/EN** in the top right; exported HTML follows the selected language.

Give the camera a name and press **Запази** to keep its IP, port and ONVIF username for next time. The password is not saved. Enter the password to compare authenticated ONVIF capabilities, profiles, PTZ status and stream URI access against anonymous responses. The tool uses ONVIF WS-Security UsernameToken digest or HTTP Digest authentication; a camera with another scheme may need a device-specific adapter. Passwords are read through standard input, not command-line arguments.

When the ONVIF username field is blank, the app first checks a saved camera with the same IP and port, then sends an anonymous ONVIF `GetUsers` request. If exactly one username is returned, it fills the field; if several are returned, you choose. Properly protected cameras normally reject anonymous `GetUsers`, so the username must then be entered manually. This function does not try default usernames or guess passwords.

**Снимка от видео** requests an ONVIF JPEG snapshot using the provided credentials. If the camera does not offer a snapshot URI, an anonymously accessible RTSP stream can be captured with FFmpeg installed on PATH. Choose where to save the JPEG. **Запази последния отчет** exports a readable HTML report or JSON data from the last check, including profile names, resolution and codec when reported. Passwords and stream URLs are excluded.

If you do not know the ONVIF port, enter the camera's IP and press **Намери портове**. It checks the listed ports on that one IP and displays ONVIF, RTSP, or unknown open services. You can edit the comma-separated port list or use a short range such as `8000-8010`; the total is limited to 32 ports. Select an ONVIF result to fill the ONVIF port. An open port or authentication response is not proof of a particular vulnerability.

If you do not know the camera IP, enter a local address such as `192.168.0.1` and press **Намери камери**. The tool assumes `/24` for a bare address; you can enter the actual network such as `192.168.0.0/24` instead. The result lists IP, port, and service; choosing an ONVIF row fills both fields. A search is capped at 254 addresses and 2048 IP/port checks and can take a while. Check your router's actual LAN range and scan only networks you control. A public router WAN address is not the camera's local address.

For a desktop connected by Ethernet, press **Открий кабелната LAN мрежа**. Windows reports the active physical Ethernet adapters and IPv4 prefixes. Select the home network, then press **Намери камери**. A Wi-Fi adapter is not required. This lists open ports and recognized ONVIF/RTSP services; a router or another device can also have an open port, so an open port alone does not identify a camera.

The **Открий устройства и ONVIF камери** button combines a bounded TCP port check, local ONVIF WS-Discovery multicast, and Windows neighbor entries on the selected private LAN (up to `/24`). WS-Discovery may locate ONVIF devices using an unlisted port. Neighbor entries may be stale and do not prove the device is a camera. Multicast discovery normally stays on the local LAN and may not work over Tailscale; the TCP scan can still use a routed subnet.

## Away from home: Tailscale subnet routing

The **Отдалечен достъп през Tailscale** button explains how to use a computer that stays on at home as a subnet router. Install Tailscale on that home Windows PC, sign in, and run the generated `tailscale up --advertise-routes=...` command there from an Administrator PowerShell. Approve the route in Tailscale's admin console. Install Tailscale and sign into the same account on the Windows computer you use away from home. Then scan the home network through the existing interface. This requires a working home computer and connection; it cannot locate cameras over the Internet without a route to your home network. Do not expose ONVIF or RTSP ports directly to the Internet.

The route can be the complete home LAN (for example `/24`), and discovery can search the same `/24` after the tunnel is connected. Official setup: https://tailscale.com/docs/use-cases/personal-or-at-home-use/access-devices-without-tailscale?tab=windows

## Nearby Wi-Fi signals without joining a network

On Windows, **Видими Wi-Fi сигнали наблизо** lists access points that the laptop's Wi-Fi adapter can currently hear, including their reported signal strength. The laptop does not need to join a network. A camera may appear only if it broadcasts its own hotspot/SSID (often during setup); a camera operating as a client of your router normally does not broadcast a separate network. The list cannot identify a camera conclusively, detect a camera far away, or read video. Windows may require Wi-Fi and location permission for the network list.

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
- `authenticated_*` fields show whether a request carrying supplied credentials succeeded. If the same operation is anonymous, this does not prove the account was verified. `authenticated_rtsp_describe` separately checks RTSP Digest authentication (MD5 or SHA-256); an RTSP 200 response still needs actual playback for visual confirmation.
- HTTP 401/403 generally means authentication was required for that request. A network error, another ONVIF path, or a different port can also explain a negative result.
- A failed test is not a comprehensive security assessment.

If movement is exposed, update camera firmware, enable ONVIF authentication where supported, disable ONVIF if unused, block Internet exposure and restrict access to trusted LAN devices. Change default credentials.

### Full audit and password check

Use **Пълен отчет / Full audit** for anonymous ONVIF and RTSP video checks, an authenticated comparison when you enter credentials, video profiles, and a detailed checklist with evidence, risk and actions. Save the report as HTML or JSON. PTZ movement and snapshot capture remain separate explicit actions.

The entered password is assessed offline for length, predictable patterns and a small built-in list of common values. The tool does not attempt password guessing against the camera. This heuristic is not a breach database check or proof that a password cannot be guessed. Password text is omitted from reports and saved camera entries. A successful credentialed request does not establish that authentication was enforced when the same anonymous operation succeeds.

### Dashboard layout

The main window keeps camera details, checks and the scrollable result console visible together. **Търсене и мрежа / Discovery and network** opens the LAN, port and nearby Wi-Fi tools in a separate window. Discovered camera addresses fill the main dashboard. The discovery window can be closed during a scan without breaking the controls.
