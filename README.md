<p align="center">
  <img src="https://cdn-icons-png.flaticon.com/512/394/394620.png" width="120" height="120" alt="Camera security check">
</p>

<h1 align="center">Cam Security Check [For educational purposes only]</h1>

<p align="center">
  Check <strong>your own</strong> IP cameras on a private LAN for anonymous ONVIF / RTSP exposure.<br>
  Dark bilingual (BG/EN) Windows dashboard, HTML reports, optional PTZ / video tests.
</p>

<p align="center">
  <a href="windows-audit/README.md">Windows audit docs</a>
  &middot;
  <a href="#disclaimer">Disclaimer</a>
  &middot;
  <a href="https://github.com/drnecrotix">dr.necrotix</a>
</p>

---

## What this repository is

Two related pieces:

| Path | What it is |
| --- | --- |
| [`windows-audit/`](windows-audit/) | **Primary tool.** Source-available Windows GUI + CLI. Python 3.10+, no third-party packages. Discovers cameras on a network you control, compares anonymous vs authenticated ONVIF, checks RTSP, exports HTML/JSON. |
| `dedsec_ptz_exploit` | Legacy Linux binary from the upstream [DEDSEC_PTZ_EXPLOIT](https://github.com/0xbitx/DEDSEC_PTZ_EXPLOIT) PoC. Not a Windows build of the audit tool. Use only on devices you own or are authorized to test. |

This project is a **diagnostic** for cameras you administer. It is not a scanning service for the public Internet and it is not a password-guessing toolkit.

---

## Preview

<p align="center">
  <img src="docs/Assets/Screenshot%202026-09-26%20021555.png" alt="Windows dashboard — Bulgarian UI, discovery and open services" width="900">
</p>
<p align="center"><em>Dashboard (BG) — discovery and open services</em></p>

<p align="center">
  <img src="docs/Assets/Screenshot%202026-09-26%20021809.png" alt="Windows dashboard — English UI" width="900">
</p>
<p align="center"><em>Detailed CCTV report - the entire document is not shown in the image.</em></p>

<p align="center">
  <img src="docs/Assets/Screenshot%202026-09-26%20022019.png" alt="HTML audit report with checks and evidence" width="900">
</p>
<p align="center"><em>Exported HTML report — checks, risk, actions (sensitive fields redacted)</em></p>

---

## Windows camera audit (recommended)

Requirements:

- Windows 10/11
- [Python 3.10+](https://www.python.org/downloads/windows/) with the <strong>py</strong> launcher
- Optional: [VLC](https://www.videolan.org/vlc/) to view a confirmed stream
- Optional: FFmpeg on <code>PATH</code> for snapshot fallback

### Start the GUI

```text
1. Install Python 3 for Windows.
2. Open windows-audit/START-WINDOWS.bat
3. Enter a private camera IP and ONVIF port.
4. Use Full audit / Check access / Check video.
```

Or from PowerShell in <code>windows-audit/</code>:

```powershell
py -3 gui.py
```

Switch <strong>BG / EN</strong> in the top right. Saved cameras keep IP, port and username — <strong>passwords are never stored</strong> in the inventory.

### What the GUI can do

- Save named cameras and run a full ONVIF + RTSP audit
- Discover ports on one IP (bounded list / short range, max 32 ports)
- Find cameras on a private `/24` you control (capped scan)
- Detect the wired Ethernet LAN prefix
- Combine TCP check + ONVIF WS-Discovery + neighbor table
- Compare anonymous vs authenticated capabilities / profiles / PTZ status / stream URI
- Offline password *heuristic* (length, patterns, common values) — **no guessing against the camera**
- Snapshot via ONVIF JPEG (or anonymous RTSP + FFmpeg)
- Open a stream in VLC only after an anonymous `RTSP/1.0 200` DESCRIBE
- Export HTML (bilingual in one file) or JSON
- Optional confidential export that includes stream URLs / the password currently typed — treat that file as a secret
- Notes for Tailscale subnet routing so you can reach a home LAN without publishing ONVIF/RTSP to the Internet

Full behavior, result fields and limits: [`windows-audit/README.md`](windows-audit/README.md).

### CLI examples

Replace IP and port with **your** camera.

```powershell
py -3 audit.py 192.168.1.50 --port 80
py -3 audit.py 192.168.1.50 --port 80 --video-test
py -3 audit.py 192.168.1.50 --port 80 --view-video
```

`--move-test` sends a short opt-in PTZ command (0.3s + Stop). Watch the camera, keep the view clear, and run it only on hardware you are allowed to move.

```powershell
py -3 audit.py 192.168.1.50 --port 80 --move-test
```

### Tests

```powershell
cd windows-audit
python -m unittest discover -s tests -v
```

---

## Interpreting a result (short)

| Signal | Meaning |
| --- | --- |
| Anonymous capabilities / profiles | Info leaked without login. Not proof of PTZ control. |
| Anonymous PTZ status | Position/status readable without login. |
| `movement_accepted` | Camera accepted a move SOAP reply. Confirm physically. |
| Anonymous stream URI | ONVIF handed back an address. Not proof the video plays. |
| `RTSP/1.0 200` DESCRIBE | Server accepted anonymous describe. Playback in VLC confirms view. |
| HTTP 401 / 403 | Auth required for that request (or wrong path/port). |

A failed or unreachable check is **not** a full penetration test.

If anonymous PTZ or video is exposed: update firmware, force ONVIF authentication, disable unused ONVIF, keep ports off the public Internet, restrict the LAN, change default credentials.

---

## Linux binary (legacy)

Tested by upstream on Kali, Parrot and Ubuntu. Clone **this** repo if you are working from here:

```bash
git clone https://github.com/drnecrotix/cam-security-check.git
cd cam-security-check
pip3 install tabulate progressbar2
chmod +x dedsec_ptz_exploit
./dedsec_ptz_exploit
```

This executable is independent of `windows-audit/`. Do not treat it as the Windows GUI.

---

## Scope and limits

- Private IPv4 / local routed subnets you control. Do not point it at random public hosts.
- Discovery is bounded (ports, host count, check count) so a home LAN scan stays finite.
- Auth support: ONVIF WS-Security UsernameToken digest or HTTP Digest. Other vendor schemes may need an adapter.
- The tool does not brute-force accounts, guess vendor RTSP paths, or record video by default.
- Open HTTP/RTSP ports do not by themselves prove a device is a camera.

---

<a id="disclaimer"></a>

## Disclaimer

Use this software only on cameras and networks you **own** or have **written authorization** to assess.

Unauthorized access to cameras, streams or PTZ control is illegal. The authors are not responsible for misuse. Educational and defensive use only.

Do not publish confidential HTML/JSON exports. They can contain stream URLs and credentials.

---

## License

See [`LICENSE`](LICENSE).

## Credits

- Windows diagnostic: [dr.necrotix](https://github.com/drnecrotix) / NecrotixLab
- Upstream Linux PoC: [0xbitx/DEDSEC_PTZ_EXPLOIT](https://github.com/0xbitx/DEDSEC_PTZ_EXPLOIT)
