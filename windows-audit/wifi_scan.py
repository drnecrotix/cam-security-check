"""Read-only list of nearby Wi-Fi access points on Windows, without connecting."""
import ctypes
import os
import subprocess


def nearby_networks():
    if os.name != 'nt':
        raise RuntimeError('Тази проверка е само за Windows с Wi-Fi адаптер.')
    result = subprocess.run(['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                            capture_output=True, timeout=15)
    codepage = ctypes.windll.kernel32.GetOEMCP()
    output = result.stdout.decode(f'cp{codepage}', errors='replace').strip()
    error = result.stderr.decode(f'cp{codepage}', errors='replace').strip()
    if result.returncode != 0:
        raise RuntimeError(error or output or 'Неуспешно търсене на Wi-Fi мрежи.')
    return output or 'Не са открити видими Wi-Fi мрежи.'
