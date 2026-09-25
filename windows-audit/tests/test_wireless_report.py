import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit import wireless_information
from reporting import render_html


class WirelessReportTests(unittest.TestCase):
    def test_status_ssid_overrides_config_and_omits_psk(self):
        network = ET.fromstring('''<Envelope xmlns:t="urn:types"><t:NetworkInterfaces token="wlan0"><t:Info><t:Name>wlan0</t:Name><t:HwAddress>AA:BB:CC:DD:EE:FF</t:HwAddress></t:Info><t:Extension><t:Dot11><t:SSID>Saved-WiFi</t:SSID><t:Security><t:PSK><t:Passphrase>never-export-me</t:Passphrase></t:PSK></t:Security></t:Dot11></t:Extension></t:NetworkInterfaces></Envelope>''')
        status = ET.fromstring('<Envelope xmlns:t="urn:types"><t:Status><t:SSID>Active-WiFi</t:SSID><t:BSSID>aa:bb:cc:dd:ee:ff</t:BSSID><t:SignalStrength>Good</t:SignalStrength><t:Channel>6</t:Channel></t:Status></Envelope>')
        with patch('audit.call', side_effect=[{'ok': True, 'root': network}, {'ok': True, 'root': status}]) as mock:
            interfaces, wifi = wireless_information('http://192.168.1.2/onvif/device_service', 1)
        self.assertEqual(wifi[0]['ssid'], 'Active-WiFi')
        self.assertEqual(wifi[0]['signal'], 'Good')
        self.assertEqual(wifi[0]['frequency'], '2437 MHz')
        self.assertEqual(mock.call_count, 2)
        self.assertNotIn('never-export-me', str((interfaces, wifi)))

    def test_unavailable_wifi_is_not_inferred(self):
        with patch('audit.call', return_value={'ok': False, 'root': None}):
            self.assertEqual(wireless_information('http://192.168.1.2/', 1), ([], []))

    def test_confidential_missing_data_is_explained_and_footer_is_safe(self):
        report = {'target': '192.168.1.2', 'port': 80, 'sensitive': {'collected': False, 'username': None, 'password': None}}
        html = render_html(report)
        self.assertIn('Събирането не е било включено', html)
        self.assertIn('Няма данни', html)
        self.assertIn('target="_blank" rel="noopener noreferrer"', html)
        self.assertIn('https://necrotixlab.com/services', html)

    def test_embedded_rtsp_credentials_are_labeled_in_confidential_report(self):
        report = {'target': '192.168.1.2', 'port': 80, 'sensitive': {
            'stream_uris': ['rtsp://camera-user:secret%21@192.168.1.2/live'], 'collected': True}}
        html = render_html(report)
        self.assertIn('camera-user', html)
        self.assertIn('secret!', html)
        self.assertIn('Вграден в RTSP адреса', html)
        self.assertIn('Потребител и парола за Wi-Fi/LAN мрежата: Няма данни', html)
        self.assertNotIn('secret!', render_html({k: v for k, v in report.items() if k != 'sensitive'}))


if __name__ == '__main__':
    unittest.main()
