import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit import configuration_snapshot
from reporting import render_html


class ConfigurationReportTests(unittest.TestCase):
    def test_allowlisted_settings_never_include_vendor_secrets(self):
        xml = ET.fromstring('''<Envelope xmlns:t="urn:types"><t:NetworkProtocols><t:Name>RTSP</t:Name><t:Enabled>true</t:Enabled><t:Port>554</t:Port><t:Secret>do-not-export</t:Secret></t:NetworkProtocols></Envelope>''')
        with patch('audit.call', return_value={'ok': True, 'root': xml}) as call:
            snapshot = configuration_snapshot('http://192.168.1.2/onvif/device_service', 1)
        self.assertEqual(call.call_count, 7)
        self.assertEqual(snapshot['network_protocols']['values']['protocols'][0]['ports'], ['554'])
        self.assertNotIn('do-not-export', str(snapshot))

    def test_denied_operation_is_marked_unavailable(self):
        with patch('audit.call', return_value={'ok': False, 'root': None}):
            snapshot = configuration_snapshot('http://192.168.1.2/onvif/device_service', 1)
        self.assertTrue(all(item['status'] == 'unavailable' for item in snapshot.values()))

    def test_page_has_both_languages_and_safe_support_links(self):
        report = {'target': '192.168.1.2', 'port': 80,
                  'configuration_snapshot': {'hostname': {'status': 'available', 'values': {'name': '<mycam>'}}}}
        page = render_html(report, 'en')
        self.assertIn('id="report-bg"', page)
        self.assertIn('id="report-en"', page)
        self.assertIn('Заяви Поддръжка', page)
        self.assertIn('Request Support', page)
        self.assertIn('&lt;mycam&gt;', page)
        self.assertEqual(page.count('target="_blank" rel="noopener noreferrer"'), 4)
        self.assertEqual(page.count('href="https://necrotixlab.com/services" target="_blank"'), 2)
        self.assertEqual(page.count('href="https://github.com/drnecrotix" target="_blank"'), 2)
        self.assertIn('footer a,footer a:visited{color:#e8eef5', page)


if __name__ == '__main__':
    unittest.main()
