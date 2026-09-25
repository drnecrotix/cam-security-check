import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_assessment import assess
from generic_camera import run
from reporting import render_html
from audit import split_stream_credentials
import ipaddress


class SecurityAssessmentTests(unittest.TestCase):
    def test_unreachable_is_not_secure(self):
        result = assess({'http_status': {'capabilities': None, 'profiles': None}, 'full_audit': True})
        self.assertEqual(result['rating'], 'insufficient_data')
        self.assertEqual(result['counts']['pass'], 0)

    def test_anonymous_access_is_weak(self):
        result = assess({'anonymous_capabilities': True, 'http_status': {'capabilities': 200, 'profiles': 401}})
        self.assertEqual(result['rating'], 'weak')
        self.assertEqual(next(t for t in result['tests'] if t['key'] == 'onvif_capabilities')['status'], 'fail')

    def test_protected_complete_check_can_be_excellent(self):
        result = assess({'http_status': {'capabilities': 401, 'profiles': 401},
                         'stream_uri_http_status': 401, 'rtsp_describe': 'RTSP/1.0 401 Unauthorized',
                         'password_assessment': {'checked': True, 'risk': 'low'}})
        self.assertEqual(result['rating'], 'excellent')
        self.assertEqual(result['counts']['unknown'], 0)

    def test_generic_no_path_is_unknown(self):
        with patch('generic_camera.http_check', return_value=200), patch('generic_camera.rtsp_options', return_value='RTSP/1.0 200 OK'):
            report = run('192.168.1.7', 80, 554, '', 1)
        self.assertEqual(report['security_assessment']['rating'], 'insufficient_data')
        self.assertEqual(report['rtsp_options'], 'RTSP/1.0 200 OK')
        self.assertEqual(next(t for t in report['security_assessment']['tests'] if t['key'] == 'rtsp')['status'], 'unknown')

    def test_full_audit_checks_reported_https_configuration(self):
        report = {'full_audit': True, 'configuration_snapshot': {
            'network_protocols': {'status': 'available', 'values': {'protocols': [
                {'name': 'HTTPS', 'enabled': 'false', 'ports': ['443']}]}},
            'discovery_mode': {'status': 'available', 'values': {'mode': 'Discoverable'}}}}
        result = assess(report)
        self.assertEqual(next(t for t in result['tests'] if t['key'] == 'https_config')['status'], 'fail')
        self.assertEqual(result['rating'], 'weak')

    def test_rtsp_uri_userinfo_is_separated_for_anonymous_probe(self):
        url, credentials = split_stream_credentials('rtsp://u:p%21@192.168.1.7:554/live',
                                                    ipaddress.ip_address('192.168.1.7'))
        self.assertEqual(url, 'rtsp://192.168.1.7:554/live')
        self.assertEqual(credentials, ('u', 'p!'))

    def test_report_escapes_device_info_and_optional_secrets(self):
        base = {'target': '192.168.1.7', 'port': 80, 'device_information': {'Model': '<camera>'}}
        self.assertIn('&lt;camera&gt;', render_html(base))
        self.assertNotIn('secret-value', render_html(base))
        with_secret = {**base, 'sensitive': {'password': 'secret-value', 'stream_uris': ['rtsp://192.168.1.7/live']}}
        self.assertIn('secret-value', render_html(with_secret))
        self.assertIn('>dr.necrotix</a>', render_html(with_secret))


if __name__ == '__main__':
    unittest.main()
