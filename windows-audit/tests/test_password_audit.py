import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from password_audit import assess


class PasswordAuditTests(unittest.TestCase):
    def test_common_and_leet_variants(self):
        for password in ('Admin123!', 'P@ssword123', 'camera2026'):
            self.assertEqual(assess(password, 'owner')['risk'], 'high')

    def test_username_and_short_password(self):
        self.assertEqual(assess('Nikola2026Secret', 'Nikola')['risk'], 'high')
        self.assertEqual(assess('N8$short')['risk'], 'high')

    def test_long_unique_password_does_not_claim_proof(self):
        result = assess('Vh8!uQp2#Nw6@zRk9')
        self.assertEqual(result['risk'], 'low')
        self.assertGreater(result['offline_candidates_checked'], 1000)
        self.assertNotIn('password', result)
        self.assertNotIn('candidate', result)

    def test_missing_password_unknown(self):
        self.assertFalse(assess(None)['checked'])


if __name__ == '__main__':
    unittest.main()
