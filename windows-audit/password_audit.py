"""Offline assessment of a supplied password; never connects to a device."""
import re

COMMON = {
    'admin', 'admin123', 'administrator', 'password', 'password123', '123456',
    '12345678', '123456789', '1234567890', 'qwerty', 'qwerty123', '111111',
    '000000', '12345', '1234', 'root', 'guest', 'camera', 'camera123',
    'ipcam', 'ipcam123', 'onvif', 'onvif123', 'changeme', 'letmein',
}


def assess(password, username=''):
    if password is None:
        return {'checked': False}
    lower = password.casefold()
    user = username.casefold().strip()
    matched_common = lower in COMMON or (user and lower in {user, user + '123', user + '1234', user + '2026'})
    patterns = []
    if matched_common:
        patterns.append('common_or_username_variant')
    if re.search(r'(.)\1{3,}', password):
        patterns.append('repeated_characters')
    if any(sequence in lower for sequence in ('1234', 'abcd', 'qwerty', 'admin', 'password')):
        patterns.append('predictable_sequence')
    classes = sum(bool(re.search(pattern, password)) for pattern in (r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'))
    if matched_common or len(password) < 10:
        risk = 'high'
    elif len(password) < 14 or patterns or classes < 2:
        risk = 'medium'
    else:
        risk = 'low'
    return {'checked': True, 'risk': risk, 'length': len(password),
            'character_classes': classes, 'patterns': patterns,
            'matched_small_offline_guess_set': bool(matched_common)}
