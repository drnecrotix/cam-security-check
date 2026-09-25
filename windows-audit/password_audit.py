"""Bounded offline candidate and pattern assessment; no device traffic or saved secret."""
import re

BASE_WORDS = (
    'admin', 'administrator', 'password', 'pass', 'root', 'guest', 'user',
    'camera', 'cam', 'ipcam', 'cctv', 'onvif', 'security', 'surveillance',
    'welcome', 'changeme', 'letmein', 'default', 'test', 'service',
    'qwerty', 'asdf', 'abc', '123456', '12345678', '111111', '000000',
)
SUFFIXES = ('', '1', '12', '123', '1234', '12345', '!', '!!', '@', '#', '2024', '2025', '2026', '2027')
TRANSLATE_LEET = str.maketrans({'@': 'a', '4': 'a', '0': 'o', '1': 'i', '3': 'e', '5': 's', '$': 's', '7': 't'})


def candidates(username=''):
    """Deterministic small local guess set; never transmitted to a camera."""
    words = list(BASE_WORDS)
    user = username.casefold().strip()
    if user and 1 <= len(user) <= 48:
        words.append(user)
    seen = set()
    for word in words:
        for suffix in SUFFIXES:
            for candidate in (word + suffix, word.capitalize() + suffix, word.upper() + suffix):
                if candidate.casefold() not in seen:
                    seen.add(candidate.casefold())
                    yield candidate.casefold()
    for number in range(1, 1001):
        candidate = str(number)
        if candidate not in seen:
            seen.add(candidate)
            yield candidate


def assess(password, username=''):
    if password is None:
        return {'checked': False}
    normalized = password.casefold()
    folded = normalized.translate(TRANSLATE_LEET)
    local_set = set(candidates(username))
    matched = normalized in local_set or folded in local_set
    patterns = []
    if matched:
        patterns.append('offline_candidate_match')
    if re.search(r'(.)\1{3,}', normalized):
        patterns.append('repeated_characters')
    if any(sequence in folded for sequence in ('1234', '4321', 'abcd', 'dcba', 'qwerty', 'asdf', 'zxcv')):
        patterns.append('predictable_sequence')
    if re.search(r'(19|20)\d{2}', normalized):
        patterns.append('year')
    user = username.casefold().strip()
    if len(user) >= 3 and user in normalized:
        patterns.append('contains_username')
    if len(password) >= 6 and len(set(normalized)) <= 2:
        patterns.append('low_variety')
    classes = sum(bool(re.search(pattern, password)) for pattern in
                  (r'[a-z]', r'[A-Z]', r'\d', r'[^A-Za-z0-9]'))
    if matched or len(password) < 12 or 'contains_username' in patterns or 'low_variety' in patterns:
        risk = 'high'
    elif len(password) < 16 or patterns:
        risk = 'medium'
    else:
        risk = 'low'
    return {'checked': True, 'risk': risk, 'length': len(password),
            'character_classes': classes, 'patterns': patterns,
            'matched_small_offline_guess_set': bool(matched),
            'offline_candidates_checked': len(local_set)}
