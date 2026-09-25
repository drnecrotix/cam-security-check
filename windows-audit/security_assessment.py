"""Evidence-limited security checks. Unknown is never treated as passed."""


def assess(report):
    tests = []

    def add(key, title_bg, title_en, state, detail_bg, detail_en):
        tests.append({'key': key, 'status': state,
                      'bg': {'title': title_bg, 'detail': detail_bg},
                      'en': {'title': title_en, 'detail': detail_en}})

    if report.get('camera_type'):
        status = report.get('http_status_generic')
        add('http', 'Уеб интерфейс', 'Web interface',
            'pass' if status in (401, 403) else 'unknown',
            f'HTTP {status}; 401/403 означава ограничен достъп, а HTTP 200 не доказва вход.' if status else 'Няма HTTP отговор.',
            f'HTTP {status}; 401/403 indicates restricted access, while HTTP 200 does not prove login.' if status else 'No HTTP response.')
    else:
        for key, title_bg, title_en, status_key in [
            ('onvif_capabilities', 'ONVIF информация', 'ONVIF capabilities', 'capabilities'),
            ('onvif_profiles', 'ONVIF видео профили', 'ONVIF video profiles', 'profiles')]:
            code = (report.get('http_status') or {}).get(status_key)
            exposed = report.get('anonymous_capabilities' if status_key == 'capabilities' else 'anonymous_profiles')
            state = 'fail' if exposed else 'pass' if code in (401, 403) else 'unknown'
            add(key, title_bg, title_en, state,
                f'Анонимна заявка: HTTP {code if code is not None else "без отговор"}.',
                f'Anonymous request: HTTP {code if code is not None else "no response"}.')
        uri = report.get('anonymous_stream_uri')
        attempted = report.get('full_audit') or report.get('rtsp_describe') is not None or report.get('authenticated_stream_uri') is not None
        add('stream_uri', 'ONVIF адрес за видео', 'ONVIF video URI',
            'fail' if uri else 'pass' if report.get('stream_uri_http_status') in (401, 403) else 'unknown',
            'Адресът е върнат без вход.' if uri else 'Анонимният достъп до адрес не е потвърден.',
            'URI returned without login.' if uri else 'Anonymous URI access was not confirmed.')
    rtsp = report.get('rtsp_describe')
    code = rtsp.split(' ', 2)[1] if isinstance(rtsp, str) and rtsp.startswith('RTSP/') and len(rtsp.split(' ', 2)) > 1 else None
    add('rtsp', 'RTSP без парола', 'RTSP without password',
        'fail' if code == '200' else 'pass' if code in ('401', '403') else 'unknown',
        f'RTSP DESCRIBE: {rtsp or "не е проверено"}.',
        f'RTSP DESCRIBE: {rtsp or "not checked"}.')
    password = report.get('password_assessment') or {}
    add('password', 'Въведена парола', 'Supplied password',
        ('fail' if password.get('risk') in ('high', 'medium') else 'pass' if password.get('risk') == 'low' else 'unknown'),
        'Локална оценка; не доказва устойчивост срещу всички атаки.' if password.get('checked') else 'Парола не е въведена.',
        'Offline heuristic; does not prove resistance to all attacks.' if password.get('checked') else 'No password supplied.')
    count = {state: sum(test['status'] == state for test in tests) for state in ('pass', 'fail', 'unknown')}
    coverage = count['pass'] + count['fail']
    if count['fail']:
        rating = 'weak'
    elif (count['pass'] >= 4 and count['unknown'] == 0 and password.get('risk') == 'low' and
          not report.get('camera_type')):
        rating = 'excellent'
    elif count['pass'] >= 2:
        rating = 'good'
    else:
        rating = 'insufficient_data'
    return {'rating': rating, 'counts': count, 'checked': coverage, 'total': len(tests), 'tests': tests}
