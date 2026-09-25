"""Bilingual, evidence-based camera audit report; no secrets or stream URLs."""
from datetime import datetime
from html import escape


def checklist(report):
    items = []

    def add(key, title, status, risk, evidence, action):
        items.append({'key': key, 'bg': dict(zip(('title', 'status', 'risk', 'evidence', 'action'),
                                               (title[0], status[0], risk[0], evidence[0], action[0]))),
                      'en': dict(zip(('title', 'status', 'risk', 'evidence', 'action'),
                                     (title[1], status[1], risk[1], evidence[1], action[1])))})

    def tri(value):
        return (('Потвърдено', 'Confirmed'), ('Не е потвърдено', 'Not confirmed'),
                ('Не е проверено', 'Not checked'))[0 if value is True else 1 if value is False else 2]

    access = [
        ('anonymous_capabilities', ('ONVIF информация без парола', 'Anonymous ONVIF capabilities'),
         ('Ограничи ONVIF до нужните акаунти и локални клиенти.', 'Restrict ONVIF to required accounts and local clients.'), 'medium'),
        ('anonymous_profiles', ('Видео профили без парола', 'Anonymous video profiles'),
         ('Изисквай удостоверяване за ONVIF Media и профилите.', 'Require authentication for ONVIF Media and profiles.'), 'medium'),
        ('anonymous_ptz_status', ('PTZ статус без парола', 'Anonymous PTZ status'),
         ('Ограничи четенето на PTZ статус до упълномощени клиенти.', 'Restrict PTZ status access to authorized clients.'), 'low'),
        ('anonymous_stream_uri', ('Адрес за видео без парола', 'Anonymous video URI'),
         ('Изисквай удостоверяване за GetStreamUri; провери и RTSP.', 'Require authentication for GetStreamUri; also check RTSP.'), 'medium'),
        ('movement_accepted', ('PTZ движение без парола', 'Anonymous PTZ movement'),
         ('Изключи анонимния PTZ контрол и ограничи мрежовия достъп.', 'Disable anonymous PTZ control and limit network access.'), 'high'),
    ]
    for key, title, action, severity in access:
        value = report.get(key)
        if key == 'movement_accepted' and not report.get('movement_attempted'):
            value = None
        if key == 'anonymous_stream_uri' and report.get('rtsp_describe') is None and not report.get('full_audit'):
            value = None
        risk = (('Висок', 'High') if severity == 'high' else ('Среден', 'Medium') if severity == 'medium' else ('Нисък', 'Low')) if value is True else ('Неустановен', 'Undetermined')
        evidence = (f'{key}={value}', f'{key}={value}')
        add(key, title, tri(value), risk, evidence, action if value is True else
            ('Провери настройката и документацията на камерата.', 'Review camera settings and documentation.'))

    rtsp = report.get('rtsp_describe')
    rtsp_ok = rtsp.startswith('RTSP/1.0 200 ') if isinstance(rtsp, str) else None
    add('rtsp', ('RTSP видео без парола', 'Anonymous RTSP video'), tri(rtsp_ok),
        ('Висок', 'High') if rtsp_ok else ('Неустановен', 'Undetermined'),
        (f'RTSP DESCRIBE: {rtsp or "няма отговор"}', f'RTSP DESCRIBE: {rtsp or "no response"}'),
        ('Изисквай RTSP удостоверяване и провери действително възпроизвеждане.', 'Require RTSP authentication and verify actual playback.')
        if rtsp_ok else ('Успешен DESCRIBE сам по себе си не доказва възпроизвеждане.', 'DESCRIBE alone does not prove playback.'))

    for key, title in [('authenticated_capabilities', ('ONVIF с данни', 'ONVIF with credentials')),
                       ('authenticated_profiles', ('Профили с данни', 'Profiles with credentials')),
                       ('authenticated_ptz_status', ('PTZ статус с данни', 'PTZ status with credentials')),
                       ('authenticated_stream_uri', ('Видео адрес с данни', 'Video URI with credentials'))]:
        value = report.get(key) if report.get('authenticated') else None
        add(key, title, tri(value), ('Информация', 'Information'), (f'{key}={value}', f'{key}={value}'),
            ('Сравни с анонимния резултат; успехът не доказва проверена парола.', 'Compare with anonymous result; success does not prove password validation.'))

    strength = report.get('password_assessment') or {'checked': False}
    risk = strength.get('risk')
    labels = {'high': ('Висок', 'High'), 'medium': ('Среден', 'Medium'), 'low': ('Нисък', 'Low')}
    evidence = (f'Дължина: {strength.get("length", "-")}; шаблони: {", ".join(strength.get("patterns", [])) or "няма"}; малък локален списък: {strength.get("matched_small_offline_guess_set", False)}',
                f'Length: {strength.get("length", "-")}; patterns: {", ".join(strength.get("patterns", [])) or "none"}; small offline guess set: {strength.get("matched_small_offline_guess_set", False)}')
    add('password_strength', ('Устойчивост на въведената парола', 'Supplied password strength'),
        (('Проверена локално', 'Checked offline') if strength.get('checked') else ('Не е проверено', 'Not checked')),
        labels.get(risk, ('Неустановен', 'Undetermined')), evidence,
        ('Смени я с уникална дълга парола и включи блокиране след неуспешни опити, ако устройството го поддържа.',
         'Use a long unique password and enable login attempt lockout if supported.') if risk in ('high', 'medium') else
        ('Пази паролата в мениджър и провери отделните акаунти.', 'Store the password in a manager and review separate accounts.'))
    add('snapshot', ('Снимка', 'Snapshot'), tri(report.get('snapshot_saved') if report.get('snapshot_saved') or report.get('snapshot_error') else None),
        ('Информация', 'Information'), (str(report.get('snapshot_error') or 'snapshot_saved=' + str(report.get('snapshot_saved'))),) * 2,
        ('Провери правата за снимка.', 'Review snapshot permissions.'))
    return items


def render_html(report, lang='bg'):
    en = lang.lower().startswith('en')
    label = lambda bg, english: english if en else bg
    rows = ''.join('<tr>' + ''.join(f'<td>{escape(str(item["en" if en else "bg"][key]))}</td>'
                                  for key in ('title', 'status', 'risk', 'evidence', 'action')) + '</tr>'
                   for item in report.get('checklist') or checklist(report))
    profiles = ''.join(f'<tr><td>{escape(str(x.get("name") or "?"))}</td><td>{escape(str(x.get("width") or "?"))} × {escape(str(x.get("height") or "?"))}</td><td>{escape(str(x.get("codec") or "?"))}</td></tr>'
                       for x in report.get('video_profiles') or [])
    return f'''<!doctype html><html lang="{'en' if en else 'bg'}"><meta charset="utf-8"><title>{label('CCTV отчет', 'CCTV report')}</title>
<style>body{{font:15px system-ui;background:#10151e;color:#e8eef5;max-width:1150px;margin:35px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%;margin:16px 0}}th,td{{border-bottom:1px solid #374555;padding:10px;text-align:left;vertical-align:top}}th{{background:#1b2532}}.muted{{color:#a8b8c9}}@media print{{body{{background:white;color:black}}th{{background:#eee}}}}</style>
<h1>{label('Подробен CCTV отчет', 'Detailed CCTV report')}</h1><p class="muted">{escape(str(report.get('target', '?')))}:{escape(str(report.get('port', '?')))} · {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}</p>
<h2>{label('Проверки, слаби места и действия', 'Checks, weaknesses and actions')}</h2><table><tr><th>{label('Проверка', 'Check')}</th><th>{label('Резултат', 'Result')}</th><th>{label('Риск', 'Risk')}</th><th>{label('Доказателство', 'Evidence')}</th><th>{label('Какво да подобриш', 'Action')}</th></tr>{rows}</table>
<h2>{label('Видео профили', 'Video profiles')}</h2><table><tr><th>{label('Име', 'Name')}</th><th>{label('Резолюция', 'Resolution')}</th><th>{label('Кодек', 'Codec')}</th></tr>{profiles or '<tr><td colspan="3">' + label('Няма получени профили', 'No profiles received') + '</td></tr>'}</table>
<p class="muted">{label('Паролата се оценява локално по дължина и малък списък с често използвани стойности. Не се записва и няма опити за отгатване към камерата. Неуспешна проверка не доказва пълна защита.', 'The password is assessed locally for length and a small set of common values. It is not saved and no guessing requests are sent to the camera. A negative check does not prove complete security.')}</p></html>'''
