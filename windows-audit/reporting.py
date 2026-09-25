"""Human-readable bilingual CCTV audit with no passwords or stream URLs."""
from datetime import datetime
from html import escape


def checklist(report):
    items = []

    def add(key, title, value, severity, evidence, fix):
        status = (('Потвърдено', 'Confirmed') if value is True else
                  ('Не е потвърдено', 'Not confirmed') if value is False else
                  ('Не е проверено', 'Not checked'))
        risk = ({'high': ('Висок', 'High'), 'medium': ('Среден', 'Medium'),
                 'low': ('Нисък', 'Low')}.get(severity, ('Информация', 'Information'))
                if value is True else ('Неустановен', 'Undetermined'))
        items.append({'key': key, 'finding': value is True and severity in ('high', 'medium', 'low'),
                      'bg': dict(zip(('title', 'status', 'risk', 'evidence', 'action'),
                                     (title[0], status[0], risk[0], evidence[0], fix[0]))),
                      'en': dict(zip(('title', 'status', 'risk', 'evidence', 'action'),
                                     (title[1], status[1], risk[1], evidence[1], fix[1])))})

    specs = [
        ('anonymous_capabilities', ('ONVIF информация без парола', 'ONVIF capabilities without password'), 'medium',
         ('Камерата върна ONVIF възможностите без вход.', 'The camera returned ONVIF capabilities without login.'),
         ('Ограничи ONVIF до упълномощени акаунти и локални клиенти.', 'Restrict ONVIF to authorized accounts and local clients.')),
        ('anonymous_profiles', ('Видео профили без парола', 'Video profiles without password'), 'medium',
         ('ONVIF Media върна профили без вход.', 'ONVIF Media returned profiles without login.'),
         ('Изисквай удостоверяване за ONVIF Media.', 'Require authentication for ONVIF Media.')),
        ('anonymous_ptz_status', ('PTZ статус без парола', 'PTZ status without password'), 'low',
         ('PTZ статусът се чете без вход; това не доказва контрол на движението.',
          'PTZ status is readable without login; this does not prove movement control.'),
         ('Ограничи четенето на PTZ статус до упълномощени клиенти.', 'Restrict PTZ status to authorized clients.')),
        ('anonymous_stream_uri', ('Адрес за видео без парола', 'Video URI without password'), 'medium',
         ('ONVIF върна адрес за поток без вход; възпроизвеждането се проверява отделно.',
          'ONVIF returned a stream URI without login; playback needs a separate check.'),
         ('Изисквай удостоверяване за GetStreamUri и провери RTSP.', 'Require authentication for GetStreamUri and check RTSP.')),
        ('movement_accepted', ('PTZ команда без парола', 'PTZ command without password'), 'high',
         ('Камерата прие команда за движение без вход; провери физическото движение.',
          'The camera accepted a movement command without login; verify physical movement.'),
         ('Забрани анонимния PTZ контрол.', 'Disable anonymous PTZ control.')),
    ]
    for key, title, severity, evidence, fix in specs:
        value = report.get(key)
        if key == 'movement_accepted' and not report.get('movement_attempted'):
            value = None
        if key == 'anonymous_stream_uri' and not (report.get('full_audit') or report.get('rtsp_describe') is not None or report.get('authenticated')):
            value = None
        add(key, title, value, severity,
            evidence if value is True else
            (('Заявката не даде потвърден анонимен достъп.', 'The request did not confirm anonymous access.')
             if value is False else ('Тази операция не беше изпълнена.', 'This operation was not run.')), fix)

    rtsp = report.get('rtsp_describe')
    rtsp_ok = (rtsp.startswith('RTSP/1.0 200 ') if isinstance(rtsp, str) and rtsp.startswith('RTSP/') else None)
    add('rtsp', ('RTSP отговор без парола', 'RTSP response without password'), rtsp_ok, 'high',
        (f'RTSP DESCRIBE: {rtsp}' if rtsp else 'RTSP не беше проверен.',
         f'RTSP DESCRIBE: {rtsp}' if rtsp else 'RTSP was not checked.'),
        ('Изисквай RTSP удостоверяване и потвърди дали видеото се възпроизвежда.',
         'Require RTSP authentication and verify actual video playback.'))

    if report.get('authenticated'):
        for key, title in [
            ('authenticated_capabilities', ('ONVIF с данни', 'ONVIF with credentials')),
            ('authenticated_profiles', ('Профили с данни', 'Profiles with credentials')),
            ('authenticated_ptz_status', ('PTZ статус с данни', 'PTZ status with credentials')),
            ('authenticated_stream_uri', ('Видео адрес с данни', 'Video URI with credentials'))]:
            value = report.get(key)
            add(key, title, value, 'info',
                (('Заявката с въведените данни успя.', 'The request with supplied credentials succeeded.') if value else
                 ('Заявката с въведените данни не успя.', 'The request with supplied credentials did not succeed.')),
                ('Сравни с анонимната проверка; успехът сам по себе си не доказва проверена парола.',
                 'Compare with anonymous access; success alone does not prove password validation.'))

    strength = report.get('password_assessment') or {}
    if strength.get('checked'):
        risk = strength.get('risk')
        patterns = ', '.join(strength.get('patterns', []))
        add('password_strength', ('Въведена парола', 'Supplied password'), risk in ('high', 'medium'),
            risk if risk in ('high', 'medium') else 'info',
            (f'Локална оценка: {strength.get("length", "?")} символа; често срещана: {"да" if strength.get("matched_small_offline_guess_set") else "не"}; предвидими шаблони: {patterns or "няма"}.',
             f'Offline assessment: {strength.get("length", "?")} characters; common: {"yes" if strength.get("matched_small_offline_guess_set") else "no"}; predictable patterns: {patterns or "none"}.'),
            ('Използвай уникална дълга парола и провери настройките за блокиране на опити.',
             'Use a long unique password and review login attempt lockout settings.'))
    else:
        add('password_strength', ('Въведена парола', 'Supplied password'), None, 'info',
            ('Не са въведени данни за локална оценка.', 'No credentials were supplied for local assessment.'),
            ('Въведи собствен ONVIF акаунт за сравнение.', 'Supply your ONVIF account for comparison.'))

    if report.get('snapshot_saved') or report.get('snapshot_error'):
        add('snapshot', ('Снимка', 'Snapshot'), bool(report.get('snapshot_saved')), 'info',
            (('Снимката беше записана.', 'Snapshot was saved.') if report.get('snapshot_saved') else
             ('Заявката за снимка не успя.', 'Snapshot request did not succeed.')),
            ('Провери настройките за достъп до снимки.', 'Review snapshot access settings.'))
    return items


def render_html(report, lang='bg'):
    en = lang.lower().startswith('en')
    label = lambda bg, english: english if en else bg
    items = report.get('checklist') or checklist(report)
    selected = 'en' if en else 'bg'
    findings = [item for item in items if item.get('finding')]
    pending = [item for item in items if item[selected]['status'] in ('Не е проверено', 'Not checked')]
    rows = ''.join('<tr class="' + ('finding' if item.get('finding') else '') + '">' +
                   ''.join(f'<td data-label="{escape(label(*headers[i]))}">{escape(str(item[selected][key]))}</td>'
                           for i, key in enumerate(('title', 'status', 'risk', 'evidence', 'action'))) + '</tr>'
                   for item in items for headers in [[('Проверка', 'Check'), ('Резултат', 'Result'),
                                                      ('Риск', 'Risk'), ('Наблюдение', 'Observation'),
                                                      ('Какво да подобриш', 'Action')]])
    profile_rows = ''.join(f'<tr><td>{escape(str(x.get("name") or "?"))}</td><td>{escape(str(x.get("width") or "?"))} × {escape(str(x.get("height") or "?"))}</td><td>{escape(str(x.get("codec") or "?"))}</td></tr>'
                           for x in report.get('video_profiles') or [])
    summary = ''.join(f'<li><strong>{escape(item[selected]["title"])}</strong> - {escape(item[selected]["action"])}</li>' for item in findings)
    return f'''<!doctype html><html lang="{'en' if en else 'bg'}"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{label('CCTV отчет', 'CCTV report')}</title>
<style>body{{font:15px/1.5 system-ui;background:#10151e;color:#e8eef5;max-width:1180px;margin:32px auto;padding:0 20px}}h1,h2{{line-height:1.2}}.muted{{color:#a8b8c9}}.summary{{background:#1b2532;border-left:4px solid #35b7a8;padding:12px 18px;border-radius:5px}}.summary li{{margin:8px 0}}table{{border-collapse:collapse;width:100%;margin:16px 0}}th,td{{border-bottom:1px solid #374555;padding:10px;text-align:left;vertical-align:top}}th{{background:#1b2532}}.finding td:nth-child(3){{color:#f6c453;font-weight:bold}}footer{{text-align:right;color:#a8b8c9;padding:30px 0 12px}}@media(max-width:760px){{thead{{display:none}}tr{{display:block;border:1px solid #374555;margin:12px 0}}td{{display:block;border:0}}td::before{{content:attr(data-label) ': ';font-weight:bold;color:#35b7a8}}}}@media print{{body{{background:white;color:black}}.summary,th{{background:#eee}}footer{{color:#333}}}}</style>
<h1>{label('Подробен CCTV отчет', 'Detailed CCTV report')}</h1><p class="muted">{escape(str(report.get('target', '?')))}:{escape(str(report.get('port', '?')))} · {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}</p>
<section class="summary"><h2>{label('Приоритетни действия', 'Priority actions')}</h2><p>{label('Установени слаби места', 'Findings')}: {len(findings)} · {label('Непроверени', 'Not checked')}: {len(pending)}</p><ul>{summary or '<li>' + label('Няма потвърдено слабо място от извършените проверки.', 'No weakness confirmed by the performed checks.') + '</li>'}</ul></section>
<h2>{label('Проверки и доказателства', 'Checks and evidence')}</h2><table><thead><tr><th>{label('Проверка', 'Check')}</th><th>{label('Резултат', 'Result')}</th><th>{label('Риск', 'Risk')}</th><th>{label('Наблюдение', 'Observation')}</th><th>{label('Какво да подобриш', 'Action')}</th></tr></thead><tbody>{rows}</tbody></table>
<h2>{label('Видео профили', 'Video profiles')}</h2><table><tr><th>{label('Име', 'Name')}</th><th>{label('Резолюция', 'Resolution')}</th><th>{label('Кодек', 'Codec')}</th></tr>{profile_rows or '<tr><td colspan="3">' + label('Няма получени профили', 'No profiles received') + '</td></tr>'}</table>
<p class="muted">{label('RTSP DESCRIBE 200 не доказва възпроизвеждане. Отрицателен тест не доказва пълна защита. Паролата се оценява локално и не се записва.', 'RTSP DESCRIBE 200 does not prove playback. A negative test does not prove complete security. Password assessment is local and the password is not saved.')}</p>
<footer>dev: dr.necrotix</footer></html>'''
