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

    if report.get('camera_type'):
        http = report.get('http_status_generic')
        add('http_interface', ('Уеб интерфейс', 'Web interface'),
            http is not None if http is not None else None, 'info',
            (f'HTTP отговор: {http}.' if http is not None else 'Няма HTTP отговор.',
             f'HTTP response: {http}.' if http is not None else 'No HTTP response.'),
            ('Провери дали интерфейсът изисква вход и дали има HTTPS.',
             'Check whether the interface requires login and supports HTTPS.'))
        rtsp = report.get('rtsp_describe')
        rtsp_ok = rtsp.startswith('RTSP/1.0 200 ') if isinstance(rtsp, str) and rtsp.startswith('RTSP/') else None
        add('rtsp', ('RTSP отговор без парола', 'RTSP response without password'), rtsp_ok, 'high',
            (f'RTSP DESCRIBE: {rtsp}' if rtsp else 'Не е въведен RTSP път.',
             f'RTSP DESCRIBE: {rtsp}' if rtsp else 'No RTSP path supplied.'),
            ('Изисквай удостоверяване и провери възпроизвеждането.',
             'Require authentication and verify actual playback.'))
        auth = report.get('authenticated_rtsp_describe')
        if report.get('authenticated') and report.get('rtsp_path_supplied'):
            add('authenticated_rtsp', ('RTSP с данни', 'RTSP with credentials'),
                auth.startswith('RTSP/1.0 200 ') if isinstance(auth, str) and auth.startswith('RTSP/') else None,
                'info', (f'RTSP DESCRIBE: {auth}', f'RTSP DESCRIBE: {auth}'),
                ('Сравни с анонимния резултат.', 'Compare with anonymous access.'))
        _add_password(items, add, report)
        return items

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

    _add_password(items, add, report)

    if report.get('snapshot_saved') or report.get('snapshot_error'):
        add('snapshot', ('Снимка', 'Snapshot'), bool(report.get('snapshot_saved')), 'info',
            (('Снимката беше записана.', 'Snapshot was saved.') if report.get('snapshot_saved') else
             ('Заявката за снимка не успя.', 'Snapshot request did not succeed.')),
            ('Провери настройките за достъп до снимки.', 'Review snapshot access settings.'))
    return items


def _add_password(items, add, report):
    strength = report.get('password_assessment') or {}
    if strength.get('checked'):
        risk = strength.get('risk')
        patterns = ', '.join(strength.get('patterns', []))
        add('password_strength', ('Въведена парола', 'Supplied password'), risk in ('high', 'medium'),
            risk if risk in ('high', 'medium') else 'info',
            (f'Локална оценка: {strength.get("length", "?")} символа; често срещана: {"да" if strength.get("matched_small_offline_guess_set") else "не"}; предвидими шаблони: {patterns or "няма"}; локални кандидати: {strength.get("offline_candidates_checked", 0)}.',
             f'Offline assessment: {strength.get("length", "?")} characters; common: {"yes" if strength.get("matched_small_offline_guess_set") else "no"}; predictable patterns: {patterns or "none"}; local candidates: {strength.get("offline_candidates_checked", 0)}.'),
            ('Използвай уникална дълга парола и провери настройките за блокиране на опити.',
             'Use a long unique password and review login attempt lockout settings.'))
    else:
        add('password_strength', ('Въведена парола', 'Supplied password'), None, 'info',
            ('Не са въведени данни за локална оценка.', 'No credentials were supplied for local assessment.'),
            ('Въведи собствен ONVIF акаунт за сравнение.', 'Supply your ONVIF account for comparison.'))



def render_html(report, lang='bg'):
    en = lang.lower().startswith('en')
    label = lambda bg, english: english if en else bg
    items = report.get('checklist') or checklist(report)
    selected = 'en' if en else 'bg'
    security = report.get('security_assessment') or {}
    ratings = {'excellent': ('Отлична', 'Excellent'), 'good': ('Добра', 'Good'),
               'weak': ('Слаба', 'Weak'), 'insufficient_data': ('Недостатъчно данни', 'Insufficient data')}
    grade = label(*ratings.get(security.get('rating'), ('Неоценена', 'Not assessed')))
    test_labels = {'pass': ('Издържан', 'Passed'), 'fail': ('Неуспешен', 'Failed'),
                   'unknown': ('Непроверен', 'Unknown')}
    test_rows = ''.join(f'<tr><td>{escape(t[selected]["title"])}</td><td>{escape(label(*test_labels[t["status"]]))}</td><td>{escape(t[selected]["detail"])}</td></tr>'
                        for t in security.get('tests', []))
    info = report.get('device_information') or {}
    info_rows = ''.join(f'<tr><th>{escape(str(k))}</th><td>{escape(str(v))}</td></tr>' for k, v in info.items() if v)
    sensitive = report.get('sensitive') or {}
    private_rows = ''.join(f'<tr><th>{escape(str(key))}</th><td>{escape(str(value or "-"))}</td></tr>'
                           for key, value in (('username', sensitive.get('username')),
                                              ('password', sensitive.get('password'))))
    private_rows += ''.join(f'<tr><th>RTSP {index}</th><td>{escape(str(uri))}</td></tr>'
                            for index, uri in enumerate(sensitive.get('stream_uris') or [], 1))
    private_section = (f'<section class="summary"><h2>{label("Поверителни данни - не споделяй отчета", "Confidential data - do not share this report")}</h2><table>{private_rows}</table></section>'
                       if sensitive else '')
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
<h1>{label('Подробен CCTV отчет', 'Detailed CCTV report')}</h1><p class="muted">{escape(str(report.get('camera_type') or 'ONVIF'))} · {escape(str(report.get('target', '?')))}:{escape(str(report.get('port', '?')))} · {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}</p>
<section class="summary"><h2>{label('Оценка на защитата', 'Security rating')}: {escape(grade)}</h2><p>{label('Издържани', 'Passed')}: {security.get('counts', {}).get('pass', 0)} · {label('Неуспешни', 'Failed')}: {security.get('counts', {}).get('fail', 0)} · {label('Непроверени', 'Unknown')}: {security.get('counts', {}).get('unknown', 0)}</p><p class="muted">{label('Оценката обхваща само изброените проверки. Недостъпно устройство не се счита за защитено.', 'The rating covers only listed checks. An unreachable device is not considered secure.')}</p></section>
<section class="summary"><h2>{label('Приоритетни действия', 'Priority actions')}</h2><p>{label('Установени слаби места', 'Findings')}: {len(findings)} · {label('Непроверени', 'Not checked')}: {len(pending)}</p><ul>{summary or '<li>' + label('Няма потвърдено слабо място от извършените проверки.', 'No weakness confirmed by the performed checks.') + '</li>'}</ul></section>
<h2>{label('Автоматични тестове', 'Automated security checks')}</h2><table><tr><th>{label('Тест', 'Test')}</th><th>{label('Статус', 'Status')}</th><th>{label('Доказателство', 'Evidence')}</th></tr>{test_rows or '<tr><td colspan="3">' + label('Няма данни', 'No data') + '</td></tr>'}</table>
<h2>{label('Информация за устройството', 'Device information')}</h2><table>{info_rows or '<tr><td>' + label('Не е предоставена', 'Not provided') + '</td></tr>'}</table>
{private_section}
<h2>{label('Проверки и доказателства', 'Checks and evidence')}</h2><table><thead><tr><th>{label('Проверка', 'Check')}</th><th>{label('Резултат', 'Result')}</th><th>{label('Риск', 'Risk')}</th><th>{label('Наблюдение', 'Observation')}</th><th>{label('Какво да подобриш', 'Action')}</th></tr></thead><tbody>{rows}</tbody></table>
<h2>{label('Видео профили', 'Video profiles')}</h2><table><tr><th>{label('Име', 'Name')}</th><th>{label('Резолюция', 'Resolution')}</th><th>{label('Кодек', 'Codec')}</th></tr>{profile_rows or '<tr><td colspan="3">' + label('Няма получени профили', 'No profiles received') + '</td></tr>'}</table>
<p class="muted">{label('RTSP DESCRIBE 200 не доказва възпроизвеждане. Отрицателен тест не доказва пълна защита. Паролата се оценява локално и не се записва.', 'RTSP DESCRIBE 200 does not prove playback. A negative test does not prove complete security. Password assessment is local and the password is not saved.')}</p>
<footer>dev: dr.necrotix</footer></html>'''
