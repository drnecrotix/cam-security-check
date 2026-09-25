"""Human-readable, local HTML report without credentials or stream URLs."""
from datetime import datetime
from html import escape


def render_html(report, lang='bg'):
    en = lang.lower().startswith('en')
    label = lambda bg, english: english if en else bg
    def value(key):
        item = report.get(key)
        return label('Да', 'Yes') if item is True else label('Не', 'No') if item is False else label('Не е проверено', 'Not checked')

    rows = [
        (label('ONVIF възможности без парола', 'ONVIF capabilities without password'), value('anonymous_capabilities')),
        (label('Видео профили без парола', 'Video profiles without password'), value('anonymous_profiles')),
        (label('PTZ статус без парола', 'PTZ status without password'), value('anonymous_ptz_status')),
        (label('Адрес за поток без парола', 'Stream URI without password'), value('anonymous_stream_uri')),
        (label('RTSP без парола', 'RTSP without password'), str(report.get('rtsp_describe') or label('Не е проверено', 'Not checked'))),
        (label('ONVIF заявка с данни', 'ONVIF with credentials'), value('authenticated_capabilities')),
        (label('Профили с данни', 'Profiles with credentials'), value('authenticated_profiles')),
        (label('PTZ статус с данни', 'PTZ with credentials'), value('authenticated_ptz_status')),
        (label('RTSP с данни', 'RTSP with credentials'), str(report.get('authenticated_rtsp_describe') or label('Не е проверено', 'Not checked'))),
        (label('PTZ движение без парола', 'PTZ movement without password'), value('movement_accepted')),
    ]
    advice = []
    if report.get('movement_accepted'):
        advice.append(label('Камерата е приела PTZ команда без парола. Потвърди физическото движение, после ограничи ONVIF достъпа.',
                            'The camera accepted a PTZ command without a password. Confirm physical movement, then restrict ONVIF access.'))
    if str(report.get('rtsp_describe') or '').startswith('RTSP/1.0 200 '):
        advice.append(label('RTSP е върнал успешен отговор без парола. Провери дали видеото действително се възпроизвежда.',
                            'RTSP returned success without a password. Confirm that the video actually plays.'))
    if report.get('anonymous_profiles'):
        advice.append(label('Видео профилите са достъпни без удостоверяване. Прегледай настройките за ONVIF акаунти.',
                            'Video profiles are readable without authentication. Review ONVIF account settings.'))
    if not advice:
        advice.append(label('Няма потвърден анонимен контрол или видеодостъп от този тест. Това не доказва пълна защита.',
                            'This test did not confirm anonymous control or video access. It does not prove complete security.'))
    advice.append(label('Провери фърмуера, смени фабричните пароли и не излагай ONVIF/RTSP портове директно в интернет.',
                        'Check firmware, change default passwords, and do not expose ONVIF/RTSP ports directly to the Internet.'))
    profiles = report.get('video_profiles') or []
    profile_rows = ''.join(f'<tr><td>{escape(str(x.get("name") or label("Без име", "Unnamed")))}</td>'
                           f'<td>{escape(str(x.get("width") or "?"))} × {escape(str(x.get("height") or "?"))}</td>'
                           f'<td>{escape(str(x.get("codec") or label("Неизвестен", "Unknown")))}</td></tr>' for x in profiles)
    table_rows = ''.join(f'<tr><th>{escape(label)}</th><td>{escape(result)}</td></tr>' for label, result in rows)
    notes = ''.join(f'<li>{escape(text)}</li>' for text in advice)
    return f'''<!doctype html><html lang="{'en' if en else 'bg'}"><meta charset="utf-8"><title>{label('CCTV проверка', 'CCTV Audit')}</title>
<style>body{{font:16px system-ui,sans-serif;max-width:850px;margin:40px auto;padding:0 20px;color:#17212b}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}th,td{{border-bottom:1px solid #d8dfe5;padding:10px;text-align:left}}
th{{width:55%;background:#f5f7f9}}h1{{margin-bottom:0}}.muted{{color:#536475}}li{{margin:9px 0}}</style>
<h1>{label('Проверка на CCTV камера', 'CCTV camera audit')}</h1><p class="muted">{escape(str(report.get('target', '?')))}:{escape(str(report.get('port', '?')))} · {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}</p>
<h2>{label('Достъп', 'Access')}</h2><table>{table_rows}</table>
<h2>{label('Видео профили', 'Video profiles')}</h2><table><tr><th>{label('Име', 'Name')}</th><th>{label('Резолюция', 'Resolution')}</th><th>{label('Кодек', 'Codec')}</th></tr>{profile_rows or '<tr><td colspan="3">' + label('Няма получени профили', 'No profiles received') + '</td></tr>'}</table>
<h2>{label('Изводи и действия', 'Findings and actions')}</h2><ul>{notes}</ul>
<p class="muted">{label('Успешна заявка с данни не доказва, че паролата е проверена, ако същата заявка работи без парола. Неуспешна проверка не доказва, че камерата е защитена.', 'A successful credentialed request does not prove the password was checked when the anonymous request also works. A negative test does not prove the camera is secure.')}</p></html>'''
