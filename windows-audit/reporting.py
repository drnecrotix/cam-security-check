"""Human-readable, local HTML report without credentials or stream URLs."""
from datetime import datetime
from html import escape


def render_html(report):
    def value(key):
        item = report.get(key)
        return 'Да' if item is True else 'Не' if item is False else 'Не е проверено'

    rows = [
        ('ONVIF възможности без парола', value('anonymous_capabilities')),
        ('Видео профили без парола', value('anonymous_profiles')),
        ('PTZ статус без парола', value('anonymous_ptz_status')),
        ('Адрес за поток без парола', value('anonymous_stream_uri')),
        ('RTSP без парола', str(report.get('rtsp_describe') or 'Не е проверено')),
        ('ONVIF заявка с данни', value('authenticated_capabilities')),
        ('Профили с данни', value('authenticated_profiles')),
        ('PTZ статус с данни', value('authenticated_ptz_status')),
        ('RTSP с данни', str(report.get('authenticated_rtsp_describe') or 'Не е проверено')),
        ('PTZ движение без парола', value('movement_accepted')),
    ]
    advice = []
    if report.get('movement_accepted'):
        advice.append('Камерата е приела PTZ команда без парола. Потвърди физическото движение, после ограничи ONVIF достъпа.')
    if str(report.get('rtsp_describe') or '').startswith('RTSP/1.0 200 '):
        advice.append('RTSP е върнал успешен отговор без парола. Провери дали видеото действително се възпроизвежда.')
    if report.get('anonymous_profiles'):
        advice.append('Видео профилите са достъпни без удостоверяване. Прегледай настройките за ONVIF акаунти.')
    if not advice:
        advice.append('Няма потвърден анонимен контрол или видеодостъп от този тест. Това не доказва пълна защита.')
    advice.append('Провери фърмуера, смени фабричните пароли и не излагай ONVIF/RTSP портове директно в интернет.')
    profiles = report.get('video_profiles') or []
    profile_rows = ''.join(f'<tr><td>{escape(str(x.get("name") or "Без име"))}</td>'
                           f'<td>{escape(str(x.get("width") or "?"))} × {escape(str(x.get("height") or "?"))}</td>'
                           f'<td>{escape(str(x.get("codec") or "Неизвестен"))}</td></tr>' for x in profiles)
    table_rows = ''.join(f'<tr><th>{escape(label)}</th><td>{escape(result)}</td></tr>' for label, result in rows)
    notes = ''.join(f'<li>{escape(text)}</li>' for text in advice)
    return f'''<!doctype html><html lang="bg"><meta charset="utf-8"><title>CCTV проверка</title>
<style>body{{font:16px system-ui,sans-serif;max-width:850px;margin:40px auto;padding:0 20px;color:#17212b}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}th,td{{border-bottom:1px solid #d8dfe5;padding:10px;text-align:left}}
th{{width:55%;background:#f5f7f9}}h1{{margin-bottom:0}}.muted{{color:#536475}}li{{margin:9px 0}}</style>
<h1>Проверка на CCTV камера</h1><p class="muted">{escape(str(report.get('target', '?')))}:{escape(str(report.get('port', '?')))} · {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M %Z')}</p>
<h2>Достъп</h2><table>{table_rows}</table>
<h2>Видео профили</h2><table><tr><th>Име</th><th>Резолюция</th><th>Кодек</th></tr>{profile_rows or '<tr><td colspan="3">Няма получени профили</td></tr>'}</table>
<h2>Изводи и действия</h2><ul>{notes}</ul>
<p class="muted">Успешна заявка с данни не доказва, че паролата е проверена, ако същата заявка работи без парола. Неуспешна проверка не доказва, че камерата е защитена.</p></html>'''
