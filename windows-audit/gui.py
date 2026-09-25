"""Windows-friendly single-camera interface for audit.py."""
import ipaddress
import json
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from scan import DEFAULT_PORTS, parse_ports, scan


class App:
    def __init__(self, root):
        self.root = root
        root.title('Проверка на ONVIF камера')
        root.geometry('680x540')
        root.minsize(560, 450)
        self.ip = tk.StringVar()
        self.port = tk.StringVar(value='80')
        self.scan_ports = tk.StringVar(value=DEFAULT_PORTS)
        self.status = tk.StringVar(value='Въведи локалния IP адрес на твоята камера.')

        frame = ttk.Frame(root, padding=18)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Проверка на собствена камера', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Само една камера в частната ти мрежа. Без търсене на други устройства.').pack(anchor='w', pady=(4, 16))

        fields = ttk.Frame(frame)
        fields.pack(fill='x')
        ttk.Label(fields, text='IP адрес').grid(row=0, column=0, sticky='w')
        ttk.Entry(fields, textvariable=self.ip, width=24).grid(row=1, column=0, sticky='ew', padx=(0, 12))
        ttk.Label(fields, text='ONVIF порт').grid(row=0, column=1, sticky='w')
        ttk.Entry(fields, textvariable=self.port, width=12).grid(row=1, column=1, sticky='w')
        fields.columnconfigure(0, weight=1)

        discover = ttk.Frame(frame)
        discover.pack(fill='x', pady=(12, 0))
        ttk.Label(discover, text='Портове за търсене').pack(anchor='w')
        line = ttk.Frame(discover)
        line.pack(fill='x')
        ttk.Entry(line, textvariable=self.scan_ports).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.scan_button = ttk.Button(line, text='Намери портове', command=self.start_scan)
        self.scan_button.pack(side='left')

        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=(18, 12))
        self.buttons = []
        for label, flag in [('Провери достъпа', None), ('Провери видео', '--video-test'),
                            ('Покажи видео във VLC', '--view-video'), ('Тествай PTZ движение', '--move-test')]:
            button = ttk.Button(buttons, text=label, command=lambda f=flag: self.run(f))
            button.pack(fill='x', pady=3)
            self.buttons.append(button)

        ttk.Label(frame, textvariable=self.status, wraplength=620).pack(anchor='w', pady=(3, 8))
        self.output = tk.Text(frame, wrap='word', height=14, state='disabled', font=('Consolas', 10))
        self.output.pack(fill='both', expand=True)
        ttk.Label(frame, text='За видео е нужен VLC. При PTZ тест камерата може да се премести за кратко.',
                  wraplength=620).pack(anchor='w', pady=(10, 0))

    def show(self, value):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('end', value)
        self.output.configure(state='disabled')

    def start_scan(self):
        try:
            ip = ipaddress.ip_address(self.ip.get().strip())
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ValueError('Въведи локален IPv4 адрес.')
            ports = parse_ports(self.scan_ports.get())
        except ValueError as error:
            messagebox.showerror('Невалиден адрес или портове', str(error))
            return
        self.scan_button.configure(state='disabled')
        self.status.set(f'Търся услуги на {ip} ({len(ports)} порта)...')
        threading.Thread(target=self.scan_worker, args=(str(ip), ports), daemon=True).start()

    def scan_worker(self, ip, ports):
        try:
            results = scan(ip, ports)
            self.root.after(0, lambda: self.show_scan(results))
        except Exception as error:
            message = str(error)
            self.root.after(0, lambda: self.scan_failed(message))

    def scan_failed(self, message):
        self.scan_button.configure(state='normal')
        self.status.set('Търсенето не успя: ' + message)

    def show_scan(self, results):
        self.scan_button.configure(state='normal')
        self.status.set(f'Открити отворени портове: {len(results)}')
        window = tk.Toplevel(self.root)
        window.title('Открити услуги на камерата')
        window.geometry('600x320')
        box = ttk.Frame(window, padding=14)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Избери ONVIF ред и натисни „Използвай порт“. Другите услуги са показани само за информация.',
                  wraplength=560).pack(anchor='w', pady=(0, 8))
        tree = ttk.Treeview(box, columns=('ip', 'port', 'service'), show='headings', selectmode='browse')
        for name, label, width in [('ip', 'IP адрес', 140), ('port', 'Порт', 70), ('service', 'Услуга', 330)]:
            tree.heading(name, text=label)
            tree.column(name, width=width)
        tree.pack(fill='both', expand=True)
        for row in results:
            tree.insert('', 'end', values=row)

        def choose():
            selected = tree.selection()
            if not selected:
                return
            ip, port, service = tree.item(selected[0], 'values')
            if not service.startswith('ONVIF'):
                messagebox.showinfo('Друг тип услуга', 'Този порт не е потвърден като ONVIF порт.')
                return
            self.ip.set(ip)
            self.port.set(port)
            window.destroy()

        ttk.Button(box, text='Използвай порт', command=choose).pack(anchor='e', pady=(8, 0))

    def run(self, flag):
        try:
            ip = ipaddress.ip_address(self.ip.get().strip())
            port = int(self.port.get().strip())
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror('Невалиден адрес', 'Въведи частен IPv4 адрес и ONVIF порт от 1 до 65535.')
            return
        if flag == '--move-test' and not messagebox.askyesno('PTZ движение',
                'Камерата може да се премести за кратко. Наблюдавай я и продължи само ако е твоя или имаш разрешение.'):
            return
        self.status.set('Проверявам камерата...')
        self.show('Свързване...')
        for button in self.buttons:
            button.configure(state='disabled')
        args = [sys.executable, str(Path(__file__).with_name('audit.py')), str(ip), '--port', str(port)]
        if flag:
            args.append(flag)
        threading.Thread(target=self.worker, args=(args,), daemon=True).start()

    def worker(self, args):
        try:
            process = subprocess.run(args, capture_output=True, text=True, timeout=70, errors='replace')
            raw = (process.stdout + '\n' + process.stderr).strip()
            start = raw.find('{')
            if start >= 0:
                report, _ = json.JSONDecoder().raw_decode(raw[start:])
                lines = [f"Камера: {report['target']}:{report['port']}",
                         f"ONVIF без парола: {'Да' if report['anonymous_capabilities'] else 'Не е потвърдено'}",
                         f"Профили без парола: {'Да' if report['anonymous_profiles'] else 'Не е потвърдено'}",
                         f"PTZ статус без парола: {'Да' if report['anonymous_ptz_status'] else 'Не е потвърдено'}"]
                if '--video-test' in args or '--view-video' in args:
                    lines += [f"Адрес за видео без парола: {'Да' if report['anonymous_stream_uri'] else 'Не е потвърдено'}",
                              f"Отговор на RTSP: {report['rtsp_describe'] or 'Няма'}",
                              f"VLC е стартиран: {'Да' if report['viewer_started'] else 'Не'}"]
                if '--move-test' in args:
                    lines += [f"Команда за движение приета: {'Да' if report['movement_accepted'] else 'Не'}",
                              f"Команда за спиране приета: {'Да' if report['stop_accepted'] else 'Не'}"]
                lines += ['', 'Потвърди видимо движение или картина. Отрицателен тест не доказва пълна защита.']
                result = '\n'.join(lines)
            else:
                result = raw or f'Проверката приключи с код {process.returncode}.'
            self.root.after(0, lambda: self.finish(result))
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            message = f'Грешка при проверката: {error}'
            self.root.after(0, lambda: self.finish(message))

    def finish(self, result):
        self.show(result)
        self.status.set('Проверката приключи.')
        for button in self.buttons:
            button.configure(state='normal')


if __name__ == '__main__':
    root = tk.Tk()
    App(root)
    root.mainloop()
