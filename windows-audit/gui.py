"""Windows-friendly single-camera interface for audit.py."""
import ipaddress
import json
import os
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from scan import DEFAULT_PORTS, parse_ports, scan_hosts
from wifi_scan import nearby_networks
from reporting import render_html, checklist, confidential_fields
from local_lan import ethernet_networks
from audit import discover_usernames
from device_discovery import discover_onvif, windows_neighbors

CONFIG_PATH = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'CameraAudit' / 'cameras.json'

DARK = {'bg': '#10151e', 'panel': '#1b2532', 'field': '#121c29',
        'text': '#e8eef5', 'muted': '#a8b8c9', 'accent': '#35b7a8'}

EN = {
    'Проверка на ONVIF камера': 'ONVIF Camera Audit',
    'Проверка на собствена камера': 'Audit your camera',
    'Въведи локалния IP на камерата или намери камери в своята домашна мрежа.': 'Enter a local camera IP or discover cameras on your home network.',
    'Запазени камери': 'Saved cameras', 'Запази': 'Save', 'Изтрий': 'Delete',
    'IP адрес': 'IP address', 'ONVIF порт': 'ONVIF port',
    'Име на камерата': 'Camera name', 'ONVIF потребител': 'ONVIF username',
    'Парола (не се запазва)': 'Password (not saved)',
    'Открий ONVIF потребител': 'Discover ONVIF username',
    'Портове за търсене (може да намалиш списъка за по-бърза проверка)': 'Ports to check (reduce for a faster scan)',
    'Намери портове': 'Find ports', 'Локален адрес или CIDR': 'Local address or CIDR',
    'Намери камери': 'Find cameras', 'Открий кабелната LAN мрежа': 'Detect Ethernet LAN',
    'Отдалечен достъп през Tailscale': 'Remote access via Tailscale',
    'Видими Wi-Fi сигнали наблизо': 'Nearby Wi-Fi signals',
    'Открий устройства и ONVIF камери': 'Discover devices and ONVIF cameras',
    'Пълен отчет': 'Full audit', 'Провери достъпа': 'Check access', 'Провери видео': 'Check video',
    'Покажи видео във VLC': 'View video in VLC', 'Снимка от видео': 'Take snapshot',
    'Тествай PTZ движение': 'Test PTZ movement',
    'Запази последния отчет': 'Save latest report',
    'За видео е нужен VLC, а за снимка - FFmpeg. Паролата не се записва. При PTZ тест камерата може да се премести за кратко.': 'VLC is needed for video. Snapshots use ONVIF or FFmpeg fallback. The password is never saved. PTZ testing may move the camera briefly.',
    'Камери': 'Cameras', 'Откриване': 'Discovery', 'Резултат': 'Results',
    'Език': 'Language',
    'Видими Wi-Fi сигнали': 'Visible Wi-Fi signals',
    'Близки Wi-Fi мрежи - без свързване към тях': 'Nearby Wi-Fi networks - no connection required',
    'Показва SSID, BSSID и сила на сигнала, когато Windows ги предоставя. Това не доказва, че мрежата е камера.': 'Shows SSID, BSSID and signal strength when Windows provides them. This does not identify a camera.',
    'Обнови списъка': 'Refresh list',
    'Отдалечен достъп до домашните камери': 'Remote access to home cameras',
    'Генерирай команда': 'Generate command', 'Копирай': 'Copy',
    'Провери връзката': 'Check connection', 'Отвори Tailscale инструкции': 'Open Tailscale instructions',
    'Избери кабелна мрежа': 'Select Ethernet network',
    'Активни Ethernet мрежи. Избери твоята домашна мрежа:': 'Active Ethernet networks. Select your home network:',
    'Използвай тази мрежа': 'Use this network', 'Открити услуги на камерата': 'Discovered camera services',
    'Избери ONVIF ред и натисни „Използвай адрес и порт“. Другите услуги са показани само за информация.': 'Select an ONVIF row and use its address and port. Other services are informational.',
    'Порт': 'Port', 'Услуга': 'Service', 'Използвай адрес и порт': 'Use address and port',
    'Избери ONVIF потребител': 'Select ONVIF username',
    'Камерата върна няколко потребителя. Избери своя:': 'The camera returned several users. Select yours:',
    'Използвай': 'Use', 'Други IP камери (RTSP/HTTP)': 'Other IP cameras (RTSP/HTTP)',
    'Събери адресите на потоците за поверителен отчет': 'Collect stream URLs for confidential report',
    'Камера и достъп': 'Camera and access', 'Проверки': 'Checks',
    'Резултат и конзола': 'Results and console', 'Търсене и мрежа': 'Discovery and network',
    'Готово за проверка. Избери камера или въведи IP адрес.': 'Ready to check. Select a camera or enter its IP address.',
    'Избери открит адрес от списъка, за да се попълни в главното табло.': 'Select a discovered address to fill the main dashboard.',
}


def dark_style(root):
    root.configure(bg=DARK['bg'])
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background=DARK['bg'], foreground=DARK['text'], font=('Segoe UI', 10))
    style.configure('TFrame', background=DARK['bg'])
    style.configure('TLabelframe', background=DARK['bg'], bordercolor='#374555')
    style.configure('TLabelframe.Label', background=DARK['bg'], foreground=DARK['accent'], font=('Segoe UI', 10, 'bold'))
    style.configure('TLabel', background=DARK['bg'], foreground=DARK['text'])
    style.configure('TButton', background=DARK['panel'], foreground=DARK['text'], padding=(10, 7), borderwidth=0)
    style.map('TButton', background=[('active', '#284457'), ('disabled', '#26303b')],
              foreground=[('disabled', DARK['muted'])])
    style.configure('TEntry', fieldbackground=DARK['field'], foreground=DARK['text'], insertcolor=DARK['text'], padding=5)
    style.configure('TCheckbutton', background=DARK['bg'], foreground=DARK['text'])
    style.map('TCheckbutton', background=[('active', DARK['bg']), ('disabled', DARK['bg'])],
              foreground=[('active', DARK['text']), ('disabled', DARK['muted'])])
    style.configure('TCombobox', fieldbackground=DARK['field'], foreground=DARK['text'], background=DARK['panel'])
    style.map('TCombobox', fieldbackground=[('readonly', DARK['field'])], foreground=[('readonly', DARK['text'])])
    style.configure('TNotebook', background=DARK['bg'], borderwidth=0)
    style.configure('TNotebook.Tab', background=DARK['panel'], foreground=DARK['muted'], padding=(18, 9))
    style.map('TNotebook.Tab', background=[('selected', DARK['accent'])], foreground=[('selected', DARK['bg'])])
    style.configure('Treeview', background=DARK['field'], foreground=DARK['text'], fieldbackground=DARK['field'], rowheight=25)
    style.map('Treeview', background=[('selected', '#285d69')])
    style.configure('Treeview.Heading', background=DARK['panel'], foreground=DARK['text'])


class App:
    def __init__(self, root):
        self.root = root
        self.language = tk.StringVar(value='BG')
        dark_style(root)
        root.title('Проверка на ONVIF камера')
        root.geometry(f'{min(1160, root.winfo_screenwidth()-60)}x{min(850, root.winfo_screenheight()-90)}')
        root.minsize(min(850, root.winfo_screenwidth()-60), min(620, root.winfo_screenheight()-90))
        self.ip = tk.StringVar()
        self.port = tk.StringVar(value='80')
        self.name = tk.StringVar()
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.collect_sensitive = tk.BooleanVar(value=False)
        self.report_password = None
        self.report_username = None
        self.last_report = None
        self.cameras = self.load_cameras()
        self.scan_ports = tk.StringVar(value=DEFAULT_PORTS)
        self.network = tk.StringVar()
        self.generic_http_port = '80'
        self.generic_rtsp_port = '554'
        self.status = tk.StringVar(value='Въведи локалния IP адрес на твоята камера.')
        self.discovery_window = None
        self.scan_busy = False
        self.scan_button = None
        self.network_button = None

        viewport = tk.Canvas(root, bg=DARK['bg'], highlightthickness=0)
        viewport.pack(side='left', fill='both', expand=True)
        page_scroll = ttk.Scrollbar(root, orient='vertical', command=viewport.yview)
        page_scroll.pack(side='right', fill='y')
        viewport.configure(yscrollcommand=page_scroll.set)
        shell = ttk.Frame(viewport, padding=18)
        shell_id = viewport.create_window((0, 0), window=shell, anchor='nw')
        shell.bind('<Configure>', lambda event: viewport.configure(scrollregion=viewport.bbox('all')))
        viewport.bind('<Configure>', lambda event: viewport.itemconfigure(shell_id, width=event.width))
        header = ttk.Frame(shell)
        header.pack(fill='x', pady=(0, 12))
        ttk.Label(header, text='Проверка на собствена камера', font=('Segoe UI', 18, 'bold')).pack(side='left')
        ttk.Label(header, text='Език').pack(side='right', padx=(8, 0))
        language = ttk.Combobox(header, textvariable=self.language, values=['BG', 'EN'], width=4, state='readonly')
        language.pack(side='right')
        language.bind('<<ComboboxSelected>>', lambda event: self.apply_language())

        frame = ttk.LabelFrame(shell, text='Камера и достъп', padding=12)
        frame.pack(fill='x')
        saved = ttk.Frame(frame)
        saved.pack(fill='x', pady=(0, 10))
        ttk.Label(saved, text='Запазени камери').pack(anchor='w')
        row = ttk.Frame(saved)
        row.pack(fill='x')
        self.camera_select = ttk.Combobox(row, state='readonly', values=[c['name'] for c in self.cameras])
        self.camera_select.pack(side='left', fill='x', expand=True, padx=(0, 6))
        self.camera_select.bind('<<ComboboxSelected>>', self.select_camera)
        ttk.Button(row, text='Запази', command=self.save_camera).pack(side='left', padx=3)
        ttk.Button(row, text='Изтрий', command=self.delete_camera).pack(side='left', padx=3)

        fields = ttk.Frame(frame)
        fields.pack(fill='x')
        for col, label, var, width, hidden in [
            (0, 'IP адрес', self.ip, 22, ''), (1, 'ONVIF порт', self.port, 10, ''),
            (2, 'Име на камерата', self.name, 20, ''),
            (3, 'ONVIF потребител', self.username, 18, ''),
            (4, 'Парола (не се запазва)', self.password, 20, '*')]:
            grid_col, grid_row = col % 3, col // 3 * 2
            ttk.Label(fields, text=label).grid(row=grid_row, column=grid_col, sticky='w', padx=(0, 8))
            ttk.Entry(fields, textvariable=var, width=width, show=hidden).grid(row=grid_row+1, column=grid_col, sticky='ew', padx=(0, 8), pady=(0, 6))
            fields.columnconfigure(grid_col, weight=1)

        quick = ttk.Frame(shell)
        quick.pack(fill='x', pady=(12, 8))
        for index, (caption, command) in enumerate([
            ('Търсене и мрежа', self.open_discovery),
            ('Открий ONVIF потребител', self.discover_username_only),
            ('Други IP камери (RTSP/HTTP)', self.open_generic_camera),
            ('Отдалечен достъп през Tailscale', self.remote_help)]):
            ttk.Button(quick, text=caption, command=command).grid(row=index//2, column=index%2, sticky='ew', padx=3, pady=3)
        quick.columnconfigure(0, weight=1)
        quick.columnconfigure(1, weight=1)

        actions = ttk.LabelFrame(shell, text='Проверки', padding=10)
        actions.pack(fill='x')
        self.buttons = []
        for index, (label, flag) in enumerate([
            ('Пълен отчет', '--full-audit'), ('Провери достъпа', None),
            ('Провери видео', '--video-test'), ('Покажи видео във VLC', '--view-video'),
            ('Снимка от видео', '--snapshot'), ('Тествай PTZ движение', '--move-test')]):
            button = ttk.Button(actions, text=label, command=lambda f=flag: self.run(f))
            button.grid(row=index // 3, column=index % 3, sticky='ew', padx=4, pady=4)
            self.buttons.append(button)
        for column in range(3):
            actions.columnconfigure(column, weight=1)
        ttk.Button(shell, text='Запази последния отчет', command=self.save_report).pack(anchor='e', pady=(8, 0))
        ttk.Checkbutton(shell, text='Събери адресите на потоците за поверителен отчет',
                        variable=self.collect_sensitive).pack(anchor='e')

        console = ttk.LabelFrame(shell, text='Резултат и конзола', padding=8)
        console.pack(fill='both', expand=True, pady=(8, 0))
        self.output = tk.Text(console, wrap='word', height=12, state='disabled', font=('Consolas', 10),
                              bg=DARK['field'], fg=DARK['text'], insertbackground=DARK['text'],
                              selectbackground='#285d69', relief='flat', padx=12, pady=12)
        scroll = ttk.Scrollbar(console, orient='vertical', command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        self.output.pack(side='left', fill='both', expand=True)
        status_row = ttk.Frame(shell)
        status_row.pack(fill='x', pady=(8, 0))
        self.status_dot = tk.Canvas(status_row, width=18, height=18, bg=DARK['bg'], highlightthickness=0)
        self.status_dot.pack(side='left', padx=(0, 8))
        self.status_circle = self.status_dot.create_oval(3, 3, 15, 15, fill='#46c985', outline='')
        ttk.Label(status_row, textvariable=self.status, wraplength=980).pack(side='left', fill='x', expand=True)
        self.apply_language()
        self.show(self.say('Готово за проверка. Избери камера или въведи IP адрес.',
                           'Ready to check. Select a camera or enter its IP address.'))

    def open_generic_camera(self):
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        window.configure(bg=DARK['bg'])
        window.title(self.say('Други IP камери', 'Other IP cameras'))
        window.geometry('650x360')
        window.minsize(650, 360)
        box = ttk.Frame(window, padding=18)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text=self.say('Камера без ONVIF - провери нейния уеб интерфейс и RTSP поток.',
                                      'Camera without ONVIF - check its web interface and RTSP stream.'),
                  wraplength=590).pack(anchor='w', pady=(0, 10))
        http_port = tk.StringVar(value=self.generic_http_port)
        rtsp_port = tk.StringVar(value=self.generic_rtsp_port)
        path = tk.StringVar()
        for caption, variable in [
            (self.say('HTTP порт', 'HTTP port'), http_port),
            (self.say('RTSP порт', 'RTSP port'), rtsp_port),
            (self.say('RTSP път от настройките на камерата (напр. /stream1)',
                      'RTSP path from camera settings (e.g. /stream1)'), path)]:
            row = ttk.Frame(box)
            row.pack(fill='x', pady=4)
            ttk.Label(row, text=caption, width=43).pack(side='left')
            ttk.Entry(row, textvariable=variable).pack(side='left', fill='x', expand=True)
        ttk.Label(box, text=self.say('Остави RTSP пътя празен, ако не го знаеш. Тогава видеото няма да се проверява.',
                                      'Leave the RTSP path blank if unknown. Video will not be tested.'),
                  wraplength=590).pack(anchor='w', pady=(10, 14))

        def check():
            try:
                ip = ipaddress.ip_address(self.ip.get().strip())
                hp, rp = int(http_port.get()), int(rtsp_port.get())
                if (ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or
                        ip.is_reserved or not 1 <= hp <= 65535 or not 1 <= rp <= 65535):
                    raise ValueError()
                rtsp_path = path.get().strip()
                if rtsp_path and (not rtsp_path.startswith('/') or len(rtsp_path) > 256 or
                                  any(c in rtsp_path for c in '\r\n?#@') or '..' in rtsp_path):
                    raise ValueError()
            except ValueError:
                messagebox.showerror(self.say('Невалиден адрес или порт', 'Invalid address or port'),
                                     self.say('Въведи частен IP адрес, валидни портове и RTSP път започващ с /.',
                                              'Enter a private IP, valid ports and an RTSP path starting with /.'))
                return
            if any(button.cget('state') == 'disabled' for button in self.buttons):
                return
            args = [sys.executable, str(Path(__file__).with_name('generic_camera.py')), str(ip),
                    '--http-port', str(hp), '--rtsp-port', str(rp)]
            if rtsp_path:
                args += ['--rtsp-path', rtsp_path]
            if self.collect_sensitive.get():
                args.append('--include-sensitive')
            password = None
            if self.username.get().strip() and self.password.get():
                args += ['--username', self.username.get().strip(), '--password-stdin']
                password = self.password.get() + '\n'
            self.report_password = self.password.get() if password else None
            self.report_username = self.username.get().strip() if password else None
            self.generic_http_port, self.generic_rtsp_port = str(hp), str(rp)
            for button in self.buttons:
                button.configure(state='disabled')
            self.set_status('busy', 'Проверявам IP камерата...', 'Checking IP camera...')
            self.show(self.say('Проверка на HTTP и RTSP...', 'Checking HTTP and RTSP...'))
            window.destroy()
            threading.Thread(target=self.worker, args=(args, password), daemon=True).start()

        ttk.Button(box, text=self.say('Провери камерата', 'Check camera'), command=check).pack(anchor='e')

    def open_discovery(self):
        if self.discovery_window and self.discovery_window.winfo_exists():
            self.discovery_window.lift()
            self.discovery_window.focus_set()
            return
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        self.discovery_window = window
        window.configure(bg=DARK['bg'])
        window.title(self.say('Търсене и мрежа', 'Discovery and network'))
        window.geometry('740x470')
        window.minsize(700, 430)
        box = ttk.Frame(window, padding=18)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Портове за търсене (може да намалиш списъка за по-бърза проверка)').pack(anchor='w')
        line = ttk.Frame(box)
        line.pack(fill='x', pady=(4, 12))
        ttk.Entry(line, textvariable=self.scan_ports).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.scan_button = ttk.Button(line, text='Намери портове', command=self.start_scan)
        self.scan_button.pack(side='left')
        if self.scan_busy:
            self.scan_button.configure(state='disabled')
        ttk.Label(box, text='Локален адрес или CIDR').pack(anchor='w')
        line = ttk.Frame(box)
        line.pack(fill='x', pady=(4, 14))
        ttk.Entry(line, textvariable=self.network).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.network_button = ttk.Button(line, text='Намери камери', command=lambda: self.start_scan(True))
        self.network_button.pack(side='left')
        if self.scan_busy:
            self.network_button.configure(state='disabled')
        for label, command in [
            ('Открий кабелната LAN мрежа', self.find_ethernet),
            ('Открий устройства и ONVIF камери', self.discover_devices),
            ('Видими Wi-Fi сигнали наблизо', self.wifi_signals)]:
            ttk.Button(box, text=label, command=command).pack(fill='x', pady=4)
        ttk.Label(box, text='Избери открит адрес от списъка, за да се попълни в главното табло.',
                  wraplength=670).pack(anchor='w', pady=(14, 0))
        def close():
            self.scan_button = None
            self.network_button = None
            self.discovery_window = None
            window.destroy()
        window.protocol('WM_DELETE_WINDOW', close)
        self.apply_language()

    def set_status(self, level, bg, en):
        colors = {'ok': '#46c985', 'busy': '#f6c453', 'error': '#ef6b73'}
        self.status_dot.itemconfigure(self.status_circle, fill=colors[level])
        self.status.set(self.say(bg, en))

    @staticmethod
    def size_for_contents(window, min_width, min_height):
        window.update_idletasks()
        width = max(min_width, window.winfo_reqwidth() + 20)
        height = max(min_height, window.winfo_reqheight() + 20)
        window.minsize(width, height)
        window.geometry(f'{width}x{height}')

    def tr(self, text):
        return EN.get(text, text) if self.language.get() == 'EN' else text

    def say(self, bg, en):
        return en if self.language.get() == 'EN' else bg

    def apply_language(self):
        self.root.title(self.tr('Проверка на ONVIF камера'))
        def visit(widget):
            try:
                original = getattr(widget, '_original_bg_text', None)
                if original is None:
                    original = widget.cget('text')
                    widget._original_bg_text = original
                if original in EN:
                    widget.configure(text=self.tr(original))
            except (tk.TclError, AttributeError):
                pass
            for child in widget.winfo_children():
                visit(child)
        visit(self.root)
        if self.last_report:
            self.show(self.format_report(self.last_report))

    def load_cameras(self):
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
            if isinstance(data, list):
                return [dict(name=str(x['name']), ip=str(x['ip']), port=int(x['port']),
                             username=str(x.get('username', ''))) for x in data if isinstance(x, dict)]
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return []

    def select_camera(self, _event=None):
        match = next((c for c in self.cameras if c['name'] == self.camera_select.get()), None)
        if match:
            self.name.set(match['name'])
            self.ip.set(match['ip'])
            self.port.set(str(match['port']))
            self.username.set(match['username'])
            self.password.set('')

    def save_camera(self):
        name = self.name.get().strip()
        try:
            ip = ipaddress.ip_address(self.ip.get().strip())
            port = int(self.port.get().strip())
            if not name or ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or not 1 <= port <= 65535:
                raise ValueError()
            record = {'name': name, 'ip': str(ip), 'port': port, 'username': self.username.get().strip()}
            self.cameras = [c for c in self.cameras if c['name'] != name] + [record]
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            CONFIG_PATH.write_text(json.dumps(self.cameras, ensure_ascii=False, indent=2), encoding='utf-8')
            self.camera_select.configure(values=[c['name'] for c in self.cameras])
            self.camera_select.set(name)
            self.status.set(self.say('Камерата е запазена без паролата.', 'Camera saved without the password.'))
        except (ValueError, OSError) as error:
            messagebox.showerror(self.say('Неуспешно запазване', 'Save failed'),
                                 self.say('Въведи име, частен IP и валиден порт. ', 'Enter a name, private IP and valid port. ') + str(error))

    def delete_camera(self):
        name = self.camera_select.get()
        if not name:
            return
        try:
            self.cameras = [c for c in self.cameras if c['name'] != name]
            CONFIG_PATH.write_text(json.dumps(self.cameras, ensure_ascii=False, indent=2), encoding='utf-8')
            self.camera_select.configure(values=[c['name'] for c in self.cameras])
            self.camera_select.set('')
            self.status.set(self.say('Записът е изтрит.', 'Camera record deleted.'))
        except OSError as error:
            messagebox.showerror('Грешка', str(error))

    def save_report(self):
        if not self.last_report:
            messagebox.showinfo(self.say('Няма отчет', 'No report'),
                                self.say('Първо изпълни проверка на камера.', 'Run a camera check first.'))
            return
        confidential = messagebox.askyesno(
            self.say('Поверителен отчет', 'Confidential report'),
            self.say('Да включа ли събраните RTSP адреси и въведената парола? Файлът ще съдържа данни за достъп. Запази го само на защитено място. Избери „Не“ за стандартен отчет.',
                     'Include collected RTSP URLs and the supplied password? The file will contain access details. Store it securely. Select No for a standard report.'))
        path = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[('HTML отчет', '*.html'), ('JSON данни', '*.json')])
        if path:
            try:
                report = {key: value for key, value in self.last_report.items() if key != 'sensitive'}
                if confidential:
                    report['sensitive'] = {**self.last_report.get('sensitive', {}),
                                           'collected': 'sensitive' in self.last_report,
                                           'username': self.report_username,
                                           'password': self.report_password}
                    user, password, sources = confidential_fields(report['sensitive'])
                    report['sensitive'].update(username=user, password=password)
                    if sources:
                        report['sensitive']['credential_sources'] = sources
                    if not report['sensitive'].get('stream_uris'):
                        messagebox.showinfo(
                            self.say('Няма RTSP адрес', 'No RTSP URI'),
                            self.say('Камерата не върна RTSP адрес или отметката е включена след последната проверка. Отчетът ще посочи причината. За нов опит пусни пълна проверка с отметката включена.',
                                     'The camera returned no RTSP URI or the checkbox was enabled after the last check. The report will state the reason. For another attempt, run a full audit with the checkbox enabled.'))
                content = (json.dumps(report, ensure_ascii=False, indent=2)
                           if path.lower().endswith('.json') else render_html(report, self.language.get()))
                Path(path).write_text(content, encoding='utf-8')
                self.status.set(self.say('Поверителният отчет е записан.' if confidential else 'Стандартният отчет е записан.',
                                         'Confidential report saved.' if confidential else 'Standard report saved.'))
            except OSError as error:
                messagebox.showerror('Грешка', str(error))

    def saved_username(self, ip, port):
        return next((c['username'] for c in self.cameras
                     if c['ip'] == str(ip) and c['port'] == port and c.get('username')), None)

    def discover_username_only(self):
        try:
            ip = ipaddress.ip_address(self.ip.get().strip())
            port = int(self.port.get().strip())
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror(self.say('Невалиден адрес', 'Invalid address'),
                                 self.say('Първо въведи локалния IP адрес и ONVIF порта на камерата.', 'Enter the local camera IP and ONVIF port first.'))
            return
        self.lookup_username(str(ip), port, None, resume=False)

    def lookup_username(self, ip, port, pending_flag, resume):
        self.set_status('busy', 'Проверявам дали камерата предоставя ONVIF потребителите без парола...',
                        'Checking whether the camera exposes ONVIF users without a password...')
        def worker():
            try:
                names = discover_usernames(ip, port)
                self.root.after(0, lambda: self.username_found(names, pending_flag, resume))
            except (OSError, ValueError) as error:
                message = str(error)
                self.root.after(0, lambda: self.username_found([], pending_flag, resume, message))
        threading.Thread(target=worker, daemon=True).start()

    def username_found(self, names, pending_flag, resume, error=None):
        if len(names) == 1:
            self.username.set(names[0])
            self.status.set(self.say(f'ONVIF потребителят е открит: {names[0]}', f'ONVIF username found: {names[0]}'))
        elif len(names) > 1:
            window = tk.Toplevel(self.root)
            window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
            window.configure(bg=DARK['bg'])
            window.title('Избери ONVIF потребител')
            window.geometry('480x180')
            window.minsize(480, 180)
            box = ttk.Frame(window, padding=14)
            box.pack(fill='both', expand=True)
            ttk.Label(box, text='Камерата върна няколко потребителя. Избери своя:').pack()
            choice = ttk.Combobox(box, state='readonly', values=names)
            choice.pack(fill='x', pady=8)
            choice.current(0)
            def select():
                self.username.set(choice.get())
                window.destroy()
                if resume:
                    self.run(pending_flag, resolved=True)
            ttk.Button(box, text='Използвай', command=select).pack()
            self.apply_language()
            return
        else:
            self.status.set(self.say('Камерата не предоставя потребителски имена без удостоверяване.',
                                     'The camera does not disclose usernames without authentication.') +
                            (f' {error}' if error else ''))
        if resume:
            self.run(pending_flag, resolved=True)

    def show(self, value):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('end', value)
        self.output.configure(state='disabled')

    def wifi_signals(self):
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        window.configure(bg=DARK['bg'])
        window.title('Видими Wi-Fi сигнали')
        window.geometry('700x520')
        window.minsize(700, 480)
        box = ttk.Frame(window, padding=14)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Близки Wi-Fi мрежи - без свързване към тях', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(box, text='Показва SSID, BSSID и сила на сигнала, когато Windows ги предоставя. Това не доказва, че мрежата е камера.',
                  wraplength=650).pack(anchor='w', pady=(4, 10))
        view = tk.Text(box, wrap='none', font=('Consolas', 10), bg=DARK['field'], fg=DARK['text'], relief='flat')
        view.pack(fill='both', expand=True)

        def update():
            view.delete('1.0', 'end')
            view.insert('end', 'Търся сигнали...')
            def worker():
                try:
                    result = nearby_networks()
                except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                    result = f'Грешка: {error}\nПровери Wi-Fi адаптера и разрешението за местоположение в Windows.'
                def display():
                    if window.winfo_exists():
                        view.delete('1.0', 'end')
                        view.insert('end', result)
                self.root.after(0, display)
            threading.Thread(target=worker, daemon=True).start()

        ttk.Button(box, text='Обнови списъка', command=update).pack(anchor='e', pady=(8, 0))
        self.apply_language()
        update()

    def find_ethernet(self):
        self.set_status('busy', 'Откривам активната кабелна мрежа...', 'Detecting the active Ethernet LAN...')
        def worker():
            try:
                networks = ethernet_networks()
                self.root.after(0, lambda: self.choose_ethernet(networks))
            except RuntimeError as error:
                message = str(error)
                self.root.after(0, lambda: self.set_status('error', message, message))
        threading.Thread(target=worker, daemon=True).start()

    def choose_ethernet(self, networks):
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        window.configure(bg=DARK['bg'])
        window.title('Избери кабелна мрежа')
        window.geometry('520x300')
        window.minsize(520, 300)
        box = ttk.Frame(window, padding=14)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Активни Ethernet мрежи. Избери твоята домашна мрежа:', wraplength=460).pack(anchor='w')
        listbox = tk.Listbox(box, bg=DARK['field'], fg=DARK['text'], selectbackground='#285d69', relief='flat')
        listbox.pack(fill='both', expand=True, pady=10)
        for name, ip, network in networks:
            listbox.insert('end', f'{name} - {ip} - {network}')
        listbox.selection_set(0)
        def choose():
            selection = listbox.curselection()
            if not selection:
                return
            _, ip, network = networks[selection[0]]
            self.network.set(network)
            self.status.set(self.say(f'Открита LAN мрежа {network} (адрес на компютъра: {ip}). Натисни „Намери камери“.',
                                     f'LAN {network} found (computer IP: {ip}). Select Find cameras.'))
            window.destroy()
        ttk.Button(box, text='Използвай тази мрежа', command=choose).pack(anchor='e')
        self.apply_language()

    def discover_devices(self):
        try:
            raw = self.network.get().strip()
            network = ipaddress.ip_network(raw if '/' in raw else raw + '/24', strict=False)
            ports = parse_ports(self.scan_ports.get())
            if (network.version != 4 or not network.is_private or network.num_addresses > 256 or
                    len(list(network.hosts())) * len(ports) > 2048):
                raise ValueError()
        except ValueError:
            messagebox.showerror('Невалидна локална мрежа' if self.language.get() == 'BG' else 'Invalid local network',
                                 'Въведи частен LAN адрес или CIDR до /24 и намали портовете при нужда.' if self.language.get() == 'BG'
                                 else 'Enter a private LAN address or CIDR up to /24 and reduce ports if needed.')
            return
        self.set_status('busy', 'Откривам устройства и ONVIF камери...', 'Discovering devices and ONVIF cameras...')
        def worker():
            try:
                onvif = discover_onvif(network)
            except (OSError, ValueError):
                onvif = []
            try:
                open_ports = scan_hosts([str(ip) for ip in network.hosts()], ports)
            except (OSError, ValueError):
                open_ports = []
            neighbors = windows_neighbors(network)
            self.root.after(0, lambda: self.show_devices(onvif, open_ports, neighbors))
        threading.Thread(target=worker, daemon=True).start()

    def show_devices(self, onvif, open_ports, neighbors):
        english = self.language.get() == 'EN'
        rows = {}
        for ip, mac in neighbors:
            rows[(ip, '-')]= ('LAN neighbor' if english else 'LAN устройство', 'ARP')
        for ip, port, service in open_ports:
            rows[(ip, str(port))] = (service, 'TCP')
        for ip, port in onvif:
            rows[(ip, str(port))] = ('ONVIF camera (WS-Discovery)' if english else 'ONVIF камера (WS-Discovery)', 'WS-Discovery')
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        window.configure(bg=DARK['bg'])
        window.title('Discovered devices' if english else 'Открити устройства')
        window.geometry('800x520')
        window.minsize(800, 520)
        box = ttk.Frame(window, padding=14)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text=('Select an ONVIF row to use it. ARP entries may be stale; an open port alone does not identify a camera.'
                             if english else 'Избери ONVIF ред. ARP записите може да са стари; отворен порт сам по себе си не доказва, че устройството е камера.'),
                  wraplength=740).pack(anchor='w', pady=(0, 8))
        tree = ttk.Treeview(box, columns=('ip','port','service','source'), show='headings', selectmode='browse')
        for key, bg, en, width in [('ip','IP адрес','IP address',150),('port','Порт','Port',70),
                                    ('service','Услуга','Service',390),('source','Източник','Source',130)]:
            tree.heading(key, text=en if english else bg)
            tree.column(key, width=width)
        tree.pack(fill='both', expand=True)
        for (ip, port), (service, source) in sorted(rows.items(), key=lambda row: (ipaddress.ip_address(row[0][0]), row[0][1])):
            tree.insert('', 'end', values=(ip, port, service, source))
        def choose():
            selected = tree.selection()
            if not selected:
                return
            ip, port, service, source = tree.item(selected[0], 'values')
            if source != 'WS-Discovery' and not service.startswith('ONVIF'):
                self.ip.set(ip)
                if service.startswith('RTSP') and port.isdigit():
                    self.generic_rtsp_port = port
                elif service.startswith('HTTP') and port.isdigit():
                    self.generic_http_port = port
                self.status.set('IP е попълнен, но ONVIF портът не е потвърден.' if not english else 'IP filled; ONVIF port is not confirmed.')
            else:
                self.ip.set(ip)
                self.port.set(port)
                self.status.set(f'ONVIF: {ip}:{port}')
            window.destroy()
        ttk.Button(box, text='Use selected' if english else 'Използвай избраното', command=choose).pack(anchor='e', pady=(8, 0))
        self.set_status('ok' if rows else 'error', f'Открити записи: {len(rows)}.', f'Entries found: {len(rows)}.')

    def remote_help(self):
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        window.configure(bg=DARK['bg'])
        window.title('Отдалечен достъп до домашните камери')
        window.geometry('650x480')
        window.minsize(650, 480)
        box = ttk.Frame(window, padding=18)
        box.pack(fill='both', expand=True)
        guide = ('1. На постоянно включения домашен Windows компютър инсталирай Tailscale и влез в акаунта си.\n'
                 '2. Въведи домашната мрежа в главния прозорец. На домашния компютър отвори PowerShell като администратор и изпълни генерираната команда.\n'
                 '3. Одобри маршрута в Tailscale Admin Console > Machines > Edit route settings.\n'
                 '4. Инсталирай Tailscale на отдалечения компютър и влез в същия акаунт.\n'
                 '5. След свързване въведи домашния адрес, например 192.168.0.1, и натисни „Намери камери“.')
        guide_en = ('1. Install Tailscale on the always-on Windows computer at home and sign in.\n'
                    '2. Enter your home network in the main window. On the home computer, run the generated command in Administrator PowerShell.\n'
                    '3. Approve the subnet route in Tailscale Admin Console > Machines > Edit route settings.\n'
                    '4. Install Tailscale on the remote computer and sign in with the same account.\n'
                    '5. Connect, enter a home address such as 192.168.0.1, then select Find cameras.')
        ttk.Label(box, text=self.say(guide, guide_en), wraplength=560, justify='left').pack(anchor='w', pady=(0, 12))
        command = tk.StringVar(value='Въведи валидна домашна мрежа в главния прозорец.')
        ttk.Entry(box, textvariable=command, state='readonly').pack(fill='x')
        status = tk.StringVar(value='')

        def generate():
            try:
                raw = self.network.get().strip()
                network = ipaddress.ip_network(raw if '/' in raw else raw + '/24', strict=False)
                if network.version != 4 or not network.is_private or network.is_loopback or network.is_link_local or network.is_reserved:
                    raise ValueError()
                command.set(f'tailscale up --advertise-routes={network}')
            except ValueError:
                command.set(self.say('Въведи домашен адрес, например 192.168.0.1, или точната мрежа в CIDR формат.',
                                     'Enter a home address such as 192.168.0.1 or the exact CIDR network.'))

        def copy():
            if not command.get().startswith('tailscale up '):
                generate()
            if command.get().startswith('tailscale up '):
                window.clipboard_clear()
                window.clipboard_append(command.get())
                status.set(self.say('Командата е копирана. Изпълни я само на домашния компютър.',
                                    'Command copied. Run it only on the home computer.'))

        def check():
            try:
                result = subprocess.run(['tailscale', 'status'], capture_output=True, timeout=5)
                status.set(self.say('Tailscale е активен на този компютър.', 'Tailscale is active on this computer.') if result.returncode == 0 else
                           self.say('Tailscale е инсталиран, но няма активна връзка.', 'Tailscale is installed but not connected.'))
            except (OSError, subprocess.TimeoutExpired):
                status.set(self.say('Tailscale не е открит или не отговаря на този компютър.',
                                    'Tailscale was not found or is not responding on this computer.'))

        buttons = ttk.Frame(box)
        buttons.pack(fill='x', pady=(10, 8))
        for label, action in [('Генерирай команда', generate), ('Копирай', copy),
                              ('Провери връзката', check),
                              ('Отвори Tailscale инструкции', lambda: webbrowser.open('https://tailscale.com/docs/use-cases/personal-or-at-home-use/access-devices-without-tailscale?tab=windows'))]:
            ttk.Button(buttons, text=label, command=action).pack(anchor='w', pady=2)
        ttk.Label(box, textvariable=status, wraplength=560).pack(anchor='w')
        self.apply_language()
        generate()

    def start_scan(self, network_mode=False):
        try:
            if network_mode:
                raw = self.network.get().strip()
                network = ipaddress.ip_network(raw if '/' in raw else raw + '/24', strict=False)
                if (network.version != 4 or network.num_addresses > 256 or
                    not all(ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_reserved
                            for ip in (network.network_address, network.broadcast_address))):
                    raise ValueError('Въведи локален адрес като 192.168.0.1 или частна мрежа до /24, например 192.168.0.0/24.')
                addresses = [str(ip) for ip in network.hosts()]
            else:
                ip = ipaddress.ip_address(self.ip.get().strip())
                if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise ValueError('Въведи локалния IP адрес на камерата (например 192.168.0.50). Публичният IP на рутера не е адрес на камерата. За достъп отдалечено първо свържи Tailscale.')
                addresses = [str(ip)]
            ports = parse_ports(self.scan_ports.get())
            if len(addresses) * len(ports) > 2048:
                raise ValueError('Намали списъка с портове до най-много 2048 проверки общо.')
        except ValueError as error:
            messagebox.showerror(self.say('Невалиден адрес или портове', 'Invalid address or ports'), str(error))
            return
        if self.scan_busy:
            return
        self.scan_busy = True
        self.set_status('busy', 'Търсенето е в ход...', 'Discovery is running...')
        if self.scan_button and self.scan_button.winfo_exists():
            self.scan_button.configure(state='disabled')
        if self.network_button and self.network_button.winfo_exists():
            self.network_button.configure(state='disabled')
        self.status.set(self.say(f'Търся услуги на {len(addresses)} адреса и {len(ports)} порта. Това може да отнеме около минута...',
                                 f'Checking {len(addresses)} addresses and {len(ports)} ports. This may take about a minute...'))
        threading.Thread(target=self.scan_worker, args=(addresses, ports), daemon=True).start()

    def scan_worker(self, addresses, ports):
        try:
            results = scan_hosts(addresses, ports)
            self.root.after(0, lambda: self.show_scan(results))
        except Exception as error:
            message = str(error)
            self.root.after(0, lambda: self.scan_failed(message))

    def scan_failed(self, message):
        self.scan_busy = False
        if self.scan_button and self.scan_button.winfo_exists():
            self.scan_button.configure(state='normal')
        if self.network_button and self.network_button.winfo_exists():
            self.network_button.configure(state='normal')
        self.set_status('error', 'Търсенето не успя: ' + message, 'Discovery failed: ' + message)
        self.show(self.say('Проверка на мрежата: ', 'Network check: ') + message)

    def show_scan(self, results):
        self.scan_busy = False
        if self.scan_button and self.scan_button.winfo_exists():
            self.scan_button.configure(state='normal')
        if self.network_button and self.network_button.winfo_exists():
            self.network_button.configure(state='normal')
        self.set_status('ok' if results else 'error',
                        f'Открити отворени портове: {len(results)}. Непозната услуга не доказва, че устройството е камера.',
                        f'Open ports found: {len(results)}. An unknown service does not identify a camera.')
        window = tk.Toplevel(self.root)
        window.after_idle(lambda w=window: self.size_for_contents(w, *w.minsize()))
        window.configure(bg=DARK['bg'])
        window.title('Открити услуги на камерата')
        window.geometry('660x390')
        window.minsize(660, 390)
        box = ttk.Frame(window, padding=14)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Избери ONVIF ред и натисни „Използвай адрес и порт“. Другите услуги са показани само за информация.',
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
            self.ip.set(ip)
            if service.startswith('ONVIF'):
                self.port.set(port)
                window.destroy()
            elif service.startswith(('RTSP', 'HTTP')):
                if service.startswith('RTSP'):
                    self.generic_rtsp_port = port
                else:
                    self.generic_http_port = port
                window.destroy()
                self.open_generic_camera()
            else:
                self.status.set(self.say('IP е попълнен; типът на услугата не е потвърден.',
                                         'IP filled; service type is unconfirmed.'))
                window.destroy()

        ttk.Button(box, text='Използвай адрес и порт', command=choose).pack(anchor='e', pady=(8, 0))
        self.apply_language()

    def run(self, flag, resolved=False):
        try:
            ip = ipaddress.ip_address(self.ip.get().strip())
            port = int(self.port.get().strip())
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or not 1 <= port <= 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror(self.say('Невалиден адрес', 'Invalid address'),
                                 self.say('Въведи локалния IP на камерата, например 192.168.0.50, и ONVIF порт от 1 до 65535. Публичният IP на рутера не е адрес на камерата. Ако си извън дома, свържи се през Tailscale.',
                                          'Enter a local camera IP such as 192.168.0.50 and an ONVIF port from 1 to 65535. Your router public IP is not the camera address. Connect through Tailscale when away from home.'))
            return
        if not self.username.get().strip() and not resolved:
            saved = self.saved_username(ip, port)
            if saved:
                self.username.set(saved)
            else:
                self.lookup_username(str(ip), port, flag, resume=True)
                return
        if flag == '--move-test' and not messagebox.askyesno(self.say('PTZ движение', 'PTZ movement'),
                self.say('Камерата може да се премести за кратко. Наблюдавай я и продължи само ако е твоя или имаш разрешение.',
                         'The camera may move briefly. Watch it and continue only if you own it or have permission.')):
            return
        if self.password.get() and not self.username.get().strip():
            messagebox.showerror(self.say('Липсва потребител', 'Username missing'),
                                 self.say('Въведи ONVIF потребител за тази парола.', 'Enter an ONVIF username for this password.'))
            return
        if flag == '--snapshot':
            destination = filedialog.asksaveasfilename(defaultextension='.jpg', filetypes=[('JPEG снимка', '*.jpg')])
            if not destination:
                return
        self.set_status('busy', 'Проверявам камерата...', 'Checking camera...')
        self.show(self.say('Свързване и проверка на камерата...\nРезултатът ще се появи тук.', 'Connecting and checking the camera...\nThe result will appear here.'))
        for button in self.buttons:
            button.configure(state='disabled')
        args = [sys.executable, str(Path(__file__).with_name('audit.py')), str(ip), '--port', str(port)]
        password = None
        if self.username.get().strip() and self.password.get():
            args += ['--username', self.username.get().strip(), '--password-stdin']
            password = self.password.get() + '\n'
        self.report_password = self.password.get() if password else None
        self.report_username = self.username.get().strip() if password else None
        if self.collect_sensitive.get():
            args.append('--include-sensitive')
        if flag == '--snapshot':
            args += ['--video-test', '--snapshot', destination]
        elif flag:
            args.append(flag)
        threading.Thread(target=self.worker, args=(args, password), daemon=True).start()

    def worker(self, args, password=None):
        try:
            process = subprocess.run(args, input=password, capture_output=True, text=True, timeout=70, errors='replace')
            raw = (process.stdout + '\n' + process.stderr).strip()
            start = raw.find('{')
            report = None
            if start >= 0:
                report, _ = json.JSONDecoder().raw_decode(raw[start:])
                result = ''
            else:
                result = raw or f'Проверката приключи с код {process.returncode}.'
            self.root.after(0, lambda: self.finish(result, report))
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            message = f'Грешка при проверката: {error}'
            self.root.after(0, lambda: self.finish(message))

    def finish(self, result, report=None):
        self.last_report = report
        self.show(self.format_report(report) if report else result)
        reachable = bool(report and (report.get('http_status_generic') is not None or
                                     (report.get('rtsp_describe') or '').startswith('RTSP/') or
                                     report.get('anonymous_capabilities') or report.get('authenticated_capabilities')
                                     or report.get('anonymous_profiles') or report.get('authenticated_profiles')))
        self.set_status('ok' if reachable else 'error',
                        'Проверката приключи.' if reachable else 'ONVIF не отговори успешно. Провери адреса, порта и връзката.',
                        'Audit finished.' if reachable else 'ONVIF did not respond successfully. Check address, port and connection.')
        for button in self.buttons:
            button.configure(state='normal')

    def format_report(self, report):
        english = self.language.get() == 'EN'
        yes = lambda value: ('Yes' if value else 'Not confirmed') if english else ('Да' if value else 'Не е потвърдено')
        label = (lambda bg, en: en if english else bg)
        security = report.get('security_assessment') or {}
        ratings = {'excellent': ('Отлична', 'Excellent'), 'good': ('Добра', 'Good'),
                   'weak': ('Слаба', 'Weak'), 'insufficient_data': ('Недостатъчно данни', 'Insufficient data')}
        summary = [f"{label('Оценка на защитата', 'Security rating')}: {label(*ratings.get(security.get('rating'), ('Неоценена', 'Not assessed')))}",
                   f"{label('Издържани', 'Passed')}: {security.get('counts', {}).get('pass', 0)} | "
                   f"{label('Неуспешни', 'Failed')}: {security.get('counts', {}).get('fail', 0)} | "
                   f"{label('Непроверени', 'Unknown')}: {security.get('counts', {}).get('unknown', 0)}", '']
        for test in security.get('tests', []):
            status = {'pass': label('Издържан', 'Passed'), 'fail': label('Неуспешен', 'Failed'),
                      'unknown': label('Непроверен', 'Unknown')}[test['status']]
            summary.append(f"- {test['en' if english else 'bg']['title']}: {status}")
        summary.append('')
        if report.get('camera_type'):
            lines = [f"{label('Камера', 'Camera')}: {report['target']}",
                     f"HTTP: {report.get('http_status_generic') or '-'}",
                     f"RTSP: {report.get('rtsp_describe') or label('Не е проверено', 'Not checked')}"]
            lines += ['', label('Проверки и препоръки:', 'Checks and recommendations:')]
            for item in report.get('checklist') or checklist(report):
                local = item['en' if english else 'bg']
                lines += [f"- {local['title']}: {local['status']} ({local['risk']})",
                          f"  {local['evidence']}", f"  {local['action']}"]
            return '\n'.join(summary + lines)
        lines = [f"{label('Камера', 'Camera')}: {report['target']}:{report['port']}",
                 f"{label('ONVIF без парола', 'ONVIF without password')}: {yes(report.get('anonymous_capabilities'))}",
                 f"{label('Профили без парола', 'Profiles without password')}: {yes(report.get('anonymous_profiles'))}",
                 f"{label('PTZ статус без парола', 'PTZ status without password')}: {yes(report.get('anonymous_ptz_status'))}"]
        if report.get('authenticated'):
            for key, bg, en in [('authenticated_capabilities', 'ONVIF с данни', 'ONVIF with credentials'),
                                ('authenticated_profiles', 'Профили с данни', 'Profiles with credentials'),
                                ('authenticated_ptz_status', 'PTZ статус с данни', 'PTZ with credentials'),
                                ('authenticated_stream_uri', 'Адрес за видео с данни', 'Video URI with credentials')]:
                lines.append(f'{label(bg, en)}: {yes(report.get(key))}')
            lines.append(f"{label('RTSP с данни', 'RTSP with credentials')}: {report.get('authenticated_rtsp_describe') or '-'}")
        if report.get('video_profiles'):
            lines += ['', label('Видео профили:', 'Video profiles:')]
            for item in report['video_profiles']:
                lines.append(f" - {item.get('name') or '?'}: {item.get('width') or '?'}x{item.get('height') or '?'}, {item.get('codec') or '?'}")
        if report.get('rtsp_describe') is not None or report.get('anonymous_stream_uri'):
            lines += [f"{label('Видео без парола', 'Video without password')}: {yes(report.get('anonymous_stream_uri'))}",
                      f"RTSP: {report.get('rtsp_describe') or '-'}"]
        if report.get('snapshot_saved') or report.get('snapshot_error'):
            lines.append(f"{label('Снимка', 'Snapshot')}: {label('Записана', 'Saved') if report.get('snapshot_saved') else report.get('snapshot_error')}")
        if report.get('movement_attempted'):
            lines.append(f"{label('PTZ движение прието', 'PTZ move accepted')}: {yes(report.get('movement_accepted'))}")
        lines += ['', label('Подробен списък и слаби места:', 'Detailed checklist and weaknesses:')]
        for item in report.get('checklist') or checklist(report):
            local = item['en' if english else 'bg']
            lines.append(f" - {local['title']}: {local['status']} [{local['risk']}]")
            lines.append(f"   {local['evidence']}")
            lines.append(f"   {local['action']}")
        lines += ['', label('Отрицателен тест не доказва пълна защита. Успех с данни не доказва проверена парола, ако анонимната заявка също работи.',
                             'A negative test does not prove security. A credentialed success does not prove the password was checked when anonymous access also works.')]
        if report.get('device_information'):
            lines += ['', label('Информация за устройството:', 'Device information:')]
            lines.extend(f' - {key}: {value}' for key, value in report['device_information'].items() if value)
        if report.get('wireless_interfaces'):
            lines += ['', label('Wi-Fi от камерата:', 'Camera Wi-Fi:')]
            lines.extend(f" - {item.get('interface') or '?'}: SSID {item.get('ssid') or '?'}"
                         for item in report['wireless_interfaces'])
        return '\n'.join(summary + lines)


if __name__ == '__main__':
    root = tk.Tk()
    App(root)
    root.mainloop()
