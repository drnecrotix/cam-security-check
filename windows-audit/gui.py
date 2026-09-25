"""Windows-friendly single-camera interface for audit.py."""
import ipaddress
import json
import subprocess
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, ttk
from scan import DEFAULT_PORTS, parse_ports, scan_hosts
from wifi_scan import nearby_networks


class App:
    def __init__(self, root):
        self.root = root
        root.title('Проверка на ONVIF камера')
        root.geometry('680x540')
        root.minsize(560, 450)
        self.ip = tk.StringVar()
        self.port = tk.StringVar(value='80')
        self.scan_ports = tk.StringVar(value=DEFAULT_PORTS)
        self.network = tk.StringVar()
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
        network_line = ttk.Frame(discover)
        network_line.pack(fill='x', pady=(8, 0))
        ttk.Label(network_line, text='Локална мрежа (CIDR)').pack(side='left', padx=(0, 8))
        ttk.Entry(network_line, textvariable=self.network).pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.network_button = ttk.Button(network_line, text='Намери IP адреси', command=lambda: self.start_scan(True))
        self.network_button.pack(side='left')
        ttk.Button(discover, text='Отдалечен достъп през Tailscale', command=self.remote_help).pack(anchor='w', pady=(8, 0))
        ttk.Button(discover, text='Видими Wi-Fi сигнали наблизо', command=self.wifi_signals).pack(anchor='w', pady=(4, 0))

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

    def wifi_signals(self):
        window = tk.Toplevel(self.root)
        window.title('Видими Wi-Fi сигнали')
        window.geometry('700x520')
        box = ttk.Frame(window, padding=14)
        box.pack(fill='both', expand=True)
        ttk.Label(box, text='Близки Wi-Fi мрежи - без свързване към тях', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(box, text='Показва SSID, BSSID и сила на сигнала, когато Windows ги предоставя. Това не доказва, че мрежата е камера.',
                  wraplength=650).pack(anchor='w', pady=(4, 10))
        view = tk.Text(box, wrap='none', font=('Consolas', 10))
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
        update()

    def remote_help(self):
        window = tk.Toplevel(self.root)
        window.title('Отдалечен достъп до домашните камери')
        window.geometry('610x390')
        box = ttk.Frame(window, padding=18)
        box.pack(fill='both', expand=True)
        guide = ('1. На постоянно включения домашен Windows компютър инсталирай Tailscale и влез в акаунта си.\n'
                 '2. Въведи домашната мрежа в главния прозорец. На домашния компютър отвори PowerShell като администратор и изпълни генерираната команда.\n'
                 '3. Одобри маршрута в Tailscale Admin Console > Machines > Edit route settings.\n'
                 '4. Инсталирай Tailscale на отдалечения компютър и влез в същия акаунт.\n'
                 '5. След свързване натисни „Намери IP адреси“ в главния прозорец. За /24 мрежа търси последователно четири /26 части.')
        ttk.Label(box, text=guide, wraplength=560, justify='left').pack(anchor='w', pady=(0, 12))
        command = tk.StringVar(value='Въведи валидна домашна мрежа в главния прозорец.')
        ttk.Entry(box, textvariable=command, state='readonly').pack(fill='x')
        status = tk.StringVar(value='')

        def generate():
            try:
                network = ipaddress.ip_network(self.network.get().strip(), strict=True)
                if network.version != 4 or not network.is_private or network.is_loopback or network.is_link_local or network.is_reserved:
                    raise ValueError()
                command.set(f'tailscale up --advertise-routes={network}')
            except ValueError:
                command.set('Въведи валидна домашна IPv4 мрежа, например 192.168.1.0/24.')

        def copy():
            if not command.get().startswith('tailscale up '):
                generate()
            if command.get().startswith('tailscale up '):
                window.clipboard_clear()
                window.clipboard_append(command.get())
                status.set('Командата е копирана. Изпълни я само на домашния компютър.')

        def check():
            try:
                result = subprocess.run(['tailscale', 'status'], capture_output=True, timeout=5)
                status.set('Tailscale е активен на този компютър.' if result.returncode == 0 else
                           'Tailscale е инсталиран, но няма активна връзка.')
            except (OSError, subprocess.TimeoutExpired):
                status.set('Tailscale не е открит или не отговаря на този компютър.')

        buttons = ttk.Frame(box)
        buttons.pack(fill='x', pady=(10, 8))
        for label, action in [('Генерирай команда', generate), ('Копирай', copy),
                              ('Провери връзката', check),
                              ('Отвори Tailscale инструкции', lambda: webbrowser.open('https://tailscale.com/docs/use-cases/personal-or-at-home-use/access-devices-without-tailscale?tab=windows'))]:
            ttk.Button(buttons, text=label, command=action).pack(anchor='w', pady=2)
        ttk.Label(box, textvariable=status, wraplength=560).pack(anchor='w')
        generate()

    def start_scan(self, network_mode=False):
        try:
            if network_mode:
                network = ipaddress.ip_network(self.network.get().strip(), strict=True)
                if (network.version != 4 or network.num_addresses > 64 or
                    not all(ip.is_private and not ip.is_loopback and not ip.is_link_local and not ip.is_reserved
                            for ip in (network.network_address, network.broadcast_address))):
                    raise ValueError('Използвай частна IPv4 мрежа с най-много 64 адреса (например 192.168.1.0/26).')
                addresses = [str(ip) for ip in network.hosts()]
            else:
                ip = ipaddress.ip_address(self.ip.get().strip())
                if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise ValueError('Въведи локален IPv4 адрес.')
                addresses = [str(ip)]
            ports = parse_ports(self.scan_ports.get())
            if len(addresses) * len(ports) > 512:
                raise ValueError('Намали списъка с портове до най-много 512 проверки общо.')
        except ValueError as error:
            messagebox.showerror('Невалиден адрес или портове', str(error))
            return
        self.scan_button.configure(state='disabled')
        self.network_button.configure(state='disabled')
        self.status.set(f'Търся услуги на {len(addresses)} адреса и {len(ports)} порта...')
        threading.Thread(target=self.scan_worker, args=(addresses, ports), daemon=True).start()

    def scan_worker(self, addresses, ports):
        try:
            results = scan_hosts(addresses, ports)
            self.root.after(0, lambda: self.show_scan(results))
        except Exception as error:
            message = str(error)
            self.root.after(0, lambda: self.scan_failed(message))

    def scan_failed(self, message):
        self.scan_button.configure(state='normal')
        self.network_button.configure(state='normal')
        self.status.set('Търсенето не успя: ' + message)

    def show_scan(self, results):
        self.scan_button.configure(state='normal')
        self.network_button.configure(state='normal')
        self.status.set(f'Открити отворени портове: {len(results)}')
        window = tk.Toplevel(self.root)
        window.title('Открити услуги на камерата')
        window.geometry('600x320')
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
            if not service.startswith('ONVIF'):
                messagebox.showinfo('Друг тип услуга', 'Този порт не е потвърден като ONVIF порт.')
                return
            self.ip.set(ip)
            self.port.set(port)
            window.destroy()

        ttk.Button(box, text='Използвай адрес и порт', command=choose).pack(anchor='e', pady=(8, 0))

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
