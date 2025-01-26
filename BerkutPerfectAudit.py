import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from subprocess import Popen, PIPE
import threading
import platform
import getpass
import webbrowser
from PIL import Image, ImageTk
import io
import requests
import datetime

class PerfectAuditApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Berkut Perfect Audit")
        self.create_reports_folder()
        self.create_tabs()
        self.create_search_tab()
        self.create_reports_tab()
        self.create_about_tab()

    def create_reports_folder(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        reports_path = os.path.join(script_dir, 'Reports')
        if not os.path.exists(reports_path):
            os.makedirs(reports_path)

    def create_tabs(self):
        self.tab_control = ttk.Notebook(self.root)

        self.search_tab = ttk.Frame(self.tab_control)
        self.reports_tab = ttk.Frame(self.tab_control)
        self.about_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.search_tab, text='Поиск')
        self.tab_control.add(self.reports_tab, text='Отчеты')
        self.tab_control.add(self.about_tab, text='Об авторе')
        self.tab_control.pack(expand=1, fill='both')

    def create_search_tab(self):
        self.options_frame = ttk.LabelFrame(self.search_tab, text="Выберите параметры поиска")
        self.options_frame.pack(fill='x', padx=10, pady=10)

        self.options = [
            "Системная информация",
            "Информация по сети",
            "Информация по запущенным процессам",
            "Информация по USB-девайсвам",
            "Информация по установленному ПО",
            "Информация по журналу событий",
            "Информация по запланированным задачам",
            "Проверка безопасности конфигурации",
            "Проверка привилегий учетной записи",
            "Анализ журнала событий безопасности",
            "Информация по статусу антивирусной защиты",
            "Комплексная проверка dxdiag"
        ]

        self.selected_options = {option: tk.BooleanVar() for option in self.options}
        self.checkbuttons = {}

        for option in self.options:
            var = self.selected_options[option]
            chk = ttk.Checkbutton(self.options_frame, text=option, variable=var, command=self.on_option_change)
            chk.pack(anchor='w')
            self.checkbuttons[option] = chk

        self.search_button = ttk.Button(self.search_tab, text="Поиск", command=self.run_audit)
        self.search_button.pack(pady=10)

        self.output_terminal = tk.Text(self.search_tab, height=15, state='disabled')
        self.output_terminal.pack(fill='both', padx=10, pady=10)

    def on_option_change(self):
        if self.selected_options["Комплексная проверка dxdiag"].get():
            for option in self.options[:-1]:
                self.checkbuttons[option].config(state='disabled')
                self.selected_options[option].set(False)
        else:
            for option in self.options[:-1]:
                self.checkbuttons[option].config(state='normal')

    def run_audit(self):
        selected_tasks = [opt for opt, var in self.selected_options.items() if var.get()]
        if not selected_tasks:
            messagebox.showwarning("Предупреждение", "Не выбрано ни одного параметра для поиска.")
            return

        self.output_terminal.config(state='normal')
        self.output_terminal.delete(1.0, tk.END)
        self.output_terminal.insert(tk.END, "Начало поиска...\n")
        self.output_terminal.config(state='disabled')

        threading.Thread(target=self.execute_audit, args=(selected_tasks,)).start()

    def execute_audit(self, tasks):
        computer_name = platform.node()
        user_name = getpass.getuser()
        report_dir = os.path.join("Reports", computer_name, user_name)
        os.makedirs(report_dir, exist_ok=True)

        for task in tasks:
            self.update_terminal(f"Выполняется: {task}...\n")

            if task == "Комплексная проверка dxdiag":
                # Переходим в папку пользователя для сохранения dxdiag без создания подпапки dxdiag
                os.chdir(report_dir)

                # Выполняем команду dxdiag
                dxdiag_command = "dxdiag /t dxdiag-info_.txt"
                process = Popen(dxdiag_command, stdout=PIPE, stderr=PIPE, shell=True)
                output, error = process.communicate()

                try:
                    if output:
                        self.update_terminal(output.decode('utf-8', errors='ignore'))
                        self.save_report(report_dir, task, output.decode('utf-8', errors='ignore'))
                    if error:
                        self.update_terminal(error.decode('utf-8', errors='ignore'))
                        self.save_report(report_dir, task, error.decode('utf-8', errors='ignore'))
                except UnicodeDecodeError:
                    self.update_terminal("Ошибка декодирования вывода.\n")

            else:
                # Выполняем обычные задачи
                command = self.get_powershell_command(task)
                process = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
                output, error = process.communicate()

                try:
                    if output:
                        self.update_terminal(output.decode('utf-8', errors='ignore'))
                        self.save_report(report_dir, task, output.decode('utf-8', errors='ignore'))
                    if error:
                        self.update_terminal(error.decode('utf-8', errors='ignore'))
                        self.save_report(report_dir, task, error.decode('utf-8', errors='ignore'))
                except UnicodeDecodeError:
                    self.update_terminal("Ошибка декодирования вывода.\n")
            
            self.update_terminal(f"{task} завершено.\n")

        self.update_terminal("Поиск завершен.\n")
        messagebox.showinfo("Поиск завершен", f"Информация была сохранена по пути: {report_dir}")

    def save_report(self, directory, task, content):
        task_names = {
            "Системная информация": "system-info",
            "Информация по сети": "network-info",
            "Информация по запущенным процессам": "running-processes",
            "Информация по USB-девайсвам": "usb-devices",
            "Информация по установленному ПО": "installed-software",
            "Информация по журналу событий": "event-log-entries",
            "Информация по запланированным задачам": "scheduled-tasks",
            "Проверка безопасности конфигурации": "security-configuration-check",
            "Проверка привилегий учетной записи": "account-privilege-check",
            "Анализ журнала событий безопасности": "security-event-log_analysis",
            "Информация по статусу антивирусной защиты": "antivirus-status",
            "Комплексная проверка dxdiag": "dxdiag-info_"
        }
        safe_task_name = task_names.get(task, "unknown_task").replace(" ", "_")
        now = datetime.datetime.now()
        formatted_date = now.strftime("%Y.%m.%d-%H.%M.%S")
        filename = os.path.join(directory, f"{safe_task_name}_{formatted_date}.txt")
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)

    def get_powershell_command(self, task):
        commands = {
            "Системная информация": "Get-ComputerInfo",
            "Информация по сети": "Get-NetIPConfiguration",
            "Информация по запущенным процессам": "Get-Process",
            "Информация по USB-девайсвам": "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' }",
            "Информация по установленному ПО": "Get-WmiObject -Query 'SELECT * FROM Win32_Product'",
            "Информация по журналу событий": "Get-EventLog -LogName Application -Newest 100",
            "Информация по запланированным задачам": "Get-ScheduledTask",
            "Проверка безопасности конфигурации": "Get-WindowsFeature | Where-Object { $_.InstallState -eq 'Installed' }",
            "Проверка привилегий учетной записи": "whoami /priv",
            "Анализ журнала событий безопасности": "Get-EventLog -LogName Security -Newest 100",
            "Информация по статусу антивирусной защиты": "Get-MpComputerStatus",
            "Комплексная проверка dxdiag": "dxdiag /t dxdiag-info_.txt"
        }
        return ["powershell", "-Command", commands[task]]

    def update_terminal(self, message):
        self.output_terminal.config(state='normal')
        self.output_terminal.insert(tk.END, message)
        self.output_terminal.see(tk.END)
        self.output_terminal.config(state='disabled')

    def create_reports_tab(self):
        self.reports_frame = ttk.Frame(self.reports_tab, padding="10")
        self.reports_frame.grid(row=0, column=0, sticky='nsew')

        self.path_label = ttk.Label(self.reports_frame, text="Выберите папку для поиска отчетов:")
        self.path_label.grid(row=0, column=0, padx=10, pady=5, sticky='w')

        self.path_entry = ttk.Entry(self.reports_frame, width=50)
        self.path_entry.grid(row=1, column=0, padx=10, pady=5, sticky='w')

        self.browse_button = ttk.Button(self.reports_frame, text="Выбрать", command=self.select_folder)
        self.browse_button.grid(row=1, column=1, padx=10, pady=5, sticky='w')

        self.search_name_label = ttk.Label(self.reports_frame, text="Поиск по имени компьютера:")
        self.search_name_label.grid(row=2, column=0, padx=10, pady=5, sticky='w')

        self.search_name_entry = ttk.Entry(self.reports_frame, width=50)
        self.search_name_entry.grid(row=3, column=0, padx=10, pady=5, sticky='w')

        self.search_name_button = ttk.Button(self.reports_frame, text="Поиск", command=self.search_by_computer_name)
        self.search_name_button.grid(row=3, column=1, padx=10, pady=5, sticky='w')

        self.search_user_label = ttk.Label(self.reports_frame, text="Поиск по имени пользователя:")
        self.search_user_label.grid(row=4, column=0, padx=10, pady=5, sticky='w')

        self.search_user_entry = ttk.Entry(self.reports_frame, width=50)
        self.search_user_entry.grid(row=5, column=0, padx=10, pady=5, sticky='w')

        self.search_user_button = ttk.Button(self.reports_frame, text="Поиск", command=self.search_user_reports)
        self.search_user_button.grid(row=5, column=1, padx=10, pady=5, sticky='w')

        self.back_button = ttk.Button(self.reports_frame, text="Назад", command=self.autosearch)
        self.back_button.grid(row=6, column=0, padx=10, pady=5, sticky='w')

        self.reports_terminal = tk.Text(self.reports_frame, height=15, state='disabled')
        self.reports_terminal.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, folder_path)
            self.search_all_reports()

    def search_all_reports(self):
        search_path = self.path_entry.get()
        if not search_path:
            messagebox.showwarning("Предупреждение", "Выберите папку для поиска отчетов.")
            return

        self.reports_terminal.config(state='normal')
        self.reports_terminal.delete(1.0, tk.END)
        self.reports_terminal.insert(tk.END, f"Поиск всех отчетов в папке: {search_path}\n")
        self.reports_terminal.config(state='disabled')

    def autosearch(self):
        # Считаем общее количество компьютеров
        search_path = self.path_entry.get()
        if not search_path:
            messagebox.showwarning("Предупреждение", "Выберите папку для поиска отчетов.")
            return

        computers = os.listdir(search_path)
        total_computers = len(computers)

        # Считаем общее количество пользователей и отчетов
        total_users = 0
        total_reports = 0
        for computer in computers:
            computer_folder = os.path.join(search_path, computer)
            if os.path.isdir(computer_folder):
                users = os.listdir(computer_folder)
                total_users += len(users)
                for user in users:
                    user_folder = os.path.join(computer_folder, user)
                    if os.path.isdir(user_folder):
                        reports = [f for f in os.listdir(user_folder) if f.endswith('.txt')]
                        total_reports += len(reports)

        # Отображаем информацию в терминале
        self.reports_terminal.config(state='normal')
        self.reports_terminal.delete(1.0, tk.END)
        self.reports_terminal.insert(tk.END, f"Общее количество компьютеров: {total_computers}\n")
        self.reports_terminal.insert(tk.END, f"Общее количество пользователей: {total_users}\n")
        self.reports_terminal.insert(tk.END, f"Общее количество отчетов: {total_reports}\n")
        self.reports_terminal.config(state='disabled')

    def search_by_computer_name(self):
        computer_name = self.search_name_entry.get().strip()  # Получаем имя компьютера и убираем лишние пробелы
        if not computer_name:
            messagebox.showwarning("Предупреждение", "Введите имя компьютера для поиска.")
            return

        self.reports_terminal.config(state='normal')
        self.reports_terminal.delete(1.0, tk.END)
        self.reports_terminal.insert(tk.END, f"Производится поиск по имени компьютера: {computer_name}...\n")
        self.reports_terminal.config(state='disabled')

        search_path = self.path_entry.get()
        if not search_path:
            messagebox.showwarning("Предупреждение", "Выберите папку для поиска отчетов.")
            return

        found_computers = [comp for comp in os.listdir(search_path) if computer_name.lower() in comp.lower()]
        if not found_computers:
            messagebox.showwarning("Предупреждение", f"Не найдено компьютеров с именем, содержащим: {computer_name}.")
            return

        for computer in found_computers:
            computer_path = os.path.join(search_path, computer)

            self.reports_terminal.config(state='normal')
            self.reports_terminal.insert(tk.END, f"Найден компьютер с именем '{computer}':\n")

            user_folders = [user for user in os.listdir(computer_path) if os.path.isdir(os.path.join(computer_path, user))]
            if not user_folders:
                self.reports_terminal.insert(tk.END, f"На компьютере '{computer}' не найдено пользователей.\n")
            else:
                for user in user_folders:
                    self.reports_terminal.insert(tk.END, f"Пользователь: {user}\n")
                    self.reports_terminal.insert(tk.END, f"Отчеты пользователя {user} на компьютере {computer}:\n")

                    user_folder = os.path.join(computer_path, user)
                    user_reports = [report.split("_")[0] for report in os.listdir(user_folder) if report.endswith(".txt")]
                    if user_reports:
                        for report in user_reports:
                            self.reports_terminal.insert(tk.END, f"- {report}\n")
                    else:
                        self.reports_terminal.insert(tk.END, "Отчеты пользователя отсутствуют.\n")

            self.reports_terminal.config(state='disabled')

        self.reports_terminal.insert(tk.END, "Поиск завершен.\n")

    def search_user_reports(self):
        user_name = self.search_user_entry.get().lower()
        if not user_name:
            messagebox.showwarning("Предупреждение", "Введите имя пользователя для поиска.")
            return

        self.reports_terminal.config(state='normal')
        self.reports_terminal.delete(1.0, tk.END)
        self.reports_terminal.insert(tk.END, f"Производится поиск по имени пользователя: {user_name}...\n")
        self.reports_terminal.config(state='disabled')

        search_path = self.path_entry.get()
        if not search_path:
            messagebox.showwarning("Предупреждение", "Выберите папку для поиска отчетов.")
            return

        found_computers = [comp for comp in os.listdir(search_path) if os.path.isdir(os.path.join(search_path, comp))]

        if not found_computers:
            messagebox.showwarning("Предупреждение", f"Не найдено компьютеров в выбранной папке: {search_path}.")
            return

        found_users = []
        for computer in found_computers:
            users = [user for user in os.listdir(os.path.join(search_path, computer)) if os.path.isdir(os.path.join(search_path, computer, user))]
            matching_users = [user for user in users if user_name in user.lower()]
            if matching_users:
                found_users.extend([(computer, user) for user in matching_users])

        if not found_users:
            self.reports_terminal.config(state='normal')
            self.reports_terminal.insert(tk.END, f"Не найдено пользователей с именем, содержащим: {user_name}.\n")
            self.reports_terminal.config(state='disabled')
            return

        for computer, user in found_users:
            self.reports_terminal.config(state='normal')
            self.reports_terminal.insert(tk.END, f"Найден пользователь компьютера {computer}: {user}\n")
            self.reports_terminal.insert(tk.END, f"Отчеты пользователя {user}:\n")

            user_reports = []
            user_folder = os.path.join(search_path, computer, user)
            for root, dirs, files in os.walk(user_folder):
                for file in files:
                    if file.endswith(".txt"):
                        report_name = file.split("_")[0]
                        user_reports.append(report_name)

            if user_reports:
                self.reports_terminal.insert(tk.END, "\n".join(f"- {report}" for report in user_reports) + "\n")
            else:
                self.reports_terminal.insert(tk.END, "Нет доступных отчетов для данного пользователя.\n")
            
            self.reports_terminal.config(state='disabled')

    def display_report(self, report_path):
        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report_content = f.read()

            file_name = os.path.basename(report_path)
            modified_time = os.path.getmtime(report_path)
            formatted_time = datetime.datetime.fromtimestamp(modified_time).strftime("%d.%m.%Y-%H:%M:%S")

            self.reports_terminal.config(state='normal')
            self.reports_terminal.insert(tk.END, f"{file_name}\t\t{formatted_time}\n")
            self.reports_terminal.config(state='disabled')
        except Exception as e:
            self.reports_terminal.config(state='normal')
            self.reports_terminal.insert(tk.END, f"Ошибка при отображении отчета: {str(e)}\n")
            self.reports_terminal.config(state='disabled')

    def create_about_tab(self):
        self.about_frame = ttk.Frame(self.about_tab, padding="10")
        self.about_frame.grid(row=0, column=0, sticky='nsew')

        about_text = ("Программа была разработана для автоматизированного аудита системы\n"
                      "и сбора технических данных с целью последующего анализа.\n\n"
                      "Привет, пользователь!\n"
                      "Благодарю тебя за использование моего ПО\n"
                      "Я являюсь дипломированным специалистом по защите информации\n"
                      "Если у тебя появятся какие-либо вопросы, можешь обращаться по контактам ниже\n\n"
                      "Контакты:")
        about_label = ttk.Label(self.about_frame, text=about_text, justify=tk.LEFT, anchor="n")
        about_label.grid(row=0, column=0, padx=10, pady=10)

        telegram_link = ttk.Label(self.about_frame, text="Telegram", foreground="blue", cursor="hand2")
        telegram_link.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        telegram_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://t.me/berkutcommunity"))

        email_link = ttk.Label(self.about_frame, text="Почта", foreground="blue", cursor="hand2")
        email_link.grid(row=1, column=0, padx=70, pady=5, sticky='w')
        email_link.bind("<Button-1>", lambda e: webbrowser.open_new("mailto:berkutosint@proton.me"))

        image_url = "https://i.postimg.cc/fR19xcKc/Kasper-Flipper512.png"
        response = requests.get(image_url)
        image_data = response.content

        image = Image.open(io.BytesIO(image_data))
        desired_width = 150
        desired_height = 150
        image = image.resize((desired_width, desired_height), Image.LANCZOS)
        render = ImageTk.PhotoImage(image)
        
        image_label = ttk.Label(self.about_frame, image=render)
        image_label.image = render
        image_label.grid(row=0, column=1, rowspan=3, padx=10, pady=0, sticky='e')

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = PerfectAuditApp(root)

    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    window_width = 690
    window_height = 550
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    root.resizable(False, False)

    app.run()