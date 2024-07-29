import tkinter as tk
import customtkinter as ctk
import requests
import socket
import threading
import whois
import subprocess
import platform
import psutil

class VPNServer:
    def __init__(self):
        self.process = None
        self.vpn_active = False

    def get_public_ip(self):
        try:
            response = requests.get('https://api.ipify.org?format=json')
            data = response.json()
            return data.get('ip', 'Non disponible')
        except requests.RequestException as e:
            return 'Erreur lors de la récupération de l\'IP publique'

    def ip_lookup(self, ip):
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/')
            data = response.json()
            if response.status_code == 200:
                info = {
                    "IP": data.get("ip", "Non disponible"),
                    "Ville": data.get("city", "Non disponible"),
                    "Région": data.get("region", "Non disponible"),
                    "Pays": data.get("country_name", "Non disponible"),
                    "Code Pays": data.get("country_code", "Non disponible"),
                    "Organisation": data.get("org", "Non disponible"),
                }
                return "\n".join([f"{key}: {value}" for key, value in info.items()])
            else:
                return "Erreur lors de la recherche d'IP"
        except requests.RequestException:
            return 'Erreur lors de la recherche d\'IP'

    def scan_ports(self, ip, callback):
        ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 25565]
        results = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                status = 'ouvert' if result == 0 else 'fermé'
                results.append(f"Port {port}: {status}")
        
        callback(results, None)

    def whois_lookup(self, query):
        try:
            w = whois.whois(query)
            info = {
                "Domain Name": w.domain_name,
                "Registrar": w.registrar,
                "Creation Date": w.creation_date,
                "Expiration Date": w.expiration_date,
                "Name Servers": w.name_servers,
            }
            return "\n".join([f"{key}: {value}" for key, value in info.items()])
        except Exception as e:
            return f"Erreur lors de la recherche WHOIS: {str(e)}"

    def ping_ip(self, ip, count=4):
        try:
            system = platform.system()
            if system == "Windows":
                command = ["ping", "-n", str(count), ip]
            else:
                command = ["ping", "-c", str(count), ip]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            output = result.stdout + result.stderr
            formatted_output = self.format_ping_output(output)
            return formatted_output
        except Exception as e:
            return f"Erreur lors du ping: {str(e)}"

    def format_ping_output(self, output):
        lines = output.splitlines()
        formatted_lines = []
        for line in lines:
            if "time=" in line:
                formatted_lines.append(f"Réponse: {line}")
            elif "Request timed out" in line:
                formatted_lines.append(f"Délais d'attente dépassé: {line}")
            elif "ping:" in line or "PING" in line:
                continue
            else:
                formatted_lines.append(line)
        return "\n".join(formatted_lines)

class VPNApp(ctk.CTk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("MOOD TOOL V2 PY")
        self.geometry("600x800")

        self.configure(bg='black')

        self.vpn_server = VPNServer()

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=0)
        self.grid_rowconfigure(4, weight=0)
        self.grid_rowconfigure(5, weight=0)
        self.grid_rowconfigure(6, weight=0)
        self.grid_rowconfigure(7, weight=0)
        self.grid_rowconfigure(8, weight=0)
        self.grid_rowconfigure(9, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=1)

        button_style = {
            'border_color': 'black',
            'border_width': 2
        }

        self.refresh_ip_button = ctk.CTkButton(self, text="Refresh IP", command=self.update_ip_display, **button_style)
        self.refresh_ip_button.grid(row=0, column=0, padx=10, pady=10, sticky='ew')

        self.ping_test_button = ctk.CTkButton(self, text="Ping My IP", command=self.ping_test, **button_style)
        self.ping_test_button.grid(row=0, column=1, padx=10, pady=10, sticky='ew')

        self.token_nuker_button = ctk.CTkButton(self, text="Token Nuker", command=self.token_nuker, **button_style)
        self.token_nuker_button.grid(row=0, column=2, padx=10, pady=10, sticky='ew')

        self.ip_lookup_button = ctk.CTkButton(self, text="IP search", command=self.ip_lookup, **button_style)
        self.ip_lookup_button.grid(row=1, column=0, padx=10, pady=10, sticky='ew')

        self.whois_lookup_button = ctk.CTkButton(self, text="WHOIS Lookup", command=self.whois_lookup, **button_style)
        self.whois_lookup_button.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

        self.scan_ports_button = ctk.CTkButton(self, text="Scan Ports", command=self.scan_ports, **button_style)
        self.scan_ports_button.grid(row=1, column=2, padx=10, pady=10, sticky='ew')

        self.ip_entry_label = ctk.CTkLabel(self, text="IP address for search:", text_color='orange')
        self.ip_entry_label.grid(row=3, column=0, columnspan=3, padx=10, pady=5, sticky='ew')

        self.ip_entry = ctk.CTkEntry(self)
        self.ip_entry.grid(row=4, column=0, columnspan=3, padx=10, pady=5, sticky='ew')

        self.result_label = ctk.CTkLabel(self, text="", text_color='orange')
        self.result_label.grid(row=5, column=0, columnspan=3, pady=10, sticky='ew')

        self.ip_label = ctk.CTkLabel(self, text="Adresse IP publique:", text_color='orange')
        self.ip_label.grid(row=6, column=0, columnspan=3, pady=5, sticky='ew')

        self.ip_display = ctk.CTkLabel(self, text="", text_color='white', bg_color='black', anchor='center')
        self.ip_display.grid(row=7, column=0, columnspan=3, pady=5, sticky='ew')

        self.show_ip_var = tk.BooleanVar(value=False)
        self.show_ip_checkbox = ctk.CTkCheckBox(self, text="Afficher l'adresse IP", variable=self.show_ip_var, command=self.toggle_ip_display)
        self.show_ip_checkbox.grid(row=8, column=0, columnspan=2, pady=5, sticky='ew')

        self.vpn_status_label = ctk.CTkLabel(self, text="VPN: Non détecté", text_color='orange')
        self.vpn_status_label.grid(row=8, column=2, pady=5, sticky='ew')

        self.console = tk.Text(self, height=15, wrap='word', bg='black', fg='orange', insertbackground='orange')
        self.console.grid(row=9, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')
        self.console.configure(state='disabled')

        self.console.tag_configure("error", foreground="red")
        self.console.tag_configure("success", foreground="green")

        self.update_ip_display()

    def toggle_ip_display(self):
        if self.show_ip_var.get():
            self.ip_display.grid()
        else:
            self.ip_display.grid_remove()

    def update_ip_display(self):
        self.console_log("Mise à jour de l'adresse IP...", "success")
        ip = self.vpn_server.get_public_ip()
        if ip:
            if self.show_ip_var.get():
                self.ip_display.configure(text=ip)
            else:
                self.ip_display.configure(text="")
        else:
            self.ip_display.configure(text="Erreur lors de la récupération de l'IP")
        self.update_vpn_status()

        # Exemple de texte ASCII ajouté
        ascii_art = """
_________________________$$$$$$$________________
________________________$$$$$$$$$$______________
________________________$$$$$$$$$$$_____________
_________________________$$$$$$$$$$$$$$_________
__________________________$$$$$$$$$$$___________
_____________________________$$$$$$$$$$$$$______
___________________________$$$$$$$$$$___________
_________________________$$$$$$$$$$$$$$$________
________________$$$______$$$$$$$$$$$$$$_________
______________$$$$$$$$_____$$$$$$__$$$$$________
_____________$$$$$$$$$$_____$$$$____$$$$$_______
___________$$$$$$_$$$$$$$$__$$$$______$$$$______
__________$$$$$_____$$$$$$$$_$$$$_______$$$_____
________$$$$$_________$$$$$$$$$$$$_______$$$____
_______$$$_____________$$$$$$$$$$$________$$$___
_____$$$________________$$$$$$$$$$________$$$$$$
__$$$$$$__________________$$$$$$$_______________
"""
        self.console_log(ascii_art)

    def ping_test(self):
        ip = self.vpn_server.get_public_ip()
        if ip:
            ping_result = self.vpn_server.ping_ip(ip)
            self.console_log(f"Résultats du ping pour {ip}:\n{ping_result}")

    def token_nuker(self):
        self.console_log("Cette fonctionnalité est encore en développement.", "error")

    def ip_lookup(self):
        ip = self.ip_entry.get()
        if ip:
            result = self.vpn_server.ip_lookup(ip)
            self.result_label.configure(text=f"Recherche IP:\n{result}")

    def whois_lookup(self):
        domain = self.ip_entry.get()
        if domain:
            result = self.vpn_server.whois_lookup(domain)
            self.result_label.configure(text=f"WHOIS Lookup:\n{result}")

    def scan_ports(self):
        ip = self.ip_entry.get()
        if ip:
            self.console_log(f"Scan des ports pour {ip}...")
            def callback(results, error):
                if error:
                    self.console_log(f"Erreur lors du scan des ports: {error}", "error")
                else:
                    result_text = "\n".join(results)
                    self.console_log(f"Résultats du scan des ports:\n{result_text}")

            self.vpn_server.scan_ports(ip, callback)

    def update_vpn_status(self):
        if self.vpn_server.vpn_active:
            self.vpn_status_label.configure(text="VPN: Actif")
        else:
            self.vpn_status_label.configure(text="VPN: Non détecté")

    def console_log(self, message, tag=""):
        self.console.configure(state='normal')
        self.console.insert('end', message + "\n", tag)
        self.console.yview_pickplace('end')
        self.console.configure(state='disabled')

if __name__ == "__main__":
    app = VPNApp()
    app.mainloop()
