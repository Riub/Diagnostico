import tkinter as tk
from tkinter import ttk, messagebox, Menu, scrolledtext, filedialog
import socket
import platform
import psutil
import pyperclip
import subprocess
import winreg
import os
import shutil
import threading
import re
import tkinter.font as tkfont
import threading
 
 
class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Diagnóstico del Sistema")
        self.geometry("900x600")
        self.config(bg="#f0f0f0")
 
        # Encabezado
        self.encabezado = tk.Label(self, text="Herramienta de Diagnóstico", font=("Arial", 24, "bold"), bg="#4a4a4a", fg="white", pady=20)
        self.encabezado.pack(fill="x")
 
        # Frame principal que contiene todo
        self.frame_principal = tk.Frame(self, bg="#f0f0f0")
        self.frame_principal.pack(fill="both", expand=True)
 
        # Barra lateral
        self.barra_lateral = tk.Frame(self.frame_principal, bg="#4a4a4a", width=150, padx=5, pady=5)
        self.barra_lateral.pack(side="left", fill="y")
 
        # Botones en la barra lateral con colores y tamaño pequeño
        botones = [
            ("Ejecutar Diagnóstico Completo", "#4a90e2"),
            ("Remediación", "#e27d60"),
            ("Utilidades", "#85dcbb"),
           
        ]
 
        for texto, color in botones:
            boton = tk.Button(self.barra_lateral, text=texto, font=("Arial", 10), bg=color, fg="white", relief="flat", pady=2, padx=2)  
            boton.pack(fill="x", pady=3)
            if texto == "Ejecutar Diagnóstico Completo":boton.config(command=self.mostrar_diagnostico)
            elif texto == "Remediación":boton.config(command=self.remediacion)
 
        # Frame derecho para mostrar el contenido principal
        self.frame_contenido = tk.Frame(self.frame_principal, bg="white", padx=20, pady=20)
        self.frame_contenido.pack(side="left", fill="both", expand=True)
 
 
 
        self.pie_pagina = tk.Label(self, text="Desarrollado por SQUAD Ingenieria SO BDB - Versión 1.0", font=("Arial", 10), bg="#4a4a4a", fg="white", pady=10)
        self.pie_pagina.pack(fill="x", side="bottom")
 
        self.mensaje_inicial()
 
    def mensaje_inicial(self):
        for widget in self.frame_contenido.winfo_children():
            widget.destroy()
        initial_message = "Bienvenido a la herramienta de diagnóstico del sistema.\nSeleccione una opción en la barra lateral para comenzar.\n"
        label = tk.Label(self.frame_contenido, text=initial_message, font=("Segoe UI", 18), bg="white")
        label.pack(pady=20)
 
    def hilo_ejecutar_diagnostico(self):
   
        hilo_diagnostico = threading.Thread(target=self.ejecutar_diagnostico_completo)
        hilo_diagnostico.start()
 
    def mostrar_diagnostico(self):
        for widget in self.frame_contenido.winfo_children():
                       
            if hasattr(self, 'campo_info')and widget == self.campo_info:
                continue
            if hasattr(self, 'label_estado')and widget == self.label_estado:
                continue
            widget.destroy()
        nombre_pc = socket.gethostname()
 
        if not hasattr(self, 'label_estado')or not self.label_estado.winfo_exists():
            self.label_estado = tk.Label(self.frame_contenido, text=nombre_pc, font=("Arial", 18), bg="white", anchor="w")
            self.label_estado.pack(fill="x", pady=10)
 
        if not hasattr(self, 'campo_info') or not self.campo_info.winfo_exists():
            self.campo_info = tk.Text(self.frame_contenido, height=15, bg="#e0e0e0", font=("Arial", 10))
            self.campo_info.pack(fill="both", expand=True, pady=10)
            self.campo_info.tag_configure('red', foreground='red')
            self.campo_info.tag_configure('green', foreground='green')
 
        frame_botones = tk.Frame(self.frame_contenido, bg="white")
        frame_botones.pack(pady=10, anchor="center")
 
        self.boton_exportar = tk.Button (frame_botones, text= "Exportar", command=self.boton_exportar_txt, bg="#4A4A4A", fg="white")
        self.boton_exportar.grid(row=0, column=0, pady=5,padx=10)
 
        self.boton_exportar = tk.Button (frame_botones, text= "Ejecutar Diagnostico", command=self.hilo_ejecutar_diagnostico, bg="#4A4A4A", fg="white")
        self.boton_exportar.grid(row=0, column=1, pady=5,padx=10)
 
    def ejecutar_diagnostico_completo(self):
        try:
            # Información del sistema operativo
            self.campo_info.insert(tk.END, "DIAGNÓSTICO DE LA ESTACIÓN:\n\n\n")
            self.campo_info.insert(tk.END, "=" * 80 )
           
            # Obtener versión de Windows
            try:
                version_windows = self.windows_version()
                numero_serial = self.obtener_numero_serie()
                bios = self.obtener_version_bios()
                nombre_pc = socket.gethostname()
               
                self.campo_info.insert(tk.END, "\n[Información del Sistema Operativo]\n\n")
                self.campo_info.insert(tk.END, f"Nombre del equipo: {nombre_pc}\n")
                self.campo_info.insert(tk.END, f"Versión de Windows: {version_windows}\n")
                self.campo_info.insert(tk.END, f"Número de Serial: {numero_serial}\n")
                self.campo_info.insert(tk.END, f"Versión de la BIOS: {bios}\n")
                self.campo_info.insert(tk.END, "=" * 80 )
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información del sistema operativo: {str(e)}\n")
                self.campo_info.insert(tk.END, "=" * 80 )
 
            try:
                hotfix = self.check_windows_versions()
                self.campo_info.insert(tk.END, "\n[Hotfix Windows]\n")
                self.campo_info.insert(tk.END, hotfix)
                self.campo_info.insert(tk.END, "=" * 80)
               
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información de Hotfix: {str(e)}\n")
                self.campo_info.insert(tk.END, "=" * 80)    
   
           
            # Obtener información de RAM
            try:
                total_ram, available_ram = self.ram_info()
                self.campo_info.insert(tk.END,"\n[Memoria RAM]\n\n")
                self.campo_info.insert(tk.END ,f"Memoria Total: {total_ram:.2f} GB\n")
                self.campo_info.insert(tk.END, f"Memoria Disponible: {available_ram:.2f} GB\n")
                self.campo_info.insert(tk.END, "=" * 80)
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información de RAM: {str(e)}\n")
                self.campo_info.insert(tk.END, "=" * 80)
            # Obtener información de discos
            try:
                disk_info = self.get_disk_info()
                self.campo_info.insert(tk.END, "\n[Unidades de Almacenamiento]\n\n")
                self.campo_info.insert(tk.END, f"{'Dispositivo':<25} {'Total (GB)':<15} {'Libre (GB)':<15}  {'% Libre':<10}\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")                      
                for dispositivo, total_disk, free_disk in disk_info:
                   
                    porcentaje_libre = (free_disk / total_disk) * 100
                    porcentaje_libre_text = f"{porcentaje_libre:.2f}%"
                    color = "green" if porcentaje_libre > 20 else "red"
 
                    self.campo_info.insert(tk.END, f"{dispositivo:<30}")
                    self.campo_info.insert(tk.END, f"{total_disk:.2f}".rjust(15))
                    self.campo_info.insert(tk.END, f"{free_disk:.2f}".rjust(15))
                    self.campo_info.insert(tk.END, f"{porcentaje_libre_text}".rjust(15) + "\n", ('color', color))  
                self.campo_info.insert(tk.END, "=" * 80 + "\n")    
 
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información de discos: {str(e)}\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")    
 
 
            # Información de drivers
            try:
                resultado_drivers = self.check_drivers()
                self.campo_info.insert(tk.END, "\n[Drivers Desactualizados]\n\n")
                color_drivers = "green" if "No hay drivers desactualizados" in resultado_drivers else "red"
                self.campo_info.insert(tk.END, resultado_drivers, color_drivers)
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información de drivers: {str(e)}\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
             
                # Obtener información de red
            try:
                datos_red, gateway = self.obtener_datos_red_directamente()
                self.campo_info.insert(tk.END, "\n[Diagnóstico de Interfaces de Red]\n\n")
                self.campo_info.insert(tk.END, f"{'Interfaz':<18} {'Estado':<17} {'MAC':<27} {'IPv4':<26} {'Gateway':<20}\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
       
                for interfaz, estado, mac, ipv4, gateway in datos_red:
                    estado_color = 'green' if estado == 'Conectado' else 'red'
                    self.campo_info.insert(tk.END, f"{interfaz:<15} ")
                    self.campo_info.insert(tk.END, f"{estado:<15}", estado_color)
                    self.campo_info.insert(tk.END, f"{mac:<20} {ipv4:<20} {gateway:<20}\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
 
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información de red: {str(e)}\n")
           
            try:
                dns_resultados = self.obtener_dns()
                self.campo_info.insert(tk.END, "\n[Servidores DNS]\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
                   
   
                if dns_resultados:
                    for adaptador, dns_list in dns_resultados.items():
                        for dns in dns_list:
                            self.campo_info.insert(tk.END, f"  - {dns}\n")
                           
                else:
                    self.campo_info.insert(tk.END, "No se encontraron servidores DNS.\n")
                    self.campo_info.insert(tk.END, "=" * 80 + "\n")
 
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener información de DNS: {str(e)}\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")    
             
            try:
                # Obtener la configuración del proxy
                proxy_resultados = self.get_proxy_settings()
                self.campo_info.insert(tk.END, "=" * 80 + "\n\n")
                self.campo_info.insert(tk.END, "[Proxy]\n")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
 
                # Mostrar la configuración en el campo_info
                if "error" in proxy_resultados and proxy_resultados["error"]:
                    self.campo_info.insert(tk.END, f"Error al obtener la configuración de proxy: {proxy_resultados['error']}\n", "red")
                else:
                    # Asegúrate de que la clave 'proxy_server' esté presente
                    proxy_server_status = proxy_resultados.get('proxy_server', 'Información no disponible')
                    color_proxy = "red" if proxy_server_status == "Proxy desactivado" else "green"
                    self.campo_info.insert(tk.END, f"{proxy_server_status}\n", color_proxy)
                    self.campo_info.insert(tk.END, "=" * 80 + "\n")
 
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al obtener la configuración de proxy: {str(e)}\n", "red")
                self.campo_info.insert(tk.END, "=" * 80 + "\n")
 
                   
               
           
            self.campo_info.insert(tk.END, "\n[Pings]\n")
            self.campo_info.insert(tk.END, "=" * 80 + "\n")
               
                # Ping al gateway
            try:
                resultado_gateway, _ = self.hacer_ping_exportar(gateway)
                color_gateway = "green" if "Éxito" in resultado_gateway else "red"
                self.campo_info.insert(tk.END, f"Ping al gateway {gateway}: {resultado_gateway}\n", color_gateway)
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al hacer ping al gateway {gateway}: {str(e)}\n", "red")
               
            try:    
                logonserver = self.obtener_logonserver()
                if logonserver:
                    try:
                        resultado_logonserver, ip_address = self.hacer_ping_exportar(logonserver)
                        color_logonserver = "green" if "Éxito" in resultado_logonserver else "red"
                        if ip_address:
                            self.campo_info.insert(tk.END, f"Ping al Controlador de dominio {logonserver} ({ip_address}): {resultado_logonserver}\n", color_logonserver)
                        else:
                            self.campo_info.insert(tk.END, f"Ping al Controlador de dominio {logonserver}: {resultado_logonserver}\n", color_logonserver)
                    except Exception as e:
                        self.campo_info.insert(tk.END, f"Error al hacer ping al Controlador de dominio {logonserver}: {str(e)}\n", "red")
                else:
                    self.campo_info.insert(tk.END, "No se encontró Controlador de dominio.\n", "red")
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error general al obtener  Controlador de dominio: {str(e)}\n")
 
            try:
                mantiz = "mantiz"
                ping_mantiz, ip_address = self.hacer_ping_exportar(mantiz)
                color_mantiz = "green" if "Éxito" in ping_mantiz else "red"
                self.campo_info.insert(tk.END, f"Ping al Controlador de dominio {mantiz} ({ip_address}): {ping_mantiz}\n", color_mantiz)
            except:
                self.campo_info.insert(tk.END, f"Error al hacer ping a mantiz {mantiz}: {str(e)}\n", "red")
 
            try:
                crm = "CRM"
                ping_crm, ip_address = self.hacer_ping_exportar(crm)
                color_crm = "green" if "Éxito" in ping_crm else "red"
                self.campo_info.insert(tk.END, f"Ping al Controlador de dominio {crm} ({ip_address}): {ping_crm}\n", color_crm)
            except:
                self.campo_info.insert(tk.END, f"Error al hacer ping a mantiz {crm}: {str(e)}\n", "red")    
 
            try:
                ip_pc = ipv4
                ip_base = ".".join(ip_pc.split(".")[:-1])
                ips_router = f"{ip_base}.120"
                resultado_router, _ = self.hacer_ping_exportar(ips_router)
                color_router = "green" if "Éxito" in ping_crm else "red"
                self.campo_info.insert(tk.END, f"Ping al router {ips_router}: {resultado_router}\n", color_router)
            except Exception as e:
                self.campo_info.insert(tk.END, f"Error al hacer ping al router {ips_router}: {str(e)}\n", "red")
 
 
 
 
 
            self.campo_info.insert(tk.END, "=" * 80 + "\n")
            self.campo_info.insert(tk.END, "Diagnóstico completado.")
 
        except Exception as e:
            self.campo_info.insert(tk.END, f"Error general en la ejecución del diagnóstico: {str(e)}\n")
 
    def boton_exportar_txt(self):
        contenido = self.campo_info.get("1.0" , tk.END)
        archivo = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivo de texto", "*.txt")])
 
        if archivo:
            with open(archivo, "w") as file:
                file.write(contenido)
   
    def get_proxy_settings(self):
        try:
            # Abrir la clave del registro donde se almacena la configuración del proxy
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0]
            proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            winreg.CloseKey(key)
           
            if proxy_enable == 0:
                # Si el proxy está desactivado
                proxy_server = "Proxy desactivado"
 
            return {
                "proxy_server": proxy_server,
                "error": None
            }
        except FileNotFoundError:
            return {
                "proxy_server": "No se encontró configuración de proxy.",
                "error": "No se encontró configuración de proxy en el registro."
            }
        except Exception as e:
            return {
                "proxy_server": "Error",
                "error": str(e)
            }
 
 
    def execute_command(self, command):
        try:
            result = subprocess.check_output(command, shell=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return result
        except subprocess.CalledProcessError as e:
            return str(e)
       
    def check_drivers(self):
        command = 'powershell -Command "Get-WmiObject Win32_PNPEntity | Where-Object{$_.ConfigManagerErrorCode -ne 0} | Select Name"'  
 
        try:
            result = self.execute_command(command)
            if result:
                return f"{result}\n"
            else:
                return "No hay drivers desactualizados.\n"
        except Exception as e:
            return f"Error al obtener información de drivers: {e}\n"
 
    def check_windows_versions(self):
        command = 'powershell -Command "Get-CimInstance -ClassName Win32_QuickFixEngineering | Select-Object Description, HotFixID"'
       
        try:
            result = self.execute_command(command)
            if result:
                return f"{result}\n"
            else:
                return "No hay informaciónde hotfix.\n"
        except Exception as e:
            return f"Error al obtener información de hotfix: {e}\n"
 
 
    def obtener_numero_serie(self):
        try:
            # Ejecutar el comando en PowerShell y capturar la salida
            comando = "powershell -Command \"Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber\""
            resultado = subprocess.check_output(comando, shell=True, text=True)
            # Filtrar y obtener el número de serie
            serial = resultado.strip()
            if serial:
                return serial
            else:
                return "No se pudo obtener el número de serie."
        except subprocess.CalledProcessError as e:
            return f"Error en el comando: {str(e)}"
        except Exception as e:
            return f"Error: {str(e)}"
 
    def obtener_version_bios(self):
        try:
             # Ejecutar el comando en PowerShell y capturar la salida
            comando = "powershell -Command \"Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion\""
            resultado = subprocess.check_output(comando, shell=True, text=True)
            bios = resultado.strip()
            if bios:
                return bios
            else:
                return "No se pudo obtener bios."
        except Exception as e:
            return f"Error: {str(e)}"
 
    def windows_version(self):
        version = platform.version()
        release = platform.release()
        version_completa = platform.platform()
        return f"Windows {release} (versión {version})"
     
 
    def ram_info(self):
        ram = psutil.virtual_memory()
        total_ram = ram.total / (1024 ** 3)
        available_ram = ram.available / (1024 ** 3)
        return total_ram, available_ram
 
    def get_disk_info(self):
        partitions = psutil.disk_partitions()
        disk_info = []
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                total_disk = usage.total / (1024 ** 3)  # Convertir a GB
                free_disk = usage.free / (1024 ** 3)  # Convertir a GB
                disk_info.append((partition.device, total_disk, free_disk))
            except Exception as e:
                pass
        return disk_info
 
 
    def obtener_gateway(self):
        try:
            resultado = subprocess.check_output("ipconfig", text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            gateways = {}
            adaptador = None
            for linea in resultado.splitlines():
                if "Adaptador" in linea or "adapter" in linea:
                    adaptador = linea.split(" ")[-1].strip(":")
                if adaptador and ("Puerta de enlace predeterminada" in linea or "Default Gateway" in linea):
                    partes = linea.split(":")
                    if len(partes) > 1:
                        gateway = partes[1].strip()
                        if gateway:
                            gateways[adaptador] = gateway
                            adaptador = None  
            return gateways
        except subprocess.CalledProcessError:
            return {}
       
    def obtener_datos_red_directamente(self):
        direcciones_interfaces_red = psutil.net_if_addrs()
        estadisticas_interfaces_red = psutil.net_if_stats()
        gateways = self.obtener_gateway()
       
 
        datos_red = []
        for interfaz, direcciones in direcciones_interfaces_red.items():
            if not (("Ethernet" in interfaz or "eth" in interfaz or "en" in interfaz) or ("Wi-Fi" in interfaz or "wlan" in interfaz or "wl" in interfaz)):
                continue
           
            mac, ipv4 = "N/A", "N/A"
            estado = "Desconectado"
            gateway = gateways.get(interfaz, "N/A")
 
            if interfaz in estadisticas_interfaces_red:
                estadisticas = estadisticas_interfaces_red[interfaz]
                estado = "Conectado" if estadisticas.isup else "Desconectado"
 
            for direccion in direcciones:
                if direccion.family == psutil.AF_LINK:
                    mac = direccion.address
                elif direccion.family == 2:
                    ipv4 = direccion.address
 
            datos_red.append((interfaz, estado, mac, ipv4, gateway))
 
        return datos_red, gateways
   
    def obtener_dns(self):
        try:
            # Ejecuta el comando ipconfig /all y guarda el resultado
            resultado = subprocess.check_output("ipconfig /all", text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            dns_servidores = {}
           
            adaptador = None
            for linea in resultado.splitlines():
                linea = linea.strip()
               
                # Captura el nombre del adaptador de red
                if "Adaptador" in linea or "adapter" in linea:
                    adaptador = linea.split()[-1].strip(":")
               
                # Busca las líneas que contienen la información de los servidores DNS
                if adaptador and ("Servidores DNS" in linea or "DNS Servers" in linea):
                    partes = linea.split(":")
                    if len(partes) > 1:
                        dns = partes[1].strip()
                        if self.es_ip_valida(dns):
                            dns_servidores.setdefault(adaptador, []).append(dns)
                elif adaptador and linea and not linea.startswith("Adaptador") and not linea.startswith("adapter"):
                    # Continúa buscando en las siguientes líneas el resto de los DNS
                    dns = linea.strip()
                    if self.es_ip_valida(dns):
                        # Evita duplicados
                        if dns not in dns_servidores.get(adaptador, []):
                            dns_servidores.setdefault(adaptador, []).append(dns)
           
            return dns_servidores
 
        except subprocess.CalledProcessError:
            return {}  # En caso de error, retorna un diccionario vacío
        except Exception as e:
            # Captura cualquier otra excepción y muestra el error (opcional)
            return {}
 
       
    def es_ip_valida(self, ip):
        # Valida si una cadena es una dirección IP válida
        patron = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return re.match(patron, ip) is not None    
   
    def obtener_logonserver(self):
        try:
            # Obtener el valor de la variable de entorno LOGONSERVER
            logonserver = os.environ.get("LOGONSERVER")
            if logonserver:
                # Eliminar las barras invertidas al principio (\\) si existen
                return logonserver.replace("\\", "")
            else:
                return None  # Retorna None si no se encuentra LOGONSERVER
        except Exception as e:
            return None  # Retorna None en caso de error
 
           
 
    def hacer_ping_exportar(self, host):
        try:
            # Intenta obtener la dirección IP del host
            try:
                ip_address = socket.gethostbyname(host)
            except socket.gaierror:
                ip_address = None
           
            # Ejecuta el comando de ping
            resultado = subprocess.check_output(["ping", "-n", "4", host], text=True, creationflags=subprocess.CREATE_NO_WINDOW)
           
            # Verifica si el ping fue exitoso buscando "TTL=" en la salida
            if "TTL=" in resultado:
                # Busca la media del tiempo en la salida (tanto en español como en inglés)
                media_ping = re.search(r"(Media|Average)[^=\d]*=\s*(\d+)\s*ms", resultado)
                if media_ping:
                    tiempo_media = media_ping.group(2)  # Captura el valor de la media
                    return f"Éxito, tiempo medio: {tiempo_media} ms", ip_address
                else:
                    return "Éxito, tiempo medio no disponible", ip_address
            else:
                return "Fallido", ip_address
        except subprocess.CalledProcessError:
            return "Fallido", None
 
    def remediacion(self):
        for widget in self.frame_contenido.winfo_children():
            widget.destroy()    
 
        fondo_contenido = self.frame_contenido.cget("bg")  
 
        self.check_aranda_var = tk.BooleanVar()
        self.check_temporales_var = tk.BooleanVar()
        self.check_proxy_var = tk.BooleanVar()
        self.check_pulse_var = tk.BooleanVar()
        self.check_adobe_var = tk.BooleanVar()
        self.check_olimpia_var = tk.BooleanVar()
 
        self.check_aranda = tk.Checkbutton(self.frame_contenido, text= "Revisar Aranda", variable= self.check_aranda_var, font=("Arial",10),bg=fondo_contenido )
        self.check_temporales = tk.Checkbutton(self.frame_contenido, text= "Limpiar Temporales", variable= self.check_temporales_var , font=("Arial",10),bg=fondo_contenido )
        self.check_proxy = tk.Checkbutton(self.frame_contenido, text= "Activar/Desactivar Proxy", variable= self.check_proxy_var, font=("Arial",10),bg=fondo_contenido )
        self.check_pulse = tk.Checkbutton(self.frame_contenido, text= "Reparar Pulse", variable= self.check_pulse_var, font=("Arial",10),bg=fondo_contenido )
        self.check_adobe = tk.Checkbutton(self.frame_contenido, text= "Reparar Adobe", variable= self.check_adobe_var, font=("Arial",10),bg=fondo_contenido )
        self.check_olimpia = tk.Checkbutton(self.frame_contenido, text= "Reparar Olimpia", variable= self.check_olimpia_var, font=("Arial",10),bg=fondo_contenido )
 
        self.check_aranda.grid(row=0, column=0, sticky="w", padx=20, pady=5)    
        self.check_temporales.grid(row=1, column=0, sticky="w", padx=20, pady=5)    
        self.check_proxy.grid(row=2, column=0, sticky="w", padx=20, pady=5)    
        self.check_pulse .grid(row=0, column=1, sticky="w", padx=20, pady=5)    
        self.check_adobe.grid(row=1, column=1, sticky="w", padx=20, pady=5)    
        self.check_olimpia.grid(row=2, column=1, sticky="w", padx=20, pady=5)
 
 
        boton_ejecutar = tk.Button(self.frame_contenido, text= "Ejecutar", font=("Arial", 12), bg="#4a90e2", fg="white", command=self.ejecutar_remediacion)
        boton_ejecutar.grid(pady=20)
 
    def ejecutar_remediacion(self):
        if self.check_aranda_var.get():
            self.check_aranda_func()
        if self.check_temporales_var.get():
            self.eliminar_archivos_temporales()  
        if self.check_proxy_var.get():
            self.cambiar_proxy()  
        if self.check_pulse_var.get():
            self.reparar_pulse()  
        if self.check_adobe_var.get():
            self.reparar_adobe()      
        if self.check_olimpia_var.get():
            self.reparar_olimpia()    
 
        self.check_aranda_var.set(False)
        self.check_temporales_var.set(False)
        self.check_proxy_var.set(False)
        self.check_pulse_var.set(False)
        self.check_adobe_var.set(False)
        self.check_olimpia_var.set(False)
 
    def reparar_olimpia(self):
        # Comando para ejecutar ReconocerServicio.exe
        command = ('powershell -Command "Start-Process \\"D:\\Apl\\Olimpia\\RreconocerServicio\\ReconocerServicio.exe\\" -Wait"')
        self.execute_command(command, "No se pudo ejecutar ReconocerServicio.exe")    
 
    def reparar_adobe(self):
        # Comando para reparar Pulse Secure usando PowerShell
 
        command = ('powershell -Command "Start-Process \\"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe\\" -ArgumentList \\"/repair=1\\" -Wait"' )
        self.execute_command(command, "No se pudo reparar Pulse Secure")    
 
    def reparar_pulse(self):
        # Comando para reparar Pulse Secure usando PowerShell
        command = ('powershell -Command "Start-Process \\"C:\\Program Files (x86)\\Pulse Secure\\Pulse\\PulseUninstall.exe\\" -ArgumentList \\"/repair=1\\" -Wait"')
        self.execute_command(command, "No se pudo reparar Pulse Secure")
 
    def check_aranda_func(self):
        command = 'powershell -Command "Get-Process SentinelFM | Format-List *; Stop-Process -Name \\"SentinelFM\\""'
        self.execute_command(command)        
   
 
    def eliminar_archivos_temporales(self):
        temp_dirs = [
            os.environ.get('TEMP'),
            os.environ.get('TMP'),
            os.path.join(os.environ.get('SystemRoot'), 'Temp'),
            os.path.join(os.environ.get('USERPROFILE'), 'AppData', 'Local', 'Temp')
        ]
 
        archivos_eliminados = 0
        carpetas_eliminadas = 0
 
        # Comandos 'attrib' para eliminar los atributos de oculto y sistema antes de borrar
        ocultar_atributos_cmds = [
            f'attrib -h -s "{os.environ.get("USERPROFILE")}\\CONFIG~1"',
            f'attrib -h -s "{os.environ.get("USERPROFILE")}\\CONFIG~1\\Archivos temporales de Internet"',
            f'attrib -h -s "{os.environ.get("USERPROFILE")}\\CONFIG~1\\Archivos temporales de Internet\\Content.IE5"'
        ]
 
        for cmd in ocultar_atributos_cmds:
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar {cmd}: {e}")
 
        for temp_dir in temp_dirs:
            if temp_dir and os.path.exists(temp_dir):
                for root, dirs, files in os.walk(temp_dir):
                    # Eliminar archivos
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            os.remove(file_path)
                            archivos_eliminados += 1
                        except Exception as e:
                            print(f"No se pudo eliminar el archivo: {file_path}. Error: {e}")
 
                    # Eliminar carpetas vacías
                    for dir in dirs:
                        dir_path = os.path.join(root, dir)
                        try:
                            shutil.rmtree(dir_path)
                            carpetas_eliminadas += 1
                        except Exception as e:
                            print(f"No se pudo eliminar la carpeta: {dir_path}. Error: {e}")
 
        # Eliminar archivos específicos con 'del' y 'rmdir'
        eliminar_cmds = [
            f'del /S /Q /F "{os.environ.get("USERPROFILE")}\\CONFIG~1\\Archivos temporales de Internet\\Content.IE5"',
            f'del /S /Q /F "{os.environ.get("USERPROFILE")}\\CONFIG~1\\Archivos temporales de Internet\\Content.IE5\\index.dat"',
            f'rmdir /Q /S "{os.environ.get("USERPROFILE")}\\AppData\\Local\\Temp"',
            f'del /S /Q /F "{os.environ.get("SystemRoot")}\\Temp\\."',
            f'del /S /Q /F "C:\\Temp\\."',
            f'del /S /Q /F "C:\\Windows\\Prefetch\\."'
        ]
 
        for cmd in eliminar_cmds:
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar {cmd}: {e}")
 
        # Vaciar la papelera de reciclaje
        try:
            subprocess.run('PowerShell -Command "Clear-RecycleBin -Force"', shell=True, check=True)
            print("Papelera de reciclaje vaciada.")
        except subprocess.CalledProcessError as e:
            print(f"Error al vaciar la papelera de reciclaje: {e}")
 
        # Restaurar atributos de oculto y sistema después de borrar
        restaurar_atributos_cmds = [
            f'attrib +h +s "{os.environ.get("USERPROFILE")}\\CONFIG~1\\Archivos temporales de Internet\\Content.IE5"',
            f'attrib +h +s "{os.environ.get("USERPROFILE")}\\CONFIG~1\\Archivos temporales de Internet"',
            f'attrib +h +s "{os.environ.get("USERPROFILE")}\\CONFIG~1"'
        ]
 
        for cmd in restaurar_atributos_cmds:
            try:
                subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error al ejecutar {cmd}: {e}")
 
        messagebox.showinfo("Completado", f"Eliminados {archivos_eliminados} archivos temporales.\nEliminadas {carpetas_eliminadas} carpetas temporales.")
 
    def cambiar_proxy(self):        
        try:
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)            
            configuracion_internet = winreg.OpenKey(registro,r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ | winreg.KEY_WRITE)
            proxy_enabled, _ = winreg.QueryValueEx(configuracion_internet,"ProxyEnable")  
 
            if proxy_enabled == 0:                
                winreg.SetValueEx(configuracion_internet,"ProxyEnable", 0, winreg.REG_DWORD, 1)
                messagebox.showinfo("Proxy Activado","El proxy ha sido activado correctamente.")            
            else:                
                winreg.SetValueEx(configuracion_internet,"ProxyEnable", 0, winreg.REG_DWORD, 0)
                messagebox.showinfo("Proxy Desactivado","El proxy ha sido desactivado correctamente.")
        except Exception as e:
            messagebox.showerror("Error",f"No se pudo cambiar el estado del proxy:{e}")    
     
# Iniciar la aplicación
if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()