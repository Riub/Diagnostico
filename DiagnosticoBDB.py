import os
import socket
import tkinter as tk
from tkinter import ttk, messagebox, Menu
import psutil
import winreg
import subprocess
import re
import threading
import pyperclip
 
class DiagnosticoRedApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Diagnóstico de Red")
        self.auto_ajustar_tamaño_pantalla()
        self.resizable(False, False)
        self.crear_widgets()
        self.crear_pie_de_pagina()
        self.actualizar_informacion_red()
        self.mostrar_informacion_proxy()
        self.mostrar_nombre_pc()
        self.ajustar_ancho_columnas()
        self.mostrar_dns()
   
    def auto_ajustar_tamaño_pantalla(self):
    # Definir tamaño inicial deseado de la ventana
        ancho_inicial = 800
        alto_inicial = 700
   
    # Obtener dimensiones de la pantalla
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
   
    # Calcular el tamaño adecuado en base al tamaño de la pantalla
        ancho_ventana = min(ancho_inicial, screen_width - 100)  # Se resta 100 para no usar todo el espacio
        alto_ventana = min(alto_inicial, screen_height - 100)  # Se resta 100 para no usar todo el espacio
   
    # Calcular la posición para centrar la ventana
        x = (screen_width - ancho_ventana) // 2
        y = (screen_height - alto_ventana) // 2
   
    # Establecer la geometría de la ventana
        self.geometry(f"{ancho_ventana}x{alto_ventana}+{x}+{y}")
 
    def crear_widgets(self):
        self.nombre_pc = tk.Label(self, text="", font=("Arial", 12, "bold"))
        self.nombre_pc.pack()
 
        #Creacion tablero con estado de interfaces
        self.treeview_red = ttk.Treeview(self, columns=("Interfaz", "Estado", "MAC", "IPv4", "Gateway"), show="headings")
        self.treeview_red.heading("Interfaz", text="Interfaz")
        self.treeview_red.heading("Estado", text="Estado")
        self.treeview_red.heading("MAC", text="MAC")
        self.treeview_red.heading("IPv4", text="IPv4")
        self.treeview_red.heading("Gateway", text="Gateway")
        self.treeview_red.pack(pady=10, fill=tk.X)
 
        #creacion ventana para copiar
        self.menu = Menu(self.treeview_red, tearoff=0)
        self.menu.add_command(label="Copiar", command=self.copiar_seleccion)
        self.treeview_red.bind("<Button-3>", self.popup_menu)
 
 
        self.frame_proxy = tk.Frame(self)
        self.frame_proxy.pack(pady=(20, 5), fill=tk.X)
 
        self.etiqueta_proxy = tk.Label(self.frame_proxy, text="Proxy Configurado:")
        self.etiqueta_proxy.pack(side=tk.LEFT, padx=(0, 10))
 
        self.texto_proxy = tk.Text(self.frame_proxy, height=1, width=40)
        self.texto_proxy.pack(side=tk.LEFT, fill=tk.X, expand=True)
 
        self.frame_dns = tk.Frame(self)
        self.frame_dns.pack(fill=tk.X, padx=10, pady=5)
 
        self.etiqueta_dns = tk.Label(self.frame_dns, text="Servidores DNS Configurados:")
        self.etiqueta_dns.pack(side=tk.LEFT, padx=(0, 10))
 
        self.texto_dns = tk.Text(self.frame_dns, height=5, width=60)
        self.texto_dns.pack(side=tk.LEFT, fill=tk.X, expand=True)
 
        self.frame_botones_proxy = tk.Frame(self)
        self.frame_botones_proxy.pack(pady=10)
 
 
        self.boton_ping_gtwy = tk.Button(self.frame_botones_proxy, text="Ping Hacia Gateway", command=self.ping_gateways)
        self.boton_ping_gtwy.pack(side=tk.LEFT, padx=10)

        self.boton_ping_gtwy = tk.Button(self.frame_botones_proxy, text="Ping Hacia Gateway", command=self.hacer_ping_dns)
        self.boton_ping_gtwy.pack(side=tk.LEFT, padx=10)
 
 
        self.frame_ping = tk.Frame(self)
        self.frame_ping.pack(pady=10)
 
        self.resultado_ping_texto = tk.Text(self.frame_ping, height=10, width=60)
        self.resultado_ping_texto.grid(row=0, column=1, rowspan=3, padx=10, sticky="nsew")
 
        self.frame_controles_ping = tk.Frame(self.frame_ping)
        self.frame_controles_ping.grid(row=0, column=0, padx=10, sticky="n")
 
        # Entrada para ingresar la dirección IP manualmente
        self.etiqueta_ip_manual = tk.Label(self.frame_controles_ping, text="Ingresar dirección IP manualmente:")
        self.etiqueta_ip_manual.grid(row=2, column=0, pady=5, sticky="w")  
 
        self.entrada_ip_manual = tk.Entry(self.frame_controles_ping, width=20)
        self.entrada_ip_manual.grid(row=3, column=0, pady=5, sticky="w")
 
        # lista desplegable para seleccionar la dirección IP
        self.etiqueta_ip_lista = tk.Label(self.frame_controles_ping, text="Seleccionar dirección IP:")
        self.etiqueta_ip_lista.grid(row=0, column=0, pady=5, sticky="w")
 
        self.combobox_ip = ttk.Combobox(self.frame_controles_ping, width=20, state="readonly")
        self.combobox_ip.grid(row=1, column=0, pady=5, sticky="w")  
 
        self.boton_ping = tk.Button(self.frame_controles_ping, text="Ping", command=self.hacer_ping)
        self.boton_ping.grid(row=2, column=1, pady=5, padx=(10, 0), sticky="e")  
 
   

    def obtener_dns(self):
        try:
            resultado = subprocess.check_output("ipconfig /all", text=True)
            dns_servidores = {}
 
            adaptador = None
            for linea in resultado.splitlines():
                if "Adaptador" in linea or "adapter" in linea:
                    adaptador = linea.split(" ")[-1].strip(":")
                if adaptador and ("Servidores DNS" in linea or "DNS Servers" in linea):
                    partes = linea.split(":")
                    if len(partes) > 1:
                        dns = partes[1].strip()
                        if self.es_ip_valida(dns):
                            if adaptador in dns_servidores:
                                dns_servidores[adaptador].append(dns)
                            else:
                                dns_servidores[adaptador] = [dns]
                elif adaptador and linea.startswith(" "):
                    dns = linea.strip()
                    if self.es_ip_valida(dns):
                        if adaptador in dns_servidores:
                            dns_servidores[adaptador].append(dns)
                        else:
                            dns_servidores[adaptador] = [dns]
           
           
            return dns_servidores
        except subprocess.CalledProcessError:
            return {}
 
    def es_ip_valida(self, ip):
        # Valida si una cadena es una dirección IP válida
        patron = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        return re.match(patron, ip) is not None
 
    def mostrar_dns(self):
        dns_servidores = self.obtener_dns()
        nombres_dns = self. obtener_nombres_de_dominio_dns()
        for adaptador, dns_list in dns_servidores.items():
            for dns in dns_list:
                self.texto_dns.insert(tk.END, f"{dns}\n")
 
    def obtener_nombre_de_dominio(self, ip_dns):
        try:
            host_dns, _, _ = socket.gethostbyaddr(ip_dns)
            return host_dns
        except socket.herror:
            return ip_dns
        except Exception as e:
            print(f"Error al obtener nombre de dominio para {ip_dns}: {str(e)}")
            return ip_dns
 
    def obtener_nombres_de_dominio_dns(self):
        dns_servidores = self.obtener_dns()
        nombres_dns = {}
        for adaptador, dns_list in dns_servidores.items():
            nombres_dns[adaptador] = [self.obtener_nombre_de_dominio(dns) for dns in dns_list]
        return nombres_dns        
 
    def obtener_gateway(self):
        try:
           
            resultado = subprocess.check_output("ipconfig", text=True)
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
 
    #Direcciones para la lista desplegable
    def cargar_direcciones_ip(self):
        self.diccionario_ips = {
            "Onbase": "10.85.2.50",
            "CRM": "10.85.2.90",
            "Mantiz": "10.85.2.96",
            "Mainframe": "10.85.138.9"
        }
 
        self.combobox_ip["values"] = list(self.diccionario_ips.keys())
        if self.diccionario_ips:
            self.combobox_ip.current(0)
 

 

    def hacer_ping_dns(self):
        threading.Thread(target=self.realizar_ping, args=(True,)).start()
   
   
    def hacer_ping(self):
        threading.Thread(target=self.realizar_ping, args=(False,)).start()
 
    def ping_gateways(self):
 
        wait_window = self.mostrar_mensaje_espera("Realizando ping a gateways...")
        self.resultado_ping_texto.delete(1.0, tk.END)
        gateways = self.obtener_gateway()
 
        try:
            for interfaz, gateway in gateways.items():
                resultado = subprocess.run(["ping", "-n", "10", gateway], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                salida_filtrada = self.filtrar_salida_ping(resultado.stdout)
                self.resultado_ping_texto.insert(tk.END, f"Ping al Gateway {gateway}:\n")
                self.resultado_ping_texto.insert(tk.END, salida_filtrada)
                self.resultado_ping_texto.insert(tk.END, "\n\n")
 
        except subprocess.TimeoutExpired:
            self.resultado_ping_texto.insert(tk.END, f"Tiempo de espera agotado para el gateway {gateway}.\n\n")
        except subprocess.CalledProcessError as e:
            self.resultado_ping_texto.insert(tk.END, f"Fallo al hacer ping al gateway {gateway}:\n{e.stderr}\n\n")
        except Exception as e:
            self.resultado_ping_texto.insert(tk.END, f"Error al hacer ping al gateway {gateway}: {str(e)}\n\n")
 
        finally:
        # Ocultar ventana de espera
            self.ocultar_mensaje_espera(wait_window)  
 
    def realizar_ping(self, es_dns):
        wait_window = self.mostrar_mensaje_espera("Realizando ping...")
 
        self.resultado_ping_texto.delete(1.0, tk.END)
 
        if es_dns:
            dns_servidores = self.obtener_dns()
            for adaptador, dns_list in dns_servidores.items():
                for ip in dns_list:
                    nombre_dominio = self.obtener_nombre_de_dominio(ip)
                    resultado = subprocess.run(['ping', '-n', '10', ip], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    salida_filtrada = self.filtrar_salida_ping(resultado.stdout)
                    self.resultado_ping_texto.insert(tk.END, f"Ping hacia {nombre_dominio} ({ip}):\n")
                    self.resultado_ping_texto.insert(tk.END, salida_filtrada)
                    self.resultado_ping_texto.insert(tk.END, "\n\n")
        else:
            ip = self.entrada_ip_manual.get().strip()
            if not ip:
                nombre_seleccionado = self.combobox_ip.get()
                ip = self.diccionario_ips.get(nombre_seleccionado, "")
 
            if not ip:
                self.resultado_ping_texto.insert(tk.END, "Por favor, ingrese o seleccione una dirección IP válida.\n")
                self.ocultar_mensaje_espera(wait_window)
                return
 
            try:
                resultado = subprocess.run(["ping", "-n", "10", ip], capture_output=True, text=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                salida_filtrada = self.filtrar_salida_ping(resultado.stdout)
                self.resultado_ping_texto.insert(tk.END, f"Ping a {ip}:\n{salida_filtrada}\n")
            except subprocess.TimeoutExpired:
                self.resultado_ping_texto.insert(tk.END, "Tiempo de espera agotado: No se pudo establecer conexión con el host.\n")
            except subprocess.CalledProcessError as e:
                self.resultado_ping_texto.insert(tk.END, f"Fallo al hacer ping a {ip}:\n{e.stderr}\n")
            except Exception as e:
                self.resultado_ping_texto.insert(tk.END, f"Error al hacer ping a {ip}: {str(e)}\n")
 
            # Limpiar el campo de entrada IP manual despues de mostrar ping
            self.entrada_ip_manual.delete(0, tk.END)
 
        self.ocultar_mensaje_espera(wait_window)
 
    def filtrar_salida_ping(self, salida_ping):
        try:
            match_es = re.search(r'Paquetes: enviados = (\d+), recibidos = (\d+), perdidos = (\d+)', salida_ping, re.IGNORECASE)
            match_en = re.search(r'Packets: Sent = (\d+), Received = (\d+), Lost = (\d+)', salida_ping, re.IGNORECASE)
            if match_es:
                paquetes_enviados = match_es.group(1)
                paquetes_recibidos = match_es.group(2)
                perdida_paquetes = match_es.group(3)
            else:
                paquetes_enviados = paquetes_recibidos = perdida_paquetes = "No disponible"
 
            if not match_es and match_en:
                paquetes_enviados = match_en.group(1)
                paquetes_recibidos = match_en.group(2)
                perdida_paquetes = match_en.group(3)
 
            match_es_media = re.search(r'Media = (\d+)', salida_ping, re.IGNORECASE)
            match_en_media = re.search(r'Average = (\d+)', salida_ping, re.IGNORECASE)
 
            if match_es_media:
                tiempo_promedio = match_es_media.group(1) + "ms"
            else:
                tiempo_promedio = "No disponible"
 
            if not match_es_media and match_en_media:
                tiempo_promedio = match_en_media.group(1) + "ms"
 
            salida_filtrada = (
                f"Paquetes: enviados = {paquetes_enviados}, recibidos = {paquetes_recibidos}, perdidos = {perdida_paquetes}\n"
                f"Media = {tiempo_promedio}\n"
            )
 
            return salida_filtrada
 
        except Exception as e:
            return f"Error al filtrar el resultado del ping: {str(e)}"
   








    def ajustar_ancho_columnas(self):
       
        ancho_disponible = self.winfo_width()
        num_columnas = len(self.treeview_red["columns"])  
        ancho_columna = int(ancho_disponible / num_columnas)        
        for col in self.treeview_red["columns"]:
            self.treeview_red.column(col, width=ancho_columna)
 

    def actualizar_informacion_red(self):
        # Limpiar Treeview
        for item in self.treeview_red.get_children():
            self.treeview_red.delete(item)
 
        # Obtener información de red
        direcciones_interfaces_red = psutil.net_if_addrs()
        estadisticas_interfaces_red = psutil.net_if_stats()
 
        # Obtener gateways
        gateways = self.obtener_gateway()
 
        # Insertar filas en Treeview
        for interfaz, direcciones in direcciones_interfaces_red.items():
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
 
           
            etiqueta = "Conectado" if estado == "Conectado" else "Desconectado"
            self.treeview_red.insert("", "end", values=(interfaz, estado, mac, ipv4, gateway), tags=(etiqueta,))
 
       
        self.treeview_red.tag_configure("Conectado", foreground="green")
        self.treeview_red.tag_configure("Desconectado", foreground="red")
 
        self.cargar_direcciones_ip()

    #Funcion para copiar con click derecho
    def copiar_seleccion(self):
        selected_items = self.treeview_red.selection()
        if selected_items:
            selected_data = []
            for item in selected_items:
                item_data = self.treeview_red.item(item)['values']
                selected_data.append("\t".join(str(value) for value in item_data))
            data_to_copy = "\n".join(selected_data)
            pyperclip.copy(data_to_copy)
 
    #Menu para click derecho copiar
    def popup_menu(self, event):
        if self.treeview_red.selection():
            self.menu.post(event.x_root, event.y_root)
    
    def mostrar_nombre_pc(self):
        nombre_pc = socket.gethostname()
        self.nombre_pc.config(text=f"Nombre del PC: {nombre_pc}")
 
    # Mensaje de espera
    def mostrar_mensaje_espera(self, mensaje):
        wait_window = tk.Toplevel(self)
        wait_window.title("Por favor espere...")
        wait_window.resizable(False, False)
 
        screen_width = wait_window.winfo_screenwidth()
        screen_height = wait_window.winfo_screenheight()
        width = 200
        height = 100
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        wait_window.geometry(f"{width}x{height}+{x}+{y}")
       
        ttk.Label(wait_window, text=mensaje, padding=20).pack()
 
        wait_window.protocol("WM_DELETE_WINDOW", self.desactivar_cierre)
 
        return wait_window
 
    def ocultar_mensaje_espera(self, wait_window):
        wait_window.destroy()
 
    def desactivar_cierre(self):
        pass
    def comprobar_proxy(self):
        proxy = os.environ.get('http_proxy') or os.environ.get('https_proxy')
        if proxy:
            return proxy
 
        try:
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            configuracion_internet = winreg.OpenKey(registro, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
           
            proxy_enable, _ = winreg.QueryValueEx(configuracion_internet, "ProxyEnable")
            if proxy_enable:
                proxy_server, _ = winreg.QueryValueEx(configuracion_internet, "ProxyServer")
                return proxy_server
        except FileNotFoundError:
            return None
        except Exception as e:
            return f"No se pudo comprobar el proxy: {e}"
        return None
 
    def mostrar_informacion_proxy(self):
        self.texto_proxy.delete(1.0, tk.END)
 
        informacion_proxy = self.comprobar_proxy()
        if informacion_proxy:
            self.texto_proxy.insert(tk.END, informacion_proxy)
        else:
            self.texto_proxy.insert(tk.END, "No se encontró configuración de proxy.")
 
    def activar_proxy(self):
        try:
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            configuracion_internet = winreg.OpenKey(registro, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(configuracion_internet, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            messagebox.showinfo("Proxy Activado", "El proxy ha sido activado correctamente.")
            self.mostrar_informacion_proxy()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo activar el proxy: {e}")
 
    def desactivar_proxy(self):
        try:
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            configuracion_internet = winreg.OpenKey(registro, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(configuracion_internet, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            messagebox.showinfo("Proxy Desactivado", "El proxy ha sido desactivado correctamente.")
            self.mostrar_informacion_proxy()
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo desactivar el proxy: {e}") 
    #Crea pie de pagina
    def crear_pie_de_pagina(self):
        pie_de_pagina_frame= tk.Frame(self)
        pie_de_pagina_frame.pack(side=tk.BOTTOM, fill=tk.X)
 
        etiqueta_desarrollado_por = tk.Label(pie_de_pagina_frame, text="Desarrollado por SQUAD Ingenieria Sistema Operativo e Infraestructura BDB", font=("Arial", 10))        
        etiqueta_desarrollado_por.pack(side=tk.LEFT, padx=10)        
        # Etiqueta de versión        
        etiqueta_version = tk.Label(pie_de_pagina_frame, text="Versión 1.0.0", font=("Arial", 10))
        etiqueta_version.pack(side=tk.RIGHT, padx=10)      
 
if __name__ == "__main__":
    app = DiagnosticoRedApp()
    app.mainloop()