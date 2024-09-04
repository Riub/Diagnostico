import tkinter as tk
from tkinter import ttk, messagebox, Menu, scrolledtext
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

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aplicación de Diagnóstico")
        self.geometry("800x600")
        self.configure(bg="#F3F4F6")

        self.bg_color = "#F3F4F6"  # Define el color de fondo
        self.desarrollado_por = "Tu Nombre"
        self.version = "1.0.0"

        # Crear el contenedor principal
        self.main_frame = tk.Frame(self, bg="#FFFFFF")
        self.main_frame.pack(fill='both', expand=True)

        # Crear la barra lateral
        self.sidebar = tk.Frame(self.main_frame, bg="#2E3A45", width=200, height=600)
        self.sidebar.pack(side='left', fill='y')

        # Crear marco principal
        self.main_area = tk.Frame(self.main_frame, bg="#ecf0f1")
        self.main_area.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Crear el contenedor para el contenido
        self.content_frame = tk.Frame(self.main_area, bg="#F3F4F6")
        self.content_frame.pack(side='top', fill='both', expand=True)

        # Botones en la barra lateral
        self.button_red = tk.Button(self.sidebar, text="Info PC", command=self.diag_pc, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_red.pack(fill='x')
        
        self.button_red = tk.Button(self.sidebar, text="Info Interfaces de Red", command=self.diag_interfaces, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_red.pack(fill='x')
        
        self.button_pc = tk.Button(self.sidebar, text="Info Proxy", command=self.show_proxy, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_pc.pack(fill='x')

        self.button_pc = tk.Button(self.sidebar, text="Varios", command=self.create_power_shell_ui, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_pc.pack(fill='x')

        # Contenido inicial
        self.mensaje_inicial()
 
    def mensaje_inicial(self):
        # Limpiar el contenido actual
        for widget in self.content_frame.winfo_children():
            widget.destroy()
       
        # Mensaje inicial
        initial_message = "Por favor, seleccione un diagnóstico desde la barra lateral."
        label = tk.Label(self.content_frame, text=initial_message, font=("Segoe UI", 18), bg="#F3F4F6")
        label.pack(pady=20)

 
    def diag_pc(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
 
         # Asegúrate de que el nombre del PC esté actualizado
        nombre_pc = socket.gethostname()
        title_text = f"Diagnóstico de PC\nNombre del PC: {nombre_pc}"
        label = tk.Label(self.content_frame, text=title_text, font=("Segoe UI", 18), bg="#F3F4F6")
        label.pack(pady=20)
 
        # Sistema Operativo
        tk.Label(self.content_frame, text="Sistema Operativo:", font=("Segoe UI", 14, 'bold'), bg="#F3F4F6").pack(anchor='w', padx=10)
        tk.Label(self.content_frame, text=self.windows_version(), font=("Segoe UI", 12), bg="#F3F4F6").pack(anchor='w', padx=10)
 
        # Memoria RAM
        tk.Label(self.content_frame, text="Memoria RAM:", font=("Segoe UI", 14, 'bold'), bg="#F3F4F6").pack(anchor='w', padx=10)
        total_ram, available_ram = self.ram_info()
        tk.Label(self.content_frame, text=f"Total: {total_ram:.2f} GB, Disponible: {available_ram:.2f} GB", font=("Segoe UI", 12), bg="#F3F4F6").pack(anchor='w', padx=10)
 
        # Crear un Treeview para la información del disco
        treeview_frame = tk.Frame(self.content_frame, bg="#F3F4F6")
        treeview_frame.pack(fill='both', expand=True, pady=10)
 
        treeview = ttk.Treeview(treeview_frame, columns=("Unidad", "Total", "Libre"), show='headings')
        treeview.pack(fill='x', pady=3, expand=True)
 
        treeview.heading("Unidad", text="Unidad")
        treeview.heading("Total", text="Total (GB)")
        treeview.heading("Libre", text="Libre (GB)")
 
        treeview.column("Unidad", anchor=tk.CENTER, width=100)
        treeview.column("Total", anchor=tk.CENTER, width=100)
        treeview.column("Libre", anchor=tk.CENTER, width=100)
 
        # Insertar la información del disco en el Treeview
        disk_info = self.get_disk_info()
        for disk in disk_info:
            treeview.insert("", "end", values=(disk[0], f"{disk[1]:.2f}", f"{disk[2]:.2f}"))

        delete_temp_button  = tk.Button(self.content_frame, text="Eliminar Archivos Temporales", command=self.eliminar_archivos_temporales, bg="#4A4A4A", fg="white")
        delete_temp_button.pack(pady=20)
    
 
 
 
########################################################################################################
# Funciones Diagnostico PC
 
    def windows_version(self):
        version = platform.version()
        release = platform.release()
        return f"Windows {release} (versión {version})"
   
    def ram_info(self):
        ram = psutil.virtual_memory()
        total_ram = ram.total / (1024 ** 3)  # Convertir a GB
        available_ram = ram.available / (1024 ** 3)  # Convertir a GB
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
   
    def eliminar_archivos_temporales(self):
        temp_dirs = [
            os.environ.get('TEMP'),
            os.environ.get('TMP'),
            os.path.join(os.environ.get('SystemRoot'), 'Temp'),
            os.path.join(os.environ.get('USERPROFILE'), 'AppData', 'Local', 'Temp')
        ]

        archivos_eliminados = 0
        carpetas_eliminadas = 0

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

        messagebox.showinfo("Completado", f"Eliminados {archivos_eliminados} archivos temporales.\nEliminadas {carpetas_eliminadas} carpetas temporales.")





######################################################################################################################
# Varios  
 
 
    def copiar_seleccion(self):
        selected_items = self.treeview_red.selection()
        if selected_items:
            selected_data = []
            for item in selected_items:
                item_data = self.treeview_red.item(item)['values']
                selected_data.append("\t".join(str(value) for value in item_data))
            data_to_copy = "\n".join(selected_data)
            pyperclip.copy(data_to_copy)
 
    # Menú para click derecho copiar
    def popup_menu(self, event):
        if self.treeview_red.selection():
            self.menu.post(event.x_root, event.y_root)

####################################################################################################################################################
# Funciones para El diagnostico de red
#  
    def diag_interfaces(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        bg_color = "#F3F4F6"
        # Asegúrate de que el nombre del PC esté actualizado
        nombre_pc = socket.gethostname()
        title_text = f"Diagnóstico de Red\nNombre del PC: {nombre_pc}"
        label = tk.Label(self.content_frame, text=title_text, font=("Segoe UI", 18), bg=bg_color)
        label.pack(pady=20)

        # Treeview para información de la red
        self.treeview_red = ttk.Treeview(self.content_frame, columns=("Interfaz", "Estado", "MAC", "IPv4", "Gateway"), show="headings")
        self.treeview_red.heading("Interfaz", text="Interfaz")
        self.treeview_red.heading("Estado", text="Estado")
        self.treeview_red.heading("MAC", text="MAC")
        self.treeview_red.heading("IPv4", text="IPv4")
        self.treeview_red.heading("Gateway", text="Gateway")
        
        num_filas = len(self.treeview_red.get_children())
        altura = min(max(5, num_filas), 10)
        self.treeview_red.configure(height=altura)

        for col in self.treeview_red["columns"]:
            self.treeview_red.column(col, width=tkfont.Font().measure(col), stretch=tk.NO)

        self.treeview_red.pack(fill=tk.X, pady=3)

        # Crear el menú contextual para Copiar
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copiar", command=self.copiar_seleccion)
        self.treeview_red.bind("<Button-3>", self.popup_menu)

        self.treeview_red.bind("<Configure>", self.ajustar_ancho_columnas)

        # Frame para los DNS
        self.frame_dns = tk.Frame(self.content_frame, bg=bg_color)
        self.frame_dns.pack(fill=tk.X, pady=(10, 10))

        self.etiqueta_dns = tk.Label(self.frame_dns, text="Servidores DNS Configurados:", font=("Segoe UI", 14, 'bold'), bg=bg_color)
        self.etiqueta_dns.pack(anchor='w', padx=(0, 10))

        self.texto_dns = tk.Text(self.frame_dns, height=3, font=("Segoe UI", 12))
        self.texto_dns.pack(fill='x', expand=True)

        # Frame para controles de ping y botones
        self.frame_ping_y_botones = tk.Frame(self.content_frame, bg=bg_color)
        self.frame_ping_y_botones.pack(fill='x', padx=10, pady=10)

        # Frame para controles de ping
        self.frame_controles_ping = tk.Frame(self.frame_ping_y_botones, bg=bg_color)
        self.frame_controles_ping.pack(side=tk.LEFT, padx=(0, 20))

        self.etiqueta_ip_lista = tk.Label(self.frame_controles_ping, text="Seleccionar dirección IP:", font=("Segoe UI", 12), bg=bg_color)
        self.etiqueta_ip_lista.grid(row=0, column=0, pady=5, sticky="w")

        self.combobox_ip = ttk.Combobox(self.frame_controles_ping, width=25, state="readonly")
        self.combobox_ip.grid(row=1, column=0, pady=5, sticky="w")

        self.etiqueta_ip_manual = tk.Label(self.frame_controles_ping, text="Ingresar dirección IP manualmente:", font=("Segoe UI", 12), bg=bg_color)
        self.etiqueta_ip_manual.grid(row=2, column=0, pady=5, sticky="w")

        self.entrada_ip_manual = tk.Entry(self.frame_controles_ping, width=25)
        self.entrada_ip_manual.grid(row=3, column=0, pady=5, sticky="w")

        self.boton_ping = tk.Button(self.frame_controles_ping, text="Ping", command=self.hacer_ping, bg="#4A4A4A", fg="white")
        self.boton_ping.grid(row=3, column=1, pady=5, padx=(10, 0), sticky="e")

        self.boton_ping_gtwy = tk.Button(self.frame_controles_ping, text="Ping Hacia Gateway", command=self.ping_gateways, bg="#4A4A4A", fg="white")
        self.boton_ping_gtwy.grid(row=4, column=0, pady=10, sticky="w")

        self.boton_ping_gtwy = tk.Button(self.frame_controles_ping, text="Ping Hacia DNS", command=self.hacer_ping_dns, bg="#4A4A4A", fg="white")
        self.boton_ping_gtwy.grid(row=5, column=0, pady=10, sticky="w")

        # Frame para mostrar resultados de ping
        self.frame_ping = tk.Frame(self.frame_ping_y_botones, bg=bg_color)
        self.frame_ping.pack(side=tk.LEFT, fill='both', expand=True)

        self.resultado_ping_texto = tk.Text(self.frame_ping, height=10, font=("Segoe UI", 12))
        self.resultado_ping_texto.pack(fill='both', expand=True)

        # Configurar la expansión de los widgets en la ventana
        self.content_frame.rowconfigure(1, weight=1)
        self.content_frame.rowconfigure(3, weight=1)
        self.content_frame.columnconfigure(0, weight=1)
        self.content_frame.columnconfigure(1, weight=1)
        self.frame_ping_y_botones.columnconfigure(1, weight=1)

        # Actualizar información de red
        self.actualizar_informacion_red()

        # Agregar el pie de página


    def ajustar_ancho_columnas(self, event=None):
        ancho_total = self.treeview_red.winfo_width()
        num_columnas = len(self.treeview_red["columns"])
        ancho_columna = int(ancho_total / num_columnas)
        for col in self.treeview_red["columns"]:
            self.treeview_red.column(col, width=ancho_columna)    


          
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

                # Llamar a las funciones para cargar la información inicial
        self.cargar_direcciones_ip()
        self.mostrar_dns()

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

####################################################################################################################################################
# Funciones Proxy
#
    def show_proxy(self):
        # Limpiar el contenido actual
        for widget in self.content_frame.winfo_children():
            widget.destroy()

        # Encabezado de la sección
        header_label = tk.Label(self.content_frame, text="Configuración de Proxy", font=("Segoe UI", 22, 'bold'), bg="#F3F4F6", fg="#2E3A45")
        header_label.pack(pady=20)

        # Inicializar variables para el servidor proxy y excepciones
        proxy_server = proxy_bypass = ""
        proxy_enabled = True

        try:
            # Abrir la clave del registro
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            proxy_server = winreg.QueryValueEx(key, "ProxyServer")[0]
            proxy_bypass = winreg.QueryValueEx(key, "ProxyOverride")[0]
            proxy_enable = winreg.QueryValueEx(key, "ProxyEnable")[0]
            winreg.CloseKey(key)
            
            if proxy_enable == 0:
                # Proxy está desactivado
                proxy_server = "Proxy desactivado"
                proxy_enabled = False

        except FileNotFoundError:
            messagebox.showwarning("Advertencia", "No se encontró configuración de proxy en el registro.")
            proxy_server = "No hay configuración de proxy."
            proxy_enabled = False
        except Exception as e:
            messagebox.showerror("Error", f"Error al leer la configuración del proxy: {e}")
            return

        # Configuración del servidor proxy
        tk.Label(self.content_frame, text="Servidor Proxy:", font=("Segoe UI", 14, 'bold'), bg="#F3F4F6").pack(anchor='w', padx=10)
        self.proxy_server_entry = tk.Entry(self.content_frame, width=50)
        self.proxy_server_entry.insert(0, proxy_server)
        self.proxy_server_entry.pack(anchor='w', padx=10)

        if proxy_enabled:
            # Excepciones del proxy
            tk.Label(self.content_frame, text="Excepciones Proxy:", font=("Segoe UI", 14, 'bold'), bg="#F3F4F6").pack(anchor='w', padx=10)

            excepciones_frame = tk.Frame(self.content_frame, bg="#F3F4F6")
            excepciones_frame.pack(fill='x', pady=5)

            self.texto_excepciones = tk.Text(excepciones_frame, height=10, width=50, font=("Segoe UI", 12), wrap="word")
            self.texto_excepciones.insert(tk.END, proxy_bypass)
            self.texto_excepciones.pack(side='left', fill='both', expand=True)

            scrollbar = tk.Scrollbar(excepciones_frame, command=self.texto_excepciones.yview)
            scrollbar.pack(side='right', fill='y')
            self.texto_excepciones.config(yscrollcommand=scrollbar.set)

        # Botones para activar y desactivar el proxy
        buttons_frame = tk.Frame(self.content_frame, bg="#F3F4F6")
        buttons_frame.pack(pady=10)

        self.boton_activar = tk.Button(buttons_frame, text="Activar Proxy", command=self.activar_proxy, bg="#4A4A4A", fg="white")
        self.boton_activar.grid(row=0, column=0, padx=10)

        self.boton_desactivar = tk.Button(buttons_frame, text="Desactivar Proxy", command=self.desactivar_proxy, bg="#4A4A4A", fg="white")
        self.boton_desactivar.grid(row=0, column=1, padx=10)

        self.boton_actualizar = tk.Button(buttons_frame, text="Actualizar Excepciones", command=self.actualizar_excepciones, bg="#4A4A4A", fg="white")
        self.boton_actualizar.grid(row=0, column=2, padx=10)



    def activar_proxy(self):
        try:
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            configuracion_internet = winreg.OpenKey(registro, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(configuracion_internet, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            messagebox.showinfo("Proxy Activado", "El proxy ha sido activado correctamente.")
            self.show_proxy()  # Actualizar la vista con la configuración actual del proxy
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo activar el proxy: {e}")
 
    def desactivar_proxy(self):
        try:
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            configuracion_internet = winreg.OpenKey(registro, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
            winreg.SetValueEx(configuracion_internet, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            messagebox.showinfo("Proxy Desactivado", "El proxy ha sido desactivado correctamente.")
            self.show_proxy()  # Actualizar la vista con la configuración actual del proxy
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo desactivar el proxy: {e}")
 
 
 
    def actualizar_excepciones(self):
        excepciones = self.texto_excepciones.get("1.0", tk.END).strip()  # Obtener el texto del cuadro de texto
       
        # Verificar si "<local>" está presente
        if "<local>" not in excepciones:
            excepciones += "; <local>"  # Agregar "<local>" si no está presente
       
        try:
            # Conectar al registro de Windows
            registro = winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER)
            configuracion_internet = winreg.OpenKey(registro, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_WRITE)
           
            # Actualizar las excepciones en el registro
            winreg.SetValueEx(configuracion_internet, "ProxyOverride", 0, winreg.REG_SZ, excepciones)
            winreg.CloseKey(configuracion_internet)
           
            # Mostrar mensaje de éxito
            messagebox.showinfo("Excepciones Actualizadas", "Las excepciones del proxy han sido actualizadas correctamente.")
        except Exception as e:
            # Mostrar mensaje de error
            messagebox.showerror("Error", f"No se pudieron actualizar las excepciones del proxy: {e}")
 
#################################################################################################################################################################################################
# Botones de varios
#            


    def create_power_shell_ui(self):
        # Limpiar el contenido actual del frame
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Título
        title_text = "Comprobaciones Varias"
        title_label = tk.Label(self.content_frame, text=title_text, font=("Segoe UI", 18), bg="#F3F4F6")
        title_label.pack(pady=20)
        
        # Frame para los botones
        button_frame = tk.Frame(self.content_frame, bg="#F3F4F6")
        button_frame.pack(pady=10, fill='x')
        
        # Botón para revisión de drivers
        self.create_button(button_frame, "Revisión de Drivers", self.check_drivers)
        
        # Botón para Microsoft Teams
        self.create_button(button_frame, "Microsoft Teams", self.check_teams)
        
        # Botón para comprobación de paginación
        self.create_button(button_frame, "Comprobación de Paginación", self.check_pagination)
        
        # Botón para Agente de Aranda
        self.create_button(button_frame, "Agente de Aranda", self.check_aranda)
        
        # Frame para mostrar resultados
        self.result_frame = tk.Frame(self.content_frame, bg="#F3F4F6")
        self.result_frame.pack(pady=10, fill='both', expand=True)
        
        # Área de texto para mostrar resultados
        self.result_text = scrolledtext.ScrolledText(self.result_frame, wrap=tk.WORD, font=("Segoe UI", 12))
        self.result_text.pack(fill='both', expand=True)


       


    def create_button(self, parent, text, command):
        button = tk.Button(parent, text=text, command=command, bg="#4A4A4A", fg="white")
        button.pack(side=tk.LEFT, padx=5)
        
    def check_drivers(self):
        command = 'powershell -Command "Get-WmiObject Win32_PNPEntity | Where-Object{$_.ConfigManagerErrorCode -ne 0} | Select Name, DeviceID"'
        self.execute_command(command, "Se revisó y no hay drivers para actualizar.")
    
    def check_teams(self):
        command = 'powershell -Command "Get-WmiObject win32_operatingsystem | select osarchitecture"'
        self.execute_command(command)

    def check_pagination(self):
        command = 'powershell -Command "gwmi Win32_ComputerSystem | fl AutomaticManagedPagefile; Get-CimInstance Win32_PageFileUsage | fl *"'
        self.execute_command(command)

    def check_aranda(self):
        command = 'powershell -Command "Get-Process SentinelFM | Format-List *; Stop-Process -Name \\"SentinelFM\\""'
        self.execute_command(command)

    def execute_command(self, command, success_message=None):
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        self.result_text.delete(1.0, tk.END)  # Limpiar el texto actual
        
        if result.stdout:
            self.result_text.insert(tk.END, result.stdout)  # Mostrar la salida del comando
        else:
            self.result_text.insert(tk.END, success_message if success_message else "El comando se ejecutó, pero no hay resultados.")

        if result.stderr:
            self.result_text.insert(tk.END, "\nError:\n" + result.stderr)  # Mostrar errores si hay


if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()