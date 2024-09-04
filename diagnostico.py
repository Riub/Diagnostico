import tkinter as tk
from tkinter import ttk, messagebox, Menu
import socket
import platform
import psutil
import pyperclip
import subprocess

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Aplicación de Diagnóstico")
        self.geometry("800x600")
        self.configure(bg="#F3F4F6")

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
        self.button_red = tk.Button(self.sidebar, text="Diagnóstico de Red", command=self.show_red_diagnosis, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_red.pack(fill='x')

        self.button_pc = tk.Button(self.sidebar, text="Diagnóstico de PC", command=self.show_pc_diagnosis, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_pc.pack(fill='x')

        # Contenido inicial
        self.show_initial_message()

    def show_initial_message(self):
        # Limpiar el contenido actual
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        # Mensaje inicial
        initial_message = "Por favor, seleccione un diagnóstico desde la barra lateral."
        label = tk.Label(self.content_frame, text=initial_message, font=("Segoe UI", 18), bg="#F3F4F6")
        label.pack(pady=20)

    

    def show_red_diagnosis(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

         # Asegúrate de que el nombre del PC esté actualizado
        nombre_pc = socket.gethostname() 
        title_text = f"Diagnóstico de Red\nNombre del PC: {nombre_pc}"
        label = tk.Label(self.content_frame, text=title_text, font=("Segoe UI", 18), bg="#F3F4F6")
        label.pack(pady=20)


        self.treeview_red = ttk.Treeview(self.content_frame, columns=("Interfaz", "Estado", "MAC", "IPv4", "Gateway"), show="headings")
        self.treeview_red.heading("Interfaz", text="Interfaz")
        self.treeview_red.heading("Estado", text="Estado")
        self.treeview_red.heading("MAC", text="MAC")
        self.treeview_red.heading("IPv4", text="IPv4")
        self.treeview_red.heading("Gateway", text="Gateway")
        self.treeview_red.pack(fill=tk.X, pady=5)     

        # Crear el menú contextual para Copiar 
        self.menu = Menu(self, tearoff=0)
        self.menu.add_command(label="Copiar", command=self.copiar_seleccion)
        self.treeview_red.bind("<Button-3>", self.popup_menu)



       # Ajustar el ancho de las columnas
        self.treeview_red.bind("<Configure>", self.ajustar_ancho_columnas)

        self.actualizar_informacion_red()

        
    def ajustar_ancho_columnas(self, event=None):
        ancho_total = self.treeview_red.winfo_width()
        num_columnas = len(self.treeview_red["columns"])
        ancho_columna = int(ancho_total / num_columnas)
        for col in self.treeview_red["columns"]:
            self.treeview_red.column(col, width=ancho_columna)     


    def show_pc_diagnosis(self):
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
        treeview.pack(fill='x', pady=5, expand=True)

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
            usage = psutil.disk_usage(partition.mountpoint)
            total_disk = usage.total / (1024 ** 3)  # Convertir a GB
            free_disk = usage.free / (1024 ** 3)  # Convertir a GB
            disk_info.append((partition.device, total_disk, free_disk))
        return disk_info
    
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

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
