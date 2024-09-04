import tkinter as tk
from tkinter import ttk
import socket

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

        # Etiqueta para mostrar el nombre del PC
        self.nombre_pc = tk.Label(self.main_area, text="", font=("Arial", 12))
        self.nombre_pc.pack(pady=10)

        # Botones en la barra lateral
        self.button_red = tk.Button(self.sidebar, text="Diagnóstico de Red", command=self.show_red_diagnosis, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_red.pack(fill='x')

        self.button_pc = tk.Button(self.sidebar, text="Diagnóstico de PC", command=self.show_pc_diagnosis, bg="#4A4A4A", fg="white", padx=20, pady=10)
        self.button_pc.pack(fill='x')

        # Crear el contenedor para el contenido
        self.content_frame = tk.Frame(self.main_area, bg="#F3F4F6")
        self.content_frame.pack(side='top', fill='both', expand=True)

        # Contenido inicial
        self.show_red_diagnosis()
        self.mostrar_nombre_pc()

    def show_red_diagnosis(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
       
        label = tk.Label(self.content_frame, text="Diagnóstico de Red", font=("Segoe UI", 18), bg="#F3F4F6")
        label.pack(pady=20)

        # Aquí puedes agregar widgets específicos para Diagnóstico de Red
        tk.Label(self.content_frame, text="Ingrese la IP para diagnóstico:", font=("Segoe UI", 12), bg="#F3F4F6").pack(pady=5)
        self.ip_entry = tk.Entry(self.content_frame)
        self.ip_entry.pack(pady=5)

        self.diagnostico_button = tk.Button(self.content_frame, text="Iniciar Diagnóstico", command=self.iniciar_diagnostico_red, bg="#4A4A4A", fg="white")
        self.diagnostico_button.pack(pady=20)

        self.mostrar_nombre_pc()

    def show_pc_diagnosis(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()
        
        label = tk.Label(self.content_frame, text="Diagnóstico de PC", font=("Segoe UI", 18), bg="#F3F4F6")
        label.pack(pady=20)

        # Aquí puedes agregar widgets específicos para Diagnóstico de PC

        self.mostrar_nombre_pc()

    def iniciar_diagnostico_red(self):
        ip = self.ip_entry.get()
        if not ip:
            tk.messagebox.showwarning("Entrada Vacía", "Por favor, ingrese una dirección IP.")
            return
        
        # Aquí puedes agregar el código real para diagnosticar la red
        tk.messagebox.showinfo("Diagnóstico de Red", f"Diagnóstico iniciado para {ip}.")

    def mostrar_nombre_pc(self):
        nombre_pc = socket.gethostname()
        self.nombre_pc.config(text=f"Nombre del PC: {nombre_pc}")

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
