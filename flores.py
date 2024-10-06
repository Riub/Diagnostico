import re
import socket

def obtener_numero_oficina():
    # Obtener el hostname
    hostname = socket.gethostname()

    # Definir la expresión regular para extraer el número de oficina
    pattern = r'^[a-zA-Z]{2}(\d{4})\d{2}$'

    # Buscar el patrón en el hostname
    match = re.match(pattern, hostname)

    if match:
        return match.group(1)  # Retornar el número de oficina
    else:
        return None  # Retornar None si no coincide con el formato

# Uso de la función
numero_oficina = obtener_numero_oficina()
if numero_oficina:
    print(f"Número de oficina: {numero_oficina}")
else:
    print("El hostname no tiene el formato esperado.")
