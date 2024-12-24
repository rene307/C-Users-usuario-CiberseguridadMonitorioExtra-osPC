import os
import psutil
import socket
import time
from datetime import datetime

# Archivo log para registrar las actividades sospechosas
LOG_FILE = "intrusion_log.txt"

# Función para obtener la fecha y hora actual formateada
def get_current_time():
    return datetime.now().strftime("[%d/%m/%Y %H:%M:%S]")

# Función para registrar eventos en el archivo log
def log_event(event):
    with open(LOG_FILE, "a") as log:
        log.write(f"{get_current_time()} - {event}\n")

# Función para detectar procesos sospechosos
def detect_suspicious_processes():
    suspicious_keywords = ["keylogger", "hack", "malware", "spy", "virus"]
    print(f"{get_current_time()} - Monitoreando procesos activos...")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()
            if any(keyword in process_name for keyword in suspicious_keywords):
                event = f"Proceso sospechoso detectado: {proc.info['name']} (PID: {proc.info['pid']})"
                print(f"{get_current_time()} - {event}")
                log_event(event)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Función para detectar conexiones de red sospechosas
def detect_suspicious_connections():
    trusted_ips = ["127.0.0.1", "192.168."]  # IPs confiables
    print(f"{get_current_time()} - Monitoreando conexiones de red...")
    for conn in psutil.net_connections(kind='inet'):
        try:
            raddr = conn.raddr.ip if conn.raddr else None
            if raddr and not any(trusted in raddr for trusted in trusted_ips):
                event = f"Conexión sospechosa detectada: {raddr} (PID: {conn.pid})"
                print(f"{get_current_time()} - {event}")
                log_event(event)
        except (psutil.NoSuchProcess, AttributeError):
            pass

# Función principal para monitorear la PC
def monitor_intrusions():
    print(f"{get_current_time()} - Iniciando el monitor de intrusos...")
    log_event("Monitor de intrusos iniciado.")
    while True:
        detect_suspicious_processes()
        detect_suspicious_connections()
        time.sleep(5)  # Monitorear cada 10 segundos

if __name__ == "__main__":
    try:
        monitor_intrusions()
    except KeyboardInterrupt:
        print(f"{get_current_time()} - Monitor detenido por el usuario.")
        log_event("Monitor detenido por el usuario.")

