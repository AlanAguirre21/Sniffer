from scapy.all import get_if_list, get_if_hwaddr
import subprocess
import platform
import sys
import logging
import ctypes
import time
# Archivos del proyecto
from interface import Interface
from capture import Capture
from analisis import Analisis

logging.basicConfig(level=logging.INFO) #Cambiar a WARNING para forma silenciosa
logger = logging.getLogger(__name__)

'''
Comprobar si existe en el dispositivo "npcap" (preferentemente) no "wincap".
por cuestiones de funcionamiento de "scapy".
CMD: sc query npcap
'''

# Se necesitan permisos de administrador para poder ejecutar el programa:
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
'''
if not is_admin():
    logger.error("Este programa requiere permisos de administrador")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()
'''
# Modo promiscuo (Aún en desarrollo)
def promisc_mode(interfaz):
    print("Promiscuo")

if __name__ == '__main__':
    interface_obj = Interface()
    interfaces = interface_obj.get_all_interfaces()
    print(f"\nINTERFACES DISPONIBLES:\nEthernet: {interfaces['ethernet']}\nWi-Fi: {interfaces['wifi']}\nLoopback: {interfaces['loopback']}\n")
    
    # AGREGADO PARA LA FASE DE CAPTURA
    def select_interface():
        interfaz_elegida = input("Ingrese el tipo de interfaz que desea utilizar \npara la captura (Wi-Fi, Ethernet, Loopback): ").strip().lower().replace("-", "")
       
        if interfaz_elegida not in ["wifi", "ethernet", "loopback"]:
            print("\n[!] Tipo de interfaz no válido. Por favor, elija entre Wi-Fi, Ethernet o Loopback.")
            time.sleep(3)
            select_interface()
        elif interfaz_elegida == "wifi":
            selected_interface = interfaces["wifi"][0] if interfaces["wifi"] else None
            print("[*] Interfaz Wi-Fi seleccionada para la captura.")
            time.sleep(3)
        elif interfaz_elegida == "ethernet":
            selected_interface = interfaces["ethernet"][0] if interfaces["ethernet"] else None
            print("[*] Interfaz Ethernet seleccionada para la captura.")
            time.sleep(3)
        elif interfaz_elegida == "loopback":
            selected_interface = interfaces["loopback"][0] if interfaces["loopback"] else None
            print("[*] Interfaz Loopback seleccionada para la captura.")
            time.sleep(3)
        return selected_interface

    selected_interface = select_interface()
    if selected_interface:
        # Se llama al módulo de captura
        paquete = Capture.iniciar_captura(selected_interface)
        #print(paquete, '\n')
        if paquete:
            print("\n[*] Captura estática completada. Datos listos para la fase de análisis.")
            package_analisis = Analisis.analice_packet(paquete)
    else:
        print("\n[!] No se encontró ninguna interfaz activa para iniciar la captura.")
