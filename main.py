from scapy.all import conf, get_if_list, get_if_hwaddr
import subprocess
import platform
import sys
# Archivos del proyecto
from interface import Interface
from capture import Capture

# Comprobar si existe en el dispositivo "npcap" (preferentemente) no "wincap".
# por cuestiones de funcionamiento de "scapy".
# CMD: sc query npcap
    
def promisc_mode(interfaz):
    print("Promiscuo")

if __name__ == '__main__':
    interfaceWifi, interfaceEthernet, interfaceLoopback = Interface.get_interfaces()
    print(f'Wi-Fi {interfaceWifi}\n', f'Ethernet {interfaceEthernet}\n', f'Loopback {interfaceLoopback}\n')
    
    # Ejecución preliminar del programa.

  
    # AGREGADO PARA LA FASE DE CAPTURA
    interfaz_elegida = None
    if interfaceWifi:
        interfaz_elegida = interfaceWifi[0]
    elif interfaceEthernet:
        interfaz_elegida = interfaceEthernet[0]
    elif interfaceLoopback:
        interfaz_elegida = interfaceLoopback[0]
        
    if interfaz_elegida:
        # Se llama al módulo de captura
        datos_crudos = Capture.iniciar_captura(interfaz_elegida)
        
        if datos_crudos:
            print("\n[*] Captura estática completada. Datos listos para la fase de análisis.")
    else:
        print("\n[!] No se encontró ninguna interfaz activa para iniciar la captura.")
