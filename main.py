from scapy.all import conf, get_if_list, get_if_hwaddr
import subprocess
import platform
import sys
# Archivos del proyecto
from interface import Interface

# Comprobar si existe en el dispositivo "npcap" (preferentemente) no "wincap".
# por cuestiones de funcionamiento de "scapy".
# CMD: sc query npcap
    
def promisc_mode(interfaz):
    print("Promiscuo")

if __name__ == '__main__':
    interfaceWifi, interfaceEthernet, interfaceLoopback = Interface.get_interfaces()
    print(f'Wi-Fi {interfaceWifi}\n', f'Ethernet {interfaceEthernet}\n', f'Loopback {interfaceLoopback}\n')
    
    # Ejecución preliminar del programa.