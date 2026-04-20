from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
import subprocess

class Interface:
    # En windows
    def get_interfaces():
        # Obtener nombres de Windows
        resultado = subprocess.run(
            ['powershell', '-Command', 'Get-NetAdapter | Select-Object Name, MacAddress'],
            capture_output=True,
            text=True
        )
        
        # Crear mapeo por MAC (que es único)
        mapeo_mac_nombre = {}
        lineas = resultado.stdout.split('\n')[3:]
        
        for linea in lineas:
            if linea.strip():
                partes = linea.split()
                if len(partes) >= 2:
                    nombre = partes[0]
                    mac = partes[1]
                    mapeo_mac_nombre[mac] = nombre 

        # Obtener UUIDs
        interfaceEthernet = []
        interfaceWifi = []
        interfaceLoopback = []
        discarded = []
        
        uuids = get_if_list()
        for uuid in uuids:
            try:
                mac = get_if_hwaddr(uuid).replace(':', '-').upper()
                try:
                    ip = get_if_addr(uuid)
                except:
                    ip = '0.0.0.0'
                    
                nombre = mapeo_mac_nombre.get(mac, "DESCONOCIDO")

                # Interfaces descartadas
                if ip == '0.0.0.0':
                    discarded.append(uuid)
                    print("Interfaz inactiva o virtual. No útil")
                    
                # Clasificación útil
                elif nombre.lower() == "ethernet":
                    interfaceEthernet.append(uuid)
                elif nombre.lower() in ["wi-fi", "wireless"]:
                    interfaceWifi.append(uuid)
                elif ip and ip.startswith("127"):
                    interfaceLoopback.append(uuid)

            except Exception as e:
                print(f"Error: {e}")
                
        #print(f'Wi-Fi {interfaceWifi}\n', f'Ethernet {interfaceEthernet}\n', f'Loopback {interfaceLoopback}\n', f'Discarded {discarded}')
        return interfaceWifi, interfaceEthernet, interfaceLoopback
 
#Interface.get_interfaces()