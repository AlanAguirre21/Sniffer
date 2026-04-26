from scapy.all import get_if_list, get_if_hwaddr
import wmi
import logging
import re

logging.basicConfig(level=logging.INFO) #Cambiar a WARNING para forma silenciosa
logger = logging.getLogger(__name__)

def is_valid_mac(mac):
    if not mac:
        return False
    pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return re.match(pattern, mac) is not None

def get_interface_type(nic):
    connection_id = (nic.NetConnectionID or "").lower().replace(" ", "").replace("-", "").replace(".", "")
    name = (nic.Name or "").lower().replace(" ", "").replace("-", "").replace(".", "")
    description = (nic.Description or "").lower().replace(" ", "").replace("-","").replace(".", "")
    #ip_address = (nic.IPAddress[0] if nic.IPAddress else "").lower().replace(" ", "")
    
    wifi_patterns = ["wifi", "wireless", "80211", "wlan"]
    if any(p in connection_id or p in name for p in wifi_patterns):
        return "wifi"
    
    eth_patterns = ["ethernet", "lan", "gigabit"]
    if any(p in connection_id or p in name for p in eth_patterns):
        return "ethernet"

    # Respaldo
    if any(p in description for p in wifi_patterns):
        return "wifi"
    if any(p in description for p in eth_patterns):
        return "ethernet"
    
    # Loopback
    if any(p in name for p in ["loopback", "lo"]):
    #if any(p in name for p in ["loopback", "lo"] or ip_address.split(".")[0] == "127"):
        return "loopback"
    
    # Otros tipos
    if any(p in name for p in ["vpn", "virtual", "tap", "tun", "vmware", "hyperv"]):
        return "virtual"
    
    return "DESCONOCIDO"

class Interface:
    def __init__(self):
        self.interfacesEthernet = []
        self.interfacesWifi = []
        self.interfacesLoopback = []
        self.interfacesDiscarded = []
        
        self.mapping = self.make_mapping()
    
    @staticmethod
    def make_mapping():
        try:
            c = wmi.WMI()
            mapping = {}
            i = 0

            for nic in c.Win32_NetworkAdapter():
                if not nic.NetEnabled:
                    logger.debug(f"Interfaz deshabilitada: {nic.Name}")
                    continue
                
                mac = nic.MACAddress
                
                if not is_valid_mac(mac):
                    logger.warning(f"MAC inválida para {nic.Name}: {mac}")
                    continue
                
                interface_type = get_interface_type(nic)
                
                if mac in mapping:
                    logger.warning(f"MAC duplicada: {mac}")
                  
                mapping[i] = {
                    "Nombre": nic.Name,
                    "MAC": mac,
                    "Tipo": interface_type,
                    "Activa": nic.NetEnabled,
                    "Fisica": nic.PhysicalAdapter
                    }
                logger.info(f"{i} ({nic.Name}): {mapping[i]}")
                i+=1  
            return mapping
        except wmi.x_wmi as e:
            logger.error(f"Error al acceder a WMI: {e}")
        except Exception as e:   
            logger.error(f"Error inesperado make_mapping: {e}")
            
    def get_interfaces_by_type(self, interface_type):
        try:
            mapping = self.mapping
            uuids = get_if_list()
            
            if not mapping:
                logger.warning("El mapping está vacío.")
                return []
            
            if not uuids:
                logger.warning("No se encontraron interfaces de red.")
                return []
            interfaces = []
            for i in mapping:
                if mapping[i]['Tipo'] == interface_type and mapping[i]['Activa']:
                    macMapping = mapping[i]['MAC']
                    
                    found = False
                    for uuid in uuids:
                        try:
                            mac = get_if_hwaddr(uuid).upper()
                            if mac == macMapping:
                                interfaces.append(uuid)
                                logger.info(f"Interfaz {interface_type} agregada: {uuid}")
                                found = True
                                break
                        except Exception as e:
                            logger.debug(f"Error al comparar MAC para {uuid}: {e}")
                            continue
                    if not found:
                        logger.debug(f"No se encontró interfaz para MAC: {macMapping}")
                        
            if not interfaces:
                logger.warning(f"No se encontraron interfaces {interface_type} activas.")
                return []
            logger.info(f"Se encontraron {len(interfaces)} interfaces {interface_type}.")
            return interfaces
        except Exception as e:
                logger.error(f"Error inesperado en get_interfaces_by_type: {e}")
                return []
    
    def get_all_interfaces(self):
        self.interfacesEthernet = self.get_interfaces_by_type("ethernet")
        self.interfacesWifi = self.get_interfaces_by_type("wifi")
        self.interfacesLoopback = self.get_interfaces_by_type("loopback")
        
        logger.info("Interfaces obtenidas correctamente")
        return {
            "ethernet": self.interfacesEthernet,
            "wifi": self.interfacesWifi,
            "loopback": self.interfacesLoopback
        }
        
    '''MAPING CON POWERSHELL
    def mac_mapping(self):
        mapping = {}
        # Nombres de las interfaces
        try:
            resultado = subprocess.run(
                [
                'powershell',
                '-Command',
                'Get-NetAdapter | Select-Object Name, MacAddress | ConvertTo-Json'
                ],
                capture_output=True,
                text=True,
                timeout=5
            )
            if resultado.returncode != 0:
                print(f"Error al ejecutar PowerShell: {resultado.stderr}")
                return mapping
            
            if not resultado.stout.strip():
                print("No se obtuvo salida de PowerShell.")
                return mapping
                
            data = json.loads(resultado.stdout)
            
            if isinstance(data, dict):
                data = [data]
            
            if not data:
                print("No se encontraron interfaces")
                return mapping
            
            for item in data:
                mac = item.get("MacAddress")
                name = item.get("Name")
                if mac and name:
                    mapping[mac] = name
            
        except subprocess.TimeoutExpired:
            print("Error: El comando PowerShell tardó demasiado en ejecutarse.")
        except FileNotFoundError:
            print("Error: PowerShell no se encontró. Asegúrate de estar ejecutando este script en Windows.")
        except json.JSONDecodeError:
            print("Error: No se pudo decodificar la salida de PowerShell. Asegúrate de que el comando se ejecute correctamente.")
        except Exception as e:
            print(f"Error en mapeado de interfaces: {e}")
            
        return mapping
    '''