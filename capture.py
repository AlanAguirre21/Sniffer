from scapy.all import sniff
import logging

logging.basicConfig(level=logging.INFO) #Cambiar a WARNING para forma silenciosa
logger = logging.getLogger(__name__)

class Capture:
    def __init__(self):
        self.sniffing_time = 5
        self.paquetes = []
        self.datos_crudos = []
    
    def set_time(self):
        try:
            print("""[*] Seleccione el tiempo en el que se capturarán los paquetes en la red:
                a) 5
                b) 10
                c) 20
                d) 30""")
            value = input("Ingrese la opción que desea utilizar:").strip().lower()
            if value not in ["a", "b", "c", "d"]:
                print("\n[!] Opción no válida. Por favor, elija entre 'a', 'b', 'c' o 'd'.")
                self.set_time()
            elif value == "a":
                self.sniffing_time = 5
            elif value == "b":
                self.sniffing_time = 10
            elif value == "c":
                self.sniffing_time = 20
            elif value == "d":
                self.sniffing_time = 30
        except Exception as e:
            logger.error(f"Error al establecer el tiempo de captura: {e}")

    def iniciar_captura(self, interfaz):
        """
        Inicia la escucha en la interfaz seleccionada y captura de forma estática (1 paquete).
        Retorna los datos en formato de bytes crudos (raw).
        """
        print(f"\n[*] Iniciando captura en la interfaz: {interfaz}")
        try:
            self.set_time()
            print(f"[*] Capturando durante {self.sniffing_time} segundos...")
            # iface recibe el UUID de la interfaz seleccionada
            self.paquetes = sniff(iface=interfaz, timeout=self.sniffing_time)
            
            if self.paquetes:
                for pkt in self.paquetes:
                    # Convertimos el paquete de Scapy a bytes crudos.
                    self.datos_crudos.append(bytes(pkt))
                
                print("[+] ¡Paquetes capturado exitosamente!")
                print(f"[*] Cantidad de tramas/paquetes: {len(self.paquetes)}.")
            else:
                print("[-] No se interceptó ningún paquete.")
                return None
                
        except Exception as e:
            logger.error(f"Error crítico al intentar capturar en la interfaz: {e}")
            return None
