from scapy.all import sniff

class Capture:
    
    @staticmethod
    def iniciar_captura(interfaz):
        """
        Inicia la escucha en la interfaz seleccionada y captura de forma estática (1 paquete).
        Retorna los datos en formato de bytes crudos (raw).
        """
        print(f"\n[*] Iniciando captura en la interfaz: {interfaz}")
        print("[*] Esperando 1 paquete estático en la red...")
        
        try:
            # iface recibe el UUID de la interfaz seleccionada
            paquetes = sniff(iface=interfaz, count=1)
            
            if paquetes:
                paquete = paquetes[0]
                #print(paquete.show(), '\n')
                # Convertimos el paquete de Scapy a bytes crudos.
                datos_crudos = bytes(paquete)
                
                print("[+] ¡Paquete capturado exitosamente!")
                print(f"[*] Tamaño de la trama: {len(datos_crudos)} bytes.")
                
                return paquete
            else:
                print("[-] No se interceptó ningún paquete.")
                return None
                
        except Exception as e:
            print(f"\n[!] Error crítico al intentar capturar en la interfaz: {e}")
            return None
