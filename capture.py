import threading
from datetime import datetime
import logging
from scapy.all import Ether, IP, IPv6, ARP, GRE, IPIP, sniff

logging.basicConfig(level=logging.INFO) #Cambiar a WARNING para forma silenciosa
logger = logging.getLogger(__name__)

class Capture:

    # PARTE 1 ─ Captura estática
    @staticmethod
    def iniciar_captura(interfaz):
        """
        Inicia la escucha en la interfaz seleccionada y captura de forma
        estática (1 paquete IPv4). Retorna el objeto Scapy del paquete capturado.
        """
        print(f"\n[*] Iniciando captura en la interfaz: {interfaz}")
        print("[*] Esperando 1 paquete IPv4 estático en la red...")

        try:
            paquetes = sniff(iface=interfaz, filter="ip", count=1)

            if paquetes:
                paquete = paquetes[0]
                datos_crudos = bytes(paquete)

                print("[+] ¡Paquete capturado exitosamente!")
                print(f"[*] Tamaño de la trama: {len(datos_crudos)} bytes.")

                return paquete
            else:
                print("[-] No se interceptó ningún paquete.")
                return None

        except Exception as e:
            logger.error(f"Error crítico al intentar capturar en la interfaz: {e}")
            return None

    # PARTE 2 ─ Captura dinámica
    @staticmethod
    def captura_dinamica(interfaz):
        """
        Captura paquetes IPv4 de forma dinámica mostrando el flujo en tiempo real.
        Presionar ENTER detiene la captura y retorna la lista de paquetes.
        """
        paquetes   = []
        stop_event = threading.Event()
        lock       = threading.Lock()
        contador   = [0]

        print(f"\n[*] Iniciando captura dinámica en la interfaz: {interfaz}")
        print("[*] Solo paquetes IPv4. Presione ENTER para detener la captura...\n")

        col = f"{'N°':<5} {'Hora':<14} {'Datagrama':<12} {'Origen':<22} {'Destino':<22} {'Long.'}"
        print(col)
        print("─" * len(col))

        def _obtener_datagram(paquete):
            if not paquete.haslayer(Ether):
                return "N/A"
            
            layer = paquete[Ether].payload
            datagrams = ["IP", "IPv6", "ARP", #             # Básico
                         "ICMP", "IGMP", "ICMPV6",          # Control
                         "GRE", "ESP", "AH", "IPIP",        # Tunneling/Security
                         "DCCP", "SCTP", "HIP", "RSVP"]     # Otros L3
            
            while layer:
                if layer.name in datagrams:
                    return layer.name
                if layer.name == "Raw":
                    return "RAW"
                layer = layer.payload
            return "DESCONOCIDO"

        def _obtener_endpoints(paquete):
            if paquete.haslayer(IP):
                return paquete[IP].src, paquete[IP].dst
            if paquete.haslayer(IPv6):
                return paquete[IPv6].src, paquete[IPv6].dst
            if paquete.haslayer(ARP):
                return paquete[ARP].psrc, paquete[ARP].pdst
            if paquete.haslayer(GRE):
                return paquete[GRE].src, paquete[GRE].dst
            if paquete.haslayer(IPIP):
                return paquete[IPIP].src, paquete[IPIP].dst
            if paquete.haslayer(Ether):
                return paquete[Ether].src, paquete[Ether].dst
            return "N/A", "N/A"

        def _callback(paquete):
            with lock:
                contador[0] += 1
                idx = contador[0]
                paquetes.append(paquete)

            hora     = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            datagram = _obtener_datagram(paquete)
            src, dst = _obtener_endpoints(paquete)
            longitud = len(bytes(paquete))

            src = (src[:19] + "…") if len(src) > 20 else src
            dst = (dst[:19] + "…") if len(dst) > 20 else dst

            print(f"{idx:<5} {hora:<14} {datagram:<12} {src:<22} {dst:<22} {longitud}")

        def _stop_filter(paquete):
            return stop_event.is_set()

        hilo = threading.Thread(
            target=lambda: sniff(
                iface=interfaz,
                #filter="ip",               - Sin filtro para mostrar todo el tráfico de red
                prn=_callback,
                stop_filter=_stop_filter
            ),
            daemon=True
        )
        hilo.start()

        try:
            input()
        except KeyboardInterrupt:
            pass

        stop_event.set()
        hilo.join(timeout=3)

        total = len(paquetes)
        print(f"\n[+] Captura detenida. Total de paquetes capturados: {total}")
        return paquetes
