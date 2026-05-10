import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, DNS


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
            print(f"\n[!] Error crítico al intentar capturar en la interfaz: {e}")
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

        col = f"{'N°':<5} {'Hora':<14} {'Protocolo':<10} {'Origen':<22} {'Destino':<22} {'Long.'}"
        print(col)
        print("─" * len(col))

        def _obtener_protocolo(paquete):
            if paquete.haslayer(DNS):
                return "DNS"
            if paquete.haslayer(TCP):
                return "TCP"
            if paquete.haslayer(UDP):
                return "UDP"
            if paquete.haslayer(ICMP):
                return "ICMP"
            if paquete.haslayer(ARP):
                return "ARP"
            if paquete.haslayer(IP):
                return "IP"
            if paquete.haslayer(Ether):
                return "Ethernet"
            return "OTRO"

        def _obtener_endpoints(paquete):
            if paquete.haslayer(IP):
                return paquete[IP].src, paquete[IP].dst
            if paquete.haslayer(ARP):
                return paquete[ARP].psrc, paquete[ARP].pdst
            if paquete.haslayer(Ether):
                return paquete[Ether].src, paquete[Ether].dst
            return "N/A", "N/A"

        def _callback(paquete):
            with lock:
                contador[0] += 1
                idx = contador[0]
                paquetes.append(paquete)

            hora     = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            proto    = _obtener_protocolo(paquete)
            src, dst = _obtener_endpoints(paquete)
            longitud = len(bytes(paquete))

            src = (src[:19] + "…") if len(src) > 20 else src
            dst = (dst[:19] + "…") if len(dst) > 20 else dst

            print(f"{idx:<5} {hora:<14} {proto:<10} {src:<22} {dst:<22} {longitud}")

        def _stop_filter(paquete):
            return stop_event.is_set()

        hilo = threading.Thread(
            target=lambda: sniff(
                iface=interfaz,
                filter="ip",
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
