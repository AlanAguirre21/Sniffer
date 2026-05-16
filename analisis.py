from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, DNS, Raw
from datetime import datetime

# Protocolos Ethertype
ETHERTYPE_TABLA = {
    0x0800: "IPv4 - Internet Protocol version 4",
    0x0804: "Chaosnet",
    0x0805: "X.25 Level 3",
    0x0806: "ARP - Address Resolution Protocol",
    0x0808: "Frame Relay ARP",
    0x8035: "RARP - Reverse Address Resolution Protocol",
    0x8100: "VLAN Tag (Q-Tag), IEEE 802.1q",
    0x8138: "IPX - Internet Packet Exchange (Novell)",
    0x814C: "SNMP - Simple Network Management Protocol",
    0x86DD: "IPv6 - Internet Protocol version 6",
    0x8808: "EPON - Ethernet Passive Optical Network",
    0x880B: "PPP - Point-to-Point Protocol",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE - Discovery Stage",
    0x8864: "PPPoE - Session Stage",
    0x888E: "EAPOL - EAP over LAN",
    0x88A2: "AoE - ATA over Ethernet",
    0x88A4: "EtherCAT",
}

# Valores campo "VERSION"
IP_VERSION_TABLA = {
    0:  "Reservado",
    1:  "No asignado (TCP v1, RFC-675 1974)",
    2:  "No asignado (TCP v2, IEN5 1977)",
    3:  "No asignado (TCP v3, IEN21 1978)",
    4:  "IPv4 (RFC-791, 1981)",
    5:  "ST-II / IPv5 - Experimental Internet Stream Protocol (RFC-1190, 1990)",
    6:  "IPv6 - IP Next Generation (RFC-2460, 1998)",
    7:  "TP/IX - IPv7 / Next Internet (RFC-1475, 1993)",
    8:  "PIP - IPv8 / Protective Internet Protocol (RFC-1621, 1994)",
    9:  "TUBA - IPv9 / TCP and UDP with bigger addresses (RFC-1347, 1992)",
    15: "Reservado",
}

# Valores campo "HLEN" (en palabras de 32 bits -> bytes)
HLEN_TABLA = {
    0:  (0,  "No valido"),
    1:  (4,  "No valido"),
    2:  (8,  "No valido"),
    3:  (12, "No valido"),
    4:  (16, "No valido"),
    5:  (20, "Valido"),
    6:  (24, "Valido"),
    7:  (28, "Valido"),
    8:  (32, "Valido"),
    9:  (36, "Valido"),
    10: (40, "Valido"),
    11: (44, "Valido"),
    12: (48, "Valido"),
    13: (52, "Valido"),
    14: (56, "Valido"),
    15: (60, "Valido"),
}

# Valores campo "DS" (DSCP)
DSCP_TABLA = {
    0:  "CS0 - Best Effort, trafico no clasificado (web, email, FTP)",
    8:  "CS1 - Trafico de fondo (actualizaciones, respaldos)",
    16: "CS2 - OAM / Gestion de red",
    24: "CS3 - Senalizacion / control de sesiones (VoIP, Zoom, Meet)",
    32: "CS4 - Video fluido (Netflix, YouTube, CCTV)",
    40: "CS5 - Video critico (escritorio Zoom)",
    48: "CS6 - Control normal (BGP, OSPF, EIGRP)",
    56: "CS7 - Control critico de sesiones (keep-alive)",
    10: "AF11 - Assured Forwarding: baja prioridad, evitando descarte",
    12: "AF12 - Assured Forwarding: baja prioridad, susceptible a descarte",
    14: "AF13 - Assured Forwarding: baja prioridad, elegible a descarte",
    18: "AF21 - Assured Forwarding: prioridad media, evitando descarte",
    20: "AF22 - Assured Forwarding: prioridad media, susceptible a descarte",
    22: "AF23 - Assured Forwarding: prioridad media, elegible a descarte",
    26: "AF31 - Assured Forwarding: alta prioridad, evitando descarte",
    28: "AF32 - Assured Forwarding: alta prioridad, susceptible a descarte",
    30: "AF33 - Assured Forwarding: alta prioridad, elegible a descarte",
    34: "AF41 - Assured Forwarding: video sin descarte (streaming/videoconf)",
    36: "AF42 - Assured Forwarding: video susceptible a descarte",
    38: "AF43 - Assured Forwarding: video con descarte alto",
    46: "EF - Expedited Forwarding: trafico critico, exclusivo VoIP (RFC-3246)",
    44: "VOICE-ADMIT - VoIP con Call Admission Control (RFC-5865)",
}

ECN_TABLA = {
    0b00: "00 - No compatible (no soporta ECN)",
    0b01: "01 - ECT(1): Identificador L4S (RFC-9331)",
    0b10: "10 - ECT(0): Soporta ECN (RFC-3168)",
    0b11: "11 - Congestion detectada",
}

# Valores campo "PROTOCOL"
PROTOCOLO_TABLA = {
    0:   "HOPOPT - Opcion Hop-by-Hop IPv6",
    1:   "ICMP - Internet Control Message Protocol",
    2:   "IGMP - Internet Group Management Protocol",
    3:   "GGP - Gateway-to-Gateway Protocol",
    4:   "IP en IP (encapsulacion)",
    5:   "ST - Stream",
    6:   "TCP - Transmission Control Protocol",
    7:   "CBT",
    8:   "EGP - Exterior Gateway Protocol",
    9:   "IGP - protocolo propietario IGP",
    17:  "UDP - User Datagram Protocol",
    41:  "IPv6",
    47:  "GRE - General Routing Encapsulation",
    50:  "ESP - Encap Security Payload",
    51:  "AH - Authentication Header",
    58:  "IPv6-ICMP - ICMP para IPv6",
    88:  "EIGRP",
    89:  "OSPF",
    103: "PIM - Protocol Independent Multicast",
    112: "VRRP - Virtual Router Redundancy Protocol",
    115: "L2TP - Layer-Two Tunneling Protocol",
}



# CLASE PRINCIPAL
class Analisis:

    # PARTE 1 - Analisis detallado de un unico paquete (semantico)
    @staticmethod
    def analice_packet(paquete):
        """
        Muestra el analisis detallado e interpretado de un paquete Scapy.
        Identifica, lee e interpreta cada campo segun lo visto en clase.
        """
        print("\n" + "=" * 65)
        print("         ANALISIS DETALLADO DEL PAQUETE")
        print("=" * 65)

        capas = paquete.layers()
        if not capas:
            print("[!] El paquete no contiene capas reconocibles.")
            return

        for i, layer_name in enumerate(capas):
            layer = paquete[layer_name]
            print(f"\n{'-' * 65}")
            print(f"  CAPA {i + 1}: {layer.name.upper()}")
            print(f"{'-' * 65}")

            if layer_name == Ether:
                Analisis._analizar_ethernet(layer)
            elif layer_name == IP:
                Analisis._analizar_ip(layer)
            elif layer_name == TCP:
                Analisis._analizar_tcp(layer)
            elif layer_name == UDP:
                Analisis._analizar_udp(layer)
            elif layer_name == ICMP:
                Analisis._analizar_icmp(layer)
            elif layer_name == ARP:
                Analisis._analizar_arp(layer)
            else:
                Analisis._analizar_generico(layer)

        print("\n" + "=" * 65 + "\n")

    
    # PARTE 2 - Resumen tabular de la lista de paquetes capturados
    @staticmethod
    def mostrar_resumen(paquetes):
        """
        Muestra una tabla resumen de todos los paquetes capturados
        para que el usuario pueda elegir cual analizar.
        """
        if not paquetes:
            print("[!] No hay paquetes para mostrar.")
            return

        print("\n" + "=" * 75)
        print("  RESUMEN DE PAQUETES CAPTURADOS")
        print("=" * 75)

        col = f"{'N':<5} {'Protocolo':<10} {'Origen':<22} {'Destino':<22} {'Long.'}"
        print(col)
        print("-" * 75)

        for idx, paquete in enumerate(paquetes, start=1):
            proto    = Analisis._obtener_protocolo(paquete)
            src, dst = Analisis._obtener_endpoints(paquete)
            longitud = len(bytes(paquete))

            src = (src[:19] + "~") if len(src) > 20 else src
            dst = (dst[:19] + "~") if len(dst) > 20 else dst

            print(f"{idx:<5} {proto:<10} {src:<22} {dst:<22} {longitud}")

        print("=" * 75)


    # ANALIZADORES SEMANTICOS POR CAPA

    @staticmethod
    def _analizar_ethernet(capa):
        """
        Frame Ethernet IEEE 802.3 / DIX
        Presentacion 07: PRE SFD DAD SAD LNG/TYP DATOS FCS
        Nota: PRE, SFD y FCS los gestiona la NIC; scapy no los expone.
        """
        SEP = "  " + "." * 58

        # PRE + SFD (informativo)
        print("  [PRE]  Preambulo        : 7 Bytes  (10101010 x 7)  sincronizacion")
        print("  [SFD]  Inicio de Frame  : 1 Byte   (10101011)      delimita inicio")
        print(SEP)

        # DAD - Direccion Destino
        dad = capa.dst
        ig_d, ul_d = Analisis._interpretar_mac(dad)
        tipo_frame = "DIX (Ethernet II)" if capa.type > 0x05DC else "IEEE 802.3"
        print(f"  [DAD]  Dir. Destino    : {dad.upper()}  (6 Bytes)")
        print(f"           I/G bit       : {ig_d}")
        print(f"           U/L bit       : {ul_d}")
        print(SEP)

        # SAD - Direccion Fuente
        sad = capa.src
        ig_s, ul_s = Analisis._interpretar_mac(sad)
        print(f"  [SAD]  Dir. Fuente     : {sad.upper()}  (6 Bytes)")
        print(f"           I/G bit       : {ig_s}")
        print(f"           U/L bit       : {ul_s}")
        print(SEP)

        # LNG / TYP
        tipo_val = capa.type
        if tipo_val <= 0x05DC:
            desc_tipo = f"Longitud del campo DATOS = {tipo_val} Bytes  ->  Frame IEEE 802.3"
        else:
            nombre = ETHERTYPE_TABLA.get(tipo_val, "Ethertype desconocido")
            desc_tipo = f"Ethertype 0x{tipo_val:04X}  ->  {nombre}  ->  Frame DIX"

        print(f"  [TYP]  Tipo / Longitud : 0x{tipo_val:04X}  ({tipo_val})  (2 Bytes)")
        print(f"           Interpretacion: {desc_tipo}")
        print(f"           Tipo de frame : {tipo_frame}")
        print(SEP)

        # DATOS + FCS
        print("  [DAT]  Campo de datos  : 46 - 1,500 Bytes  (LLC / IP / ARP / ...)")
        print("  [FCS]  Sec. verificac. : 4 Bytes  CRC-32  (gestionado por la NIC)")

    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_ip(capa):
        """
        Datagrama IPv4 - Presentacion 09
        Campos: VER HLEN DS TLEN ID FLAG FRAG TTL PROTO CHKSM SRC DST OPTIONS
        """
        SEP = "  " + "." * 58

        # VER
        ver = capa.version
        ver_desc = IP_VERSION_TABLA.get(ver, "Valor desconocido")
        print(f"  [VER]  Version         : {ver}  ({ver:04b}b)  (4 bits)")
        print(f"           Interpretacion: {ver_desc}")
        print(SEP)

        # HLEN
        hlen = capa.ihl
        bytes_enc, valido = HLEN_TABLA.get(hlen, (hlen * 4, "Desconocido"))
        print(f"  [HLEN] Long. Encabez.  : {hlen}  ({hlen:04b}b)  (4 bits)")
        print(f"           Tamano real   : {hlen} x 4 = {bytes_enc} Bytes  -  Estado: {valido}")
        print(SEP)

        # DS = DSCP (6 bits) + ECN (2 bits)
        tos   = capa.tos
        dscp  = tos >> 2
        ecn   = tos & 0b11
        dscp_desc = DSCP_TABLA.get(dscp, f"Codigo DSCP {dscp}  sin clasificar en el curso")
        ecn_desc  = ECN_TABLA.get(ecn, "Valor ECN desconocido")
        print(f"  [DS]   Serv. Diferenc. : 0x{tos:02X}  ({tos:08b}b)  (8 bits)")
        print(f"           DSCP (6 bits) : {dscp:06b}b = {dscp}  ->  {dscp_desc}")
        print(f"           ECN  (2 bits) : {ecn:02b}b         ->  {ecn_desc}")
        print(SEP)

        # TLEN
        tlen  = capa.len
        d_len = tlen - bytes_enc
        print(f"  [TLEN] Long. Total     : {tlen} Bytes  (16 bits)")
        print(f"           TLEN = HLEN + Datos  =>  {tlen} = {bytes_enc} + {d_len} Bytes")
        print(SEP)

        # IDENTIFICATION
        ident = capa.id
        print(f"  [ID]   Identificacion  : {ident}  (0x{ident:04X})  (16 bits)")
        print(f"           Identifica el datagrama y todos sus fragmentos de forma unica")
        print(SEP)

        # FLAGS
        flags_raw = int(capa.flags)
        df_bit = 1 if flags_raw & 0b010 else 0
        mf_bit = 1 if flags_raw & 0b001 else 0
        print(f"  [FLAG] Banderas        : - D M  =>  - {df_bit} {mf_bit}  (3 bits)")
        print(f"           D (Don't Frag): {df_bit}  ->  {'NO se puede fragmentar' if df_bit else 'SE puede fragmentar'}")
        print(f"           M (More Frag) : {mf_bit}  ->  {'Hay mas fragmentos' if mf_bit else 'Ultimo o unico fragmento'}")
        print(SEP)

        # FRAGMENTATION OFFSET
        frag_off = capa.frag
        byte_off = frag_off * 8
        print(f"  [FRAG] Despl. Fragm.   : {frag_off}  (13 bits)")
        print(f"           Byte inicio   : {frag_off} x 8 = {byte_off} Bytes desde el inicio del datagrama original")
        print(SEP)

        # TTL
        ttl = capa.ttl
        print(f"  [TTL]  Tiempo de Vida  : {ttl} saltos restantes  (8 bits)")
        print(f"           Se decrementa 1 por ruteador; se descarta al llegar a 0")
        print(SEP)

        # PROTOCOL
        proto      = capa.proto
        proto_desc = PROTOCOLO_TABLA.get(proto, f"Protocolo {proto}  (ver Anexo 5 del curso)")
        print(f"  [PROT] Protocolo       : {proto}  (0x{proto:02X})  (8 bits)")
        print(f"           Protocolo capa superior: {proto_desc}")
        print(SEP)

        # CHECKSUM
        chk = capa.chksum
        print(f"  [CHKS] Suma verific.   : 0x{chk:04X}  (16 bits)  CRC del encabezado IP")
        print(SEP)

        # SOURCE IP
        src     = capa.src
        clase_s = Analisis._clase_ipv4(src)
        tipo_s  = Analisis._tipo_ip(src)
        print(f"  [SRC]  IP Fuente       : {src}  (32 bits)")
        print(f"           Clase         : {clase_s}")
        print(f"           Tipo          : {tipo_s}")
        print(SEP)

        # DESTINATION IP
        dst     = capa.dst
        clase_d = Analisis._clase_ipv4(dst)
        tipo_d  = Analisis._tipo_ip(dst)
        print(f"  [DST]  IP Destino      : {dst}  (32 bits)")
        print(f"           Clase         : {clase_d}")
        print(f"           Tipo          : {tipo_d}")

        # OPTIONS (si las hay)
        if hlen > 5 and capa.options:
            print(SEP)
            opc_bytes = bytes_enc - 20
            print(f"  [OPT]  Opciones        : {opc_bytes} Bytes de opciones  (ver Anexo 6)")

    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_tcp(capa):
        SEP = "  " + "." * 58
        print(f"  [SPT]  Puerto Origen   : {capa.sport}")
        print(f"  [DPT]  Puerto Destino  : {capa.dport}")
        print(SEP)
        print(f"  [SEQ]  Num. Secuencia  : {capa.seq}")
        print(f"  [ACK]  Num. ACK        : {capa.ack}")
        print(SEP)
        flags_str = str(capa.flags)
        print(f"  [FLG]  Flags TCP       : {flags_str}")
        print(f"           SYN:{int('S' in flags_str)}  ACK:{int('A' in flags_str)}  "
              f"FIN:{int('F' in flags_str)}  RST:{int('R' in flags_str)}  "
              f"PSH:{int('P' in flags_str)}  URG:{int('U' in flags_str)}")
        print(SEP)
        print(f"  [WIN]  Ventana         : {capa.window} Bytes")
        print(f"  [CHK]  Checksum        : 0x{capa.chksum:04X}")

    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_udp(capa):
        SEP = "  " + "." * 58
        print(f"  [SPT]  Puerto Origen   : {capa.sport}")
        print(f"  [DPT]  Puerto Destino  : {capa.dport}")
        print(SEP)
        print(f"  [LEN]  Longitud        : {capa.len} Bytes  (encabezado UDP + datos)")
        print(f"  [CHK]  Checksum        : 0x{capa.chksum:04X}")

    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_icmp(capa):
        SEP = "  " + "." * 58
        tipos_icmp = {
            0:  "Echo Reply (respuesta a ping)",
            3:  "Destination Unreachable (destino inalcanzable)",
            5:  "Redirect (redireccion)",
            8:  "Echo Request (ping)",
            11: "Time Exceeded (TTL agotado en transito)",
            12: "Parameter Problem",
        }
        tipo_desc = tipos_icmp.get(capa.type, f"Tipo {capa.type}")
        print(f"  [TYP]  Tipo ICMP       : {capa.type}  ->  {tipo_desc}")
        print(f"  [COD]  Codigo          : {capa.code}")
        print(SEP)
        print(f"  [CHK]  Checksum        : 0x{capa.chksum:04X}")

    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_arp(capa):
        SEP = "  " + "." * 58
        op_desc = {1: "ARP Request (quien tiene la IP?)", 2: "ARP Reply (la tengo yo)"}
        print(f"  [OP]   Operacion       : {capa.op}  ->  {op_desc.get(capa.op, 'Desconocido')}")
        print(SEP)
        print(f"  [SMA]  MAC Fuente      : {capa.hwsrc.upper()}")
        print(f"  [SPA]  IP Fuente       : {capa.psrc}")
        print(SEP)
        print(f"  [DMA]  MAC Destino     : {capa.hwdst.upper()}")
        print(f"  [DPA]  IP Destino      : {capa.pdst}")

    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_generico(capa):
        """Fallback: muestra campos crudos para capas no especificas."""
        campos = capa.fields
        if not campos:
            print("  (sin campos disponibles)")
            return
        for field, value in campos.items():
            if isinstance(value, bytes):
                print(f"  - {field:<20}: {value.hex()}")
            else:
                print(f"  - {field:<20}: {value}")


    # HELPERS INTERNOS

    @staticmethod
    def _interpretar_mac(mac):
        """
        Interpreta los bits I/G y U/L del primer octeto de la MAC.
        Presentacion 07 - Semantica del campo DAD/SAD.
        """
        try:
            primer = int(mac.split(":")[0], 16)
            ig = primer & 0x01
            ul = (primer >> 1) & 0x01
            ig_txt = "1 -> Direccion de grupo   (multicast / broadcast)" if ig else "0 -> Direccion individual (unicast)"
            ul_txt = "1 -> Localmente administrada"                       if ul else "0 -> Universalmente administrada (OUI asignado por IEEE)"
            return ig_txt, ul_txt
        except Exception:
            return "Desconocido", "Desconocido"

    @staticmethod
    def _clase_ipv4(ip_str):
        """Determina la clase de una direccion IPv4 (Presentacion 08)."""
        try:
            primer = int(ip_str.split(".")[0])
            if primer < 128:
                return "Clase A  (0.0.0.0 - 127.255.255.255)"
            elif primer < 192:
                return "Clase B  (128.0.0.0 - 191.255.255.255)"
            elif primer < 224:
                return "Clase C  (192.0.0.0 - 223.255.255.255)"
            elif primer < 240:
                return "Clase D  (224.0.0.0 - 239.255.255.255)  Multicast"
            else:
                return "Clase E  (240.0.0.0 - 255.255.255.255)  Reservada"
        except Exception:
            return "Desconocida"

    @staticmethod
    def _tipo_ip(ip_str):
        """Determina si la IP es publica, privada, loopback, etc. (Presentacion 08)."""
        try:
            partes = list(map(int, ip_str.split(".")))
            p = partes[0]
            if p == 127:
                return "Loopback  (127.X.X.X)"
            if ip_str == "255.255.255.255":
                return "Broadcast limitado"
            if p == 10:
                return "Privada Clase A  (10.0.0.0/8)  RFC 1918"
            if p == 172 and 16 <= partes[1] <= 31:
                return "Privada Clase B  (172.16.0.0/12)  RFC 1918"
            if p == 192 and partes[1] == 168:
                return "Privada Clase C  (192.168.0.0/16)  RFC 1918"
            if p == 169 and partes[1] == 254:
                return "APIPA / Link-local  (sin servidor DHCP)"
            return "Publica (ruteable en Internet)"
        except Exception:
            return "Desconocida"

    @staticmethod
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

    @staticmethod
    def _obtener_endpoints(paquete):
        if paquete.haslayer(IP):
            return paquete[IP].src, paquete[IP].dst
        if paquete.haslayer(ARP):
            return paquete[ARP].psrc, paquete[ARP].pdst
        if paquete.haslayer(Ether):
            return paquete[Ether].src, paquete[Ether].dst
        return "N/A", "N/A"

