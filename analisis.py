from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, RARP, IGMP, GRE, IPv6, ESP, AH, DCCP, SCTP
from datetime import datetime

from protocol_map import *
from capture import _obtener_layer_3, _obtener_endpoints
from protocols.layer_2 import _analizar_ethernet
from protocols.layer_3_principal import _analizar_arp, _analizar_ip, _analizar_ipv6, _analizar_rarp
from protocols.layer_4 import _analizar_tcp, _analizar_udp, _analizar_dccp, _analizar_sctp

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

            # Capa 2
            if layer_name == Ether:
                _analizar_ethernet(layer)
            
            # Capa 3
            elif layer_name == IP:
                _analizar_ip(layer)
            elif layer_name == IPv6:
                _analizar_ipv6(layer)
            elif layer_name == ARP:
                _analizar_arp(layer)
            elif layer.name == RARP:
                _analizar_rarp(layer)
            
            # Capa 3 - Encapsulados
                # IGMP, GRE, ESP, AH, IPIP, DCCP, RSVP, HIP, 
                # ICMPv6, ESP, AH, GRE
            elif layer_name == GRE:
                Analisis._analizar_gre(layer)
            elif layer_name == IGMP:
                Analisis._analizar_igmp(layer)
            elif layer_name == ICMP:
                Analisis._analizar_icmp(layer)
            elif layer_name == ESP:
                Analisis._analizar_esp(layer)
            elif layer_name == AH:
                Analisis._analizar_ah(layer)
                
            # Capa 4
                # SCTP, DCCP - Dentro de Capa 3 IP o IPv6
            elif layer_name == TCP:
                _analizar_tcp(layer)
            elif layer_name == UDP:
                _analizar_udp(layer)
            elif layer_name == DCCP:
                _analizar_udp(layer)
            elif layer_name == SCTP:
                _analizar_sctp(layer)
                
            # Capa 7 TCP
                # HTTP, HTTPS, FTP, SFTP, SSH, Telnet, SMTP, POP3, IMAP, LDAP, Kerberos, VNC
            # Capa 7 UDP
                # DNS, DHCP, NTP, SNMP, RTP
            
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

        col = f"{'N':<5} {'Protocolo Red':<15} {'Origen':<22} {'Destino':<22} {'Long.'}"
        print(col)
        print("-" * 75)

        for idx, paquete in enumerate(paquetes, start=1):
            layer_3    = Analisis._obtener_layer_3(paquete)
            src, dst = Analisis._obtener_endpoints(paquete)
            longitud = len(bytes(paquete))

            src = (src[:19] + "~") if len(src) > 20 else src
            dst = (dst[:19] + "~") if len(dst) > 20 else dst

            print(f"{idx:<5} {layer_3:<15} {src:<22} {dst:<22} {longitud}")

        print("=" * 75)


    # ANALIZADORES SEMANTICOS POR CAPA    
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

    
    # --------------------------------------------------------------------------

    @staticmethod
    def _analizar_igmp(capa):
        """
        Datagrama IGMP - Internet Group Management Protocol
        Campos: TYPE CODE CHECKSUM GROUP_ADDR (VERSION RESP_TIME para IGMPv2/v3)
        """
        SEP = "  " + "." * 58

        # TYPE
        igmp_type = capa.type
        igmp_type_desc = IGMP_TYPE_TABLA.get(igmp_type, f"Tipo IGMP {igmp_type}  desconocido")
        print(f"  [TYPE]   Tipo IGMP      : {igmp_type}  (8 bits)")
        print(f"            Descripción   : {igmp_type_desc}")
        print(SEP)

        # CODE (usado en IGMPv3)
        code = capa.code if hasattr(capa, 'code') else 0
        print(f"  [CODE]   Código         : {code}  (8 bits)")
        print(f"            (utilizado en IGMPv3 para subtipos)")
        print(SEP)

        # CHECKSUM
        chk = capa.chksum
        print(f"  [CHKS]   Suma verific.  : 0x{chk:04X}  (16 bits)")
        print(f"            CRC del mensaje IGMP")
        print(SEP)

        # GROUP ADDRESS
        group_addr = capa.gaddr if hasattr(capa, 'gaddr') else "N/A"
        if group_addr != "N/A":
            grupo_desc = Analisis._tipo_multicast(group_addr)
            print(f"  [GROUP]  Dir. Grupo     : {group_addr}  (32 bits)")
            print(f"            Tipo          : {grupo_desc}")
        print(SEP)

        # Max Response Time (IGMPv2/v3)
        if hasattr(capa, 'mrtime'):
            mrtime = capa.mrtime
            tiempo_ms = mrtime * 100  # En unidades de 100ms
            print(f"  [MRTIME] T. Resp. Max   : {mrtime}  ({tiempo_ms} ms)  (8 bits)")
            print(f"            Tiempo máximo para responder (IGMPv2+)")
            print(SEP)

        # Number of Sources (IGMPv3)
        if hasattr(capa, 'numsrc'):
            numsrc = capa.numsrc
            print(f"  [NUMSRC] Num. Fuentes   : {numsrc}  (16 bits)")
            print(f"            Número de direcciones de fuente (IGMPv3)")
            print(SEP)

        # Source Addresses (IGMPv3)
        if hasattr(capa, 'srcaddr') and capa.srcaddr:
            print(f"  [SRC]    Dir. Fuentes   : (IGMPv3)")
            for i, src in enumerate(capa.srcaddr, 1):
                print(f"            {i}. {src}")
            print(SEP)

        # Auxiliary Data (IGMPv3)
        if hasattr(capa, 'auxdata') and capa.auxdata:
            auxdata = capa.auxdata
            print(f"  [AUX]    Datos Auxiliar : {len(auxdata)} Bytes  (IGMPv3)")
            print(f"            Datos adicionales del mensaje")
            print(SEP)

        # Determinar versión IGMP
        version = "IGMPv1"
        if hasattr(capa, 'mrtime'):
            version = "IGMPv2"
        if hasattr(capa, 'numsrc'):
            version = "IGMPv3"

        print(f"  [INFO]   Protocolo IGMP : {version}")
        print(f"            Gestión de grupos multicast (Capa 3)")

    # --------------------------------------------------------------------------
    
    @staticmethod
    def _analizar_gre(capa):
        """
        Datagrama GRE - Generic Routing Encapsulation
        Campos: FLAGS VERSION PROTOCOL CHECKSUM OFFSET KEY SEQUENCE ROUTING
        """
        SEP = "  " + "." * 58

        # FLAGS
        flags = capa.flags
        chksum_present = (flags >> 15) & 1
        routing_present = (flags >> 14) & 1
        key_present = (flags >> 13) & 1
        seqnum_present = (flags >> 12) & 1
        reserved = (flags >> 11) & 1
        ack_present = (flags >> 10) & 1
        print(f"  [FLAGS]  Banderas       : 0x{flags:04X}  ({flags:016b}b)  (16 bits)")
        print(f"            C (Checksum) : {chksum_present}  ->  {'Checksum presente' if chksum_present else 'Sin checksum'}")
        print(f"            R (Routing)  : {routing_present}  ->  {'Routing presente' if routing_present else 'Sin routing'}")
        print(f"            K (Key)      : {key_present}  ->  {'Key presente' if key_present else 'Sin key'}")
        print(f"            S (Sequence) : {seqnum_present}  ->  {'Número de secuencia presente' if seqnum_present else 'Sin secuencia'}")
        print(f"            R (Reserved) : {reserved}")
        print(f"            A (Ack)      : {ack_present}  ->  {'ACK presente' if ack_present else 'Sin ACK'}")
        print(SEP)

        # VERSION
        version = capa.version
        version_desc = GRE_VERSION_TABLA.get(version, f"Versión {version}  desconocida")
        print(f"  [VERS]   Versión        : {version}  (3 bits)")
        print(f"            Descripción   : {version_desc}")
        print(SEP)

        # PROTOCOL
        proto = capa.proto
        proto_desc = GRE_PROTOCOL_TABLA.get(proto, f"Protocolo 0x{proto:04X}  (ver RFC)")
        print(f"  [PROTO]  Protocolo      : 0x{proto:04X}  (16 bits)")
        print(f"            Descripción   : {proto_desc}")
        print(SEP)

        # CHECKSUM (si está presente)
        if chksum_present:
            chk = capa.chksum if hasattr(capa, 'chksum') else 0
            print(f"  [CHKS]   Suma verific.  : 0x{chk:04X}  (16 bits)")
            print(f"            CRC del encabezado y payload GRE")
            print(SEP)
            
            # OFFSET (si checksum está presente)
            if hasattr(capa, 'offset'):
                offset = capa.offset
                print(f"  [OFFSET] Desplazamiento : {offset}  (16 bits)")
                print(f"            Offset del campo de routing")
                print(SEP)

        # KEY (si está presente)
        if key_present:
            key = capa.key if hasattr(capa, 'key') else 0
            print(f"  [KEY]    Clave          : 0x{key:08X}  (32 bits)")
            print(f"            Identificador de flujo o túnel")
            print(SEP)

        # SEQUENCE NUMBER (si está presente)
        if seqnum_present:
            seq = capa.seqence if hasattr(capa, 'seqence') else 0
            print(f"  [SEQ]    Núm. Secuencia : {seq}  (32 bits)")
            print(f"            Número de secuencia del paquete")
            print(SEP)

        # ACKNOWLEDGEMENT (si está presente)
        if ack_present:
            ack = capa.ack if hasattr(capa, 'ack') else 0
            print(f"  [ACK]    Reconocimiento : {ack}  (32 bits)")
            print(f"            Número ACK (confirmación recibida hasta)")
            print(SEP)

        # ROUTING (si está presente)
        if routing_present:
            print(f"  [ROUT]   Información Rut: (presente)")
            print(f"            Datos de encaminamiento específicos del protocolo")
            print(SEP)

        print(f"  [INFO]   GRE es un protocolo de tunelización genérico")
        print(f"            Encapsula otros protocolos (IP, IPX, etc.)")
        print(f"            Usado en VPNs y conectividad entre redes")

    # --------------------------------------------------------------------------
    @staticmethod
    def _analizar_esp(capa):
        """
        Datagrama ESP - Encapsulating Security Payload (IPSec)
        Campos: SPI SEQUENCE_NUMBER PAYLOAD IV TRAILER AUTH_TAG
        """
        SEP = "  " + "." * 58

        # SECURITY PARAMETERS INDEX (SPI)
        spi = capa.spi if hasattr(capa, 'spi') else 0
        print(f"  [SPI]    Índice Parámetros: 0x{spi:08X}  (32 bits)")
        print(f"            Security Parameters Index")
        print(f"            Identifica la asociación de seguridad (SA)")
        print(SEP)

        # SEQUENCE NUMBER
        seq = capa.seq if hasattr(capa, 'seq') else 0
        print(f"  [SEQ]    Núm. Secuencia  : {seq}  (32 bits)")
        print(f"            Previene replay attacks")
        print(f"            Se incrementa con cada paquete ESP")
        print(SEP)

        # PAYLOAD DATA (encriptado)
        if hasattr(capa, 'data'):
            payload = capa.data
            payload_len = len(payload) if payload else 0
            print(f"  [PAY]    Datos Encriptados: {payload_len} Bytes")
            print(f"            Contenido cifrado (IP, TCP, UDP, etc.)")
            print(f"            No se puede interpretar sin la clave de desencriptación")
            print(SEP)
        else:
            print(f"  [PAY]    Datos Encriptados: (presentes)")
            print(f"            No se puede interpretar sin la clave de desencriptación")
            print(SEP)

        # INITIALIZATION VECTOR (IV) - si está presente
        if hasattr(capa, 'iv') and capa.iv:
            iv = capa.iv
            print(f"  [IV]     Vector Inicial  : 0x{iv.hex() if isinstance(iv, bytes) else iv}  (variable)")
            print(f"            Necesario para algunos algoritmos de cifrado")
            print(f"            (DES, 3DES, AES en modo CBC)")
            print(SEP)

        # PADDING
        if hasattr(capa, 'pad'):
            pad = capa.pad if capa.pad else 0
            print(f"  [PAD]    Relleno         : {pad} Bytes")
            print(f"            Para alinear a múltiplo de 4 bytes")
            print(SEP)

        # PAD LENGTH
        if hasattr(capa, 'padlen'):
            padlen = capa.padlen
            print(f"  [PADLEN] Long. Relleno   : {padlen}  (8 bits)")
            print(f"            Longitud del relleno en bytes")
            print(SEP)

        # NEXT HEADER
        if hasattr(capa, 'nh'):
            nh = capa.nh
            nh_desc = PROTOCOLO_TABLA.get(nh, f"Protocolo {nh}  desconocido")
            print(f"  [NH]     Próx. Encabezado: {nh}  (8 bits)")
            print(f"            Protocolo encapsulado: {nh_desc}")
            print(f"            (descifrará al desencriptar)")
            print(SEP)

        # AUTHENTICATION TAG
        if hasattr(capa, 'icv') and capa.icv:
            icv = capa.icv
            icv_len = len(icv) if isinstance(icv, bytes) else len(str(icv))
            print(f"  [AUTH]   Tag Autenticación: {icv_len} Bytes")
            print(f"            ICV (Integrity Check Value)")
            print(f"            Valida integridad y autenticidad del paquete")
            print(f"            Generado por el algoritmo de autenticación (HMAC)")
            print(SEP)

        # INFORMACIÓN GENERAL
        print(f"  [INFO]   ESP proporciona confidencialidad e integridad")
        print(f"            Encripta el payload completo")
        print(f"            Autentica encabezado + payload")
        print(f"            Parte del protocolo IPSec (junto con AH)")
        print(f"")
        print(f"  [NOTA]   Los datos encriptados NO se pueden analizar")
        print(f"            sin las claves de desencriptación y autenticación")

    # --------------------------------------------------------------------------
    @staticmethod
    def _analizar_ah(capa):
        """
        Datagrama AH - Authentication Header (IPSec)
        Campos: NEXT_HEADER PAYLOAD_LEN RESERVED SPI SEQUENCE_NUMBER AUTH_DATA
        """
        SEP = "  " + "." * 58

        # NEXT HEADER
        nh = capa.nh if hasattr(capa, 'nh') else 0
        nh_desc = PROTOCOLO_TABLA.get(nh, f"Protocolo {nh}  desconocido")
        print(f"  [NH]     Próx. Encabezado: {nh}  (8 bits)")
        print(f"            Protocolo encapsulado: {nh_desc}")
        print(f"            (IP, ICMP, TCP, UDP, ESP, etc.)")
        print(SEP)

        # PAYLOAD LENGTH
        plen = capa.len if hasattr(capa, 'len') else 0
        payload_bytes = (plen + 2) * 4
        print(f"  [PLEN]   Long. Payload   : {plen}  (8 bits)")
        print(f"            Longitud en unidades de 32 bits")
        print(f"            Tamaño real del encabezado AH: {payload_bytes} Bytes")
        print(SEP)

        # RESERVED
        reserved = capa.reserved if hasattr(capa, 'reserved') else 0
        print(f"  [RSVD]   Reservado       : 0x{reserved:04X}  (16 bits)")
        print(f"            Debe ser cero, reservado para uso futuro")
        print(SEP)

        # SECURITY PARAMETERS INDEX (SPI)
        spi = capa.spi if hasattr(capa, 'spi') else 0
        print(f"  [SPI]    Índice Parámetros: 0x{spi:08X}  (32 bits)")
        print(f"            Security Parameters Index")
        print(f"            Identifica la asociación de seguridad (SA)")
        print(f"            Combinado con dirección destino, identifica única SA")
        print(SEP)

        # SEQUENCE NUMBER
        seq = capa.seq if hasattr(capa, 'seq') else 0
        print(f"  [SEQ]    Núm. Secuencia  : {seq}  (32 bits)")
        print(f"            Previene ataques de repetición (replay attacks)")
        print(f"            Se incrementa con cada paquete AH")
        print(f"            Rango: 0 a 2^32-1 (se reinicia en SA nueva)")
        print(SEP)

        # AUTHENTICATION DATA / INTEGRITY CHECK VALUE (ICV)
        if hasattr(capa, 'icv') and capa.icv:
            icv = capa.icv
            icv_len = len(icv) if isinstance(icv, bytes) else len(str(icv))
            print(f"  [AUTH]   Datos Autenticación: {icv_len} Bytes")
            print(f"            ICV (Integrity Check Value)")
            print(f"            Hash HMAC del encabezado + payload")
            if icv_len == 12:
                print(f"            Tipo: HMAC-SHA-96 (truncado a 96 bits)")
            elif icv_len == 16:
                print(f"            Tipo: HMAC-MD5-128 o HMAC-SHA-128")
            elif icv_len == 20:
                print(f"            Tipo: HMAC-SHA-160 (20 bytes)")
            elif icv_len == 32:
                print(f"            Tipo: HMAC-SHA-256 (completo)")
            print(f"            Valida integridad de TODO el paquete IP")
            print(SEP)
        else:
            print(f"  [AUTH]   Datos Autenticación: (presentes)")
            print(f"            ICV (Integrity Check Value)")
            print(f"            Valida integridad de TODO el paquete IP")
            print(SEP)

        # INFORMACIÓN DE ESTRUCTURA
        print(f"  [STRUCT] Encabezado AH   : {payload_bytes} Bytes")
        print(f"            Campos fijos   : 12 Bytes (NH + PLEN + RSVD + SPI + SEQ)")
        print(f"            Auth Data      : {payload_bytes - 12} Bytes")
        print(SEP)

        # INFORMACIÓN GENERAL
        print(f"  [INFO]   AH proporciona autenticación e integridad")
        print(f"            NO encripta el payload (solo autentica)")
        print(f"            Autentica: encabezado IP + payload + AH")
        print(f"            Parte del protocolo IPSec (junto con ESP)")
        print(f"")
        print(f"  [DIFER]  AH vs ESP:")
        print(f"            • AH: autentica pero NO cifra")
        print(f"            • ESP: autentica Y cifra")
        print(f"            • Pueden usarse juntos (AH + ESP)")

# ------------------------------------------------------------------------

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
    
def _tipo_ipv6(ip_str):
    """Determina el tipo de dirección IPv6 (unicast, multicast, link-local, etc.)"""
    try:
        # Convertir a minúsculas para comparación
        ip = ip_str.lower()
        
        # Loopback
        if ip == "::1":
            return "Loopback (::1)"
        
        # Unspecified (dirección cero)
        if ip == "::":
            return "Sin especificar (::)"
        
        # Link-local (fe80::/10)
        if ip.startswith("fe80:"):
            return "Link-local (fe80::/10)  - alcance local"
        
        # Unique local (fc00::/7)
        if ip.startswith("fc") or ip.startswith("fd"):
            return "Unique Local (fc00::/7 o fd00::/8)  - privada"
        
        # Multicast (ff00::/8)
        if ip.startswith("ff"):
            scope = ip.split(":")[0]
            if scope == "ff02":
                return "Multicast (ff02::/16)  - alcance link-local"
            elif scope == "ff05":
                return "Multicast (ff05::/16)  - alcance site-local"
            elif scope == "ff0e":
                return "Multicast (ff0e::/16)  - alcance global"
            else:
                return "Multicast (ff00::/8)  - varios alcances"
        
        # IPv4-mapped IPv6 (::ffff:0:0/96)
        if ip.startswith("::ffff:"):
            ipv4_part = ip.split("::ffff:")[1]
            return f"IPv4-mapped IPv6 (::ffff:{ipv4_part})"
        
        # IPv4-compatible IPv6 (deprecated) (::0:0/96)
        if ip.startswith("::") and "." in ip:
            return "IPv4-compatible IPv6 (deprecated)"
        
        # Documentation (2001:db8::/32)
        if ip.startswith("2001:db8:"):
            return "Documentación (2001:db8::/32)  - ejemplos/docs"
        
        # Teredo (2001::/32)
        if ip.startswith("2001:0:") or ip.startswith("2001:"):
            if ip.startswith("2001:0:"):
                return "Teredo (2001:0::/32)  - IPv6 sobre IPv4"
            elif ip.startswith("2001:4860:"):
                return "Google Global Unicast (2001:4860::/32)"
        
        # Discard (100::/64) - RFC 6666
        if ip.startswith("100::"):
            return "Discard (100::/64)  - descartable"
        
        # Global Unicast (2000::/3)
        if ip.startswith("2") or ip.startswith("3"):
            primer_nibble = int(ip[0], 16)
            if 0x2000 <= (primer_nibble << 12) < 0x4000:
                return "Global Unicast (2000::/3)  - ruteable públicamente"
        
        # Default para direcciones que comienzan con otros valores
        if any(ip.startswith(f"{c}") for c in "456789abcde"):
            return "Global Unicast (2000::/3)  - ruteable públicamente"
        
        return "Unicast (desconocida)"
    
    except Exception:
        return "Dirección inválida"
    
def _tipo_multicast(direccion):
    """Identifica el tipo de dirección multicast IPv4"""
    try:
        octetos = list(map(int, direccion.split('.')))
        if octetos[0] == 224:
            if octetos[1] == 0 and octetos[2] == 0:
                return "Reservada (Local Network Control)"
            elif octetos[1] == 0 and octetos[2] == 1:
                return "Reservada (Internet Structure)"
            else:
                return "Multicast Global"
        return "No es multicast"
    except:
        return "Dirección inválida"
