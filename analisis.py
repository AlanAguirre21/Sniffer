from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether, RARP, IGMP, GRE, IPv6, ESP, AH, DCCP, SCTP, RSVP, HIP, ICMPv6
from datetime import datetime

from capture import _obtener_layer_3, _obtener_endpoints
from protocols.layer_2 import *
from protocols.layer_3_principal import *
from protocols.layer_3_encapsulated import *
from protocols.layer_4 import *

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
                analizar_ethernet(layer)
            
            # Capa 3
            elif layer_name == IP:
                analizar_ip(layer)
            elif layer_name == IPv6:
                analizar_ipv6(layer)
            elif layer_name == ARP:
                analizar_arp(layer)
            elif layer.name == RARP:
                analizar_rarp(layer)
            
            # Capa 3 - Encapsulados
                # IGMP, GRE, ESP, AH, IPIP, RSVP, HIP, 
                # ICMPv6, ESP, AH, GRE
            elif layer_name == IGMP:
                analizar_igmp(layer)
            elif layer_name == ICMP:
                analizar_icmp(layer)
            elif layer_name == ICMPv6:
                analizar_icmpv6(layer)
            elif layer_name == ESP:
                analizar_esp(layer)
            elif layer_name == AH:
                analizar_ah(layer)
            elif layer_name == RSVP:
                analizar_rsvp(layer)
            elif layer_name == HIP:
                analizar_hip(layer)
            elif layer_name == GRE:
                analizar_gre(layer)   
             
            # Capa 4
                # SCTP, DCCP - Dentro de Capa 3 IP o IPv6
            elif layer_name == TCP:
                analizar_tcp(layer)
            elif layer_name == UDP:
                analizar_udp(layer)
            elif layer_name == DCCP:
                analizar_udp(layer)
            elif layer_name == SCTP:
                analizar_sctp(layer)
                
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

# Función auxiliar para obtener servicio del puerto
def obtener_servicio_puerto(puerto):
    """Devuelve el servicio asociado a un puerto TCP común"""
    return puerto_servicio.get(puerto, "Desconocido")