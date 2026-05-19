from protocol_map import *
from analisis import Analisis

# ---------- ICMP --------------

def analizar_icmp(capa):
    """
    Datagrama ICMP - Internet Control Message Protocol
    Protocolo 1 - Mensajes de control y diagnóstico de red (Capa 3)
    Campos: TYPE CODE CHECKSUM REST_OF_HEADER DATA
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   ICMP - Internet Control Message Protocol")
    print(f"            Protocolo de control de red (Capa 3)")
    print(f"            No transporta datos de usuario")
    print(f"            Usado para diagnóstico y control de red")
    print(SEP)

    # TYPE
    icmp_type = capa.type
    icmp_type_desc = ICMP_TYPE_TABLA.get(icmp_type, f"Tipo {icmp_type}  desconocido")
    print(f"  [TYPE]   Tipo ICMP       : {icmp_type}  (8 bits)")
    print(f"            Descripción   : {icmp_type_desc}")
    print(SEP)

    # CODE
    code = capa.code
    code_desc = ICMP_CODE_TABLA.get((icmp_type, code), f"Código {code}  para tipo {icmp_type}")
    print(f"  [CODE]   Código          : {code}  (8 bits)")
    print(f"            Descripción   : {code_desc}")
    print(SEP)

    # CHECKSUM
    chk = capa.chksum
    print(f"  [CHKS]   Suma verific.   : 0x{chk:04X}  (16 bits)")
    print(f"            CRC del mensaje ICMP (encabezado + datos)")
    print(SEP)

    # SEQUENCE NUMBER (para Echo Request/Reply)
    if icmp_type in [8, 0]:  # Echo Request o Echo Reply
        seq = capa.seq if hasattr(capa, 'seq') else 0
        id_icmp = capa.id if hasattr(capa, 'id') else 0
        print(f"  [ID]     Identificador  : {id_icmp}  (16 bits)")
        print(f"            Identifica el proceso que envió el echo")
        print(SEP)
        
        print(f"  [SEQ]    Núm. Secuencia : {seq}  (16 bits)")
        print(f"            Número de secuencia para correlacionar request/reply")
        print(SEP)
    
    # REST OF HEADER (campos específicos según tipo)
    if icmp_type == 3:  # Destination Unreachable
        print(f"  [UNREACH] Destino No Alcanzable")
        print(f"             El código especifica la razón:")
        print(f"             0: Network unreachable")
        print(f"             1: Host unreachable")
        print(f"             2: Protocol unreachable")
        print(f"             3: Port unreachable")
        print(f"             13: Communication administratively prohibited")
        print(SEP)
    
    elif icmp_type == 5:  # Redirect
        if hasattr(capa, 'gw'):
            gw = capa.gw
            print(f"  [REDIR]  Redirección")
            print(f"            Gateway IP   : {gw}")
            print(f"            Usa este gateway para futuros paquetes")
            print(SEP)
    
    elif icmp_type == 11:  # Time Exceeded
        print(f"  [TIMEOUT] Tiempo Excedido")
        print(f"            El código especifica la razón:")
        print(f"            0: TTL exceeded in transit")
        print(f"            1: Fragment reassembly time exceeded")
        print(SEP)
    
    elif icmp_type == 12:  # Parameter Problem
        if hasattr(capa, 'ptr'):
            ptr = capa.ptr
            print(f"  [PARAM]  Problema de Parámetro")
            print(f"            Pointer      : {ptr}")
            print(f"            Octet problemático en el datagrama IP original")
            print(SEP)
    
    elif icmp_type == 13:  # Timestamp Request
        print(f"  [TSTAMP] Solicitud de Marca de Tiempo")
        if hasattr(capa, 'ts_ori'):
            ts_ori = capa.ts_ori if hasattr(capa, 'ts_ori') else 0
            ts_rx = capa.ts_rx if hasattr(capa, 'ts_rx') else 0
            ts_tx = capa.ts_tx if hasattr(capa, 'ts_tx') else 0
            print(f"            Timestamp Original : {ts_ori}")
            print(f"            Timestamp Recibido : {ts_rx}")
            print(f"            Timestamp Transmit : {ts_tx}")
            print(SEP)
    
    # DATA (payload)
    if hasattr(capa, 'payload') and capa.payload:
        payload_len = len(capa.payload)
        print(f"  [DATA]   Datos ICMP      : {payload_len} Bytes")
        print(f"            (generalmente IP original + primeros 8 bytes de datos)")
        print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [TIPOS]  Tipos ICMP comunes:")
    print(f"            • 0:  Echo Reply (respuesta a ping)")
    print(f"            • 3:  Destination Unreachable (destino no alcanzable)")
    print(f"            • 5:  Redirect (cambiar ruta)")
    print(f"            • 8:  Echo Request (ping)")
    print(f"            • 11: Time Exceeded (TTL=0)")
    print(f"            • 12: Parameter Problem (parámetro inválido)")
    print(SEP)

    print(f"  [CASOS]  Casos de uso:")
    print(f"            • Ping (echo request/reply)")
    print(f"            • Traceroute (TTL exceeded)")
    print(f"            • Path MTU Discovery (fragmentation needed)")
    print(f"            • Diagnóstico de conectividad de red")
    print(f"            • Notificación de errores")
    print(SEP)

    print(f"  [NOTA]   ICMP NO transporta datos de usuario")
    print(f"            Es un protocolo de control y diagnóstico")
    print(f"            Algunos firewalls filtran ICMP por seguridad")

# ------------- ICMPv6 ------------------

def analizar_icmpv6(capa):
    """
    Datagrama ICMPv6 - Internet Control Message Protocol version 6
    Protocolo 58 - Mensajes de control y diagnóstico de red IPv6 (Capa 3)
    Campos: TYPE CODE CHECKSUM REST_OF_HEADER DATA
    Incluye: Echo, Neighbor Discovery, Router Advertisement, etc.
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   ICMPv6 - Internet Control Message Protocol version 6")
    print(f"            Protocolo de control de red para IPv6 (Capa 3)")
    print(f"            Protocolo 58 dentro de IPv6")
    print(f"            Incluye diagnóstico, descubrimiento y configuración")
    print(SEP)

    # TYPE
    icmpv6_type = capa.type
    icmpv6_type_desc = ICMPV6_TYPE_TABLA.get(icmpv6_type, f"Tipo {icmpv6_type}  desconocido")
    print(f"  [TYPE]   Tipo ICMPv6     : {icmpv6_type}  (8 bits)")
    print(f"            Descripción   : {icmpv6_type_desc}")
    print(SEP)

    # CODE
    code = capa.code
    code_desc = ICMPV6_CODE_TABLA.get((icmpv6_type, code), f"Código {code}  para tipo {icmpv6_type}")
    print(f"  [CODE]   Código          : {code}  (8 bits)")
    print(f"            Descripción   : {code_desc}")
    print(SEP)

    # CHECKSUM
    chk = capa.chksum
    print(f"  [CHKS]   Suma verific.   : 0x{chk:04X}  (16 bits)")
    print(f"            CRC del mensaje ICMPv6 (encabezado + datos)")
    print(f"            Incluye pseudo-encabezado IPv6")
    print(SEP)

    # ECHO REQUEST / ECHO REPLY (Tipos 128/129)
    if icmpv6_type in [128, 129]:
        id_icmpv6 = capa.id if hasattr(capa, 'id') else 0
        seq = capa.seq if hasattr(capa, 'seq') else 0
        
        print(f"  [ID]     Identificador  : {id_icmpv6}  (16 bits)")
        print(f"            Identifica el proceso que envió el echo")
        print(SEP)
        
        print(f"  [SEQ]    Núm. Secuencia : {seq}  (16 bits)")
        print(f"            Número de secuencia para correlacionar request/reply")
        print(SEP)
        
        if capa.payload and len(capa.payload) > 0:
            data_len = len(capa.payload)
            print(f"  [DATA]   Datos Echo      : {data_len} Bytes")
            print(f"            Datos de ping (generalmente timestamp)")
            print(SEP)

    # DESTINATION UNREACHABLE (Tipo 1)
    elif icmpv6_type == 1:
        print(f"  [UNREACH] Destino No Alcanzable")
        if code == 0:
            print(f"            No route to destination")
        elif code == 1:
            print(f"            Communication with destination administratively prohibited")
        elif code == 2:
            print(f"            Beyond scope of source address")
        elif code == 3:
            print(f"            Address unreachable")
        elif code == 4:
            print(f"            Port unreachable")
        elif code == 5:
            print(f"            Source address failed ingress/egress policy")
        elif code == 6:
            print(f"            Reject route to destination")
        print(SEP)

    # TIME EXCEEDED (Tipo 3)
    elif icmpv6_type == 3:
        print(f"  [TIMEOUT] Tiempo Excedido")
        if code == 0:
            print(f"            Hop limit exceeded in transit")
        elif code == 1:
            print(f"            Fragment reassembly time exceeded")
        print(SEP)

    # PARAMETER PROBLEM (Tipo 4)
    elif icmpv6_type == 4:
        ptr = capa.ptr if hasattr(capa, 'ptr') else 0
        print(f"  [PARAM]  Problema de Parámetro")
        print(f"            Pointer      : {ptr}")
        print(f"            Octet problemático en el datagrama IPv6 original")
        if code == 0:
            print(f"            Erroneous header field encountered")
        elif code == 1:
            print(f"            Unrecognized next header type encountered")
        elif code == 2:
            print(f"            Unrecognized IPv6 option encountered")
        print(SEP)

    # NEIGHBOR SOLICITATION (Tipo 135)
    elif icmpv6_type == 135:
        target = capa.tgt if hasattr(capa, 'tgt') else "N/A"
        print(f"  [NS]     Neighbor Solicitation")
        print(f"            Dirección Objetivo: {target}")
        print(f"            Solicitud de dirección MAC (reemplaza ARP)")
        print(f"            Quien tiene {target}?")
        
        if hasattr(capa, 'options') and capa.options:
            print(f"            Opciones: presentes")
        print(SEP)

    # NEIGHBOR ADVERTISEMENT (Tipo 136)
    elif icmpv6_type == 136:
        target = capa.tgt if hasattr(capa, 'tgt') else "N/A"
        flags = capa.flags if hasattr(capa, 'flags') else 0
        
        router_flag = (flags >> 7) & 1
        solicited_flag = (flags >> 6) & 1
        override_flag = (flags >> 5) & 1
        
        print(f"  [NA]     Neighbor Advertisement")
        print(f"            Dirección Objetivo: {target}")
        print(f"            Respuesta a Neighbor Solicitation")
        print(f"            Tengo {target}")
        print(f"")
        print(f"            Flags:")
        print(f"              Router Flag    : {router_flag}  (soy router)")
        print(f"              Solicited Flag : {solicited_flag}  (respuesta a NS)")
        print(f"              Override Flag  : {override_flag}  (reemplazar entrada)")
        
        if hasattr(capa, 'options') and capa.options:
            print(f"            Opciones: presentes")
        print(SEP)

    # ROUTER SOLICITATION (Tipo 133)
    elif icmpv6_type == 133:
        print(f"  [RS]     Router Solicitation")
        print(f"            Solicitud de anuncio de router")
        print(f"            Quién es el router en esta red?")
        
        if hasattr(capa, 'options') and capa.options:
            print(f"            Opciones: presentes")
        print(SEP)

    # ROUTER ADVERTISEMENT (Tipo 134)
    elif icmpv6_type == 134:
        cur_hop_limit = capa.chlim if hasattr(capa, 'chlim') else 0
        flags = capa.flags if hasattr(capa, 'flags') else 0
        router_lifetime = capa.router_lifetime if hasattr(capa, 'router_lifetime') else 0
        reachable_time = capa.reachable_time if hasattr(capa, 'reachable_time') else 0
        retrans_timer = capa.retrans_timer if hasattr(capa, 'retrans_timer') else 0
        
        managed_flag = (flags >> 7) & 1
        other_flag = (flags >> 6) & 1
        
        print(f"  [RA]     Router Advertisement")
        print(f"            Anuncio de router")
        print(f"            Información de configuración IPv6")
        print(f"")
        print(f"            Hop Limit       : {cur_hop_limit}")
        print(f"            Managed Address : {managed_flag}  (usar DHCP)")
        print(f"            Other Config    : {other_flag}  (otra configuración)")
        print(f"            Router Lifetime : {router_lifetime} segundos")
        print(f"            Reachable Time  : {reachable_time} ms")
        print(f"            Retrans Timer   : {retrans_timer} ms")
        
        if hasattr(capa, 'options') and capa.options:
            print(f"            Opciones (prefijos, DNS, etc.): presentes")
        print(SEP)

    # REDIRECT (Tipo 137)
    elif icmpv6_type == 137:
        target = capa.tgt if hasattr(capa, 'tgt') else "N/A"
        dest = capa.dst if hasattr(capa, 'dst') else "N/A"
        
        print(f"  [REDIR]  Redirect")
        print(f"            Cambiar ruta para destino específico")
        print(f"            Destino       : {dest}")
        print(f"            Gateway       : {target}")
        print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [TIPOS]  Tipos ICMPv6 más comunes:")
    print(f"            • 1:   Destination Unreachable")
    print(f"            • 2:   Packet Too Big (MTU Discovery)")
    print(f"            • 3:   Time Exceeded")
    print(f"            • 4:   Parameter Problem")
    print(f"            • 128: Echo Request (ping)")
    print(f"            • 129: Echo Reply (respuesta a ping)")
    print(f"            • 133: Router Solicitation")
    print(f"            • 134: Router Advertisement")
    print(f"            • 135: Neighbor Solicitation (¿quién eres?)")
    print(f"            • 136: Neighbor Advertisement (soy yo)")
    print(f"            • 137: Redirect")
    print(SEP)

    print(f"  [CARACT] Características de ICMPv6:")
    print(f"            • Diagnóstico: ping, traceroute")
    print(f"            • Neighbor Discovery: reemplaza ARP")
    print(f"            • Router Discovery: autoconfiguration")
    print(f"            • SLAAC: autoconfiguración de dirección")
    print(f"            • Más completo que ICMP (IPv4)")
    print(f"            • Integra múltiples funciones en un protocolo")
    print(SEP)

    print(f"  [ND]     Neighbor Discovery (ICMPv6):")
    print(f"            Reemplaza ARP de IPv4")
    print(f"            • NS (135): Who has this IPv6 address?")
    print(f"            • NA (136): I have this IPv6 address")
    print(f"            • RS (133): Who is the router?")
    print(f"            • RA (134): I am the router, here is config")
    print(SEP)

    print(f"  [CASOS]  Casos de uso:")
    print(f"            • Ping IPv6 (tipos 128/129)")
    print(f"            • Descubrimiento de vecinos (tipos 135/136)")
    print(f"            • Descubrimiento de routers (tipos 133/134)")
    print(f"            • Autoconfiguration de dirección (SLAAC)")
    print(f"            • Detección de multihoming")
    print(f"            • Descubrimiento de MTU Path")
    print(SEP)

    print(f"  [NOTA]   ICMPv6 es más integrado que ICMP")
    print(f"            Maneja tareas que en IPv4 son separadas")
    print(f"            Esencial para funcionamiento de IPv6")

# ------------- IGMP ------------------

def analizar_igmp(capa):
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

# ------------- RSVP ------------------

def analizar_rsvp(capa):
    """
    Datagrama RSVP - Resource Reservation Protocol
    Protocolo 46 - Reserva de recursos de red (Capa 3)
    Campos: VERSION FLAGS MESSAGE_TYPE CHECKSUM SEND_TTL LENGTH RSVP_CHECKSUM
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   RSVP - Resource Reservation Protocol")
    print(f"            Protocolo de reserva de recursos (Capa 3)")
    print(f"            Reserva ancho de banda y QoS en la red")
    print(f"            Protocolo 46 dentro de IP")
    print(SEP)

    # VERSION
    version = capa.version if hasattr(capa, 'version') else 0
    print(f"  [VERS]   Versión RSVP    : {version}  (4 bits)")
    print(f"            Versión del protocolo RSVP")
    print(SEP)

    # FLAGS
    flags = capa.flags if hasattr(capa, 'flags') else 0
    refresh_reduction = (flags >> 0) & 1
    print(f"  [FLAGS]  Banderas        : 0x{flags:02X}  ({flags:08b}b)  (4 bits)")
    print(f"            Refresh Reduction: {refresh_reduction}")
    print(f"            (optimización de mensajes periódicos)")
    print(SEP)

    # MESSAGE TYPE
    msg_type = capa.msg_type if hasattr(capa, 'msg_type') else 0
    msg_type_desc = RSVP_MESSAGE_TYPE_TABLA.get(msg_type, f"Tipo {msg_type}  desconocido")
    print(f"  [TYPE]   Tipo de Mensaje : {msg_type}  (8 bits)")
    print(f"            Descripción   : {msg_type_desc}")
    print(SEP)

    # RSVP CHECKSUM
    chk = capa.chksum if hasattr(capa, 'chksum') else 0
    print(f"  [CHKS]   Suma verific.   : 0x{chk:04X}  (16 bits)")
    print(f"            CRC del mensaje RSVP")
    print(SEP)

    # SEND TTL
    send_ttl = capa.ttl if hasattr(capa, 'ttl') else 0
    print(f"  [STTL]   Send TTL        : {send_ttl}  (8 bits)")
    print(f"            TTL usado cuando se envió el mensaje")
    print(f"            Detecta cambios de topología")
    print(SEP)

    # LENGTH
    length = capa.length if hasattr(capa, 'length') else 0
    print(f"  [LEN]    Longitud        : {length} Bytes  (16 bits)")
    print(f"            Longitud total del mensaje RSVP (sin IP header)")
    print(SEP)

    # RSVP CHECKSUM (campo adicional)
    rsvp_chk = capa.rsvp_chksum if hasattr(capa, 'rsvp_chksum') else 0
    print(f"  [RCHKS]  RSVP Checksum   : 0x{rsvp_chk:04X}  (16 bits)")
    print(f"            Checksum específico de RSVP")
    print(SEP)

    # SESSION OBJECT
    if hasattr(capa, 'session'):
        print(f"  [SESS]   Objeto Sesión")
        session = capa.session
        if hasattr(session, 'dest'):
            print(f"            Destino       : {session.dest}")
        if hasattr(session, 'proto'):
            print(f"            Protocolo     : {session.proto}")
        if hasattr(session, 'port'):
            print(f"            Puerto        : {session.port}")
        print(SEP)

    # SENDER TEMPLATE
    if hasattr(capa, 'sender_template'):
        print(f"  [SENDER] Template del Remitente")
        sender = capa.sender_template
        if hasattr(sender, 'src'):
            print(f"            IP Origen     : {sender.src}")
        if hasattr(sender, 'port'):
            print(f"            Puerto Origen : {sender.port}")
        print(SEP)

    # SENDER TSPEC
    if hasattr(capa, 'sender_tspec'):
        print(f"  [TSPEC]  Especificación de Tráfico")
        tspec = capa.sender_tspec
        if hasattr(tspec, 'token_bucket_rate'):
            print(f"            Tasa Bucket   : {tspec.token_bucket_rate} bytes/sec")
        if hasattr(tspec, 'peak_data_rate'):
            print(f"            Tasa Pico     : {tspec.peak_data_rate} bytes/sec")
        if hasattr(tspec, 'max_packet_size'):
            print(f"            Tam. Max Paq. : {tspec.max_packet_size} Bytes")
        print(SEP)

    # FLOWSPEC
    if hasattr(capa, 'flowspec'):
        print(f"  [FLOW]   Especificación de Flujo (QoS requerida)")
        flowspec = capa.flowspec
        if hasattr(flowspec, 'service_type'):
            service = RSVP_SERVICE_TYPE_TABLA.get(flowspec.service_type, "Desconocido")
            print(f"            Tipo de Servicio: {service}")
        if hasattr(flowspec, 'max_latency'):
            print(f"            Latencia Máx. : {flowspec.max_latency} µs")
        if hasattr(flowspec, 'max_jitter'):
            print(f"            Jitter Máx.   : {flowspec.max_jitter} µs")
        print(SEP)

    # ADSPEC (si está presente)
    if hasattr(capa, 'adspec'):
        print(f"  [ADSPEC] Especificación de Anuncio (parámetros de red)")
        print(f"            Información sobre capacidades de la red")
        print(f"            Actualizado por cada router")
        print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [TIPOS]  Tipos de Mensaje RSVP:")
    print(f"            • 1: Path (reserva de recursos en ruta)")
    print(f"            • 2: Resv (confirmación de reserva)")
    print(f"            • 3: PathErr (error en ruta)")
    print(f"            • 4: ResvErr (error en reserva)")
    print(f"            • 5: PathTear (liberar reserva)")
    print(f"            • 6: ResvTear (cancelar confirmación)")
    print(f"            • 7: ResvConf (confirmación de reserva)")
    print(SEP)

    print(f"  [QOS]    Clases de Servicio RSVP:")
    print(f"            • Guaranteed Service: garantiza ancho de banda")
    print(f"            • Controlled Load: servicio 'best effort' mejorado")
    print(f"            • Default: sin garantías (best effort)")
    print(SEP)

    print(f"  [CASOS]  Casos de uso:")
    print(f"            • Reserva de ancho de banda para VoIP")
    print(f"            • Streaming de video con garantías QoS")
    print(f"            • Videoconferencias en tiempo real")
    print(f"            • Garantizar latencia y jitter bajo")
    print(f"            • Redes MPLS (Traffic Engineering)")
    print(SEP)

    print(f"  [NOTA]   RSVP es poco usado en Internet público")
    print(f"            Más común en redes corporativas/privadas")
    print(f"            Requiere soporte en todos los routers")
    print(f"            Alternativa: DiffServ (menos invasivo)")
    
# ---------- GRE -------------
def analizar_gre(capa):
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
    
# -------------- ESP --------------

def analizar_esp(capa):
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

# ------------ AH -------------------

def analizar_ah(capa):
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

# ----------- HIP --------------
def analizar_hip(capa):
    """
    Datagrama HIP - Host Identity Protocol
    Protocolo 139 - Protocolo de identidad de host (Capa 3)
    Campos: NEXT_HEADER HEADER_LENGTH PACKET_TYPE VERSION RES CHECKSUM CONTROLS HIT SPI
    
    HIP es un protocolo que separa la identidad del host de su dirección IP
    Permite movilidad y multihoming transparentes
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   HIP - Host Identity Protocol")
    print(f"            Protocolo de identidad de host (Capa 3)")
    print(f"            Protocolo 139 dentro de IP")
    print(f"            Separa identidad de host de su localización (IP)")
    print(SEP)

    # NEXT HEADER
    nh = capa.next_header if hasattr(capa, 'next_header') else 0
    nh_desc = PROTOCOLO_TABLA.get(nh, f"Protocolo {nh}  desconocido")
    print(f"  [NH]     Próximo Encab.  : {nh}  (8 bits)")
    print(f"            Protocolo encapsulado: {nh_desc}")
    print(f"            (TCP, UDP, ICMP, etc.)")
    print(SEP)

    # HEADER LENGTH
    hlen = capa.header_length if hasattr(capa, 'header_length') else 0
    header_bytes = hlen * 8
    print(f"  [HLEN]   Long. Encabez.  : {hlen}  (8 bits)")
    print(f"            Longitud en unidades de 8 bytes")
    print(f"            Tamaño real del encabezado: {header_bytes} Bytes")
    print(SEP)

    # PACKET TYPE
    pkt_type = capa.packet_type if hasattr(capa, 'packet_type') else 0
    pkt_type_desc = HIP_PACKET_TYPE_TABLA.get(pkt_type, f"Tipo {pkt_type}  desconocido")
    print(f"  [PTYPE]  Tipo de Paquete : {pkt_type}  (4 bits)")
    print(f"            Descripción   : {pkt_type_desc}")
    print(SEP)

    # VERSION
    version = capa.version if hasattr(capa, 'version') else 0
    print(f"  [VERS]   Versión HIP     : {version}  (4 bits)")
    print(f"            Versión del protocolo HIP")
    print(SEP)

    # RESERVED
    reserved = capa.reserved if hasattr(capa, 'reserved') else 0
    print(f"  [RSVD]   Reservado       : {reserved}  (3 bits)")
    print(f"            Para uso futuro")
    print(SEP)

    # CHECKSUM
    chk = capa.checksum if hasattr(capa, 'checksum') else 0
    print(f"  [CHKS]   Suma verific.   : 0x{chk:04X}  (16 bits)")
    print(f"            CRC del encabezado HIP")
    print(SEP)

    # CONTROLS
    controls = capa.controls if hasattr(capa, 'controls') else 0
    ack_req = (controls >> 15) & 1
    ack = (controls >> 14) & 1
    from_bit = (controls >> 13) & 1
    relay_bit = (controls >> 12) & 1
    print(f"  [CTRL]   Controles       : 0x{controls:04X}  ({controls:016b}b)  (16 bits)")
    print(f"            ACK Required  : {ack_req}")
    print(f"            ACK           : {ack}")
    print(f"            FROM          : {from_bit}")
    print(f"            RELAY         : {relay_bit}")
    print(SEP)

    # HIT (Host Identity Tag)
    if hasattr(capa, 'sender_hit'):
        hit = capa.sender_hit
        print(f"  [HIT]    Host Identity Tag (Sender): {hit}")
        print(f"            Hash de la clave pública del remitente")
        print(f"            Identifica de forma única al host")
        print(SEP)

    # RECEIVER HIT
    if hasattr(capa, 'receiver_hit'):
        hit_rx = capa.receiver_hit
        print(f"  [RCEIVER_HIT] Host Identity Tag (Receiver): {hit_rx}")
        print(f"            Hash de la clave pública del receptor")
        print(SEP)

    # SPI (Security Parameter Index)
    if hasattr(capa, 'spi'):
        spi = capa.spi
        print(f"  [SPI]    Índice Parámetros: 0x{spi:08X}  (32 bits)")
        print(f"            Security Parameters Index")
        print(f"            Identifica la asociación de seguridad")
        print(SEP)

    # PARAMETERS
    if hasattr(capa, 'parameters'):
        print(f"  [PARAM]  Parámetros HIP  : (presentes)")
        print(f"            Información adicional del protocolo")
        print(f"            Host Association Token, Signature, etc.")
        print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [TIPOS]  Tipos de Paquete HIP:")
    print(f"            • 1: I1 (Initiator HIP Packet)")
    print(f"            • 2: R1 (Responder HIP Packet)")
    print(f"            • 3: I2 (Initiator HIP Packet 2)")
    print(f"            • 4: R2 (Responder HIP Packet 2)")
    print(f"            • 5: UPDATE")
    print(f"            • 6: NOTIFY")
    print(f"            • 7: CLOSE")
    print(f"            • 8: CLOSE-ACK")
    print(SEP)

    print(f"  [CARACT] Características de HIP:")
    print(f"            • Separa identidad (HIT) de localización (IP)")
    print(f"            • Permite movilidad de hosts transparente")
    print(f"            • Soporta multihoming (múltiples IPs)")
    print(f"            • Incorpora seguridad criptográfica")
    print(f"            • Autenticación mutua de hosts")
    print(f"            • Protección contra ataques de ubicación")
    print(SEP)

    print(f"  [VENTAJAS] Ventajas de HIP:")
    print(f"            • Movilidad sin interrumpir conexiones")
    print(f"            • Multihoming nativo")
    print(f"            • Seguridad integrada (IPSec)")
    print(f"            • Resistencia a ataques DoS")
    print(f"            • Privacidad mejorada")
    print(SEP)

    print(f"  [CASOS]   Casos de uso:")
    print(f"            • Dispositivos móviles (cambio de red)")
    print(f"            • VoIP con movilidad")
    print(f"            • Servidores multi-homed")
    print(f"            • Aplicaciones sensibles a seguridad")
    print(f"            • Redes militares y críticas")
    print(SEP)

    print(f"  [ESTADO]  HIP en la actualidad:")
    print(f"            • Protocolo experimental (RFC 7401)")
    print(f"            • Soporte limitado en sistemas operativos")
    print(f"            • Más común en investigación que en producción")
    print(f"            • Alternativas: Mobile IP, MPTCP")
    print(SEP)

    print(f"  [NOTA]   HIP es complejo y poco utilizado en Internet público")
    print(f"            Principalmente usado en entornos de investigación")
    print(f"            Futuro prometedor para IoT y redes móviles")