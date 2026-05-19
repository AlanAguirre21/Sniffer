from protocol_map import *
from analisis import obtener_servicio_puerto

# PROTOCOLO TCP
def analizar_tcp(capa):
    """
    Datagrama TCP - Transmission Control Protocol
    Protocolo 6 - Transporte confiable orientado a conexión (Capa 4)
    Campos: SOURCE_PORT DEST_PORT SEQUENCE_NUMBER ACKNOWLEDGMENT_NUMBER
            DATA_OFFSET RESERVED FLAGS WINDOW_SIZE CHECKSUM URGENT_POINTER OPTIONS DATA
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   TCP - Transmission Control Protocol")
    print(f"            Protocolo de transporte confiable (Capa 4)")
    print(f"            Orientado a conexión y orientado a flujo")
    print(f"            Garantiza entrega en orden sin duplicados")
    print(SEP)

    # SOURCE PORT
    sport = capa.sport
    sport_service = obtener_servicio_puerto(sport)
    print(f"  [SPORT]  Puerto Origen   : {sport}  (16 bits)")
    print(f"            Servicio      : {sport_service}")
    print(SEP)

    # DESTINATION PORT
    dport = capa.dport
    dport_service = obtener_servicio_puerto(dport)
    print(f"  [DPORT]  Puerto Destino  : {dport}  (16 bits)")
    print(f"            Servicio      : {dport_service}")
    print(SEP)

    # SEQUENCE NUMBER
    seq = capa.seq
    print(f"  [SEQ]    Núm. Secuencia : {seq}  (0x{seq:08X})  (32 bits)")
    print(f"            Número del primer byte de datos en este segmento")
    print(f"            Permite ordenar segmentos correctamente")
    print(SEP)

    # ACKNOWLEDGMENT NUMBER
    ack = capa.ack
    print(f"  [ACK]    Número Reconoc. : {ack}  (0x{ack:08X})  (32 bits)")
    print(f"            Próximo byte esperado del remitente")
    print(f"            Valido solo si flag ACK está activo")
    print(SEP)

    # DATA OFFSET
    data_offset = capa.dataofs
    header_bytes = data_offset * 4
    print(f"  [DOFF]   Despl. de Datos : {data_offset}  (4 bits)")
    print(f"            Longitud del encabezado TCP")
    print(f"            Tamaño real: {data_offset} x 4 = {header_bytes} Bytes")
    print(f"            Mínimo: 20 Bytes (sin opciones)")
    print(SEP)

    # RESERVED
    print(f"  [RSVD]   Reservado       : (3 bits)")
    print(f"            Debe ser cero")
    print(SEP)

    # FLAGS
    flags_str = ""
    flags_list = []
    
    fin = capa.flags & 0x01
    syn = (capa.flags >> 1) & 0x01
    rst = (capa.flags >> 2) & 0x01
    psh = (capa.flags >> 3) & 0x01
    ack_flag = (capa.flags >> 4) & 0x01
    urg = (capa.flags >> 5) & 0x01
    ece = (capa.flags >> 6) & 0x01
    cwr = (capa.flags >> 7) & 0x01
    ns = (capa.flags >> 8) & 0x01
    
    if fin:
        flags_list.append("FIN")
    if syn:
        flags_list.append("SYN")
    if rst:
        flags_list.append("RST")
    if psh:
        flags_list.append("PSH")
    if ack_flag:
        flags_list.append("ACK")
    if urg:
        flags_list.append("URG")
    if ece:
        flags_list.append("ECE")
    if cwr:
        flags_list.append("CWR")
    if ns:
        flags_list.append("NS")
    
    flags_str = ", ".join(flags_list) if flags_list else "None"
    
    print(f"  [FLAGS]  Banderas        : 0x{capa.flags:03X}  ({capa.flags:09b}b)  (9 bits)")
    print(f"            Banderas activas: {flags_str}")
    print(f"            FIN (Finalizar)  : {fin}")
    print(f"            SYN (Sincronizar): {syn}")
    print(f"            RST (Reset)      : {rst}")
    print(f"            PSH (Push)       : {psh}")
    print(f"            ACK (Reconocim.) : {ack_flag}")
    print(f"            URG (Urgente)    : {urg}")
    print(f"            ECE (ECN Echo)   : {ece}")
    print(f"            CWR (Congestion) : {cwr}")
    print(f"            NS (Nonce Sum)   : {ns}")
    print(SEP)

    # WINDOW SIZE
    window = capa.window
    print(f"  [WIND]   Tamaño Ventana  : {window} Bytes  (16 bits)")
    print(f"            Bytes que el remitente está dispuesto a recibir")
    print(f"            Control de flujo (flow control)")
    print(SEP)

    # CHECKSUM
    chk = capa.chksum
    print(f"  [CHKS]   Suma verific.   : 0x{chk:04X}  (16 bits)")
    print(f"            CRC del encabezado TCP + datos")
    print(f"            Incluye pseudo-encabezado IP")
    print(SEP)

    # URGENT POINTER
    if urg:
        urgent = capa.urgptr
        print(f"  [URG]    Puntero Urgente : {urgent}  (16 bits)")
        print(f"            Offset del dato urgente")
        print(f"            Valido solo si flag URG está activo")
        print(SEP)

    # OPTIONS
    if data_offset > 5 and hasattr(capa, 'options'):
        opt_bytes = header_bytes - 20
        print(f"  [OPT]    Opciones        : {opt_bytes} Bytes")
        print(f"            Opciones TCP (MSS, Window Scale, SACK, Timestamps, etc.)")
        
        # Intentar mostrar opciones específicas
        options = capa.options if capa.options else []
        if options:
            for opt in options:
                if isinstance(opt, tuple):
                    opt_name, opt_val = opt
                    print(f"              • {opt_name}: {opt_val}")
        print(SEP)

    # PAYLOAD DATA
    if capa.payload and len(capa.payload) > 0:
        payload_len = len(capa.payload)
        print(f"  [DATA]   Datos           : {payload_len} Bytes")
        print(f"            Datos de la aplicación (HTTP, SSH, etc.)")
        print(SEP)

    # ANÁLISIS DE ESTADO DE CONEXIÓN
    print(f"  [STATE]  Estado de Conexión (basado en flags):")
    if syn and not ack_flag:
        print(f"            → SYN: Inicio de conexión (cliente → servidor)")
    elif syn and ack_flag:
        print(f"            → SYN-ACK: Aceptación de conexión (servidor → cliente)")
    elif ack_flag and not syn and not fin:
        print(f"            → ACK: Reconocimiento/datos")
    elif fin and ack_flag:
        print(f"            → FIN-ACK: Cierre de conexión")
    elif rst:
        print(f"            → RST: Reset/cierre forzado de conexión")
    elif psh and ack_flag:
        print(f"            → PSH-ACK: Datos con push (envío inmediato)")
    print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [CARACT] Características de TCP:")
    print(f"            • Confiable: garantiza entrega")
    print(f"            • Ordenado: mantiene orden de datos")
    print(f"            • Sin duplicados: detecta y descarta duplicados")
    print(f"            • Control de flujo: window size")
    print(f"            • Control de congestión: algoritmos (Reno, CUBIC, etc.)")
    print(f"            • Orientado a conexión: 3-way handshake")
    print(SEP)

    print(f"  [3WAY]   3-Way Handshake (establecimiento de conexión):")
    print(f"            1. Cliente envía SYN (seq=X)")
    print(f"            2. Servidor responde SYN-ACK (seq=Y, ack=X+1)")
    print(f"            3. Cliente envía ACK (seq=X+1, ack=Y+1)")
    print(SEP)

    print(f"  [CLOSE]  Cierre de conexión (4-Way Handshake):")
    print(f"            1. Origen envía FIN")
    print(f"            2. Destino responde ACK")
    print(f"            3. Destino envía FIN")
    print(f"            4. Origen responde ACK")
    print(SEP)

    print(f"  [CASOS]  Casos de uso:")
    print(f"            • HTTP/HTTPS (web)")
    print(f"            • SSH (terminal remota)")
    print(f"            • SMTP/POP3/IMAP (correo)")
    print(f"            • FTP (transferencia de archivos)")
    print(f"            • Telnet (terminal insegura)")
    print(f"            • Cualquier aplicación que necesite confiabilidad")
    print(SEP)

    print(f"  [PERF]   Consideraciones de rendimiento:")
    print(f"            • Latencia más alta que UDP (3-way handshake)")
    print(f"            • Overhead de control más alto")
    print(f"            • Mejor para datos críticos que deben llegar")
    print(f"            • Retransmisión automática de datos perdidos")
    print(SEP)

# --------------------------------------------------------------------------

# PROTOCOLO UDP
def analizar_udp(capa):
    """
    Datagrama UDP - User Datagram Protocol
    Protocolo 17 - Transporte sin conexión (Capa 4)
    Campos: SOURCE_PORT DEST_PORT LENGTH CHECKSUM DATA
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   UDP - User Datagram Protocol")
    print(f"            Protocolo de transporte sin conexión (Capa 4)")
    print(f"            Protocolo 17 dentro de IP")
    print(SEP)

    # SOURCE PORT
    sport = capa.sport
    print(f"  [SPORT]  Puerto Origen   : {sport}  (16 bits)")
    print(f"            Puerto fuente del datagrama UDP")
    print(SEP)

    # DESTINATION PORT
    dport = capa.dport
    print(f"  [DPORT]  Puerto Destino  : {dport}  (16 bits)")
    print(f"            Puerto destino del datagrama UDP")
    print(SEP)

    # LENGTH
    length = capa.len
    payload_len = length - 8
    print(f"  [LEN]    Longitud Total  : {length} Bytes  (16 bits)")
    print(f"            Longitud = Encabezado (8) + Datos ({payload_len})")
    print(f"            Tamaño completo del datagrama UDP")
    print(SEP)

    # CHECKSUM
    chk = capa.chksum
    if chk == 0:
        chk_status = "DESHABILITADO (0x0000)"
    else:
        chk_status = f"0x{chk:04X}"
    print(f"  [CHKS]   Suma verific.   : {chk_status}  (16 bits)")
    print(f"            CRC del encabezado UDP + datos")
    print(f"            Si es 0, el checksum está deshabilitado")
    print(f"            Incluye pseudo-encabezado IP para validación")
    print(SEP)

    # PAYLOAD DATA
    if capa.payload and len(capa.payload) > 0:
        payload_len = len(capa.payload)
        print(f"  [DATA]   Datos           : {payload_len} Bytes")
        print(f"            Carga útil (payload) del datagrama UDP")
        print(SEP)
    else:
        print(f"  [DATA]   Datos           : 0 Bytes")
        print(f"            Datagrama vacío (solo encabezado)")
        print(SEP)
    
# --------------------------------------------------------------------------

# PROTOCOLO DCCP
def analizar_dccp(capa):
    """
    Datagrama DCCP - Datagram Congestion Control Protocol
    Protocolo 33 - Transporte confiable con baja latencia
    Campos: SOURCE_PORT DEST_PORT SEQ_NUM CHECKSUM TYPE CODE OPTIONS DATA
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   DCCP - Datagram Congestion Control Protocol")
    print(f"            Protocolo de transporte (Capa 4)")
    print(f"            Confiable pero optimizado para baja latencia")
    print(f"            Usado en streaming de video/audio en tiempo real")
    print(SEP)

    # SOURCE PORT
    sport = capa.sport if hasattr(capa, 'sport') else 0
    print(f"  [SPORT]  Puerto Origen   : {sport}  (16 bits)")
    print(f"            Puerto fuente del datagrama")
    print(SEP)

    # DESTINATION PORT
    dport = capa.dport if hasattr(capa, 'dport') else 0
    print(f"  [DPORT]  Puerto Destino  : {dport}  (16 bits)")
    print(f"            Puerto destino del datagrama")
    print(SEP)

    # SEQUENCE NUMBER
    seq = capa.seq if hasattr(capa, 'seq') else 0
    print(f"  [SEQ]    Núm. Secuencia  : {seq}  (24 bits)")
    print(f"            Número de secuencia del paquete DCCP")
    print(f"            Para detectar pérdida de paquetes")
    print(SEP)

    # CHECKSUM
    chk = capa.chksum if hasattr(capa, 'chksum') else 0
    print(f"  [CHKS]   Suma verific.   : 0x{chk:04X}  (16 bits)")
    print(f"            CRC de encabezado + datos DCCP")
    print(SEP)

    # TYPE
    pkt_type = capa.type if hasattr(capa, 'type') else 0
    pkt_type_desc = DCCP_TYPE_TABLA.get(pkt_type, f"Tipo {pkt_type}  desconocido")
    print(f"  [TYPE]   Tipo Paquete    : {pkt_type}  (4 bits)")
    print(f"            Descripción   : {pkt_type_desc}")
    print(SEP)

    # RESERVED
    reserved = (capa.x_bit if hasattr(capa, 'x_bit') else 0)
    print(f"  [RSVD]   X (Extensión)   : {reserved}")
    print(f"            Indica si hay campos extendidos de secuencia")
    print(SEP)

    # CODE (subtipo del paquete)
    code = capa.code if hasattr(capa, 'code') else 0
    code_desc = DCCP_CODE_TABLA.get(code, f"Código {code}  desconocido")
    print(f"  [CODE]   Código          : {code}  (4 bits)")
    print(f"            Descripción   : {code_desc}")
    print(f"            Subtipo específico del paquete DCCP")
    print(SEP)

    # CCVAL (Congestion Control Validation)
    ccval = capa.ccval if hasattr(capa, 'ccval') else 0
    print(f"  [CCVAL]  CC Validation   : {ccval}  (4 bits)")
    print(f"            Valor para validación de control de congestión")
    print(SEP)

    # DATA LENGTH
    data_len = capa.data_offset if hasattr(capa, 'data_offset') else 0
    print(f"  [DLEN]   Long. Datos     : {data_len} Bytes")
    print(f"            Longitud de los datos encapsulados")
    print(SEP)

    # OPTIONS (si las hay)
    if hasattr(capa, 'options') and capa.options:
        print(f"  [OPT]    Opciones        : (presentes)")
        print(f"            Parámetros adicionales de DCCP")
        print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [CARACT] Características de DCCP:")
    print(f"            • Orientado a datagramas (como UDP)")
    print(f"            • Control de congestión (como TCP)")
    print(f"            • Baja latencia (mejor que TCP)")
    print(f"            • Pérdida de paquetes tolerada")
    print(SEP)

    print(f"  [CASOS]  Casos de uso:")
    print(f"            • Streaming de video/audio en tiempo real")
    print(f"            • Videojuegos en línea")
    print(f"            • Conferencias de voz/video (VoIP)")
    print(f"            • Aplicaciones sensibles a latencia")
    print(SEP)

    print(f"  [NOTA]   DCCP es menos común que TCP/UDP")
    print(f"            Soporte limitado en sistemas operativos")
    print(f"            Proporciona alternativa equilibrada entre UDP y TCP")
    
# ----------------- SCTP -----------------------
def analizar_sctp(capa):
    """
    Datagrama SCTP - Stream Control Transmission Protocol
    Protocolo 132 - Transporte confiable multistream
    Campos: SOURCE_PORT DEST_PORT VTAG CHECKSUM CHUNKS
    """
    SEP = "  " + "." * 58

    print(f"  [INFO]   SCTP - Stream Control Transmission Protocol")
    print(f"            Protocolo de transporte (Capa 4)")
    print(f"            Confiable como TCP pero con múltiples streams")
    print(f"            Usado en telefonía y señalización (SIGTRAN)")
    print(SEP)

    # SOURCE PORT
    sport = capa.sport if hasattr(capa, 'sport') else 0
    print(f"  [SPORT]  Puerto Origen   : {sport}  (16 bits)")
    print(f"            Puerto fuente del datagrama SCTP")
    print(SEP)

    # DESTINATION PORT
    dport = capa.dport if hasattr(capa, 'dport') else 0
    print(f"  [DPORT]  Puerto Destino  : {dport}  (16 bits)")
    print(f"            Puerto destino del datagrama SCTP")
    print(SEP)

    # VERIFICATION TAG
    vtag = capa.vtag if hasattr(capa, 'vtag') else 0
    print(f"  [VTAG]   Etiqueta Verif. : 0x{vtag:08X}  (32 bits)")
    print(f"            Verification Tag - identifica la asociación SCTP")
    print(f"            Previene spoofing de direcciones")
    print(SEP)

    # CHECKSUM
    chk = capa.chksum if hasattr(capa, 'chksum') else 0
    print(f"  [CHKS]   Suma verific.   : 0x{chk:08X}  (32 bits)")
    print(f"            CRC-32 de todo el datagrama SCTP")
    print(f"            Valida integridad del paquete")
    print(SEP)

    # CHUNKS
    if hasattr(capa, 'chunks') and capa.chunks:
        print(f"  [CHUNKS] Fragmentos      : {len(capa.chunks)} chunks")
        print(f"            Bloques de datos/control en el paquete")
        print(SEP)
        
        for i, chunk in enumerate(capa.chunks, 1):
            if hasattr(chunk, 'type'):
                chunk_type = chunk.type
                chunk_type_desc = SCTP_CHUNK_TYPE_TABLA.get(chunk_type, f"Tipo {chunk_type}  desconocido")
                print(f"            Chunk {i}:")
                print(f"              Tipo      : {chunk_type}  ->  {chunk_type_desc}")
                
                if hasattr(chunk, 'flags'):
                    print(f"              Flags     : 0x{chunk.flags:02X}")
                
                if hasattr(chunk, 'length'):
                    print(f"              Longitud  : {chunk.length} Bytes")
    else:
        print(f"  [CHUNKS] Fragmentos      : (presentes)")
        print(f"            Bloques de datos/control")
        print(SEP)

    # INFORMACIÓN SOBRE ASOCIACIÓN SCTP
    print(f"  [ASOC]   Asociación SCTP")
    print(f"            VTAG identifica la asociación entre endpoints")
    print(f"            Similar a conexión en TCP pero más flexible")
    print(SEP)

    # INFORMACIÓN GENERAL
    print(f"  [CARACT] Características de SCTP:")
    print(f"            • Confiable (como TCP)")
    print(f"            • Multistream (múltiples flujos en una asociación)")
    print(f"            • Multihoming (múltiples direcciones IP)")
    print(f"            • Orientado a mensajes (no a bytes como TCP)")
    print(f"            • Control de congestión (como TCP)")
    print(SEP)

    print(f"  [CASOS]  Casos de uso:")
    print(f"            • Telefonía VoIP (SIGTRAN)")
    print(f"            • Señalización de redes móviles")
    print(f"            • DNS sobre SCTP")
    print(f"            • M2UA, M3UA, SUA (protocolos de señalización)")
    print(f"            • Aplicaciones que necesitan múltiples streams")
    print(SEP)

    print(f"  [NOTA]   SCTP es menos común que TCP/UDP")
    print(f"            Soporte principalmente en servidores de telefonía")
    print(f"            Combina ventajas de TCP (confiabilidad)")
    print(f"            con ventajas de UDP (orientado a mensajes)")