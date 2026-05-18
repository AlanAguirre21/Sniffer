from protocol_map import *
# PROTOCOLO TCP
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

# PROTOCOLO UDP
def _analizar_udp(capa):
    SEP = "  " + "." * 58
    print(f"  [SPT]  Puerto Origen   : {capa.sport}")
    print(f"  [DPT]  Puerto Destino  : {capa.dport}")
    print(SEP)
    print(f"  [LEN]  Longitud        : {capa.len} Bytes  (encabezado UDP + datos)")
    print(f"  [CHK]  Checksum        : 0x{capa.chksum:04X}")
    

# --------------------------------------------------------------------------

# PROTOCOLO DCCP
def _analizar_dccp(capa):
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
def _analizar_sctp(capa):
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