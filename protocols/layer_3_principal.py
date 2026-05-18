from protocol_map import *
from analisis import _clase_ipv4, _interpretar_mac, _tipo_ip, _tipo_ipv6

# DATAGRAMA IP
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
    clase_s = _clase_ipv4(src)
    tipo_s  = _tipo_ip(src)
    print(f"  [SRC]  IP Fuente       : {src}  (32 bits)")
    print(f"           Clase         : {clase_s}")
    print(f"           Tipo          : {tipo_s}")
    print(SEP)

    # DESTINATION IP
    dst     = capa.dst
    clase_d = _clase_ipv4(dst)
    tipo_d  = _tipo_ip(dst)
    print(f"  [DST]  IP Destino      : {dst}  (32 bits)")
    print(f"           Clase         : {clase_d}")
    print(f"           Tipo          : {tipo_d}")

    # OPTIONS (si las hay)
    if hlen > 5 and capa.options:
        print(SEP)
        opc_bytes = bytes_enc - 20
        print(f"  [OPT]  Opciones        : {opc_bytes} Bytes de opciones")

# --------------------------------------------------------------------------
# DATAGRAMA IPv6
@staticmethod
def _analizar_ipv6(capa):
    """
    Datagrama IPv6 - Presentacion 09
    Campos: VER TC FL PLEN NH HLIM SRC DST
    """
    SEP = "  " + "." * 58

    # VER
    ver = capa.version
    ver_desc = IP_VERSION_TABLA.get(ver, "Valor desconocido")
    print(f"  [VER]  Version         : {ver}  ({ver:04b}b)  (4 bits)")
    print(f"           Interpretacion: {ver_desc}")
    print(SEP)

    # TRAFFIC CLASS (TC) = DSCP (6 bits) + ECN (2 bits)
    tc   = capa.tc
    dscp = tc >> 2
    ecn  = tc & 0b11
    dscp_desc = DSCP_TABLA.get(dscp, f"Codigo DSCP {dscp}  sin clasificar en el curso")
    ecn_desc  = ECN_TABLA.get(ecn, "Valor ECN desconocido")
    print(f"  [TC]   Clase Trafico   : 0x{tc:02X}  ({tc:08b}b)  (8 bits)")
    print(f"           DSCP (6 bits) : {dscp:06b}b = {dscp}  ->  {dscp_desc}")
    print(f"           ECN  (2 bits) : {ecn:02b}b         ->  {ecn_desc}")
    print(SEP)

    # FLOW LABEL
    fl = capa.fl
    print(f"  [FL]   Etiqueta Flujo  : {fl}  (0x{fl:05X})  (20 bits)")
    print(f"           Identifica flujos de trafico que requieren tratamiento especial")
    print(SEP)

    # PAYLOAD LENGTH
    plen = capa.plen
    print(f"  [PLEN] Long. Carga     : {plen} Bytes  (16 bits)")
    print(f"           Tamaño de datos despues del encabezado IPv6 (40 Bytes)")
    print(SEP)

    # NEXT HEADER
    nh      = capa.nh
    nh_desc = PROTOCOLO_TABLA.get(nh, f"Protocolo {nh}  (ver Anexo 5 del curso)")
    print(f"  [NH]   Sgte. Encab.    : {nh}  (0x{nh:02X})  (8 bits)")
    print(f"           Protocolo capa superior: {nh_desc}")
    print(SEP)

    # HOP LIMIT
    hlim = capa.hlim
    print(f"  [HLIM] Limite Saltos   : {hlim} saltos restantes  (8 bits)")
    print(f"           Similar a TTL en IPv4; se decrementa 1 por ruteador")
    print(SEP)

    # SOURCE ADDRESS
    src = capa.src
    tipo_s = _tipo_ipv6(src)
    print(f"  [SRC]  Direc. Fuente   : {src}  (128 bits)")
    print(f"           Tipo          : {tipo_s}")
    print(SEP)

    # DESTINATION ADDRESS
    dst = capa.dst
    tipo_d = _tipo_ipv6(dst)
    print(f"  [DST]  Direc. Destino  : {dst}  (128 bits)")
    print(f"           Tipo          : {tipo_d}")
    
# -------------------------------------------------------------------------

# DATAGRAMA ARP   
@staticmethod
def _analizar_arp(capa):
    """
    Datagrama ARP - Address Resolution Protocol
    Campos: HWTYPE PTYPE HWLEN PLEN OP HWSRC PSRC HWDST PDST
    """
    SEP = "  " + "." * 58

    # HARDWARE TYPE
    hwtype = capa.hwtype
    hwtype_desc = HWTYPE_TABLA.get(hwtype, f"Tipo hardware {hwtype}  desconocido")
    print(f"  [HWTYPE] Tipo Hardware  : {hwtype}  (16 bits)")
    print(f"            Descripción   : {hwtype_desc}")
    print(SEP)

    # PROTOCOL TYPE
    ptype = capa.ptype
    ptype_desc = PTYPE_TABLA.get(ptype, f"Tipo protocolo {ptype}  desconocido")
    print(f"  [PTYPE]  Tipo Protocolo : 0x{ptype:04X}  (16 bits)")
    print(f"            Descripción   : {ptype_desc}")
    print(SEP)

    # HARDWARE ADDRESS LENGTH
    hwlen = capa.hwlen
    print(f"  [HWLEN]  Long. Dir. HW  : {hwlen} Bytes  (8 bits)")
    print(f"            Longitud de la dirección hardware (MAC)")
    print(SEP)

    # PROTOCOL ADDRESS LENGTH
    plen = capa.plen
    print(f"  [PLEN]   Long. Dir. Prot: {plen} Bytes  (8 bits)")
    print(f"            Longitud de la dirección de protocolo (IP)")
    print(SEP)

    # OPERATION
    op = capa.op
    op_desc = ARP_OPERATION_TABLA.get(op, f"Operación {op}  desconocida")
    print(f"  [OP]     Operación      : {op}  (16 bits)")
    print(f"            Tipo          : {op_desc}")
    print(SEP)

    # SENDER HARDWARE ADDRESS
    hwsrc = capa.hwsrc
    print(f"  [HWSRC]  Dir. HW Origen : {hwsrc}  ({hwlen} Bytes)")
    print(f"            MAC del dispositivo que envía la solicitud")
    print(SEP)

    # SENDER PROTOCOL ADDRESS
    psrc = capa.psrc
    print(f"  [PSRC]   Dir. IP Origen : {psrc}  ({plen} Bytes)")
    print(f"            IP del dispositivo que envía la solicitud")
    print(SEP)

    # TARGET HARDWARE ADDRESS
    hwdst = capa.hwdst
    print(f"  [HWDST]  Dir. HW Dest.  : {hwdst}  ({hwlen} Bytes)")
    print(f"            MAC del dispositivo destino (vacío en ARP Request)")
    print(SEP)

    # TARGET PROTOCOL ADDRESS
    pdst = capa.pdst
    print(f"  [PDST]   Dir. IP Dest.  : {pdst}  ({plen} Bytes)")
    print(f"            IP del dispositivo destino (a buscar)")
    print(SEP)

    print(f"  [INFO]   ARP resuelve direcciones IP a direcciones MAC")
    print(f"            (mapeo entre Capa 3 e Capa 2)")

# --------------------------------------------------------------------------
# DATAGRAMA RARP
@staticmethod
def _analizar_rarp(capa):
    """
    Datagrama RARP - Reverse Address Resolution Protocol
    Campos: HWTYPE PTYPE HWLEN PLEN OP HWSRC PSRC HWDST PDST
    """
    SEP = "  " + "." * 58

    # HARDWARE TYPE
    hwtype = capa.hwtype
    hwtype_desc = HWTYPE_TABLA.get(hwtype, f"Tipo hardware {hwtype}  desconocido")
    print(f"  [HWTYPE] Tipo Hardware  : {hwtype}  (16 bits)")
    print(f"            Descripción   : {hwtype_desc}")
    print(SEP)

    # PROTOCOL TYPE
    ptype = capa.ptype
    ptype_desc = PTYPE_TABLA.get(ptype, f"Tipo protocolo {ptype}  desconocido")
    print(f"  [PTYPE]  Tipo Protocolo : 0x{ptype:04X}  (16 bits)")
    print(f"            Descripción   : {ptype_desc}")
    print(SEP)

    # HARDWARE ADDRESS LENGTH
    hwlen = capa.hwlen
    print(f"  [HWLEN]  Long. Dir. HW  : {hwlen} Bytes  (8 bits)")
    print(f"            Longitud de la dirección hardware (MAC)")
    print(SEP)

    # PROTOCOL ADDRESS LENGTH
    plen = capa.plen
    print(f"  [PLEN]   Long. Dir. Prot: {plen} Bytes  (8 bits)")
    print(f"            Longitud de la dirección de protocolo (IP)")
    print(SEP)

    # OPERATION
    op = capa.op
    op_desc = RARP_OPERATION_TABLA.get(op, f"Operación {op}  desconocida")
    print(f"  [OP]     Operación      : {op}  (16 bits)")
    print(f"            Tipo          : {op_desc}")
    print(SEP)

    # SENDER HARDWARE ADDRESS
    hwsrc = capa.hwsrc
    print(f"  [HWSRC]  Dir. HW Origen : {hwsrc}  ({hwlen} Bytes)")
    print(f"            MAC del dispositivo que envía la solicitud")
    print(SEP)

    # SENDER PROTOCOL ADDRESS
    psrc = capa.psrc
    print(f"  [PSRC]   Dir. IP Origen : {psrc}  ({plen} Bytes)")
    print(f"            IP del dispositivo que envía la solicitud")
    print(SEP)

    # TARGET HARDWARE ADDRESS
    hwdst = capa.hwdst
    print(f"  [HWDST]  Dir. HW Dest.  : {hwdst}  ({hwlen} Bytes)")
    print(f"            MAC del dispositivo destino (a buscar en RARP Request)")
    print(SEP)

    # TARGET PROTOCOL ADDRESS
    pdst = capa.pdst
    print(f"  [PDST]   Dir. IP Dest.  : {pdst}  ({plen} Bytes)")
    print(f"            IP del dispositivo destino (respuesta esperada)")
    print(SEP)

    print(f"  [INFO]   RARP resuelve la dirección IP a partir de la MAC")
    print(f"            (inverso a ARP: dados MAC y HW, encuentra IP)")