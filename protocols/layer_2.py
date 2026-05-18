from analisis import Analisis
from protocol_map import ETHERTYPE_TABLA

# FRAME ETHERNET
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
        desc_tipo = f"Longitud del campo DATOS = {tipo_val} Bytes"
    else:
        nombre = ETHERTYPE_TABLA.get(tipo_val, "Ethertype desconocido")
        desc_tipo = f"Ethertype 0x{tipo_val:04X}  ->  {nombre}"

    print(f"  [TYP]  Tipo / Longitud : 0x{tipo_val:04X}  ({tipo_val})  (2 Bytes)")
    print(f"           Interpretacion: {desc_tipo}")
    print(f"           Tipo de frame : {tipo_frame}")
    print(SEP)

    # DATOS + FCS
    print("  [DAT]  Campo de datos  : 46 - 1,500 Bytes  (LLC / IP / ARP / ...)")
    print("  [FCS]  Sec. verificac. : 4 Bytes  CRC-32  (gestionado por la NIC)")