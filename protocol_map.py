# Protocolos Ethertype

CAPTURE_TYPE_LENGTH = {
    0x0800: "IPv4",
    0x0804: "Chaosnet",
    0x0805: "X.25",
    0x0806: "ARP",
    0x0808: "Frame Relay ARP",
    0x8035: "RARP",
    0x8100: "VLAN",
    0x8138: "IPX",
    0x814C: "SNMP",
    0x86DD: "IPv6",
    0x8808: "EPON",
    0x880B: "PPP",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x888E: "EAPOL",
    0x88A2: "AoE",
    0x88A4: "EtherCAT",
}

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

# ----------------- DATAGRAMA IPv4 ---------------------

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

# --------- RARP ---------
# Tipo de Hardware
HWTYPE_TABLA = {
    0: "Hardware Address Space (Reserved)",
    1: "Ethernet (10Mb)",
    2: "Experimental Ethernet",
    3: "Amateur Radio AX.25",
    4: "Proteon ProNET Token Ring",
    5: "Chaos",
    6: "Token Ring",
    7: "ARCNET",
    8: "ARCNET (Novell)",
    9: "AppleTalk",
    10: "LocalTalk",
    11: "LocalNet (IBM PCNet or SYTEK LocalNET)",
    12: "Ultra Network",
    13: "SMDS",
    14: "Frame Relay",
    15: "ATM",
    16: "HDLC",
    17: "Fibre Channel",
    18: "ATM (RFC 2225)",
    19: "Serial Line",
    20: "ARPSec",
    21: "IPsec tunnel",
    22: "Infiniband",
    23: "TIA-102 Project 25 Common Air Interface (CAI)",
    24: "PowerPC",
    25: "IP and ARP over ISO 7816-3",
    26: "PowerLine",
    27: "Phonetic Devices",
    28: "Proprietary Ethernet",
    29: "Localtalk",
    30: "Smart Cable",
    31: "Ultra Link",
    32: "VLAN",
    33: "IP and ARP over ISO IEC 14443-3",
    34: "Dicops",
    35: "PPP",
    36: "SLIP",
    37: "Netrom",
    38: "Appletalk ADSP",
    39: "AppleTalk over Ethernet",
    40: "ATA over Ethernet",
    41: "Open Standards Interconnection (OSI) model",
    42: "AX.25 over Ethernet",
    43: "All LANs routed to nowhere",
    44: "RFC 1149 IP over Avian Carriers",
    45: "IEEE 1394.1995",
    46: "EUI-64",
    47: "HIPARP",
    48: "IP over ISO 7816-3",
    49: "ARPSec Encrypted ARP",
    50: "Raw Serial Line",
    51: "PPP (Point-to-Point Protocol)",
    52: "Cisco HDLC",
    53: "IEEE 802.15.4 (Wireless Sensor Network)",
    54: "IEEE 802.15.4 (Low-Rate Wireless PAN)",
}

# Tabla de Protocolo
PTYPE_TABLA = {
    0x0800: "IPv4",
    0x0801: "X.75 Internet",
    0x0802: "NBS Internet",
    0x0803: "ECMA Internet",
    0x0804: "Chaosnet",
    0x0805: "X.25 Level 3",
    0x0806: "ARP",
    0x0808: "Frame Relay ARP",
    0x6559: "Transaction Auth (deprecated)",
    0x8035: "RARP",
    0x809B: "AppleTalk",
    0x80F3: "AppleTalk AARP",
    0x8100: "VLAN Tag (802.1q)",
    0x8102: "SLPP",
    0x8103: "VLACP",
    0x8137: "IPX",
    0x8138: "IPX (Novell)",
    0x814C: "SNMP",
    0x86DD: "IPv6",
    0x8808: "EPON",
    0x880B: "PPP",
    0x8847: "MPLS unicast",
    0x8848: "MPLS multicast",
    0x8863: "PPPoE Discovery Stage",
    0x8864: "PPPoE Session Stage",
    0x888E: "EAPOL (EAP over LAN)",
    0x88A2: "AoE (ATA over Ethernet)",
    0x88A4: "EtherCAT",
    0x88CC: "LLDP (Link Layer Discovery Protocol)",
    0x8906: "Fibre Channel over Ethernet",
    0x894F: "DRACP",
    0x9000: "Ethernet Configuration Testing Protocol",
}

# Tabla de operación RARP
RARP_OPERATION_TABLA = {
    1: "RARP Request",
    2: "RARP Reply",
    3: "DRARP Request",
    4: "DRARP Reply",
    5: "DRARP Error",
    6: "InARP Request",
    7: "InARP Reply",
    8: "ARP NAK",
    9: "MARS Request",
    10: "MARS Multi",
    11: "MARS MServ",
    12: "MARS Unserv",
    13: "MARS SJoin",
    14: "MARS SLeave",
    15: "Mars Grouplist Request",
    16: "Mars Grouplist Reply",
    17: "Mars Redirect Map",
    18: "MapOES",
    19: "OP_EXP1",
    20: "OP_EXP2",
}

# -------- ARP -------------

ARP_OPERATION_TABLA = {
    1: "ARP Request",
    2: "ARP Reply",
    3: "RARP Request",
    4: "RARP Reply",
    5: "DRARP Request",
    6: "DRARP Reply",
    7: "DRARP Error",
    8: "InARP Request",
    9: "InARP Reply",
    10: "ARP NAK",
    11: "MARS Request",
    12: "MARS Multi",
    13: "MARS MServ",
    14: "MARS Unserv",
    15: "MARS SJoin",
    16: "MARS SLeave",
    17: "MARS Grouplist Request",
    18: "MARS Grouplist Reply",
    19: "MARS Redirect Map",
    20: "MapOES",
}

# ------------ IGMP ---------------

IGMP_TYPE_TABLA = {
    0x11: "Membership Query",
    0x12: "Version 1 - Membership Report",
    0x13: "DVMRP (Distance Vector Multicast Routing Protocol)",
    0x14: "PIM - Protocol Independent Multicast",
    0x15: "Cisco Trace Messages",
    0x16: "Version 2 - Membership Report",
    0x17: "Version 2 - Leave Group",
    0x22: "Version 3 - Membership Report",
    0x30: "Multicast Router Advertisement",
    0x31: "Multicast Router Solicitation",
    0x32: "Multicast Router Termination",
}

# ------------ GRE ---------------

GRE_VERSION_TABLA = {
    0: "GRE versión 0 (RFC 1701)",
    1: "GRE versión 1 (PPTP GRE)",
    2: "GRE versión 2 (Cisco)",
}

GRE_PROTOCOL_TABLA = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x880B: "PPP",
    0x8137: "IPX",
    0x809B: "AppleTalk",
    0x6558: "DECnet Phase IV",
    0x6559: "DECnet Phase V",
    0x0600: "XEROX PUP",
    0x0BAD: "VLAN",
    0x08FF: "Frame Relay",
}

# ------------- ESP --------------

ESP_CIPHER_TABLA = {
    0: "Reservado",
    1: "DES-CBC",
    2: "IDEA-CBC",
    3: "Blowfish-CBC",
    4: "RC5-CBC",
    5: "3DES-CBC",
    6: "CAST-CBC",
    7: "AES-CBC",
    8: "AES-CTR",
    9: "NULL",
    12: "AES-GCM",
    13: "AES-CCM",
}

ESP_AUTH_TABLA = {
    0: "Reservado",
    1: "HMAC-MD5-96",
    2: "HMAC-SHA-96",
    3: "HMAC-RIPEMD160-96",
    4: "AES-XCBC-MAC-96",
    5: "HMAC-MD5-128",
    6: "HMAC-SHA-256",
    7: "HMAC-SHA-384",
    8: "HMAC-SHA-512",
}

# ------------- AH -------------
AH_ALGORITHM_TABLA = {
    0: "Reservado",
    1: "HMAC-MD5-96",
    2: "HMAC-SHA-96",
    3: "HMAC-RIPEMD-160-96",
    4: "AES-XCBC-MAC-96",
    5: "HMAC-MD5-128",
    6: "HMAC-SHA-1-160",
    7: "HMAC-SHA-256",
    8: "HMAC-SHA-384",
    9: "HMAC-SHA-512",
}

# Mapeo de tamaño de ICV a tipo de algoritmo
AH_ICV_SIZE_TABLA = {
    12: "HMAC-SHA-1-96 (truncado)",
    16: "HMAC-MD5-128 o HMAC-SHA-1-128",
    20: "HMAC-SHA-1-160 (completo)",
    32: "HMAC-SHA-256 (completo)",
    48: "HMAC-SHA-384 (completo)",
    64: "HMAC-SHA-512 (completo)",
}

# -------------- DCCP --------------
DCCP_TYPE_TABLA = {
    0: "Request",
    1: "Response",
    2: "Data",
    3: "Ack",
    4: "DataAck",
    5: "CloseReq",
    6: "Close",
    7: "Reset",
    8: "Sync",
    9: "SyncAck",
}

DCCP_CODE_TABLA = {
    0: "normal",
    1: "Ack_Vector (option required)",
    2: "CCID Option (option required)",
    3: "Request_Ack_vector",
    4: "Response_Ack_vector",
    5: "Close_Ack",
    6: "Reset_Ack",
    7: "Sync_Ack",
    8: "Data_Ack (normal acknowledgement)",
    9: "Ack_vector_for_data",
    10: "Explicit_Congestion_Notification",
    11: "Feature_Negotiation",
    12: "Partial_Reliability_Option",
    13: "Reserved",
    14: "Reserved",
    15: "Reserved",
}

# ------------ SCTP -----------------
SCTP_CHUNK_TYPE_TABLA = {
    0: "DATA",
    1: "INIT",
    2: "INIT-ACK",
    3: "SACK (Selective Acknowledgement)",
    4: "HEARTBEAT",
    5: "HEARTBEAT-ACK",
    6: "ABORT",
    7: "SHUTDOWN",
    8: "SHUTDOWN-ACK",
    9: "ERROR",
    10: "COOKIE-ECHO",
    11: "COOKIE-ACK",
    12: "ECNE (Explicit Congestion Notification Echo)",
    13: "CWR (Congestion Window Reduced)",
    14: "SHUTDOWN-COMPLETE",
    15: "AUTH",
    16: "ASCONF-ACK",
    17: "RE-CONFIG",
    18: "PAD",
    19: "FORWARD-TSN",
    20: "ASCONF",
}

SCTP_CHUNK_FLAGS_TABLA = {
    0x00: "No flags",
    0x01: "Beginning of message",
    0x02: "End of message",
    0x03: "Complete message",
}