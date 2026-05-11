from scapy.all import sniff
import logging

import capture

logging.basicConfig(level=logging.INFO) #Cambiar a WARNING para forma silenciosa
logger = logging.getLogger(__name__)

class Analisis:
    def __init__(self):
        self.framesEthernet = []
        self.datagramEthernet = []
        self.TCPsegment_UDPdatagram = []
        self.rawContent = []
        self.data = []
        
    @staticmethod
    def show_packet(packages):        
        for package in packages:
        
            for idx, pkt in enumerate(package):
                print(f"PAQUETE {idx+1}:")
                '''
                if "Ether" in pkt:
                    frame_ethernet = pkt["Ether"]
                    print(f"{frame_ethernet.dst}")
                    print(f"{frame_ethernet.src}")
                    print(f"{frame_ethernet.type}")
                '''
                for i, layer_name in enumerate(pkt.layers()):
                    layer = pkt[layer_name]
                    #print(type(layer.name))
                    #print(layer.name)
                    print('-'*50)
                    print(f" Capa {i+1}: {layer.name}")
                    print('-'*50)
                    
                    for field, value in layer.fields.items():
                        if isinstance(value, bytes):
                            print(f"- {field}: {value.hex()}")
                        else:
                            print(f"- {field}: {value}")
                