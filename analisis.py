from scapy.all import sniff

class Analisis:
    
    @staticmethod
    def analice_packet(package):     
        for i, package in enumerate(package):
            print(f"PAQUETE {i+1}:")
            
            for i, layer_name in enumerate(package.layers()):
                layer = package[layer_name]
                #print(type(layer.name))
                #print(layer.name)
                print('-'*50)
                print(f" Capa{i}: {layer.name}")
                print('-'*50)
                
                for field, value in layer.fields.items():
                    if isinstance(value, bytes):
                        print(f"Campo: {field}: Valor: {value.hex()}")
                    else:
                        print(f"Campo: {field}: Valor: {value}")
                
