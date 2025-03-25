from scapy.all import *
from scapy.packet import Packet, bind_layers
from scapy.fields import *
import argparse

# 1. Definir la estructura del OGM de BATMAN
class BATMAN_OGM(Packet):
    name = "BATMAN_OGM"
    fields_desc = [
        ByteField("version", 5),          # Versión 5 (según tu captura)
        ByteField("flags", 0),            # Flags (0x00 en tu ejemplo)
        ByteField("ttl", 0),              # TTL (47 y 48 en tu captura)
        ByteField("gw_flags", 0),         # Gateway Flags (0x00)
        IntField("seqno", 0),             # Seqno (30 en tu captura)
        ShortField("gw_port", 4305),      # Puerto Gateway (4306)
        IPField("orig_addr", "0.0.0.0"),  # Originador (ej: 10.0.0.12)
        IPField("recv_addr", "0.0.0.0"),  # Recibido de (ej: 10.0.0.10)
        ByteField("tq", 0),               # Calidad (73 y 114 en tu captura)
        ByteField("hna_len", 0)           # Número de HNAs (0)
    ]

# 2. Asociar BATMAN_OGM al puerto UDP 4305
bind_layers(UDP, BATMAN_OGM, dport=4305)
bind_layers(UDP, BATMAN_OGM, sport=4305)

def parse_args():
    parser = argparse.ArgumentParser(description='Analizar OGMs de B.A.T.M.A.N.')
    parser.add_argument('--pcapng', type=str, required=True, help='Ruta del archivo .pcapng')
    return parser.parse_args()

def analyze_packets(args):
    ogms = []
    packets = rdpcap(args.pcapng)
    
    for pkt in packets:
        # 3. Buscar paquetes UDP/4305 con capa BATMAN_OGM
        if pkt.haslayer(UDP) and (pkt[UDP].dport == 4305 or pkt[UDP].sport == 4305):
            if pkt.haslayer(BATMAN_OGM):
                ogm = pkt[BATMAN_OGM]
                ogms.append({
                    'seqno': ogm.seqno,
                    'originator': ogm.orig_addr,
                    'tq': ogm.tq,
                    'timestamp': pkt.time
                })
                print(f"OGM detectado: Seq={ogm.seqno} | Origen={ogm.orig_addr} | TQ={ogm.tq}")
    
    print(f"\nResumen:")
    print(f"- Paquetes procesados: {len(packets)}")
    print(f"- OGMs detectados: {len(ogms)}")
    if ogms:
        print("\nEjemplo:")
        print(f"Primer OGM: Seq={ogms[0]['seqno']} | Origen={ogms[0]['originator']}")

if __name__ == '__main__':
    args = parse_args()
    analyze_packets(args)