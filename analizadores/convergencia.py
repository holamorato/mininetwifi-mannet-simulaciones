from scapy.utils import PcapNgReader
from scapy.layers.dot11 import Dot11
from scapy.layers.l2 import LLC, SNAP
from scapy.layers.inet import UDP, IP
from scapy.all import raw
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Analizar OGMs de B.A.T.M.A.N.')
    parser.add_argument('--pcapng', type=str, required=True, help='Ruta del archivo .pcapng')
    return parser.parse_args()

def process_packets(args):
    with PcapNgReader(args.pcapng) as pcap:
        return list(pcap)

def extract_batman_ogms(packets):
    ogm_list = []
    for pkt in packets:
        try:
            # 1. Filtrar por capas 802.11/LLC/SNAP/IP/UDP
            if not (Dot11 in pkt and LLC in pkt and SNAP in pkt):
                continue
            snap = pkt[SNAP]
            if snap.OUI != 0x000000 or snap.code != 0x0800:
                continue
            ip_pkt = IP(snap.payload.load)
            if UDP not in ip_pkt or ip_pkt.dport != 4305:
                continue

            # 2. Extraer payload UDP
            udp_layer = ip_pkt[UDP]
            payload = raw(udp_layer.payload)
            
            # 3. Tamaño de cada OGM según estructura del frame (20 bytes)
            ogm_size = 20  # Ajustado según el frame proporcionado
            offset = 0
            
            # 4. Iterar sobre cada OGM en el payload
            while offset + ogm_size <= len(payload):
                ogm = payload[offset:offset+ogm_size]
                
                # Extraer seqno (bytes 6-9 del payload, big-endian)
                seqno = int.from_bytes(ogm[6:10], byteorder='big')
                originator = f"{ogm[10]}.{ogm[11]}.{ogm[12]}.{ogm[13]}"
                
                ogm_list.append({
                    'seqno': seqno,
                    'originator': originator,
                    'timestamp': pkt.time
                })
                offset += ogm_size

        except Exception as e:
            continue

    return ogm_list

if __name__ == '__main__':
    args = parse_args()
    packets = process_packets(args)
    ogms = extract_batman_ogms(packets)
    
    print(f"\nResumen:")
    print(f"- Paquetes procesados: {len(packets)}")
    print(f"- OGMs detectados: {len(ogms)}")
    if ogms:
        print("\nEjemplo de OGMs detectados:")
        for ogm in ogms[:5]:
            print(f"Seq={ogm['seqno']} | Origen={ogm['originator']} | T={ogm['timestamp']:.2f}")