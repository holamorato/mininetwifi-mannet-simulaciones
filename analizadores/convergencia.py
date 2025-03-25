import argparse
from scapy.all import *
from scapy.layers.inet import UDP

class BATMAN_OGM(Packet):
    name = "BATMAN OGM v5"
    fields_desc = [
        ByteField("version", 5),
        ByteField("flags", 0),
        ByteField("ttl", 0),
        ByteField("gw_flags", 0),
        ShortField("sequence", 0),
        ShortField("gw_port", 4305),
        IPField("originator", "0.0.0.0"),
        IPField("received_from", "0.0.0.0"),
        ByteField("tx_quality", 0),
        ByteField("hna_count", 0)
    ]  # 18 bytes total

bind_layers(UDP, BATMAN_OGM, dport=4305)

def process_packet(payload):
    """Procesa todos los OGMs de 18 bytes en el payload"""
    ogm_size = 18
    return [BATMAN_OGM(payload[i:i+ogm_size]) for i in range(0, len(payload), ogm_size) 
            if len(payload[i:i+ogm_size]) == ogm_size]

def main():
    parser = argparse.ArgumentParser(description="Analizador de primeros 10 paquetes BATMAN")
    parser.add_argument("--archivo", required=True)
    args = parser.parse_args()
    
    packet_count = 0
    results = []
    
    with PcapNgReader(args.archivo) as pcap:
        for pkt in pcap:
            if UDP in pkt and pkt[UDP].dport == 4305:
                packet_count += 1
                payload = bytes(pkt[UDP].payload)
                ogms = process_packet(payload)
                results.append((packet_count, pkt.time , len(payload), ogms))
                
                if packet_count >= 10:
                    break
    
    print(f"=== Resultados ({len(results)} paquetes procesados) ===")
    for pkt_num, timestamp, pkt_len, ogms in results:
        print(f"\n[Paquete {pkt_num}] Tiempo: {timestamp:.6f} | Bytes: {pkt_len}")
        print(f"OGMs detectados: {len(ogms)}")
        
        for ogm_num, ogm in enumerate(ogms, 1):
            print(f"\n  OGM {ogm_num}:")
            print(f"    Versión: {ogm.version}")
            print(f"    TTL: {ogm.ttl}")
            print(f"    Originator: {ogm.originator}")
            print(f"    Recibido de: {ogm.received_from}")
            print(f"    Secuencia: {ogm.sequence}")
            print(f"    Calidad TX: {ogm.tx_quality}")
            print(f"    HNAs: {ogm.hna_count}")
        print("═" * 60)

if __name__ == "__main__":
    main()