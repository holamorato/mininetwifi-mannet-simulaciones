import argparse
from scapy.all import *
from scapy.layers.inet import UDP

class BATMAN_OGM(Packet):
    name = "BATMAN OGM Custom"
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
    ]  # Total: 18 bytes

bind_layers(UDP, BATMAN_OGM, dport=4305)

def process_packet(payload):
    ogms = []
    ogm_size = 18  # Tamaño exacto de tus OGMs
    total_ogms = len(payload) // ogm_size
    
    for i in range(total_ogms):
        start = i * ogm_size
        end = start + ogm_size
        try:
            ogm = BATMAN_OGM(payload[start:end])
            if ogm.version == 5:
                ogms.append(ogm)
        except:
            continue
    
    return ogms

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archivo", required=True)
    args = parser.parse_args()
    
    counter = 0
    with PcapNgReader(args.archivo) as pcap:
        for pkt in pcap:
            if UDP in pkt and pkt[UDP].dport == 4305:
                counter += 1
                if counter == 5:
                    payload = bytes(pkt[UDP].payload)
                    ogms = process_packet(payload)
                    print(f"=== 5º paquete UDP ({len(payload)} bytes) ===")
                    print(f"OGMs detectados: {len(ogms)}\n")
                    
                    for i, ogm in enumerate(ogms, 1):
                        print(f"OGM {i}:")
                        print(f"  Versión: {ogm.version}")
                        print(f"  TTL: {ogm.ttl}")
                        print(f"  Originator: {ogm.originator}")
                        print(f"  Received from: {ogm.received_from}")
                        print(f"  Secuencia: {ogm.sequence}")
                        print(f"  Calidad TX: {ogm.tx_quality}")
                        print("-" * 40)
                    return
    
    print("No se encontró el 5º paquete")

if __name__ == "__main__":
    main()