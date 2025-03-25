import argparse
from scapy.all import PcapNgReader, UDP

def show_udp_payload(file_path, packet_number=5):
    counter = 0
    with PcapNgReader(file_path) as pcap:
        for pkt in pcap:
            if UDP in pkt and pkt[UDP].dport == 4305:
                counter += 1
                if counter == packet_number:
                    payload = bytes(pkt[UDP].payload)
                    print(f"=== Paquete UDP número {packet_number} ===")
                    print(f"Longitud: {len(payload)} bytes")
                    print("Hexadecimal:")
                    print(payload.hex(" "))
                    print("ASCII:")
                    print(payload.decode("ascii", errors="replace"))
                    return
    
    print(f"Solo se encontraron {counter} paquetes UDP en el puerto 4305")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Muestra payload del 5º paquete BATMAN")
    parser.add_argument("--archivo", required=True)
    args = parser.parse_args()
    
    show_udp_payload(args.archivo, 5)