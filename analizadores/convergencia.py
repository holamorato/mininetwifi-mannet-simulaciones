import argparse
from scapy.all import PcapNgReader, UDP

def show_first_udp_payload(file_path):
    with PcapNgReader(file_path) as pcap:
        for pkt in pcap:
            if UDP in pkt and pkt[UDP].dport == 4305:
                payload = bytes(pkt[UDP].payload)
                print("=== Primer paquete UDP (puerto 4305) ===")
                print(f"Longitud del payload: {len(payload)} bytes")
                print("Contenido en hexadecimal:")
                print(payload.hex(" "))
                return
    
    print("No se encontraron paquetes UDP en el puerto 4305")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Muestra payload del primer paquete BATMAN")
    parser.add_argument("--archivo", required=True, help="Ruta al archivo .pcapng")
    args = parser.parse_args()
    
    show_first_udp_payload(args.archivo)