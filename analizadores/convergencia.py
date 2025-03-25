import argparse
from scapy.all import *
from scapy.layers.inet import UDP

def parse_ogm(ogm_data):
    """Analiza los datos binarios de un paquete OGM B.A.T.M.A.N"""
    if len(ogm_data) < 20:
        return None  # Longitud mínima asumida para OGM
    
    parsed = {
        'version': ogm_data[0],
        'flags': ogm_data[1],
        'sequence_number': int.from_bytes(ogm_data[4:8], byteorder='big'),
        'originator': ':'.join(f'{b:02x}' for b in ogm_data[8:14]),
        'raw_hex': ogm_data.hex(),
        'raw_data': ogm_data
    }
    return parsed

def process_pcap(file_path):
    """Procesa el archivo pcapng y encuentra el primer OGM"""
    reader = PcapNgReader(file_path)
    for pkt in reader:
        if UDP in pkt and pkt[UDP].dport == 4305:
            udp_payload = bytes(pkt[UDP].payload)
            if not udp_payload:
                continue
            
            # Extraer primer OGM (asumiendo que ocupa todo el payload)
            ogm = parse_ogm(udp_payload)
            if ogm:
                reader.close()
                return ogm
    reader.close()
    return None

def main():
    parser = argparse.ArgumentParser(description='Analizador de OGM B.A.T.M.A.N')
    parser.add_argument('--archivo', required=True, help='Ruta al archivo .pcapng')
    args = parser.parse_args()

    ogm = process_pcap(args.archivo)
    
    if ogm:
        print("[+] Primer OGM encontrado:")
        print(f"Versión: {ogm['version']}")
        print(f"Flags: 0x{ogm['flags']:02x}")
        print(f"Número de secuencia: {ogm['sequence_number']}")
        print(f"Originator: {ogm['originator']}")
        print(f"Raw data (hex): {ogm['raw_hex']}")
    else:
        print("[-] No se encontraron paquetes OGM B.A.T.M.A.N")

if __name__ == '__main__':
    main()