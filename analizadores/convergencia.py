from scapy.utils import PcapNgReader
from scapy.layers.dot11 import Dot11
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
import matplotlib.pyplot as plt
import argparse
from scapy import config
import os
from datetime import datetime

# Optimización: Desactivar chequeo de capas
config.conf.dot11_ack = False

def parse_args():
    parser = argparse.ArgumentParser(description='Calcula tiempo de convergencia para B.A.T.M.A.N. en .pcapng')
    parser.add_argument('--protocol', type=str, required=True, choices=['batmand', 'batman-adv'], 
                       help='Protocolo a analizar (batmand o batman-adv)')
    parser.add_argument('--pcapng', type=str, required=True, help='Ruta del archivo .pcapng')
    parser.add_argument('--sta1_mac', type=str, default='02:00:00:00:00:01', help='MAC de sta1')
    parser.add_argument('--sta20_mac', type=str, default='02:00:00:00:00:14', help='MAC de sta20')
    return parser.parse_args()

def process_packets(args):
    packets = []
    try:
        with PcapNgReader(args.pcapng) as pcap:
            packet_count = 0
            for pkt in pcap:
                packets.append(pkt)
                packet_count += 1
                if packet_count % 1000 == 0:
                    print(f"Paquetes procesados: {packet_count}")
    except KeyboardInterrupt:
        print("\nLectura interrumpida por el usuario.")
    return packets

def extract_data(args, packets):
    assoc_times = {}
    ogm_data = {}
    
    # Normalizar MACs
    sta1_mac = args.sta1_mac.lower().replace('-', ':')
    sta20_mac = args.sta20_mac.lower().replace('-', ':')

    for pkt in packets:
        # *** Cambio 1: Eliminar detección de asociación (no hay tramas en hwsim0) ***
        
        # *** Cambio 2: Ajustar filtros para batmand (puerto 4305) ***
        if args.protocol == 'batmand':
            if UDP in pkt and pkt[UDP].dport == 4305 and IP in pkt:  # Puerto corregido
                seqno = pkt[UDP].sport
                ip_src = pkt[IP].src
                if seqno not in ogm_data:
                    ogm_data[seqno] = {}
                ogm_data[seqno][ip_src] = pkt.time
        
        # *** Cambio 3: Procesar batman-adv en capa Ethernet ***
        elif args.protocol == 'batman-adv':
            if Ether in pkt and pkt[Ether].type == 0x4305:
                raw_payload = bytes(pkt[Ether].payload)
                if len(raw_payload) >= 16:
                    try:
                        originator_mac = raw_payload[6:12].hex(':')  # Offset corregido
                        seqno = int.from_bytes(raw_payload[14:16], byteorder='little')
                        forwarder_mac = pkt[Ether].src
                        key = (originator_mac, seqno)
                        if key not in ogm_data:
                            ogm_data[key] = {}
                        ogm_data[key][forwarder_mac] = pkt.time
                    except:
                        continue

    return assoc_times, ogm_data

def calculate_convergence(args, assoc_times, ogm_data):
    conv_times = []
    sta1_mac = args.sta1_mac.lower().replace('-', ':')
    
    # *** Cambio 4: Calcular desde el primer OGM (sin eventos de asociación) ***
    if args.protocol == 'batmand':
        seqnos = list(ogm_data.keys())
        if seqnos:
            first_seqno = min(seqnos)
            if args.sta20_mac in ogm_data[first_seqno]:
                t_start = min(ogm_data[first_seqno].values())
                t_end = ogm_data[first_seqno][args.sta20_mac]
                conv_times.append((t_start, t_end - t_start))
    
    elif args.protocol == 'batman-adv':
        sta1_ogms = [k for k in ogm_data if k[0] == sta1_mac]
        if sta1_ogms:
            first_seqno = min(sta1_ogms, key=lambda x: x[1])
            if args.sta20_mac in ogm_data[first_seqno]:
                t_start = min(ogm_data[first_seqno].values())
                t_end = ogm_data[first_seqno][args.sta20_mac]
                conv_times.append((t_start, t_end - t_start))
    
    return conv_times

def plot_results(conv_times, protocol):
    # Crear directorio de salida
    output_dir = os.path.join("graficas", "convergencia", protocol)
    os.makedirs(output_dir, exist_ok=True)
    
    # Generar nombre de archivo único
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"convergencia_{timestamp}.png")
    
    # Generar gráfica
    if not conv_times:
        print("¡No hay datos para graficar!")
        return
    
    timestamps = [t for t, _ in conv_times]
    times = [t - min(timestamps) for t in timestamps]
    conv_values = [ct for _, ct in conv_times]
    
    plt.figure(figsize=(10,5))
    plt.plot(times, conv_values, 'ro-', label=protocol)
    plt.xlabel('Tiempo de Simulación (s)')
    plt.ylabel('Tiempo de Convergencia (s)')
    plt.title(f'Convergencia - {protocol}')
    plt.grid(True)
    plt.legend()
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Gráfica guardada en: {filename}")

if __name__ == '__main__':
    args = parse_args()
    packets = process_packets(args)
    assoc_times, ogm_data = extract_data(args, packets)
    conv_times = calculate_convergence(args, assoc_times, ogm_data)
    plot_results(conv_times, args.protocol)