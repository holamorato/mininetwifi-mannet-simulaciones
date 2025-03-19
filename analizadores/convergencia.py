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

    for pkt in packets:
        if Dot11 in pkt and pkt[Dot11].type == 0 and pkt[Dot11].subtype in [0, 1]:
            if pkt[Dot11].addr2 == args.sta1_mac or pkt[Dot11].addr1 == args.sta1_mac:
                assoc_time = pkt.time
                ap_mac = pkt[Dot11].addr3
                assoc_times[ap_mac] = assoc_time
        
        if args.protocol == 'batmand':
            if UDP in pkt and pkt[UDP].dport == 1966 and IP in pkt:
                seqno = pkt[UDP].sport
                ip_src = pkt[IP].src
                if seqno not in ogm_data:
                    ogm_data[seqno] = {}
                ogm_data[seqno][ip_src] = pkt.time
        
        elif args.protocol == 'batman-adv':
            if Dot11 in pkt and pkt[Dot11].type == 2:
                raw_payload = bytes(pkt[Dot11].payload)
                if len(raw_payload) >= 8 and raw_payload[:6] == b'\xaa\xaa\x03\x00\x00\x43':
                    originator_mac = raw_payload[6:12].hex(':')
                    seqno = int.from_bytes(raw_payload[14:16], byteorder='little')
                    forwarder_mac = pkt[Dot11].addr2
                    key = (originator_mac, seqno)
                    if key not in ogm_data:
                        ogm_data[key] = {}
                    ogm_data[key][forwarder_mac] = pkt.time

    return assoc_times, ogm_data

def calculate_convergence(args, assoc_times, ogm_data):
    conv_times = []
    
    for ap_mac, t_assoc in assoc_times.items():
        if args.protocol == 'batmand':
            seqnos = [seqno for seqno in ogm_data if args.sta1_mac in ogm_data[seqno]]
            if not seqnos:
                continue
            first_seqno = min(seqnos)
            if args.sta20_mac in ogm_data[first_seqno]:
                t_conv = ogm_data[first_seqno][args.sta20_mac] - t_assoc
                conv_times.append((t_assoc, t_conv))
        
        elif args.protocol == 'batman-adv':
            sta1_ogms = []
            for key in ogm_data:
                orig_mac, seqno = key
                if orig_mac == args.sta1_mac:
                    # Corrección aquí: 3 paréntesis al final
                    sta1_ogms.append((seqno, min(ogm_data[key].values())))  # <--- ¡Corregido!
            if not sta1_ogms:
                continue
            first_seqno, t_first_ogm = min(sta1_ogms, key=lambda x: x[1])
            if args.sta20_mac in ogm_data[(args.sta1_mac, first_seqno)]:
                t_conv = ogm_data[(args.sta1_mac, first_seqno)][args.sta20_mac] - t_assoc
                conv_times.append((t_assoc, t_conv))
    
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