from scapy.utils import PcapNgReader
from scapy.layers.dot11 import Dot11
from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP, IP
import matplotlib.pyplot as plt
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Calcula tiempo de convergencia para B.A.T.M.A.N. en .pcapng')
    parser.add_argument('--protocol', type=str, required=True, choices=['batmand', 'batman-adv'], 
                       help='Protocolo a analizar (batmand o batman-adv)')
    parser.add_argument('--pcapng', type=str, required=True, help='Ruta del archivo .pcapng')
    parser.add_argument('--sta1_mac', type=str, default='00:00:00:00:00:01', help='MAC de sta1')
    parser.add_argument('--sta20_mac', type=str, default='00:00:00:00:00:14', help='MAC de sta20')
    return parser.parse_args()

def process_packets(args):
    packets = []
    with PcapNgReader(args.pcapng) as pcap:
        for pkt in pcap:
            packets.append(pkt)
    return packets

def extract_data(args, packets):
    assoc_times = {}
    ogm_data = {}

    for pkt in packets:
        # Detectar asociaciones (802.11)
        if Dot11 in pkt and pkt[Dot11].type == 0 and pkt[Dot11].subtype in [0, 1]:
            if pkt[Dot11].addr2 == args.sta1_mac or pkt[Dot11].addr1 == args.sta1_mac:
                assoc_time = pkt.time
                ap_mac = pkt[Dot11].addr3
                assoc_times[ap_mac] = assoc_time
        
        # Procesar protocolos
        if args.protocol == 'batmand':
            if UDP in pkt and pkt[UDP].dport == 1966 and IP in pkt:
                seqno = pkt[UDP].sport
                ip_src = pkt[IP].src
                if seqno not in ogm_data:
                    ogm_data[seqno] = {}
                ogm_data[seqno][ip_src] = pkt.time
        
        elif args.protocol == 'batman-adv':
            if Dot11 in pkt and pkt[Dot11].type == 2:  # Data frame
                raw_payload = bytes(pkt[Dot11].payload)
                # Buscar encapsulación Ethernet (LLC/SNAP + 0x4305)
                if len(raw_payload) >= 8 and raw_payload[:6] == b'\xaa\xaa\x03\x00\x00\x43':
                    originator_mac = raw_payload[6:12].hex(':')
                    seqno = int.from_bytes(raw_payload[14:16], byteorder='little')
                    forwarder_mac = pkt[Dot11].addr2  # MAC del nodo que reenvía
                    key = (originator_mac, seqno)
                    if key not in ogm_data:
                        ogm_data[key] = {}
                    ogm_data[key][forwarder_mac] = pkt.time

    return assoc_times, ogm_data

def calculate_convergence(args, assoc_times, ogm_data):
    conv_times = []
    
    for ap_mac, t_assoc in assoc_times.items():
        if args.protocol == 'batmand':
            # Buscar OGMs de sta1 (IP)
            seqnos = [seqno for seqno in ogm_data if args.sta1_mac in ogm_data[seqno]]
            if not seqnos:
                continue
            first_seqno = min(seqnos)
            if args.sta20_mac in ogm_data[first_seqno]:
                t_conv = ogm_data[first_seqno][args.sta20_mac] - t_assoc
                conv_times.append((t_assoc, t_conv))
        
        elif args.protocol == 'batman-adv':
            # Buscar OGMs de sta1 (MAC)
            sta1_ogms = []
            for key in ogm_data:
                orig_mac, seqno = key
                if orig_mac == args.sta1_mac:
                    sta1_ogms.append((seqno, min(ogm_data[key].values())))
            if not sta1_ogms:
                continue
            first_seqno, t_first_ogm = min(sta1_ogms, key=lambda x: x[1])
            if args.sta20_mac in ogm_data[(args.sta1_mac, first_seqno)]:
                t_conv = ogm_data[(args.sta1_mac, first_seqno)][args.sta20_mac] - t_assoc
                conv_times.append((t_assoc, t_conv))
    
    return conv_times

def plot_results(conv_times, protocol):
    timestamps = [t for t, _ in conv_times]
    times = [t - min(timestamps) for t in timestamps] if timestamps else []
    conv_values = [ct for _, ct in conv_times]
    
    plt.plot(times, conv_values, 'ro-', label=protocol)
    plt.xlabel('Tiempo de Simulación (s)')
    plt.ylabel('Tiempo de Convergencia (s)')
    plt.title(f'Convergencia - {protocol}')
    plt.grid(True)
    plt.legend()
    plt.show()

if __name__ == '__main__':
    args = parse_args()
    packets = process_packets(args)
    assoc_times, ogm_data = extract_data(args, packets)
    conv_times = calculate_convergence(args, assoc_times, ogm_data)
    plot_results(conv_times, args.protocol)