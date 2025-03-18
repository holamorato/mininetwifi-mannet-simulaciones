from scapy.all import *
import matplotlib.pyplot as plt
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Calcula tiempo de convergencia para B.A.T.M.A.N.')
    parser.add_argument('--protocol', type=str, required=True, choices=['batmand', 'batman-adv'], 
                       help='Protocolo a analizar (batmand o batman-adv)')
    parser.add_argument('--pcap', type=str, required=True, help='Ruta del archivo PCAP')
    parser.add_argument('--sta1_mac', type=str, default='00:00:00:00:00:01', help='MAC de sta1')
    parser.add_argument('--sta20_mac', type=str, default='00:00:00:00:00:14', help='MAC de sta20')
    return parser.parse_args()

def process_packets(args):
    packets = rdpcap(args.pcap)
    assoc_times = {}  # {ap_mac: tiempo_asociacion}
    ogm_data = {}     # Estructura depende del protocolo

    for pkt in packets:
        # Detectar asociaciones de sta1 (común para ambos protocolos)
        if Dot11 in pkt and pkt[Dot11].type == 0 and pkt[Dot11].subtype in [0, 1]:
            if pkt[Dot11].addr2 == args.sta1_mac or pkt[Dot11].addr1 == args.sta1_mac:
                assoc_time = pkt.time
                ap_mac = pkt[Dot11].addr3
                assoc_times[ap_mac] = assoc_time
        
        # Procesar OGMs según protocolo
        if args.protocol == 'batmand':
            if UDP in pkt and pkt[UDP].dport == 1966:
                ip_src = pkt[IP].src
                seqno = pkt[UDP].sport  # Ajustar según implementación real
                if seqno not in ogm_data:
                    ogm_data[seqno] = {}
                ogm_data[seqno][ip_src] = pkt.time
                
        elif args.protocol == 'batman-adv':
            if Ether in pkt and pkt[Ether].type == 0x4305:
                originator_mac = pkt[Ether].src  # ¡Ojo! En batman-adv está en el payload
                seqno = int(pkt[Ether].payload[4:6].hex(), 16)  # Ajustar offset
                forwarder_mac = pkt[Ether].src
                if seqno not in ogm_data:
                    ogm_data[seqno] = {}
                if originator_mac not in ogm_data[seqno]:
                    ogm_data[seqno][originator_mac] = {}
                ogm_data[seqno][originator_mac][forwarder_mac] = pkt.time

    return assoc_times, ogm_data

def calculate_convergence(args, assoc_times, ogm_data):
    conv_times = []
    
    for ap_mac, t_assoc in assoc_times.items():
        if args.protocol == 'batmand':
            # Lógica para batmand
            seqnos = [seqno for seqno in ogm_data if args.sta1_mac in ogm_data[seqno]]
            if not seqnos:
                continue
            first_seqno = min(seqnos)
            if args.sta20_mac in ogm_data[first_seqno]:
                t_conv = ogm_data[first_seqno][args.sta20_mac] - t_assoc
                conv_times.append((t_assoc, t_conv))
                
        elif args.protocol == 'batman-adv':
            # Lógica para batman-adv
            sta1_ogms = []
            for seqno in ogm_data:
                if args.sta1_mac in ogm_data[seqno]:
                    sta1_ogms.append((seqno, min(ogm_data[seqno][args.sta1_mac].values())))
            if not sta1_ogms:
                continue
            first_seqno, t_first_ogm = min(sta1_ogms, key=lambda x: x[1])
            if args.sta20_mac in ogm_data[first_seqno][args.sta1_mac]:
                t_conv = ogm_data[first_seqno][args.sta1_mac][args.sta20_mac] - t_assoc
                conv_times.append((t_assoc, t_conv))
    
    return conv_times

def plot_results(conv_times, protocol):
    timestamps = [t for t, _ in conv_times]
    times = [t - min(timestamps) for t in timestamps]
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
    assoc_times, ogm_data = process_packets(args)
    conv_times = calculate_convergence(args, assoc_times, ogm_data)
    plot_results(conv_times, args.protocol)