#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import ICMP

def analyze_convergence(pcap_file, mobile_node="10.0.0.1"):
    convergence_data = []
    last_reply_time = None

    with PcapNgReader(pcap_file) as pcap:
        for pkt in pcap:
            if ICMP in pkt and IP in pkt:
                icmp = pkt[ICMP]
                timestamp = float(pkt.time)

                # Solo analizar paquetes ICMP Reply provenientes del nodo móvil
                if pkt[IP].dst == mobile_node and icmp.type == 0:  # ICMP Echo Reply
                    if last_reply_time is not None:
                        time_between_replies = timestamp - last_reply_time
                        convergence_data.append((timestamp, time_between_replies))
                        print(f"[DEBUG] Tiempo entre Echo Reply: {time_between_replies:.2f}s")

                    last_reply_time = timestamp

    return convergence_data

def plot_convergence(convergence_data, output_file="convergence_plot.png"):
    times = [entry[0] for entry in convergence_data]
    durations = [entry[1] for entry in convergence_data]

    plt.figure(figsize=(15, 6))
    plt.bar(times, durations, width=0.8, align='center')
    plt.title('Tiempo de Convergencia ICMP (Ping)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('Tiempo de convergencia (segundos)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Gráfica guardada como: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Analizador de convergencia ICMP")
    parser.add_argument("--archivo", required=True, help="Archivo .pcapng de captura")
    args = parser.parse_args()

    convergence_data = analyze_convergence(args.archivo)
    
    if convergence_data:
        plot_convergence(convergence_data)
    else:
        print("No se detectaron eventos de convergencia")

if __name__ == "__main__":
    main()