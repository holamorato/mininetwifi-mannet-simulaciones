#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import ICMP
import os

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

def plot_convergence(convergence_data, protocolo="batmand"):
    # Crear directorio si no existe
    output_dir = f"./graficas/convergencia/{protocolo}/"
    os.makedirs(output_dir, exist_ok=True)

    # Generar nombre de archivo único
    version = 1
    while True:
        output_file = f"{output_dir}convergencia {protocolo} v{version}.png"
        if not os.path.exists(output_file):
            break
        version += 1

    # Extraer datos para la gráfica
    times = [entry[0] for entry in convergence_data]
    durations = [entry[1] for entry in convergence_data]

    # Crear gráfica
    plt.figure(figsize=(15, 6))
    plt.bar(times, durations, width=0.8, align='center')
    plt.title('Tiempo de Convergencia ICMP (Ping)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('Tiempo de convergencia (segundos)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Gráfica guardada como: {output_file}")

def analyze_latency(pcap_file, src_node="10.0.0.1", dst_node="10.0.0.12"):
    latency_data = {}
    results = []
    start_time = None  # Tiempo inicial de la simulación

    with PcapNgReader(pcap_file) as pcap:
        for pkt in pcap:
            if ICMP in pkt and IP in pkt:
                ip = pkt[IP]
                icmp = pkt[ICMP]
                timestamp = float(pkt.time)

                # Establecer el tiempo inicial si no se ha definido
                if start_time is None:
                    start_time = timestamp

                # Ajustar el timestamp para que sea relativo al inicio
                relative_time = timestamp - start_time

                # Identificar Echo Request
                if ip.src == src_node and ip.dst == dst_node and icmp.type == 8:  # ICMP Echo Request
                    latency_data[icmp.id] = relative_time

                # Identificar Echo Reply
                elif ip.src == dst_node and ip.dst == src_node and icmp.type == 0:  # ICMP Echo Reply
                    if icmp.id in latency_data:
                        latency = relative_time - latency_data.pop(icmp.id)
                        results.append((relative_time, latency))
                        print(f"[DEBUG] Latencia ICMP: {latency:.2f}s")

    return results

def plot_latency(latency_data, protocolo="batmand"):
    # Crear directorio si no existe
    output_dir = f"./graficas/latencia/{protocolo}/"
    os.makedirs(output_dir, exist_ok=True)

    # Generar nombre de archivo único
    version = 1
    while True:
        output_file = f"{output_dir}latencia {protocolo} v{version}.png"
        if not os.path.exists(output_file):
            break
        version += 1

    # Extraer datos para la gráfica
    times = [entry[0] for entry in latency_data]
    latencies = [entry[1] for entry in latency_data]

    # Crear gráfica
    plt.figure(figsize=(15, 6))
    plt.bar(times, latencies, width=0.8, align='center', color='b', label='Latencia')
    plt.title('Latencia ICMP (Ping)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('Latencia (segundos)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Gráfica guardada como: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Analizador de latencia ICMP")
    parser.add_argument("--archivo", required=True, help="Archivo .pcapng de captura")
    parser.add_argument("--dst_node", required=True, help="Dirección IP del nodo destino")
    args = parser.parse_args()

    latency_data = analyze_latency(args.archivo, dst_node=args.dst_node)
    
    if latency_data:
        plot_latency(latency_data)
    else:
        print("No se detectaron eventos de latencia")

if __name__ == "__main__":
    main()