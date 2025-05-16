#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import ICMP
import os

def analyze_pdr(pcap_file, src_node="10.0.0.1", dst_node="10.0.0.12"):
    print(f"[INFO] Analizando PDR en el archivo: {pcap_file}")
    request_sequences = set()
    reply_sequences = set()
    pdr_data = []
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

                # Verificar si es un Echo Request
                if ip.src == src_node and ip.dst == dst_node and icmp.type == 8:  # ICMP Echo Request
                    request_sequences.add(icmp.seq)

                    # Calcular PDR en tiempo real incluso si no hay respuestas
                    delivered = len(reply_sequences & request_sequences)  # Intersección de secuencias
                    total_sent = len(request_sequences)
                    pdr = (delivered / total_sent) * 100 if total_sent > 0 else 0
                    pdr_data.append((relative_time, pdr))

                # Verificar si es un Echo Reply
                elif ip.src == dst_node and ip.dst == src_node and icmp.type == 0:  # ICMP Echo Reply
                    reply_sequences.add(icmp.seq)

    print(f"[INFO] Análisis de PDR completado. Total de datos: {len(pdr_data)}")
    return pdr_data

def plot_pdr(pdr_data, protocolo="batmand"):
    print(f"[INFO] Generando gráfica de PDR para el protocolo: {protocolo}")
    # Crear directorio si no existe
    output_dir = f"./graficas/pdr/{protocolo}/"
    os.makedirs(output_dir, exist_ok=True)

    # Generar nombre de archivo único
    version = 1
    while True:
        output_file = f"{output_dir}pdr {protocolo} v{version}.png"
        if not os.path.exists(output_file):
            break
        version += 1

    # Extraer datos para la gráfica
    times = [entry[0] for entry in pdr_data]
    pdr_values = [entry[1] for entry in pdr_data]

    # Crear gráfica
    plt.figure(figsize=(15, 6))
    plt.plot(times, pdr_values, linestyle='-', color='g', label='PDR (%)')
    plt.title('Packet Delivery Ratio (PDR)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('PDR (%)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Gráfica guardada como: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Analizador de Packet Delivery Ratio (PDR)")
    parser.add_argument("--archivo", required=True, help="Archivo .pcapng de captura")
    args = parser.parse_args()

    pdr_data = analyze_pdr(args.archivo)
    
    if pdr_data:
        plot_pdr(pdr_data)
    else:
        print("No se detectaron eventos de PDR")

if __name__ == "__main__":
    main()