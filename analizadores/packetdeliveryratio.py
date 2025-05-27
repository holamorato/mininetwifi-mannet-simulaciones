#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import ICMP
import os
from collections import deque

def analyze_pdr(pcap_file, src_node="10.0.0.1", dst_node="10.0.0.12"):
    print(f"[INFO] Analizando PDR en el archivo: {pcap_file}")
    packets = []  # Lista para almacenar pares de (tipo, seq, timestamp)
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

                # Registrar Echo Request
                if ip.src == src_node and ip.dst == dst_node and icmp.type == 8:  # ICMP Echo Request
                    packets.append(("request", icmp.seq, relative_time))

                # Registrar Echo Reply
                elif ip.src == dst_node and ip.dst == src_node and icmp.type == 0:  # ICMP Echo Reply
                    packets.append(("reply", icmp.seq, relative_time))

    print(f"[INFO] Registro de paquetes completado. Total de paquetes: {len(packets)}")
    return calculate_pdr(packets)

def calculate_pdr(packets, observation_window=10):
    print(f"[INFO] Calculando PDR con ventana de observación de {observation_window} segundos")
    pdr_data = []
    n = len(packets)
    # Extraer solo los paquetes request y reply con sus timestamps
    requests = [(seq, t) for typ, seq, t in packets if typ == "request"]
    replies = [(seq, t) for typ, seq, t in packets if typ == "reply"]

    # Para cada request, buscar replies en la ventana
    for i, (seq_req, t_req) in enumerate(requests):
        window_start = t_req
        window_end = t_req + observation_window

        # Requests en la ventana
        reqs_in_window = [seq for seq, t in requests if window_start <= t < window_end]
        # Replies en la ventana
        reps_in_window = [seq for seq, t in replies if window_start <= t < window_end]

        delivered = sum(1 for seq in reqs_in_window if seq in reps_in_window)
        total_sent = len(reqs_in_window)
        pdr = (delivered / total_sent) * 100 if total_sent > 0 else 0
        pdr_data.append((t_req, pdr))

    print(f"[INFO] Cálculo de PDR completado. Total de puntos: {len(pdr_data)}")
    return pdr_data

def plot_pdr(pdr_data, protocolo="batmand", escenario=0):
    print(f"[INFO] Generando gráfica de PDR para el protocolo: {protocolo}, escenario: {escenario}")
    # Crear directorio si no existe
    output_dir = f"./graficas/pdr/{protocolo}/"
    os.makedirs(output_dir, exist_ok=True)

    # Generar nombre de archivo único
    version = 1
    while True:
        output_file = f"{output_dir}pdr {protocolo} E{escenario} v{version}.png"
        if not os.path.exists(output_file):
            break
        version += 1

    # Extraer datos para la gráfica
    times = [entry[0] for entry in pdr_data]
    pdr_values = [entry[1] for entry in pdr_data]

    # Crear gráfica
    plt.figure(figsize=(15, 6))
    plt.plot(times, pdr_values, linestyle='-', color='g', label='PDR (%)')  # Conectar puntos con líneas
    plt.scatter(times, pdr_values, color='g', s=10)  # Añadir puntos sobre las líneas
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
    parser.add_argument("--escenario", type=int, required=True, help="Número del escenario")
    parser.add_argument("--dst_node", default="10.0.0.12", help="Dirección IP del nodo destino (por defecto: 10.0.0.12)")
    args = parser.parse_args()

    pdr_data = analyze_pdr(args.archivo, dst_node=args.dst_node)
    
    if pdr_data:
        plot_pdr(pdr_data, escenario=args.escenario)
    else:
        print("No se detectaron eventos de PDR")

if __name__ == "__main__":
    main()