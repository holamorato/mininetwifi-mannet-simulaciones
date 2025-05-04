#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import ICMP
import os

def analyze_convergence(pcap_file, mobile_node="10.0.0.1"):
    print(f"[INFO] Analizando convergencia en el archivo: {pcap_file}")
    convergence_data = []
    last_reply_time = None

    with PcapNgReader(pcap_file) as pcap:
        print("[INFO] Leyendo paquetes del archivo...")
        for pkt in pcap:
            if ICMP in pkt and IP in pkt:
                icmp = pkt[ICMP]
                timestamp = float(pkt.time)

                # Solo analizar paquetes ICMP Reply provenientes del nodo móvil
                if pkt[IP].dst == mobile_node and icmp.type == 0:  # ICMP Echo Reply
                    print(f"[DEBUG] ICMP Echo Reply detectado desde {pkt[IP].src}")
                    if last_reply_time is not None:
                        time_between_replies = timestamp - last_reply_time
                        convergence_data.append((timestamp, time_between_replies))
                        print(f"[DEBUG] Tiempo entre Echo Reply: {time_between_replies:.2f}s")

                    last_reply_time = timestamp

    print(f"[INFO] Análisis de convergencia completado. Total de datos: {len(convergence_data)}")
    return convergence_data

def plot_convergence(convergence_data, protocolo="batmand"):
    print(f"[INFO] Generando gráfica de convergencia para el protocolo: {protocolo}")
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
    print(f"[INFO] Gráfica de convergencia guardada en: {output_file}")

def analyze_latency(pcap_file, src_node="10.0.0.1", dst_node="10.0.0.2"):
    print(f"[INFO] Analizando latencia en el archivo: {pcap_file}")
    latency_data = {}
    results = []

    with PcapNgReader(pcap_file) as pcap:
        print("[INFO] Leyendo paquetes del archivo...")
        for pkt in pcap:
            if ICMP in pkt and IP in pkt:
                ip = pkt[IP]
                icmp = pkt[ICMP]
                timestamp = float(pkt.time)

                # Identificar Echo Request
                if ip.src == src_node and ip.dst == dst_node and icmp.type == 8:  # ICMP Echo Request
                    print(f"[DEBUG] Echo Request detectado: ID={icmp.id}")
                    latency_data[icmp.id] = timestamp

                # Identificar Echo Reply
                elif ip.src == dst_node and ip.dst == src_node and icmp.type == 0:  # ICMP Echo Reply
                    print(f"[DEBUG] Echo Reply detectado: ID={icmp.id}")
                    if icmp.id in latency_data:
                        latency = timestamp - latency_data.pop(icmp.id)
                        results.append((timestamp, latency))
                        print(f"[DEBUG] Latencia ICMP: {latency:.2f}s")

    print(f"[INFO] Análisis de latencia completado. Total de resultados: {len(results)}")
    return results

def plot_latency(latency_data, protocolo="batmand"):
    print(f"[INFO] Generando gráfica de latencia para el protocolo: {protocolo}")
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
    plt.plot(times, latencies, linestyle='-', color='b', label='Latencia')  # Eliminado el marcador
    plt.title('Latencia ICMP (Ping)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('Latencia (segundos)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"[INFO] Gráfica de latencia guardada en: {output_file}")

def analyze_pdr(pcap_file, src_node="10.0.0.1", dst_node="10.0.0.2"):
    print(f"[INFO] Analizando PDR en el archivo: {pcap_file}")
    request_sequences = set()
    reply_sequences = set()
    pdr_data = []

    with PcapNgReader(pcap_file) as pcap:
        print("[INFO] Leyendo paquetes del archivo...")
        for pkt in pcap:
            if ICMP in pkt and IP in pkt:
                ip = pkt[IP]
                icmp = pkt[ICMP]
                timestamp = float(pkt.time)

                print(f"[TRACE] Paquete leído: IP src={ip.src}, IP dst={ip.dst}, ICMP type={icmp.type}, ICMP seq={icmp.seq}")

                # Verificar si es un Echo Request
                if ip.src == src_node and ip.dst == dst_node and icmp.type == 8:  # ICMP Echo Request
                    print(f"[DEBUG] Echo Request detectado: Seq={icmp.seq}")
                    request_sequences.add(icmp.seq)
                    print(f"[TRACE] Secuencia agregada a request_sequences: {icmp.seq}")

                # Verificar si es un Echo Reply
                elif ip.src == dst_node and ip.dst == src_node and icmp.type == 0:  # ICMP Echo Reply
                    print(f"[DEBUG] Echo Reply detectado: Seq={icmp.seq}")
                    reply_sequences.add(icmp.seq)
                    print(f"[TRACE] Secuencia agregada a reply_sequences: {icmp.seq}")

                # Calcular PDR en tiempo real
                if request_sequences:
                    delivered = len(reply_sequences & request_sequences)  # Intersección de secuencias
                    total_sent = len(request_sequences)
                    pdr = (delivered / total_sent) * 100
                    pdr_data.append((timestamp, pdr))
                    print(f"[DEBUG] PDR: {pdr:.2f}% (Requests: {total_sent}, Replies: {delivered})")
                else:
                    print("[TRACE] No se encontraron secuencias coincidentes aún.")

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
    plt.plot(times, pdr_values, linestyle='-', color='g', label='PDR (%)')  # Eliminado el marcador
    plt.title('Packet Delivery Ratio (PDR)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('PDR (%)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.legend()
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"[INFO] Gráfica de PDR guardada en: {output_file}")

def main():
    print("[INFO] Iniciando el programa...")
    parser = argparse.ArgumentParser(description="Analizador de Packet Delivery Ratio (PDR)")
    parser.add_argument("--archivo", required=True, help="Archivo .pcapng de captura")
    args = parser.parse_args()
    print(f"[INFO] Archivo de entrada: {args.archivo}")

    pdr_data = analyze_pdr(args.archivo)
    
    if pdr_data:
        print("[INFO] Generando gráfica de PDR...")
        plot_pdr(pdr_data)
    else:
        print("[WARNING] No se detectaron eventos de PDR")

if __name__ == "__main__":
    main()