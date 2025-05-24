#!/usr/bin/env python3
import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import ICMP
import os
import matplotlib.ticker as ticker

def analyze_convergence(pcap_file, mobile_node="10.0.0.1"):
    convergence_data = []
    last_reply_time = None
    start_time = None  # Tiempo inicial de la simulación

    with PcapNgReader(pcap_file) as pcap:
        for pkt in pcap:
            if ICMP in pkt and IP in pkt:
                icmp = pkt[ICMP]
                timestamp = float(pkt.time)

                # Establecer el tiempo inicial si no se ha definido
                if start_time is None:
                    start_time = timestamp

                # Ajustar el timestamp para que sea relativo al inicio
                relative_time = timestamp - start_time

                # Solo analizar paquetes ICMP Reply provenientes del nodo móvil
                if pkt[IP].dst == mobile_node and icmp.type == 0:  # ICMP Echo Reply
                    if last_reply_time is not None:
                        time_between_replies = relative_time - last_reply_time
                        convergence_data.append((relative_time, time_between_replies))
                        print(f"[DEBUG] Tiempo entre Echo Reply: {time_between_replies:.2f}s")

                    last_reply_time = relative_time

    return convergence_data

def plot_convergence(convergence_data, protocolo="batmand", escenario=0):
    # Crear directorio si no existe
    output_dir = f"./graficas/convergencia/{protocolo}/"
    os.makedirs(output_dir, exist_ok=True)

    # Generar nombre de archivo único
    version = 1
    while True:
        output_file = f"{output_dir}convergencia {protocolo} E{escenario} V{version}.png"
        if not os.path.exists(output_file):
            break
        version += 1

    # Extraer datos para la gráfica
    times = [entry[0] for entry in convergence_data]
    durations = [entry[1] for entry in convergence_data]

    # Crear gráfica
    plt.figure(figsize=(15, 6))
    plt.bar(times, durations, width=0.8, align='center')
    plt.title('Tiempo de Convergencia de Rutas entre ICMP (Ping)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('Tiempo entre Echo Reply (segundos)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)

    # Configurar formato de los ejes para evitar notación científica
    ax = plt.gca()
    ax.xaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))
    ax.yaxis.set_major_formatter(ticker.FormatStrFormatter('%.2f'))

    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Gráfica guardada como: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Analizador de convergencia ICMP")
    parser.add_argument("--archivo", required=True, help="Archivo .pcapng de captura")
    parser.add_argument("--escenario", type=int, required=True, help="Número del escenario")
    args = parser.parse_args()

    convergence_data = analyze_convergence(args.archivo)
    
    if convergence_data:
        plot_convergence(convergence_data, escenario=args.escenario)
    else:
        print("No se detectaron eventos de convergencia")

if __name__ == "__main__":
    main()