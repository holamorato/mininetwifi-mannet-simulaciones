import argparse
import matplotlib.pyplot as plt
from scapy.all import *
from scapy.layers.inet import UDP
from collections import defaultdict

class BATMAN_OGM(Packet):
    name = "BATMAN OGM v5"
    fields_desc = [
        ByteField("version", 5),
        ByteField("flags", 0),
        ByteField("ttl", 0),
        ByteField("gw_flags", 0),
        ShortField("sequence", 0),
        ShortField("gw_port", 4305),
        IPField("originator", "0.0.0.0"),
        IPField("received_from", "0.0.0.0"),
        ByteField("tx_quality", 0),
        ByteField("hna_count", 0)
    ]

bind_layers(UDP, BATMAN_OGM, dport=4305)

def analyze_convergence(pcap_file, mobile_node="10.0.0.1"):
    convergence_data = []
    current_best = None
    last_change_time = None
    
    with PcapNgReader(pcap_file) as pcap:
        for pkt in pcap:
            if UDP in pkt and BATMAN_OGM in pkt:
                ogm = pkt[BATMAN_OGM]
                timestamp = float(pkt.time)
                
                # Solo OGMs del nodo móvil (STA1)
                if ogm.originator == mobile_node:
                    print(f"[DEBUG] OGM detectado: {ogm.originator} -> Seq {ogm.sequence}")
                    
                    # Actualizar mejor ruta
                    if not current_best or ogm.sequence > current_best["sequence"]:
                        if current_best:
                            convergence_time = timestamp - last_change_time
                            convergence_data.append((timestamp, convergence_time))
                            print(f"[DEBUG] Cambio detectado: Tiempo {convergence_time:.2f}s")
                        
                        current_best = {
                            "sequence": ogm.sequence,
                            "start_time": timestamp
                        }
                        last_change_time = timestamp
    
    return convergence_data

def plot_convergence(convergence_data, output_file="convergence_plot.png"):
    times = [entry[0] for entry in convergence_data]
    durations = [entry[1] for entry in convergence_data]

    plt.figure(figsize=(15, 6))
    plt.bar(times, durations, width=0.8, align='center')
    plt.title('Tiempo de Convergencia hacia sta20 (10.0.0.20)')
    plt.xlabel('Tiempo de simulación (segundos)')
    plt.ylabel('Tiempo de convergencia (segundos)')
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Gráfica guardada como: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Analizador de convergencia BATMAN")
    parser.add_argument("--archivo", required=True, help="Archivo .pcapng de captura")
    args = parser.parse_args()

    convergence_data = analyze_convergence(args.archivo)
    
    if convergence_data:
        plot_convergence(convergence_data)
    else:
        print("No se detectaron eventos de convergencia")

if __name__ == "__main__":
    main()