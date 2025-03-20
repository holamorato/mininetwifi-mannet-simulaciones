from scapy.utils import PcapNgReader
from scapy.layers.dot11 import Dot11, LLC, SNAP
from scapy.layers.inet import UDP, IP
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Debug para B.A.T.M.A.N. batmand')
    parser.add_argument('--pcapng', type=str, required=True, help='Ruta del archivo .pcapng')
    return parser.parse_args()

def process_packets(args):
    packets = []
    with PcapNgReader(args.pcapng) as pcap:
        for pkt in pcap:
            packets.append(pkt)
    return packets

def extract_batmand_data(packets):
    ogm_list = []
    for pkt in packets:
        if Dot11 in pkt and LLC in pkt and SNAP in pkt:
            snap = pkt[SNAP]
            if snap.OUI == 0x000000 and snap.code == 0x0800:  # IPv4
                try:
                    ip_pkt = IP(snap.payload.load)
                    if UDP in ip_pkt and ip_pkt.dport == 4305:
                        seqno = ip_pkt[UDP].sport
                        ip_src = ip_pkt.src
                        timestamp = pkt.time
                        ogm_list.append({
                            'seqno': seqno,
                            'ip_src': ip_src,
                            'timestamp': timestamp
                        })
                        print(f"[OGM] Seq={seqno}, IP={ip_src}, T={timestamp}")
                except:
                    continue
    return ogm_list

if __name__ == '__main__':
    args = parse_args()
    packets = process_packets(args)
    ogm_data = extract_batmand_data(packets)
    print(f"\nTotal OGMs detectados: {len(ogm_data)}")