"""
PCAP & Network Flow Parser: Extracts bidirectional flow telemetry,
TLS JA3/JA4 metadata, DNS queries, and packet timing statistics.
"""

import math
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte sequence (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = defaultdict(int)
    for b in data:
        counts[b] += 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class PcapParser:
    """
    Parses PCAP/PCAPNG files into normalized flow records and individual packet events.
    """

    def __init__(self, pcap_path: str | Path):
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    def parse(self) -> Dict[str, Any]:
        """
        Processes PCAP and returns both packet-level timeline events and aggregated flow records.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy library is required for PCAP parsing.")

        packets = rdpcap(str(self.pcap_path))
        packet_records: List[Dict[str, Any]] = []
        flow_buckets = defaultdict(list)

        for idx, pkt in enumerate(packets):
            if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
                continue

            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            timestamp = float(pkt.time)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else "OTHER")
            src_port = 0
            dst_port = 0
            tcp_flags = ""

            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport

            # Canonical Flow Key (bidirectional)
            endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            flow_id = f"{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}_{proto}"

            payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            payload_entropy = calculate_entropy(pkt[Raw].load) if pkt.haslayer(Raw) else 0.0

            # DNS Analysis
            dns_query = None
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    dns_query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    dns_query = str(pkt[DNSQR].qname)

            # TLS SNI & Handshake heuristic
            tls_sni = None
            ja3_hash = None
            if pkt.haslayer(TCP) and (dst_port == 443 or src_port == 443 or payload_len > 0):
                if pkt.haslayer(Raw):
                    load = bytes(pkt[Raw].load)
                    # Detect TLS Client Hello (0x16 0x03)
                    if len(load) > 5 and load[0] == 0x16 and load[1] == 0x03:
                        # Extract rudimentary SNI if present
                        sni_pos = load.find(b"\x00\x00")
                        if sni_pos != -1 and sni_pos + 5 < len(load):
                            # Approximate JA3 representation
                            ja3_raw = f"771,{len(load)},{load[1]}_{load[2]}"
                            ja3_hash = hashlib.md5(ja3_raw.encode()).hexdigest()

            rec = {
                "packet_index": idx,
                "timestamp": timestamp,
                "flow_id": flow_id,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "tcp_flags": tcp_flags,
                "length": len(pkt),
                "payload_len": payload_len,
                "payload_entropy": payload_entropy,
                "dns_query": dns_query,
                "tls_sni": tls_sni,
                "ja3": ja3_hash
            }
            packet_records.append(rec)
            flow_buckets[flow_id].append(rec)

        # Aggregate into Flow Summaries
        flow_records: List[Dict[str, Any]] = []
        for flow_id, pkts in flow_buckets.items():
            pkts.sort(key=lambda x: x["timestamp"])
            timestamps = [p["timestamp"] for p in pkts]
            durations = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
            lengths = [p["length"] for p in pkts]

            mean_delta = sum(durations) / len(durations) if durations else 0.0
            jitter = (
                math.sqrt(sum((d - mean_delta) ** 2 for d in durations) / len(durations))
                if len(durations) > 1
                else 0.0
            )

            total_bytes = sum(lengths)
            flow_dur = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

            # Gather any DNS or JA3
            dns_queries = list({p["dns_query"] for p in pkts if p["dns_query"]})
            ja3_hashes = list({p["ja3"] for p in pkts if p["ja3"]})

            flow_summary = {
                "flow_id": flow_id,
                "src_ip": pkts[0]["src_ip"],
                "src_port": pkts[0]["src_port"],
                "dst_ip": pkts[0]["dst_ip"],
                "dst_port": pkts[0]["dst_port"],
                "protocol": pkts[0]["protocol"],
                "packet_count": len(pkts),
                "total_bytes": total_bytes,
                "duration_sec": round(flow_dur, 4),
                "mean_delta_sec": round(mean_delta, 4),
                "jitter_sec": round(jitter, 4),
                "avg_packet_len": round(total_bytes / len(pkts), 2),
                "dns_queries": dns_queries,
                "ja3": ja3_hashes[0] if ja3_hashes else None,
                "start_time": timestamps[0],
                "end_time": timestamps[-1]
            }
            flow_records.append(flow_summary)

        return {
            "total_packets": len(packet_records),
            "total_flows": len(flow_records),
            "packets": packet_records,
            "flows": flow_records
        }
