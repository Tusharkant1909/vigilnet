from scapy.all import sniff, TCP, UDP, ICMP, DNS, Raw, IP, ARP
from collections import defaultdict
import socket
import re
from datetime import datetime

def resolve_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip  # fallback to IP if DNS lookup fails

def detect_suspicious_packets(pkt):
    suspicious_flags = []
    
    # Check for ARP spoofing
    if pkt.haslayer(ARP):
        if pkt[ARP].op == 2:  # ARP reply
            if pkt[ARP].hwsrc != pkt[ARP].hwdst:
                suspicious_flags.append("Possible ARP Spoofing")
    
    # Check for unusual TCP flags combinations
    if pkt.haslayer(TCP):
        tcp_flags = pkt[TCP].flags
        # NULL scan detection
        if tcp_flags == 0:
            suspicious_flags.append("NULL TCP Scan")
        # FIN scan detection
        elif tcp_flags & 0x01 and not (tcp_flags & 0x02):
            suspicious_flags.append("FIN Scan")
        # XMAS scan detection
        elif tcp_flags & 0x29 == 0x29:  # FIN, PSH, URG
            suspicious_flags.append("XMAS Scan")
    
    # Check for DNS tunneling attempts
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0:  # DNS query
            if dns.qd:
                qname = dns.qd.qname.decode('utf-8', errors='ignore')
                # Check for long domain names (possible tunneling)
                if len(qname) > 50:
                    suspicious_flags.append("Possible DNS Tunneling")
                # Check for suspicious characters in domain
                if re.search(r'([^\w\.-]|[_]{2,})', qname):
                    suspicious_flags.append("Suspicious DNS Query")
    
    # Check for suspicious payload patterns
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore').lower()
        # Common attack patterns
        attack_patterns = [
            r'select.*from',               # SQL injection
            r'union.*select',              # SQL injection
            r'<script>.*</script>',        # XSS
            r'\.\./',                      # Path traversal
            r'echo.*\b\w+\(\)\s*\{\s*\}',  # PHP code injection
            r'bash -i',                    # Reverse shell
            r'\/bin\/sh'                   # Shell command
        ]
        for pattern in attack_patterns:
            if re.search(pattern, payload):
                suspicious_flags.append(f"Suspicious payload: {pattern}")
                break
    
    return suspicious_flags if suspicious_flags else None

def count_packet(pkt):
    stats = defaultdict(int)
    if pkt.haslayer(ARP):
        stats["ARP"] += 1
    if pkt.haslayer(IP):
        stats["IP"] += 1
        if pkt[IP].version == 6:
            stats["IPv6"] += 1
    if pkt.haslayer(TCP):
        stats["TCP"] += 1
        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
            stats["HTTP"] += 1
        elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            stats["HTTPS"] += 1
    if pkt.haslayer(UDP):
        stats["UDP"] += 1
    if pkt.haslayer(ICMP):
        stats["ICMP"] += 1
    if pkt.haslayer(DNS):
        stats["DNS"] += 1
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore').upper()
        if "HTTP" in payload:
            stats["HTTP"] += 1
        elif "HTTPS" in payload or "TLS" in payload:
            stats["HTTPS"] += 1
    return stats

def get_packet_stats():
    results = defaultdict(int)
    dns_logs = []
    suspicious_packets = []

    def process_packet(pkt):
        packet_stats = count_packet(pkt)
        for protocol, count in packet_stats.items():
            results[protocol] += count

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            src_host = resolve_dns(src_ip)
            dst_host = resolve_dns(dst_ip)
            dns_logs.append({
                "src": src_ip,
                "src_host": src_host,
                "dst": dst_ip,
                "dst_host": dst_host
            })
            
            # Detect suspicious packets
            suspicious = detect_suspicious_packets(pkt)
            if suspicious:
                suspicious_packets.append({
                    "src": src_ip,
                    "dst": dst_ip,
                    "flags": suspicious,
                    "timestamp": datetime.now().isoformat()
                })

    sniff(prn=process_packet, timeout=10, store=0)
    return {
        "protocols": dict(results),
        "connections": dns_logs,
        "suspicious": suspicious_packets
    }