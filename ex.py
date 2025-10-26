from scapy.all import *

def create_custom_tcp():
    packet = IP(src="10.36.50.214", dst="10.36.50.148") / TCP(
        sport=80,
        dport=53,
        seq=0,
        flags="S",
        options=[
            ('WScale', 10),
            ('NOP', None),
            ('MSS', 1460),
            ('Timestamp', (0xFFFFFFFF, 0)),
            ('SAckOK', '')
        ]
    ) / "Custom payload data"

    # Print the whole packet summary
    print(packet.show(dump=True))  # human-readable breakdown

    # Get raw bytes
    raw_bytes = bytes(packet)
    print("Raw packet bytes:", raw_bytes.hex())

    # Slice out the TCP header only
    ip_header_len = packet[IP].ihl * 4  # IP header length in bytes
    tcp_header_len = packet[TCP].dataofs * 4  # TCP header length in bytes
    tcp_header_bytes = raw_bytes[ip_header_len:ip_header_len+tcp_header_len]
    print("Raw TCP header bytes:", " ".join(f"{b:02x}" for b in tcp_header_bytes))

    # Send the packet
    send(packet)

create_custom_tcp()
