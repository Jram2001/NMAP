from scapy.all import *

# Source and destination IPs
src_ip = "10.36.50.214"
dst_ip = "10.36.50.148"

# Your raw TCP header + options (no payload)
tcp_raw = bytes.fromhex(
    "005000350000000000000000a002ffff0000000003030a01020405b4080affffffff000000000402"
)

# Build a pseudo-header (12 bytes)
pseudo_header = IP(src=src_ip, dst=dst_ip)/Raw(load=tcp_raw)

# Scapy can compute checksum using TCP layer by creating a fake packet
tcp_pkt = TCP(tcp_raw)  # raw TCP bytes

# Scapy’s checksum calculation utility
# 1. Build TCP object from raw bytes
tcp_layer = TCP(tcp_raw)

# 2. Recalculate checksum using scapy function
tcp_layer.chksum = None  # clear old checksum
tcp_layer = TCP(bytes(tcp_layer))  # recalc checksum

# Alternatively, use scapy's checksum function directly:
from scapy.utils import checksum
from scapy.layers.inet import struct

# Compute pseudo-header sum manually for checksum
def calc_tcp_checksum(src, dst, tcp_bytes):
    # Convert IPs to bytes
    src_bytes = bytes(map(int, src.split('.')))
    dst_bytes = bytes(map(int, dst.split('.')))
    
    # Pseudo-header: src(4)+dst(4)+0+protocol(1)+length(2)
    pseudo = src_bytes + dst_bytes + bytes([0]) + bytes([6]) + len(tcp_bytes).to_bytes(2,'big')
    
    # Combine pseudo-header + TCP header
    combined = pseudo + tcp_bytes
    
    # Add padding if odd length
    if len(combined) % 2 != 0:
        combined += b'\x00'
    
    # Compute checksum
    s = 0
    for i in range(0, len(combined), 2):
        w = combined[i] << 8 | combined[i+1]
        s += w
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

chk = calc_tcp_checksum(src_ip, dst_ip, tcp_raw)
print(f"TCP checksum: {hex(chk)}")
