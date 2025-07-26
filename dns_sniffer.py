import socket
import struct

def dns_sniffer():
    # Raw socket to sniff UDP (DNS typically uses UDP port 53)
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    try:
        while True:
            raw_data = sniffer.recvfrom(65536)[0]
            eth_proto = struct.unpack('!H', raw_data[12:14])[0]

            # IPv4
            if eth_proto == 0x0800:
                ip_proto = raw_data[23]
                # UDP protocol
                if ip_proto == 17:
                    src_ip = ".".join(map(str, raw_data[26:30]))
                    dst_ip = ".".join(map(str, raw_data[30:34]))
                    src_port = struct.unpack('!H', raw_data[34:36])[0]
                    dst_port = struct.unpack('!H', raw_data[36:38])[0]

                    # DNS port (53)
                    if dst_port == 53 or src_port == 53:
                        dns_data = raw_data[42:]  # DNS payload
                        # Basic domain name parsing
                        domain = ''
                        i = 12
                        length = dns_data[i]
                        while length != 0:
                            domain += dns_data[i+1:i+1+length].decode(errors='ignore') + '.'
                            i += length + 1
                            length = dns_data[i]
                        print(f"[DNS] {src_ip} → {dst_ip} | Domain: {domain.strip('.')}")
    except KeyboardInterrupt:
        print("\nStopped.")

dns_sniffer()
