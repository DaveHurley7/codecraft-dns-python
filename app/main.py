import socket

def main():
    
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            c_hdr = buf[:12]
            c_id = c_hdr[:2]
            c_flags = int.from_bytes(c_hdr[2:4])
            qr = 0x8000
            opcode = c_flags & 0x7800
            aa = 0
            tc = 0
            rd = c_flags & 0x0100
            ra = 0
            rsv = 0
            rcode = 0 if opcode == 0 else 4
            flags = qr|opcode|aa|tc|rd|ra|rsv|rcode
            flags = flags.to_bytes(2)
            
            qdcount = b"\x00\x01"
            ancount = b"\x00\x01"
            nscount = b"\x00\x00"
            arcount = b"\x00\x00"
            header = c_id + flags + qdcount + ancount + nscount + arcount
            
            qsectlabel_end = buf.index(b"\x00",12)+1
            
            question = buf[12:qsectlabel_end] + b"\x00\x01\x00\x01"
            ttl = b"\x00\x00\x00\x3c"
            data = b"\x08\x08\x08\x08"
            data_len = b"\x00\x04"
            answer = buf[12:qsectlabel_end] + b"\x00\x01\x00\x01" + ttl + data_len + data
            response = header+question+answer
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
