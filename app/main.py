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
            c_flags = c_hdr[2:4]
            qr = b"\x80\x00"
            opcode = c_flags & b"\x78\x00"
            aa = b"\x00\x00"
            tc = b"\x00\x00"
            rd = c_flags & b"\x01\x00"
            ra = b"\x00\x00"
            rsv = b"\x00\x00"
            rcode = b"\x00\x00"
            flags = qr|opcode|aa|tc|rd|ra|rsv|rcode
            
            qdcount = b"\x00\x01"
            ancount = b"\x00\x01"
            nscount = b"\x00\x00"
            arcount = b"\x00\x00"
            header = c_id + flags + qdcount + ancount + nscount + arcount
            question = b"\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"
            ttl = b"\x00\x00\x00\x3c"
            data = b"\x08\x08\x08\x08"
            data_len = b"\x00\x04"
            answer = b"\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"+ttl+data_len+data
            response = header+question+answer
            
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
