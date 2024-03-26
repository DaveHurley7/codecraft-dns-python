import socket

QR = 0
OPCODE = 1
RD = 2
RCODE = 3

class DNSMessage:
    ipbyte = 8
    def __init__(self,buffer=None):
        if buffer:
            self.buf = buffer
            self.pid = buffer[:2]
            self.flags = int.from_bytes(buffer[2:4])
            self.qd_num = int.from_bytes(buffer[4:6])
            self.an_num = int.from_bytes(buffer[6:8])
            self.ns_num = int.from_bytes(buffer[8:10])
            self.ar_num = int.from_bytes(buffer[10:12])
        else:
            self.buf = b"\x00"*12
            self.pid = b"\x00\x00"
            self.flags = 0
            self.qd_num = 0
            self.an_num = 0
            self.ns_num = 0
            self.ar_num = 0
        self.qtns = []
        self.awrs = []
        
    def get_header(self):
        return self.pid + self.flags.to_bytes(2) + self.qd_num.to_bytes(2) + self.an_num.to_bytes(2) + self.ns_num.to_bytes(2) + self.ar_num.to_bytes(2) 
    
    def get_pid(self):
        return self.pid
    
    def set_flag(self,fname,val=None):
        if fname == QR:
            self.flags |= 0x8000
        elif fname == OPCODE:
            self.flags |= val & 0x7800
        elif fname == RD:
            self.flags |= val & 0x0100
        elif fname == RCODE:
            self.flags = 0 if self.get_opcode() == 0 else 4
            
    def get_opcode(self):
        return (self.flags & 0x7800) >> 11
    
    def get_flags(self):
        return self.flags
    
    def set_pid(self,pid):
        self.pid = pid
        
    def add_q(self,qbuf):
        self.qtns.append(qbuf)
        self.qd_num += 1
        
    def add_a(self,qbuf):
        print("ANS")
        ttlv = 60
        ttl = ttlv.to_bytes(4)
        dlenv = 4
        dlen = dlenv.to_bytes(2)
        data = b"\x08\x08\x08"+self.ipbyte.to_bytes(1)
        ipbyte += 1
        self.awrs.append(qbuf+ttl+dlen+data)
        self.an_num += 1
        
    def make_msg(self):
        msg = self.get_header()
        for qa in range(self.qd_num):
            msg += self.qtns[qa]
            msg += self.awrs[qa]
        

def main():
    
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            dmsg = DNSMessage(buf)
            rsp = DNSMessage()
            rsp.set_pid(dmsg.get_pid())
            rsp.set_flag(QR)
            rsp.set_flag(OPCODE,dmsg.get_flags())
            rsp.set_flag(RD,dmsg.get_flags())
            rsp.set_flag(RCODE)
            rsp.qd_num = dmsg.qd_num
            rsp.an_num = dmsg.qd_num
            
            bpos = 12
            qd_buf = b""
            for _ in range(dmsg.qd_num):
                if buf[bpos] == b"\x00":
                    print('NL')
                    qd_buf += buf[bpos:bpos+5]
                    bpos += 5
                    rsp.add_q(qd_buf)
                    rsp.add_a(qd_buf)
                elif buf[bpos] & 0xc0:
                    print('LP')
                    msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
                    qd_ptr = msg_offset.to_bytes(2)
                    qd_buf += buf[msg_offset]
                    msg_offset += 1
                    c = 0
                    while c < qd_ptr:
                        qd_buf += buf[msg_offset]
                        c += 1
                    bpos += 2
                else:
                    print('DL')
                    lb_len = buf[bpos]
                    bpos += 1
                    c = 0
                    print(bpos,buf)
                    while c < lb_len:
                        print(c,lb_len)
                        qd_buf += buf[bpos].to_bytes(1)
                        c += 1
                        bpos += 1
                        
            response = rsp.make_msg()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
