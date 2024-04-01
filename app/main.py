import socket, sys

QR = 0
OPCODE = 1
RD = 2
RCODE = 3

fwdqueries = {}

def socket_from_addr(addr):
    ip, port = addr.split(":")
    return ip, int(port)

class DNSMessage:
    def __init__(self,buffer,src):
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
        self.ipbyte = 8
        self.client = src

    def get_header(self):
        return self.pid + self.flags.to_bytes(2) + len(self.qtns).to_bytes(2) + len(awrs).to_bytes(2) + self.ns_num.to_bytes(2) + self.ar_num.to_bytes(2) 
    
    def get_fwdhdr(self):
        qd_num = 1
        an_num = 1
        return self.pid + self.flags.to_bytes(2) + qd_num.to_bytes(2) + an_num.to_bytes(2) + self.ns_num.to_bytes(2) + self.ar_num.to_bytes(2) 
    
    def update_flags(self,fwd_buf):
        self.flags = int.from_bytes(fwd_buf[2:4])
    
    def set_flag(self,fname,val=None):
        if fname == QR:
            self.flags |= 0x8000
        elif fname == OPCODE:
            self.flags |= val & 0x7800
        elif fname == RD:
            self.flags |= val & 0x0100
        elif fname == RCODE:
            self.flags |= 0 if self.get_opcode() == 0 else 4
            
    def get_opcode(self):
        return (self.flags & 0x7800) >> 11
        
    def add_q(self,qbuf):
        self.qtns.append(qbuf)
        self.qd_num += 1
        
    def add_a(self,qbuf):
        ttlv = 60
        ttl = ttlv.to_bytes(4)
        dlenv = 4
        dlen = dlenv.to_bytes(2)
        data = b"\x08\x08\x08"+self.ipbyte.to_bytes(1)
        self.ipbyte += 1
        self.awrs.append(qbuf+ttl+dlen+data)
        self.an_num += 1
        
    def add_fwd_a(self,qbuf):
        self.awrs.append(qbuf)
        print("ADDING ANSWER TO ID",self.pid)
        self.an_num += 1
        
    def make_msg(self):
        msg = self.get_header()
        for q in self.qtns:
            print("Adding question:",q)
            msg += q
        for a in self.awrs:
            print("Adding answer:",a)
            msg += a
        return msg
    
    def make_fwdquery(self,sk,fwdaddr,c_addr):
        if ":" in fwdaddr:
            addr, port = fwdaddr.split(":")
            port = int(port)
        else:
            print("Error resolver info incorrect")
            exit()
        fwdquery = self.get_header() + self.qtns[-1]
        fwdqueries[self.get_header()[:2]] = self
        print("MSG TO SERVER",fwdquery)
        sk.sendto(fwdquery,0,(addr,port))
    
    def qacountmatch(self):
        print("CHECKING ID:",self.pid)
        return len(qtns) == len(awrs)
    
    def get_raw_buf(self):
        return self.buf
    
    def send_query(self,sk,fwdaddr):
        header = self.get_fwdhdr()
        self.parse_questions()
        for q in self.qtns:
            query = header + q
            sk.sendto(query,fwaddr)
        
            
    def parse_questions(self):
        subbuf = b""
        bpos = 12
        qd_num = int.to_bytes(self.buf[4:6])
        for _ in range(qd_num):
            while buf[bpos]:
                if buf[bpos] & 0xc0:
                    msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
                    sect_end = msg_offset
                    while buf[sect_end]:
                        sect_end += 1
                    subbuf += buf[msg_offset:sect_end]
                    bpos += 1
                    break
                else:
                    subbuf_start = bpos
                    bpos += buf[bpos]+1
                    subbuf += buf[subbuf_start:bpos]
            bpos += 1
            subbuf += b"\x00" + buf[bpos:bpos+4]
            bpos += 4
            self.qtns.append(subbuf)
            
def get_answer_from_server(self,sbuf):
    bpos = 12
    while buf[bpos]:
        if buf[bpos] & 0xc0:
            msg_offset = int.from_bytes(sbuf[bpos:bpos+2]) & 0x3fff
            sect_end = msg_offset
            while sbuf[sect_end]:
                sect_end += 1
            bpos += 1
            break
        else:
            bpos += sbuf[bpos]+1
    bpos += 5
    return sbuf[bpos:]
            
        

def main():
    
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            bufhdr = buf[:12]
            msgid = bufhdr[:2]
            print("FROM SOURCE:",source)
            print("BUF:",buf)
            if msgid in fwdqueries.keys():
                cdns = fwdqueries[msgid]
                awr = get_answer_from_server(buf)
                client = cdns.client
                cdns.awrs.append(awr)
                if cdns.qacountmatch():
                    print("TO CLIENT:",client,"->",buf)
                    response = cdns.make_msg()
                    udp_socket.sendto(response,client)
                    del fwdqueries[msgid]
                '''
                print("FROM SERVER:",buf)
                dnsq = fwdqueries[qid]
                dnsq.update_flags(bufhdr)
                qd_num = int.from_bytes(bufhdr[4:6])
                bpos = 12
                for _ in range(qd_num):
                    while buf[bpos]:
                        if buf[bpos] & 0xc0:
                            msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
                            sect_end = msg_offset
                            while buf[sect_end]:
                                sect_end += 1
                            bpos += 1
                            break
                        else:
                            bpos += buf[bpos]+1
                    bpos += 5
                for an in dnsq.awrs:
                    print("ANSWER:",an)
                dnsq.add_fwd_a(buf[bpos:])
                #if dnsq.qacountmatch() or dnsq.an_num > dnsq.qd_num:
                response = dnsq.make_msg()
                print("FINAL MSG:",response)
                udp_socket.sendto(response,dnsq.client_addr)
                dnsq.qd_num = 0
                dnsq.an_num = 0
                #else:
                #print("MISMATCH:",dnsq.qd_num,dnsq.an_num)
                '''
                            
            else:
                #bpos = 12
                #dmsg = DNSMessage(buf)
                rsp = DNSMessage(buf,source)
                #qd_num = int.from_bytes(bufhdr[4:6])
                fwdqueries[buf[:2]] = rsp
                rsp.send_query(udp_socket,socket_from_addr(sys.argv[2]))
                '''
                for _ in range(qd_num):
                    subbuf = b""
                    while buf[bpos]:
                        if buf[bpos] & 0xc0:
                            msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
                            sect_end = msg_offset
                            while buf[sect_end]:
                                sect_end += 1
                            subbuf += buf[msg_offset:sect_end]
                            bpos += 1
                            break
                        else:
                            subbuf_start = bpos
                            bpos += buf[bpos]+1
                            subbuf += buf[subbuf_start:bpos]
                    bpos += 1
                    subbuf += b"\x00" + buf[bpos:bpos+4]
                    bpos += 4
                    rsp.add_q(subbuf)
                    rsp.make_fwdquery(udp_socket,sys.argv[2],source)
                    '''
            """
            bpos = 12
            dmsg = DNSMessage(buf)
            rsp = DNSMessage(buf)
            qd_num = int.from_bytes(bufhdr[4:6])
            for _ in range(qd_num):
                subbuf = b""
                while buf[bpos]:
                    if buf[bpos] & 0xc0:
                        msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
                        sect_end = msg_offset
                        while buf[sect_end]:
                            sect_end += 1
                        subbuf += buf[msg_offset:sect_end]
                        bpos += 1
                        break
                    else:
                        subbuf_start = bpos
                        bpos += buf[bpos]+1
                        subbuf += buf[subbuf_start:bpos]
                bpos += 1
                subbuf += b"\x00" + buf[bpos:bpos+4]
                bpos += 4
                rsp.add_q(subbuf)
                rsl_flag = "--resolver"
                if rsl_flag in sys.argv:
                    forwarding = sys.argv.index(fsl_flag) + 1
                    rsp.make_fwdquery(udp_socket,forwarding,source)
                rsp.add_a(subbuf)
                qd_buf = b""
            
            print("CL_MSG:",buf)
            dmsg = DNSMessage(buf)
            rsp = DNSMessage()
            rsp.pid = dmsg.pid
            rsp.set_flag(QR)
            rsp.set_flag(OPCODE,dmsg.flags)
            rsp.set_flag(RD,dmsg.flags)
            rsp.set_flag(RCODE)
            
            bpos = 12
            for _ in range(dmsg.qd_num):
                subbuf = b""
                while buf[bpos]:
                    if buf[bpos] & 0xc0:
                        msg_offset = int.from_bytes(buf[bpos:bpos+2]) & 0x3fff
                        sect_end = msg_offset
                        while buf[sect_end]:
                            sect_end += 1
                        subbuf += buf[msg_offset:sect_end]
                        bpos += 1
                        break
                    else:
                        subbuf_start = bpos
                        bpos += buf[bpos]+1
                        subbuf += buf[subbuf_start:bpos]
                bpos += 1
                subbuf += b"\x00" + buf[bpos:bpos+4]
                bpos += 4
                rsp.add_q(subbuf)
                rsp.add_a(subbuf)
                qd_buf = b""
                """
                        
            #response = rsp.make_msg()
            #print("RSP:",response)
            #udp_socket.sendto(response, source)
            print("MSG HANDLED")
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
