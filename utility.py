# this file just exists for reference, but actually useless

# Why not using packet socket to implement traceroute? Using packet socket might reduce the code (no need to set up goalCheck and goalThread additionally for example), but the performance could be poorer and the portablity is unsure (although both raw socket and packet socket are sure to be somehow incapable on Windows);

import os
import logging
import socket
import struct
from random import random

#  <linux/if_ether.h>
#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */

ETH_P_IP = 0x0800;
ETH_P_ALL = 3;


#ipSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
#icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'));
#ethSock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP));
#rawEthSock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL));
#sock1 = icmpSock;
#sock1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
#sock1.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1);

def prepare():
    global log;
    global LOGLEVEL;
    logging.basicConfig();
    log = logging.getLogger();
    log.setLevel(LOGLEVEL);
    socket.setdefaulttimeout(10);
prepare();

def localAddr(sRemote=None):
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    sRemote = sRemote or '1.1.1.1';
    sock1.connect((sRemote, 1));
    sAddr = sock1.getsockname()[0]
    sock1.close();
    return sAddr;

def checksum(bData):
    if (len(bData) & 1):
        bData += b'\x00';
    i = 0;
    nSum = 0;
    while i < len(bData):
        nSum += (bData[i] << 8) + bData[i+1];
        i += 2;
    nCarry = nSum >> 16;
    while nCarry:
        nSum = (nSum & 0xffff) + nCarry;
        nCarry = (nSum >> 16);
    nSum = (~nSum & 0xffff);
    return nSum;

def craftIp(ip=None, sDAddr=None, sSAddr=None, nId=None, nFlagsOffset=None, nTtl=None, sProto=None, bData=None):
    # Linux will fill in source address, packet ID, IP checksum and total length field.
    sDAddr = sDAddr or getattr(ip, 'daddr', None);
    assert sDAddr;
    bDAddr = socket.inet_aton(sDAddr);
    sSAddr = sSAddr or getattr(ip, 'saddr', None);
    bSAddr = sSAddr and socket.inet_aton(sSAddr) or b'\x00' * 4;
    # (4 << 4) + 5 = 69
    nVerIhl = 69;
    nId = nId or getattr(ip, 'ident', None) or 0;
    # 0b0100000000000000 == 16384, meaning 'don't fragment' only
    nFlagsOffset = nFlagsOffset or getattr(ip, 'flagsOffset', None) or 16384;
    nTtl = nTtl or getattr(ip, 'ttl', None) or 64;
    sProto = sProto;
    # socket.getprotobyname('tcp') == 6
    nProto = sProto and socket.getprotobyname(sProto) or getattr(ip, 'protocol', 6);
    bData = bData or getattr(ip, 'payload', None) or b'';
    bHeader = struct.pack('>BBHHHBBH',
            nVerIhl, 0, 0,
            nId, nFlagsOffset,
            nTtl, nProto, 0
    );
    bHeader += bSAddr + bDAddr;
    bIp = bHeader + bData;
    #log.debug('crafted ip packet: {}'.format(locals()));
    return bIp;

def craftIcmp(icmp=None, bData=b'', nSize=0, nId=0, nSeq=0):
    nType = 8;
    nCode = 0;
    nCheck = 0;
    nId =  nId or getattr(icmp, 'ident', None) or os.getpid();
    nSeq = nSeq or getattr(icmp, 'seq', None) or 1;
    bData = bData or getattr(icmp, 'payload', None) or (nSize and nSize * b'\x00') or b'';
    bHeader = struct.pack('>BBHHH', nType, nCode, nCheck, nId, nSeq);
    bIcmp = bHeader + bData;
    nCheck = checksum(bIcmp);
    bHeader = struct.pack('>BBHHH', nType, nCode, nCheck, nId, nSeq);
    bIcmp = bHeader + bData;
    return bIcmp;

def craftUdp(udp=None, sSAddr=None, sDAddr=None, nSPort=None, nDPort=None, bData=None, nSize=None):
    nSPort = nSPort or getattr(udp, 'sport', 0);
    nDPort = nDPort or getattr(udp, 'dport', 0);
    bData = bData or getattr(udp, 'payload', b'') or (nSize and nSize * b'\x00') or b'';
    nLength = len(bData) + 8;
    nCheck = 0;
    bHeader = struct.pack('>HHHH', nSPort, nDPort, nLength, nCheck);
    bUdp = bHeader + bData;
    if (sSAddr and sDAddr):
        bPseudo = socket.inet_aton(sSAddr) + socket.inet_aton(sDAddr) + struct.pack('>BBH', 0, 17, len(bUdp));
        nCheck = checksum(bPseudo + bUdp);
        bHeader = struct.pack('>HHHH', nSPort, nDPort, nLength, nCheck);
        bUdp = bHeader + bData;
    return bUdp;

def craftTcp(tcp=None, sSAddr=None, sDAddr=None, nSPort=0, nDPort=0, nSeq=0, nAckn=0, urg=0, ack=0, psh=0, rst=0, syn=0, fin=0, nWindow=0, nUrgp=0, bOptions=None, bData=None, nSize=0):
    nSPort = nSPort or getattr(tcp, 'sport', 0);
    nDPort = nDPort or getattr(tcp, 'dport', 0);
    nSeq = nSeq or getattr(tcp, 'seq', 0) or int(random() * 10000);
    nAckn = nAckn or getattr(tcp, 'ackn', 0);
    bOptions = bOptions or getattr(tcp, 'options', b'');
    bOptions += b'\x00' * (-len(bOptions) % 4)
    nOffset = 5 + len(bOptions) // 4;
    assert nOffset >> 4 == 0;
    urg = bool(urg or getattr(tcp, 'urg', 0));
    ack = bool(ack or getattr(tcp, 'ack', 0));
    psh = bool(psh or getattr(tcp, 'psh', 0));
    rst = bool(rst or getattr(tcp, 'rst', 0));
    syn = bool(syn or getattr(tcp, 'syn', 0));
    fin = bool(fin or getattr(tcp, 'fin', 0));
    nORF = (nOffset << 12) + (urg << 5) + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin;
    nWindow = nWindow or getattr(tcp, 'window', 29200);
    nCheck = 0;
    nUrgp = nUrgp or getattr(tcp, 'urgp', 0);
    bData = bData or getattr(tcp, 'payload', b'') or (nSize and nSize * b'\x00') or b'';
    bHeader = struct.pack('>HHLLHHHH', nSPort, nDPort, nSeq, nAckn, nORF, nWindow, nCheck, nUrgp);
    bTcp = bHeader + bOptions + bData;
    bPseudo = socket.inet_aton(sSAddr) + socket.inet_aton(sDAddr) + struct.pack('>BBH', 0, 6, len(bTcp));
    nCheck = checksum(bPseudo + bTcp);
    bHeader = struct.pack('>HHLLHHHH', nSPort, nDPort, nSeq, nAckn, nORF, nWindow, nCheck, nUrgp);
    bTcp = bHeader + bOptions + bData;
    return bTcp;


def parseIp(bIn):
    assert len(bIn) >= 20;
    global IpObj;
    (
        verIhl, dscpEcn, length,
        ident, flagsOffset,
        ttl, protocol, checksum
    ) = struct.unpack('>BBHHHBBH', bIn[:12]);
    saddr = socket.inet_ntoa(bIn[12:16]);
    daddr = socket.inet_ntoa(bIn[16:20]);
    nVersion = verIhl >> 4;
    if (not nVersion == 4):
        return False;
    nHeaderLength = verIhl & 0xf;
    nOffset = nHeaderLength * 4;
    options = bIn[20:nOffset];
    payload = bIn[nOffset:]
    ip = IpObj(verIhl, dscpEcn, length, ident, flagsOffset, ttl, protocol, checksum, saddr, daddr, options, payload);
    return ip;

def parseIcmp(bIn):
    global IcmpObj;
    #nType, nCode, nCheck, nId, nSeq = struct.unpack('>BBHHH', bIn[:8]);
    aIcmp = struct.unpack('>BBHHH', bIn[:8]);
    bData = bIn[8:];
    #icmp = IcmpObj(nType, nCode, nCheck, nId, nSeq, bData);
    icmp = IcmpObj(*aIcmp, bData);
    return icmp;

def parseUdp(bIn):
    global UdpObj;
    aUdp = struct.unpack('>HHHH', bIn[:8]);
    bData = bIn[8:]
    udp = UdpObj(*aUdp, bData);
    return udp;

def parseTcp(bIn):
    global TcpObj;
    sport, dport, seq, ackn, nORF, window, checksum, urgp = struct.unpack('>HHLLHHHH', bIn[:20])
    offset = (nORF >> 12);
    nOffset = offset * 4;
    urg = (nORF >> 5) & 1;
    ack = (nORF >> 4) & 1;
    psh = (nORF >> 3) & 1;
    rst = (nORF >> 2) & 1;
    syn = (nORF >> 1) & 1;
    fin = nORF & 1;
    bOptions = bIn[20: nOffset];
    bData = bIn[nOffset:];
    tcp = TcpObj(sport, dport, seq, ackn, offset, urg, ack, psh, rst, syn, fin, window, checksum, urgp, bOptions, bData);
    return tcp;

class Hop():
    @property
    def nRecv(self):
        return len(self.aRtts);
    @property
    def nLast(self):
        if (self.aRtts):
            return self.aRtts[-1];
        else:
            return 0;
    @property
    def nMin(self):
        if (self.aRtts):
            return min(self.aRtts);
        else:
            return 0;
    @property
    def nMax(self):
        if (self.aRtts):
            return max(self.aRtts);
        else:
            return 0;
    @property
    def nAvg(self):
        if (self.aRtts):
            return sum(self.aRtts) / self.nRecv;
        else:
            return 0;
    @property
    def nMdev(self):
        if (self.aRtts):
            nSquareSum = sum(map(lambda x:x*x, self.aRtts))
            nMdev = (nSquareSum / self.nRecv - self.nAvg ** 2) ** 0.5;
            return nMdev
        else:
            return 0;
    @property
    def nLossRate(self):
        return (1 - self.nRecv / self.nSent) * 100;

    def __init__(self, nHop, sAddr=None, aRtts=None):
        self.nHop = int(nHop);
        self.sAddr = sAddr or '';
        self.aAddrs = [];
        if (self.sAddr):
            self.aAddrs.append(self.sAddr);
        self.aRtts = aRtts or [];
        self.mIdMap = {};
        self.mSPortMap = {};
        self.mIcmpSeqMap = {};
        self.nSent = 0;
        #self.nRecv
        #self.nMin
        #self.nMax
        #self.nAvg
        #sefl.nMdev
        #self.nLossRate
    def addHost(self, sAddr):
        assert sAddr;
        if (not self.sAddr): self.sAddr = sAddr;
        if (not sAddr in self.aAddrs): self.aAddrs.append(sAddr);
    def addRtt(self, nRtt):
        self.aRtts.append(nRtt);
