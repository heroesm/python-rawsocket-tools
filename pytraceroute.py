#! /usr/bin/env python3

import sys
import os
import socket
import struct
import time
import logging
import argparse
import threading
from collections import namedtuple
from random import random

TARGET = '';
LOGLEVEL = logging.DEBUG;
SIZE = 0;
INTERVAL = 0.2;
TIMEOUT = 3;
TTLMIN = None;
TTLMAX = None;
VERBOSE = False;
NUMBER = 3;
PORT = 0;
TYPE = 'icmp';

nEthHeader = 14;
nIpHeader = 20;
nIcmp8Header = 8;
IpObj = namedtuple('IpObj', 'verIhl,dscpEcn,length,ident,flagsOffset,ttl,protocol,checksum,saddr,daddr,options,payload');
IcmpObj = namedtuple('IcmpObj', 'type,code,checksum,ident,seq,payload');
UdpObj = namedtuple('UdpObj', ('sport', 'dport', 'length', 'checksum', 'payload'));
TcpObj = namedtuple('TcpObj', 'sport,dport,seq,ackn,offset,urg,ack,psh,rst,syn,fin,window,checksum,urgp,options,payload');
log = None;

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

class TraceRoute():
    def __init__(self, sTarget, nTtlMin=None, nTtlMax=None, nTimeout=None, nInterval=None, nNumber=None):
        global TTLMIN, TTLMAX, TIMEOUT, INTERVAL, NUMBER;
        self.sTarget = sTarget;
        self.sAddr = socket.gethostbyname(sTarget);
        self.sHost = localAddr(self.sAddr);
        self.nTtlMin = nTtlMin or TTLMIN or 1;
        self.nTtlMax = nTtlMax or TTLMAX or 30;
        assert self.nTtlMin < self.nTtlMax;
        self.nTimeout = nTimeout or TIMEOUT or 3.0;
        self.nInterval = nInterval or INTERVAL or 0.2;
        self.nNumber = nNumber or NUMBER or 3;
        self.aHops = [];
        self.aGoalRtts = [];
        self.sProtocol = None;
        # first IP identification 
        self.nFirstId = os.getpid() + (int(time.time()) & 0xfff) or 1;
        self.sendSock = None;
        self.recvSock = None;
        self.goalSock = None;
        self.recvThread = None;
        self.goalThread = None;
        self.event = threading.Event();
        self.nTtlCursor = 0;
        self.topHop = 0;
        self.topAddr = None;
        self.isRunning = False;
        self.isSending = False;
    def findAndPurge(self, index, sAttr):
        # search IP packet and auxiliary information within the most current 4 hops, older data shall be purged
        # hops range from 1 to len(aHops), differing from index of aHops by 1;
        nEnd = self.nTtlCursor - 1;
        nStart = nEnd - len(self.aHops) + 1
        nBound = max(nEnd - 9, nStart);
        nCursor = nStart;
        while nCursor <= nEnd:
            hop = self.aHops[nCursor];
            if (hop):
                if (nCursor < nBound):
                    setattr(hop, sAttr, {});
                else:
                    mInfo = getattr(hop, sAttr).get(index);
                    if (mInfo):
                        return mInfo;
            nCursor += 1;
        return False;
    def reset(self):
        self.aHops = [];
        self.topHop = 0;
        self.topAddr = None;
        self.isRunning = False;
        self.isSending = False;
        self.event.set();
        if (self.recvThread):
            self.recvThread.join();
            self.recvThread = None;
        if (self.goalThread):
            self.goalThread.join();
            self.goalThread = None;
        if (self.sendSock):
            self.sendSock.close();
            self.sendSock = None;
        if (self.recvSock):
            self.recvSock.close();
            self.recvSock = None;
        if (self.goalSock):
            self.goalSock.close();
            self.goalSock = None;
    def send(self):
        raise NotImplementedError;
    def handleReply(self, bIp, sHopAddr):
        nRecvTime = time.monotonic() * 1000;
        ip = parseIp(bIp);
        assert sHopAddr == ip.saddr;
        icmp = parseIcmp(ip.payload);
        if not (icmp.type == 11 and icmp.code == 0):
            return False;
        oriIp = parseIp(icmp.payload);
        mSent = self.findAndPurge(oriIp.ident, 'mIdMap');
        if (mSent):
            sentIp = mSent['ip'];
            nSentTime = mSent['nSent'];
            nRtt = nRecvTime- nSentTime;
            nHop = sentIp.ttl;
            hop = self.aHops[nHop-1];
            assert hop;
            hop.addHost(sHopAddr);
            hop.addRtt(nRtt);
            if (self.topHop > nHop):
                pass
                #log.debug('\ndisordered packet in hop {} from {}: {:.3f} ms\n'.format(nHop, sHopAddr, nRtt));
            else:
                if (self.topHop < nHop):
                    sys.stdout.write('\n{:2}:'.format(nHop));
                    self.topHop = nHop;
                    self.topAddr = None;
                if (self.topAddr != sHopAddr):
                    sys.stdout.write(' {}'.format(sHopAddr));
                    self.topAddr = sHopAddr;
                sys.stdout.write(' {:.3f} ms'.format(nRtt));
                sys.stdout.flush();
            return True;
        else:
            return False
    def receive(self, nFalseThreshold=9999):
        global parseIp;
        self.recvSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP);
        self.recvSock.settimeout(self.nTimeout);
        nFalseCount = 0;
        while nFalseCount < nFalseThreshold and self.isRunning:
            try:
                bIp, aHopAddr = self.recvSock.recvfrom(4096);
            except socket.timeout as e:
                if (self.isSending):
                    self.event.wait();
                    self.event.clear();
                    continue;
                else:
                    print('\nreceiving socket timeout, stop running');
                    self.isRunning = False;
                    self.event.set();
                    break;
            else:
                #log.debug('icmp packets from {}: {}'.format(bIp, aHopAddr));
                sHopAddr = aHopAddr[0];
                isHandled = self.handleReply(bIp, sHopAddr);
                if (not isHandled):
                    nFalseCount += 1;
        print();
        if (nFalseCount == nFalseThreshold):
            print('too many unmatched ICMP messages received, abort ICMP receiving')
        self.recvSock.close();
        self.recvSock = None;
    def goalCheck(self):
        raise NotImplementedError;
    def output(self):
        sys.stderr.write('\n');
        for hop in self.aHops:
            if (not hop):
                continue;
            if (hop.sAddr):
                sAddrs = ', '.join(hop.aAddrs);
                sRtts = ', '.join(str(round(x, 3)) for x in hop.aRtts);
                sOutput = '\n'.join([
                    'hop {} from {}: {} ms',
                    '  {} packets transmitted, {} received, {:.3f}% packet loss',
                    '  rtt min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms',
                    ''
                ]).format(
                    hop.nHop, sAddrs, sRtts,
                    hop.nSent, hop.nRecv, hop.nLossRate,
                    hop.nMin, hop.nAvg, hop.nMax, hop.nMdev
                );
                sys.stderr.write(sOutput);
            else:
                sys.stderr.write('hop {}: no packet received\n'.format(hop.nHop));
            sys.stderr.write('\n');
        if (self.aGoalRtts):
            sRtts = ', '.join(str(round(x, 3)) + ' ms' for x in self.aGoalRtts);
            sys.stderr.write(
                'target host "{}"({}) reached with RTT: {}\n'.format(
                    self.sTarget, self.sAddr, sRtts
                )
            );
    def run(self):
        sys.stdout.write('traceroute to {} ({}), {} hops min, {} hops max, {} bytes payload, {} packets per hop, {} seconds interval, {} seconds timeout\n'
                .format(self.sTarget, self.sAddr, self.nTtlMin, self.nTtlMax, self.nSize, self.nNumber, self.nInterval, self.nTimeout)
        );
        self.reset();
        self.isRunning = True;
        self.recvThread = threading.Thread(target=self.receive, name='recvThread', daemon=True);
        self.recvThread.start();
        self.goalThread = threading.Thread(target=self.goalCheck, name='goalThread', daemon=True);
        self.goalThread.start();
        try:
            self.send();
        except KeyboardInterrupt as e:
            self.isSending = False;
            self.isRunning = False;
            self.event.set();
        self.recvThread.join();
        self.goalThread.join();
        self.output();
        self.reset();

class TcpTraceRoute(TraceRoute):
    def __init__(self, sTarget, nTtlMin=None, nTtlMax=None, nTimeout=None, nDPort=None):
        super().__init__(sTarget, nTtlMin, nTtlMax, nTimeout)
        self.sProtocol = 'tcp';
        self.nSize = 0;
        self.nDPort = nDPort or PORT or 0;
        self.aSPortRange = (40000, 50000);
    def send(self):
        global IpObj
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
        self.isSending = True;
        nSPort = self.aSPortRange[0];
        if (self.nDPort == 0):
            nDPort = int(2 * time.time()) & 0xffff or 1;
        else:
            nDPort = self.nDPort;
        nIpId = self.nFirstId;
        nTtl = self.nTtlMin;
        self.aHops = [None] * (nTtl - 1);
        while nTtl <= self.nTtlMax and self.isSending and self.isRunning:
            hop = Hop(nTtl);
            self.nTtlCursor = nTtl;
            self.aHops.append(hop);
            for i in range(self.nNumber):
                bTcp = craftTcp(sSAddr=self.sHost, sDAddr=self.sAddr, nSPort=nSPort, nDPort=nDPort, syn=1);
                bIp = craftIp(sDAddr=self.sAddr, nId=nIpId, nTtl=nTtl, sProto='tcp', bData=bTcp);
                ip = parseIp(bIp);
                self.sendSock.sendto(bIp, (self.sAddr, 0));
                self.event.set();
                nSentTime = time.monotonic() * 1000;
                hop.mIdMap[nIpId] = {
                        'ip': ip,
                        'nSent': nSentTime
                };
                hop.mSPortMap[nSPort] = {
                        'ip': ip,
                        'nSent': nSentTime
                };
                hop.nSent += 1;
                if (self.nInterval):
                    time.sleep(self.nInterval);
                nSPort += 1;
                if (nSPort > self.aSPortRange[1]):
                    nSPort = self.aSPortRange[0];
                if (self.nDPort == 0):
                    nDPort = (nDPort + 1) & 0xffff or 1;
                nIpId = (nIpId + 1) & 0xffff or 1;
            assert len(self.aHops) == nTtl;
            nTtl += 1;
        self.isSending = False;
    def sendRst(self, ip, tcp):
        bTcp = craftTcp(sSAddr=self.sHost, sDAddr=self.sAddr, nSPort=tcp.dport, nDPort=tcp.sport, nSeq=tcp.ack, rst=1);
        bIp = craftIp(sDAddr=ip.saddr, sProto='tcp', bData=bTcp);
        self.sendSock.sendto(bIp, (ip.saddr, 0));
    def goalCheck(self):
        self.goalSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP);
        self.goalSock.settimeout(0);
        self.goalSock.settimeout(self.nTimeout);
        while self.isRunning:
            try:
                bIp, aRemote = self.goalSock.recvfrom(4096);
            except socket.timeout as e:
                self.event.wait();
                self.event.clear();
                continue;
            sRemote = aRemote[0];
            if (sRemote == self.sAddr):
                nRecvTime = time.monotonic() * 1000;
                ip = parseIp(bIp);
                tcp = parseTcp(ip.payload);
                if (tcp.syn and tcp.ack or tcp.rst):
                    mSent = self.findAndPurge(tcp.dport, 'mSPortMap');
                    if (mSent):
                        sentIp = mSent['ip'];
                        nSentTime = mSent['nSent'];
                        nRtt = nRecvTime - nSentTime;
                        nHop = sentIp.ttl;
                        hop = self.aHops[nHop-1];
                        hop.addHost(sRemote);
                        hop.addRtt(nRtt);
                        self.aGoalRtts.append(nRtt);
                        if (self.isSending):
                            print('\ntarget host reached, stop sending');
                            self.isSending = False;
                        if (tcp.syn):
                            self.sendRst(sentIp, tcp);

class UdpTraceRoute(TraceRoute):
    def __init__(self, sTarget, nTtlMin=None, nTtlMax=None, nTimeout=None, nSize=None, nDPort=None):
        global SIZE, PORT;
        super().__init__(sTarget, nTtlMin, nTtlMax, nTimeout)
        self.sProtocol = 'udp';
        self.nSize = nSize or SIZE or 32;
        self.nDPort = nDPort or PORT or 0;
        self.aSPortRange = (40000, 50000);
    def send(self):
        global IpObj
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
        self.isSending = True;
        nSPort = self.aSPortRange[0];
        if (self.nDPort == 0):
            nDPort = int(2 * time.time()) & 0xffff or 1;
        else:
            nDPort = self.nDPort;
        nIpId = self.nFirstId;
        nTtl = self.nTtlMin;
        self.aHops = [None] * (nTtl - 1);
        while nTtl <= self.nTtlMax and self.isSending and self.isRunning:
            hop = Hop(nTtl);
            self.nTtlCursor = nTtl;
            self.aHops.append(hop);
            for i in range(self.nNumber):
                bUdp = craftUdp(sSAddr=self.sHost, sDAddr=self.sAddr, nSPort=nSPort, nDPort=nDPort, nSize=self.nSize);
                bIp = craftIp(sDAddr=self.sAddr, nId=nIpId, nTtl=nTtl, sProto='udp', bData=bUdp);
                ip = parseIp(bIp);
                self.sendSock.sendto(bIp, (self.sAddr, 0));
                self.event.set();
                nSentTime = time.monotonic() * 1000;
                hop.mIdMap[nIpId] = {
                        'ip': ip,
                        'nSent': nSentTime
                };
                #hop.mSPortMap[nSPort] = {
                #        'ip': ip,
                #        'nSent': nSentTime
                #};
                hop.nSent += 1;
                if (self.nInterval):
                    time.sleep(self.nInterval);
                nSPort += 1;
                if (nSPort > self.aSPortRange[1]):
                    nSPort = self.aSPortRange[0];
                if (self.nDPort == 0):
                    nDPort = (nDPort + 1) & 0xffff or 1;
                nIpId = (nIpId + 1) & 0xffff or 1;
            assert len(self.aHops) == nTtl;
            nTtl += 1;
        self.isSending = False;
    def goalCheck(self):
        self.goalSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP);
        self.goalSock.settimeout(self.nTimeout);
        while self.isRunning:
            try:
                bIp, aRemote = self.goalSock.recvfrom(4096);
            except socket.timeout as e:
                self.event.wait();
                self.event.clear();
                continue;
            sRemote = aRemote[0];
            if (sRemote == self.sAddr):
                nRecvTime = time.monotonic() * 1000;
                ip = parseIp(bIp);
                icmp = parseIcmp(ip.payload);
                if (icmp.type == 3 and icmp.code == 3):
                    oriIp = parseIp(icmp.payload);
                    mSent = self.findAndPurge(oriIp.ident, 'mIdMap');
                    if (mSent):
                        sentIp = mSent['ip'];
                        nSentTime = mSent['nSent'];
                        nRtt = nRecvTime - nSentTime;
                        nHop = sentIp.ttl;
                        hop = self.aHops[nHop-1];
                        hop.addHost(sRemote);
                        hop.addRtt(nRtt);
                        self.aGoalRtts.append(nRtt);
                        if (self.isSending):
                            print('\ntarget host reached, stop sending');
                            self.isSending = False;


class IcmpTraceRoute(TraceRoute):
    def __init__(self, sTarget, nTtlMin=None, nTtlMax=None, nTimeout=None, nSize=None):
        super().__init__(sTarget, nTtlMin, nTtlMax, nTimeout)
        self.sProtocol = 'icmp';
        self.nSize = nSize or SIZE or 32;
        self.nIcmpId = int(time.time()) & 0xffff or 1;
    def send(self):
        global IpObj
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
        self.isSending = True;
        nIcmpSeq = 1;
        nIpId = self.nFirstId;
        nTtl = self.nTtlMin;
        self.aHops = [None] * (nTtl - 1);
        while nTtl <= self.nTtlMax and self.isSending and self.isRunning:
            hop = Hop(nTtl);
            self.nTtlCursor = nTtl;
            self.aHops.append(hop);
            for i in range(self.nNumber):
                bIcmp = craftIcmp(nSize=self.nSize, nId=self.nIcmpId, nSeq=nIcmpSeq);
                bIp = craftIp(sDAddr=self.sAddr, nId=nIpId, nTtl=nTtl, sProto='icmp', bData=bIcmp);
                ip = parseIp(bIp);
                self.sendSock.sendto(bIp, (self.sAddr, 0));
                self.event.set();
                nSentTime = time.monotonic() * 1000;
                hop.mIdMap[nIpId] = {
                        'ip': ip,
                        'nSent': nSentTime
                };
                hop.mIcmpSeqMap[nIcmpSeq] = {
                        'ip': ip,
                        'nSent': nSentTime
                };
                hop.nSent += 1;
                if (self.nInterval):
                    time.sleep(self.nInterval);
                nIcmpSeq = (nIcmpSeq + 1) & 0xffff or 1;
                nIpId = (nIpId + 1) & 0xffff or 1;
            assert len(self.aHops) == nTtl;
            nTtl += 1;
        self.isSending = False;
    def goalCheck(self):
        self.goalSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP);
        self.goalSock.settimeout(self.nTimeout);
        while self.isRunning:
            try:
                bIp, aRemote = self.goalSock.recvfrom(4096);
            except socket.timeout as e:
                self.event.wait();
                self.event.clear();
                continue;
            sRemote = aRemote[0];
            if (sRemote == self.sAddr):
                nRecvTime = time.monotonic() * 1000;
                ip = parseIp(bIp);
                icmp = parseIcmp(ip.payload);
                if (icmp.type == 0 and icmp.code == 0 and icmp.ident == self.nIcmpId):
                    mSent = self.findAndPurge(icmp.seq, 'mIcmpSeqMap');
                    if (mSent):
                        sentIp = mSent['ip'];
                        nSentTime = mSent['nSent'];
                        nRtt = nRecvTime - nSentTime;
                        nHop = sentIp.ttl;
                        hop = self.aHops[nHop-1];
                        hop.addHost(sRemote);
                        hop.addRtt(nRtt);
                        self.aGoalRtts.append(nRtt);
                        if (self.isSending):
                            print('\ntarget host reached, stop sending');
                            self.isSending = False;

def parseArg():
    global LOGLEVEL, TARGET, SIZE, INTERVAL, TIMEOUT, TTLMIN, TTLMAX, NUMBER, PORT, VERBOSE;
    global TYPE;
    global log
    parser = argparse.ArgumentParser(description='traceroute in python3, need superuser privilege, supporting TCP, UDP and ICMP probe');
    parser.add_argument('target',
            help='target address'
    );
    group1 = parser.add_mutually_exclusive_group();
    group1.add_argument('-s', '--size',
            help='set the size of data used to traceroute'
    );
    parser.add_argument('-i', '--interval',
            help='set interval between each packet sent'
    );
    parser.add_argument('-w', '--timeout',
            help='set socket timeout in second'
    );
    parser.add_argument('-f', '--firsttl',
            help='set the initial time to live IP header field'
    );
    parser.add_argument('-m', '--maxttl',
            help='set the maximum time to live IP header field'
    );
    parser.add_argument('-n', '--number',
            help='set the number of packets to be sent per hop'
    );
    parser.add_argument('-p', '--port',
            help='set the destination port to test; only apply to TCP and UDP traceroute; defalut to use various port;'
    );
    parser.add_argument('-v', '--verbose',
            action='store_true',
            help='show verbose per hop RTT output'
    );
    group2 = parser.add_mutually_exclusive_group();
    group2.add_argument('-I', '--icmp',
            action='store_true',
            help='use ICMP echo request to traceroute; the default option, could be omitted'
    );
    group2.add_argument('-U', '--udp',
            action='store_true',
            help='use UDP to traceroute'
    );
    group2.add_argument('-T', '--tcp',
            action='store_true',
            help='use TCP syn to traceroute'
    );
    args = parser.parse_args();
    if (args.verbose):
        LOGLEVEL = logging.DEBUG;
    else:
        LOGLEVEL = logging.INFO;
    log.setLevel(LOGLEVEL);
    VERBOSE = bool(args.verbose);
    TARGET = args.target;
    SIZE = int(args.size or SIZE or 0);
    INTERVAL = float(args.interval or INTERVAL or 0);
    TIMEOUT = float(args.timeout or TIMEOUT or None);
    TTLMIN = int(args.firsttl or TTLMIN or 0);
    TTLMAX = int(args.maxttl or TTLMAX or 0);
    NUMBER = int(args.number or NUMBER or 0);
    PORT = int(args.port or PORT or 0);
    TYPE = 'udp' if args.udp else 'tcp' if args.tcp else 'icmp';
    log.debug('passed command line arguments: {}'.format(
        {key: value for (key, value) in vars(args).items() if value is not None}
    ));
    return args;

def main():
    global TARGET;
    global TYPE;
    if (sys.platform == 'win32'):
        raise NotImplementedError('modifying IP header of raw socket is not supported on Windows!');
    parseArg();
    print('traceroute type: {}'.format(TYPE.upper()));
    if (TYPE == 'tcp'):
        tr = TcpTraceRoute(TARGET);
    elif (TYPE == 'udp'):
        tr = UdpTraceRoute(TARGET);
    else:
        tr = IcmpTraceRoute(TARGET);
    tr.run();

if __name__ == '__main__':
    main();
