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
TIMEOUT = 2;
TTLMIN = None;
TTLMAX = None;
VERBOSE = None;
NUMBER = 1;
PORT = 0;
CYCLE = 0;
REPORT = None;

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

def localAddr():
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    sock1.connect(('1.1.1.1', 1));
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

class Mtr():
    def __init__(self, sTarget, nTtlMin=None, nTtlMax=None, nTimeout=None, nInterval=None, nNumber=None, isVerbose=None, nCycle=0, isReport=None):
        global TTLMIN, TTLMAX, TIMEOUT, INTERVAL, NUMBER, VERBOSE, CYCLE, REPORT;
        self.sHost = localAddr();
        self.sTarget = sTarget;
        self.sAddr = socket.gethostbyname(sTarget);
        self.nTtlMin = int(nTtlMin or TTLMIN or 1);
        self.nTtlMax = int(nTtlMax or TTLMAX or 30);
        assert self.nTtlMin < self.nTtlMax;
        self.nTimeout = float(nTimeout or TIMEOUT or 3.0);
        self.nInterval = float(nInterval or INTERVAL or 0.2);
        self.nNumber = int(nNumber or NUMBER or 3);
        self.isVerbose = isVerbose if isVerbose is not None else VERBOSE;
        self.nCycle = int(nCycle or CYCLE or 0);
        self.isReport = isReport if isReport is not None else REPORT;
        self.aHops = [];
        self.sProtocol = None;
        self.nFirstId = os.getpid() + (int(time.time()) & 0xfff) or 1; # first IP identification 
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
        self.nLines = 0; # lines printed
        self.aOutput = [];
        self.mCache = {};
        self.updateLock = threading.Lock();
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
    def updateOneLine(self, nHop, isSent=False):
        for i in range(len(self.aOutput), nHop):
            self.aOutput.append('{:>2}. ???'.format(i + 1));
        hop = self.aHops[nHop - 1];
        if (isSent):
            aArgs = self.mCache.get(nHop)
            if (not aArgs):
                aArgs = [0,] * 10; 
                aArgs[1] = hop.sAddr;
                aArgs[0] = nHop;
            aArgs[2] = hop.nLossRate;
            aArgs[3] = hop.nSent;
        else:
            sAddr = hop.sAddr;
            if (len(hop.aAddrs) > 1):
                sAddr += ' and {} more'.format(len(hop.aAddrs) - 1);
            aArgs = [
                    nHop, sAddr, hop.nLossRate, hop.nSent, hop.nRecv,
                    hop.nLast, hop.nAvg, hop.nMin, hop.nMax, hop.nMdev
            ];
            self.mCache[nHop] = aArgs;
        sLine = (
                '{:>2}. {:<30} {:>5.1f}% {:>5} {:>5}' +
                ' {:>6.1f} {:>6.1f} {:>6.1f} {:>6.1f} {:>6.1f}'
        ).format(*aArgs);
        self.aOutput[nHop - 1] = sLine;
    def updateDisplay(self, nHop, isSent=False):
        self.updateLock.acquire();
        if (self.nLines):
            sys.stderr.write('\033[{}F\033[0J'.format(self.nLines));
        if (nHop > 0):
            self.updateOneLine(nHop, isSent);
        else:
            for i in range(1, len(self.aHops)):
                self.updateOneLine(i, isSent);
        sOutput = '\n'.join(self.aOutput) + '\n';
        sys.stderr.write(sOutput);
        self.nLines = len(self.aOutput);
        self.updateLock.release();
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
            if (not self.isReport):
                self.updateDisplay(nHop);
            return True;
        else:
            return False
    def receive(self):
        global parseIp;
        self.recvSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP);
        self.recvSock.settimeout(self.nTimeout);
        while self.isRunning:
            try:
                bIp, aHopAddr = self.recvSock.recvfrom(4096);
            except socket.timeout as e:
                if (self.isSending):
                    self.event.wait();
                    self.event.clear();
                    continue;
                else:
                    #log.debug('receiving socket timeout, stop running');
                    self.isRunning = False;
                    self.event.set();
                    break;
            else:
                sHopAddr = aHopAddr[0];
                self.handleReply(bIp, sHopAddr);
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
                #sRtts = ', '.join(str(round(x, 3)) for x in hop.aRtts);
                sOutput = '\n'.join([
                    'hop {} from {}:',
                    '  {} packets transmitted, {} received, {:.3f}% packet loss',
                    '  rtt min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms',
                    ''
                ]).format(
                    hop.nHop, sAddrs,
                    hop.nSent, hop.nRecv, hop.nLossRate,
                    hop.nMin, hop.nAvg, hop.nMax, hop.nMdev
                );
                sys.stderr.write(sOutput);
            else:
                sys.stderr.write('hop {}: no packet received\n'.format(hop.nHop));
            sys.stderr.write('\n');
    def run(self):
        sys.stdout.write('mtr to {} ({}), {} hops min, {} hops max, {} bytes payload, {} packets per hop, {} seconds interval, {} seconds timeout, {} cycles\n'
                .format(self.sTarget, self.sAddr, self.nTtlMin, self.nTtlMax, self.nSize, self.nNumber, self.nInterval, self.nTimeout, self.nCycle)
        );
        sys.stderr.write('{0:46}Packets{0:30}Pings\n'.format(''));
        sys.stderr.write(' Host {:28}  Loss%   Snt   Rcv   Last    Avg   Best   Wrst  StDev\n'.format(''));
        self.reset();
        self.isRunning = True;
        self.recvThread = threading.Thread(target=self.receive, name='recvThread', daemon=True);
        self.recvThread.start();
        self.goalThread = threading.Thread(target=self.goalCheck, name='goalThread', daemon=True);
        self.goalThread.start();
        try:
            nIpId = nIcmpSeq = None;
            nCycle = 0;
            while not self.nCycle or nCycle < self.nCycle:
                nIpId, nIcmpSeq = self.send(nIpId, nIcmpSeq);
                nCycle += 1;
        except KeyboardInterrupt as e:
            print();
        finally:
            self.isSending = False;
            self.isRunning = False;
            self.event.set();
        #self.recvThread.join();
        #self.goalThread.join();
        if (self.isReport):
            self.updateDisplay(0);
        if (self.isVerbose):
            self.output();
        #self.reset();

class IcmpMtr(Mtr):
    def __init__(self, sTarget, nTtlMin=None, nTtlMax=None, nTimeout=None, nSize=None):
        super().__init__(sTarget, nTtlMin, nTtlMax, nTimeout)
        self.sProtocol = 'icmp';
        self.nSize = nSize or SIZE or 32;
        self.nIcmpId = int(time.time()) & 0xffff or 1;
    def send(self, nIpId=None, nIcmpSeq=None):
        global IpObj
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
        self.isSending = True;
        nIpId = nIpId or self.nFirstId;
        nIcmpSeq = nIcmpSeq or 1;
        nTtl = self.nTtlMin;
        if (not self.aHops):
            self.aHops = [None] * (nTtl - 1);
        while nTtl <= self.nTtlMax and self.isSending and self.isRunning:
            self.nTtlCursor = nTtl;
            hop = self.aHops[nTtl-1:nTtl];
            hop = hop and hop[0];
            if (not hop):
                hop = Hop(nTtl);
                self.aHops.append(hop);
                assert len(self.aHops) == nTtl;
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
                if (not self.isReport):
                    self.updateDisplay(nTtl, isSent=True);
            nTtl += 1;
        self.sendSock.close();
        self.sendSock = None;
        return nIpId, nIcmpSeq;
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
                        self.nTtlMax = nHop;
                        if (not self.isReport):
                            self.updateDisplay(nHop);

def parseArg():
    global LOGLEVEL, TARGET, SIZE, INTERVAL, TIMEOUT, TTLMIN, TTLMAX, NUMBER, PORT, VERBOSE, CYCLE, REPORT;
    global log
    parser = argparse.ArgumentParser(description='mtr in python3 using threading, need superuser privilege, only ICMP implemented; use ctrl+c to terminate');
    parser.add_argument('target',
            help='target address'
    );
    group1 = parser.add_mutually_exclusive_group();
    group1.add_argument('-s', '--size',
            help='set the size of data used as probe'
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
    parser.add_argument('-v', '--verbose',
            action='store_true',
            help='show debug output'
    );
    parser.add_argument('-c', '--cycle',
            help='set the count to cycle; defaluts to 0 meaning cycling until terminated by user;'
    );
    parser.add_argument('-r', '--report',
            action='store_true',
            help='report mode, supress output while running and display the output when terminated instead; could be combined with -c'
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
    CYCLE = int(args.cycle or CYCLE or 0);
    REPORT = args.report;
    log.debug('passed command line arguments: {}'.format(
        {key: value for (key, value) in vars(args).items() if value is not None}
    ));
    return args;

def main():
    global TARGET;
    if (sys.platform == 'win32'):
        raise NotImplementedError('modifying IP header of raw socket is not supported on Windows!');
    parseArg();
    mtr = IcmpMtr(TARGET);
    mtr.run();

if __name__ == '__main__':
    main();
