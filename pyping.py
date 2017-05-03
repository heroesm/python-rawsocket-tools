#! /usr/bin/env python3

import sys
import os
import socket
import struct
import time
import logging
import argparse
#from binascii import hexlify
from collections import namedtuple

#  <linux/if_ether.h>
#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet	*/
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/
#define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */

TARGET = '';
LOGLEVEL = logging.DEBUG;
INPUT = b'';
SIZE = 0;
INTERVAL = 0.3;
TIMEOUT = 3;
COUNT = 0;
TTL = None;
INTERFACE = '';
QUIET = False;

ETH_P_IP = 0x0800;
ETH_P_ALL = 3;

log = None;

nEthHeader = 14;
nIpHeader = 20;
nIcmp8Header = 8;

IpObj = namedtuple('IpObj', 'verIhl,dscpEcn,length,ident,flagsOffset,ttl,protocol,checksum,saddr,daddr,options,payload');
IcmpObj = namedtuple('IcmpObj', 'type,code,checksum,ident,seq,payload');

def prepare():
    global log
    global LOGLEVEL
    logging.basicConfig();
    log = logging.getLogger();
    log.setLevel(LOGLEVEL);
    socket.setdefaulttimeout(10);
prepare();

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
    # socket.getprotobyname('tcp') == 6
    sProto = sProto or getattr(ip, 'protocol', None) or 'icmp';
    nProto = socket.getprotobyname(sProto);
    bData = bData or getattr(ip, 'payload', None) or b'';
    bHeader = struct.pack('>BBHHHBBH',
            nVerIhl, 0, 0,
            0, nFlagsOffset,
            nTtl, nProto, 0
    );
    bHeader += bSAddr + bDAddr;
    bOut = bHeader + bData;
    #log.debug('crafted ip packet: {}'.format(locals()));
    return bOut;

def craftIcmp(icmp=None, bData=b'', nSize=0, nId=0, nSeq=0):
    nType = 8;
    nCode = 0;
    nCheck = 0;
    nId =  nId or getattr(icmp, 'ident', None) or os.getpid();
    nSeq = nSeq or getattr(icmp, 'seq', None) or 1;
    bData = bData or getattr(icmp, 'payload', None) or (nSize and nSize * b'\x00') or b'';
    bHeader = struct.pack('>BBHHH', nType, nCode, nCheck, nId, nSeq);
    bOut = bHeader + bData;
    nCheck = checksum(bOut);
    bHeader = struct.pack('>BBHHH', nType, nCode, nCheck, nId, nSeq);
    bOut = bHeader + bData;
    return bOut;

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

def showStat(sOriName, aRtts):
    global log;
    assert aRtts;
    nAllCount = len(aRtts);
    i = 0;
    nRecvCount = 0;
    nSum = nSquareSum = 0;
    nMin = float('inf');
    nMax = 0.0;
    while i < nAllCount:
        nRtt = aRtts[i];
        if (nRtt > 0):
            nRecvCount += 1;
            if (nRtt < nMin):
                nMin = nRtt;
            elif (nRtt > nMax):
                nMax = nRtt;
            nSum += nRtt;
            nSquareSum += nRtt**2;
        i += 1;
    if (nRecvCount):
        nLossRate = 1 - nRecvCount / nAllCount;
        nAvg = nSum / nRecvCount;
        nMdev = (nSquareSum / nRecvCount - nAvg ** 2) ** 0.5;
    else:
        nLossRate = 1.0;
        nMin = nMax = nAvg = nMdev = 0.0;
    sOut = '\n'.join([
            '',
            '--- {} ping statistics ---',
            '{} packets transmitted, {} received, {:.3f}% packet loss',
            'rtt min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms'
    ]).format(sOriName, nAllCount, nRecvCount, nLossRate*100, nMin, nAvg, nMax, nMdev);
    print(sOut);
    return True;

def recvIcmpReply(recvSock, nTime0, sAddr=None, nTopSeq=None, nId=None, isQuiet=False):
    # return round trip time in millisecond
    global nEthHeader;
    global log;
    try:
        while True:
            aRes = recvSock.recvfrom(4096);
            nElapse = time.monotonic() - nTime0;
            nRtt = nElapse * 1000;
            bData = aRes[0];
            ip = parseIp(bData);
            log.debug('ip: {}'.format(ip));
            icmp = parseIcmp(ip.payload);
            log.debug('icmp: {}'.format(icmp));
            if (nId and nId != icmp.ident or sAddr and sAddr != ip.saddr):
                log.debug('unmatched reply. id: {}, {}; addr: {} {}'
                        .format(nId, icmp.ident, sAddr, ip.saddr)
                );
                continue;
            if (nTopSeq):
                log.debug('top seq: {}, target seq: {}'.format(nTopSeq, icmp.seq));
                assert icmp.seq <= nTopSeq;
                if (icmp.seq == nTopSeq):
                    if (not isQuiet):
                        nEthLength = len(bData) + nEthHeader;
                        print('{} bytes from {}: icmp_seq={} ttl={} time={:.2f} ms'
                            .format(nEthLength, sAddr, icmp.seq, ip.ttl, nRtt)
                        );
                    return nRtt;
                else:
                    continue;
            else:
                return nRtt;
    except (socket.timeout, BlockingIOError) as e:
        if (not isQuiet):
            print('ping to {} timeout'.format(sAddr))
        return 0;

def ping(sAddr, bInput=None, *, nSize=None, nInterval=None, nTimeout=None, nMaxCount=None, nTtl=None, sInterface=None, isQuiet=None):
    global TARGET, INPUT, SIZE, INTERVAL, TIMEOUT, COUNT, TTL, INTERFACE, QUIET;
    global nIpHeader, nIcmp8Header;
    global log;
    global IpObj, IcmpObj;
    nSize = int(nSize or SIZE or 0);
    bInput = bInput or (nSize and nSize * b'\x00') or INPUT or b'';
    nSize = len(bInput);
    nInterval = float(nInterval or INTERVAL or 0);
    nTimeout = float(nTimeout or TIMEOUT or 0);
    nMaxCount = int(nMaxCount or COUNT or 0);
    nTtl = int(nTtl or TTL or 0);
    sInterface = sInterface or INTERFACE or '';
    isQuiet = isQuiet or QUIET or False;

    sOriName = sAddr;
    sAddr = socket.gethostbyname(sAddr);
    aAddr = (sAddr, 0);
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP);
    print('PING {} ({}) {} bytes of data.'.format(
        sOriName, sAddr, nSize + nIpHeader + nIcmp8Header
    ));
    isRawIp = False;
    if (nTtl):
        # it seems impossible to customise the IP header to be sent in Windows
        if (sys.platform == 'win32'):
            raise NotImplementedError('cannot send raw IP socket in Windows');
        sock1.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1);
        # raw IP socket is unable to receive inbound packets
        #sock1 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW);
        isRawIp = True;
    if (sInterface):
        sock1.bind((sInterface, 0));
    sock1.settimeout(nTimeout);
    nCount = 0;
    nId = os.getpid();
    nSeq = 1;
    aDelays = [];
    try:
        while not nMaxCount or nCount < nMaxCount:
            nTime0 = time.monotonic();
            nElapse = 0;
            #bIcmp = craftIcmp(bData=bInput, nnSize=nSize, nId=nId, nSeq=nSeq);
            icmp = IcmpObj(8, 0, 0, nId, nSeq, bInput);
            bIcmp = craftIcmp(icmp=icmp, nSize=nSize);
            bData = bIcmp;
            if (isRawIp):
                ip = IpObj(0, 0, 0, 0, 0, nTtl, 'icmp', 0, 0, sAddr, 0, bIcmp);
                bIp = craftIp(ip=ip);
                #bIp = craftIp(sAddr, nTtl=nTtl, sProto='icmp', bData=bIcmp);
                bData = bIp;
            sock1.sendto(bData, aAddr);
            nRtt = recvIcmpReply(sock1, nTime0, sAddr, nSeq, nId, isQuiet) or 0;
            aDelays.append(nRtt);
            nSleep = nInterval - nElapse;
            if (nSleep > 0):
                time.sleep(nSleep);
            nCount += 1;
            nSeq += 1;
    except KeyboardInterrupt as e:
        pass
    showStat(sOriName, aDelays);

def parseArg():
    global LOGLEVEL, TARGET, INPUT, SIZE, INTERVAL, TIMEOUT, COUNT, TTL, INTERFACE, QUIET;
    global log
    parser = argparse.ArgumentParser(description='ping in python3, need superuser privilege');
    parser.add_argument('target',
            help='address to ping'
    );
    group1 = parser.add_mutually_exclusive_group();
    group1.add_argument('-d', '--data',
            help='set data used to ping'
    );
    group1.add_argument('-s', '--size',
            help='set the size of data used to ping'
    );
    parser.add_argument('-i', '--interval',
            help='set interval between each ping'
    );
    parser.add_argument('-w', '--timeout',
            help='set socket timeout in second'
    );
    parser.add_argument('-c', '--count',
            help='set the maximum count of ping; 0 means unlimited'
    );
    parser.add_argument('-t', '--ttl',
            help='set time to live IP header field'
    );
    parser.add_argument('-I', '--interface',
            help='set the interface to be bound'
    );
    parser.add_argument('-q', '--quiet',
            action='store_true',
            help='suppress per ping echo message'
    );
    parser.add_argument('-v', '--verbose',
            action='store_true',
            help='show verbose debug information'
    );
    args = parser.parse_args();
    if (args.verbose):
        LOGLEVEL = logging.DEBUG;
    else:
        LOGLEVEL = logging.INFO;
    log.setLevel(LOGLEVEL);
    TARGET = args.target;
    INPUT = args.data and args.data.encode() or INPUT or b'';
    SIZE = int(args.size or SIZE or 0);
    INTERVAL = float(args.interval or INTERVAL or 0);
    TIMEOUT = float(args.timeout or TIMEOUT or None);
    COUNT = int(args.count or COUNT or 0);
    TTL = int(args.ttl or TTL or 0);
    INTERFACE = args.interface or INTERFACE or '';
    QUIET = args.quiet;
    log.debug('passed command line arguments: {}'.format(
        {key: value for (key, value) in vars(args).items() if value is not None}
    ));
    return args;

def main():
    global TARGET;
    parseArg();
    ping(TARGET);

if __name__ == '__main__':
    main();
