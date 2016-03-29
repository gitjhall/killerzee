import usb.core
import usb.util
import xml.etree.ElementTree as ET
from urllib import urlopen
from scapy.all import *
from scapy.layers.ZWave import *
from scapy.layers.gnuradio import *


def hexdump(src, length=16):
    '''
    Creates a tcpdump-style hex dump string output.
    @type src: String
    @param src: Input string to convert to hexdump output.
    @type length: Int
    @param length: Optional length of data for a single row of output, def=16
    @rtype: String
    '''
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    result = []
    for i in xrange(0, len(src), length):
       chars = src[i:i+length]
       hex = ' '.join(["%02x" % ord(x) for x in chars])
       printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
       result.append("%04x:  %-*s  %s\n" % (i, length*3, hex, printable))
    return ''.join(result)

def zwid():
    '''
    Enumerate the available RfCat devices connected to the USB bus.
    @rtype:     List
    @returns:   List of device resources supporting RfCat. Each list element is a tuple of (devnum, dev)
    '''
    dongles = []
    for bus in usb.busses():
        for dev in bus.devices:
            # OpenMoko assigned or Legacy TI
            if (dev.idVendor == 0x0451 and dev.idProduct == 0x4715) or (dev.idVendor == 0x1d50 and (dev.idProduct == 0x6047 or dev.idProduct == 0x6048 or dev.idProduct == 0x605b)):
                #do = dev.open()
                #iSN = do.getDescriptor(1,0,50)[16]
                devnum = dev.devnum
                dongles.append((devnum, dev))

    dongles.sort()
    return dongles


def send_wireshark(packet):
    '''
    Sends ZWave packet to Wireshark for dissection
    @type packet: String or scapy ZWave()
    @param packet: ZWave packet to be sent to Wireshark
    @rtype: None
    '''

    #Eventually need to fix Wireshark dissector and remove GnuradioPacket layer
    send(IP(dst='127.0.0.1') / UDP(dport=52002, sport=52000) / GnuradioPacket(proto=1) / packet, verbose=False)
    return



