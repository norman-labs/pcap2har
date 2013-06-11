import logging

import dpkt

import tcp
from packetdispatcher import PacketDispatcher


def ParsePcap(dispatcher, filename=None, reader=None):
    '''
    Parses the passed pcap file or pcap reader.

    Adds the packets to the PacketDispatcher. Keeps a list

    Args:
    dispatcher = PacketDispatcher
    reader = dpkt.pcap.Reader or None
    filename = filename of pcap file or None

    check for filename first; if there is one, load the reader from that. if
    not, look for reader.
    '''
    if filename:
        f = open(filename, 'rb')
        try:
            reader = dpkt.pcap.Reader(f)
        except dpkt.dpkt.Error as e:
            logging.warning('failed to parse pcap file %s' % filename)
            return
    elif reader:
        pass
    else:
        raise 'function ParsePcap needs either a filename or pcap reader'
    # now we have the reader; read from it
    packet_count = 1  # start from 1 like Wireshark
    errors = [] # store errors for later inspection
    try:
        for timestamp, buf in reader:
            try:
                linktype = reader.datalink()
                if linktype == dpkt.pcap.DLT_LINUX_SLL:
                    # handle SLL packets, thanks Libo
                    packet = dpkt.sll.SLL(buf)
                elif linktype == dpkt.pcap.DLT_EN10MB:
                    packet = dpkt.ethernet.Ethernet(buf)
                else:
                    # otherwise, for now, assume raw IP packets
                    packet = dpkt.ip.IP(buf)
                dispatcher.add(timestamp, buf, packet)
            except dpkt.Error as e:
                errors.append((timestamp, buf, e, packet_count))
                logging.warning(
                    'Error parsing packet: %s. On packet #%d' %
                    (e, packet_count))
            packet_count += 1
    except dpkt.dpkt.NeedData as error:
        logging.warning(error)
        logging.warning(
            'A packet in the pcap file was too short, packet_count=%d' %
            packet_count)
        errors.append((None, error))


def EasyParsePcap(filename=None, reader=None):
    '''
    Like ParsePcap, but makes and returns a PacketDispatcher for you.
    '''
    dispatcher = PacketDispatcher()
    ParsePcap(dispatcher, filename=filename, reader=reader)
    dispatcher.finish()
    return dispatcher
