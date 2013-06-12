import dpkt

from . import tcp, udp

class PacketDispatcher:
    '''
    takes a series of dpkt.Packet's and calls callbacks based on their type

    For each packet added, picks it apart into its transport-layer packet type
    and adds it to an appropriate handler object. Automatically creates handler
    objects for now.

    Members:
    * flowbuilder = tcp.FlowBuilder
    * udp = udp.Processor
    '''

    def __init__(self):
        self.tcp = tcp.FlowBuilder()
        self.udp = udp.Processor()

    def add(self, timestamp, raw, packet):
        '''
        timestamp = dpkt timestamp
        raw = original packet data
        packet = dpkt.Packet subclass, be it Ethernet or IP or whatever
        '''
        eth = ip = None
        # Strip away layers until we obtain a TCP or UDP segment.
        if isinstance(packet, dpkt.ethernet.Ethernet):
            eth = packet
            packet = eth.data
        if isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
            ip = packet
            packet = ip.data

        if isinstance(packet, dpkt.tcp.TCP):
            self.tcp.add(tcp.Packet(timestamp, raw, eth, ip, packet))
        elif isinstance(packet, dpkt.udp.UDP):
            self.udp.add(timestamp, packet)

    def finish(self):
        #This is a hack, until tcp.Flow no longer has to be `finish()`ed
        self.tcp.finish()
