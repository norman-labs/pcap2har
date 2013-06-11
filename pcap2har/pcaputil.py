'''
Various small, useful functions which have no other home.
'''

import dpkt
import resource
import sys

# Re-implemented here only because it's missing on AppEngine.
def inet_ntoa(packed):
    '''Custom implementation of inet_ntoa'''
    if not isinstance(packed, str) or len(packed) != 4:
        raise ValueError('Argument to inet_ntoa must a string of length 4')
    return '.'.join(str(ord(c)) for c in packed)


def friendly_tcp_flags(flags):
    '''
    returns a string containing a user-friendly representation of the tcp flags
    '''
    # create mapping of flags to string repr's
    d = {
        dpkt.tcp.TH_FIN: 'FIN',
        dpkt.tcp.TH_SYN: 'SYN',
        dpkt.tcp.TH_RST: 'RST',
        dpkt.tcp.TH_PUSH: 'PUSH',
        dpkt.tcp.TH_ACK: 'ACK',
        dpkt.tcp.TH_URG: 'URG',
        dpkt.tcp.TH_ECE: 'ECE',
        dpkt.tcp.TH_CWR: 'CWR'
    }
    #make a list of the flags that are activated
    active_flags = filter(lambda t: t[0] & flags, d.iteritems())
    #join all their string representations with '|'
    return '|'.join(t[1] for t in active_flags)


def friendly_socket(sock):
    '''
    returns a socket where the addresses are converted by inet_ntoa into
    human-friendly strings. sock is in tuple format, like
    ((sip, sport),(dip, sport))
    '''
    return '((%s, %d), (%s, %d))' % (
        inet_ntoa(sock[0][0]),
        sock[0][1],
        inet_ntoa(sock[1][0]),
        sock[1][1]
    )


def friendly_data(data):
    '''
    convert (possibly binary) data into a form readable by people on terminals
    '''
    return `data`


def ms_from_timedelta(td):
    '''
    gets the number of ms in td, which is datetime.timedelta.
    Modified from here:
    http://docs.python.org/library/datetime.html#datetime.timedelta, near the
    end of the section.
    '''
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**3


def ms_from_dpkt_time(td):
    '''
    Get milliseconds from a dpkt timestamp. This should probably only really be
    done on a number gotten from subtracting two dpkt timestamps. td could be
    None if the packet if the packet the timestamp should have been gotten
    from was missing, in which case -1 is returned.
    '''
    if td is None:
        return -1
    return int(td * 1000)


def ms_from_dpkt_time_diff(td1, td2):
    '''
    Get milliseconds from the difference of two dpkt timestamps.  Either
    timestamp could be None if packets are missing, in which case -1 is
    returned.
    '''
    if td1 is None or td2 is None:
        return -1
    return ms_from_dpkt_time(td1 - td2)


class FakeStream(object):
    '''
    Emulates a tcp.Direction with a predetermined data stream.

    Useful for debugging http message classes.
    '''
    def __init__(self, data):
        self.data = data
    def byte_to_seq(self, n):
        return n
    def seq_final_arrival(self, n):
        return None


class FakeFlow(object):
    '''
    Emulates a tcp.Flow, with two FakeStream's.
    '''
    def __init__(self, fwd, rev):
        self.fwd = fwd
        self.rev = rev

def print_rusage():
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == 'darwin':
        rss /= 1024  # Mac OSX returns rss in bytes, not KiB
    print 'max_rss:', rss, 'KiB'
