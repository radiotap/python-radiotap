#!/usr/bin/env python
# parse radiotap fields from pcap buffers into a dictionary
#
# example:
# >>> import radiotap as r, pcap
# >>> pc = pcap.pcap(name='foo.pcap')
# >>> tstamp, pkt = pc[0]
# >>> off, radiotap = r.radiotap_parse(pkt)
# >>> off, mac = r.ieee80211_parse(pkt, off)
import struct

def _parse_mactime(packet, offset):
    mactime, = struct.unpack_from('<Q', packet, offset)
    return offset + 8, {'TSFT' : mactime}

def _parse_flags(packet, offset):
    flags, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'flags' : flags}

def _parse_rate(packet, offset):
    rate, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'rate' : rate / 2.}

def _parse_radiotap_field(field_id, packet, offset):

    dispatch_table = [
        _parse_mactime,
        _parse_flags,
        _parse_rate,
    ]
    if field_id >= len(dispatch_table):
        return None, {}

    return dispatch_table[field_id](packet, offset)

def radiotap_parse(packet):
    """
    Parse out a the radiotap header from a packet.  Return a tuple of
    the fields as a dict (if any) and the new offset into packet.
    """
    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)

    if len(packet) < radiotap_header_len:
        return 0, {}

    header = struct.unpack_from(radiotap_header_fmt, packet)

    version, pad, radiotap_len, present = header
    if version != 0 or pad != 0 or radiotap_len > len(packet):
        return 0, {}

    # there may be multiple present bitmaps if high bit is set.
    # assemble them into one large bitmap
    count = 1
    offset = radiotap_header_len
    while present & (1 << (32 * count - 1)):
        next_present = struct.unpack_from("<I", packet[offset:])
        present |= next_present
        offset += 4

    radiotap = {}
    for i in range(0, 32 * count):
        if present & (1 << i):
            offset, fields = _parse_radiotap_field(i, packet, offset)
            radiotap.update(fields)
            if offset == radiotap_len or offset is None:
                break

    return radiotap_len, radiotap

def macstr(macbytes):
    return ':'.join(['%02x' % ord(k) for k in macbytes])

def ieee80211_parse(packet, offset):
    hdr_fmt = "<HH6s6s6sH"
    hdr_len = struct.calcsize(hdr_fmt)

    if len(packet) - offset < hdr_len:
        return 0, {}

    fc, duration, addr1, addr2, addr3, seq = \
        struct.unpack_from(hdr_fmt, packet, offset)

    return hdr_len, {
        'fc': fc,
        'duration': duration * .001024,
        'DA': macstr(addr1),
        'SA': macstr(addr2),
        'BSSID': macstr(addr3),
        'seq': seq >> 4,
        'frag': seq & 3
    }
