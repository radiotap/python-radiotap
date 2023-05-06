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

from radiotap.vht import *


mcs_rate_table = [
    (6.50, 7.20, 13.50, 15.00),
    (13.00, 14.40, 27.00, 30.00),
    (19.50, 21.70, 40.50, 45.00),
    (26.00, 28.90, 54.00, 60.00),
    (39.00, 43.30, 81.00, 90.00),
    (52.00, 57.80, 108.00, 120.00),
    (58.50, 65.00, 121.50, 135.00),
    (65.00, 72.20, 135.00, 150.00),
    (13.00, 14.40, 27.00, 30.00),
    (26.00, 28.90, 54.00, 60.00),
    (39.00, 43.30, 81.00, 90.00),
    (52.00, 57.80, 108.00, 120.00),
    (78.00, 86.70, 162.00, 180.00),
    (104.00, 115.60, 216.00, 240.00),
    (117.00, 130.00, 243.00, 270.00),
    (130.00, 144.40, 270.00, 300.00),
    (19.50, 21.70, 40.50, 45.00),
    (39.00, 43.30, 81.00, 90.00),
    (58.50, 65.00, 121.50, 135.00),
    (78.00, 86.70, 162.00, 180.00),
    (117.00, 130.00, 243.00, 270.00),
    (156.00, 173.30, 324.00, 360.00),
    (175.50, 195.00, 364.50, 405.00),
    (195.00, 216.70, 405.00, 450.00),
    (26.00, 28.80, 54.00, 60.00),
    (52.00, 57.60, 108.00, 120.00),
    (78.00, 86.80, 162.00, 180.00),
    (104.00, 115.60, 216.00, 240.00),
    (156.00, 173.20, 324.00, 360.00),
    (208.00, 231.20, 432.00, 480.00),
    (234.00, 260.00, 486.00, 540.00),
    (260.00, 288.80, 540.00, 600.00),
]

def align(val, align):
    return (val + align - 1) & ~(align-1)

def _parse_mactime(packet, offset):
    offset = align(offset, 8)
    mactime, = struct.unpack_from('<Q', packet, offset)
    return offset + 8, {'TSFT' : mactime}

def _parse_flags(packet, offset):
    flags, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'flags' : flags}

def _parse_rate(packet, offset):
    rate, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'rate' : rate / 2.}

def _parse_channel(packet, offset):
    offset = align(offset, 2)

    chan_freq, chan_flags, = struct.unpack_from('<HH', packet, offset)
    return offset + 4, {'chan_freq' : chan_freq, 'chan_flags' : chan_flags}

def _parse_fhss(packet, offset):
    fhss, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'fhss' : fhss}

def _parse_dbm_antsignal(packet, offset):
    dbm_antsignal, = struct.unpack_from('<b', packet, offset)
    return offset + 1, {'dbm_antsignal' : dbm_antsignal}

def _parse_dbm_antnoise(packet, offset):
    dbm_antnoise, = struct.unpack_from('<b', packet, offset)
    return offset + 1, {'dbm_antnoise' : dbm_antnoise}

def _parse_lock_quality(packet, offset):
    offset = align(offset, 2)
    lock_quality, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'lock_quality' : lock_quality}

def _parse_tx_attenuation(packet, offset):
    offset = align(offset, 2)
    tx_attenuation, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'tx_attenuation' : tx_attenuation}

def _parse_db_tx_attenuation(packet, offset):
    offset = align(offset, 2)
    db_tx_attenuation, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'db_tx_attenuation' : db_tx_attenuation}

def _parse_dbm_tx_power(packet, offset):
    dbm_tx_power, = struct.unpack_from('<b', packet, offset)
    return offset + 1, {'dbm_tx_power' : dbm_tx_power}

def _parse_antenna(packet, offset):
    antenna, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'antenna' : antenna}

def _parse_db_antsignal(packet, offset):
    db_antsignal, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'db_antsignal' : db_antsignal}

def _parse_db_antnoise(packet, offset):
    db_antnoise, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'db_antnoise' : db_antnoise}

def _parse_rx_flags(packet, offset):
    offset = align(offset, 2)
    rx_flags, = struct.unpack_from('<H', packet, offset)
    return offset + 2, {'rx_flags' : rx_flags}

def _parse_tx_flags(packet, offset):
    tx_flags, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'tx_flags' : tx_flags}

def _parse_rts_retries(packet, offset):
    rts_retries, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'rts_retries' : rts_retries}

def _parse_data_retries(packet, offset):
    data_retries, = struct.unpack_from('<B', packet, offset)
    return offset + 1, {'data_retries' : data_retries}

def _parse_xchannel(packet, offset):
    offset = align(offset, 4)
    xchannel_flags, xchannel_freq, xchannel_num, xchannel_maxpower = \
        struct.unpack_from('<IHBB', packet, offset)
    return offset + 8, {
        'xchannel_flags' : xchannel_flags,
        'xchannel_freq' : xchannel_freq,
        'xchannel_num' : xchannel_num,
        'xchannel_maxpower' : xchannel_maxpower
    }

def _parse_mcs(packet, offset):
    mcs_known, mcs_flags, mcs_index = \
        struct.unpack_from('<BBB', packet, offset)
    is_40 = (mcs_flags & 0x3) == 1
    short_gi = (mcs_flags & 0x04) != 0

    mcs_rate = mcs_rate_table[mcs_index][2 * is_40 + short_gi]
    return offset + 3, {
        'mcs_known': mcs_known,
        'mcs_flags': mcs_flags,
        'mcs_index': mcs_index,
        'mcs_rate': mcs_rate
    }

def _parse_ampdu(packet, offset):
    """see http://www.radiotap.org/defined-fields/A-MPDU%20status
       u32 reference number, u16 flags, u8 delimiter CRC value, u8 reserved"""
    ampdu_refnum, ampdu_flags, ampdu_delim_crc_val, ampdu_reserved = \
        struct.unpack_from('<LHBB', packet, offset)
    return offset + 8, {
        'ampdu_refnum': ampdu_refnum,
        'ampdu_flags': ampdu_flags,
        'ampdu_delim_crc_val': ampdu_delim_crc_val,
        'ampdu_reserved': ampdu_reserved
    }


def _parse_vht(packet, offset):
    """ see http://www.radiotap.org/defined-fields/VHT
        u16 known, u8 flags, u8 bandwidth, u8 mcs_nss[4], u8 coding, u8 group_id, u16 partial_aid """
    vht_known, vht_flags, vht_bw, vht_user_0, vht_user_1, vht_user_2, vht_user_3, \
        vht_coding, vht_group_id, vht_partial_aid = struct.unpack_from('<H8BH', packet, offset)

    vht_gi = vht_bandwidth = None
    if vht_known & 0x0004:
        # GI is known
        vht_gi = (vht_flags & 0x04) >> 0x02
    if vht_known & 0x0040:
        # BW is known
        vht_bandwidth = vht_bandwidth_lut[0x1f & vht_bw][0]

    # per-user info for MIMO-MU
    vht_per_user =  {}
    for (i, vht_user) in enumerate([vht_user_0, vht_user_1, vht_user_2, vht_user_3]):
        if vht_user:
            vht_per_user[i] = {}
            vht_nss_n =  vht_user & 0xf0 >> 4
            vht_mcs_index_n = (vht_user & 0xf0)  >> 4
            vht_per_user[i]['vht_coding'] = (vht_coding & 2**i) >> i
            if not(vht_gi is None) and not(vht_bandwidth is None):
                vht_per_user[i].update(vht_rate_description(vht_mcs_index_n,vht_nss_n,vht_gi,vht_bandwidth))

    return offset + 12, {
        'vht_known': vht_known,
        'vht_flags': vht_flags,
        'vht_bw': vht_bw,
        'vht_coding': vht_coding,
        'vht_group_id': vht_group_id,
        'vht_gi': vht_gi,
        'vht_bandwidth': vht_bandwidth,
        'vht_user': vht_per_user,
    }

def _parse_vendor(packet, offset):
    offset = align(offset, 2)
    oui, subns, length = struct.unpack_from("<3sBH", packet, offset)
    offset += 6
    return offset + length, {
        'oui': oui,
        'subns': subns,
        'data': packet[offset:offset + length],
        'present': 0
    }

def _parse_radiotap_field(namespace, field_id, packet, offset):

    if namespace and namespace != 'radiotap':
        # skipped already
        return offset, None

    dispatch_table = [
        _parse_mactime,
        _parse_flags,
        _parse_rate,
        _parse_channel,
        _parse_fhss,
        _parse_dbm_antsignal,
        _parse_dbm_antnoise,
        _parse_lock_quality,
        _parse_tx_attenuation,
        _parse_db_tx_attenuation,
        _parse_dbm_tx_power,
        _parse_antenna,
        _parse_db_antsignal,
        _parse_db_antnoise,
        _parse_rx_flags,
        _parse_tx_flags,
        _parse_rts_retries,
        _parse_data_retries,
        _parse_xchannel,
        _parse_mcs,
        _parse_ampdu,
        _parse_vht,
    ]
    if field_id >= len(dispatch_table):
        return None, {}

    return dispatch_table[field_id](packet, offset)

def _present_bits(bitmap):
    offset = 0
    count = 0
    reset_count = False
    namespace = 'radiotap'
    while offset < len(bitmap):
        present, = struct.unpack_from("<I", bitmap[offset:])
        for i in range(0, 32):
            # reserved bits:
            #  29 = radiotap namespace
            #  30 = vendor namespace
            #  31 = extended bitmap
            if present & (1 << i):
                if i == 29:
                    namespace = 'radiotap'
                    reset_count = True
                    yield namespace, None
                elif i == 30:
                    namespace = 'vendor'
                    reset_count = True
                    yield namespace, None
                elif i == 31:
                    pass
                else:
                    yield namespace, count + i
        if reset_count:
            count = 0
            reset_count = False
        else:
            count += 32
        offset += 4

def _add_fields(d, fields):
    if not fields:
        return

    if isinstance(d, list):
        d.append(fields)
    else:
        d.update(fields)

def _add_vendor_presence_bit(d, bit):

    if isinstance(d, list):
        tgt = d[-1]
    else:
        tgt = d
    tgt['present'] |= 1 << bit

def radiotap_parse(packet, valuelist=False):
    """
    Parse out a the radiotap header from a packet.  Return a tuple
    (offset, fields) where offset is the new offset and values
    is a dictionary of field name to value.

    If valuelist is true, every field is returned in file order as a list
    of items rather than as a single dictionary.  This allows retrieving
    items that are specified more than once via the namespacing feature.
    """
    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)

    if len(packet) < radiotap_header_len:
        return 0, {}

    header = struct.unpack_from(radiotap_header_fmt, packet)

    version, pad, radiotap_len, present = header
    if version != 0 or pad != 0 or radiotap_len > len(packet):
        return 0, {}

    # skip to end of presence bitmaps
    offset = radiotap_header_len
    present_offset = offset - 4
    while present & (1 << 31):
        present, = struct.unpack_from("<I", packet[offset:])
        offset += 4

    radiotap = [] if valuelist else {}

    for namespace, i in _present_bits(packet[present_offset:offset]):
        if i is None:
            # namespace switch; if vendor switch to vendor namespace
            if namespace == 'vendor':
                offset, fields = _parse_vendor(packet, offset)
                _add_fields(radiotap, fields)
            continue

        elif namespace == 'vendor':
            # just track the presence bit...
            _add_vendor_presence_bit(radiotap, i)

        offset, fields = _parse_radiotap_field(namespace, i, packet, offset)
        _add_fields(radiotap, fields)
        if offset == radiotap_len or offset is None:
            break

    return radiotap_len, radiotap

def macstr(macbytes):
    return ':'.join(['%02x' % ord(k) for k in macbytes])

def is_blkack(mac):
    fc = mac.get('fc', 0)
    type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0x0f

    # control frame and block ack
    return type == 1 and subtype == 0x9

def is_qos_data(mac):
    fc = mac.get('fc', 0)
    type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0x0f

    return type == 2 and subtype == 0x8

def is_qos_null(mac):
    fc = mac.get('fc', 0)
    type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0x0f

    return type == 2 and subtype == 0xc

def is_qos(mac):
    return is_qos_null(mac) or is_qos_data(mac)

def ieee80211_parse(packet, offset):
    hdr_fmt = "<HH6s"
    hdr_len = struct.calcsize(hdr_fmt)

    if len(packet) - offset < hdr_len:
        return 0, {}

    fc, duration, addr1 = \
        struct.unpack_from(hdr_fmt, packet, offset)

    offset += hdr_len
    mac = {
        'fc': fc,
        'duration': duration * .001024,
        'addr1': macstr(addr1),
    }

    if is_blkack(mac):
        blkack_fmt = "<6sHH8s"
        blkack_len = struct.calcsize(blkack_fmt)
        if len(packet) - offset < blkack_len:
            return offset, mac

        addr2, ba_ctrl, ba_ssc, ba_bitmap = \
            struct.unpack_from(blkack_fmt, packet, offset)
        offset += blkack_len
        mac.update({
            'addr2': macstr(addr2),
            'ba_ctrl': ba_ctrl,
            'ba_ssc': ba_ssc,
            'ba_bitmap': ba_bitmap
        })
        return offset, mac

    three_addr_fmt = "<6s6sH"
    three_addr_len = struct.calcsize(three_addr_fmt)
    if len(packet) - offset < three_addr_len:
        return offset, mac

    addr2, addr3, seq = \
        struct.unpack_from(three_addr_fmt, packet, offset)
    offset += three_addr_len
    mac.update({
        'addr2': macstr(addr2),
        'addr3': macstr(addr3),
        'seq': seq >> 4,
        'frag': seq & 0x0f
    })

    if is_qos(mac):
        four_addr_fmt = "<6s"
        four_addr_len = struct.calcsize(four_addr_fmt)
        if len(packet) - offset < four_addr_len:
            return offset, mac

        addr4, = struct.unpack_from(four_addr_fmt, packet, offset)
        offset += four_addr_len
        mac.update({
            'addr4': macstr(addr4)
        })

        qos_ctrl_fmt = "<H"
        qos_ctrl_len = struct.calcsize(qos_ctrl_fmt)
        if len(packet) - offset < qos_ctrl_len:
            return offset, mac

        qos_ctrl, = struct.unpack_from(qos_ctrl_fmt, packet, offset)
        tid = qos_ctrl & 0xf
        eosp = (qos_ctrl >> 4) & 1
        mesh_ps = (qos_ctrl >> 9) & 1
        rspi = (qos_ctrl >> 10) & 1

        mac.update({
            'tid': tid,
            'eosp': eosp,
            'rspi': rspi,
            'mesh_ps': mesh_ps,
        })

    return offset, mac
