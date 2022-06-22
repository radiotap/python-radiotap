import radiotap as r

def test_ac_rate_1():
    """
    Frame 1: 4865 bytes on wire (38920 bits), 188 bytes captured (1504 bits)
Radiotap Header v0, Length 38
    Header revision: 0
    Header pad: 0
    Header length: 38
    Present flags
    MAC timestamp: 270036265
    Flags: 0x40
    Channel frequency: 5180 [A 36]
    Channel flags: 0x0140, Orthogonal Frequency-Division Multiplexing (OFDM), 5 GHz spectrum
    SSI Signal: -76 dBm
    Antenna: 0
    RX flags: 0x0000
    VHT information
        Known VHT information: 0x44
        .... .1.. = Guard interval: short (1)
        Bandwidth: 80 MHz (4)
        User 0: MCS 9
            1001 .... = MCS index 0: 9 (256-QAM 5/6)
            .... 0011 = Spatial streams 0: 3
            Coding 0: BCC (0)
            [Data Rate: 1299.9 Mb/s]
802.11 radio information
    PHY type: 802.11ac (8)
    Short GI: True
    Bandwidth: 80 MHz (4)
    User 0: MCS 9
    Channel: 36
    Frequency: 5180 MHz
    Signal strength (dBm): -76 dBm
    TSF timestamp: 270036265
IEEE 802.11 Unrecognized (Reserved frame), Flags: o.m.R..T
IEEE 802.11 wireless LAN extension frame
    """
    buf = (
        b"""\x00\x00&\x00+H \x00)m\x18\x10\x00\x00\x00\x00@\x00<\x14@\x01\xb4\x00\x00\x00D\x00\x04\x04\x93"""
        b"\x00\x00\x00\x00\x00\x00\x00\x8c\xa9z\xa8\'\xda\x8c.\xeaD$l\x95\x16\xa9>\xd5\x8eo\xdb\xb7$\xceIF"
        b"""\xa1\x19\xd38\x0b\xc4%\xce\xb5.\xbaM\'\xad\xc9\x8a.\x83\'\xa9\xab\xe1<\xe8B\x0c\x1dE\x08@"\xf7"""
        b"""\x06Bb\xdf\xf2\xf7\x11\xd8\xf2\xd6[\x98Lv\xa9{\x07Ph~\xa1\x8a\x96\xf7o\xff\xb9\x1c\xc3\xf0\xd3\x04"""
        b"""\xfb\xfe\xbc\xa5\x16\xbd;l\xb1\xa7l\xc5\xf3\x84\xdf\xdd`Vn\xeb\xac\xbf\x04\x9by\x91T"`\xbb\xbbl\n"""
        b"""\xfd\xd77\'_\x91\x1d_\xb8\xa6\\0S\xf9q\xd8\x18O\xb7\xf0G\xc0\x9e\x0e|\xa8 \x14""")
    off, radiotap = r.radiotap_parse(buf)
    assert radiotap
    assert len(radiotap['vht_user'])==1
    assert radiotap['vht_user'][0] == {'vht_rate_mbps': 1300.0,
                                       'vht_coding': 0,
                                       'vht_mcs_index': 9,
                                       'vht_mcs_descr': ('256QAM', '5/6')}

def test_ac_rate_2():
   """
   Frame 1: 1615 bytes on wire (12920 bits), 188 bytes captured (1504 bits)
Radiotap Header v0, Length 38
    Header revision: 0
    Header pad: 0
    Header length: 38
    Present flags
    MAC timestamp: 254101463
    Flags: 0x40
    Channel frequency: 5180 [A 36]
    Channel flags: 0x0140, Orthogonal Frequency-Division Multiplexing (OFDM), 5 GHz spectrum
    SSI Signal: -76 dBm
    Antenna: 0
    RX flags: 0x0000
    VHT information
        Known VHT information: 0x44
        .... .0.. = Guard interval: long (0)
        Bandwidth: 80 MHz (4)
        User 0: MCS 8
            1000 .... = MCS index 0: 8 (256-QAM 3/4)
            .... 0011 = Spatial streams 0: 3
            Coding 0: BCC (0)
            [Data Rate: 1053.0 Mb/s]
802.11 radio information
    PHY type: 802.11ac (8)
    Short GI: False
    Bandwidth: 80 MHz (4)
    User 0: MCS 8
    Channel: 36
    Frequency: 5180 MHz
    Signal strength (dBm): -76 dBm
    TSF timestamp: 254101463
IEEE 802.11 QoS Null function (No data), Flags: ....R.F.
   """
   buf = (
    b"""\x00\x00&\x00+H \x00\xd7G%\x0f\x00\x00\x00\x00@\x00<\x14@\x01\xb4\x00\x00\x00D\x00\x00\x04\x83\x00\x00"""
    b"""\x00\x00\x00\x00\x00\xc9\n\xacT\x9d\x0b#T\xe6]\xa3p\xdfN\x98\xfdyR_\x8a=~\xb7\x90\x07\x10_2\x95\xa6\xa3"""
    b"""\xf2\x06\xa9/E\xa5?\xcbg\xac\x11Y]\xcb\\\xd8-\n\xc8\xb6|}0[S\x8d\xac\xcc\xafmT%\xd2\xa7\xdep\xfb\xe2\x0f"""
    b"""\xf1\x0e\xd8hF\xcb\xf6\x92t\xd5\n\xed\xb4y\xf2qj\x8a\x04\xbc\xf3C\x93]\xd9n\xa0\xfa{l\xff\xa3=MC\xb0"""
    b"""\xd2\xf6\x0f\xb8\x87\xf2T\xdf#}\xfe\xe1\x8f\xe1\xa1\xd5zI\x1f6\xceZ\xa0\xae\x14\x01\xfeb\xce\xa3@\xa4"""
    b"""\xe2M\x13\n\xb9\x99\x1f\n\x88p\xcb\xb8""")
   off, radiotap = r.radiotap_parse(buf)
   assert radiotap
   assert len(radiotap['vht_user'])==1
   assert radiotap['vht_user'] == {0: {'vht_rate_mbps': 1053.0,
                                       'vht_mcs_index': 8,
                                       'vht_coding': 0,
                                       'vht_mcs_descr': ('256QAM', '3/4')}}
