import struct

"""Utility for windows based SID"""
class WinSID(object):
    @classmethod
    def strsid(cls, byte):
        ret = "S"
        sid = []
        sid.append(cls.byte_to_long(byte[0:1]))
        sid.append(cls.byte_to_long(byte[2: 2 + 6], False))
        for i in range(8, len(byte), 4):
            sid.append(cls.byte_to_long(byte[i: i + 4]))
        for i in sid:
            ret += "-" + str(i)
        return ret

    @classmethod
    def byte_to_long(cls, byte, little_endian=True):
        if len(byte) > 8:
            raise Exception("Bytes too long. Needs to be <= 8 or 64bit")
        else:
            if little_endian:
                adjusted = byte.ljust(8, b"\x00")
                return struct.unpack("<q", adjusted)[0]
            else:
                adjusted = byte.rjust(8, b"\x00")
                return struct.unpack(">q", adjusted)[0]
