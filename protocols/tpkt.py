from scapy.fields import ByteField, ShortField
from scapy.packet import Packet


class TPKT(Packet):
    name = "TPKT"
    fields_desc = [ByteField("version", 3),
                   ByteField("reserved", 0),
                   ShortField("length", 0x0000)]
