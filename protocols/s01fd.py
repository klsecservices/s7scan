from scapy.fields import ShortField
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import SNAP


class S01FD(Packet):
    name = "S01FD"
    fields_desc = [ShortField("type", 0)]

bind_layers(SNAP, S01FD, OUI=0x080006, code=0x01fd)
