from scapy.fields import ByteField
from scapy.layers.l2 import LLC
from scapy.packet import Packet, bind_layers

class CLNP(Packet):
    name = "CLNP"
    fields_desc = [ByteField("subnet", 0) ]
bind_layers(LLC, CLNP, dsap=0xfe, ssap=0xfe, ctrl=3)