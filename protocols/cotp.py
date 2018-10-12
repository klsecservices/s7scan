import random
import socket
from scapy.fields import ShortField, BitField, ByteField, IntField
from scapy.packet import Packet, bind_layers
from scapy.layers.l2 import LLC
from scapy.compat import raw
from scapy.sendrecv import sendp
from clnp import CLNP
from tpkt import TPKT
from ether import EtherRaw

# Timeout walue
TRUSTED_TIMEOUT_TCP_IP = 1

class COTP_Exception(Exception):
    def __init__(self, message, packet=None):
        self._message_ = message
        self._packet_ = packet
    def __str__(self):
        if self._packet_ == None:
            return "[ERROR][COTP]{}".format(self._message_)
        else:
            return "[ERROR][COTP]{}\nPacket:{}".format(self._message_, str(self._packet_).encode('hex'))
class UnreachableHostException(Exception):
    """Thrown when socket.timeout occured while connecting to host"""
    def __init__(self):
        self.message = "[ERROR][COTP]Host TCP-connect request timeout exceeded"
class ConnectionRefusedException(Exception):
    """Thrown when socket.timeout occured while connecting to host"""
    def __init__(self):
        self.message = "[ERROR][COTP]Host TCP-connect on port refused"
class COTP(Packet):
    name = "COTP"
    fields_desc = [
        ByteField("length", 0),
        ByteField("pdu_type", 0)
        ]
class COTP_TCP_ConnectRequest(Packet):
    name = "COTP_TCP_ConnectRequest"
    fields_desc = [
        ShortField("dst_ref", 0),
        ShortField("src_ref", 0),
        BitField('class_', 0, 4),
        BitField('reserved', 0, 2),
        BitField('ext_format', 0, 1),
        BitField('explicit', 0, 1),
        ShortField("tpdu_size_param", 0xc001),
        ByteField("tpdu_size_value", 0x0a),
        ShortField("src_tsap_param", 0xc102),
        ShortField("src_tsap_value", 0x0),
        ShortField("dst_tsap_param", 0xc202),
        ShortField("dst_tsap_value", 0x0)
    ]
class COTP_LLC_ConnectRequest(Packet):
    name = "COTP_LLC_ConnectRequest"
    fields_desc = [
        ShortField("dst_ref", 0),
        ShortField("src_ref", 0),
        BitField('class_', 0, 4),
        BitField('reserved', 0, 2),
        BitField('ext_format', 0, 1),
        BitField('explicit', 0, 1),
        ShortField("dst_tsap_param", 0xc202),
        ShortField("dst_tsap_value", 0x0),
        ShortField("src_tsap_param", 0xc102),
        ShortField("src_tsap_value", 0x0),
        ShortField("tpdu_size_param", 0xc001),
        ByteField("tpdu_size_value", 0x0),
        ShortField("version_param", 0xc401),
        ByteField("version_value", 0x1),
        ShortField("options_param", 0xc601),
        ByteField("options_value", 0x2),
        ShortField("priority_param", 0x8702),
        ShortField("priority_value", 0x0),
        ShortField("checksum_param", 0xc302),
        ShortField("checksum_value", 0x0000),
    ]
class COTP_TCP_ConnectConfirm(Packet):
    name = "COTP_TCP_ConnectConfirm"
    fields_desc = [
        ShortField("dst_ref", 0),
        ShortField("src_ref", 0),
        BitField('class_', 0, 4),
        BitField('reserved', 0, 2),
        BitField('ext_format', 0, 1),
        BitField('explicit', 0, 1),
        ShortField("tpdu_size_param", 0xc001),
        ByteField("tpdu_size_value", 0x0a),
        ShortField("src_tsap_param", 0xc102),
        ShortField("src_tsap_value", 0x0),
        ShortField("dst_tsap_param", 0xc202),
        ShortField("dst_tsap_value", 0x0)
    ]
class COTP_LLC_ConnectConfirm(Packet):
    name = "COTP_LLC_ConnectConfirm"
    fields_desc = [
        ShortField("dst_ref", 0),
        ShortField("src_ref", 0),
        BitField('class_', 0, 4),
        BitField('reserved', 0, 2),
        BitField('ext_format', 0, 1),
        BitField('explicit', 0, 1),
        ShortField("tpdu_size_param", 0xc001),
        ByteField("tpdu_size_value", 0x0),
        ShortField("options_param", 0xc601),
        ByteField("options_value", 0x0),
    ]
class COTP_DataAcknowledgement(Packet):
    name = "COTP_DataAcknowledgement"
    fields_desc = [
        ShortField("dst_ref", 0),
        IntField("tpdu_num", 0),
        ShortField("credit", 1)
    ]
class COTP_LLC_Data(Packet):
    name = "COTP_LLC_Data"
    fields_desc = [
        ShortField("dst_ref", 0),
        BitField('last_data_unit', 1, 1),
        BitField('tpdu_num', 0, 31)
    ]
class COTP_TCP_Data(Packet):
    name = "COTP_TCP_Data"
    fields_desc = [
        BitField('last_data_unit', 1, 1),
        BitField('tpdu_num', 0, 7)
    ]
class COTP_DisconnectRequest(Packet):
    name = "COTP_DisconnectRequest"
    fields_desc = [
        ShortField("dst_ref", 0),
        ShortField("src_ref", 0),
        ByteField("cause", 0x0),
    ]
class COTP_DisconnectConfirm(Packet):
    name = "COTP_DisconnectConfirm"
    fields_desc = [
        ShortField("dst_ref", 0), 
        ShortField("src_ref", 0)
    ]

bind_layers(CLNP, COTP)
bind_layers(TPKT, COTP)
bind_layers(COTP, COTP_TCP_ConnectRequest, pdu_type=0xe0, length=17)
bind_layers(COTP, COTP_TCP_ConnectConfirm, pdu_type=0xd0)
bind_layers(COTP, COTP_LLC_ConnectRequest, pdu_type=0xe1, length=0x1F)
bind_layers(COTP, COTP_LLC_ConnectConfirm, pdu_type=0xd1)
bind_layers(COTP, COTP_DataAcknowledgement, pdu_type=0x60, length=0x09)
bind_layers(COTP, COTP_LLC_Data, pdu_type=0xf0, length=0x07)
bind_layers(COTP, COTP_TCP_Data, pdu_type=0xf0, length=0x02)
bind_layers(COTP, COTP_DisconnectRequest, pdu_type=0x80, length=0x06)
bind_layers(COTP, COTP_DisconnectConfirm, pdu_type=0xC0)

def _stop_filter(x):
    """ This filter stops capture when it meets certain amount 
        of COTP packets with appropriate dst_ref. Without capture stop 
        we will loose a lot of time waiting for timeout at each packet sendrecv.
    """
    if x.haslayer(COTP_LLC_ConnectConfirm):
        i = COTP_LLC_ConnectConfirm
    elif x.haslayer(COTP_LLC_Data):
        i = COTP_LLC_Data
    elif x.haslayer(COTP_DataAcknowledgement):
        i = COTP_DataAcknowledgement
    elif x.haslayer(COTP_DisconnectConfirm):
        i = COTP_DisconnectConfirm
    elif x.haslayer(COTP_DisconnectRequest):
        i = COTP_DisconnectRequest
    else:
        return False
    if x[i].dst_ref == _stop_filter.dst_ref:
        # In case of disconnect request to ud we need to stop capture immediately
        if i == COTP_DisconnectRequest:
            return True
        else:
            _stop_filter.counter += 1
    if _stop_filter.counter == _stop_filter.count:
        return True
    else:
        return False

class COTP_Layer():
    """ This class implements COTP network layer. Supports LLC- and TCP/IP-based networks
    """
    def __init__(self, is_llc=False, ifname=None, mac_addr=None, timeout=10):
        """ is_llc - choose whether COTP layer must be based on LLC or TCP/IP network
            ifname - name of the network interface to use (only for LLC-based network)
            mac_addr - source mac_addr to use (only for LLC-based network)
            timeout - receive timeout in seconds
        """
        self._timeout_ = timeout
        self._socket_ = None
        if is_llc == True:
            self._is_llc_ = True
            if ifname == None or mac_addr == None:
                raise COTP_Exception("[INIT]For LLC-based COTP layer source mac_addr and ifname must be specified")
            self._ether_ = EtherRaw(ifname, mac_addr, timeout)
            self._socket_ = None
            self._dst_mac_ = None
        else:
            self._is_llc_ = False
            self._ether_ = None
        self._src_tpdu_num_ = 0
        self._srv_tpdu_num = 0
        self._src_ref_ = 0
        self._dst_ref_ = 0
        self._connected_ = False
    def _filter(self, packets):
        """ Filters only COTP packets.
            This protects us from the theoretical case when we send COTP packet to the server and expect COTP answer, 
            but receive non-COTP packet(s) for some reason
        """
        filtered = []
        if len(packets) == 0:
            return filtered
        for packet in packets:
            if packet.haslayer(COTP):
                filtered.append(packet)
        return filtered
    def _send(self, packet):
        if self._is_llc_:
            self._ether_.send(self._dst_mac_, LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / CLNP() / COTP() / packet)
        else:
            l = len(str(TPKT() / COTP() / packet))
            self._socket_.send(str(TPKT(length=l) / COTP() / packet))
    def _sendrcv(self, packet, recv_count=1):
        """ Sends COTP packet and receives up to recv_count COTP packets from the server
        """
        if self._is_llc_:
            # Init _stop_filter static vars
            _stop_filter.count = recv_count
            _stop_filter.counter = 0
            _stop_filter.dst_ref = self._src_ref_
            full_packet = LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / CLNP() / COTP() / packet
            # For LLC connect requests we need to calculate checksum
            if full_packet.haslayer(COTP_LLC_ConnectRequest):
                full_packet[COTP_LLC_ConnectRequest].checksum_value = self.checksum(raw(full_packet[COTP])[:-2])
            answers = self._ether_.sendrcv(self._dst_mac_, full_packet, _stop_filter)
            # Filter COTP answers only
            return self._filter(answers)
        else:
            self._send(packet)
            answer = self._socket_.recv(4096)
            if answer == None:
                return None
            else:
                return [TPKT(answer)]
    def settimeout(self, timeout):
        self._timeout_ = timeout
    def connect(self, dst_addr, src_tsap, dst_tsap):
        """ Performs COTP connection. 
            dst_addr - destination address. MAC-address for LLC or IP-address for TCP/IP
            Throws: COTP_Exception
        """
        timeout_counter = 0
        self._dst_addr_ = dst_addr
        self._src_ref_ = random.randint(0x0000, 0xFFFF)
        if not self._is_llc_:
            self._socket_ = socket.socket()
            self._socket_.settimeout(self._timeout_)
            while timeout_counter < 2:
                try:
                    self._socket_.connect(dst_addr)
                    break
                except (socket.timeout, socket.error) as e:
                    if type(e) == socket.timeout:
                        if self._timeout_ < TRUSTED_TIMEOUT_TCP_IP:
                            self._timeout_ = TRUSTED_TIMEOUT_TCP_IP
                            self._socket_ = socket.socket()
                            self._socket_.settimeout(self._timeout_)
                            timeout_counter += 1
                            continue
                        else:
                            raise UnreachableHostException
                    elif type(e) == socket.error and e.errno == 10061:
                        raise ConnectionRefusedException
                    else:
                        raise e
            answer = self._sendrcv(COTP_TCP_ConnectRequest(
                dst_ref=self._dst_ref_, src_ref=self._src_ref_, dst_tsap_value=dst_tsap, src_tsap_value=src_tsap)
            )
        else:
            self._dst_mac_ = dst_addr
            answer = self._sendrcv(COTP_LLC_ConnectRequest(
                dst_ref=self._dst_ref_, src_ref=self._src_ref_, class_=0x4, ext_format=1,
                dst_tsap_value=dst_tsap, src_tsap_value=src_tsap, tpdu_size_value=0xa)
            )
        if len(answer) == 0:
            raise COTP_Exception("[CONNECT]No response from the server")
        elif len(answer) > 1:
            raise COTP_Exception("[CONNECT]Received more than one answer")
        answer = answer[0]
        if self._is_llc_:
            cc = COTP_LLC_ConnectConfirm
        else:
            cc = COTP_TCP_ConnectConfirm
        if answer.haslayer(cc):
            self._dst_ref_ = answer[cc].src_ref
            self._src_tpdu_num_ = 0
            self._srv_tpdu_num = 0
            if self._is_llc_:
                # For LLC we need to send acknowledge for each COTP packet
                # For TCP acknowledges are controlled by TCP itself (no need to send COTP Acks)
                self._send(COTP_DataAcknowledgement(dst_ref=self._dst_ref_))
            self._connected_ = True
        elif answer.haslayer(COTP_DisconnectRequest):
            self._src_ref_ = 0
            self._dst_addr_ = None
            raise COTP_Exception("[CONNECT]Received DR", packet=answer)
        else:
            raise COTP_Exception("[CONNECT]Received Unexpected answer", packet=answer)
    def disconnect(self):
        if not self._connected_:
            raise COTP_Exception("[DISCONNECT]Not connected")
        if self._is_llc_:
            answer = self._sendrcv(COTP_DisconnectRequest(dst_ref=self._dst_ref_, src_ref=self._src_ref_))
        else:
            self._socket_.close()
            self._socket_ = None
            answer = None
        self._dst_mac_ = None
        self._dst_ref_ = 0
        self._src_ref_ = 0
        self._src_tpdu_num_ = 0
        self._srv_tpdu_num = 0
        self._connected_ = False
        _stop_filter.dst_ref = 0
        if self._is_llc_:
            if len(answer) == 0:
                raise COTP_Exception("[CONNECT]No response from the server")
            elif len(answer) > 1:
                raise COTP_Exception("[DISCONNECT]Received more than one answer")
            answer = answer[0]
            if not answer.haslayer(COTP_DisconnectConfirm):
                raise COTP_Exception("[DISCONNECT]Received Unexpected answer", packet=answer)
    def sendrecv(self, packet):
        if not self._connected_:
            raise COTP_Exception("[DATA]Not connected")
        if self._is_llc_:
            answer = self._sendrcv(COTP_LLC_Data(dst_ref=self._dst_ref_, tpdu_num=self._src_tpdu_num_) / packet, recv_count=2)
            if len(answer) < 2:
                raise COTP_Exception("[DATA]No response from server")
            ack = answer[0]
            data = answer[1]
            if not ack.haslayer(COTP_DataAcknowledgement) or not data.haslayer(COTP_LLC_Data):
                raise COTP_Exception("[DATA]Incorrect response from server")
            old_src_tpdu_num = self._src_tpdu_num_
            self._src_tpdu_num_ = ack[COTP_DataAcknowledgement].tpdu_num # Next tpdu_num we will use
            if data[COTP_LLC_Data].tpdu_num != old_src_tpdu_num:
                raise COTP_Exception("[DATA]Packet contains incorrect tpdu_number")
            self._srv_tpdu_num += 1
            # Send ACK for data packet
            self._send(COTP_DataAcknowledgement(dst_ref=self._dst_ref_, tpdu_num=self._srv_tpdu_num))
        else:
            answer = self._sendrcv(COTP_TCP_Data(tpdu_num=self._src_tpdu_num_) / packet)
            if len(answer) < 1:
                raise COTP_Exception("[DATA]No response from server")
            data = answer[0]
            if not data.haslayer(COTP_TCP_Data):
                raise COTP_Exception("[DATA]Incorrect response from server")
        return data
    def checksum(self, data):
        c0 = c1 = 0
        for byte in data:
            c0 += ord(byte)
            c1 += c0
        x = (-c1 - c0) % 255
        y = c1 % 255
        return ((x << 8) & 0xFF00) | (y & 0x00FF)