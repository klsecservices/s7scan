from scapy.sendrecv import sendp, sniff
from scapy.layers.l2 import Dot3
import threading


class receiverThread (threading.Thread):
    def __init__(self, ifname, timeout, handler):
        threading.Thread.__init__(self)
        self.ifname = ifname
        self.handler = handler
        self.packets = None
        self.timeout = timeout

    def run(self):
        self.packets = sniff(stop_filter=self.handler, iface=self.ifname,
                             timeout=self.timeout)


class receiverTimeoutThread (threading.Thread):
    def __init__(self, ifname, timeout):
        threading.Thread.__init__(self)
        self.ifname = ifname
        self.timeout = timeout
        self.packets = None

    def run(self):
        self.packets = sniff(timeout=self.timeout, iface=self.ifname)


class EtherRaw():
    BROADCAST_MAC_ADDR = "FF:FF:FF:FF:FF:FF"

    def __init__(self, ifname, mac_addr, timeout=10):
        self._ifname_ = ifname
        self._addr = mac_addr
        self._timeout_ = timeout

    def _addr_filter(self, packets):
        result = []
        if packets is None:
            return result
        for packet in packets:
            if packet.haslayer(Dot3):
                if (packet[Dot3].dst == self._addr) or (packet[Dot3].dst == self.BROADCAST_MAC_ADDR):
                    result.append(packet)
        return result

    def send(self, dst_mac, packet):
        sendp(Dot3(src=self._addr, dst=dst_mac) / packet,
              iface=self._ifname_, verbose=False)

    def recv(self, stop_filter):
        return filter(stop_filter,
                      sniff(stop_filter=stop_filter, iface=self._ifname_))

    def sendrcv(self, dst_mac, packet, stop_filter=None):
        receiver = receiverThread(self._ifname_, self._timeout_, stop_filter)
        receiver.start()
        self.send(dst_mac, packet)
        receiver.join()
        return self._addr_filter(receiver.packets)

    def sendrcv_timeout(self, dst_mac, packet, timeout):
        receiver = receiverTimeoutThread(self._ifname_, timeout)
        receiver.start()
        self.send(dst_mac, packet)
        receiver.join()
        return receiver.packets
