import sys
import random
sys.path.append('../')
from protocols.ether import EtherRaw
from protocols.s01fd import *
from protocols.s7 import *

class PLCClient():
    def __init__(self, is_llc, iface, src_mac, recv_timeout=10):
        self._is_llc = is_llc
        self._ether_ = EtherRaw(iface, src_mac)
        self._tpdu_num_ = 0
        self._s7comm_ = S7Layer(is_llc=is_llc, ifname=iface, mac_addr=src_mac, recv_timeout=recv_timeout)

    @staticmethod
    def recv_s7_filter(self):
        def recv_cc_filter(x):
            if x.haslayer(COTP_Data):
                # x.show()
                return True

    def sendrecv_s7(self, dst, src_ref, dst_ref, data):
        self._ether_.send(dst, 
            LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / 
            CLNP(subnet=0) /
            COTP(length=0x9, dst_ref=dst_ref) /
            COTP_DataAcknowledgement(tpdu_num=0x0, credit=0x1)
        )
        answer = self._ether_.sendrcv(dst,
            LLC(dsap=0xfe, ssap=0xfe, ctrl=3) / 
            CLNP(subnet=0) /
            COTP(length=0x7, dst_ref=dst_ref) /
            COTP_Data(tpdu_num=self._tpdu_num_) / 
            Raw(data),
            PLCClient.recv_s7_filter
        )
        self._tpdu_num_ += 1
        answer = filter(PLCClient.recv_s7_filter, answer)
        if len(answer) != 1:
            raise Exception()
        return answer[0]

    def scan(self, dst, szls):
        self._cotp_.connect(dst, 0x0100, 0x0100)
        s7_setup = '32010000020000080000f0000002000201e0'.decode('hex')
        self.sendrecv_s7(dst, src_ref, target_ref, s7_setup)
        for i, szl in enumerate(szls):
            id, index = szl
            s7_request = ('320700000a00000800080001120411440100ff090004'.decode('hex') + struct.pack('>H', id) + struct.pack('>H', index)).decode('hex')
            self.sendrecv_s7(dst, src_ref, target_ref, s7_request)

    def plc_enumerate(self, timeout):
        bcast = "ff:ff:ff:ff:ff:ff"
        answers = self._ether_.sendrcv_timeout(bcast, LLC() / SNAP() / S01FD(type=0x0500), timeout)
        macs = []
        for x in answers:
            if x.haslayer(S01FD):
                if x[S01FD].type == 0x0501:
                    macs.append(x.src)
        return macs

def main():
    is_llc = True
    plc_ip = '192.168.129.129'
    plc_port = 102
    iface="VMware Virtual Ethernet Adapter for VMnet1"

    if is_llc:
        client = PLCClient(is_llc, iface, "00:00:00:00:00:01", 10)
        print "Enumerating PLC devices in the network..."
        plc_macs = client.plc_enumerate(3)
        for plc_mac in plc_macs:
            print "Found PLC with MAC-address {}".format(plc_mac)
            print "Connecting to PLC using COTP..."
            try:
                client._s7comm_.connect(plc_mac)
            except (COTP_Exception, S7COMM_Exception) as e:
                print str(e)
                continue
            print "Connected successfully"
            client._s7comm_.read_szl(0x0132, 0x0004)
            try:
                client._s7comm_.disconnect()
            except COTP_Exception as e:
                print str(e)
                continue
    else:
        client = PLCClient(is_llc, None, None, 10)
        client._s7comm_.connect((plc_ip, plc_port))
        
    


    szls = [(0x132, 0x4), (0x0, 0x0), (0x111, 0x1), (0x424, 0x0), (0xf19, 0x0), (0x19, 0x0), (0xf11, 0x0), (0x11, 0x0)]
    #client.scan("00:00:00:00:00:02", szls)
    """
    macs = client.enum(10)
    for target in macs:
        client.scan(target, szls)
    """

if __name__ == '__main__':
    main()
