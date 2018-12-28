import struct
from socket import inet_ntoa
from scapy.packet import Packet, bind_layers
from scapy.fields import LEShortField, ThreeBytesField, ByteField, ShortField, BitField
from cotp import COTP_Layer, COTP_LLC_Data, COTP_TCP_Data


class S7COMM_Exception(Exception):
    def __init__(self, message, packet=None, code=0):
        self._message_ = message
        self._packet_ = packet
        self._code_ = code

    def __str__(self):
        if self._packet_ is None:
            s = "[ERROR][S7]{}".format(self._message_)
        else:
            s = "[ERROR][S7]{}\r\n    Packet:{}".format(
                self._message_, str(self._packet_).encode('hex'))
        if self._code_ != 0:
            s += "\r\n    Code: {}".format(self._code_)
        if self._code_ == 0xD402:
            s += " (Information function unavailable)"
        return s


class S7COMM(Packet):
    name = "S7COMM"
    fields_desc = [
        ByteField("protocol_id", 0x32),
        ByteField("rosctr", 1),             # Remote operating service control
        ShortField("reserved", 0x0000),
        LEShortField("pdu_ref", 0x0000),
        ShortField("param_length", 0x0000),
        ShortField("data_length", 0x0000)
        ]


class S7COMM_Ack(Packet):
    name = "S7COMM_Ack"
    fields_desc = [
        ByteField("error_class", 0),
        ByteField("error_code", 0)
    ]


class S7COMM_Job(Packet):
    name = "S7COMM_Job_Func"
    fields_desc = [ByteField("function", 0)]


class S7COMM_Job_Connect(Packet):
    name = "S7COMM_ConnectRequest"
    fields_desc = [
        ByteField("reserved", 0x00),
        ShortField("max_amq_calling", 1),
        ShortField("max_amq_called", 1),
        ShortField("pdu_length", 0x01E0)
    ]


class S7COMM_Data(Packet):
    name = "S7COMM_Data"
    fields_desc = [
        ThreeBytesField("param_head", 0x000112),
        ByteField("param_length", 4),
        ByteField("request_response", 0x11),
        BitField('type', 4, 4),
        BitField('func_group', 0, 4),
        ByteField("subfunc", 1),
        ByteField("seq_num", 0)
    ]


class S7COMM_Data_ReadSZL(Packet):
    name = "S7COMM_Read_SZL"
    fields_desc = [
        ByteField("return_code", 0xFF),
        ByteField("transport_size_os", 0x09),
        ShortField("transport_size_value", 0x0004),
        ShortField("szl_id", 0x0000),
        ShortField("szl_ind", 0x0000)
    ]


class S7COMM_Data_SZL(Packet):
    name = "S7COMM_Data_SZL"
    fields_desc = [
        ByteField("du_ref_num", 0),
        ByteField("last_du", 0),
        ShortField("error_code", 0x0000),
        ByteField("return_code", 0xFF),
        ByteField("transport_size_os", 0x09),
        ShortField("length", 0x0000)
    ]

bind_layers(COTP_LLC_Data, S7COMM)
bind_layers(COTP_TCP_Data, S7COMM)
bind_layers(S7COMM, S7COMM_Ack, rosctr=3)
bind_layers(S7COMM, S7COMM_Job, rosctr=1)
bind_layers(S7COMM, S7COMM_Data, rosctr=7)
bind_layers(S7COMM_Ack, S7COMM_Job)
bind_layers(S7COMM_Job, S7COMM_Job_Connect, function=0xF0)
bind_layers(S7COMM_Data, S7COMM_Data_ReadSZL, request_response=0x11,
            type=4, func_group=4, subfunc=1)
bind_layers(S7COMM_Data, S7COMM_Data_SZL,
            request_response=0x12, func_group=4, subfunc=1)


class ModuleID_Record():
    def __init__(self, data):
        self.index = struct.unpack("!H", data[:2])[0]
        self.order_number = data[2:22].strip(" ").strip("\x00")
        self.reserved = struct.unpack("!H", data[22:24])[0]
        self.version = struct.unpack("!H", data[24:26])[0]
        self.version2 = struct.unpack("!H", data[26:28])[0]
        # Skip letter 'V/v' in version
        if chr((self.version >> 8) & 0xFF) in ['V', 'v']:
            self.version = self.version & 0xFF

    def __str__(self):
        if self.index == 1:
            s = "Module\r\n"
        elif self.index == 6:
            s = "Basic hardware\r\n"
        elif self.index == 7:
            s = "Basic firmware\r\n"
        else:
            s = "Unknown index {}\r\n".format(self.index)
        if self.order_number != "":
            if self.index in [1, 6]:
                s += "    Order number: {}\r\n".format(self.order_number)
            else:
                s += "    {}\r\n".format(self.order_number)
        s += "    Version: {}.{}.{}".format(self.version, self.version2 >> 8, self.version2 & 0xFF)
        return s


class ProtectionRecord():
    def __init__(self, data):
        index = struct.unpack("!H", data[0:2])[0]
        index_b0 = (index >> 8) & 0xFF
        if index_b0 == 0:
            self.cpu_type = "Standard CPU"
            self.cpu_mode = None
            self.rack_num = 0
        else:
            self.cpu_type = "H CPU (High availability)"
            self.rack_num = index_b0 & 0x07
            if index_b0 & 0x08 == 0:
                self.cpu_mode = "Standby CPU"
            else:
                self.cpu_mode = "Master CPU"
        self.protection_mode_selector = struct.unpack("!H", data[2:4])[0]
        self.protection_parameters = struct.unpack("!H", data[4:6])[0]
        self.protection_cpu = struct.unpack("!H", data[6:8])[0]
        self.mode_selector = struct.unpack("!H", data[8:10])[0]
        self.startup_switch = struct.unpack("!H", data[10:12])[0]
        self.id = struct.unpack("!H", data[12:14])[0]
        self.hw_chksum_1 = struct.unpack("!H", data[14:16])[0]
        self.hw_chksum_2 = struct.unpack("!H", data[16:18])[0]
        self.user_prog_chksum_1 = struct.unpack("!H", data[18:20])[0]
        self.user_prog_chksum_2 = struct.unpack("!H", data[20:22])[0]

    def __str__(self):
        s = "    CPU type: {}\r\n".format(self.cpu_type)
        if self.cpu_type == "H CPU (High availability)":
            s += "    CPU rack number: {}. Mode: {}\r\n".format(self.rack_num,
                                                                self.cpu_mode)
        if self.protection_mode_selector in [1, 2, 3]:
            s += "    Protection level set with the mode selector: {}\r\n".format(self.protection_mode_selector)
        else:
            s += "    Protection level set with the mode selector: not applicable ({})\r\n".format(self.protection_mode_selector)
        if self.protection_parameters in [0, 1, 2, 3]:
            s += "    Protection level set in parameters: {}".format(self.protection_parameters)
            if self.protection_parameters == 0:
                s += " (no password)"
            s += "\r\n"
        else:
            s += "    Protection level set in parameters: unknown ({})\r\n".format(self.protection_parameters)
        if self.protection_cpu in [0, 1, 2, 3]:
            s += "    Valid protection level of the cpu: {}\r\n".format(self.protection_cpu)
        else:
            s += "    Valid protection level of the cpu: unknown ({})\r\n".format(self.protection_cpu)
        s += "    Mode selector: {} (".format(self.mode_selector)
        if self.mode_selector == 1:
            s += "RUN)\r\n"
        elif self.mode_selector == 2:
            s += "RUN-P)\r\n"
        elif self.mode_selector == 3:
            s += "STOP)\r\n"
        elif self.mode_selector == 4:
            s += "MRES)\r\n"
        else:
            s += "undefined / cannont be determined)\r\n"
        s += "    Startup switch setting: {} (".format(self.startup_switch)
        if self.startup_switch == 1:
            s += "CRST)\r\n"
        elif self.startup_switch == 2:
            s += "WRST)\r\n"
        else:
            s += "undefined)\r\n"
        return s


class ComponentID_Record():
    def __init__(self, data):
        self.index = struct.unpack("!H", data[:2])[0]
        if self.index in [1, 2, 5]:
            self.name = data[2:26].strip("\x00")
        elif self.index in [3, 7, 8, 11]:
            self.name = data[2:34].strip("\x00")
        elif self.index == 4:
            self.name = data[2:28].strip("\x00")
        elif self.index == 9:
            self.name = ""
            self.manufacturer_id = struct.unpack("!H", data[2:4])[0]
            self.profile_id = struct.unpack("!H", data[4:6])[0]
            self.profile_type = struct.unpack("!H", data[6:8])[0]
        elif self.index == 10:
            self.name = data[2:28].strip("\x00")
            self.oem_id = struct.unpack("!H", data[28:30])[0]
            self.oem_add_id = struct.unpack("!H", data[30:32])[0]
        else:
            self.name = data[2:]

    def __str__(self):
        if self.name == "" and self.index not in [9, 10]:
            return ""
        if self.index == 1:
            return "    PLC name: {}".format(self.name)
        elif self.index == 2:
            return "    Module name: {}".format(self.name)
        elif self.index == 3:
            return "    Plant identification of the module: {}".format(self.name)
        elif self.index == 4:
            return "    Stamp: {}".format(self.name)
        elif self.index == 5:
            return "    Serial number: {}".format(self.name)
        elif self.index == 7:
            return "    Module type name: {}".format(self.name)
        elif self.index == 8:
            if self.name in ["MC", "MMC"]:
                return "    No memory card installed"
            else:
                return "    Memory card serial number: {}".format(self.name)
        elif self.index == 9:
            return "    Manufacturer ID: {}; ptofile ID: {}; profile specific type: {}".format(self.manufacturer_id, self.profile_id, self.profile_type)
        elif self.index == 10:
            return "    OEM copyright ID: {}; OEM ID: {}; additional OEM ID: {}".format(self.name, self.oem_id, self.oem_add_id)
        elif self.index == 11:
            return "    Location designation: {}".format(self.name)
        else:
            return "    Unknown component identification index ({}) {}\r\n    {}".format(self.index, self.name, self.name.encode("hex"))


class EthDetailsRecord():
    def __init__(self, data):
        self.logaddr = struct.unpack("!H", data[:2])[0]
        self.ip_addr = inet_ntoa(data[2:6])
        self.subnetmask = inet_ntoa(data[6:10])
        self.defaultrouter = inet_ntoa(data[10:14])
        self.mac_addr = "{}:{}:{}:{}:{}:{}".format(data[14].encode('hex'),
                                                   data[15].encode('hex'),
                                                   data[16].encode('hex'),
                                                   data[17].encode('hex'),
                                                   data[18].encode('hex'),
                                                   data[19].encode('hex'))
        self.source = ord(data[20])
        if self.source == 0:
            self.source_str = "IP address not initialized"
        elif self.source == 1:
            self.source_str = "IP address was configured in STEP 7"
        elif self.source == 2:
            self.source_str = "IP address was set via DCP"
        elif self.source == 3:
            self.source_str = " IP address was obtained from a DHCP server"
        else:
            self.source_str = ""
        self.dcp_mod_timestamp = data[21:29]
        self.phys_modes = data[30:46]

    def __str__(self):
        s = "    Logical base address: {:X}\r\n".format(self.logaddr)
        if self.source_str:
            s += "    {}\r\n".format(self.source_str)
        if self.source in [1, 2, 3]:
            s += "    IP address: {}/{}\r\n".format(self.ip_addr, self.subnetmask)
            s += "    Default gateway: {}\r\n".format(self.defaultrouter)
        s += "    MAC address: {}\r\n".format(self.mac_addr)
        if self.source == 2:
            s += "    IP address last changed through DCP: {:X}".format(self.dcp_mod_timestamp.encode("hex"))
        s += "    Physical status of ports: {}".format(self.phys_modes.encode("hex"))
        return s


class S7Layer():
    def __init__(self, is_llc=False, ifname=None, mac_addr=None, recv_timeout=10):
        # S7 layer relies on COTP layer
        self._cotp_ = COTP_Layer(is_llc, ifname, mac_addr, recv_timeout)
        self._connected_ = False
        self._pdu_ref_ = 0

    def _parse_szl(self, szl_data, elen=0, ecount=0):
        entries = []
        if len(szl_data) < 8:
            raise S7COMM_Exception("[PARSE SZL]Unknown szl format")
        szl_data = szl_data[4:]  # Skip SZL id and index from szl_data
        entry_len, entries_count = struct.unpack("!HH", szl_data[:4])
        if elen != 0 and elen != entry_len:
            raise S7COMM_Exception("[PARSE SZL]Incorrect entry length")
        if ecount != 0 and ecount != entries_count:
            raise S7COMM_Exception("[PARSE SZL]Incorrect entries count")
        if len(szl_data) - 4 < entry_len * entries_count:
            raise S7COMM_Exception("[PARSE SZL]Incorrect data length")
        for i in range(0, entries_count):
            offset = 4 + entry_len * i
            entries.append(szl_data[offset:offset+entry_len])
        return entries

    def settimeout(self, timeout):
        self._cotp_.settimeout(timeout)

    def sendrecv(self, packet):
        packet[S7COMM].pdu_ref = self._pdu_ref_
        answer = self._cotp_.sendrecv(packet)
        self._pdu_ref_ = (self._pdu_ref_ + 1) & 0xFFFF
        return answer

    def connect(self, dst_addr, dst_tsap):
        self._cotp_.connect(dst_addr, 0x0100, dst_tsap)
        answer = self.sendrecv(S7COMM(param_length=8, data_length=0) / S7COMM_Job() / S7COMM_Job_Connect())
        if not answer.haslayer(S7COMM_Ack) or not answer.haslayer(S7COMM_Job_Connect):
            raise S7COMM_Exception("[CONNECT]Incorrect reply from server", answer)
        if answer[S7COMM_Ack].error_class != 0 or answer[S7COMM_Ack].error_code != 0:
            raise S7COMM_Exception("[CONNECT]Server replied with connection error", answer)
        self._connected_ = True
        self._pdu_length_ = answer[S7COMM_Job_Connect].pdu_length

    def disconnect(self):
        self._cotp_.disconnect()
        self._connected_ = False

    def read_szl(self, szl_id, szl_index):
        if not self._connected_:
            raise S7COMM_Exception("[READ_SZL]Not connected")
        answer = self.sendrecv(
            S7COMM(param_length=8, data_length=8) /
            S7COMM_Data(param_length=4) /
            S7COMM_Data_ReadSZL(szl_id=szl_id, szl_ind=szl_index)
        )
        if not answer.haslayer(S7COMM_Data_SZL):
            raise S7COMM_Exception("[READ_SZL]Incorrect reply from server")
        # Save SZL data
        szl_data = str(answer[S7COMM_Data_SZL].payload)[:answer[S7COMM_Data_SZL].length]
        # If data unit is not last, we need to get the rest part
        while answer[S7COMM_Data_SZL].last_du:
            answer = self.sendrecv(
                S7COMM(param_length=12, data_length=4) /
                S7COMM_Data(param_length=4, seq_num=answer[S7COMM_Data].seq_num) /
                S7COMM_Data_SZL(return_code=0x0A, transport_size_os=0)
            )
            szl_data = szl_data + str(answer[S7COMM_Data_SZL].payload)[:answer[S7COMM_Data_SZL].length]
        return szl_data

    def read_szl_list(self):
        szl_list = []
        szl_data = self.read_szl(0x0000, 0x0000)
        try:
            entries = self._parse_szl(szl_data, elen=2)
        except S7COMM_Exception:
            return szl_data
        for entry in entries:
            szl_list.append(struct.unpack("!H", entry)[0])
        return szl_list

    def read_module_id(self):
        records = []
        szl_data = self.read_szl(0x0011, 0x0000)
        try:
            entries = self._parse_szl(szl_data, elen=28)
        except S7COMM_Exception:
            return szl_data
        for entry in entries:
            records.append(ModuleID_Record(entry))
        return records

    def read_protection(self):
        records = []
        szl_data = self.read_szl(0x0232, 0x0004)
        try:
            entries = self._parse_szl(szl_data, elen=40)
        except S7COMM_Exception:
            return szl_data
        for entry in entries:
            records.append(ProtectionRecord(entry))
        return records

    def read_component_id(self):
        records = []
        szl_data = self.read_szl(0x001C, 0x0000)
        try:
            entries = self._parse_szl(szl_data, elen=34)
        except S7COMM_Exception:
            return szl_data
        for entry in entries:
            records.append(ComponentID_Record(entry))
        return records

    def read_eth_details(self):
        records = []
        szl_data = self.read_szl(0x0037, 0x0000)
        try:
            entries = self._parse_szl(szl_data, elen=48)
        except S7COMM_Exception:
            return szl_data
        for entry in entries:
            records.append(EthDetailsRecord(entry))
        return records
