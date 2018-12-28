import sys
import os
import platform
import socket
import struct
import pickle
import datetime
from collections import OrderedDict
from argparse import ArgumentParser
# sys.path.append('./third_parties')
from scapy.arch import get_if_hwaddr
from scapy.layers.l2 import LLC, SNAP
from protocols import s7, cotp, s01fd, ether

S7SCAN_LOG_FILE = "scan_log.txt"
S7SCAN_PLC_FILE = "plc_data.dat"


def ask_yes_no():
    valid = {"yes": True, "y": True, "no": False, "n": False}
    while True:
        choice = raw_input().lower()
        if choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no'\n")


def get_ip_list(mask):
    try:
        net_addr, mask = mask.split('/')
        mask = int(mask)
        start, = struct.unpack('!L', socket.inet_aton(net_addr))
        start &= 0xFFFFFFFF << (32-mask)
        end = start | (0xFFFFFFFF >> mask)
        return [socket.inet_ntoa(struct.pack('!L', addr)) for addr in range(start + 1, end)]
    except (struct.error, socket.error, ValueError):
        return []


def validate_ip(ip):
    try:
        socket.inet_aton(ip)
    except socket.error:
        return False
    return ip.count(".") == 3


def validate_mac(mac):
    if mac.count(":") != 5:
        return False
    for i in mac.split(":"):
        if len(i) != 2:
            return False
        for j in i:
            if j.upper() > "F" or (j.upper() < "A" and not j.isdigit()) or len(i) != 2:
                return False
    return True


def get_user_args(argv):
    # Setup option parser
    parser = ArgumentParser(
        usage="s7scan [options] [addresses]...",
        description="""Scan network for Siemens PLC devices. \
        Supports LLC- and TCP/IP based networks. \
        Uses S7 to communicate to PLCs"""
        )
    parser.add_argument("--llc", action='store_const',
                        const=True, default=False, dest='is_llc',
                        help="Perform LLC networ scan")
    parser.add_argument("--tcp", action='store_const',
                        const=True, default=False, dest='is_tcp',
                        help="Perform TCP network scan")
    parser.add_argument("--iface", default="", dest='iface',
                        help="Network interface to use (required for LLC scan only)")
    parser.add_argument("--tcp-hosts", dest="tcp_hosts", help="""Scan TCP hosts from FILE. \
        TCP host list is a list of IP-addresses. Each address must be placed \
        on a separate line""",
                        metavar="FILE")
    parser.add_argument("--llc-hosts", dest="llc_hosts", help="""Scan LLC hosts from FILE. \
        LLC host list is a list of MAC-addresses. Each address must be placed \
        on a separate line""",
                        metavar="FILE")
    parser.add_argument("--ports", dest="ports",
                        help="Scan ports from PORTS (for TCP/IP only)",
                        metavar="PORTS", default="102")
    parser.add_argument("--timeout", dest="timeout", default=0,
                        help="Receive timeout (seconds). How long to wait for server responses")
    parser.add_argument("--log-dir", dest="log_dir",
                        help="Path to the directory where scan results will be stored",
                        metavar="LOG_DIR",
                        default=os.path.join(".", "s7scan_{}".format(datetime.datetime.now().strftime("%Y%m%d_%H%M"))))
    parser.add_argument("--no-log", action='store_const',
                        const=True, default=False, dest='no_log',
                        help="Disable saving scan results in files")
    parser.add_argument("addresses", nargs="*")
    # Parse arguments and retrun them to caller
    args = parser.parse_args(argv)
    return parser, args


def validate_user_args(args):
    # Check if at least one scanning protocol is selected
    if not (args.is_llc or args.is_tcp):
        print("Select at least one protocol to scan (LLC/TCP)")
        return False
    # Check user input for args.iface
    if args.is_llc:
        if args.iface == "":
            print("Please specify network interface to use for LLC scan (For example, 'eth0' or 'Intel(R) Ethernet Connection')")
            return False
        try:
            get_if_hwaddr(args.iface)
        except (IOError, ValueError):  # For Linux it's IOError in ioctl, for Windows it's ValueError
            print("Error: invalid interface '{}'. Please check that network interface specified exists. A valid interface might be 'eth0' or 'Intel(R) Ethernet Connection'").format(args.iface)
            return False
    # Prepare arrays for TCP and LLC scan hosts
    tcp_scan_hosts = []
    llc_scan_hosts = []
    # Read args.tcp_hosts file contents if --tcp was specified
    if args.is_tcp:
        if args.tcp_hosts:
            try:
                tcp_scan_hosts = [line.strip() for line in open(args.tcp_hosts, 'r').readlines()]
            except IOError:
                print("Can't open file {}".format(args.tcp_hosts))
                return False
    # Read args.llc_hosts file contents if --llc was specified
    if args.is_llc:
        if args.llc_hosts:
            try:
                llc_scan_hosts = [line.strip() for line in open(args.llc_hosts, 'r').readlines()]
            except IOError:
                print("Can't open file {}".format(args.llc_hosts))
                return False
    # Add addresses from args.addresses
    if args.is_tcp:
        for addr in args.addresses:
            tcp_scan_hosts.extend(get_ip_list(addr) if '/' in addr else [addr])
    elif args.is_llc:
        llc_scan_hosts.extend(args.addresses)
    # Delete empty and repeated hosts
    llc_scan_hosts = filter(None, llc_scan_hosts)
    llc_scan_hosts = list(OrderedDict.fromkeys(llc_scan_hosts))
    tcp_scan_hosts = filter(None, tcp_scan_hosts)
    tcp_scan_hosts = list(OrderedDict.fromkeys(tcp_scan_hosts))
    # Validate all target IP addresses
    for host in tcp_scan_hosts:
        if not validate_ip(host):
            print("Error: incorrect target IP address found: {}".format(host))
            return False
    for host in llc_scan_hosts:
        if not validate_mac(host):
            print("Error: incorrect target MAC address found: {}".format(host))
            return False
    if args.is_tcp and not tcp_scan_hosts:
        print("No targets for TCP/IP scan")
        return False
    args.tcp_hosts = tcp_scan_hosts
    args.llc_hosts = llc_scan_hosts
    # Validate scan ports (TCP only)
    if args.is_tcp:
        try:
            scan_ports = [int(port) for port in args.ports.split(',')]
        except ValueError:
            print("Incorrect port value specified")
            return False
        args.ports = scan_ports
    # Check whether the directory for log files exists if args.no_log is not specified
    if not args.no_log:
        logfile = os.path.join(args.log_dir, S7SCAN_LOG_FILE)
        plcfile = os.path.join(args.log_dir, S7SCAN_PLC_FILE)
        if not os.path.isdir(args.log_dir):
            # The directory does not exist. Create it now
            try:
                os.makedirs(args.log_dir)
                open(logfile, "wb")
                open(plcfile, "wb")
            except:
                print("Error: unable to create directory for log files {}. Please check access rights".format(args.log_dir))
                return False
        else:
            # The directory already exists. Check whether log files exist in it
            if os.path.isfile(logfile) or os.path.isfile(plcfile):
                print("The log files already exist in specified log directory. Do you want to override them?")
                if not ask_yes_no():
                    print("Cancelled")
                    return False
                else:
                    try:
                        open(logfile, "wb")
                        open(plcfile, "wb")
                    except IOError:
                        print("Error: unable to create access log files. Please check access rights")
                        return False
    else:
        args.log_dir = None
    # Validate timeout value
    try:
        args.timeout = int(args.timeout)
    except ValueError:
        print("Incorrect timeout value specified")
        return False
    if args.timeout == 0:
        if args.is_llc:
            args.timeout = 10
        else:
            args.timeout = 1
    # All arguments seem to be OK, returning True
    return True


class S7_PLC_Module:
    def __init__(self, tsap, port=None, records=None):
        self.tsap = tsap
        self.port = port
        self.module_ids_records = []
        self.protection_records = []
        self.component_id_records = []
        self.eth_records = []
        self.szl_list = []
        if records:
            self.add_records(records)

    def __str__(self):
        s = "Tsap {:04X}".format(self.tsap)
        if self.port:
            s += " (found on TCP port {})\r\n".format(self.port)
        else:
            s += "\r\n"
        s += "Module identification:\r\n"
        for record in self.module_ids_records:
            s += str(record) + "\r\n"
        s += "Module protection:\r\n"
        for record in self.protection_records:
            s += str(record) + "\r\n"
        s += "Component identification:\r\n"
        for record in self.component_id_records:
            s += str(record) + "\r\n"
        s += "Module ethernet details:\r\n"
        for record in self.eth_records:
            s += str(record) + "\r\n"
        return s

    def add_szl_list(self, szls):
        self.szl_list = szls

    def add_records(self, records):
        if not records:
            return
        for record in records:
            if isinstance(record, s7.ModuleID_Record):
                self.module_ids_records.append(record)
            elif isinstance(record, s7.ProtectionRecord):
                self.protection_records.append(record)
            elif isinstance(record, s7.ComponentID_Record):
                self.component_id_records.append(record)
            elif isinstance(record, s7.EthDetailsRecord):
                self.eth_records.append(record)
            else:
                continue


class S7_PLC:
    def __init__(self, sup_llc, sup_tcp, ip_addr, mac_addr):
        self.ip_addr = ip_addr
        self.mac_addr = mac_addr
        self.ports = []
        self.supports_tcp = sup_tcp
        self.supports_llc = sup_llc
        self.modules = OrderedDict()

    def add_module(self, tsap, port=None):
        if tsap not in self.modules.keys():
            self.modules[tsap] = S7_PLC_Module(tsap)
        if port and port not in self.ports:
            self.ports.append(port)
        return self.modules[tsap]


class PLC_Scanner():
    def __init__(self, is_llc=False, ifname=None, timeout=3, log_dir=None):
        if is_llc:
            self._mac_addr_ = get_if_hwaddr(ifname)
            self._ifname_ = ifname
            self._ether_ = ether.EtherRaw(ifname, self._mac_addr_)
        else:
            self._mac_addr_ = None
            self._ifname_ = None
            self._ether_ = None
        self._conn_ = s7.S7Layer(is_llc, ifname, self._mac_addr_, timeout)
        self._szl_list_ = []
        self._timeout_ = timeout
        self._is_llc = is_llc
        self.results = OrderedDict()
        self.results["Scan start time"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        self.results["Command line arguments"] = []
        for arg in sys.argv:
            self.results["Command line arguments"].append(arg.decode(sys.stdin.encoding).encode("utf-8"))
        self.plcs = OrderedDict()
        if log_dir:
            self.logfile = open(os.path.join(log_dir, S7SCAN_LOG_FILE), "wb")
            self.plcfile = open(os.path.join(log_dir, S7SCAN_PLC_FILE), "wb")
        else:
            self.logfile = None
            self.plcfile = None
        self.silent = False
    """
    Reset scanner and configure it to use another protocol without using
    previous scan results
    """
    def reset(self, is_llc=False, ifname=None, timeout=3):
        if is_llc:
            self._mac_addr_ = get_if_hwaddr(ifname)
            self._ifname_ = ifname
            self._ether_ = ether.EtherRaw(ifname, self._mac_addr_)
        else:
            self._mac_addr_ = None
            self._ifname_ = None
            self._ether_ = None
        self._conn_ = s7.S7Layer(is_llc, ifname, self._mac_addr_, timeout)
        self._timeout_ = timeout
        self._is_llc = is_llc

    def log_write(self, log_str):
        if not self.silent:
            print(log_str)
        if self.logfile:
            self.logfile.write(log_str + "\r\n")

    def log_flush(self):
        if self.logfile:
            self.logfile.flush()

    def serialize_plc(self, addr):
        if self.plcfile and addr in self.plcs.keys():
            pickle.dump(self.plcs[addr], self.plcfile)
            self.plcfile.flush()

    def add_plc(self, addr):
        if addr not in self.plcs.keys():
            if self._is_llc:
                self.plcs[addr] = S7_PLC(True, False, None, addr)
            else:
                self.plcs[addr] = S7_PLC(False, True, addr, None)

    def add_plc_module(self, addr, tsap):
        if not self._is_llc:
            (addr, port) = addr
        else:
            (addr, port) = (addr, None)
        if addr not in self.plcs.keys():
            self.add_plc(addr)
        return self.plcs[addr].add_module(tsap, port)

    def llc_enumerate(self, timeout):
        bcast = "ff:ff:ff:ff:ff:ff"
        bcast_packet = LLC() / SNAP() / s01fd.S01FD(type=0x0500)
        answers = self._ether_.sendrcv_timeout(bcast, bcast_packet, timeout)
        macs = []
        for x in answers:
            if x.haslayer(s01fd.S01FD):
                if x[s01fd.S01FD].type == 0x0501:
                    macs.append(x.src)
        return macs

    def read_device_info(self, szl_list, szls):
        result = []
        for szl in szls:
            if (len(szl_list) == 0) or (len(szl_list) > 0 and szl in szl_list):
                if szl == 0x0011:
                    ids = self._conn_.read_module_id()
                    log_str = "module identification"
                elif szl == 0x001C:
                    ids = self._conn_.read_component_id()
                    log_str = "component identification"
                elif szl == 0x0232:
                    ids = self._conn_.read_protection()
                    log_str = "module protection info"
                elif szl == 0x0037:
                    ids = self._conn_.read_eth_details()
                    log_str = "module ethernet details"
                else:
                    ids = []
                if type(ids) is str:
                    if len(ids) > 0:
                        self.log_write("    [-] Error occured while reading {} (unknown response format). Raw resposne:".format(log_str))
                        self.log_write(ids.encode('hex'))
                    else:
                        self.log_write("    [-] Error occured while reading {} (no answer from the device)".format(log_str))
                    ids = []
            else:
                if szl == 0x0011:
                    log_str = "module identification"
                elif szl == 0x001C:
                    log_str = "component identification"
                elif szl == 0x0232:
                    log_str = "module protection info"
                elif szl == 0x0037:
                    log_str = "module ethernet details"
                else:
                    log_str = "unknown"
                self.log_write("[-] {} SZL ({:04X}) is not supported by this module".format(log_str, szl))
                ids = []
            self.log_flush()
            result.extend(ids)
        return result

    def scan(self, addr, tsap):
        # 1. Connect to the device
        try:
            self._conn_.connect(addr, tsap)
        except (cotp.COTP_Exception, s7.S7COMM_Exception, socket.error):
            return
        self.log_write("\r\n\r\nConnected to {} with tsap {:04x}".format(addr, tsap))
        self.log_flush()
        # 1. Create new PLC module (and PLC, if it doesn't exist)
        module = self.add_plc_module(addr, tsap)
        # 2. Get SZL list from the device
        szl_list = self._conn_.read_szl_list()
        if len(szl_list) == 0:
            self.log_write("[-] Error occured while reading SZL list (no answer from the device)")
        elif type(szl_list) is str:
            self.log_write("[-] Error occured while reading SZL list (unknown response format). Raw resposne:")
            self.log_write(szl_list.encode('hex'))
            szl_list = []
        module.add_szl_list(szl_list)
        self.log_flush()
        # 3. Read all module parameters, save them in the PLC array and log
        module.add_records(self.read_device_info(szl_list, [0x0011, 0x001C, 0x0232, 0x0037]))
        self.log_write(str(module))
        self.log_flush()

    def scan_llc(self, scan_hosts):
        self.log_write("LLC network scan started")
        self.log_write("Using network interface {} / {}".format(self._ifname_, self._mac_addr_))
        if scan_hosts in [None, []]:
            self.log_write("Hosts to scan were not specified. Sending broadcast enumeration request...")
            scan_hosts = self.llc_enumerate(5)
            if len(scan_hosts) == 0:
                self.log_write("No PLCs detected in the network")
                return
            self.log_write("Detected hosts: {}".format(scan_hosts))
        self.log_flush()
        for host in scan_hosts:
            self.log_write("\rScanning {}...".format(host))
            # Restore timeout value after possible fine tune from previous host scan
            self._conn_.settimeout(self._timeout_)
            for tsap in range(0x0100, 0x0200):
                    self.scan(host, tsap)
            # Serialize data collected for curent PLC (host)
            self.serialize_plc(host)
        self.log_write("\r\n\r\nScan ended")
        return

    def scan_tcp(self, scan_hosts, scan_ports):
        self.log_write("TCP/IP network scan started")
        for host in scan_hosts:
            sys.stdout.write("\rScanning {}...".format(host))
            # Restore timeout value after possible fine tune from previous host scan
            self._conn_.settimeout(self._timeout_)
            for port in scan_ports:
                for tsap in range(0x0100, 0x0200):
                    try:
                        self.scan((host, port), tsap)
                    except (cotp.UnreachableHostException, cotp.ConnectionRefusedException, cotp.COTP_Exception, s7.S7COMM_Exception, socket.timeout) as e:
                        if type(e) == socket.timeout:
                            self.log_write("socket timeout happened")
                            continue
                        elif type(e) == s7.S7COMM_Exception or type(e) == cotp.COTP_Exception:
                            self.log_write(str(e))
                            continue
                        else:
                            break
            # Serialize data collected for curent PLC (host)
            self.serialize_plc(host)
        self.log_write("\r\n\r\nScan ended")


def main():
    print("s7scan v1.03 [Python 2] [Scapy-based]")
    # Get user arguments
    parser, args = get_user_args(sys.argv[1:])
    # Validate user arguments
    if not validate_user_args(args):
        parser.print_help()
        return
    # Run scan
    scanner = None
    if args.is_llc:
        # For LLC we need to check whether WinPcap is installed first (in case we are running on Windows)
        #system = platform.system()
        #if system == 'Windows':
        #    if not winpcap_installer.is_installed():
        #        # WinPcap is not installed. We need to install it to continue
        #        print "[Warning] WinPcap is not installed on the current Windows system. Do you want to install it (y/n)?"
        #        print "It will be uninstalled automatically after scan"
        #        if not ask_yes_no():
        #            print "LLC scan without WinPcap is not supported. Terminating..."
        #            return
        #        else:
        #            winpcap_installer.install()
        #            reload(scapy)
        # Setup scanner
        scanner = PLC_Scanner(is_llc=True, ifname=args.iface, timeout=args.timeout, log_dir=args.log_dir)
        scanner.scan_llc(args.llc_hosts)
        # winpcap_installer.uninstall()
    if args.is_tcp:
        # Setup scanner
        if scanner:
            scanner.reset()
        else:
            scanner = PLC_Scanner(is_llc=False, ifname=None, timeout=args.timeout, log_dir=args.log_dir)
        scanner.scan_tcp(args.tcp_hosts, args.ports)
    # Serialize collected data to the separate file using pickle
    #if not args.no_log:
    #    json.dump(scanner.results, open(args.log_file, "wb"), indent=4)
    #    print("Scan results saved to {}".format(args.log_file))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\r\nScan terminated")
