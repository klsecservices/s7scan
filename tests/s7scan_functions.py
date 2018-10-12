import sys
sys.path.append('../')
from s7scan import ask_yes_no, get_ip_list, validate_ip, validate_mac, get_user_args, validate_user_args

def test_ask_yes_no():
    print("Testing ask_yes_no()")
    result = ask_yes_no()
    print("Result was {}".format(result))
def test_get_ip_list(ip_list):
    print("Testing get_ip_list()")
    result = get_ip_list(ip_list)
    print("Result IP list:")
    print(result)
def test_validate_ip(ip):
    print("Testing validate_ip()")
    result = validate_ip(ip)
    print("Validation result: {}".format(result))
def test_validate_mac(mac):
    print("Testing validate_mac()")
    result = validate_mac(mac)
    print("Validation result: {}".format(result))
def test_user_args(argv):
    parser, args = get_user_args(argv)
    result = validate_user_args(args)
    print("Argument validation result: {}".format(result))
    if result:
        print("Arguments:")
        print("    is_llc: {}".format(args.is_llc))
        print("    is_tcp: {}".format(args.is_tcp))
        print("    iface: {}".format(args.iface))
        print("    tcp_hosts: {}".format(args.tcp_hosts))
        print("    llc_hosts: {}".format(args.llc_hosts))
        print("    ports: {}".format(args.ports))
        print("    timeout: {}".format(args.timeout))
        print("    log_dir: {}".format(args.log_dir))
        print("    no_log: {}".format(args.no_log))
        print("    addresses: {}".format(args.addresses))
