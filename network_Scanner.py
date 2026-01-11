import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option(
        "-t", "--target",
        dest="target",
        help="Target IP / IP Range"
    )
    (options, arguments) = parser.parse_args()

    if not options.target:
        parser.error("Please specify the target, use --help for more info.")

    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = scapy.srp(
        arp_request_broadcast,
        timeout=1,
        verbose=False
    )[0]

    clients = []

    for element in answered_list:
        mac = element[1].hwsrca
        try:
            vendor = MacLookup().lookup(mac)
        except:
            vendor = "Unknown"

        clients_dict = {
            "IP": element[1].psrc,
            "MAC": mac,
            "Vendor": vendor
        }
        clients.append(clients_dict)

    return clients


def print_result(client_list):
    print("-" * 60)
    print("IP Address\t\tMAC Address\t\t\tVendor")
    print("-" * 60)

    for client in client_list:
        print(
            client["IP"] + "\t\t" +
            client["MAC"] + "\t\t" +
            client["Vendor"]
        )


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)