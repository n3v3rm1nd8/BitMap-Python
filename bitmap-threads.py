###########################################################
###### ES EL MISMO SCRIPT PERO ACTUALIZADO CON HILOS ######
###########################################################

import argparse, sys, socket, time, signal, colorama, re, ipaddress, threading
from scapy.all import *

print()
print('    ____  _ __  __  ___')
print('   / __ )(_) /_/  |/  /___ _____')
print('  / __  / / __/ /|_/ / __ `/ __ \\')
print(' / /_/ / / /_/ /  / / /_/ / /_/ /')
print('/_____/_/\\__/_/  /_/\\__,_/ .___/')
print('                        /_/')
print()
print('\t    Powered by @n3v3rm1nd8')
print()
print('\t    Tw: @n3v3r___m1nd')
print()


def ctrl_c(sig, frame):
    print(colorama.Fore.RED + '\n\n[!] Exiting...\n' + colorama.Style.RESET_ALL)
    sys.exit(1)

def helpPanel():
    print(colorama.Fore.RED + f'\n[!] Use: python3 {sys.argv[0]} -4 <IPv4> or -6 <IPv6>\n\n' + colorama.Style.RESET_ALL)
    print(colorama.Fore.MAGENTA + '[*]' + colorama.Style.RESET_ALL + colorama.Fore.YELLOW + ' -4|--ipv4:' + colorama.Style.RESET_ALL + ' IPv4 target to scan\n')
    print(colorama.Fore.MAGENTA + '[*]' + colorama.Style.RESET_ALL + colorama.Fore.YELLOW + ' -6|--ipv6:' + colorama.Style.RESET_ALL + ' IPv6 target to scan\n')
    print(colorama.Fore.MAGENTA + '[*]' + colorama.Style.RESET_ALL + colorama.Fore.YELLOW + ' -t|--threads:' + colorama.Style.RESET_ALL + ' Number of threads for parallel scanning (default: 5)\n')
    sys.exit(0)

def Scan_IPv4(ipv4, ports, thread_count):
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        try:
            result = sock.connect_ex((ipv4, port))
            srv = socket.getservbyport(port)
            if result == 0:
                print(colorama.Fore.GREEN + f'[+] {port} open' + colorama.Style.RESET_ALL)
                print(f'({srv})\n')
        except:
            pass
        sock.close()

def Check_Scan_IPv4(address):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, address):
        octets = address.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False

def Check_Scan_IPv6(ipv6):
    try:
        ipaddress.IPv6Address(ipv6)
        return True
    except ipaddress.AddressValueError:
        return False

def Scan_IPv6(ipv6, ports, thread_count):
    for port in ports:
        packet = IPv6(dst=ipv6)/TCP(dport=port, flags='S')
        response = sr1(packet, timeout=0.1, verbose=False)
        if response is not None and response.haslayer(TCP) and response[TCP].flags == 'SA':
            try:
                srv = socket.getservbyport(port)
                print(colorama.Fore.GREEN + f'[+] {port} open' + colorama.Style.RESET_ALL)
                print(f'({srv})\n')
            except OSError:
                print(colorama.Fore.GREEN + f'[+] {port} open' + colorama.Style.RESET_ALL)
                print('[Service unknown]\n')
        else:
            pass

def Main():
    colorama.init()
    signal.signal(signal.SIGINT, ctrl_c)

    parser = argparse.ArgumentParser()
    parser.add_argument('-4', '--ipv4')
    parser.add_argument('-6', '--ipv6')
    parser.add_argument('-t', '--threads', type=int, default=5)

    parser.format_help = lambda: helpPanel()

    args, arg_unknown = parser.parse_known_args()

    if not args.ipv4 and not args.ipv6:
        print(colorama.Fore.RED + f"[!] Use '{sys.argv[0]} --help'" + colorama.Style.RESET_ALL)
        sys.exit(1)

    if arg_unknown:
        print(colorama.Fore.RED + f"[!] Unknown option: '{sys.argv[1]}'. Use '{sys.argv[0]} --help'" + colorama.Style.RESET_ALL)
        sys.exit(1)

    if args.ipv4 and Check_Scan_IPv4(args.ipv4):
        ports = range(1, 65536)
        threads = [threading.Thread(target=Scan_IPv4, args=(args.ipv4, ports[i::args.threads], args.threads)) for i in range(args.threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    if args.ipv6 and Check_Scan_IPv6(args.ipv6):
        ports = range(1, 65536)
        threads = [threading.Thread(target=Scan_IPv6, args=(args.ipv6, ports[i::args.threads], args.threads)) for i in range(args.threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

if __name__ == "__main__":
    Main()

