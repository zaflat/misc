#!/usr/bin/env python

from bcc import BPF
import pyroute2
import time
import sys
import os
import curses
import math

icmp_type_map = "Echo Reply", "Unassigned", "Unassigned", "Destination Unreachable", "Source Quench ", "Redirect", "Alternate Host Address ", "Unassigned", "Echo Request", "Router Advertisement", "Router Selection", "Time Exceeded", "Parameter Problem", "Timestamp", "Timestamp Reply", "Information Request ", "Information Reply ", "Address Mask Request ", "Address Mask Reply ", "Reserved Security", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Reserved Robustness", "Traceroute ", "Datagram Conversion Error ", "Mobile Host Redirect ", "IPv6 Where-Are-You ", "IPv6 I-Am-Here ", "Mobile Registration Request ", "Mobile Registration Reply ", "Domain Name Request ", "Domain Name Reply ", "SKIP ", "Photuris", "experimental mobility", "Extended Echo Request", "Extended Echo Reply", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "RFC3692-style Experiment 1", "RFC3692-style Experiment 2", "Reserved"

ipv4_protocol_map = "HOPOPT", "ICMP", "IGMP", "GGP", "IPv4", "ST", "TCP", "CBT", "EGP", "IGP", "BBN-RCC-MON", "NVP-II", "PUP", "ARGUS", "EMCON", "XNET", "CHAOS", "UDP", "MUX", "DCN-MEAS", "HMP", "PRM", "XNS-IDP", "TRUNK-1", "TRUNK-2", "LEAF-1", "LEAF-2", "RDP", "IRTP", "ISO-TP4", "NETBLT", "MFE-NSP", "MERIT-INP", "DCCP", "3PC", "IDPR", "XTP", "DDP", "IDPR-CMTP", "TP++", "IL", "IPv6", "SDRP", "IPv6-Route", "IPv6-Frag", "IDRP", "RSVP", "GRE", "DSR", "BNA", "ESP", "AH", "I-NLSP", "SWIPE", "NARP", "MOBILE", "TLSP", "SKIP", "IPv6-ICMP", "IPv6-NoNxt", "IPv6-Opts", "any_host_internal_protocol", "CFTP", "any_local_network", "SAT-EXPAK", "KRYPTOLAN", "RVD", "IPPC", "any_distributed_file_system", "SAT-MON", "VISA", "IPCV", "CPNX", "CPHB", "WSN", "PVP", "BR-SAT-MON", "SUN-ND", "WB-MON", "WB-EXPAK", "ISO-IP", "VMTP", "SECURE-VMTP", "VINES", "TTP/IPTM", "NSFNET-IGP", "DGP", "TCF", "EIGRP", "OSPFIGP", "Sprite-RPC", "LARP", "MTP", "AX.25", "IPIP", "MICP", "SCC-SP", "ETHERIP", "ENCAP", "any_private_encryption_scheme", "GMTP", "IFMP", "PNNI", "PIM", "ARIS", "SCPS", "QNX", "A/N", "IPComp", "SNP", "Compaq-Peer", "IPX-in-IP", "VRRP", "PGM", "any_0-hop_protocol", "L2TP", "DDX", "IATP", "STP", "SRP", "UTI", "SMP", "SM", "PTP", "ISIS", "FIRE", "CRTP", "CRUDP", "SSCOPMCE", "IPLT", "SPS", "PIPE", "SCTP", "FC", "RSVP-E2E-IGNORE", "Mobility", "UDPLite", "MPLS-in-IP", "manet", "HIP", "Shim6", "WESP", "ROHC", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Unassigned", "Experimental", "Experimental", "Reserved"

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

flags = 0
def usage():
    print("Usage: {0} <ifdev>\n".format(sys.argv[0]))
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2:
    usage()

if len(sys.argv) == 2:
    device = sys.argv[1]

# load BPF program
b = BPF(src_file="xdp_ipv4_count.c", cflags=["-w"])

fn = b.load_func("ipv4_count", BPF.XDP)

b.attach_xdp(device, fn, flags)

ip4cnt = b.get_table("ip4cnt")
tcportcnt = b.get_table("tcportcnt")
udportcnt = b.get_table("udportcnt")
icmpcnt = b.get_table("icmpcnt")

stdscr = curses.initscr()
curses.noecho()
curses.cbreak()

total = 0
spin = 0
spinner = '|/-\\'

try:
    while 1:
        try:
            stdscr.clear()
            for k in ip4cnt.keys():
               val = ip4cnt.sum(k).value
               if val:
                   total += val
            stdscr.addstr(0, 0, "{}DP DEMO: RX   {:>11} IPv4 Packets".format(spinner[spin % 4],total))
            stdscr.addstr(1, 0, "---------------------------------------")
            line = 2
            for k in ip4cnt.keys():
                val = ip4cnt.sum(k).value
                if val:
                    stdscr.addstr(line, 0, "")
                    line += 1
                    prcnt = 0 if total == 0 else 1 if (float(val)/total*10) < 1 else 10 if val > total else int(float(val)/total*10)
                    stat_bar = '*' * prcnt + ' ' * (10 - prcnt)
                    stdscr.addstr(line, 0, "{:>13}: {:>11} |{}|".format(ipv4_protocol_map[k.value], val, stat_bar))
                    line += 1
                # TCP
                if k.value == IPPROTO_TCP:
                    if val:
                        subtotal = val
                        stdscr.addstr(line, 0, "{:>13}  {:>11}               S-Port".format("", "", ""))
                        line += 1
                        for k in tcportcnt.keys():
                            val = tcportcnt.sum(k).value
                            if val:
                                prcnt = 0 if subtotal == 0 else 1 if (float(val)/subtotal*10) < 1 else 10 if val > subtotal else int(float(val)/subtotal*10)
                                stat_bar = '*' * prcnt + ' ' * (10 - prcnt)
                                stdscr.addstr(line, 0, "{:>13}  {:>11} |{}|  {}".format("", val, stat_bar, k.value))
                                line += 1
                # UDP
                if k.value == IPPROTO_UDP:
                    if val:
                        subtotal = val
                        stdscr.addstr(line, 0, "{:>13}  {:>11}               D-Port".format("", "", ""))
                        line += 1
                        for k in udportcnt.keys():
                            val = udportcnt.sum(k).value
                            if val:
                                prcnt = 0 if subtotal == 0 else 1 if (float(val)/subtotal*10) < 1 else 10 if val > subtotal else int(float(val)/subtotal*10)
                                stat_bar = '*' * prcnt + ' ' * (10 - prcnt)
                                stdscr.addstr(line, 0, "{:>13}  {:>11} |{}|  {}".format("", val, stat_bar, k.value))
                                line += 1
                # ICMP
                if k.value == IPPROTO_ICMP:
                    if val:
                        subtotal = val
                        stdscr.addstr(line, 0, "{:>13}  {:>11}               Type".format("", "", ""))
                        line += 1
                        for k in icmpcnt.keys():
                            val = icmpcnt.sum(k).value
                            if val:
                                prcnt = 0 if subtotal == 0 else 1 if (float(val)/subtotal*10) < 1 else 10 if val > subtotal else int(float(val)/subtotal*10)
                                stat_bar = '*' * prcnt + ' ' * (10 - prcnt)
                                stdscr.addstr(line, 0, "{:>13}  {:>11} |{}|  {}".format("", val, stat_bar, icmp_type_map[k.value]))
                                line += 1

            stdscr.addstr(line, 0, "CTRL+C to exit")
            stdscr.refresh()
            time.sleep(0.5)
            total = 0
            spin += 1
        except KeyboardInterrupt:
            break;

finally:
       curses.echo()
       curses.nocbreak()
       curses.endwin()

b.remove_xdp(device, flags)
