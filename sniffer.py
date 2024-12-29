#! /usr/bin/env python3

import socket
import struct
import ipaddress
import sys
import argparse


parser = argparse.ArgumentParser(description="Sniff Packets Using Sockets")
parser.add_argument("-i", help="Interface to listen to. By default listens to all interfaces.",
                    default="0.0.0.0")

class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack("<BBHHHBBH4s4s", self.packet[0:20])
        self.ver = header[0] >> 4
        self.iph = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.proto = header[6]
        self.hdr_chsm = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        self.proto_map = {
            0: "HOPOPT",
            1: "ICMP",
            2: "IGMP",
            3: "GGP",
            4: "IP-in-IP",
            5: "ST",
            6: "TCP",
            7: "CBT",
            8: "EGP",
            9: "IGP",
            10: "BBN-RCC-MON",
            11: "NVP-II",
            12: "PUP",
            13: "ARGUS",
            14: "EMCON",
            15: "XNET",
            16: "CHAOS",
            17: "UDP",
            18: "MUX",
            19: "DCN-MEAS",
            20: "HMP",
            21: "PRM",
            22: "XNS-IDP",
            23: "TRUNK-1",
            24: "TRUNK-2",
            25: "LEAF-1",
            26: "LEAF-2",
            27: "RDP",
            28: "IRTP",
            29: "ISO-TP4",
            30: "NETBLT",
            31: "MFE-NSP",
            32: "MERIT-INP",
            33: "DCCP",
            34: "3PC",
            35: "IDPR",
            36: "XTP",
            37: "DDP",
            38: "IDPR-CMTP",
            39: "TP++",
            40: "IL",
            41: "IPv6",
            42: "SDRP",
            43: "IPv6-Route",
            44: "IPv6-Frag",
            45: "IDRP",
            46: "RSVP",
            47: "GRE",
            48: "DSR",
            49: "BNA",
            50: "ESP",
            51: "AH",
            52: "I-NLSP",
            53: "SwIPe",
            54: "NARP",
            55: "MOBILE",
            56: "TLSP",
            57: "SKIP",
            58: "IPv6-ICMP",
            59: "IPv6-NoNxt",
            60: "IPv6-Opts",
            61: "Host Internal Protocol(Any)",
            62: "CFTP",
            63: "Any Local Network",
            64: "SAT-EXPAK",
            65: "KRYPTOLAN",
            66: "RVD",
            67: "IPPC",
            68: "Any distributed file system",
            69: "SAT-MON",
            70: "VISA",
            71: "IPCU",
            72: "CPNX",
            73: "CPHB",
            74: "WSN",
            75: "PVP",
            76: "BR-SAT-MON",
            77: "SUN-ND",
            78: "WB-MON",
            79: "WB-EXPAK",
            80: "ISO-IP",
            81: "VMTP",
            82: "SECURE-VMTP",
            83: "VINES",
            84: "TTP",
            84: "IPTM",
            85: "NSFNET-IGP",
            86: "DGP",
            87: "TCF",
            88: "EIGRP",
            89: "OSPF",
            90: "Sprite-RPC",
            91: "LARP",
            92: "MTP",
            93: "AX.25",
            94: "OS",
            95: "MICP",
            96: "SCC-SP",
            97: "ETHERIP",
            98: "ENCAP",
            99: "Any Private Encryption Scheme",
            100: "GMTP",
            101: "IFMP",
            102: "PNNI",
            103: "PIM",
            104: "ARIS",
            105: "SCPS",
            106: "QNX",
            107: "A/N",
            108: "IPComp",
            109: "SNP",
            110: "Compaq-Peer",
            111: "IPX-in-IP",
            112: "VRRP",
            113: "PGM",
            114: "Any 0-hop protocol",
            115: "L2TP",
            116: "DDX",
            117: "IATP",
            118: "STP",
            119: "SRP",
            120: "UTI",
            121: "SMP",
            122: "SM",
            123: "PTP",
            124: "IS-IS over IPv4",
            125: "FIRE",
            126: "CRTP",
            127: "CRUDP",
            128: "SSCOPMCE",
            129: "IPLT",
            130: "SPS",
            131: "PIPE",
            132: "SCTP",
            133: "FC",
            134: "RSVP-E2E-IGNORE",
            135: "Mobility Header",
            136: "UDPLite",
            137: "MPLS-in-IP",
            138: "manet",
            139: "HIP",
            140: "Shim6",
            141: "WESP",
            142: "ROHC",
            143: "Ethernet",
            144: "AGGFRAG",
            145: "NSH"
        }

        try:
            self.protocol = self.proto_map[self.proto]
        except Exception as e:
            print(f"{e} no protocol for {self.proto}")
            self.protocol = str(self.proto)

    def print_header_short(self):
        print(f"Protocol: {self.protocol} {self.src_addr} -> {self.dst_addr}")


def sniff(interface: str):
    # sniff_proto = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sniffer.bind(("wlan0", 0))

    while True:
        try:
            raw_data = sniffer.recv(65535)
            packet = Packet(raw_data)
            packet.print_header_short()
        except KeyboardInterrupt:
            sys.exit(1)


if __name__ == "__main__":
    args = parser.parse_args()
    iface = args.i
    sniff(iface)
