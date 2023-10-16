import ruamel.yaml.scalarstring
import scapy.all as scapy
import ruamel.yaml as yaml
from collections import *
import os
import argparse
import configparser


class Frame:
    index = None
    hex_value = None
    hex_value_formated = None

    eth_type = None
    dest_mac = None
    src_mac = None
    length_api = None
    length_med = None
    sap = None
    app_protocol = None

    src_ip = None
    dest_ip = None
    nested_ip = None
    size_ip = None

    src_port = None
    dest_port = None
    nested_port = None

    urg_flag = None
    ack_flag = None
    push_flag = None
    reset_flag = None
    syn_flag = None
    fin_flag = None

    icmp_type = None

    arp_opcode = None
    arp_src_ip = None
    arp_dest_ip = None


def getMin(x,y):
    if x < y:
        return x
    else:
        return y
def calculateDestinationMAC(packet):
    packetBytes = bytes(packet)
    destinationMAC = packetBytes[0:6]
    return ':'.join(f'{byte:02X}' for byte in destinationMAC)
def calculateSourceMAC(packet):
    packetBytes = bytes(packet)
    sourceMAC = packetBytes[6:12]
    return ':'.join(f'{byte:02X}' for byte in sourceMAC)
    

def calculateFrameLength(packet):
    packetBytes = bytes(packet)
    frameLength = len(packetBytes)
    return frameLength
def calculateFrameLengthMedium(packet):
    packetBytes = bytes(packet)
    frameLength = len(packetBytes)
    if frameLength < 60:
        return 64
    else:
        return frameLength + 4


def calculateServiceAccessPoint(packet, isSource):
    sapType = 'source' if isSource else 'destination'
    sapByteNumber = 15 if isSource else 14


    packetBytes = bytes(packet)
    sapByte = packetBytes[sapByteNumber]

    return sapMap.get(sapByte, f'Unknown {sapType} SAP')


def calculateFrameType(packet):
    packetBytes = bytes(packet)
    frameBytes = packetBytes[12:14]
    fourthID =  packetBytes[14:16]
    frameTypeNumber = (frameBytes[0] << 8) + frameBytes[1] ## << 8 posuniem o 8 bitov do lava aby som mohol spravit 16bit cislo
    frameType = 'Unknown'
    if frameTypeNumber > 1500:
        frameType = 'Ethernet II'

    elif frameTypeNumber < 1500:

        if fourthID == b'\xff\xff':
            frameType = 'IEEE 802.3 RAW'
        if fourthID == b'\xaa\xaa':
            frameType = 'IEEE 802.3 LLC & SNAP'

        else:
            frameType = 'IEEE 802.3 LLC'

    return frameType


def calculateEtherType(packet, frameType):
    packetBytes = bytes(packet)
    frameBytes = packetBytes[12:14]


    etherTypeNumber = (frameBytes[0] << 8) + frameBytes[1]
    etherType = etherTypeMap.get(etherTypeNumber, 'Unknown')
    return etherType

def calculateProtocolID(packet):
    packetBytes = bytes(packet)
    frameBytes = packetBytes[20:22]
    pidNumber = int.from_bytes(frameBytes, byteorder='big') ### https://stackoverflow.com/questions/21017698/converting-int-to-bytes-in-python-3
    pid = etherTypeMap.get(pidNumber, 'Unknown')
    return pid

def calculateIPv4protocol(packet):
    packetBytes = bytes(packet)
    frameBytes = packetBytes[23:24]
    protocolInteger = int.from_bytes(frameBytes, byteorder='big')
    protocol = ipv4Map.get(protocolInteger, 'Unknown')
    return protocol

def calculateIPv4source(packet):
    packetBytes = bytes(packet)
    frameBytes = packetBytes[26:30]
    source = '.'.join(f'{byte}' for byte in frameBytes)
    return source
def calculateIPv4destination(packet):
    packetBytes = bytes(packet)
    frameBytes = packetBytes[30:34]
    destination = '.'.join(f'{byte}' for byte in frameBytes)
    return destination
def readdectxt(filename):
    decimalMap = {}
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                buffer = line.split(': ')
                if len(buffer) == 2:
                    number, name = int(buffer[0]), buffer[1]
                    decimalMap[number] = name
    return decimalMap
def readtxt(filename):
    etherTypeMap = {}
    with open(filename, 'r') as file:
        for line in file:
            line = line.strip() #odstrani \n
            if line:
                buffer = line.split(': ')
                if len(buffer) == 2:
                    number, name = int(buffer[0], 16), buffer[1]
                    etherTypeMap[number] = name
    return etherTypeMap

def calculateIPsourceport(packet):
    packetBytes = bytes(packet)
    ipHeader = (packetBytes[14] & 0x0F) * 4  # hlavicka moze byt dlha 5-15 (20B-60B) slov, kazde slovo ma 4B
    frameBytes = packetBytes[ipHeader +14:ipHeader + 16]
    sourceport = int.from_bytes(frameBytes, byteorder='big')
    return sourceport

def calculateIPdestinationport(packet):
    packetBytes = bytes(packet)
    ipHeader = (packetBytes[14] & 0x0F) * 4  # hlavicka moze byt dlha 5-15 (20B-60B) slov, kazde slovo ma 4B
    frameBytes = packetBytes[ipHeader + 16:ipHeader + 18]
    destinationport = int.from_bytes(frameBytes, byteorder='big')
    return destinationport

def calculateAppProtocol(packet):

    if (appMap.get(calculateIPsourceport(packet), 'Unknown') != 'Unknown' and appMap.get(calculateIPdestinationport(packet), 'Unknown') != 'Unknown'):
        appProtocol = getMin(calculateIPsourceport(packet), calculateIPdestinationport(packet))
    elif appMap.get(calculateIPsourceport(packet), 'Unknown') != 'Unknown' and appMap.get(
            calculateIPdestinationport(packet), 'Unknown') == 'Unknown':
        appProtocol = calculateIPsourceport(packet)
    elif appMap.get(calculateIPsourceport(packet), 'Unknown') == 'Unknown' and appMap.get(
            calculateIPdestinationport(packet), 'Unknown') != 'Unknown':
        appProtocol = calculateIPdestinationport(packet)
    else:
        appProtocol = 0

    return appProtocol


'''def loading(f,packet):
    f.len_frame_pcap = calculateFrameLength(packet)
    f.len_frame_medium = calculateFrameLengthMedium(packet)
    f.src_mac = calculateSourceMAC(packet)
    f.dest_mac = calculateDestinationMAC(packet)
    if (calculateFrameType(packet) == 'Ethernet 2'):
        f.eth_type = calculateEtherType(packet, calculateFrameType(packet))
        f.src_ip = calculateIPv4source(packet)
        f.dest_ip = calculateIPv4destination(packet)
        if (calculateEtherType(packet, calculateFrameType(packet)) == 'IPv4'):
            f.size_ip = calculateipHeaderSize(f.hex_value[28::])
            f.nested_port = calculateIPv4protocol(packet)
            if (calculateIPv4protocol(packet) in 'TCP' or 'UDP'):
                f.src_port = calculateIPsourceport(packet)
                f.dst_port = calculateIPdestinationport(packet)
                appProtocol = calculateAppProtocol(packet)
                print(f.src_port)
                f.app_protocol = appMap.get(appProtocol, 'Unknown')
                #if (calculateIPv4protocol(packet == 'TCP')):
                    #tcpAnalysis(f)'''
def get_length_medium(len_api):
    if len_api < 60:
        len_med = 64
    else:
        len_med = len_api + 4
    return len_med
def start(f,packet):
    f.length_api = calculateFrameLength(packet)
    f.length_med = calculateFrameLengthMedium(packet)
    f.app_protocol = appMap.get(calculateAppProtocol(packet))

    f.eth_type = calculateFrameType(packet)
    f.dest_mac,f.src_mac = get_mac(f.hex_value)

    nested_protocols(f)

def get_mac(hex_v):
    dest = hex_v[0:12]
    src = hex_v[12:24]
    return dest, src

def read_cfg():
    cfg = configparser.ConfigParser()
    cfg.read('config.cfg')
    return cfg


def ip(ip_hex):
    size = int(ip_hex[1], 16) * 4
    try:
        nested_ip = config.get('IpProtocols', str(int(ip_hex[18: 20], 16)))
    except configparser.NoOptionError:
        nested_ip = None
    src_ip = str(int(ip_hex[24: 26], 16)) + "." + str(int(ip_hex[26: 28], 16)) + "." + str(
        int(ip_hex[28: 30], 16)) + "." + str(int(ip_hex[30: 32], 16))
    ips.append(src_ip)
    dest_ip = str(int(ip_hex[32: 34], 16)) + "." + str(int(ip_hex[34: 36], 16)) + "." + str(
        int(ip_hex[36: 38], 16)) + "." + str(int(ip_hex[38: 40], 16))

    return src_ip, dest_ip, nested_ip, size
def nested_mac(nested_protocol_dec, section):
    try:
        nested = config.get(section, str(nested_protocol_dec))
    except configparser.NoOptionError:
        nested = None
    return nested
def nested_protocols(f):
    if f.eth_type == "Ethernet II":
        f.nested_mac = nested_mac(int(f.hex_value[24:28], 16), 'EtherTypes')
        if int(f.hex_value[24:28], 16) == 2048:
            f.src_ip, f.dest_ip, f.nested_ip, f.size_ip = ip(f.hex_value[28::])
            if f.nested_ip is not None:
                nested_internet(f)

    elif "802.3 LLC" == f.eth_type:
        f.nested_mac = nested_mac(int(f.hex_value[28:30], 16), 'SAPs')

    elif "802.3 - raw" == f.eth_type:
        f.nested_mac = "IPX"

    elif "802.3 LLC + SNAP" == f.eth_type:
        f.nested_mac = nested_mac(int(f.hex_value[40:44], 16), 'EtherTypes')


def nested_internet(f):
    try:
        if f.nested_ip == "TCP":
            f.src_port = int(f.hex_value[(28 + (f.size_ip * 2)): (32 + (f.size_ip * 2))], 16)
            f.dest_port = int(f.hex_value[(32 + (f.size_ip * 2)): (36 + (f.size_ip * 2))], 16)
            tcp_analyze(f)
            f.nested_port = config.get('TCP_ports', str(f.dest_port))
        elif f.nested_ip == "UDP":
            f.src_port = int(f.hex_value[(28 + (f.size_ip * 2)): (32 + (f.size_ip * 2))], 16)
            f.dest_port = int(f.hex_value[(32 + (f.size_ip * 2)): (36 + (f.size_ip * 2))], 16)
            f.nested_port = config.get('UDP_ports', str(f.dest_port))
        #elif f.nested_ip == "ICMP":
            #icmp_analyze(f)
    except configparser.NoOptionError:
        f.nested_port = None


def tcp_analyze(f):
    flags = str(bin(int(f.hex_value[(53 + (f.size_ip * 2)): (56 + (f.size_ip * 2))], 16)))[2::]
    flags = flags[::-1]
    while len(flags) < 6:
        flags += "0"
    flags = flags[::-1]

    if flags[0] == "1":
        f.urg_flag = True
    if flags[1] == "1":
        f.ack_flag = True
    if flags[2] == "1":
        f.push_flag = True
    if flags[3] == "1":
        f.reset_flag = True
    if flags[4] == "1":
        f.syn_flag = True
        if f.ack_flag is None:
            syns.append(f.index)
    if flags[5] == "1":
        f.fin_flag = True
def get_tcp_comms(frms, port):
    syn, sync_ack, ack, datas, socket, out = None, None, None, [], [], []
    for x in syns:
        if frms[x].dest_port == port or frms[x].src_port == port:
            print(1)
            syn = frms[x]

            for u in range(x, len(frms)):
                if (syn.src_ip == frms[u].dest_ip) and (syn.dest_ip == frms[u].src_ip) and (
                        syn.src_port == frms[u].dest_port) and (syn.dest_port == frms[u].src_port):
                    if (frms[u].syn_flag == True) and (frms[u].ack_flag == True):
                        sync_ack = frms[u]

                        break
            for u in range(sync_ack.index + 1, len(frms)):
                if (syn.src_ip == frms[u].src_ip) and (syn.dest_ip == frms[u].dest_ip) and (
                        syn.src_port == frms[u].src_port) and (syn.dest_port == frms[u].dest_port):
                    if frms[u].ack_flag:
                        ack = frms[u]

                        break
            if (syn is not None) and (sync_ack is not None) and (ack is not None):
                socket.append(syn.src_ip)
                socket.append(syn.src_port)
                socket.append(syn.dest_ip)
                socket.append(syn.dest_port)
                for u in range(ack.index + 1, len(frms)):
                    if (frms[u].src_ip in socket) and (frms[u].src_port in socket) and (frms[u].dest_ip in socket) and (
                            frms[u].dest_port in socket):
                        datas.append(frms[u])
                datas = [syn, sync_ack, ack] + datas
                out.append(datas)
                datas = []
                socket = []

    finished, unfinished = None, None
    for m in range(len(out)):
        k = 0
        for n in range(len(out[m])):
            frm = out[m][n]
            if frm.reset_flag == True:
                if finished == None:
                    finished = m
                k = 1
                break
            elif frm.fin_flag == True:
                try:
                    frm2 = out[m][n + 1]
                except IndexError:
                    break
                if frm2.fin_flag == True:
                    try:
                        frm3 = out[m][n + 2]
                    except IndexError:
                        break
                    if frm3.ack_flag == True:  # FIN FIN ACK
                        if finished == None:
                            finished = m
                        k = 1
                        break
                    elif frm3.reset_flag == True:  # FIN FIN RST
                        if finished == None:
                            finished = m
                        k = 1
                        break
                    else:
                        if unfinished == None:
                            unfinished = m
                elif frm2.ack_flag == True:
                    try:
                        frm3 = out[m][n + 2]
                    except IndexError:
                        break
                    if frm3.fin_flag == True:
                        try:
                            frm4 = out[m][n + 3]
                        except IndexError:
                            break
                        if frm4.ack_flag == True:  # FIN ACK FIN ACK
                            if finished == None:
                                finished = m
                            k = 1
                            break
                        elif frm4.reset_flag == True:  # FIN ACK FIN RST
                            if finished == None:
                                finished = m
                            k = 1
                            break
                        else:
                            if unfinished == None:
                                unfinished = m
                    elif frm3.reset_flag == True:  # FIN ACK RST
                        if finished == None:
                            finished = m
                        k = 1
                        break
                    else:
                        if unfinished == None:
                            unfinished = m
                elif frm2.reset_flag == True:  # FIN RST
                    if finished == None:
                        finished = m
                    k = 1
                    break
            if n + 1 == len(out[m]) and k == 0 and unfinished == None:
                unfinished = m
        if unfinished != None and finished != None:
            break
    return out, unfinished, finished


def format_mac(macAdress):
    return ":".join(macAdress[i:i + 2] for i in range(0, len(macAdress), 2))

def print_tcp(datas, unfin, fin,output_file):
    output = []

    if unfin is not None:
        unfinished_data = []

        for frm in datas[unfin]:
            frame_data = {
                "frame_number": frm.index + 1,
                "len_frame_pcap": frm.length_api,
                "len_frame_medium": frm.length_med,
                "frame_type": frm.eth_type,
                "src_mac": frm.src_mac,
                "dst_mac": frm.dest_mac,
                "app_protocol": frm.app_protocol,
                "ether_type": frm.eth_type,
                "source_ip": frm.src_ip,
                "destination_ip": frm.dest_ip,
                "hexa_frame": frm.hex_value_formated
            }

            flags = []
            if frm.ack_flag:
                flags.append("ACK")
            if frm.push_flag:
                flags.append("PUSH")
            if frm.reset_flag:
                flags.append("RESET")
            if frm.syn_flag:
                flags.append("SYN")
            if frm.fin_flag:
                flags.append("FIN")

            frame_data["flags"] = flags
            unfinished_data.append(frame_data)

        output.append({"Unfinished": unfinished_data})
    if fin is not None:

        finished_data = []

        for frm in datas[fin]:
            frame_data = {
                "frame_number": frm.index + 1,
                "len_frame_pcap": frm.length_api,
                "len_frame_medium": frm.length_med,
                "frame_type": frm.eth_type,
                "src_mac": format_mac(frm.src_mac),
                "dst_mac": format_mac(frm.dest_mac),
                "app_protocol": frm.app_protocol,
                "ether_type": frm.eth_type,
                "source_ip": frm.src_ip,
                "destination_ip": frm.dest_ip,
                "hexa_frame": frm.hex_value_formated
            }

            flags = []
            if frm.ack_flag:
                flags.append("ACK")
            if frm.push_flag:
                flags.append("PUSH")
            if frm.reset_flag:
                flags.append("RESET")
            if frm.syn_flag:
                flags.append("SYN")
            if frm.fin_flag:
                flags.append("FIN")

            frame_data["flags"] = flags
            finished_data.append(frame_data)

        output.append({"Finished": finished_data})

    with open(output_file, 'w') as file:
        yaml.dump(output, file, default_flow_style=False)

def main ():

    pcapFile = '/Users/michalhlinka/PycharmProjects/pythonProject1/vzorky_pcap_na_analyzu/trace-27.pcap' #treba cestu
    packets = scapy.rdpcap(pcapFile)
    filterpacket = scapy.rdpcap(pcapFile)
    frames = []
    global syns,config,ips
    syns,ips = [],[]
    config = read_cfg()

    x = 0
    for pkt in filterpacket:
        frame = Frame()
        frame.hex_value = scapy.raw(pkt).hex()
        frame.index = x
        x += 1
        start(frame,pkt)
        formatted_hex = ' '.join([frame.hex_value[i:i + 2] for i in range(0, len(frame.hex_value), 2)])
        formatted_hex = '\n'.join([formatted_hex[i:i + 48] for i in range(0, len(formatted_hex), 48)])
        frame.hex_value_formated = ruamel.yaml.scalarstring.PreservedScalarString(formatted_hex)
        frames.append(frame)

    packetCount = len(packets)
    packetCounter = 1
    filterCounter = 1
    file = os.path.basename (pcapFile)
    senders = defaultdict(int)
    info = {
        'name': 'PKS2023/24',
        'pcap_name': file
    }
    printer = {
        'packets': []

    }

    # ---------filter section------------
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--protocol", help="Filter by protocol")
    args = parser.parse_args()
    filterNumbers = []

    protocolFilter = args.protocol


    # ---------frame section------------
    for packet in packets:
        packetBytes = bytes(packet)

        frame = OrderedDict()  # na udrzanie poradia
        frame['frame_number'] = packetCounter
        if protocolFilter:
            if appMap.get(calculateAppProtocol(packet)) == protocolFilter:
                filterNumbers.append(packetCounter)
        frame['len_frame_pcap'] = calculateFrameLength(packet)
        frame['len_frame_medium'] = calculateFrameLengthMedium(packet)
        frame['frame_type'] = calculateFrameType(packet)
        frame['src_mac'] = calculateSourceMAC(packet)
        frame['dst_mac'] = calculateDestinationMAC(packet)
        if (calculateFrameType(packet) == 'Ethernet II'):
            frame['ether_type'] = calculateEtherType(packet, calculateFrameType(packet))
            frame['source_ip'] = calculateIPv4source(packet)
            frame['destination_ip'] = calculateIPv4destination(packet)
            if (calculateEtherType(packet, calculateFrameType(packet)) == 'IPv4'):
                frame['protocol'] = calculateIPv4protocol(packet)
                senders[frame['source_ip']] += 1  # pridanie do slovnika, vyuzitie defaultdict
                if (calculateIPv4protocol(packet) in 'TCP' or 'UDP'):
                    frame['src_port'] = calculateIPsourceport(packet)
                    frame['dst_port'] = calculateIPdestinationport(packet)
                    appProtocol = calculateAppProtocol(packet)
                    frame['app_protocol'] = appMap.get(appProtocol, 'Unknown')

        if (calculateFrameType(packet) == 'IEEE 802.3 LLC & SNAP' or calculateFrameType(packet) == 'IEEE 802.3 LLC'):
            frame['dsap'] = calculateServiceAccessPoint(packet, False)
            frame['ssap'] = calculateServiceAccessPoint(packet, True)
        if calculateFrameType(packet) == 'IEEE 802.3 LLC & SNAP':
            frame['pid'] = calculateProtocolID(packet)

        # ---------hexa section------------


        hexaGulas = ' '.join([f'{byte:02X}' for byte in packetBytes])  # https://stackoverflow.com/questions/49597486/convert-bytes-to-hexadecimal-in-python
        hexRows = ''.join([hexaGulas[i:i+48] for i in range(0, len(hexaGulas), 48)])

        frame['hexa_frame'] = ruamel.yaml.scalarstring.PreservedScalarString(hexRows)

        frame['hexa_frame'] = hexRows
        printer['packets'].append(frame)
        # print out the packets
        packetCounter += 1

    if protocolFilter:
        data, finished, unfinished = get_tcp_comms(frames, 443)
        print_tcp(data, unfinished, finished, 'tcp.yaml')


        print(protocolFilter)
        print(appMap.get(calculateAppProtocol(packet)))



        # skontrolujeme ci je zadany protol platny
        if protocolFilter in appMap.values():
            filtratedPackets = [packet for packet in packets if appMap.get(calculateAppProtocol(packet)) == protocolFilter]
            filtratedCount = len(filtratedPackets)
            print(filtratedCount)

            if filtratedCount > 0:
                filtratedOutput = {
                    'filtrated_packets': []
                }
                for packet in filtratedPackets:
                    packetBytes = bytes(packet)
                    frame = OrderedDict()  # na udrzanie poradia
                    frame['frame_number'] = filterNumbers[filterCounter - 1]
                    frame['len_frame_pcap'] = calculateFrameLength(packet)
                    frame['len_frame_medium'] = calculateFrameLengthMedium(packet)
                    frame['frame_type'] = calculateFrameType(packet)
                    frame['src_mac'] = calculateSourceMAC(packet)
                    frame['dst_mac'] = calculateDestinationMAC(packet)
                    if (calculateFrameType(packet) == 'Ethernet II'):
                        frame['ether_type'] = calculateEtherType(packet, calculateFrameType(packet))
                        frame['source_ip'] = calculateIPv4source(packet)
                        frame['destination_ip'] = calculateIPv4destination(packet)
                        if (calculateEtherType(packet, calculateFrameType(packet)) == 'IPv4'):
                            frame['protocol'] = calculateIPv4protocol(packet)
                            if (calculateIPv4protocol(packet) in 'TCP' or 'UDP'):
                                frame['src_port'] = calculateIPsourceport(packet)
                                frame['dst_port'] = calculateIPdestinationport(packet)
                                appProtocol = calculateAppProtocol(packet)
                                frame['app_protocol'] = appMap.get(appProtocol, 'Unknown')


                    if (calculateFrameType(packet) == 'IEEE 802.3 LLC & SNAP' or calculateFrameType(packet) == 'IEEE 802.3 LLC'):
                        frame['dsap'] = calculateServiceAccessPoint(packet, False)
                        frame['ssap'] = calculateServiceAccessPoint(packet, True)
                    if calculateFrameType(packet) == 'IEEE 802.3 LLC & SNAP':
                        frame['pid'] = calculateProtocolID(packet)


                    hexaGulas = ' '.join([f'{byte:02X}' for byte in packetBytes])  # https://stackoverflow.com/questions/49597486/convert-bytes-to-hexadecimal-in-python
                    hexRows = ''.join([hexaGulas[i:i + 48] for i in range(0, len(hexaGulas), 48)])

                    frame['hexa_frame'] = ruamel.yaml.scalarstring.PreservedScalarString(hexRows)
                    frame['hexa_frame'] = hexRows

                    filterCounter += 1
                    filtratedOutput['filtrated_packets'].append(frame)
                with open('filter.yaml', 'w') as yaml_file:
                    yaml.dump(filtratedOutput, yaml_file, default_flow_style=False, Dumper=yaml.Dumper)
            else:
                print('No packets with specified protocol')
        else:
            print('Invalid protocol')





    # ---------senders section------------
    ipv4senders = []
    for sender, packetNumber in senders.items():
        ipv4senders.append({'ip': sender, 'packet_count': packetNumber})

    topsenders = []
    topsendersNumber = max(senders.values())
    for sender, packetNumber in senders.items():
        if packetNumber == topsendersNumber:
            topsenders.append({'ip': sender, 'packet_count': packetNumber})
    senderPrint = {
        'ipv4_senders': ipv4senders,
        'top_ipv4_senders': topsenders
    }
    # ---------yaml section------------

    with open ('output.yaml', 'w') as yaml_file:
        yaml.dump(info, yaml_file, default_flow_style=False, Dumper = yaml.Dumper)
        yaml.dump(printer, yaml_file, default_flow_style=False, Dumper = yaml.Dumper)
        yaml.dump(senderPrint, yaml_file, default_flow_style=False, Dumper = yaml.Dumper)


    yaml_file.close()


ethertxt = '/Users/michalhlinka/PycharmProjects/pythonProject1/EtherType'
etherTypeMap = readtxt(ethertxt)
saptxt = '/Users/michalhlinka/PycharmProjects/pythonProject1/saptxt'
sapMap = readtxt(saptxt)
ipv4txt = '/Users/michalhlinka/PycharmProjects/pythonProject1/ipv4txt'
ipv4Map = readtxt(ipv4txt)
apptxt = '/Users/michalhlinka/PycharmProjects/pythonProject1/appprotocol'
appMap = readdectxt(apptxt)
main()

#tato cast krasne vypise hexa_frame, v yaml to nefunguje
'''hexaGulas = ' '.join([f'{byte:02X}' for byte in packetBytes]) # https://stackoverflow.com/questions/49597486/convert-bytes-to-hexadecimal-in-python
        hexRows = [hexaGulas[i:i+48] for i in range(0, len(hexaGulas), 48)]
        for line in hexRows:
            print(line)
        print()'''
