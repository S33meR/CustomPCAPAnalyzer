import ruamel.yaml.scalarstring
from scapy.all import rdpcap
import ruamel.yaml as yaml
from collections import *
import os
import argparse

class IPv4Stream:
    ip_dst = []
    ip_src = []
    port_dst = []
    port_src = []
    frames = []
    def __init__(self, p_ip_dst, p_ip_src, p_port_dst, p_port_src, p_frameNumber):
        self.ip_dst = p_ip_dst
        self.ip_src = p_ip_src
        self.port_dst = p_port_dst
        self.port_src = p_port_src
        self.frames = []
        self.frames.append(p_frameNumber + 1)


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
        frameType = 'Ethernet 2'

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

def get_transport_protocol(p_frame):
    head_len = (getDataFromFrame(p_frame, 14, 14, True) - int(
        getDataFromFrame(p_frame, 14, 14, True) / 16) * 16) * 4
    return p_frame[14 + head_len:len(p_frame)]

def getDataFromFrame(packet, pStart, pEnd, pInteger = False):
    if pInteger:
        return int.from_bytes(packet[pStart:(pEnd + 1)], byteorder='big')
    else:
        return packet[pStart:(pEnd + 1)]

def IPinStream(p_streams, p_ipDestination, p_ipSource, p_portSource = 0, p_portDestination = 0):

    for i in range (0, len(p_streams)):
        if ((p_streams[i].ip_src == p_ipDestination) and (p_streams[i].ip_dst == p_ipSource) and (p_streams[i].port_dst == p_portSource) and (p_streams[i].port_src == p_portDestination))  or ((p_streams[i].ip_src == p_ipSource) and
        (p_streams[i].ip_dst == p_ipDestination) and (p_streams[i].port_dst == p_portDestination) and (p_streams[i].port_src == p_portSource)):
            return i
    return -1

def insertToStream(p_arrayStreams, p_frameNumber, p_ipSource, p_ipDestination, p_portSource = 0, p_portDestination = 0):

    curStr = IPinStream(p_arrayStreams, p_ipSource, p_ipDestination, p_portSource, p_portDestination)
    if curStr >= 0:
        p_arrayStreams[curStr].frames.append(p_frameNumber + 1)
    elif curStr == -1:
        p_arrayStreams.append(IPv4Stream(p_ipSource, p_ipDestination, p_portSource, p_portDestination, p_frameNumber))

def main ():

    pcapFile = '/Users/michalhlinka/PycharmProjects/pythonProject1/vzorky_pcap_na_analyzu/trace-27.pcap' #treba cestu
    packets = rdpcap(pcapFile)
    filterpacket = rdpcap(pcapFile)
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

    # --------TCP section------------
    tcpStreams = []
    for frameNumber in range(0, len(packets)):
        frame = bytes(packets[frameNumber])
        if (getDataFromFrame(frame,12, 13, True) == 2048):

            if (calculateIPv4protocol(frame) == 'TCP'):
                tcp = get_transport_protocol(frame)
                if (getDataFromFrame(tcp, 0, 1, True) in appMap):
                    #print(1)
                    if appMap.get(getDataFromFrame(tcp, 0, 1, True), 'Unknown') != protocolFilter:
                        continue
                else:
                    if (getDataFromFrame(tcp, 2, 3, True) in appMap):
                        if appMap.get(getDataFromFrame(tcp, 2, 3, True), 'Unknown') != protocolFilter:
                            continue
                    else:
                        continue
                insertToStream(tcpStreams, frameNumber, getDataFromFrame(frame, 26, 29), getDataFromFrame(frame, 30, 33), getDataFromFrame(tcp, 0, 1), getDataFromFrame(tcp, 2, 3))

    buffer = 0
    halfbuffer = 0
    # zisti ci je komunikacia kompletna
    for i in tcpStreams:
        start = 0
        end = 0
        if (getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[0] - 1])), 13, 13, True) == 0x2) and (getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[1] - 1])), 13, 13, True) == 0x12) and getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[2] - 1])), 13, 13, True) == 0x10:
            start = 1
        end0 = getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[len(i.frames) - 1] - 1])), 13, 13, True)
        end1 = getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[len(i.frames) - 2] - 1])), 13, 13, True)

        if len(i.frames) - 3 < 0 :
            end2 = -1
        else:
            end2 = getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[len(i.frames) - 3] - 1])), 13, 13, True)
        if len(i.frames) - 4 < 0 :
            end3 = -1
        else:
            end3 = getDataFromFrame(get_transport_protocol(bytes(packets[i.frames[len(i.frames) - 4] - 1])), 13, 13, True)

        #rst
        if (end0 == 0x14)  or (end0 == 0x1):
            end = 1
        else:
            # 3 way handshake
            if (end0 == 0x10) and ((end1 == 0x11) or (end == 0x19)) \
                and ((end2 == 0x11) or (end2 == 0x19)):
                end = 1
            else:
                if (end0 == 0x10) and ((end1 == 0x11) or (end1 == 0x19)) \
                    and (end2 == 0x10) and ((end3 == 0x11) or (end3 == 0x19)):
                    end = 1






















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
        if (calculateFrameType(packet) == 'Ethernet 2'):
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

        '''hex_str = ''.join([f'{byte:02X}' for byte in packetBytes])
        hex_array = hex_split(hex_str)
        formatted_hex_dump = hex_dump_str(hex_array)'''

        frame['hexa_frame'] = hexRows
        printer['packets'].append(frame)
        # print out the packets
        packetCounter += 1

    if protocolFilter:
        # skontrolujeme ci je zadany protokol platny
        if protocolFilter in appMap.values():
            filtratedPackets = [packet for packet in packets if appMap.get(calculateAppProtocol(packet)) == protocolFilter]
            filtratedCount = len(filtratedPackets)

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
                    if (calculateFrameType(packet) == 'Ethernet 2'):
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
