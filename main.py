import ruamel.yaml.scalarstring
from scapy.all import rdpcap
import ruamel.yaml as yaml
from collections import *
import os
import argparse

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


def main ():

    pcapFile = '/Users/michalhlinka/PycharmProjects/pythonProject1/vzorky_pcap_na_analyzu/trace-26.pcap' #treba cestu
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

    protocolFilter = args.protocol

    if protocolFilter:
        # skontrolujeme ci je zadany protokol platny
        if protocolFilter in ipv4Map.values():
            filtratedPackets = [packet for packet in packets if calculateIPv4protocol(packet) == protocolFilter]
            filtratedCount = len(filtratedPackets)

            if filtratedCount > 0:
                filtratedOutput = {
                    'filtrated_packets': []
                }
                for packet in filtratedPackets:
                    frame = OrderedDict()  # na udrzanie poradia
                    frame['frame_number'] = filterCounter
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

                    if (calculateFrameType(packet) == 'IEEE 802.3 LLC & SNAP' or calculateFrameType(
                            packet) == 'IEEE 802.3 LLC'):
                        frame['dsap'] = calculateServiceAccessPoint(packet, False)
                        frame['ssap'] = calculateServiceAccessPoint(packet, True)
                    if calculateFrameType(packet) == 'IEEE 802.3 LLC & SNAP':
                        frame['pid'] = calculateProtocolID(packet)
                    filterCounter += 1
                    filtratedOutput['filtrated_packets'].append(frame)

                with open('filter.yaml', 'w') as yaml_file:
                    yaml.dump(filtratedOutput, yaml_file, default_flow_style=False, Dumper=yaml.Dumper)
            else:
                print('No packets with specified protocol')
        else:
            print('Invalid protocol')




    # ---------frame section------------
    for packet in packets:
        packetBytes = bytes(packet)

        frame = OrderedDict()  # na udrzanie poradia
        frame['frame_number'] = packetCounter
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
        packetCounter += 1





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
    #with open('filter.yaml', 'w') as yaml_file:
        #yaml.dump(filtrated, yaml_file, default_flow_style=False, Dumper = yaml.Dumper)

    yaml_file.close()


ethertxt = '/Users/michalhlinka/PycharmProjects/pythonProject1/EtherType'
etherTypeMap = readtxt(ethertxt)
saptxt = '/Users/michalhlinka/PycharmProjects/pythonProject1/saptxt'
sapMap = readtxt(saptxt)
ipv4txt = '/Users/michalhlinka/PycharmProjects/pythonProject1/ipv4txt'
ipv4Map = readtxt(ipv4txt)
main()

#tato cast krasne vypise hexa_frame, v yaml to nefunguje
'''hexaGulas = ' '.join([f'{byte:02X}' for byte in packetBytes]) # https://stackoverflow.com/questions/49597486/convert-bytes-to-hexadecimal-in-python
        hexRows = [hexaGulas[i:i+48] for i in range(0, len(hexaGulas), 48)]
        for line in hexRows:
            print(line)
        print()'''
