from scapy.all import *



def sniff():
    sniff(iface="wlp0s20f3", filter="dst port [port num]", prn=parse_packet, store=False)

def parse_packet(packet):
    raw_layer = packet.getlayer(Raw)
    if raw_layer:
        # data is bytes
        data = raw_layer.load
        
        syn_bit: int = int.from_bytes(data)
        
        # extract the first four bytes
        sequence_number: int = int.from_bytes(data[0: 4], byteorder='big')
    
    return




"""
    Pass in source port and destination port as ints
    ack_num will need to be set by info from received packet
    sequence_num pass in as int
"""
def build_packet(sport, dport, flags, data, window, ack_num=0, sequence_num=0):
    message = ""

    message += format(sport, '016b')
    message += format(dport, '016b')
    message += format(sequence_num, '032b')
    message += format(ack_num, '032b')

    print(message)
    

    # # Starting sequence:
    # if (flags['SYN'] == 1) and (flags['ACK'] == 0):
    #     pass

    # elif (flags['SYN'] == 1) and (flags['ACK'] == 1):
    #     pass

    # elif (flags['SYN'] == 0) and (flags['ACK'] == 1):
    #     pass

    return

build_packet(1234, 5678, {'SYN':1, 'ACK':0}, "Hello, World!", 1024, 0, 0)


def send_packet(packet, ip, port):
    return




def handle_error(missing_packets):
    return

