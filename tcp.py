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




def build_packet(sequence_num, ack_num, flags, data, window):
    return




def send_packet(packet, ip, port):
    return




def handle_error(missing_packets):
    return

