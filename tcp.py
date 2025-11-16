from scapy.all import *


def sniff():
    sniff(iface="wlp0s20f3", filter="dst port [port num]", prn=parse_packet, store=False)

def parse_packet(packet):
    raw_layer: bytes = packet.getlayer(Raw)
    if raw_layer:
        # data is bytes
        rec_data: bytes = raw_layer.load
        # rec_data is an array of bytes, not bits (so we index based on bytes
        rec_flags: int = int.from_bytes(rec_data[10], byteorder='big')
        #ack_bit: int = int.from_bytes(rec_data[44], byteorder='big')

        if rec_flags == 2: # 00000010
            rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
            seq_num: int = 1
            ack_num: int = rec_seq_num + 1
            flags: int = 18     # 00010010 (sets the ACK and SYN bits)
            data: bytes = b""
            window: int = 0 # 0 for now until we figure out if we need it

            build_packet(seq_num, ack_num, flags, data, window)

        elif rec_flags == 18:
            rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
            seq_num: int = 0
            ack_num: int = rec_seq_num + 1
            flags: int = 16    # 00010000 (sets only ACK bit)
            data: bytes = b""
            window: int = 0

            build_packet(seq_num, ack_num, flags, data, window)

        else rec_flags == 16:
            rec_ack_num: int = int.from_bytes(rec_data[4:8], byteorder='big')
            seq_num: int = 
            ack_num: int =
            flags: int = 
            data: bytes = 
            window: int = 0
    
    return


def build_packet(sequence_num, ack_num, flags, data, window):
    return




def send_packet(packet, ip, port):
    return




def handle_error(missing_packets):
    return


