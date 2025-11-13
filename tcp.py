from scapy.all import *

def sniff():
    sniff(iface="wlp0s20f3", filter="dst port [port num]", prn=parse_packet, store=False)

def parse_packet(packet):
    raw_layer: bytes = packet.getlayer(Raw)
    if raw_layer:
        # data is bytes
        rec_data: bytes = raw_layer.load        
        syn_bit: int = int.from_bytes(rec_data[47], byteorder='big')
        ack_bit: int = int.from_bytes(rec_data[44], byteorder='big')

        if syn_bit == 1 and ack_bit == 0:
            # extract the first four bytes
            rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
            seq_num: int = 1
            ack_num: int = rec_seq_num + 1
            flags: int = 18     # 00010010 (sets the ACK and SYN bits)
            data: bytes = b""
            window: int = 0; # 0 for now until we figure out if we need it

            build_packet(seq_num, ack_num, flags, data, window)

        elif syn_bit == 1 and ack_bit == 1:
            rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
            seq_num: int = 0
            ack_num: int = rec_seq_num + 1
            flags: int = 16    # 00010000 (sets only ACK bit)
            data: bytes = b""
            window: int - 0;

            build_packet(seq_num, ack_num, flags, data, window)

        else syn_bit == 0 and ack_bit == 1:
            # do something
            rec_ack: int = int.from_bytes(rec_data[], byteorder='big')
