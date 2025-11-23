# from SendingCrafter import SendingCrafter
from scapy.all import *






def send_SYN_and_log(crafter, log1, val1, log2, val2, ack_num):
    pkt = crafter.build_packet(sequence_num=0, ack_num=ack_num, flags=2, data=b"", window=0)
    send_and_log_packet(pkt, log1, val1, log2, val2)



def send_SYNACK_and_log(crafter, log1, val1, log2, val2, ack_num):
    pkt = crafter.build_packet(sequence_num=0, ack_num=ack_num, flags=18, data=b"", window=0)
    send_and_log_packet(pkt, log1, val1, log2, val2)



def send_ACK_and_log(crafter, log1, val1, log2, val2, ack_num):
    pkt = crafter.build_packet(sequence_num=0, ack_num=ack_num, flags=16, data=b"", window=0)
    send_and_log_packet(pkt, log1, val1, log2, val2)



def send_FIN_and_log(crafter, log1, log2, val2, sequence_num, ack_num):
    pkt = crafter.build_packet(sequence_num=sequence_num, ack_num=ack_num, flags=17, data=b"", window=0)
    send_and_log_packet(pkt, log1, sequence_num, log2, val2)



def send_DATA_and_log(crafter, log1, val1, log2, val2, sequence_num, ack_num):
    # Convert data to bytes


    pkt = crafter.build_packet(sequence_num=sequence_num, ack_num=ack_num, flags=17, data=b"hello", window=0)

    # Split bytes between packets
    

    # Send packets

    return



"""
    Function to send packets and log key info about the for future use
"""
def send_and_log_packet(packet, log1, val1, log2, val2):
    log1.append(val1)
    log2.append(val2)

    send(packet)
