from scapy.all import *



"""
FLAGS FORMAT:
Will be a string with order:
    CWR | ECE | URG | ACK | PSH | RST | SYN | FIN

eg.
SYN    = 00000010
ACK    = 00010000
SYNACK = 00010010
"""




def sniff():
    sniff(iface="wlp0s20f3", filter="dst port [port num]", prn=parse_packet, store=False)

def parse_packet(packet):
    
    # Need source port and destination port in here to be able to build and send packets

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
            window: int = 0 # 0 for now until we figure out if we need it

            build_packet(seq_num, ack_num, flags, data, window) # NEED SOURCE AND DEST PORTS

        elif syn_bit == 1 and ack_bit == 1:
            rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
            seq_num: int = 0
            ack_num: int = rec_seq_num + 1
            flags: int = 16    # 00010000 (sets only ACK bit)
            data: bytes = b""
            window: int = 0 # 0 for now until we figure out if we need it

            build_packet(seq_num, ack_num, flags, data, window) # NEED SOURCE AND DEST PORTS

        # elif syn_bit == 0 and ack_bit == 1:
        #     # do something
        #     rec_ack: int = int.from_bytes(rec_data[0:4], byteorder='big')
    
    return





def build_packet(sport, dport, sequence_num, ack_num, flags, data, window):
    """
    This function builds a TCP packet with the given parameters.

    Arguments:
        sport,          Integer: source port
        dport,          Integer: destination port
        ack_num,        Integer: acknowledgment number
        sequence_num,   Integer: sequence number

        flags,          String: 8-bit string representing TCP flags

        data, :

        window, :
    """
    # String to store the binary representation of the packet
    message = ""

    # Build the TCP header
    message += format(sport, '016b')
    message += format(dport, '016b')
    message += format(sequence_num, '032b')
    message += format(ack_num, '032b')


    message += "0101"               # 4 bits        Offset (in 4byte words) to start of data section (Min:5 Max:15)
    message += "0000"               # 4 bits        These must be set to 0

    message += flags

    message += "\nwindow bits"      # 2 bytes

    message += "\nChecksum"         # 2 bytes

    message += "\nurgent pointer"   # 2 bytes

    # Options TOREPLACE (if using this then need to change data offset and check how long this is)

    # Data TOREPLACE - NEED to see how packet size is determined and how to split data between packets

    return message

mess = build_packet(1234, 5678, 0, 0, '00010000', "Hello, World!", 1024)
print(mess)





def send_packet(packet, ip, port):
    return




"""
    missing_packets: list of sequence numbers that were not received
"""
def handle_error(missing_packets):
    
    for i in missing_packets:
        pass
    
    return
