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

# Globals
# keeps track of the sequence numbers we have sent
sequence_nums_sent[]
# keeps track of the fin-related sequence numbers we have sent
fin_nums_sent[]
# keeps track of sizes of the data we have sent
data_sizes_sent[]
# keeps track of the packets we have sent
packets_sent[]

def sniff():
    # using port 5555 for no reason in particular
    # was trying to find a port that is not dedicated to a service already
    # that way we do not get traffic other than our own on it
    sniff(iface="wlp0s20f3", filter="dst port 5555", prn=parse_packet, store=False)

def set_data_packet_parameters(packet):
    src_port: int = 5555
    dst_port: int = packet[UDP].sport
    seq_num: int = 0
    ack_num: int = 1
    flags: int = 0 # data transfer mode, no flags needed
    data: bytes = b""
    window: int = 0

    # add to our tracking lists
    sequence_nums_sent.append(seq_num)
    data_sizes_sent.append(len(data))

    build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)

def parse_packet(packet):
    raw_layer: bytes = packet.getlayer(Raw)
    if raw_layer:
        # data is bytes
        rec_data: bytes = raw_layer.load
        # rec_data is an array of bytes, not bits (so we index based on bytes)
        rec_flags: int = int.from_bytes(rec_data[10], byteorder='big')
        rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
        rec_ack_num: int = int.from_bytes(rec_data[4:8], byteorder='big')

        if rec_flags == 2: # SYN set
            # we want to send back to the source port that sent to us
            src_port: int = 5555
            dst_port: int = packet[UDP].sport
            seq_num: int = 1
            ack_num: int = rec_seq_num + 1
            flags: int = 18     # 00010010 (sets the ACK and SYN bits)
            data: bytes = b""
            window: int = 0 # 0 for now until we figure out if we need it

            sequence_nums_sent.append(seq_num)
            data_sizes_sent.append(len(data))

            build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)

        elif rec_flags == 18: # SYN and ACK set
            src_port: int = 5555
            dst_port: int = packet[UDP].sport
            seq_num: int = 0
            ack_num: int = rec_seq_num + 1
            flags: int = 16    # 00010000 (sets only ACK bit)
            data: bytes = b""
            window: int = 0

            sequence_nums_sent.append(seq_num)
            data_sizes_sent.append(len(data))

            build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)

        elif rec_flags == 16: # ACK set
            if rec_ack_num == sequence_nums_sent[len(sequence_nums_sent - 1)] + 1:
                # handshake complete, start sending data
                set_data_packet_parameters(packet)

            # check if is an ACK to a FIN
            elif rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # want to see if we are ready to receive a FIN from other side
                # or if we have more data to send

            else:
                if rec_seq_num == 1 and rec_ack_num == sequence_nums_sent[len(sequence_nums_sent - 1)] + data_sizes_sent[len(data_sizes_sent - 1)]:
                    set_data_packet_parameters(packet)
                else:
                    # error sending data . . . resend
                    send_packet(sent_packets[len(send_packets) - 1])
        elif rec_flags == 1: #fin
            # check if this is a response to a FIN
            if rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # what do we do if we did not receive ack before this?
                src_port: int = 5555
                dst_port: int = packet[UDP].sport
                seq_num: int = 0 # doesn't matter what this is
                ack_num: int = rec_seq_num + 1
                flags: int = 16    # 00010000 (sets only ACK bit)
                data: bytes = b""
                window: int = 0

                sequence_nums_sent.append(seq_num)
                data_sizes_sent.append(len(data))

                build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)
            # or the first fin in the teardown sequence
            else
                # first send an ACK
                src_port: int = 5555
                dst_port: int = packet[UDP].sport
                seq_num: int = 0 # doesn't matter what this is
                ack_num: int = rec_seq_num + 1
                flags: int = 16    # 00010000 (sets only ACK bit)
                data: bytes = b""
                window: int = 0

                sequence_nums_sent.append(seq_num)
                data_sizes_sent.append(len(data))

                build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)
                
                # then send a FIN
                src_port: int = 5555
                dst_port: int = packet[UDP].sport
                seq_num: int = rec_ack_num
                ack_num: int = rec_seq_num + 1
                flags: int = 16    # 00010000 (sets only ACK bit)
                data: bytes = b""
                window: int = 0

                fin_nums_sent.append(seq_num)
                data_sizes_sent.append(len(data))

                build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)
    
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




'''
This function will take the packet built by build_packet() and
simply use the send() function to send it to its destination
'''
def send_packet(packet):
    send(packet)
    return




"""
    missing_packets: list of sequence numbers that were not received
"""
def handle_error(missing_packets):
    
    for i in missing_packets:
        pass
    
    return

