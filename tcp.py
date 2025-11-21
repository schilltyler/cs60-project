from scapy.all import *
import threading
from scapy.layers.inet import UDP

"""
FLAGS FORMAT:
Will be a string with order:
    CWR | ECE | URG | ACK | PSH | RST | SYN | FIN

eg.
SYN    = 00000010
ACK    = 00010000
SYNACK = 00010010
"""

"""
Globals
"""
# keeps track of the sequence numbers we have sent
sequence_nums_sent = []
# keeps track of the fin-related sequence numbers we have sent
fin_nums_sent = []
# keeps track of sizes of the data we have sent
data_sizes_sent = []
# keeps track of the packets we have sent
packets_sent = []
# list of data to put in packets
data_to_send = []
# the sequence number of the last acknowledged packet
#last_acked_packet


"""
This function sniffs network traffic to find the packets
transmitted to us
"""
def sniff():
    # using port 5555 for no reason in particular
    # was trying to find a port that is not dedicated to a service already
    # that way we do not get traffic other than our own on it
    sniff(iface="wlp0s20f3", filter="dst port 5555", prn=parse_packet, store=False)

"""
This function sets the parameters for data packet
"""
def set_data_packet_parameters(packet):
    src_port: int = 5555
    dst_port: int = packet[UDP].sport
    seq_num: int = 0
    ack_num: int = 1
    data_offset: int = 3 # 3 * 4 bytes (12 byte header)
    flags: int = 0 # data transfer mode, no flags needed
    data: bytes = b""
    window: int = 0
    checksum: int = 0

    # add to our tracking lists
    sequence_nums_sent.append(seq_num)
    data_sizes_sent.append(len(data))

    build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)


"""
This function will compute the checksum on the received TCP
header to make sure it is valid
"""
def verify_checksum(data):
    # calculate checksum
    # had help from Chatgpt.com to formulate some of this code
    if len(data) % 2 == 1:
        header_and_data += b'\x00' # pad with zero byte to get even length

    two_byte_chunks = []
    for i in range(0, len(data), 2): # every two bytes
        two_byte_chunks.append(data[i:i+2])

    checksum: int = 0
    for i in range(0, len(two_byte_chunks)):
        checksum += two_byte_chunks[i]

    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # invert all of the bits (~ operator)
    checksum = ~sum & 0xFFFF

    if checksum == 0xFFFF:
        return 0 # success
    else:
        return 1 # invalid checksum

"""
    missing_packets: list of sequence numbers that were not received
"""
def handle_error(missing_packets):

    for i in missing_packets:
        pass

    return


"""
This function will take the packet built by build_packet() and
simply use the send() function to send it to its destination
"""
def send_packet(packet):
    send(packet)
    return

"""
This function takes tcp header parameters (as well as two UDP parameters) and
creates a packet that can be sent using Scapy's framework
"""
def build_packet(sport, dport, sequence_num, ack_num, data_offset, flags, data, window, checksum):
    header_and_data: bytes = b"".join(
        (
            sequence_num.to_bytes(4, 'big'),
            ack_num.to_bytes(4, 'big'),
            data_offset.to_bytes(1, 'big')
            flags.to_bytes(1, 'big'),
            window.to_bytes(2, 'big'),
            checksum.to_bytes(2, 'big'),
            data.to_bytes(len(data), 'big')
        )
    )

    # calculate checksum
    # had help from Chatgpt.com to formulate some of this code
    if len(header_and_data) % 2 == 1:
        header_and_data += b'\x00' # pad with zero byte to get even length

    two_byte_chunks = []
    for i in range(0, len(header_and_data), 2): # every two bytes
        two_byte_chunks.append(header_and_data[i:i+2])

    checksum: int = 0
    for i in range(0, len(two_byte_chunks)):
        checksum += two_byte_chunks[i]

    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # invert all of the bits (~ operator)
    checksum = ~sum & 0xFFFF

    # reassemble bytes object now including checksum
    header_and_data = b"".join(
        (
            sequence_num.to_bytes(4, 'big'),
            ack_num.to_bytes(4, 'big'),
            data_offset.to_bytes(1, 'big')
            flags.to_bytes(1, 'big'),
            window.to_bytes(2, 'big'),
            checksum.to_bytes(2, 'big')
            data.to_bytes(len(data), 'big')
        )
    )

    packet = IP(dst='') / UDP(sport=sport, dport=dport) / Raw(header_and_data)

    send_packet(packet)

    return

"""
This function parses the TCP header within the data section
of received UDP packets. It will decide how to set the header of the response packet
based on the fields of the received packet

TODO:
* finish connection teardown logic
* figure out what data to send in packets
* figure out how to start connection (two different programs?)
* add call to handle_error when sequence numbers are out of order
"""
def parse_packet(packet):
    raw_layer: bytes = packet.getlayer(Raw)

    if raw_layer:
        # verify checksum
        result: int = verify_checksum(raw_layer)
        if result == 0:
            pass
        else:
            # invalid checksum, don't do any logic
            return

        # rec_data is an array of bytes, not bits (so we index based on bytes)
        rec_data: bytes = raw_layer.load
        rec_flags: int = int.from_bytes(rec_data[10], byteorder='big')
        rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
        rec_ack_num: int = int.from_bytes(rec_data[4:8], byteorder='big')

        # print received packet
        print("Received Packet:")
        print("Flags: " + rec_flags)
        print("Seq Num: " + rec_seq_num)
        print("Ack Num: " + rec_ack_num)

        # SYN set
        if rec_flags == 2:
            # we want to send back to the source port that sent to us
            src_port: int = 5555
            dst_port: int = packet[UDP].sport
            seq_num: int = 1
            ack_num: int = rec_seq_num + 1
            data_offset: int = 3
            flags: int = 18     # 00010010 (sets the ACK and SYN bits)
            data: bytes = b""
            window: int = 0 # 0 for now until we figure out if we need it
            checksum: int = 0

            sequence_nums_sent.append(seq_num)
            data_sizes_sent.append(len(data))

            build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)

        # SYN and ACK set
        elif rec_flags == 18:
            src_port: int = 5555
            dst_port: int = packet[UDP].sport
            seq_num: int = 0
            ack_num: int = rec_seq_num + 1
            data_offset: int = 3
            flags: int = 16    # 00010000 (sets only ACK bit)
            data: bytes = b""
            window: int = 0
            checksum: int = 0

            sequence_nums_sent.append(seq_num)
            data_sizes_sent.append(len(data))

            build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)

        # ACK set
        elif rec_flags == 16:
            if rec_ack_num == sequence_nums_sent[len(sequence_nums_sent - 1)] + 1:
                # handshake complete, start sending data
                set_data_packet_parameters(packet)

            # check if is an ACK to a FIN
            elif rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # want to see if we are ready to receive a FIN from other side
                # or if we have more data to send
                pass

            else:
                if rec_seq_num == 1 and rec_ack_num == sequence_nums_sent[len(sequence_nums_sent - 1)] + data_sizes_sent[len(data_sizes_sent - 1)]:
                    set_data_packet_parameters(packet)
                else:
                    # error sending data . . . resend
                    send_packet(packets_sent[len(packets_sent) - 1])

        # FIN set
        elif rec_flags == 1:
            # check if this is a response to a FIN
            if rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # what do we do if we did not receive ack before this?
                src_port: int = 5555
                dst_port: int = packet[UDP].sport
                seq_num: int = 0 # doesn't matter what this is
                ack_num: int = rec_seq_num + 1
                data_offset: int = 3
                flags: int = 16    # 00010000 (sets only ACK bit)
                data: bytes = b""
                window: int = 0
                checksum: int = 0

                sequence_nums_sent.append(seq_num)
                data_sizes_sent.append(len(data))

                build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)
            # or the first fin in the teardown sequence
            else:
                # first send an ACK
                src_port: int = 5555
                dst_port: int = packet[UDP].sport
                seq_num: int = 0 # doesn't matter what this is
                ack_num: int = rec_seq_num + 1
                data_offset: int = 3
                flags: int = 16    # 00010000 (sets only ACK bit)
                data: bytes = b""
                window: int = 0
                checksum: int = 0

                sequence_nums_sent.append(seq_num)
                data_sizes_sent.append(len(data))

                build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)
                
                # then send a FIN
                src_port: int = 5555
                dst_port: int = packet[UDP].sport
                seq_num: int = rec_ack_num
                ack_num: int = rec_seq_num + 1
                data_offset: int = 3
                flags: int = 16    # 00010000 (sets only ACK bit)
                data: bytes = b""
                window: int = 0
                checksum: int = 0

                fin_nums_sent.append(seq_num)
                data_sizes_sent.append(len(data))

                build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)
    
    return


"""
This function will start the TCP connection by sending a SYN segment

Notes:
* start by sending a SYN packet
* only want one side to send this though(?)
"""
def main():
    # popualate the array of data
    for i in range(1, 50):
        data_to_send.append(f"data packet {i}")

    # create thread
    sniff_thread = Thread(target=sniff, args())
    
    sniff_thread.start()

    # send a SYN packet
    src_port: int = 5555
    dst_port: int = 5555
    seq_num: int = 0
    ack_num: int = 0
    flags: int = 2    # 00010000 (sets only SYN bit)
    data: bytes = b""
    window: int = 0

    sequence_nums_sent.append(seq_num)
    data_sizes_sent.append(len(data))

    build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)

    thread.join()
    
    return

if __name__ == "__main__":
    main()


