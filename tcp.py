from scapy.all import *
import threading
from scapy.layers.inet import Ether, IP, UDP, Raw, send

from packetCrafting import build_packet, set_data_packet_parameters

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


"""
Need to set a standard packet size to split data into multiple packets if needed
"""
PACKET_SIZE = 512




def sniff():
    # using port 5555 for no reason in particular
    # was trying to find a port that is not dedicated to a service already
    # that way we do not get traffic other than our own on it
    sniff(iface="wlp0s20f3", filter="dst port 5555", prn=parse_packet, store=False)





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

        SRC = 5555
        DST = packet[UDP].sport
        ACK_NUM = rec_seq_num + 1
        E_DATA = b""

        # SYN set
        if rec_flags == 2:

            sequence_nums_sent.append(1)
            data_sizes_sent.append(0)

            # Not sure what to do about window yet, 0 until figure it out
            # 18 as flags sets both SYN and ACK bits

            build_packet(SRC, DST, sequence_num=1, ack_num=ACK_NUM, flags=18, data=E_DATA, window=0)

        # SYN and ACK set
        elif rec_flags == 18:

            sequence_nums_sent.append(0)
            data_sizes_sent.append(0)

            # 16 as flags sets ACK bit

            build_packet(SRC, DST, sequence_num=0, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)

        # ACK set
        elif rec_flags == 16:

            # handshake complete, start sending data
            if rec_ack_num == sequence_nums_sent[len(sequence_nums_sent - 1)] + 1:
                set_data_packet_parameters(packet)

            # check if is an ACK to a FIN
            elif rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # want to see if we are ready to receive a FIN from other side
                # or if we have more data to send
                pass

            # ACK to data packet
            else:
                # 
                if rec_seq_num == 1 and rec_ack_num == sequence_nums_sent[len(sequence_nums_sent - 1)] + data_sizes_sent[len(data_sizes_sent - 1)]:
                    set_data_packet_parameters(packet)
                else:
                    # error sending data . . . resend
                    send(packets_sent[len(packets_sent) - 1])

        # FIN set
        elif rec_flags == 1:
            # check if this is a response to a FIN
            if rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # what do we do if we did not receive ack before this?

                sequence_nums_sent.append(0)
                data_sizes_sent.append(0)

                # 16 as flags sets ACK bit

                build_packet(SRC, DST, sequence_num=0, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)
            # or the first fin in the teardown sequence
            else:
                # first send an ACK

                sequence_nums_sent.append(0)
                data_sizes_sent.append(0)

                # Sequence number doesn't matter here
                # 16 as flags sets ACK bit

                build_packet(SRC, DST, sequence_num=0, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)

                
                # then send a FIN

                fin_nums_sent.append(rec_ack_num)
                data_sizes_sent.append(0)

                # 16 as flags sets ACK bit

                build_packet(SRC, DST, sequence_num=rec_ack_num, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)
    
    return





"""
    missing_packets: list of sequence numbers that were not received
"""
def handle_error(missing_packets):
    
    for i in missing_packets:
        pass
    
    return






"""
This function will start the TCP connection by sending a SYN segment

Notes:
* start by sending a SYN packet
* only want one side to send this though(?)
"""
def main():
    
    # Need MAC and IP addresses from received packet to build response packets
    # Also need a wat to initiate the connection from one side

    # Start listening

    ipad = input("Enter destination ip address: ")

    # Need to have the option to either continuously listen for syn or send a syn
    choice = input("Enter 'i' to initiate connection or 'l' to listen: ")

    # If initiating connection, send SYN packet
    if choice == 'i':
        ipad = input("Enter destination ip address: ")

        # Send syn




    # Start listening in the background anyway on a separate thread
    # On this thread handle user input to send data packets when needed
    # Need to have initiator mode and listener mode
    # Initiator mode sends SYN packets until connection is established
    # Listener mode just listens for SYN packets and responds accordingly
    # No
    # Large part of this is that you can send and receieve at the same time
    # Who starts the connection then?????
    # Connection only starts when one side is prompted to send something
    # In our continuous listening thread we can have a user input prompt to start the connection
    # How to do this??

    # # Set ip address of target here
    # ipad = "127.0.0.1"

    # Sending data in the parser function so need to pass addresses there




    # populate the array of data
    for i in range(1, 50):
        data_to_send.append(f"data packet {i}")

    # send a SYN packet

    # Call sniffing function in a separate thread
    sniff_thread = threading.Thread(target=sniff)
    sniff_thread.start()

    
    
    # Send data packets here
    # Can be 

    
    return

if __name__ == "__main__":
    main()


