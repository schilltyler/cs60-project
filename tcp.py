from scapy.all import *
import threading
from scapy.layers.inet import Ether, IP, UDP, raw

from SendingCrafter import SendingCrafter


conf.use_pcap = True

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



# Need to set a standard packet size to split data into multiple packets if needed
PACKET_SIZE = 512



def start_sniffer(crafter):
    # Start the sniffer with the crafter passed in
    sniff(
        iface=crafter.get_iface(),
        filter="udp and dst port " + str(crafter.get_src_port()),
        prn=lambda pkt: parse_packet(pkt, crafter),
        store=False
    )





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
def parse_packet(packet, crafter):

    print("Packet received\n\n")

    # Get the raw layer object
    raw_layer = packet.getlayer(Raw)

    # If the raw layer exists, parse the TCP header fields
    if raw_layer:
        # rec_data is an array of bytes, not bits (so we index based on bytes)
        rec_data: bytes = raw_layer.load

        print(rec_data)

        # Single byte does not need conversion (it is already an int)
        rec_flags: int = rec_data[9]

        # Convert 4 byte slices to integers
        rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
        rec_ack_num: int = int.from_bytes(rec_data[4:8], byteorder='big')

        for i in rec_data:
            print(i)

        # print received packet
        print("\nReceived Packet:")
        print("Flags: ", rec_flags)
        print("Seq Num: ", rec_seq_num)
        print("Ack Num: " , rec_ack_num)

        ACK_NUM = rec_seq_num + 1
        E_DATA = b""


        # SYN set - This is a new connection
        if rec_flags == 2:
            print("\nGOT SYN\n\n")
            # Get the port and ip from the new connection initiator
            dst_port = packet[UDP].sport
            dst_ip = packet[IP].src

            # Edit crafting object to set destination ip and port
            crafter.set_dest(dst_ip, dst_port)

            print(crafter.get_dst_port())

            # Not sure what to do about window yet, 0 until figure it out
            # 18 as flags sets both SYN and ACK bits
            pkt = crafter.build_packet(sequence_num=1, ack_num=ACK_NUM, flags=18, data=E_DATA, window=0)
            send_and_log_packet(pkt, sequence_nums_sent, 1, 0)


        # SYN and ACK set
        elif rec_flags == 18:
            print("\nGOT SYNACK\n\n")
            # 16 as flags sets ACK bit
            pkt = crafter.build_packet(sequence_num=0, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)
            send_and_log_packet(pkt, sequence_nums_sent, 0, 0)


        # ACK set
        elif rec_flags == 16:
            print("\nGOT ACK\n\n")

            # handshake complete, start sending data
            if rec_ack_num == sequence_nums_sent[len(sequence_nums_sent) - 1] + 1:
                # set_data_packet_parameters(packet)
                print("op1")
                pass

            # check if is an ACK to a FIN
            elif rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # want to see if we are ready to receive a FIN from other side
                # or if we have more data to send
                print("op2")
                pass

            # ACK to data packet
            else:
                # 
                if rec_seq_num == 1 and rec_ack_num == sequence_nums_sent[len(sequence_nums_sent) - 1] + data_sizes_sent[len(data_sizes_sent) - 1]:
                    # set_data_packet_parameters(packet)
                    print("op3")
                    pass
                else:
                    # error sending data . . . resend
                    print("op4")
                    send(packets_sent[len(packets_sent) - 1])

        # FIN set
        elif rec_flags == 1:
            # check if this is a response to a FIN
            if rec_ack_num == fin_nums_sent[len(fin_nums_sent) - 1] + 1:
                # what do we do if we did not receive ack before this?

                # 16 as flags sets ACK bit
                pkt = crafter.build_packet(sequence_num=0, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)
                send_and_log_packet(pkt, sequence_nums_sent, 0, 0)
            

            # or the first fin in the teardown sequence
            else:
                # first send an ACK

                # Sequence number doesn't matter here
                # 16 as flags sets ACK bit
                pkt = crafter.build_packet(sequence_num=0, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)
                send_and_log_packet(pkt, sequence_nums_sent, 0, 0)

                
                # then send a FIN

                # 16 as flags sets ACK bit
                pkt = crafter.build_packet(sequence_num=rec_ack_num, ack_num=ACK_NUM, flags=16, data=E_DATA, window=0)
                send_and_log_packet(pkt, fin_nums_sent, rec_ack_num, 0)
    
    return









"""
    Function to send packets and log key info about the for future use
"""
def send_and_log_packet(packet, l1, slog, dlog):

    l1.append(slog)
    data_sizes_sent.append(dlog)

    send(packet)





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

    # our_interface = input("Enter the interface to sniff on: ")
    # our_port = input("Enter the port to sniff on: ")
    our_interface = "lo0"
    our_port = "5555"

    # Build crafting object with our port specified
    crafter = SendingCrafter(our_interface, our_port)

    # Call sniffing function in a separate thread
    sniff_thread = threading.Thread(target=start_sniffer, args=(crafter,))
    sniff_thread.start()


    # Need to have the option to either continuously listen for syn or send a syn
    choice = input("Enter 'i' to initiate connection or 'l' to listen: ")


    # If initiating connection, send SYN packet
    if choice == 'i':
        dst_ip = input("Enter destination ip address: ")
        dst_port = input("Enter destination port: ")

        # Edit crafting object to set destination ip and port
        crafter.set_dest(dst_ip, dst_port)

        pkt = crafter.build_packet(sequence_num=0, ack_num=0, flags=2, data=b"", window=0)
        send_and_log_packet(pkt, sequence_nums_sent, 1, 0)



    # # populate the array of data
    # for i in range(1, 50):
    #     data_to_send.append(f"data packet {i}")

    # Send data packets here
    # Can be

    
    return




if __name__ == "__main__":
    main()
