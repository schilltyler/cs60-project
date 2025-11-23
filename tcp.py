from scapy.all import *
import threading
from scapy.layers.inet import Ether, IP, UDP, raw

from SendingCrafter import SendingCrafter

from SendingHelpers import *





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

# This will be used to stop the program when the user requests it
stopEvent = threading.Event()



def start_sniffer(crafter):
    # Start the sniffer with the crafter passed in
    while not stopEvent.is_set():
        sniff(
            iface=crafter.get_iface(),
            filter="udp and dst port " + str(crafter.get_src_port()),
            prn=lambda pkt: parse_packet(pkt, crafter),
            store=False,
            timeout=1,
            count=1
        )


def parse_user_input(crafter):
    while True:
        if (crafter.get_dst_ip() == None):
            print("\n\n\n")
            print("*****************************************")
            print("Following options:")
            print("    O to try opening new TCP connection")
            print("    Q to shutdown")
            print(" ")
            command = input("Please make a selection: ")

            if command == "O":
                print("New connection attempt requested. ")
                new_connection_target(crafter)
            
            elif command == "Q":
                print("Shutdown requested. ")
                # This will stop the sniffer from running and close the program
                stopEvent.set()
                break
        
        else:
            print("\n\n\n")
            print("*****************************************")
            print("Following options:")
            print("    F to close connection")
            print("    M to make a message to send")
            print(" ")
            command = input("Please make a selection: ")

            if command == "F":
                print("User requested connection termination. ")
                send_FIN_and_log(crafter, fin_nums_sent, data_sizes_sent, 0, 100, 100)
            
            elif command == "M":
                message = input("Message: ")
                # Send message (in data field) to other side
                # send_FIN_and_log(crafter, fin_nums_sent, data_sizes_sent, 0, 100, 100)
            




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

        # Single byte does not need conversion (it is already an int)
        rec_flags: int = rec_data[9]
        # Convert 4 byte slices to integers
        rec_seq_num: int = int.from_bytes(rec_data[0:4], byteorder='big')
        rec_ack_num: int = int.from_bytes(rec_data[4:8], byteorder='big')

        # for i in rec_data:
        #     print(i)

        print("\nReceived Packet:")
        print("Flags: ", rec_flags)
        print("Seq Num: ", rec_seq_num)
        print("Ack Num: " , rec_ack_num)

        ACK_NUM = rec_seq_num + 1


        # Received a SYN - this is a new connection
        if rec_flags == 2:
            # print("\nGOT SYN\n\n")
            # Get the port and ip from the new connection initiator
            dst_port = packet[UDP].sport
            dst_ip = packet[IP].src

            # Edit crafting object to set destination ip and port
            crafter.set_dest(dst_ip, dst_port)
            # print(crafter.get_dst_port())

            # Not sure what to do about window yet, 0 until figure it out
            send_SYNACK_and_log(crafter, sequence_nums_sent, 0, data_sizes_sent, 0, ACK_NUM)



        # Received a SYNACK
        elif rec_flags == 18:
            # print("\nGOT SYNACK\n\n")
            send_ACK_and_log(crafter, sequence_nums_sent, 0, data_sizes_sent, 0, ACK_NUM)
            # Start SENDING data


        # Received an ACK
        elif rec_flags == 16:
            print("\nGOT ACK\n\n")
            # print(sequence_nums_sent)
            # print(fin_nums_sent)

            # Handshake complete, start RECEIVING data - Wont this also be ACK to a data packet???
            if rec_ack_num == sequence_nums_sent[-1] + 1:
                # set_data_packet_parameters(packet)
                print("\nHandshake Complete!!\nConnection is established\nNow receiving data:\n\n")

            # Check if is an ACK to a FIN we sent
            elif (rec_ack_num == fin_nums_sent[-1] + 1):
                # If final ACK received, close connection
                if (crafter.get_closing() == True):
                    # In this case we need to close the connection and reset variables
                    crafter.wipe_dest()
                    print("\n\n Connection closed\n")
                    crafter.set_closing(False)


            # ACK to data packet
            else:
                # 
                if (rec_seq_num == 1) and (rec_ack_num == (sequence_nums_sent[-1] + data_sizes_sent[-1])):
                    # set_data_packet_parameters(packet)
                    print("op3")
                    pass
                else:
                    # error sending data . . . resend
                    print("op4")
                    send(packets_sent[len(packets_sent) - 1])

        # Received a FIN
        elif rec_flags == 17:
            # print("GOT FIN")
            # print(fin_nums_sent)

            # If we get a FIN that is replying to our FIN
            if (fin_nums_sent != []) and (rec_ack_num == fin_nums_sent[- 1] + 1):
                # Send back an ACK
                send_ACK_and_log(crafter, sequence_nums_sent, 0, data_sizes_sent, 0, ACK_NUM)

                # In this case we need to close the connection and reset variables
                crafter.wipe_dest()
                print("\n\n Connection closed\n")
            

            # If the other side started the connection closure
            else:
                # First send an ACK
                send_ACK_and_log(crafter, sequence_nums_sent, 0, data_sizes_sent, 0, ACK_NUM)

                # Then send a FIN
                send_FIN_and_log(crafter, fin_nums_sent, data_sizes_sent, 0, rec_ack_num, ACK_NUM)

                # Leave connection open here waiting for final ACK from other side
                crafter.set_closing(True)

                









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




def new_connection_target(crafter):
    dst_ip = input("Enter destination ip address: ")
    dst_port = input("Enter destination port: ")

    # Edit crafting object to set destination ip and port
    crafter.set_dest(dst_ip, dst_port)
    send_SYN_and_log(crafter, sequence_nums_sent, 0, data_sizes_sent, 0, 0)




# def terminate_connection(crafter):
#     # Send FIN to initiate connection closure
#     send_FIN_and_log(crafter, fin_nums_sent, data_sizes_sent, 0, 100, 100)






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


    # If initiating connection
    if choice == 'i':
        # Get the target from user and send a SYN
        new_connection_target(crafter)
    

    # Start a thread to get user input
    in_thread = threading.Thread(target=parse_user_input, args=(crafter,))
    in_thread.start()


    # # populate the array of data
    # for i in range(1, 50):
    #     data_to_send.append(f"data packet {i}")

    # Send data packets here
    # Can be




if __name__ == "__main__":
    main()
