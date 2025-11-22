from scapy.all import *
import threading
from scapy.layers.inet import Ether, IP, UDP, raw

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



class Crafter():

    def __init__(self, iface, src_port):
        self.iface = iface
        self.src_port = src_port

        self.dst_ip = None
        self.dst_port = None
    
    def set_dest(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
    
    def get_iface(self):
        return self.iface

    def get_src_port(self):
        return self.src_port

    def get_dst_ip(self):
        return self.dst_ip

    def get_dst_port(self):
        return self.dst_port
    
    def build_packet(self, sequence_num, ack_num, flags, data, window):
        """
        This function builds a TCP packet with the given parameters.

        Arguments:
            sport,          Integer: source port
            dport,          Integer: destination port
            ack_num,        Integer: acknowledgment number
            sequence_num,   Integer: sequence number

            flags,          Integer: Integer number representing TCP flags

            data, :

            window, :
        """
        # IP layer to indicate destination IP address
        ip_layer = IP(dst=self.dst_ip)
        # UDP layer to indicate source and destination ports
        udp_layer = UDP(sport=int(self.src_port), dport=int(self.dst_port))

        # String to store the binary representation of the packet
        message = ""

        # Build the TCP header
        message += format(sequence_num, '032b')
        message += format(ack_num, '032b')


        message += "0101"               # 4 bits        Offset (in 4byte words) to start of data section (Min:5 Max:15)
        message += "0000"               # 4 bits        These must be set to 0

        message += format(flags, '08b') # 8 bits        Flags

        message += format(0, '016b')    # 2 bytes       Window Bits  - Need to figure this part out

        pkt = ip_layer / udp_layer / Raw(load=message)


        # send(pkt)
        return pkt



# c = Crafter("wo0", "5555")
# c.set_dest("127.0.0.1", "1234")
# pkt = c.build_packet(1, 2, 2, 0, 0)

# pkt.show()


# def set_data_packet_parameters(packet):
#     src_port: int = 5555
#     dst_port: int = packet[UDP].sport
#     seq_num: int = 0
#     ack_num: int = 1
#     flags: int = 0 # data transfer mode, no flags needed
#     data: bytes = b""
#     window: int = 0

#     # add to our tracking lists
#     sequence_nums_sent.append(seq_num)
#     data_sizes_sent.append(len(data))


#     # If splitting data into multiple packets is needed, do it here
#     # Convert data to bytes
#     # Split into chunks of PACKET_SIZE
#     # For each chunk, call build_packet with that chunk as data

#     build_packet(src_port, dst_port, seq_num, ack_num, flags, data, window)







# def build_packet(sport, dport, dip, sequence_num, ack_num, flags, data, window):
#     """
#     This function builds a TCP packet with the given parameters.

#     Arguments:
#         sport,          Integer: source port
#         dport,          Integer: destination port
#         ack_num,        Integer: acknowledgment number
#         sequence_num,   Integer: sequence number

#         flags,          Integer: Integer number representing TCP flags

#         data, :

#         window, :
#     """
#     # IP layer to indicate destination IP address
#     ip_layer = IP(dst=dip)
#     # UDP layer to indicate source and destination ports
#     udp_layer = UDP(sport=sport, dport=dport)

#     # String to store the binary representation of the packet
#     message = ""

#     # Build the TCP header
#     message += format(sequence_num, '032b')
#     message += format(ack_num, '032b')


#     message += "0101"               # 4 bits        Offset (in 4byte words) to start of data section (Min:5 Max:15)
#     message += "0000"               # 4 bits        These must be set to 0

#     message += format(flags, '08b') # 8 bits        Flags

#     message += format(0, '016b')    # 2 bytes       Window Bits  - Need to figure this part out

#     pkt = ip_layer / udp_layer / Raw(load=message)


#     # send(pkt)
#     return pkt


    # # Need logic to calculate checksum
    # message += "\nChecksum"         # 2 bytes       Checksum - to be calculated later
    # # Need logic to set ugrent pointer if needed
    # message += "\nurgent pointer"   # 2 bytes       Urgent Pointer - only used if URG flag is set
    # Options TOREPLACE (if using this then need to change data offset and check how long this is)

    # Data TOREPLACE - NEED to see how packet size is determined and how to split data between packets

    # return message

# build_packet(1234, 5678, 0, 0, 16, "Hello, World!", 1024)





# def build_syn(src_port, dst_port, seq_num, ack_num, data, window):
#     # we want to send back to the source port that sent to us
#     src_port: int = src_port
#     dst_port: int = dst_port
#     seq_num: int = 1
#     ack_num: int = rec_seq_num + 1
#     flags: int = 2     # 00010010 (sets the ACK and SYN bits)
#     data: bytes = b""
#     window: int = 0 # 0 for now until we figure out if we need it

#     sequence_nums_sent.append(seq_num)
#     data_sizes_sent.append(len(data))
#     pass

