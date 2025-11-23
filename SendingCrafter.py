from scapy.all import *
from scapy.layers.inet import IP, UDP

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
Need to set a standard packet size to split data into multiple packets if needed
"""
PACKET_SIZE = 512



class SendingCrafter():

    def __init__(self, iface, src_port):
        self.iface = iface
        self.src_port = src_port

        self.dst_ip = None
        self.dst_port = None

        self.closing = False
    
    def set_dest(self, dst_ip, dst_port):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
    
    def wipe_dest(self):
        self.dst_ip = None
        self.dst_port = None
    
    def set_closing(self, val):
        self.closing = val
    
    def get_closing(self):
        return self.closing
    
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

            data,           Bytes  :  Bytes representing the message to send to the user

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

        
        # Convert the bit string to actual bytes
        mint = int(message, 2)
        nbs = len(message) // 8
        payload = mint.to_bytes(nbs, byteorder='big')

        # Create packet by stacking layers
        pkt = ip_layer / udp_layer / Raw(payload)

        # Return the created packet
        return pkt





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

