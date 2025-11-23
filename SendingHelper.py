# from SendingCrafter import SendingCrafter
from scapy.all import *



class SendingHelper:

    def __init__(self, sseq):
        self.seq_num = sseq
        self.ack_num = 0

        self.fin_num_sent = None
        self.last_seq_sent = None
        # self.crafter = crafter
    
    def increment_ack(self, data_size):
        self.ack_num += data_size
    
    def get_fin_num_sent(self):
        return self.fin_num_sent
    
    def get_last_seq_sent(self):
        return self.last_seq_sent

    # Sending a SYN and increment Sequence number
    def send_SYN_and_log(self, crafter):
        pkt = crafter.build_packet(sequence_num=self.seq_num, ack_num=self.ack_num, flags=2, data=b"", window=0)
        send_and_log_packet(pkt)
        self.last_seq_sent = self.seq_num
        self.seq_num += 1


    # Sending a SYNACK and increment Sequence number
    def send_SYNACK_and_log(self, crafter):
        pkt = crafter.build_packet(sequence_num=self.seq_num, ack_num=self.ack_num, flags=18, data=b"", window=0)
        send_and_log_packet(pkt)
        self.last_seq_sent = self.seq_num
        self.seq_num += 1


    # Sending an ACK and no increment
    def send_ACK_and_log(self, crafter):
        pkt = crafter.build_packet(sequence_num=self.seq_num, ack_num=self.ack_num, flags=16, data=b"", window=0)
        send_and_log_packet(pkt)


    # Sending a FIN and increment Sequence number
    def send_FINACK_and_log(self, crafter):
        pkt = crafter.build_packet(sequence_num=self.seq_num, ack_num=self.ack_num, flags=17, data=b"", window=0)
        send_and_log_packet(pkt)
        self.fin_num_sent = self.seq_num
        # self.last_seq_sent = self.seq_num
        self.seq_num += 1


    def send_DATA_and_log(self, crafter, data):
        # Convert data to bytes
        dinb = data.encode()

        # Split bytes between packets

        # Test packet
        pkt = crafter.build_packet(sequence_num=self.seq_num, ack_num=self.ack_num, flags=16, data=dinb, window=0)


        # Send packets
        send_and_log_packet(pkt)

        return



"""
    Function to send packets and log key info about the for future use
"""
def send_and_log_packet(packet):
    send(packet)

