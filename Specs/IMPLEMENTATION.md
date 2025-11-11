# Implementation

## Function Prototypes

### Parse Packet
A function to read and parse received packets
```python
def parse_packet(packet)
```
* `packet` = a UDP packet we sniffed

### Build Packet
A function to build packets
```python
def build_packet(sequence_num, ack_num, flags, data, window)
```
* `sequence_num` = the sequence number we want the packet to have
* `ack_num` = the acknowledgement number we want the packet to have
* `data` = the data we want the packet to have
* `window` = the amount of packets we can still send before the receiver
stops accepting packets

### Send Packet
A function to send packets
```python
def send_packet(packet)
```
* `packet` = the packet we constructed using `build_packet`

### Handle Error
A function to resend a specific packet (selective repeat) when user doesn't receive
```python
def handle_error(missing_packets)
```
* `missing_packets` = a list of packets that we have not received an ack for



## Psuedo Code

### parse_packet(packet)
```
Sniff for packets that are on the port we choose
Check if the syn or ack (or both for syn-ack) bits are set
Do this by checking for substring within data section of packet
And also for fields that are only a bit, can check if they
are greater than 0
If the syn bit is set and not the ack bit:
    ** We just received SYN **
    Set the ack number sequence number plus 1
    Set the sequence number to something random
    Set the syn bit
    Set the ack bit
    Call build_packet() with these parameters
If the syn bit is set and the ack bit is set:
    ** We just received SYN-ACK **
    Set ack number to sequence number plus 1
    Set the ack bit
    Unset the syn bit
    Call build_packet() with these parameters
If the ack bit is set and not the syn bit:
    ** We just received ACK **
    If ack number is last syn sent plus 1:
        Handshake is finished, both hosts can start sending data
        Set sequence number to 0
        Set ack number to 1
        Add data to packet
        Add window number to packet
        Call build_packet() with these parameters
    ** OR we just received acknowledgement of data sent **
    Check if the sequence number equals 1
    Check if the ack equals the last sequence number sent plus
    the size of the last data sent
    If both things true:
        We successfully sent data
        Set sequence number to 0
        Set ack number to 1
        Add data to packet
        Add window number to packet
        Call build_packet() with these parameters
    If one of those things not true:
        There was an error in sending data
        Resend
```

### build_packet(sequence_num, ack_num, flags, data, window)
```
Read arguments passed in to determine what type of packet to build (SYN, SYNACK, ACk, data, etc.)
Use the arguments passed in to calculate error info (checksum)
Build the different packet layers and convert the packet(s) to binary to prepare for sending
Return the packet(s)
```

### send_packet(packet)
```
Use send() to send packet that was built using build_packet
```

Basil
### handle_error(missing_packets)
```
Call build_packet to rebuild the data packets
Index the specific data packets that were missing
Resend only the missing packets
Repeat until no missing packets
```

Send SYN and wait

Receive SYNACK and then send ACK

Start sending data

If multiple ACKs received (missing packet), then keep track of which packet(s) are lost

After done sending, resend all lost packets



## Data Structures

* Python list to keep track of data indicies in each packet so can easily resend
* This list will be the sequences numbers we sent, and we will remove sequence
numbers as they are acknowledged

### Our "TCP" Packet
** In this order **
* 32 bit sequence number
* 32 bit acknowledgement number
* 4 bits of data offset (number of 4-byte words before data starts)
* 8 bits of flags
* 16 bit window (number of packets sender can still send before
receiver will not accept any more un-acked packets)

Already have:
* Source port
* Destination port
* Checksum

UDP header will always be 8 bytes, so after that is when "TCP" packet will start. 
Put simply, we will just attach the TCP header into the start of the data section
the UDP packet

## Error Handling

* Implement selective repeat algorithm
* Checksum to ensure packet integrity

## Testing Plan
* We will hard-code a certain amount of packets to send
* We will have a client and a server, so one will send the initial syn packet
to get the connection going (that will be the only difference between the two files,
otherwise, they function the same way and have the same code)
* We will send the hard-coded amount of data packets
* We will us iptables to create rules that will simulate packet drop
(this will be used to test our error handling mechanisms)
