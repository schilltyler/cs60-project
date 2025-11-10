# Implementation

## Function Prototypes
Include parameters

* Function to read and parse received packets
```python
def parse_packet(packet)
```

* Function to build packets
```python
def build_packet(type, payload)
```

* Function to send packets
```python
def send_packet(packet)
```

* Function to resend a specific packet (selective repeat) when user doesn't receive
```python
def handle_error(missing_packets)
```



## Psuedo Code

Tyler
### parse_packet(packet)
```python
Sniff for packets that are on the port we choose
Check if the syn or ack (or both for syn-ack) bits are set
Do this by checking for substring within data section of packet
And also for fields that are only a bit, can check if they
are greater than 0
If the syn bit is set and not the ack bit:
    ** We just received SYN **
    Check 
    Set the ack number sequence number plus 1
    Set the sequence number to something random
    Set the syn bit
    Set the ack bit
If the syn bit is set and the ack bit is set:
    ** We just received SYN-ACK **
    Set ack number to sequence number plus 1
    Set the ack bit
    Unset the syn bit
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
    If one of those things not true:
        There was an error in sending data
        Resend
```
Basil
### build_packet(sequence #, ack #, data, window)
```python

```
Tyler
### send_packet(packet)
```python
Use send() to send packet that was build using build_packet
```

Basil
### handle_error(missing_packets)
```python

```

Send SYN and wait

Receive SYNACK and then send ACK

Start sending data

If multiple ACKs received (missing packet), then keep track of which packet(s) are lost

After done sending, resend all lost packets



## Data Structures

* Python list to keep track of data indicies in each packet so can easily resend
* Maybe have this list be the sequences numbers we sent and then remove
items from the list as they are acknowledged?

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

UDP header will always be 4 bytes, so that's when "TCP" packet will start

## Error Handling

* Implement selective repeat algorithm
* Checksum to ensure packet integrity

## Notes
* Can use iptables to create a rule that simulates packet drop when testing
