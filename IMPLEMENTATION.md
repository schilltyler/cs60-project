# Implementation

## Function Prototypes
Include parameters

* Function to read and parse received packets

* Function to build SYN, SYNACK, and ACK packets
* Function to send syn... packets initialy to setup communication with other party

* Function to send data in partitions across multiple packets
* Function to resend a specific packet (selective repeat) when user doesn't receive



## Psuedo Code

Send SYN and wait

Receive SYNACK and then send ACK

Start sending data

If multiple ACKs received (missing packet), then keep track of which packet(s) are lost

After done sending, resend all lost packets



## Data Structures

Python list to keep track of data indicies in each packet so can easily resend



## Error Handling


