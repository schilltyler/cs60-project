# Design Specification

## User Interface
We will not have a user interface. We will simply hard-code the number of packets
we want to send and what data to put into them.

## Inputs and Outputs
There will be no inputs, we will simply run our program which will use hard-coded
values in order to know how many packets to send and what data to put within them.
We will output important testing/debugging information such as if we were able to
successfully complete a handshake, or the number of packets we have sent so far.

## Functional Decomposition into Modules

### Sniffing
We will have a thread that constantly sniffs for traffic on the port we decide to use.
When we receive a packet, the sniffer will direct it to our packet parser.

### Packer Parsing
We will take each received packet and examine its "TCP" fields in order to figure out
how we should respond. Once we know how to respond, we will send a packet back in most cases.

### Packet Construction / Sending
After we have parsed incoming packets and know how to respond, we will construct packets
to be sent back to the sender.

### Error Handler
In any of the three modules above, if an error is detected, we will handle it in this module.
