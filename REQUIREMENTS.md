# Requirements

## Functionality
Our UDP implementation shall be able to:
* ensure correct ordering of packets
* acknowledge when a packet has been received
* identify and retransmit dropped packets
* detect corrupted packets
* control congestion

## Security
* We will detect corrupted packets

## Testing
* We need to test that we can successfully make a handshake
* We need to test that we can successfully transfer data packets
* We need to handle the scenario when packets are dropped (whether during a handshake or data transfer)
* We need to handle the scenario when packets are malformed (i.e. a bit flips during transfer)

## Timeline
* Req and Imp Spec due on Tuesday 11th Nov
* Project code and demo due on Saturday 22nd Nov
We plan to be done coding by the 18th of November so we can test with hardware if possible.
