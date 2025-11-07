# Requirements

## Functionality
What should the system do?
Our UDP implementation shall be able to:
- ensure correct ordering of packets
- acknowledge when a packet has been received
- identify and retransmit dropped packets
- detect corrupted packets
- control congestion

## Performance
Goals for speed
- UDP is faster than TCP in its standard form, however we will be adding into
UDP the features that make TCP slower
- We expect the performance of our UDP implementation to be the same
as TCP

## Compatibility
With standards or with existing systems

## Security
- TCP and UDP do not have any encryption, as that is implemented in the
layer above via TLS, so we will not include it
- We will detect corrupted packets

## Timeline
* Req and Imp Spec due on Tuesday 11th Nov
* Project code and demo due on Saturday 22nd Nov
We plan to be done coding by the 18th of November so we can test with hardware if possible.
