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
### parse_packet()
```python

```
Basil
### build_packet()
```python

```
Tyler
### send_packet()
```python

```

Basil
### handle_error()
```python

```

Send SYN and wait

Receive SYNACK and then send ACK

Start sending data

If multiple ACKs received (missing packet), then keep track of which packet(s) are lost

After done sending, resend all lost packets



## Data Structures

* Python list to keep track of data indicies in each packet so can easily resend



## Error Handling

* Implement selective repeat algorithm
* Checksum to ensure packet integrity

