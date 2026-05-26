# Sniffit
 
A Python raw socket packet sniffer that captures IPv4 packets from a network interface.


### Limitations
 
- The IPv4 **Options** field is not parsed (it is skipped entirely)
- The **Flags** field in the IPv4 header is not separated from the **Fragment Offset** (they are treated as a single combined value)

