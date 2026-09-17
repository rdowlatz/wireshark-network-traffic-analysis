# wireshark-network-traffic-analysis
Controlled analysis of DNS, HTTPS, plaintext HTTP, and TCP SYN scan traffic using Wireshark and Nmap.
### DNS Analysis

Packets 330–333 show DNS resolution for `example.com`. The client first
requested an IPv4 address using an A query and received two IPv4
addresses. It then requested IPv6 addresses using an AAAA query and
received two IPv6 addresses.

- A query: Packet 330
- A response: Packet 331
- Returned IPv4 addresses: `104.20.23.154`, `172.66.147.243`
- AAAA query: Packet 332
- AAAA response: Packet 333

The matching transaction IDs connect each request to its corresponding
response.
