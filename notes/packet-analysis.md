# Packet Analysis Notes
## DNS Evidence

- Filter: `dns.qry.name == "example.com"`
- A query packet: 330
- A response packet: 331
- AAAA query packet: 332
- AAAA response packet: 333
- Resolver: `137.82.1.1`
- Returned IPv4 addresses: `104.20.23.154`, `172.66.147.243`
- Interpretation: Normal DNS resolution for IPv4 and IPv6 addresses.

## HTTPS/TLS Evidence

- Filter: `tls.handshake.type == 1`
- Client Hello packet: 866
- Destination: 104.20.23.154
- Interpretation: TLS negotiation preceding encrypted communication.

## HTTP Evidence

- Filter: `http.request.method == "POST"`
- POST packet: 441
- TCP stream: 4
- Request path: `/login`
- Visible body: `username=myusername&password=mypassword818`
- Interpretation: Fake credentials were readable because HTTP did not
  encrypt the request body.

## SYN-Scan Evidence

- Filter: `ip.addr == 127.0.0.1 && tcp.flags.syn == 1 && tcp.flags.ack == 0`
- Source: `127.0.0.1`
- Destination: `127.0.0.1`
- Tested ports: `1-1000,8000`
- Interpretation: Multiple connection attempts across different ports
  in a short time window indicate port enumeration.

