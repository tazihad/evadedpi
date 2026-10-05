# 🔬 Evasion Techniques Deep Dive

EvadeDPI implements a comprehensive catalog of transport and application layer desynchronization techniques. This document explains the underlying mechanics of each method.

---

## 1. TLS ClientHello & SNI Segmentation

### The Problem
During an HTTPS connection, TLS establishes encrypted end-to-end communication. However, before keys are exchanged, the client transmits an unencrypted `ClientHello` message. This message contains the **Server Name Indication (SNI)** extension, which declares the target domain name in plaintext (e.g., `Host Name: youtube.com`).

DPI middleboxes passively sniff or actively filter on this plaintext field. If the SNI matches a blocked pattern, the middlebox terminates the connection.

### The Solution
TCP is a byte-stream protocol, not a packet protocol. A TLS record can be fragmented across multiple TCP packets at arbitrary byte boundaries.

```text
Original TLS ClientHello (Single Packet):
┌───────────────────────────────┬────────────────────────────┬────────────────────────┐
│ TLS Header + Ciphers          │ SNI Extension: youtube.com │ TLS Extensions         │
└───────────────────────────────┴────────────────────────────┴────────────────────────┘

EvadeDPI SNI Segmentation (Two Packets):
Packet 1:
┌───────────────────────────────┬─────────┐
│ TLS Header + Ciphers          │ SNI Pre │  ==> Sent with TCP_NODELAY + Flush
└───────────────────────────────┴─────────┘
   [Inter-segment delay: 2ms]
Packet 2:
┌────────────────────────┬────────────────────────────┐
│ fix: "youtube.com"     │ Remainder Extensions       │  ==> Sent after delay
└────────────────────────┴────────────────────────────┘
```

When Packet 1 arrives at the middlebox:
1. The middlebox parser checks for a complete SNI extension.
2. Because the packet terminates right before or inside the SNI domain, the extension length is truncated or incomplete.
3. High-throughput DPI hardware typically does not reassemble fragmented TCP streams due to memory constraints; it marks the packet as incomplete and forwards it.
4. When Packet 2 arrives, the middlebox has already treated the connection as evaluated.
5. The origin web server’s operating system reassembles the TCP byte stream and processes the complete ClientHello normally.

---

## 2. TLS Record Layer Fragmentation (`--tlsrec`)

### The Problem
Some advanced DPI middleboxes (such as modern TSPU in Russia) perform full TCP stream reassembly for individual packets to thwart standard TCP segmentation.

### The Solution
EvadeDPI implements **RFC-compliant TLS record layer splitting** (RFC 5246 Section 6.2.1, RFC 8446 Section 5.1):
> *"Client message fragments MAY be split across multiple TLS records of the same type."*

Instead of splitting a single TLS record across two TCP packets, EvadeDPI wraps the ClientHello into **two separate TLS records**:

```text
Record 1 (Header: 0x16 0x03 0x01 [Length N1]):
┌───────────────────────────────┬────────────────────────┐
│ Handshake Header              │ Partial ClientHello    │
└───────────────────────────────┴────────────────────────┘

Record 2 (Header: 0x16 0x03 0x01 [Length N2]):
┌────────────────────────────────────────────────────────┐
│ Remaining ClientHello (Contains SNI payload)           │
└────────────────────────────────────────────────────────┘
```

The DPI middlebox expects the entire ClientHello to reside in the first TLS record. Failing to locate the SNI in Record 1, it allows the flow. The web server's TLS engine seamlessly merges both records into one handshake message.

---

## 3. Decoy / Fake ClientHello Injection (`--fake`)

### The Problem
Stateful DPI systems maintain a session table tracking the state of each TCP 4-tuple (`SrcIP:SrcPort -> DstIP:DstPort`).

### The Solution
Before transmitting the genuine ClientHello, EvadeDPI transmits a decoy ClientHello:
1. **Decoy SNI**: Contains a harmless, globally permitted domain (e.g. `www.microsoft.com` or `cloudflare.com`).
2. **Low TTL (`--fake-ttl 4`)**: The IP packet is transmitted with a low Time-To-Live.
3. The DPI middlebox (typically 2 to 5 network hops away from the client inside the ISP’s edge network) receives the decoy packet. It inspects `www.microsoft.com`, marks the session in its state table as **ALLOWED**, and forwards the packet.
4. Because the TTL was small, the decoy packet expires in transit before reaching the real destination server.
5. EvadeDPI restores normal TTL (e.g. 64) and transmits the real ClientHello.
6. The DPI middlebox sees the subsequent packets on an already-whitelisted TCP connection and bypasses deep inspection entirely.

---

## 4. TCP Disordering / Out-of-Order Delivery (`--disorder`)

When transmitting segments, EvadeDPI can invert the order:
- **Step 1**: Transmit Segment 2 (containing the tail of the ClientHello).
- **Step 2**: Delay briefly (e.g. 2–5ms).
- **Step 3**: Transmit Segment 1 (containing the beginning of the ClientHello).

The remote server's TCP stack receives Segment 2, holds it in its retransmission/reorder queue, receives Segment 1, and passes the reassembled stream to the web application. DPI middleboxes that only inspect in-order streams fail to classify the connection.

---

## 5. TCP Out-Of-Band Data (`--oob`)

TCP allows transmitting urgent data with the `MSG_OOB` flag set, pointing the TCP Urgent Pointer to a single byte of out-of-band data.
- Stateful DPI middleboxes frequently track TCP sequence numbers strictly and miscalculate stream offsets when an urgent byte is encountered.
- Standard HTTP/TLS web servers do not read out-of-band data unless specifically configured to do so, safely ignoring the byte.

---

## 6. HTTP/1.1 Header Mutations

For unencrypted HTTP connections, EvadeDPI supports classic GoodbyeDPI and ByeDPI mutations:
1. **`mix_host`**: Mutates the case of the header name:
   `Host: example.com` ➔ `hoSt: example.com`
   (RFC 2616 / RFC 7230 states header names are case-insensitive; middlebox string matchers often look strictly for `Host:`).
2. **`host_space_trim`**: Removes the space following the colon:
   `Host:example.com`
3. **`extra_method_space`**: Adds an extra space between HTTP method and URI:
   `GET  /path HTTP/1.1`
4. **`newline_before_host`**: Inserts a carriage-return/line-feed (`\r\n`) before the `Host:` header.

---

## 7. QUIC / HTTP3 Blocking (`--block-quic`)

### Why Block QUIC?
QUIC (RFC 9000) runs over UDP port 443. While modern and performant, QUIC packets:
- Are encrypted from the initial packet with keys derived from connection IDs.
- Cannot be segmented using standard TCP byte-stream fragmentation tricks.
- If DPI hardware cannot inspect QUIC, it often employs crude UDP rate-limiting or outright UDP 443 packet drops.

By blocking QUIC UDP requests at the proxy layer, EvadeDPI forces the web browser to instantly downgrade to TCP HTTPS, where TLS segmentation and decoy injection operate with high reliability.

---

## 8. DNS-over-HTTPS (DoH)

Many censorship events begin with DNS hijacking:
- The ISP intercepts plaintext UDP port 53 DNS queries and returns forged IP addresses (e.g. `127.0.0.1`, `0.0.0.0`, or a government notice server).

EvadeDPI includes an asynchronous DoH client that queries trusted encrypted resolvers (Cloudflare `1.1.1.1`, Google `8.8.8.8`, Quad9, or AdGuard) over HTTPS. Resolved IP addresses are cached locally in memory with TTL respect, preventing DNS poisoning before the TCP connection is even initiated.
