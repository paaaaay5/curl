---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: haproxy-protocol-v2
Help: Send HAProxy PROXY protocol v2 header
Protocols: HTTP
Added: 8.23.0
Category: http proxy
Multi: boolean
See-also:
  - haproxy-protocol
  - haproxy-clientip
  - proxy
Example:
  - --haproxy-protocol-v2 $URL
---

# `--haproxy-protocol-v2`

Send a HAProxy PROXY protocol v2 header at the beginning of the connection.
This is the binary variant of the PROXY protocol and is used by some load
balancers and reverse proxies to indicate the client's true IP address and
port.

Unlike the version 1 header sent by --haproxy-protocol, the version 2 header
is binary. curl reports the real source and destination addresses and ports
(or the address set with --haproxy-clientip) using the TCP over IPv4 or TCP
over IPv6 address family as appropriate. When the connection is made over a
Unix domain socket, a version 2 LOCAL header with no address information is
sent instead.

This option is primarily useful when sending test requests to a service that
expects this header.
