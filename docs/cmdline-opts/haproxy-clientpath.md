---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: haproxy-clientpath
Arg: <path>
Help: Set UNIX socket path in HAProxy PROXY v2
Protocols: HTTP
Added: 8.23.0
Category: http proxy
Multi: single
See-also:
  - haproxy-protocol-v2
  - haproxy-clientip
  - proxy
Example:
  - --haproxy-protocol-v2 --haproxy-clientpath /run/client.sock $URL
---

# `--haproxy-clientpath`

Set a client UNIX socket path to send in a HAProxy PROXY protocol v2 header,
using the AF_UNIX address family.

The AF_UNIX address family only exists in version 2 of the protocol, so this
option implies --haproxy-protocol-v2. The provided path is sent as both the
source and destination address and must not be longer than 108 bytes. This is
primarily useful when testing a service that consumes AF_UNIX addresses from
the PROXY protocol.
