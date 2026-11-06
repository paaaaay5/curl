---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HAPROXY_CLIENT_PATH
Section: 3
Source: libcurl
Protocol:
  - All
See-also:
  - CURLOPT_HAPROXYPROTOCOL (3)
  - CURLOPT_HAPROXY_CLIENT_IP (3)
  - CURLOPT_PROXY (3)
Added-in: 8.23.0
---

# NAME

CURLOPT_HAPROXY_CLIENT_PATH - set HAProxy PROXY protocol client UNIX path

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HAPROXY_CLIENT_PATH,
                          char *client_path);
~~~

# DESCRIPTION

When this parameter is set to a UNIX socket path, the library sends this as
the client address in a HAProxy PROXY protocol v2 header at the beginning of
the connection, using the AF_UNIX address family.

The path is reported upstream as the source *and* destination address of the
non-existing client connection. The path must not be longer than 108 bytes,
which is the size of the fixed-length address field in the protocol.

The AF_UNIX address family only exists in version 2 of the PROXY protocol, so
setting this option enables the version 2 header (see
CURLOPT_HAPROXYPROTOCOL(3)). It takes precedence over
CURLOPT_HAPROXY_CLIENT_IP(3) when both are set.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL, no HAProxy header is sent

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_PATH, "/run/client.sock");
    result = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
