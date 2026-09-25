/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

/* Clearing CURLOPT_HAPROXY_CLIENT_IP must not switch off a PROXY protocol
   header that was asked for with CURLOPT_HAPROXYPROTOCOL.

   The curl tool never passes a NULL here, so this ordering is only reachable
   from an application and needs a libcurl test of its own. */

static CURLcode test_lib3234(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HAPROXYPROTOCOL, 1L);

  /* no address to spoof: the header must still be sent, carrying the real
     addresses of the connection */
  easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, (char *)NULL);

  result = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
