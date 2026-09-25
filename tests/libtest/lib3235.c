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

/* An empty CURLOPT_HAPROXY_CLIENT_IP must be rejected. Accepting it used to
   leave the address fields of the PROXY protocol header empty, which makes the
   header syntactically invalid.

   Addresses that are not valid IP addresses are still accepted, as documented.

   The curl tool rejects a blank argument on its own, so this is only reachable
   from an application. */

static CURLcode test_lib3235(const char *URL)
{
  CURL *curl = NULL;
  CURLcode result = CURLE_OK;
  CURLcode ret;

  start_test_timing();

  global_init(CURL_GLOBAL_ALL);
  easy_init(curl);

  easy_setopt(curl, CURLOPT_URL, URL);
  easy_setopt(curl, CURLOPT_HAPROXYPROTOCOL, 1L);

  ret = curl_easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, "");
  if(ret != CURLE_BAD_FUNCTION_ARGUMENT) {
    curl_mfprintf(stderr, "an empty client IP returned %d, expected %d\n",
                  (int)ret, (int)CURLE_BAD_FUNCTION_ARGUMENT);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* a non-address string is not verified and gets sent as-is */
  ret = curl_easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, "not-an-ip");
  if(ret != CURLE_OK) {
    curl_mfprintf(stderr, "an unverified client IP returned %d, expected 0\n",
                  (int)ret);
    result = TEST_ERR_FAILURE;
    goto test_cleanup;
  }

  /* back to no address, so the header carries the real ones */
  easy_setopt(curl, CURLOPT_HAPROXY_CLIENT_IP, (char *)NULL);

  result = curl_easy_perform(curl);

test_cleanup:

  curl_easy_cleanup(curl);
  curl_global_cleanup();

  return result;
}
