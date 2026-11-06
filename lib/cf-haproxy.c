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
#include "curl_setup.h"

#ifndef CURL_DISABLE_PROXY

#include "urldata.h"
#include "cfilters.h"
#include "cf-haproxy.h"
#include "connect.h"
#include "curl_addrinfo.h"
#include "curlx/inet_pton.h"
#include "curl_trc.h"
#include "select.h"


typedef enum {
  HAPROXY_INIT,     /* init/default/no tunnel state */
  HAPROXY_SEND,     /* data_out being sent */
  HAPROXY_DONE      /* all work done */
} haproxy_state;

struct cf_haproxy_ctx {
  int state;
  struct dynbuf data_out;
};

static void cf_haproxy_ctx_free(struct cf_haproxy_ctx *ctx)
{
  if(ctx) {
    curlx_dyn_free(&ctx->data_out);
    curlx_free(ctx);
  }
}

/* The 12 byte protocol signature that starts every PROXY protocol v2
   header. */
static const unsigned char haproxy_v2_sig[12] = {
  0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
  0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
};

/* Append a PROXY protocol v2 header carrying the client's source and
   destination addresses and ports. Unlike v1, this is a binary format, so we
   convert the textual addresses back into their network representation and
   pass on the real endpoints (rather than UNSPEC), matching the intent of the
   protocol. */
static CURLcode cf_haproxy_v2_addr(struct dynbuf *out,
                                   bool is_ipv6,
                                   const char *src_ip,
                                   const char *dst_ip,
                                   unsigned short src_port,
                                   unsigned short dst_port)
{
  unsigned char hdr[16 + 36]; /* fixed 16 bytes + at most an IPv6 block (36) */
  unsigned char *p = hdr;
  size_t addrlen;

  memcpy(p, haproxy_v2_sig, sizeof(haproxy_v2_sig));
  p += sizeof(haproxy_v2_sig);
  *p++ = 0x21; /* protocol version 2 (0x20) | PROXY command (0x01) */

  if(is_ipv6) {
    unsigned char saddr[16];
    unsigned char daddr[16];
    if((curlx_inet_pton(AF_INET6, src_ip, saddr) != 1) ||
       (curlx_inet_pton(AF_INET6, dst_ip, daddr) != 1))
      return CURLE_COULDNT_CONNECT;
    *p++ = 0x21; /* AF_INET6 (0x20) | STREAM (0x01) */
    addrlen = 16 + 16 + 2 + 2;
    *p++ = (unsigned char)((addrlen >> 8) & 0xff);
    *p++ = (unsigned char)(addrlen & 0xff);
    memcpy(p, saddr, 16);
    p += 16;
    memcpy(p, daddr, 16);
    p += 16;
  }
  else {
    unsigned char saddr[4];
    unsigned char daddr[4];
    if((curlx_inet_pton(AF_INET, src_ip, saddr) != 1) ||
       (curlx_inet_pton(AF_INET, dst_ip, daddr) != 1))
      return CURLE_COULDNT_CONNECT;
    *p++ = 0x11; /* AF_INET (0x10) | STREAM (0x01) */
    addrlen = 4 + 4 + 2 + 2;
    *p++ = (unsigned char)((addrlen >> 8) & 0xff);
    *p++ = (unsigned char)(addrlen & 0xff);
    memcpy(p, saddr, 4);
    p += 4;
    memcpy(p, daddr, 4);
    p += 4;
  }

  /* source and destination ports, in network byte order */
  *p++ = (unsigned char)((src_port >> 8) & 0xff);
  *p++ = (unsigned char)(src_port & 0xff);
  *p++ = (unsigned char)((dst_port >> 8) & 0xff);
  *p++ = (unsigned char)(dst_port & 0xff);

  return curlx_dyn_addn(out, hdr, (size_t)(p - hdr));
}

/* Append a PROXY protocol v2 LOCAL header with no address information. Used
   when we cannot report meaningful addresses (e.g. over a Unix domain
   socket), mirroring the "PROXY UNKNOWN" case of version 1. */
#ifdef USE_UNIX_SOCKETS
static CURLcode cf_haproxy_v2_local(struct dynbuf *out)
{
  unsigned char hdr[16];
  memcpy(hdr, haproxy_v2_sig, sizeof(haproxy_v2_sig));
  hdr[12] = 0x20; /* protocol version 2 (0x20) | LOCAL command (0x00) */
  hdr[13] = 0x00; /* AF_UNSPEC | UNSPEC transport */
  hdr[14] = 0x00; /* address length high byte */
  hdr[15] = 0x00; /* address length low byte */
  return curlx_dyn_addn(out, hdr, sizeof(hdr));
}
#endif /* USE_UNIX_SOCKETS */

/* Maximum length of a PROXY protocol v2 AF_UNIX address field. */
#define HAPROXY_V2_UNIX_PATH_LEN 108

/* Append a PROXY protocol v2 header for the AF_UNIX address family, carrying
   the given source and destination socket paths. Each path occupies a fixed
   108 byte, NUL-padded field. */
static CURLcode cf_haproxy_v2_unix(struct dynbuf *out,
                                   const char *src_path,
                                   const char *dst_path)
{
  unsigned char hdr[16 + 2 * HAPROXY_V2_UNIX_PATH_LEN];
  unsigned char *p = hdr;
  size_t slen = strlen(src_path);
  size_t dlen = strlen(dst_path);
  size_t addrlen = 2 * HAPROXY_V2_UNIX_PATH_LEN;

  if((slen > HAPROXY_V2_UNIX_PATH_LEN) || (dlen > HAPROXY_V2_UNIX_PATH_LEN))
    /* the path does not fit the fixed-size address field */
    return CURLE_BAD_FUNCTION_ARGUMENT;

  memcpy(p, haproxy_v2_sig, sizeof(haproxy_v2_sig));
  p += sizeof(haproxy_v2_sig);
  *p++ = 0x21; /* protocol version 2 (0x20) | PROXY command (0x01) */
  *p++ = 0x31; /* AF_UNIX (0x30) | STREAM (0x01) */
  *p++ = (unsigned char)((addrlen >> 8) & 0xff);
  *p++ = (unsigned char)(addrlen & 0xff);
  memset(p, 0, addrlen);
  memcpy(p, src_path, slen);
  memcpy(p + HAPROXY_V2_UNIX_PATH_LEN, dst_path, dlen);
  p += addrlen;

  return curlx_dyn_addn(out, hdr, (size_t)(p - hdr));
}

static CURLcode cf_haproxy_date_out_set(struct Curl_cfilter *cf,
                                        struct Curl_easy *data)
{
  /* We fake a client connection report to the upstream server
   * with the HAProxy protocol, reporting the client's source
   * and destination IP addresses and ports.
   * addresses: either the ones used to talk to the upstream
   *            OR the value supplied by the user
   * ports: the ports used in the upstream connection */
  struct cf_haproxy_ctx *ctx = cf->ctx;
  CURLcode result;
  struct ip_quadruple ipquad;
  bool is_ipv6;
  bool v2 = (data->set.haproxyprotocol == CURLHAPROXY_V2);
  const char *client_ip = CURL_EASY_STR(data, STRING_HAPROXY_CLIENT_IP);
  const char *client_path = CURL_EASY_STR(data, STRING_HAPROXY_CLIENT_PATH);

  DEBUGASSERT(ctx);
  DEBUGASSERT(ctx->state == HAPROXY_INIT);

  /* A user-supplied UNIX socket path is reported using the AF_UNIX address
     family, which only exists in the version 2 header. */
  if(v2 && client_path)
    return cf_haproxy_v2_unix(&ctx->data_out, client_path, client_path);

  /* A user-supplied client IP is reported regardless of the actual transport,
     so it works for a real Unix socket connection too. The ports of such a
     connection are not available, so zero is used for them. */
  if(client_ip) {
    is_ipv6 = !Curl_is_ipv4addr(client_ip);
#ifdef USE_UNIX_SOCKETS
    if(Curl_conn_get_first_peer(cf->conn, cf->sockindex)->unix_socket) {
      if(v2)
        return cf_haproxy_v2_addr(&ctx->data_out, is_ipv6,
                                  client_ip, client_ip, 0, 0);
      return curlx_dyn_addf(&ctx->data_out, "PROXY %s %s %s 0 0\r\n",
                            is_ipv6 ? "TCP6" : "TCP4", client_ip, client_ip);
    }
#endif /* USE_UNIX_SOCKETS */
  }

#ifdef USE_UNIX_SOCKETS
  else if(Curl_conn_get_first_peer(cf->conn, cf->sockindex)->unix_socket) {
    /* A real Unix socket connection with no spoofed address has no client
       address to report. */
    if(v2)
      return cf_haproxy_v2_local(&ctx->data_out);
    return curlx_dyn_addn(&ctx->data_out, STRCONST("PROXY UNKNOWN\r\n"));
  }
#endif /* USE_UNIX_SOCKETS */

  /* A real TCP connection: report the actual endpoints, or the spoofed client
     IP with the real ports. */
  result = Curl_conn_cf_get_ip_info(cf->next, data, &is_ipv6, &ipquad);
  if(result)
    return result;

  if(!client_ip) {
    client_ip = ipquad.local_ip;
    if(v2)
      result = cf_haproxy_v2_addr(&ctx->data_out, is_ipv6,
                                  ipquad.local_ip, ipquad.remote_ip,
                                  ipquad.local_port, ipquad.remote_port);
    else
      result = curlx_dyn_addf(&ctx->data_out, "PROXY %s %s %s %d %d\r\n",
                              is_ipv6 ? "TCP6" : "TCP4",
                              ipquad.local_ip, ipquad.remote_ip,
                              ipquad.local_port, ipquad.remote_port);
  }
  else {
    is_ipv6 = !Curl_is_ipv4addr(client_ip);
    if(v2)
      result = cf_haproxy_v2_addr(&ctx->data_out, is_ipv6,
                                  client_ip, client_ip,
                                  ipquad.local_port, ipquad.remote_port);
    else
      result = curlx_dyn_addf(&ctx->data_out, "PROXY %s %s %s %d %d\r\n",
                              is_ipv6 ? "TCP6" : "TCP4",
                              client_ip, client_ip,
                              ipquad.local_port, ipquad.remote_port);
  }
  return result;
}

static CURLcode cf_haproxy_connect(struct Curl_cfilter *cf,
                                   struct Curl_easy *data,
                                   bool *done)
{
  struct cf_haproxy_ctx *ctx = cf->ctx;
  CURLcode result;
  size_t len;

  DEBUGASSERT(ctx);
  if(cf->connected) {
    *done = TRUE;
    return CURLE_OK;
  }

  result = cf->next->cft->do_connect(cf->next, data, done);
  if(result || !*done)
    return result;

  switch(ctx->state) {
  case HAPROXY_INIT:
    result = cf_haproxy_date_out_set(cf, data);
    if(result)
      goto out;
    ctx->state = HAPROXY_SEND;
    FALLTHROUGH();
  case HAPROXY_SEND:
    len = curlx_dyn_len(&ctx->data_out);
    if(len > 0) {
      size_t nwritten;
      result = Curl_conn_cf_send(cf->next, data,
                                 curlx_dyn_uptr(&ctx->data_out), len, FALSE,
                                 &nwritten);
      if(result) {
        if(result != CURLE_AGAIN)
          goto out;
        result = CURLE_OK;
        nwritten = 0;
      }
      curlx_dyn_tail(&ctx->data_out, len - nwritten);
      if(curlx_dyn_len(&ctx->data_out) > 0) {
        result = CURLE_OK;
        goto out;
      }
    }
    ctx->state = HAPROXY_DONE;
    FALLTHROUGH();
  default:
    curlx_dyn_free(&ctx->data_out);
    break;
  }

out:
  *done = (!result) && (ctx->state == HAPROXY_DONE);
  cf->connected = *done;
  return result;
}

static void cf_haproxy_destroy(struct Curl_cfilter *cf,
                               struct Curl_easy *data)
{
  CURL_TRC_CF(data, cf, "destroy");
  cf_haproxy_ctx_free(cf->ctx);
}

static CURLcode cf_haproxy_adjust_pollset(struct Curl_cfilter *cf,
                                          struct Curl_easy *data,
                                          struct easy_pollset *ps)
{
  if(cf->next->connected && !cf->connected) {
    /* If we are not connected, but the filter "below" is
     * and not waiting on something, we are sending. */
    return Curl_pollset_set_out_only(
      data, ps, Curl_conn_cf_get_socket(cf, data));
  }
  return CURLE_OK;
}

struct Curl_cftype Curl_cft_haproxy = {
  "HAPROXY",
  CF_TYPE_PROXY | CF_TYPE_SETUP,
  0,
  cf_haproxy_destroy,
  cf_haproxy_connect,
  Curl_cf_def_shutdown,
  cf_haproxy_adjust_pollset,
  Curl_cf_def_data_pending,
  Curl_cf_def_send,
  Curl_cf_def_recv,
  Curl_cf_def_cntrl,
  Curl_cf_def_conn_is_alive,
  Curl_cf_def_conn_keep_alive,
  Curl_cf_def_query,
};

static CURLcode cf_haproxy_create(struct Curl_cfilter **pcf,
                                  struct Curl_easy *data)
{
  struct Curl_cfilter *cf = NULL;
  struct cf_haproxy_ctx *ctx;
  CURLcode result;

  (void)data;
  ctx = curlx_calloc(1, sizeof(*ctx));
  if(!ctx) {
    result = CURLE_OUT_OF_MEMORY;
    goto out;
  }
  ctx->state = HAPROXY_INIT;
  curlx_dyn_init(&ctx->data_out, DYN_HAXPROXY);

  result = Curl_cf_create(&cf, &Curl_cft_haproxy, ctx);
  if(result)
    goto out;
  ctx = NULL;

out:
  cf_haproxy_ctx_free(ctx);
  *pcf = result ? NULL : cf;
  return result;
}

CURLcode Curl_cf_haproxy_insert_after(struct Curl_cfilter *cf_at,
                                      struct Curl_easy *data)
{
  struct Curl_cfilter *cf;
  CURLcode result;

  result = cf_haproxy_create(&cf, data);
  if(result)
    goto out;
  Curl_conn_cf_insert_after(cf_at, cf);

out:
  return result;
}

#endif /* !CURL_DISABLE_PROXY */
