/* Copyright libuv contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "task.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK_HANDLE(handle) \
  ASSERT((uv_udp_t*)(handle) == &recver || (uv_udp_t*)(handle) == &sender)

#define BUFFER_MULTIPLIER 4
#define BUFFER_SIZE (BUFFER_MULTIPLIER * 64 * 1024)
#define NUM_SENDS 8
#define EXPECTED_MMSG_ALLOCS (NUM_SENDS / BUFFER_MULTIPLIER)

static uv_udp_t recver;
static uv_udp_t sender;
static int recv_cb_called;
static int close_cb_called;
static int alloc_cb_called;


static void alloc_cb(uv_handle_t* handle,
                     size_t suggested_size,
                     uv_buf_t* buf) {
  CHECK_HANDLE(handle);
  /* Actually malloc to exercise free'ing the buffer later */
  buf->base = malloc(BUFFER_SIZE);
  ASSERT(buf->base != NULL);
  buf->len = BUFFER_SIZE;
  alloc_cb_called++;
}


static void close_cb(uv_handle_t* handle) {
  CHECK_HANDLE(handle);
  ASSERT(uv_is_closing(handle));
  close_cb_called++;
}


static void recv_cb(uv_udp_t* handle,
                       ssize_t nread,
                       const uv_buf_t* rcvbuf,
                       const struct sockaddr* addr,
                       unsigned flags) {
  ASSERT_GE(nread, 0);

  if (nread > 0) {
    ASSERT_EQ(nread, 4);
    ASSERT(addr != NULL);
    ASSERT_MEM_EQ("PING", rcvbuf->base, nread);

    recv_cb_called++;
    if (recv_cb_called == NUM_SENDS) {
      uv_close((uv_handle_t*)handle, close_cb);
      uv_close((uv_handle_t*)&sender, close_cb);
    }
  }

  /* Don't free if the buffer could be reused via mmsg */
  if (rcvbuf && !(flags & UV_UDP_MMSG_CHUNK))
    free(rcvbuf->base);
}


TEST_IMPL(udp_mmsg) {
  struct sockaddr_in addr;
  uv_buf_t buf;
  int i;

  ASSERT_EQ(0, uv_ip4_addr("0.0.0.0", TEST_PORT, &addr));

  ASSERT_EQ(0, uv_udp_init_ex(uv_default_loop(), &recver,
                              AF_UNSPEC | UV_UDP_RECVMMSG));

  ASSERT_EQ(0, uv_udp_bind(&recver, (const struct sockaddr*) &addr, 0));

  ASSERT_EQ(0, uv_udp_recv_start(&recver, alloc_cb, recv_cb));

  ASSERT_EQ(0, uv_ip4_addr("127.0.0.1", TEST_PORT, &addr));

  ASSERT_EQ(0, uv_udp_init(uv_default_loop(), &sender));

  buf = uv_buf_init("PING", 4);
  for (i = 0; i < NUM_SENDS; i++) {
    ASSERT_EQ(4, uv_udp_try_send(&sender, &buf, 1, (const struct sockaddr*) &addr));
  }

  ASSERT_EQ(0, uv_run(uv_default_loop(), UV_RUN_DEFAULT));

  ASSERT_EQ(close_cb_called, 2);
  ASSERT_EQ(recv_cb_called, NUM_SENDS);

  ASSERT_EQ(sender.send_queue_size, 0);
  ASSERT_EQ(recver.send_queue_size, 0);

  printf("%d allocs for %d recvs\n", alloc_cb_called, recv_cb_called);

  /* On platforms that don't support mmsg, each recv gets its own alloc */
  ASSERT(alloc_cb_called == EXPECTED_MMSG_ALLOCS || alloc_cb_called == recv_cb_called);

  MAKE_VALGRIND_HAPPY();
  return 0;
}