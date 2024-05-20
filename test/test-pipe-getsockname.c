/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
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

#include "task.h"
#include "uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h> /* close */

static uv_pipe_t pipe_client;
static uv_pipe_t pipe_server;
static uv_connect_t connect_req;

static int pipe_close_cb_called = 0;
static int pipe_client_connect_cb_called = 0;


static void pipe_close_cb(uv_handle_t* handle)
{
    ASSERT_NE(handle == (uv_handle_t*)&pipe_client ||
                  handle == (uv_handle_t*)&pipe_server,
              0);
    pipe_close_cb_called++;
}


static void pipe_client_connect_cb(uv_connect_t* req, int status)
{
    char buf[1024];
    size_t len;
    int r;

    ASSERT_PTR_EQ(req, &connect_req);
    ASSERT_OK(status);

    len = sizeof buf;
    r = uv_pipe_getpeername(&pipe_client, buf, &len);
    ASSERT_OK(r);

    if (*buf == '\0') { /* Linux abstract socket. */
        const char expected[] = "\0" TEST_PIPENAME;
        ASSERT_EQ(len, sizeof(expected) - 1);
        ASSERT_MEM_EQ(buf, expected, len);
    } else {
        ASSERT_NE(0, buf[len - 1]);
        ASSERT_MEM_EQ(buf, TEST_PIPENAME, len);
    }

    len = sizeof buf;
    r = uv_pipe_getsockname(&pipe_client, buf, &len);
    ASSERT(r == 0 && len == 0);

    pipe_client_connect_cb_called++;

    uv_close((uv_handle_t*)&pipe_client, pipe_close_cb);
    uv_close((uv_handle_t*)&pipe_server, pipe_close_cb);
}


static void pipe_server_connection_cb(uv_stream_t* handle, int status)
{
    /* This function *may* be called, depending on whether accept or the
     * connection callback is called first.
     */
    ASSERT_OK(status);
}


TEST_IMPL(pipe_getsockname)
{
    uv_loop_t* loop;
    char namebuf[256];
    char buf[1024];
    size_t namelen;
    size_t len;
    int r;

    snprintf(namebuf, sizeof(namebuf), "%s-oob", TEST_PIPENAME);
    namelen = sizeof(TEST_PIPENAME) - 1;

    loop = uv_default_loop();
    ASSERT_NOT_NULL(loop);

    r = uv_pipe_init(loop, &pipe_server, 0);
    ASSERT_OK(r);

    r = uv_pipe_bind2(&pipe_server, "bad\0path", 8, 0);
    ASSERT_EQ(r, UV_EINVAL);

    len = sizeof buf;
    r = uv_pipe_getsockname(&pipe_server, buf, &len);
    ASSERT_EQ(r, UV_EBADF);

    len = sizeof buf;
    r = uv_pipe_getpeername(&pipe_server, buf, &len);
    ASSERT_EQ(r, UV_EBADF);

    r = uv_pipe_bind2(&pipe_server, namebuf, namelen, 0);
    ASSERT_OK(r);

    ASSERT_STR_EQ(pipe_server.pipe_fname, TEST_PIPENAME);

    len = sizeof buf;
    r = uv_pipe_getsockname(&pipe_server, buf, &len);
    ASSERT_OK(r);

    ASSERT_NE(0, buf[len - 1]);
    ASSERT_EQ(buf[len], '\0');
    ASSERT_OK(memcmp(buf, TEST_PIPENAME, len));

    len = sizeof buf;
    r = uv_pipe_getpeername(&pipe_server, buf, &len);
    ASSERT_EQ(r, UV_ENOTCONN);

    r = uv_listen((uv_stream_t*)&pipe_server, 0, pipe_server_connection_cb);
    ASSERT_OK(r);

    r = uv_pipe_init(loop, &pipe_client, 0);
    ASSERT_OK(r);

    len = sizeof buf;
    r = uv_pipe_getsockname(&pipe_client, buf, &len);
    ASSERT_EQ(r, UV_EBADF);

    len = sizeof buf;
    r = uv_pipe_getpeername(&pipe_client, buf, &len);
    ASSERT_EQ(r, UV_EBADF);

    r = uv_pipe_connect2(&connect_req,
                         &pipe_client,
                         namebuf,
                         namelen,
                         0,
                         pipe_client_connect_cb);
    ASSERT_OK(r);

    len = sizeof buf;
    r = uv_pipe_getsockname(&pipe_client, buf, &len);
    ASSERT(r == 0 && len == 0);

    len = sizeof buf;
    r = uv_pipe_getpeername(&pipe_client, buf, &len);
    ASSERT_OK(r);

    ASSERT_NE(0, buf[len - 1]);
    ASSERT_OK(memcmp(buf, TEST_PIPENAME, len));

    r = uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_OK(r);
    ASSERT_EQ(1, pipe_client_connect_cb_called);
    ASSERT_EQ(2, pipe_close_cb_called);

    MAKE_VALGRIND_HAPPY(loop);
    return 0;
}


TEST_IMPL(pipe_getsockname_abstract)
{
    /* TODO(bnoordhuis) Use unique name, susceptible to concurrent test runs. */
    static const char name[] = "\0" TEST_PIPENAME;
    char buf[256];
    size_t buflen;

    buflen = sizeof(buf);
    memset(buf, 0, sizeof(buf));
    ASSERT_OK(uv_pipe_init(uv_default_loop(), &pipe_server, 0));
    ASSERT_OK(uv_pipe_bind2(&pipe_server, name, sizeof(name) - 1, 0));
    ASSERT_OK(uv_pipe_getsockname(&pipe_server, buf, &buflen));
    ASSERT_UINT64_EQ(sizeof(name) - 1, buflen);
    ASSERT_MEM_EQ(name, buf, buflen);
    ASSERT_OK(
        uv_listen((uv_stream_t*)&pipe_server, 0, pipe_server_connection_cb));
    ASSERT_OK(uv_pipe_init(uv_default_loop(), &pipe_client, 0));
    ASSERT_OK(uv_pipe_connect2(&connect_req,
                               &pipe_client,
                               name,
                               sizeof(name) - 1,
                               0,
                               pipe_client_connect_cb));
    ASSERT_OK(uv_run(uv_default_loop(), UV_RUN_DEFAULT));
    ASSERT_EQ(1, pipe_client_connect_cb_called);
    ASSERT_EQ(2, pipe_close_cb_called);
    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}

TEST_IMPL(pipe_getsockname_blocking)
{
    MAKE_VALGRIND_HAPPY(uv_default_loop());
    return 0;
}
