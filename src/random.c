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

#include "uv-common.h"
#include "uv.h"

#include "unix/internal.h"

static int uv__random(void* buf, size_t buflen)
{
    int rc;

    rc = uv__random_getrandom(buf, buflen);
    if (rc == UV_ENOSYS)
        rc = uv__random_devurandom(buf, buflen);
    switch (rc) {
    case UV_EACCES:
    case UV_EIO:
    case UV_ELOOP:
    case UV_EMFILE:
    case UV_ENFILE:
    case UV_ENOENT:
    case UV_EPERM: rc = uv__random_sysctl(buf, buflen); break;
    }

    return rc;
}


static void uv__random_work(struct uv__work* w)
{
    uv_random_t* req;

    req = container_of(w, uv_random_t, work_req);
    req->status = uv__random(req->buf, req->buflen);
}


static void uv__random_done(struct uv__work* w, int status)
{
    uv_random_t* req;

    req = container_of(w, uv_random_t, work_req);
    uv__req_unregister(req->loop, req);

    if (status == 0)
        status = req->status;

    req->cb(req, status, req->buf, req->buflen);
}


int uv_random(uv_loop_t* loop, uv_random_t* req, void* buf, size_t buflen,
              unsigned flags, uv_random_cb cb)
{
    if (buflen > 0x7FFFFFFFu)
        return UV_E2BIG;

    if (flags != 0)
        return UV_EINVAL;

    if (cb == NULL)
        return uv__random(buf, buflen);

    uv__req_init(loop, req, UV_RANDOM);
    req->loop = loop;
    req->status = 0;
    req->cb = cb;
    req->buf = buf;
    req->buflen = buflen;

    uv__work_submit(
        loop, &req->work_req, UV__WORK_CPU, uv__random_work, uv__random_done);

    return 0;
}
