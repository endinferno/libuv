/* Copyright libuv project contributors. All rights reserved.
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

#include <stdlib.h>

#if defined(PTHREAD_BARRIER_SERIAL_THREAD)
STATIC_ASSERT(sizeof(uv_barrier_t) == sizeof(pthread_barrier_t));
#endif

/* Note: guard clauses should match uv_barrier_t's in include/uv/unix.h. */
int uv_barrier_init(uv_barrier_t* barrier, unsigned int count)
{
    return UV__ERR(pthread_barrier_init(barrier, NULL, count));
}


int uv_barrier_wait(uv_barrier_t* barrier)
{
    int rc;

    rc = pthread_barrier_wait(barrier);
    if (rc != 0)
        if (rc != PTHREAD_BARRIER_SERIAL_THREAD)
            abort();

    return rc == PTHREAD_BARRIER_SERIAL_THREAD;
}


void uv_barrier_destroy(uv_barrier_t* barrier)
{
    if (pthread_barrier_destroy(barrier))
        abort();
}
