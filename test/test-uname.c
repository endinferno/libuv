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

#include "task.h"
#include "uv.h"
#include <string.h>

#include <sys/utsname.h>

TEST_IMPL(uname)
{
    struct utsname buf;
    uv_utsname_t buffer;
    int r;

    /* Verify that NULL is handled properly. */
    r = uv_os_uname(NULL);
    ASSERT_EQ(r, UV_EINVAL);

    /* Verify the happy path. */
    r = uv_os_uname(&buffer);
    ASSERT_OK(r);

    ASSERT_NE(uname(&buf), -1);
    ASSERT_OK(strcmp(buffer.sysname, buf.sysname));
    ASSERT_OK(strcmp(buffer.version, buf.version));
    ASSERT_OK(strcmp(buffer.release, buf.release));
    ASSERT_OK(strcmp(buffer.machine, buf.machine));

    return 0;
}
