// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#pragma warning(disable : 4996)

#include <assert.h>
#include <fcntl.h>
#include <openenclave/host.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "myfileio.h"

int mbed_test_open(const char* path, int flags, mode_t mode)
{
#ifdef _WIN32
    return _open(path, flags, mode);
#else
    return open(path, flags, mode);
#endif
}

ssize_t mbed_test_read(int fd, char* buf, size_t buf_len)
{
#ifdef _WIN32
    return _read(fd, buf, (int)buf_len);
#else
    return read(fd, buf, (int)buf_len);
#endif
}

int mbed_test_close(int fd)
{
#ifdef _WIN32
    return _close(fd);
#else
    return close(fd);
#endif
}

int mbed_test_lseek(int fd, int offset, int whence)
{
#ifdef _WIN32
    return _lseek(fd, offset, whence);
#else
    return lseek(fd, offset, whence);
#endif
}
