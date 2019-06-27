// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "socket.h"
#include "common.h"
#include "syscall.h"

ssize_t ve_recvmsg(int sockfd, struct ve_msghdr* msg, int flags)
{
    long x1 = (long)sockfd;
    long x2 = (long)msg;
    long x3 = (long)flags;
    return (ssize_t)ve_syscall6(VE_SYS_recvmsg, x1, x2, x3, 0, 0, 0);
}
