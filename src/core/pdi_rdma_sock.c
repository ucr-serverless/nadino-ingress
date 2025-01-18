/*
# Copyright 2024 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "pdi_rdma_sock.h"

ngx_log_t * rdma_log;

ssize_t sock_utils_read(int sock_fd, void *buffer, ssize_t len)
{
    ssize_t nr, tot_read;
    char *buf = buffer; // avoid pointer arithmetic on void pointer
    tot_read = 0;

    while (len != 0 && (nr = read(sock_fd, buf, len)) != 0)
    {
        if (nr < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                return -1;
            }
        }
        len -= nr;
        buf += nr;
        tot_read += nr;
    }

    return tot_read;
}

ssize_t sock_utils_write(int sock_fd, void *buffer, ssize_t len)
{
    ssize_t nw, tot_written;
    const char *buf = buffer; // avoid pointer arithmetic on void pointer

    for (tot_written = 0; tot_written < len;)
    {
        nw = write(sock_fd, buf, len - tot_written);

        if (nw <= 0)
        {
            if (nw == -1 && errno == EINTR)
            {
                continue;
            }
            else
            {
                return -1;
            }
        }

        tot_written += nw;
        buf += nw;
    }
    return tot_written;
}

int sock_utils_bind(char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sock_fd = -1, ret = 0;
    int opt = 1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(NULL, port, &hints, &result);
    if (ret != 0)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "Error, fail to create sock bind");
        goto error;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd < 0)
        {
            continue;
        }

        // Set SO_REUSEADDR to reuse the address
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            perror("setsockopt(SO_REUSEADDR) failed");
            close(sock_fd);
            return -1;
        }

        ret = bind(sock_fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0)
        {
            /* bind success */
            break;
        }

        close(sock_fd);
        sock_fd = -1;
    }
    if (rp == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "Error, create socket");
        goto error;
    }

    freeaddrinfo(result);
    return sock_fd;

error:
    if (result)
    {
        freeaddrinfo(result);
    }
    if (sock_fd > 0)
    {
        close(sock_fd);
    }
    return -1;
}

int sock_utils_connect(char *server_name, char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sock_fd = -1, ret = 0;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    ret = getaddrinfo(server_name, port, &hints, &result);
    if (ret != 0)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "Error, create sock %s", gai_strerror(ret));
        goto error;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd == -1)
        {
            continue;
        }

        ret = connect(sock_fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0)
        {
            /* connection success */
            break;
        }

        close(sock_fd);
        sock_fd = -1;
    }

    if (rp == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "Error, could not connect sock");
        goto error;
    }

    freeaddrinfo(result);
    return sock_fd;

error:
    if (result)
    {
        freeaddrinfo(result);
    }
    if (sock_fd != -1)
    {
        close(sock_fd);
    }
    return -1;
}

int set_socket_nonblocking(int sockfd)
{
    // Get the current file descriptor flags
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "get sock current flag fail", strerror(errno));
        return -1;
    }

    // Set the socket to non-blocking mode
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "get sock current flag fail", strerror(errno));
        return -1;
    }
    return 0;
}
