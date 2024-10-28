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
#ifndef _PDI_RDMA_SOCK_H
#define _PDI_RDMA_SOCK_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <inttypes.h>
#include <stdlib.h>
#include "pdi_rdma_config.h"


ssize_t sock_utils_read(int sock_fd, void *buffer, ssize_t len);
ssize_t sock_utils_write(int sock_fd, void *buffer, ssize_t len);

int sock_utils_bind(char *port);
int sock_utils_connect(char *server_name, char *port);

int set_socket_nonblocking(int sockfd);

#endif
