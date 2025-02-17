/*
# Copyright 2025 University of California, Riverside
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

#ifndef PDI_RDMA_H
#define PDI_RDMA_H

#include <ngx_core.h>
#include <ngx_config.h>

#include "rdma_common_doca.h"

/* DOCA RDMA helpers */
void pdin_init_doca_rdma_client_ctx(ngx_int_t proc_id, void *cfg, ngx_cycle_t *cycle);
void pdin_destroy_doca_rdma_client_ctx(struct rdma_config *config, struct rdma_resources *resources);
int pdin_rdma_ctrl_path_client_connect(char *server_ip, uint16_t server_port);
ssize_t pdin_rdma_ctrl_path_client_read(int sock_fd, void *buffer, size_t len);
void pdin_init_rdma_config(struct rdma_config *cfg, ngx_int_t proc_id);
void pdin_rdma_send(void *ngx_http_request_pt, void *pdin_rdma_handler_pt, void *pdin_rdma_handler_log_pt, void *ngx_http_request_mempool_pt);
doca_error_t pdin_create_doca_log_backend(void);

#endif /* PDI_RDMA_H */