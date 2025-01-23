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

#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>

#include "rdma_common_doca.h"

#define MAX_MSG_BUF_SIZE 10240

struct dummy_msg *dummy_msg_alloc(void);
void dummy_msg_free_burst(struct dummy_msg **pkts_burst, uint16_t nb_pkts);

int pdin_init_worker_rings(ngx_cycle_t *cycle);
uint16_t pdin_rdma_tx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst);
int pdin_rdma_rx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst, uint16_t nb_pkts);
uint16_t pdin_ngx_rx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst);
int pdin_ngx_tx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst, uint16_t nb_pkts);

ngx_int_t init_unix_domain_sock(ngx_cycle_t *cycle);
void ud_sock_send_message_to_worker(ngx_cycle_t *cycle);
void ud_sock_receive_message_from_worker();

void pdin_test_ngx_worker_tx(void);
void pdin_test_ngx_worker_rx(void);
void pdin_test_rdma_worker_bounce(ngx_cycle_t *cycle);

struct pdin_rdma_md_s {
    /* pointer to received HTTP request */
    void *ngx_http_request_pt;
    /* pointer to callback handler */
    void *pdin_rdma_handler_pt;
    /* pointer to handler log */
    void *pdin_rdma_handler_log_pt;
    /* pointer to request mempool */
    void *ngx_http_request_mempool_pt;
} __attribute__((packed)) __rte_cache_aligned;

struct pdin_rdma_md_s *pdin_rdma_md_alloc(void);
void pdin_rdma_md_free(struct pdin_rdma_md_s *md);
int pdin_init_md_rings(ngx_cycle_t *cycle);
void pdin_rdma_write_rte_ring(ngx_int_t proc_id, struct pdin_rdma_md_s *md);
struct pdin_rdma_md_s *pdin_rdma_read_rte_ring(ngx_int_t proc_id);

/* DOCA RDMA helpers */
void pdin_init_doca_rdma_client_ctx(ngx_int_t proc_id, void *cfg, ngx_cycle_t *cycle);
void pdin_destroy_doca_rdma_client_ctx(struct rdma_config *config, struct rdma_resources *resources);
int pdin_rdma_ctrl_path_client_connect(char *server_ip, uint16_t server_port);
ssize_t pdin_rdma_ctrl_path_client_read(int sock_fd, void *buffer, size_t len);
void pdin_init_rdma_config(struct rdma_config *cfg, ngx_int_t proc_id);
void pdin_rdma_send(void *ngx_http_request_pt, void *pdin_rdma_handler_pt, void *pdin_rdma_handler_log_pt, void *ngx_http_request_mempool_pt);
doca_error_t pdin_create_doca_log_backend(void);
#endif /* PDI_RDMA_H */