#ifndef PDI_RDMA_H
#define PDI_RDMA_H

#include <ngx_core.h>
#include <ngx_config.h>

#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>

#include "pdi_rdma_config.h"

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

} __attribute__((packed)) __rte_cache_aligned;

struct pdin_rdma_md_s *pdin_rdma_md_alloc(void);
void pdin_rdma_md_free(struct pdin_rdma_md_s *md);
int pdin_init_md_rings(ngx_cycle_t *cycle);
void pdin_rdma_write_rte_ring(ngx_int_t proc_id, struct pdin_rdma_md_s *md);
struct pdin_rdma_md_s *pdin_rdma_read_rte_ring(ngx_int_t proc_id);

#endif /* PDI_RDMA_H */