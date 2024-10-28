#include <ngx_core.h>
#include <ngx_config.h>

#include <rte_eal.h>
#include <rte_ring.h>
#include <rte_mempool.h>

#include "pdi_rdma_config.h"

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
