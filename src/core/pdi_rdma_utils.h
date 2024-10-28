#ifndef RDMA_UTILS
#define RDMA_UTILS

#include "bitmap.h"
#include "common.h"
#include "glib.h"
#include "ib.h"
#include "qp.h"
#include "rdma_config.h"
#include <rte_mempool.h>
#include <generic/rte_spinlock.h>
#include <rte_spinlock.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

enum qp_status
{
    CONNECTED,
    DISCONNECTED,
};
struct qp_id
{
    uint32_t node_id;
    uint32_t qp_num;
};
struct qp_res
{
    // only set for qpres under local rdma_node_res
    struct ibv_qp *qp;
    uint32_t qp_num;
    struct mr_info *start;
    uint32_t mr_info_num;
    bitmap *mr_bitmap;
    uint32_t unsignaled_cnt;
    uint32_t outstanding_cnt;
    enum qp_status status;
    struct qp_id peer_qp_id;
    uint32_t next_slot_idx;
    rte_spinlock_t lock;
};

struct rdma_node_res
{
    uint32_t n_qp;
    struct ib_res ibres;
    struct qp_res *qpres;
    GHashTable *qp_num_to_qp_res;
    // array of pointer of remote qp_res, which connected to current node
    GArray *connected_qp_res_array;
    GHashTable *wr_to_addr;
    // used by select_qp_rr to select qp in round-robin
    uint32_t last_connected_qp_mark;
};

struct connected_qp
{
    struct qp_res *local_qpres;
    struct qp_res *remote_qpres;
};

int rdma_init();

int rdma_exit();

int rdma_qp_connection_init();

int rdma_one_side_node_res_init(struct ib_res *ibres, struct rdma_node_res *node_res);

int rdma_two_side_node_res_init(struct ib_res *ibres, struct rdma_node_res *node_res);

int reset_qp_res(struct qp_res *qpres);
int destroy_rdma_node_res(struct rdma_node_res *node_res);

int init_qp_bitmap(uint32_t mr_per_qp, uint32_t mr_len, uint32_t slot_size, bitmap **bp);

int find_avaliable_slot(struct qp_res *remote_qpres, uint32_t message_size, uint32_t slot_hint,
                        uint32_t *slot_idx_start, uint32_t *n_slot, void **raddr, uint32_t *rkey, uint32_t *r_mr_idx);

int remote_addr_convert_slot_idx(void *remote_addr, uint32_t remote_len, struct mr_info *start, uint32_t mr_info_len,
                                 uint32_t slot_size, uint32_t *slot_idx, uint32_t *slot_num);

int qp_num_to_qp_res(struct rdma_node_res *res, uint32_t qp_num, struct qp_res **qpres);

int slot_idx_to_addr(struct rdma_node_res *local_res, uint32_t local_qp_num, uint32_t slot_idx, uint32_t mr_info_num,
                     uint32_t slot_size, void **addr);

uint32_t memory_len_to_slot_len(uint32_t len, uint32_t slot_size);

int rdma_one_side_rpc_client(void *arg);

int rdma_one_side_rpc_server(void *arg);

int rdma_two_side_rpc_server(void *arg);

int rdma_two_side_rpc_client(void *arg);
#endif // !RDMA_UTILS
