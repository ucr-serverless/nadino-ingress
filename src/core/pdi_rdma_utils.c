#include <generic/rte_spinlock.h>
#include <glib.h>
#include <infiniband/verbs.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "control_server.h"
#include "glibconfig.h"
#include "ib.h"
#include "rdma_config.h"
#include "sock_utils.h"

#include "common.h"
#include "http.h"
#include "timer.h"
#include "utility.h"
#include "log.h"

#include "pdi_rdma_utils.h"
#include "bitmap.h"

#define FIND_SLOT_RETRY_MAX 3
#define NUM_WC 20

int rdma_init()
{
    int ret = 0;

    struct rdma_param rparams = {
        .qp_num = cfg->nodes[cfg->local_node_idx].qp_num,
        .device_idx = cfg->nodes[cfg->local_node_idx].device_idx,
        .sgid_idx = cfg->nodes[cfg->local_node_idx].sgid_idx,
        .ib_port = cfg->nodes[cfg->local_node_idx].ib_port,
        .init_cqe_num = cfg->rdma_init_cqe_num,
        .max_send_wr = cfg->rdma_max_send_wr,
        .n_send_wc = NUM_WC,
        .n_recv_wc = NUM_WC,
    };
    if (cfg->use_one_side == 1)
    {
        rparams.local_mr_num = cfg->local_mempool_size;
        rparams.local_mr_size = cfg->local_mempool_elt_size;
        rparams.remote_mr_num = cfg->remote_mempool_size;
        rparams.remote_mr_size = cfg->remote_mempool_elt_size;
    }
    if (cfg->use_one_side == 0)
    {
        rparams.local_mr_num = 0;
        rparams.local_mr_size = 0;
        rparams.remote_mr_num = cfg->local_mempool_size;
        rparams.remote_mr_size = cfg->local_mempool_elt_size;
    }

    log_debug("local mr_size: %u", rparams.local_mr_size);
    log_debug("remote mr_size: %u", rparams.remote_mr_size);

    cfg->local_mempool_addrs = (void **)calloc(cfg->local_mempool_size, sizeof(void *));
    if (!cfg->local_mempool_addrs)
    {
        log_error("failed to allocate local_mempool_addrs");
        goto error;
    }
    retrieve_mempool_addresses(cfg->mempool, cfg->local_mempool_addrs);

    if (cfg->use_one_side == 1)
    {
        cfg->remote_mempool_addrs = (void **)calloc(cfg->remote_mempool_size, sizeof(void *));
        if (!cfg->remote_mempool_addrs)
        {
            log_error("failed to allocate local_mempool_addrs");
            goto error;
        }

        retrieve_mempool_addresses(cfg->remote_mempool, cfg->remote_mempool_addrs);
    }

    log_info("init RDMA ctx");

    if (cfg->use_one_side == 1)
    {
        ret = init_ib_ctx(&cfg->rdma_ctx, &rparams, cfg->local_mempool_addrs, cfg->remote_mempool_addrs);
    }
    if (cfg->use_one_side == 0)
    {
        ret = init_ib_ctx(&cfg->rdma_ctx, &rparams, NULL, cfg->local_mempool_addrs);
    }

    log_info("init RDMA ctx finished");
    log_debug("send cqe: %u", cfg->rdma_ctx.send_cqe);
    log_debug("recv cqe: %u", cfg->rdma_ctx.recv_cqe);
    log_debug("srq qe: %u", cfg->rdma_ctx.srqe);

    cfg->rdma_unsignal_freq = cfg->rdma_ctx.max_send_wr / 2;
    log_debug("unsignaled freq: %u", cfg->rdma_unsignal_freq);

    if (unlikely(ret != RDMA_SUCCESS))
    {
        log_error("init ib ctx fail");
        goto error;
    }

    cfg->mp_elt_to_mr_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!cfg->mp_elt_to_mr_map)
    {
        log_error("failed to allocate mp_elt_to_mr_map");
        goto error;
    }
    if (cfg->use_one_side == 1)
    {
        for (size_t i = 0; i < rparams.local_mr_num; i++)
        {
            g_hash_table_insert(cfg->mp_elt_to_mr_map, (gpointer)cfg->local_mempool_addrs[i],
                                cfg->rdma_ctx.local_mrs[i]);
        }
    }
    if (cfg->use_one_side == 0)
    {
        for (size_t i = 0; i < rparams.remote_mr_num; i++)
        {
            g_hash_table_insert(cfg->mp_elt_to_mr_map, (gpointer)cfg->local_mempool_addrs[i],
                                cfg->rdma_ctx.remote_mrs[i]);
            /* log_debug("mr addr: %p, mp_elt addr: %p", cfg->rdma_ctx.remote_mrs[i]->addr,
             * cfg->local_mempool_addrs[i]); */
        }
    }

    cfg->node_res = (struct rdma_node_res *)calloc(cfg->n_nodes, sizeof(struct rdma_node_res));

    if (unlikely(cfg->node_res == NULL))
    {
        log_error("allocate node res fail");
        goto error;
    }
    return 0;
error:
    return -1;
}

int rdma_exit()
{
    if (cfg->local_mempool_addrs)
    {
        free(cfg->local_mempool_addrs);
        cfg->local_mempool_addrs = NULL;
    }
    if (cfg->remote_mempool_addrs)
    {
        free(cfg->remote_mempool_addrs);
        cfg->remote_mempool_addrs = NULL;
    }
    if (cfg->control_server_socks)
    {
        free(cfg->control_server_socks);
        cfg->control_server_socks = NULL;
    }
    if (cfg->node_res)
    {
        for (size_t i = 0; i < cfg->n_nodes; i++)
        {
            destroy_rdma_node_res(&(cfg->node_res[i]));
        }
        free(cfg->node_res);
        cfg->node_res = NULL;
    }
    if (cfg->mp_elt_to_mr_map)
    {
        g_hash_table_destroy(cfg->mp_elt_to_mr_map);
        cfg->mp_elt_to_mr_map = NULL;
    }
    destroy_ib_ctx(&cfg->rdma_ctx);
    return 0;
}

int rdma_qp_connection_init_node(uint32_t remote_node_idx)
{
    uint32_t node_num = cfg->n_nodes;
    uint32_t local_idx = cfg->local_node_idx;
    int ret = 0;
    struct rdma_node_res *local_res = &(cfg->node_res[local_idx]);
    struct rdma_node_res *remote_res = &(cfg->node_res[remote_node_idx]);
    uint32_t remote_n_qp = remote_res->n_qp;
    uint32_t local_n_qp = local_res->n_qp;
    uint32_t local_qp_slot_start = 0;
    uint32_t remote_qp_slot_start = 0;
    uint32_t n_qp_connect = 0;
    if (remote_node_idx > local_idx)
    {
        local_qp_slot_start = (remote_node_idx - 1) * (local_n_qp / (node_num - 1));
        remote_qp_slot_start = local_idx * (remote_n_qp / (node_num - 1));
    }
    else
    {
        local_qp_slot_start = remote_node_idx * (local_n_qp / (node_num - 1));
        remote_qp_slot_start = (local_idx - 1) * (remote_n_qp / (node_num - 1));
    }
    if (remote_n_qp > local_n_qp)
    {
        n_qp_connect = local_n_qp / (node_num - 1);
    }
    else
    {
        n_qp_connect = remote_n_qp / (node_num - 1);
    }
    for (size_t i = 0; i < n_qp_connect; i++)
    {
        struct qp_res *remote_qpres = &remote_res->qpres[remote_qp_slot_start + i];
        struct qp_res *local_qpres = &(local_res->qpres[local_qp_slot_start + i]);
        uint32_t peer_qp_num = cfg->node_res[remote_node_idx].qpres[remote_qp_slot_start + i].qp_num;
        uint32_t local_qp_num = local_qpres->qp_num;
        ret = modify_qp_init_to_rts(cfg->rdma_ctx.qps[local_qp_slot_start + i], &cfg->node_res[local_idx].ibres,
                                    &cfg->node_res[remote_node_idx].ibres, peer_qp_num);
        if (ret != RDMA_SUCCESS)
        {
            log_error("init qp to node: %u, qp_num: %u failed", remote_node_idx, remote_qp_slot_start + i);
            goto error;
        }
        local_qpres->peer_qp_id.qp_num = peer_qp_num;
        local_qpres->peer_qp_id.node_id = remote_node_idx;
        local_qpres->status = CONNECTED;

        remote_qpres->peer_qp_id.qp_num = local_qp_num;
        remote_qpres->peer_qp_id.node_id = local_idx;
        remote_qpres->status = CONNECTED;

        struct connected_qp cqp = {
            .local_qpres = local_qpres,
            .remote_qpres = remote_qpres,
        };

        g_array_append_val(remote_res->connected_qp_res_array, cqp);

        log_debug("pushed connected_qp_res to node_idx: %u from qp_num: %u to %u, array size %d", remote_node_idx,
                  cqp.local_qpres->qp_num, cqp.remote_qpres->qp_num, remote_res->connected_qp_res_array->len);
    }
    log_debug("%u RDMA_connections to node: %u established", n_qp_connect, remote_node_idx);
    return 0;
error:

    return -1;
}

int post_two_side_srq_recv(uint32_t wr_id, void **addr)
{
    int ret = 0;
    ret = rte_mempool_get(cfg->mempool, addr);
    if (unlikely(ret < 0))
    {
        log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
        goto error;
    }
    struct ibv_mr *mr = (struct ibv_mr *)g_hash_table_lookup(cfg->mp_elt_to_mr_map, (gpointer) * (addr));
    if (mr == NULL)
    {
        log_error("txn: %p not valid", *addr);
        goto error;
    }
    /* log_debug("mr addr: %p, mp_elt addr: %p", mr->addr, *addr); */
    if (mr->addr != *addr)
    {
        log_fatal("looked up mr addr does not equal to mp_elt addr");
        goto error;
    }
    log_debug("get mp elt addr: %p", *addr);
    ret = post_srq_recv(cfg->rdma_ctx.srq, mr->addr, sizeof(struct http_transaction), mr->lkey, wr_id);
    if (unlikely(ret != RDMA_SUCCESS))
    {
        log_error("post srq fail");
        goto error;
    }
    return 0;
error:
    if (!(*addr))
    {
        rte_mempool_put(cfg->mempool, *addr);
    }
    return -1;
}

int rdma_qp_connection_init()
{
    int ret = 0;
    void *addr = NULL;
    uint32_t node_num = cfg->n_nodes;
    uint32_t local_idx = cfg->local_node_idx;
    for (size_t i = 0; i < node_num; i++)
    {
        if (i == local_idx)
        {
            continue;
        }
        ret = rdma_qp_connection_init_node(i);
        if (ret != 0)
        {
            log_error("connect qp to node: %u failed", i);
            goto error;
        }
    }
    if (cfg->use_one_side == 1)
    {
        ret = pre_post_dumb_srq_recv(cfg->rdma_ctx.srq, cfg->rdma_ctx.remote_mrs[0]->addr, cfg->rdma_remote_mr_size,
                                     cfg->rdma_ctx.remote_mrs[0]->lkey, 0, MIN(cfg->rdma_ctx.srqe, 10000));
        if (ret != RDMA_SUCCESS)
        {
            log_error("pre post srq recv failed");
            goto error;
        }
    }
    if (cfg->use_one_side == 0)
    {
        for (size_t i = 0; i < MIN(cfg->rdma_ctx.srqe, 100000); i++)
        {

            ret = post_two_side_srq_recv(i, &addr);
            if (unlikely(ret == -1))
            {
                log_error("pre post srq recv failed");
                goto error;
            }
            g_hash_table_insert(cfg->node_res[local_idx].wr_to_addr, GINT_TO_POINTER(i), addr);
            log_debug("insert %p into map", addr);
        }
        log_debug("post two side srq recv finished");
    }
    return 0;
error:
    return -1;
}

int rdma_one_side_node_res_init(struct ib_res *ibres, struct rdma_node_res *noderes)
{
    int ret = 0;
    if (!ibres || !(noderes))
    {
        return RDMA_FAILURE;
    }
    if (ibres->n_qp * cfg->rdma_remote_mr_per_qp != ibres->n_mr)
    {
        log_fatal("The number of mr is not equal to the number of qp times mr_per_qp");
        return RDMA_FAILURE;
    }
    (noderes)->n_qp = ibres->n_qp;
    noderes->qp_num_to_qp_res = g_hash_table_new(g_direct_hash, g_direct_equal);
    noderes->connected_qp_res_array = g_array_new(FALSE, TRUE, sizeof(struct connected_qp));
    noderes->wr_to_addr = NULL;
    (noderes)->qpres = (struct qp_res *)calloc(ibres->n_qp, sizeof(struct qp_res));
    if (!(noderes)->qpres)
    {
        log_error("Failed to allocate qp_res");
        return RDMA_FAILURE;
    }
    for (size_t i = 0; i < ibres->n_qp; i++)
    {
        g_hash_table_insert(noderes->qp_num_to_qp_res, GUINT_TO_POINTER(ibres->qp_nums[i]), &noderes->qpres[i]);
        ret = init_qp_bitmap(cfg->rdma_remote_mr_per_qp, cfg->rdma_remote_mr_size, cfg->rdma_slot_size,
                             &((noderes)->qpres[i].mr_bitmap));
        if (ret != RDMA_SUCCESS)
        {
            return RDMA_FAILURE;
        }
        rte_spinlock_init(&noderes->qpres[i].lock);
        noderes->qpres[i].qp = NULL;
        noderes->qpres[i].qp_num = ibres->qp_nums[i];
        noderes->qpres[i].mr_info_num = cfg->rdma_remote_mr_per_qp;
        noderes->qpres[i].start = ibres->mrs + i * cfg->rdma_remote_mr_per_qp;
        noderes->qpres[i].outstanding_cnt = 0;
        noderes->qpres[i].unsignaled_cnt = 0;
        noderes->qpres[i].peer_qp_id.qp_num = 0;
        noderes->qpres[i].peer_qp_id.node_id = 0;
        noderes->qpres[i].next_slot_idx = 0;
        noderes->qpres[i].status = DISCONNECTED;
    }

    return RDMA_SUCCESS;
}

int rdma_two_side_node_res_init(struct ib_res *ibres, struct rdma_node_res *noderes)
{
    if (!ibres || !(noderes))
    {
        return RDMA_FAILURE;
    }
    noderes->n_qp = ibres->n_qp;
    noderes->qp_num_to_qp_res = g_hash_table_new(g_direct_hash, g_direct_equal);
    noderes->connected_qp_res_array = g_array_new(FALSE, TRUE, sizeof(struct connected_qp));
    noderes->wr_to_addr = g_hash_table_new(g_direct_hash, g_direct_equal);
    noderes->qpres = (struct qp_res *)calloc(ibres->n_qp, sizeof(struct qp_res));
    if (!(noderes)->qpres)
    {
        log_error("Failed to allocate qp_res");
        return RDMA_FAILURE;
    }
    for (size_t i = 0; i < ibres->n_qp; i++)
    {
        g_hash_table_insert(noderes->qp_num_to_qp_res, GUINT_TO_POINTER(ibres->qp_nums[i]), &noderes->qpres[i]);

        noderes->qpres[i].mr_bitmap = NULL;
        noderes->qpres[i].qp = NULL;
        noderes->qpres[i].qp_num = ibres->qp_nums[i];
        noderes->qpres[i].mr_info_num = 0;
        noderes->qpres[i].start = NULL;
        noderes->qpres[i].outstanding_cnt = 0;
        noderes->qpres[i].unsignaled_cnt = 0;
        noderes->qpres[i].peer_qp_id.qp_num = 0;
        noderes->qpres[i].peer_qp_id.node_id = 0;
        noderes->qpres[i].next_slot_idx = 0;
        noderes->qpres[i].status = DISCONNECTED;
    }

    return RDMA_SUCCESS;
}

int reset_qp_res(struct qp_res *qpres)
{
    if (!qpres)
    {
        return RDMA_FAILURE;
    }
    qpres->unsignaled_cnt = 0;
    qpres->outstanding_cnt = 0;
    qpres->status = DISCONNECTED;
    qpres->peer_qp_id.qp_num = 0;
    qpres->peer_qp_id.node_id = 0;
    qpres->next_slot_idx = 0;
    bitmap_clear_all(qpres->mr_bitmap);
    return RDMA_SUCCESS;
}

int destroy_rdma_node_res(struct rdma_node_res *node_res)
{
    if (!node_res)
    {
        return RDMA_SUCCESS;
    }
    if (!node_res->qpres)
    {
        return RDMA_SUCCESS;
    }
    for (size_t i = 0; i < node_res->n_qp; i++)
    {
        if (node_res->qpres[i].mr_bitmap)
        {
            bitmap_deallocate(node_res->qpres[i].mr_bitmap);
        }
    }
    if (node_res->qp_num_to_qp_res)
    {
        g_hash_table_destroy(node_res->qp_num_to_qp_res);
        node_res->qp_num_to_qp_res = NULL;
    }
    if (node_res->connected_qp_res_array)
    {
        g_array_free(node_res->connected_qp_res_array, TRUE);
        node_res->connected_qp_res_array = NULL;
    }
    if (node_res->wr_to_addr)
    {
        g_hash_table_destroy(node_res->wr_to_addr);
        node_res->wr_to_addr = NULL;
    }
    destroy_ib_res(&(node_res->ibres));
    free(node_res->qpres);
    return RDMA_SUCCESS;
}

int init_qp_bitmap(uint32_t mr_num, uint32_t single_mr_size, uint32_t slot_size, bitmap **bp)
{
    assert(single_mr_size % slot_size == 0);
    *bp = bitmap_allocate(mr_num * single_mr_size / slot_size);
    if (!bp)
    {
        log_error("Error, allocate bitmap\n");
        exit(1);
    }
    return RDMA_SUCCESS;
}

int find_avaliable_slot_in_range(bitmap *bp, uint32_t start, uint32_t end, uint32_t n_slot, uint32_t *result_slot_idx)
{
    log_debug("start from %u and end by %u", start, end);
    if (end < start)
    {
        log_error("Error, range is not valid\n");
        return RDMA_FAILURE;
    }
    bool success = true;
    for (size_t i = start; i <= end - n_slot;)
    {
        for (size_t j = 0; j < n_slot; j++)
        {
            if (bitmap_read(bp, i + j) == 1)
            {
                i = i + j + 1;
                success = false;
                break;
            }
        }
        if (success)
        {
            *result_slot_idx = i;
            return RDMA_SUCCESS;
        }
        success = true;
    }
    return RDMA_FAILURE;
}

int find_avaliable_slot_inside_mr(bitmap *bp, uint32_t mr_bp_idx_start, uint32_t mr_blk_len, uint32_t msg_blk_len,
                                  uint32_t *slot_idx)
{
    if (mr_blk_len < msg_blk_len)
    {
        log_error("Error, meg size is larger than mr size\n");
        return RDMA_FAILURE;
    }
    bool success = true;
    for (size_t i = 0; i <= mr_blk_len - msg_blk_len; i++)
    {
        for (size_t j = 0; j < msg_blk_len; j++)
        {
            if (bitmap_read(bp, mr_bp_idx_start + i + j) == 1)
            {
                i = i + j;
                success = false;
                break;
            }
        }
        if (success)
        {
            *slot_idx = mr_bp_idx_start + i;
            return RDMA_SUCCESS;
        }
        success = true;
    }
    return RDMA_FAILURE;
}

int find_avaliable_slot_try(bitmap *bp, uint32_t message_size, uint32_t slot_size, uint32_t mr_size,
                            struct mr_info *start, uint32_t n_mr_info, uint32_t start_idx_hint, uint32_t *slot_idx,
                            uint32_t *slot_num, void **raddr, uint32_t *rkey, uint32_t *r_mr_idx)
{
    assert(n_mr_info > 0);
    assert(start);
    start_idx_hint %= bp->bits;
    uint32_t n_mr_slot = mr_size / slot_size;
    uint32_t n_msg_slot = memory_len_to_slot_len(message_size, slot_size);
    int ret = 0;

    uint32_t start_mr_idx = start_idx_hint / n_mr_slot;

    if (start_idx_hint % n_mr_slot != 0)
    {
        ret = find_avaliable_slot_in_range(
            bp, start_idx_hint, start_idx_hint + n_mr_slot - (start_idx_hint % n_mr_slot), n_msg_slot, slot_idx);
        if (ret == RDMA_SUCCESS)
        {
            goto success;
        }
        start_mr_idx = (start_mr_idx + 1) % n_mr_info;
    }
    for (size_t i = 0; i < n_mr_info; i++)
    {
        ret = find_avaliable_slot_in_range(bp, start_mr_idx * n_mr_slot, (start_mr_idx + 1) * n_mr_slot, n_msg_slot,
                                           slot_idx);
        if (ret == RDMA_SUCCESS)
        {
            goto success;
        }
        start_mr_idx = (start_mr_idx + 1) % n_mr_info;
    }

    return RDMA_FAILURE;
success:
    *slot_num = n_msg_slot;
    *rkey = start[start_mr_idx].rkey;
    *raddr = start[start_mr_idx].addr + (*slot_idx - start_mr_idx * n_mr_slot) * slot_size;
    *r_mr_idx = start_mr_idx;
    return RDMA_SUCCESS;
}

int find_avaliable_slot(struct qp_res *remote_qpres, uint32_t message_size, uint32_t slot_hint,
                        uint32_t *slot_idx_start, uint32_t *n_slot, void **raddr, uint32_t *rkey, uint32_t *r_mr_idx)
{
    return find_avaliable_slot_try(remote_qpres->mr_bitmap, message_size, cfg->rdma_slot_size, cfg->rdma_remote_mr_size,
                                   remote_qpres->start, remote_qpres->mr_info_num, slot_hint, slot_idx_start, n_slot,
                                   raddr, rkey, r_mr_idx);
}

int remote_slot_idx_convert(uint32_t slot_idx, struct mr_info *start, uint32_t mr_info_len, uint32_t blk_size,
                            void **addr, uint32_t *rkey)
{
    assert(mr_info_len > 0);
    assert(start);
    uint32_t blk_len_per_mr = 0;
    size_t i = 0;
    for (; i < mr_info_len; i++)
    {
        blk_len_per_mr = start[i].length / blk_size;
        assert(blk_len_per_mr != 0);
        if (slot_idx >= blk_len_per_mr)
        {
            slot_idx -= blk_len_per_mr;
            continue;
        }
        else
        {
            break;
        }
    }
    if (i == mr_info_len)
    {
        return RDMA_FAILURE;
    }
    *addr = start[i].addr + blk_size * slot_idx;
    *rkey = start[i].rkey;
    return RDMA_SUCCESS;
}

int remote_addr_convert_slot_idx(void *remote_addr, uint32_t remote_len, struct mr_info *start, uint32_t mr_info_len,
                                 uint32_t slot_size, uint32_t *slot_idx, uint32_t *slot_num)
{
    uint32_t result = 0;
    for (size_t i = 0; i < mr_info_len; i++)
    {
        if ((unsigned char *)start[i].addr <= (unsigned char *)remote_addr &&
            (unsigned char *)remote_addr < (unsigned char *)start[i].addr + start[i].length)
        {
            if ((unsigned char *)remote_addr + remote_len <= (unsigned char *)start[i].addr + start[i].length)
            {
                uint32_t slot_diff = (unsigned char *)remote_addr - (unsigned char *)start[i].addr;
                if (slot_diff % slot_size != 0)
                {
                    return RDMA_FAILURE;
                }
                result += slot_diff / slot_size;
                *slot_idx = result;
                *slot_num = memory_len_to_slot_len(remote_len, slot_size);
                return RDMA_SUCCESS;
            }
        }
        result += start[i].length / slot_size;
    }
    return RDMA_FAILURE;
}

int qp_num_to_qp_res(struct rdma_node_res *res, uint32_t qp_num, struct qp_res **qpres)
{
    *qpres = (struct qp_res *)g_hash_table_lookup(res->qp_num_to_qp_res, GUINT_TO_POINTER(qp_num));
    return RDMA_SUCCESS;
}

int slot_idx_to_addr(struct rdma_node_res *local_res, uint32_t local_qp_num, uint32_t slot_idx, uint32_t mr_info_num,
                     uint32_t slot_size, void **addr)
{
    struct qp_res *local_qpres = NULL;
    if (qp_num_to_qp_res(local_res, local_qp_num, &local_qpres) != RDMA_SUCCESS)
    {
        return RDMA_FAILURE;
    }
    struct mr_info *start = local_qpres->start;

    uint32_t n_mr_slot = cfg->rdma_remote_mr_size / slot_size;

    uint32_t mr_idx = slot_idx / n_mr_slot;
    uint32_t remain = slot_idx % n_mr_slot;

    if (mr_idx >= local_qpres->mr_info_num)
    {
        log_error("slot_idx is out of range");
        return RDMA_FAILURE;
    }
    *addr = start[mr_idx].addr + remain * slot_size;
    log_debug("local idx is: %p", *addr);
    return RDMA_SUCCESS;
}

uint32_t memory_len_to_slot_len(uint32_t len, uint32_t slot_size)
{
    assert(len > 0);
    assert(slot_size > 0);
    return (len + slot_size - 1) / slot_size;
}

int select_qp_rr(int peer_node_idx, struct rdma_node_res *noderes, struct connected_qp **qpres)
{
    int array_size = noderes->connected_qp_res_array->len;
    log_debug("size of array: %d", array_size);
    if (array_size == 0)
    {
        log_error("no qp connected for node: %u", peer_node_idx);
        goto error;
    }
    noderes->last_connected_qp_mark = (noderes->last_connected_qp_mark + 1) % array_size;
    *qpres = &g_array_index(noderes->connected_qp_res_array, struct connected_qp, noderes->last_connected_qp_mark);

    return 0;
error:
    return -1;
}

int select_qp_rand(int peer_node_idx, struct rdma_node_res *noderes, struct connected_qp **qpres)
{
    int array_size = noderes->connected_qp_res_array->len;
    log_debug("size of array: %d", array_size);
    if (array_size == 0)
    {
        log_error("no qp connected for node: %u", peer_node_idx);
        goto error;
    }
    noderes->last_connected_qp_mark = (noderes->last_connected_qp_mark + 1) % array_size;
    *qpres = &g_array_index(noderes->connected_qp_res_array, struct connected_qp, noderes->last_connected_qp_mark);
    int pos = rand() % array_size;
    *qpres = &g_array_index(noderes->connected_qp_res_array, struct connected_qp, pos);
    return 0;
error:
    return -1;
}

int rdma_one_side_rpc_client_send(int peer_node_idx, struct http_transaction *txn)
{
    int ret = 0;
    uint32_t slot_idx;
    int num_completion;
    int retry = 0;

    int message_size = sizeof(struct http_transaction);
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, \
        Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);

    struct connected_qp *cqp = NULL;
    ret = select_qp_rr(peer_node_idx, &cfg->node_res[peer_node_idx], &cqp);
    if (unlikely(ret == -1))
    {
        log_error("select qp fail");
        goto error;
    }

    struct rdma_node_res local_noderes = cfg->node_res[cfg->local_node_idx];

    struct qp_res *local_qpres = cqp->local_qpres;
    struct qp_res *remote_qpres = cqp->remote_qpres;

    log_debug("local qp_num: %u, remote qp_num: %u", local_qpres->qp_num, remote_qpres->qp_num);

    uint32_t n_slot;
    void *raddr;
    uint32_t rkey;
    uint32_t r_mr_idx;

    do
    {

        ret = find_avaliable_slot(remote_qpres, message_size, remote_qpres->next_slot_idx, &slot_idx, &n_slot, &raddr,
                                  &rkey, &r_mr_idx);
        retry++;
    } while (ret != RDMA_SUCCESS && retry < FIND_SLOT_RETRY_MAX);
    if (ret != RDMA_SUCCESS)
    {
        log_error("can not find avaliable slot");
        goto error;
    }
    log_debug("found memory slot at peer_node_idx: %u, peer_qp_num: %u, slot_idx %u, size %u, found raddr: %p, rkey: "
              "%u, r_mr_idx: %u",
              peer_node_idx, remote_qpres->qp_num, slot_idx, n_slot, raddr, rkey, r_mr_idx);

    uint32_t is_remote_mem = txn->is_rdma_remote_mem;

    void *local_mr_addr = NULL;
    uint32_t local_mr_lkey = 0;

    if (is_remote_mem == 0)
    {

        struct ibv_mr *local_mr = (struct ibv_mr *)g_hash_table_lookup(cfg->mp_elt_to_mr_map, (gpointer)txn);
        if (local_mr == NULL)
        {
            log_error("txn: %p not valid", txn);
            goto error;
        }

        local_mr_addr = local_mr->addr;
        local_mr_lkey = local_mr->lkey;
    }
    else
    {
        struct qp_res *txn_dst_qpres = NULL;
        uint32_t txn_dst_qpnum = txn->rdma_recv_qp_num;
        log_debug("local_idx: %u, txn recved by node_idx: %u, qp_num: %u", cfg->local_node_idx, txn->rdma_recv_node_idx,
                  txn_dst_qpnum);

        qp_num_to_qp_res(&local_noderes, txn_dst_qpnum, &txn_dst_qpres);
        if (ret != RDMA_SUCCESS)
        {
            log_error("remote qp num invalid");
            goto error;
        }
        log_debug("query qp_num: %u, got qp_num: %u", txn_dst_qpnum, txn_dst_qpres->qp_num);

        struct mr_info *info = txn_dst_qpres->start + txn->rdma_remote_mr_idx;
        local_mr_addr = info->addr;
        local_mr_lkey = info->lkey;
    }

    log_debug("the txn addr: %p, the mr addr %p, mr lkey %u, is_local_remote_mr: %u", txn, local_mr_addr, local_mr_lkey,
              is_remote_mem);

    txn->is_rdma_remote_mem = 1;
    txn->rdma_send_node_idx = cfg->local_node_idx;
    txn->rdma_send_qp_num = local_qpres->qp_num;
    txn->rdma_recv_node_idx = peer_node_idx;
    txn->rdma_recv_qp_num = local_qpres->peer_qp_id.qp_num;
    txn->rdma_remote_mr_idx = r_mr_idx;
    txn->rdma_n_slot = n_slot;

    if (local_qpres->unsignaled_cnt == cfg->rdma_unsignal_freq)
    {
        log_debug("post write imm signaled");
        ret = post_write_imm_signaled(local_qpres->qp, txn, sizeof(struct http_transaction), local_mr_lkey, 0,
                                      (uint64_t)raddr, rkey, slot_idx);
        local_qpres->unsignaled_cnt = 0;
        do
        {
            num_completion = ibv_poll_cq(cfg->rdma_ctx.send_cq, NUM_WC, cfg->rdma_ctx.send_wc);
        } while (num_completion == 0);
        if (unlikely(num_completion < 0))
        {
            log_error("poll send completion error");
            goto error;
        }
        local_qpres->outstanding_cnt -= num_completion;
    }
    else
    {
        log_debug("post write imm unsignaled");
        ret = post_write_imm_unsignaled(local_qpres->qp, txn, sizeof(struct http_transaction), local_mr_lkey, 0,
                                        (uint64_t)raddr, rkey, slot_idx);
        local_qpres->unsignaled_cnt++;
        local_qpres->outstanding_cnt++;
    }
    if (unlikely(ret != RDMA_SUCCESS))
    {
        log_error("post imm unsignaled failed");
        goto error;
    }

    do
    {
        ret = rte_spinlock_trylock(&remote_qpres->lock);

    } while (ret != 1);

    bitmap_set_consecutive(remote_qpres->mr_bitmap, slot_idx, n_slot);

    /* bitmap_print_bit(remote_qpres->mr_bitmap); */
    rte_spinlock_unlock(&remote_qpres->lock);

    remote_qpres->next_slot_idx = slot_idx + n_slot;
    log_debug("next slot_idx: %u", remote_qpres->next_slot_idx);

    log_debug("peer_node_idx: %d \t sizeof(*txn): %ld", peer_node_idx, sizeof(*txn));
    log_debug("rpc_client_send is done.");

    return 0;
error:
    return -1;
}
int rdma_one_side_rpc_client(void *arg)
{
    log_info("rdma_rpc_client init");
    srand(time(NULL));
    int epoll_fd;
    struct epoll_event ev, events[N_EVENTS_MAX];
    int nfds;
    int ret;

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = add_weighted_pipes_to_epoll(epoll_fd, &ev);
    if (ret == -1)
    {
        return ret;
    }

    int gcd_weight = get_gcd_weight();
    int max_weight = get_max_weight();
    int current_index = -1;
    int current_weight = max_weight;
    struct http_transaction *txn = NULL;
    struct control_server_msg msg = {
        .source_qp_num = 0,
        .source_node_idx = 0,
        .slot_idx = 0,
        .dest_node_idx = 0,
        .bf_addr = 0,
        .bf_len = 0,
    };

    while (1)
    {
        nfds = epoll_wait(epoll_fd, events, N_EVENTS_MAX, -1);
        if (nfds == -1)
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; n++)
        {
            tenant_pipe *tp = (tenant_pipe *)events[n].data.ptr;

            log_debug("Tenant-%d's pipe is ready to be consumed ...", tp->tenant_id);

            while (1)
            {
                current_index = (current_index + 1) % cfg->n_tenants;
                if (current_index == 0)
                {
                    current_weight -= gcd_weight;
                    if (current_weight <= 0)
                    {
                        current_weight = max_weight;
                    }
                }

                log_debug("Tenant ID: %d \t Assigned Weight: %d \t Current Weight: %d ", current_index,
                          tenant_pipes[current_index].weight, current_weight);

                if (current_index == tp->tenant_id && tenant_pipes[current_index].weight >= current_weight)
                {

                    txn = read_pipe(tp);
                    if (txn == NULL)
                    {
                        close(tp->fd[0]);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, tp->fd[0], NULL);
                    }

                    uint8_t peer_node_idx = get_node(txn->next_fn);

                    uint8_t is_rdma_remote_mem = txn->is_rdma_remote_mem;

                    msg.dest_node_idx = txn->rdma_send_node_idx;
                    msg.source_node_idx = cfg->local_node_idx;
                    msg.source_qp_num = txn->rdma_recv_qp_num;
                    msg.slot_idx = txn->rdma_slot_idx;
                    msg.bf_addr = txn;
                    msg.bf_len = sizeof(struct http_transaction);
                    msg.n_slot = txn->rdma_n_slot;

                    log_debug("if the mem is remote_mem, %u", is_rdma_remote_mem);

                    ret = rdma_one_side_rpc_client_send(peer_node_idx, txn);

                    if (is_rdma_remote_mem == 1)
                    {
                        send_release_signal(&msg);
                    }
                    else
                    {
                        rte_mempool_put(cfg->mempool, txn);
                    }

                    break;
                }
            }
        }
    }

    close(epoll_fd);
    return -1;
    return 0;
}

int rdma_one_side_rpc_server(void *arg)
{

    log_info("rdma_rpc_server init");
    int n_events;
    int i;
    int local_idx = cfg->local_node_idx;
    struct http_transaction *txn = NULL;
    int *pipefd_dispacher = (int *)arg;
    log_debug("pipe fd", pipefd_dispacher[1]);
    uint32_t slot_idx;
    int ret = 0;
    struct ibv_mr *dumb_mr = cfg->rdma_ctx.remote_mrs[0];

    struct ibv_wc *wc = cfg->rdma_ctx.recv_wc;
    if (unlikely(!wc))
    {
        log_error("allocate %u ibv_wc failed", NUM_WC);
        return -1;
    }
    log_debug("rdma_rpc_server initialized");

    while (1)
    {
        n_events = ibv_poll_cq(cfg->rdma_ctx.recv_cq, NUM_WC, wc);
        if (unlikely(n_events < 0))
        {
            log_error("failed to poll cq");
            goto error;
        }
        for (i = 0; i < n_events; i++)
        {

            log_debug("Receiving from PEER GW.");
            if (wc[i].status != IBV_WC_SUCCESS)
            {
                log_error("wc failed status: %s.", ibv_wc_status_str(wc[i].status));
                goto error;
            }

            if (wc[i].opcode == IBV_WC_RECV_RDMA_WITH_IMM)
            {
                if (wc[i].byte_len != sizeof(struct http_transaction))
                {
                    log_error("recved len %u, not size of http_transaction", wc[i].byte_len);
                    goto error;
                }
                slot_idx = ntohl(wc[i].imm_data);
                log_debug("qp_num: %u, slot_idx: %u", wc[i].qp_num, slot_idx);
                ret = slot_idx_to_addr(&cfg->node_res[local_idx], wc[i].qp_num, slot_idx, cfg->rdma_remote_mr_per_qp,
                                       cfg->rdma_slot_size, (void **)&txn);
                if (ret != RDMA_SUCCESS)
                {
                    log_error("slot idx not valid");
                    goto error;
                }
                txn->rdma_slot_idx = slot_idx;
            }
            else
            {
                log_debug("receive opcode %u", wc[i].opcode);
            }

            ret = post_dumb_srq_recv(cfg->rdma_ctx.srq, dumb_mr->addr, dumb_mr->length, dumb_mr->lkey, wc[i].wr_id);
            if (unlikely(ret != RDMA_SUCCESS))
            {
                log_error("post srq recv failed");
                goto error;
            }
            txn->is_rdma_remote_mem = 1;

            log_debug("Bytes received: %zd. \t sizeof(*txn): %ld.", wc[i].byte_len, sizeof(struct http_transaction));

            // Send txn to local function
            log_debug("\tRoute id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                      cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);
            ssize_t bytes_written = write(pipefd_dispacher[1], &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_written == -1))
            {
                log_error("write() error: %s", strerror(errno));
                goto error;
            }
        }
    }

error:
    return -1;
}

int rdma_two_side_rpc_client_send(int peer_node_idx, struct http_transaction *txn)
{
    int ret = 0;
    int num_completion;

    int message_size = sizeof(struct http_transaction);
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, \
        Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);

    struct connected_qp *cqp = NULL;
    ret = select_qp_rr(peer_node_idx, &cfg->node_res[peer_node_idx], &cqp);
    if (unlikely(ret == -1))
    {
        log_error("select qp fail");
        goto error;
    }

    struct qp_res *local_qpres = cqp->local_qpres;

    struct ibv_mr *local_mr = (struct ibv_mr *)g_hash_table_lookup(cfg->mp_elt_to_mr_map, (gpointer)txn);
    if (local_mr == NULL)
    {
        log_error("txn: %p not valid", txn);
        goto error;
    }

    txn->rdma_send_node_idx = cfg->local_node_idx;
    txn->rdma_send_qp_num = local_qpres->qp_num;
    txn->rdma_recv_node_idx = peer_node_idx;
    txn->rdma_recv_qp_num = local_qpres->peer_qp_id.qp_num;

    if (local_qpres->unsignaled_cnt == cfg->rdma_unsignal_freq)
    {
        log_debug("post write imm signaled");
        ret = post_send_signaled(local_qpres->qp, (char *)txn, message_size, local_mr->lkey, 0, 0);
        local_qpres->unsignaled_cnt = 0;
        do
        {
            num_completion = ibv_poll_cq(cfg->rdma_ctx.send_cq, NUM_WC, cfg->rdma_ctx.send_wc);
        } while (num_completion == 0);
        if (unlikely(num_completion < 0))
        {
            log_error("poll send completion error");
            goto error;
        }
        local_qpres->outstanding_cnt -= num_completion;
    }
    else
    {
        log_debug("post write imm unsignaled");
        ret = post_send_unsignaled(local_qpres->qp, (char *)txn, message_size, local_mr->lkey, 0, 0);
        local_qpres->unsignaled_cnt++;
        local_qpres->outstanding_cnt++;
    }
    if (unlikely(ret != RDMA_SUCCESS))
    {
        log_error("post imm unsignaled failed");
        goto error;
    }

    log_debug("peer_node_idx: %d \t sizeof(*txn): %ld", peer_node_idx, sizeof(*txn));
    log_debug("rpc_client_send is done.");
    return 0;
error:
    return -1;
}
int rdma_two_side_rpc_client(void *arg)
{
    log_info("rdma_rpc_client init");
    srand(time(NULL));
    int epoll_fd;
    struct epoll_event ev, events[N_EVENTS_MAX];
    int nfds;
    int ret;

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1)
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    ret = add_weighted_pipes_to_epoll(epoll_fd, &ev);
    if (ret == -1)
    {
        return ret;
    }

    int gcd_weight = get_gcd_weight();
    int max_weight = get_max_weight();
    int current_index = -1;
    int current_weight = max_weight;
    struct http_transaction *txn = NULL;

    while (1)
    {
        nfds = epoll_wait(epoll_fd, events, N_EVENTS_MAX, -1);
        if (nfds == -1)
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        for (int n = 0; n < nfds; n++)
        {
            tenant_pipe *tp = (tenant_pipe *)events[n].data.ptr;

            log_debug("Tenant-%d's pipe is ready to be consumed ...", tp->tenant_id);

            while (1)
            {
                current_index = (current_index + 1) % cfg->n_tenants;
                if (current_index == 0)
                {
                    current_weight -= gcd_weight;
                    if (current_weight <= 0)
                    {
                        current_weight = max_weight;
                    }
                }

                log_debug("Tenant ID: %d \t Assigned Weight: %d \t Current Weight: %d ", current_index,
                          tenant_pipes[current_index].weight, current_weight);

                if (current_index == tp->tenant_id && tenant_pipes[current_index].weight >= current_weight)
                {

                    txn = read_pipe(tp);
                    if (txn == NULL)
                    {
                        close(tp->fd[0]);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, tp->fd[0], NULL);
                    }

                    uint8_t peer_node_idx = get_node(txn->next_fn);

                    ret = rdma_two_side_rpc_client_send(peer_node_idx, txn);
                    rte_mempool_put(cfg->mempool, txn);

                    break;
                }
            }
        }
    }

    close(epoll_fd);
    return -1;
    return 0;
}

int rdma_two_side_rpc_server(void *arg)
{

    log_info("rdma_rpc_server init");
    int n_events;
    int i;
    struct http_transaction *txn = NULL;
    int *pipefd_dispacher = (int *)arg;
    log_debug("pipe fd", pipefd_dispacher[1]);
    int ret = 0;
    uint32_t wr_id = 0;
    void *new_addr = NULL;
    struct rdma_node_res local_noderes = cfg->node_res[cfg->local_node_idx];

    struct ibv_wc *wc = cfg->rdma_ctx.recv_wc;
    if (unlikely(!wc))
    {
        log_error("allocate %u ibv_wc failed", NUM_WC);
        return -1;
    }
    log_debug("rdma_rpc_server initialized");

    while (1)
    {
        n_events = ibv_poll_cq(cfg->rdma_ctx.recv_cq, NUM_WC, wc);
        if (unlikely(n_events < 0))
        {
            log_error("failed to poll cq");
            goto error;
        }
        for (i = 0; i < n_events; i++)
        {

            log_debug("Receiving from PEER GW.");
            if (wc[i].status != IBV_WC_SUCCESS)
            {
                log_error("wc failed status: %s.", ibv_wc_status_str(wc[i].status));
                goto error;
            }

            wr_id = wc[i].wr_id;
            if (wc[i].opcode == IBV_WC_RECV)
            {
                if (wc[i].byte_len != sizeof(struct http_transaction))
                {
                    log_error("recved len %u, not size of http_transaction", wc[i].byte_len);
                    goto error;
                }
                // only post less than uint32_t recv req

                txn = (struct http_transaction *)g_hash_table_lookup(local_noderes.wr_to_addr, GINT_TO_POINTER(wr_id));

                log_debug("current wr_id is %u", wr_id);
            }
            else
            {
                log_debug("receive opcode %u", wc[i].opcode);
            }

            ret = post_two_side_srq_recv(wr_id, &new_addr);
            if (unlikely(ret != 0))
            {
                log_error("post srq recv failed");
                goto error;
            }
            g_hash_table_insert(local_noderes.wr_to_addr, GINT_TO_POINTER(wr_id), new_addr);

            log_debug("\tRoute id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                      cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);
            ssize_t bytes_written = write(pipefd_dispacher[1], &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_written == -1))
            {
                log_error("write() error: %s", strerror(errno));
                goto error;
            }
        }
    }

error:
    return -1;
}