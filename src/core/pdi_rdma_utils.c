#include <generic/rte_spinlock.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <glib.h>
#include <infiniband/verbs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "ib.h"
#include "ngx_log.h"
#include "rdma_config.h"


#include "pdi_rdma_sock.h"
#include "pdi_rdma_utils.h"
#include "pdi_rdma_config.h"

#define FIND_SLOT_RETRY_MAX 3

struct rte_mempool *message_pool;

int destroy_control_server_socks(struct rdma_config* cfg)
{
    if (!cfg->control_server_socks)
    {
        return 0;
    }
    for (size_t i = 0; i < cfg->n_nodes; i++)
    {
        if (cfg->control_server_socks[i])
        {
            close(cfg->control_server_socks[i]);
        }
    }
    return 0;
}

int control_server_socks_init(struct rdma_config* cfg)
{
    cfg->control_server_socks = (int *)calloc(cfg->n_nodes, sizeof(int));

    if (unlikely(cfg->control_server_socks == NULL))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "allocate control server fd fail");
        goto error;
    }
    int ret = 0;
    uint32_t node_num = cfg->n_nodes;
    uint32_t self_idx = cfg->local_node_idx;
    char buffer[6];
    int sock_fd = -1;
    uint32_t connected_nodes = 0;
    for (size_t i = 0; i < self_idx; i++)
    {
        sprintf(buffer, "%u", cfg->nodes[i].control_server_port);

        do
        {
            sock_fd = sock_utils_connect(cfg->nodes[i].ip_address, buffer);

        } while (sock_fd <= 0);

        ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "Connected to server: %s: %s", cfg->nodes[i].ip_address, buffer);
        cfg->control_server_socks[i] = sock_fd;
        connected_nodes++;
    }
    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "connected to all servers with idx lower than %d", self_idx);
    if (connected_nodes == node_num - 1)
    {
        return 0;
    }
    sprintf(buffer, "%u", cfg->nodes[self_idx].control_server_port);
    int bind_fd = sock_utils_bind(cfg->nodes[self_idx].ip_address, buffer);
    if (bind_fd <= 0)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "failed to open listen socket");
        goto error;
    }
    ret = listen(bind_fd, 10);
    if (ret < 0) {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "listen failed, sockfd:%d, errno:%d, %s\n", bind_fd, errno, strerror(errno));
        goto error;
    }
    int peer_fd = 0;
    struct sockaddr_in peer_addr;
    socklen_t peer_addr_len = sizeof(struct sockaddr_in);
    char client_ip[INET_ADDRSTRLEN];
    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "accepting connections from other nodes");
    while (connected_nodes < node_num - 1)
    {
        peer_fd = accept(bind_fd, (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (peer_fd < 0)
        {
            ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "client connect fail");
            continue;
        }
        inet_ntop(AF_INET, &peer_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "client ip %s connected", client_ip);
        for (size_t i = self_idx + 1; i < node_num; i++)
        {
            if (strcmp(cfg->nodes[i].ip_address, client_ip) == 0)
            {
                cfg->control_server_socks[i] = peer_fd;
                connected_nodes++;
            } else {
                close(peer_fd);
            }
            
        }
    }
    cfg->control_server_socks[self_idx] = 0;
    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "control_server_socks initialized");
    close(bind_fd);

    int keepalive = 1;

    for (size_t i = 0; i < node_num; i++)
    {
        if (cfg->control_server_socks[i])
        {
            ret = setsockopt(cfg->control_server_socks[i], SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
            if (ret < 0)
            {
                ngx_log_error(NGX_LOG_CRIT, rdma_log, 0, "setsockopt(TCP_KEEPIDLE) control server");
                goto error;
            }
            /* ret = set_socket_nonblocking(cfg->control_server_socks[i]); */
            /* if (ret < 0) */
            /* { */
            /*     ngx_log_error(NGX_LOG_CRIT, rdma_log, 0, "set sock non_blocking fail"); */
            /*     goto error; */
            /* } */
        }
    }

    return 0;
error:
    destroy_control_server_socks(cfg);
    return -1;
}

int exchange_rdma_info(struct rdma_config *cfg)
{
    ngx_log_error(NGX_LOG_CRIT, rdma_log, 0, "start exchange rdma info");
    int ret = 0;
    uint32_t local_idx = cfg->local_node_idx;
    uint32_t node_num = cfg->n_nodes;
    ret = init_local_ib_res(&(cfg->rdma_ctx), &(cfg->node_res[local_idx].ibres));
    if (ret != RDMA_SUCCESS) {
        ngx_log_error(NGX_LOG_CRIT, rdma_log, 0, "init local ib res failed");
        goto error;
    }
    for (size_t i = 0; i < node_num; i++)
    {
        if (i == local_idx)
        {
            continue;
        }
        if (i < local_idx)
        {
            ret = send_ib_res(&(cfg->node_res[local_idx].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "send res to node idx %d failed", i);
                goto error;
            }
            ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "local ibres sent to node %l", i);
            ret = recv_ib_res(&(cfg->node_res[i].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "recv res from node idx %l failed", i);
                goto error;
            }
            ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "remote ibres recv from node %l", i);
        }
        if (i > local_idx)
        {
            printf("here recv");
            ret = recv_ib_res(&(cfg->node_res[i].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "recv res from node idx %l failed", i);
                goto error;
            }
            ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "remote ibres recv from node %l", i);
            ret = send_ib_res(&(cfg->node_res[local_idx].ibres), cfg->control_server_socks[i]);
            if (ret != RDMA_SUCCESS)
            {
                ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "send res to node idx %l failed", i);
                goto error;
            }
            ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "local ibres sent to node %l", i);
        }
    }
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "finished exchange information with all nodes");
    for (size_t i = 0; i < node_num; i++)
    {
        if (cfg->use_one_side == 0)
        {
            ret = rdma_two_side_node_res_init(&(cfg->node_res[i].ibres), &(cfg->node_res[i]));
        }
        if (ret != RDMA_SUCCESS)
        {
            ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "init node_res for idx %d failed", i);
            goto error;
        }
    }
    for (size_t i = 0; i < cfg->node_res[local_idx].n_qp; i++)
    {
        cfg->node_res[local_idx].qpres[i].qp = cfg->rdma_ctx.qps[i];
    }
    return 0;
error:
    return -1;
}
void save_mempool_element_address(struct rte_mempool *mp, void *opaque, void *obj, unsigned int idx)
{
    void **addr_list = (void **)opaque;
    addr_list[idx] = obj;
}

void retrieve_mempool_addresses(struct rte_mempool *mp, void **addr_list)
{
    rte_mempool_obj_iter(mp, save_mempool_element_address, addr_list);
}

int rdma_init(struct rdma_config *cfg, struct rte_mempool *mp)
{
    int ret = 0;

    struct rdma_param rparams = {
        .qp_num = cfg->nodes[cfg->local_node_idx].qp_num,
        .device_idx = cfg->nodes[cfg->local_node_idx].device_idx,
        .sgid_idx = cfg->nodes[cfg->local_node_idx].sgid_idx,
        .ib_port = cfg->nodes[cfg->local_node_idx].ib_port,
        .init_cqe_num = cfg->rdma_init_cqe_num,
        .max_send_wr = cfg->rdma_max_send_wr,
        .n_send_wc = MAX_PKT_BURST,
        .n_recv_wc = MAX_PKT_BURST,
    };
    if (cfg->use_one_side == 0)
    {
        rparams.local_mr_num = 0;
        rparams.local_mr_size = 0;
        rparams.remote_mr_num = cfg->local_mempool_size;
        rparams.remote_mr_size = cfg->local_mempool_elt_size;
    }

    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "local mr_size: %l", rparams.local_mr_size);
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "remote mr_size: %l", rparams.remote_mr_size);

    cfg->local_mempool_addrs = (void **)calloc(cfg->local_mempool_size, sizeof(void *));
    if (!cfg->local_mempool_addrs)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "failed to allocate local_mempool_addrs");
        goto error;
    }
    retrieve_mempool_addresses(cfg->mempool, cfg->local_mempool_addrs);


    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "init RDMA ctx");

    if (cfg->use_one_side == 0)
    {
        ret = init_ib_ctx(&cfg->rdma_ctx, &rparams, NULL, cfg->local_mempool_addrs);
    }

    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "init RDMA ctx finished");
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "send cqe: %l", cfg->rdma_ctx.send_cqe);
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "recv cqe: %l", cfg->rdma_ctx.recv_cqe);
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "srq qe: %l", cfg->rdma_ctx.srqe);

    cfg->rdma_unsignal_freq = cfg->rdma_ctx.max_send_wr / 2;
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "unsignaled freq: %l", cfg->rdma_unsignal_freq);

    if (unlikely(ret != RDMA_SUCCESS))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "init ib ctx fail");
        goto error;
    }

    cfg->mp_elt_to_mr_map = g_hash_table_new(g_direct_hash, g_direct_equal);
    if (!cfg->mp_elt_to_mr_map)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "failed to allocate mp_elt_to_mr_map");
        goto error;
    }
    if (cfg->use_one_side == 0)
    {
        for (size_t i = 0; i < rparams.remote_mr_num; i++)
        {
            g_hash_table_insert(cfg->mp_elt_to_mr_map, (gpointer)cfg->local_mempool_addrs[i],
                                cfg->rdma_ctx.remote_mrs[i]);
            /* ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "mr addr: %p, mp_elt addr: %p", cfg->rdma_ctx.remote_mrs[i]->addr,
             * cfg->local_mempool_addrs[i]); */
        }
    }

    cfg->node_res = (struct rdma_node_res *)calloc(cfg->n_nodes, sizeof(struct rdma_node_res));

    if (unlikely(cfg->node_res == NULL))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "allocate node res fail");
        goto error;
    }
    return 0;
error:
    ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "init RDMA failed");
    rdma_exit(cfg);
    exit(1);
}

int rdma_exit(struct rdma_config *cfg)
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

int rdma_qp_connection_init_node(struct rdma_config* cfg, uint32_t remote_node_idx)
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
            ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "init qp to node: %l, qp_num: %l failed", remote_node_idx, remote_qp_slot_start + i);
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

        ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "pushed connected_qp_res to node_idx: %l from qp_num: %l to %l, array size %d", remote_node_idx,
                  cqp.local_qpres->qp_num, cqp.remote_qpres->qp_num, remote_res->connected_qp_res_array->len);
    }
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "%l RDMA_connections to node: %l established", n_qp_connect, remote_node_idx);
    return 0;
error:

    return -1;
}

int post_two_side_srq_recv(struct rdma_config * cfg, uint32_t wr_id, void **addr)
{
    int ret = 0;
    ret = rte_mempool_get(cfg->mempool, addr);
    if (unlikely(ret < 0))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "rte_mempool_get() error: %s", rte_strerror(-ret));
        goto error;
    }
    struct ibv_mr *mr = (struct ibv_mr *)g_hash_table_lookup(cfg->mp_elt_to_mr_map, (gpointer) * (addr));
    if (mr == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "txn: %p not valid", *addr);
        goto error;
    }
    /* ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "mr addr: %p, mp_elt addr: %p", mr->addr, *addr); */
    if (mr->addr != *addr)
    {
        ngx_log_error(NGX_LOG_CRIT, rdma_log, 0, "looked up mr addr does not equal to mp_elt addr");
        goto error;
    }
    /* ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "get mp elt addr: %p", *addr); */
    ret = post_srq_recv(cfg->rdma_ctx.srq, mr->addr, sizeof(struct dummy_pkt), mr->lkey, wr_id);
    if (unlikely(ret != RDMA_SUCCESS))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "post srq fail");
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

int rdma_qp_connection_init(struct rdma_config * cfg)
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
        ret = rdma_qp_connection_init_node(cfg, i);
        if (ret != 0)
        {
            ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "connect qp to node: %l failed", i);
            goto error;
        }
    }

    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "rdma connection initialized");

    size_t num_srq = MIN(cfg->rdma_ctx.srqe, cfg->mempool->size);
    num_srq = MIN(num_srq, 1000);
    if (cfg->use_one_side == 0)
    {
        for (size_t i = 0; i < num_srq; i++)
        {

            ret = post_two_side_srq_recv(cfg, i, &addr);
            if (unlikely(ret == -1))
            {
                ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "pre post srq recv failed");
                goto error;
            }
            g_hash_table_insert(cfg->node_res[local_idx].wr_to_addr, GINT_TO_POINTER(i), addr);
            /* ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "insert %p into map", addr); */
        }
        ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "post two side srq recv finished");
    }
    return 0;
error:
    return -1;
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
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "Failed to allocate qp_res");
        return RDMA_FAILURE;
    }
    for (size_t i = 0; i < ibres->n_qp; i++)
    {
        g_hash_table_insert(noderes->qp_num_to_qp_res, GUINT_TO_POINTER(ibres->qp_nums[i]), &noderes->qpres[i]);

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








int qp_num_to_qp_res(struct rdma_node_res *res, uint32_t qp_num, struct qp_res **qpres)
{
    *qpres = (struct qp_res *)g_hash_table_lookup(res->qp_num_to_qp_res, GUINT_TO_POINTER(qp_num));
    return RDMA_SUCCESS;
}



int select_qp_rr(int peer_node_idx, struct rdma_node_res *noderes, struct connected_qp **qpres)
{
    int array_size = noderes->connected_qp_res_array->len;
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "size of array: %d", array_size);
    if (array_size == 0)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "no qp connected for node: %l", peer_node_idx);
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
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "size of array: %d", array_size);
    if (array_size == 0)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "no qp connected for node: %l", peer_node_idx);
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



/**
 * @brief send packet at txn to peer_node_idx.
 *
 * @param cfg the rdma_config structure.
 * @param peer_node_idx the idx of the destination node
 * @param txn the pointer to the pkt to be sent, the pkt should be in the mempool and the address is the address of the mempool element.
 * @return -1 is error state, 0 is success
 */
int rdma_send(struct rdma_config * cfg, int peer_node_idx, struct dummy_pkt *txn)
{
    int ret = 0;
    int num_completion;

    int message_size = sizeof(struct dummy_pkt);

    struct connected_qp *cqp = NULL;
    ret = select_qp_rr(peer_node_idx, &cfg->node_res[peer_node_idx], &cqp);
    if (unlikely(ret == -1))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "select qp fail");
        goto error;
    }

    struct qp_res *local_qpres = cqp->local_qpres;

    struct ibv_mr *local_mr = (struct ibv_mr *)g_hash_table_lookup(cfg->mp_elt_to_mr_map, (gpointer)txn);
    if (local_mr == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "txn: %p not valid", txn);
        goto error;
    }

    /* txn->rdma_send_node_idx = cfg->local_node_idx; */
    /* txn->rdma_send_qp_num = local_qpres->qp_num; */
    /* txn->rdma_recv_node_idx = peer_node_idx; */
    /* txn->rdma_recv_qp_num = local_qpres->peer_qp_id.qp_num; */

    // force a completion when we have already sent out unsignaled_cnt requests
    if (local_qpres->unsignaled_cnt == cfg->rdma_unsignal_freq)
    {
        ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "post write imm signaled");
        ret = post_send_signaled(local_qpres->qp, (char *)txn, message_size, local_mr->lkey, 0, 0);
        local_qpres->unsignaled_cnt = 0;
        do
        {
            num_completion = ibv_poll_cq(cfg->rdma_ctx.send_cq, MAX_PKT_BURST, cfg->rdma_ctx.send_wc);
        } while (num_completion == 0);
        if (unlikely(num_completion < 0))
        {
            ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "poll send completion error");
            goto error;
        }
        local_qpres->outstanding_cnt -= num_completion;
    }
    else
    {
        ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "post write imm unsignaled");
        ret = post_send_unsignaled(local_qpres->qp, (char *)txn, message_size, local_mr->lkey, 0, 0);
        local_qpres->unsignaled_cnt++;
        local_qpres->outstanding_cnt++;
    }
    if (unlikely(ret != RDMA_SUCCESS))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "post imm unsignaled failed");
        goto error;
    }

    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "peer_node_idx: %d \t sizeof(*txn): %ld", peer_node_idx, sizeof(*txn));
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "rpc_client_send is done.");
    return 0;

error:
    return -1;
}

/**
 * @brief recv packets, each packets is stored as one element in the shared memory.
 *
 * @param cfg the rdma_config structure.
 * @param pkt_ptrs a list of void pointers to hold the pointer to the received packets, the values will be either NULL or a pointer to a shared memory element. The caller should iterate the first pkt_ptrs_len element and judge if it is NULL to get the pointer.
 * @param pkt_ptrs_len a pointer points to the length of the pkt_ptrs list. When passed in, it holds the length of pkt_ptrs, which should be larger then the MAX_PKT_BURST. After the function call, it will be set to the length of ptr received.
 * @return -1 is error state, else are the number of received pkts
 */
int rdma_recv(struct rdma_config * cfg, void** pkt_ptrs, size_t pkt_ptrs_len)
{
    assert(pkt_ptrs_len >= MAX_PKT_BURST);

    ngx_log_error(NGX_LOG_INFO, rdma_log, 0, "rdma_rpc_server init");
    int n_events;
    int i;
    struct dummy_pkt *txn = NULL;
    int ret = 0;
    uint32_t wr_id = 0;
    void *new_addr = NULL;

    struct rdma_node_res local_noderes = cfg->node_res[cfg->local_node_idx];

    struct ibv_wc *wc = cfg->rdma_ctx.recv_wc;
    if (unlikely(!wc))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "allocate %l ibv_wc failed", MAX_PKT_BURST);
        goto error;
    }
    ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "rdma_rpc_server initialized");

    n_events = ibv_poll_cq(cfg->rdma_ctx.recv_cq, MAX_PKT_BURST, wc);
    if (unlikely(n_events < 0))
    {
        ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "failed to poll cq");
        goto error;
    }
    for (i = 0; i < n_events; i++)
    {

        ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "Receiving from PEER GW.");
        if (wc[i].status != IBV_WC_SUCCESS)
        {
            ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "wc failed status: %s.", ibv_wc_status_str(wc[i].status));
            goto error;
        }

        wr_id = wc[i].wr_id;
        if (wc[i].opcode == IBV_WC_RECV)
        {
            /* if (wc[i].byte_len != sizeof(struct dummy_pkt)) */
            /* { */
            /*     ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "recved len %l, not size of dummy_pkt", wc[i].byte_len); */
            /*     goto error; */
            /* } */

            txn = (struct dummy_pkt *)g_hash_table_lookup(local_noderes.wr_to_addr, GINT_TO_POINTER(wr_id));

            pkt_ptrs[i] = txn;

            ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "current wr_id is %l", wr_id);
        }
        else
        {
            ngx_log_error(NGX_LOG_DEBUG, rdma_log, 0, "receive opcode %l", wc[i].opcode);
            pkt_ptrs[i] = NULL;
        }

        ret = post_two_side_srq_recv(cfg, wr_id, &new_addr);
        if (unlikely(ret != 0))
        {
            ngx_log_error(NGX_LOG_ERR, rdma_log, 0, "post srq recv failed");
            goto error;
        }
        g_hash_table_insert(local_noderes.wr_to_addr, GINT_TO_POINTER(wr_id), new_addr);

    }
    return n_events;

error:
    return -1;
}
