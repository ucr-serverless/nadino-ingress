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

#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <thread>
#include <vector>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <iostream>
#include <mutex>
#include <vector>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include "comch_ctrl_path_common.h"
#include "comch_utils.h"
#include "common_doca.h"
#include "dma_common_doca.h"
#include "doca_buf.h"
#include "doca_comch.h"
#include "doca_ctx.h"
#include "doca_dma.h"
#include "doca_error.h"
#include "doca_pe.h"
#include "doca_rdma.h"
#include "rdma_common_doca.h"
#include <netdb.h>
#include <unordered_map>

DOCA_LOG_REGISTER(RDMA_SERVER::MAIN);

#define MAX_PORT_LEN 6

/* Epoll configs */
#define BACKLOG (1U << 16)
#define MAX_EVENTS 64

struct epoll_params {
    struct rdma_config *cfg;
    struct rdma_resources *resources;
};

/* HPA/DNE OP codes */
#define DNE_ACK_READY 200 /* DNE notifies HPA that PDIN is ready */
#define HPA_SND_TERM  300 /* HPA notifies DNE to disconnect RC connections with PDIN */
#define DNE_ACK_TERM  400 /* DNE notifies HPA that PDIN can be reloaded */

#define HPA_SERVER_PORT 9000

struct pdin_rdma_md_s {
    void *ngx_http_request_pt; /* pointer to received HTTP request */
    void *pdin_rdma_handler_pt; /* pointer to callback handler */
    void *pdin_rdma_handler_log_pt; /* pointer to handler log */
    void *ngx_http_request_mempool_pt; /* pointer to request mempool */
};

uint32_t NUM_BUFS_PER_PDIN_WORKER_PROCESS = DEFAULT_RDMA_TASK_NUM;
uint32_t MAX_NUM_PDIN_WORKERS = 40;

struct {
    int clt_sk_fds[MAX_NUM_CONNECTIONS];
    uint32_t n_clts_connected;
} pdin_clt_sks_md;

std::unordered_map<struct doca_buf*, struct doca_buf*> dpu_buf_to_host_buf;
std::unordered_map<struct doca_buf*, struct doca_buf*> dst_buf_to_src_buf;
std::unordered_map<struct doca_buf*, struct doca_rdma_task_receive*> dst_buf_to_recv_task;


static ssize_t
sock_utils_write(int sock_fd, void *buffer, size_t len)
{
    ssize_t nw, tot_written;
    const char *buf = (char *) buffer; // avoid pointer arithmetic on void pointer

    for (tot_written = 0; tot_written < (ssize_t) len;) {
        nw = write(sock_fd, buf, len - tot_written);

        if (nw <= 0) {
            if (nw == -1 && errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        }

        tot_written += nw;
        buf += nw;
    }
    return tot_written;
}

static ssize_t
sock_utils_read(int sock_fd, void *buffer, ssize_t len) {
    ssize_t nr, tot_read;
    char *buf = (char *) buffer; // avoid pointer arithmetic on void pointer
    tot_read = 0;

    while (len != 0 && (nr = read(sock_fd, buf, len)) != 0) {
        if (nr < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        }
        len -= nr;
        buf += nr;
        tot_read += nr;
    }

    return tot_read;
}

static int
conn_close(int epfd, int sockfd)
{
    int ret;

    if (epfd > 0) {
        ret = epoll_ctl(epfd, EPOLL_CTL_DEL, sockfd, NULL);
        if (ret == -1) {
            DOCA_LOG_ERR("epoll_ctl() error: %s", strerror(errno));
            goto error_1;
        }
    }

    ret = close(sockfd);
    if (ret == -1){
        DOCA_LOG_ERR("close() error: %s", strerror(errno));
        goto error_0;
    }

    return 0;

error_1:
    close(sockfd);
error_0:
    return -1;
}

doca_error_t
init_send_imm_rdma_resources_without_start(struct rdma_resources *resources,
                                           struct rdma_config *cfg,
                                           struct rdma_cb_config *cb_cfg)
{
    union doca_data ctx_user_data = {0};
    doca_error_t result, tmp_result;

    DOCA_LOG_INFO("Server prepared [%u] recv tasks and [%u] send tasks.", DEFAULT_RDMA_TASK_NUM, DEFAULT_RDMA_TASK_NUM);

    result = doca_rdma_task_receive_set_conf(resources->rdma, cb_cfg->msg_recv_cb, cb_cfg->msg_recv_err_cb,
                                             DEFAULT_RDMA_TASK_NUM);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to set configurations for RDMA receive task: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }
    result = doca_rdma_task_send_imm_set_conf(resources->rdma, cb_cfg->send_imm_task_comp_cb,
                                              cb_cfg->send_imm_task_comp_err_cb, DEFAULT_RDMA_TASK_NUM);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to set configurations for RDMA send task: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }

    result = doca_ctx_set_state_changed_cb(resources->rdma_ctx, cb_cfg->state_change_cb);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to set state change callback for RDMA context: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }

    /* Include the program's resources in user data of context to be used in callbacks */
    ctx_user_data.ptr = cb_cfg->ctx_user_data;
    result = doca_ctx_set_user_data(resources->rdma_ctx, ctx_user_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set context user data: %s", doca_error_get_descr(result));
        goto destroy_resources;
    }

    return result;

destroy_resources:
    tmp_result = destroy_rdma_resources(resources, cfg);
    if (tmp_result != DOCA_SUCCESS)
    {
        DOCA_LOG_ERR("Failed to destroy DOCA RDMA resources: %s", doca_error_get_descr(tmp_result));
        DOCA_ERROR_PROPAGATE(result, tmp_result);
    }
    return tmp_result;
}

void
server_rdma_recv_then_send_callback(struct doca_rdma_task_receive *recv_task,
                                    union doca_data task_user_data,
                                    union doca_data ctx_user_data)
{
    doca_error_t result;
    struct doca_rdma_task_send_imm *send_task;

    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;
    const struct doca_rdma_connection *conn = doca_rdma_task_receive_get_result_rdma_connection(recv_task);
    struct doca_rdma_connection *rdma_connection = (struct doca_rdma_connection *)conn;

    struct doca_buf *recv_buf = doca_rdma_task_receive_get_dst_buf(recv_task);
    if (recv_buf == NULL) {
        DOCA_LOG_ERR("Failed to get recv buffer.");
    }

    struct pdin_rdma_md_s *recv_data;
    result = doca_buf_get_data(recv_buf, (void **) &recv_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to get data from recv buffer.");
    }
    // printf("Received PDIN RDMA header: [r:%p] [handler:%p] [rlog:%p] [mp:%p]\n",
    //         recv_data->ngx_http_request_pt, recv_data->pdin_rdma_handler_pt, recv_data->pdin_rdma_handler_log_pt, recv_data->ngx_http_request_mempool_pt);

    auto src_buf = dst_buf_to_src_buf[recv_buf];

    struct pdin_rdma_md_s *sent_data;
    result = doca_buf_get_data(src_buf, (void **) &sent_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("get src buf fail");
    }

    /* Copy PDIN RDMA header from recv_data to send_data */
    sent_data->ngx_http_request_pt         = recv_data->ngx_http_request_pt;
    sent_data->pdin_rdma_handler_pt        = recv_data->pdin_rdma_handler_pt;
    sent_data->pdin_rdma_handler_log_pt    = recv_data->pdin_rdma_handler_log_pt;
    sent_data->ngx_http_request_mempool_pt = recv_data->ngx_http_request_mempool_pt;
    // printf("[src_buf] PDIN RDMA header: [r:%p] [handler:%p] [rlog:%p] [mp:%p]\n",
    //         sent_data->ngx_http_request_pt, sent_data->pdin_rdma_handler_pt, sent_data->pdin_rdma_handler_log_pt, sent_data->ngx_http_request_mempool_pt);

    doca_buf_reset_data_len(recv_buf);
    // print_doca_buf_len(recv_buf);

    /* Resubmit the recv task */
    result = doca_task_submit(doca_rdma_task_receive_as_task(recv_task));
    JUMP_ON_DOCA_ERROR(result, free_task);

    /* Submit the new send task */
    result = submit_send_imm_task(resources->rdma, rdma_connection, src_buf, 0, task_user_data, &send_task);
    JUMP_ON_DOCA_ERROR(result, free_task);
    return;

free_task:
    result = doca_buf_dec_refcount(recv_buf, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to decrease dst_buf count: %s", doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }
    doca_task_free(doca_rdma_task_receive_as_task(recv_task));
}

static doca_error_t
dne_alloc_bufs_and_submit_recv_tasks(struct rdma_resources *resources)
{
    doca_error_t result, tmp_result;
    uint32_t buf_inv_offset;

    struct doca_rdma_task_receive *recv_tasks[DEFAULT_RDMA_TASK_NUM] = {0};
    struct doca_buf *send_bufs[DEFAULT_RDMA_TASK_NUM] = {0};
    struct doca_buf *recv_bufs[DEFAULT_RDMA_TASK_NUM] = {0};

    struct doca_mmap *local_mmap = resources->mmap;
    char *start_addr = resources->mmap_memrange;

    union doca_data task_user_data = {0};
    task_user_data.ptr = resources;

    for (uint32_t i = 0; i < DEFAULT_RDMA_TASK_NUM; i++) {

        /* Allocate send bufs */
        buf_inv_offset = 2 * i * resources->cfg->msg_sz;
        // DOCA_LOG_INFO("[%u] buf_inv_offset: %u", i, buf_inv_offset);
        result = get_buf_from_inv_with_full_data_len(resources->buf_inventory, local_mmap,
                    start_addr + buf_inv_offset, resources->cfg->msg_sz, &send_bufs[i]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to allocate DOCA buffer [%d] to DOCA buffer inventory: %s", i,
                        doca_error_get_descr(result));
            return result;
        }

        /* Allocate recv bufs */
        buf_inv_offset = (2 * i + 1) * resources->cfg->msg_sz;
        // DOCA_LOG_INFO("[%u] buf_inv_offset: %u", i, buf_inv_offset);
        result = get_buf_from_inv_with_zero_data_len(resources->buf_inventory, local_mmap,
                    start_addr + buf_inv_offset, resources->cfg->msg_sz, &recv_bufs[i]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to allocate DOCA buffer [%d] to DOCA buffer inventory: %s", i,
                        doca_error_get_descr(result));
            return result;
        }

        dst_buf_to_src_buf[recv_bufs[i]] = send_bufs[i];

        /* Submit recv tasks (Must not exceed DEFAULT_RDMA_TASK_NUM) */
        result = submit_recv_task(resources->rdma, recv_bufs[i], task_user_data, &recv_tasks[i]);

        dst_buf_to_recv_task[recv_bufs[i]] = recv_tasks[i];
        JUMP_ON_DOCA_ERROR(result, destroy_src_buf);
    }

    DOCA_LOG_INFO("Server completed buffer allocation.");

    return result;

destroy_src_buf:
    for (uint32_t i = 0; i < NUM_BUFS_PER_PDIN_WORKER_PROCESS; i++) {
        tmp_result = doca_buf_dec_refcount(send_bufs[i], NULL);
        if (tmp_result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to decrease send_buf count: %s", doca_error_get_descr(tmp_result));
            DOCA_ERROR_PROPAGATE(result, tmp_result);
        }
    }

    return result;
}

/* TODO: Drain submitted tasks before disconnecting */
doca_error_t
dne_disconnect_pdin_workers(struct rdma_resources *resources)
{
    doca_error_t result = DOCA_SUCCESS;
    uint32_t i = 0;

    /* Disconnect control path connections */
    for (i = 0; i < pdin_clt_sks_md.n_clts_connected; i++) {
        if (shutdown(pdin_clt_sks_md.clt_sk_fds[i], SHUT_RDWR) == -1) {
            DOCA_LOG_ERR("Error in shutdown(): %s", strerror(errno));
        }

        if (close(pdin_clt_sks_md.clt_sk_fds[i]) == -1) {
            DOCA_LOG_ERR("Error in close(): %s", strerror(errno));
        }
        // pdin_clt_sks_md.clt_sk_fds[i] = -1;
    }
    // pdin_clt_sks_md.n_clts_connected = 0;

    /* Disconnect RDMA connections */
    for (i = 0; i < resources->num_connection_established; i++) {
        result = doca_rdma_connection_disconnect(resources->connections[i]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("DNE failed to disconnect RC connection [%u]: %s", i, doca_error_get_descr(result));
            break;
        } else {
            DOCA_LOG_INFO("DNE successfully disconnected RC connection [%u]", i);
        }
        // resources->connections[i] = NULL;
    }
    // resources->num_connection_established = 0;

    return result;
}

doca_error_t
dne_connect_pdin_worker(struct rdma_resources *resources, int clt_sk_fd, uint32_t clt_id)
{
    doca_error_t result = DOCA_SUCCESS;

    resources->remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);
    if (!resources->remote_rdma_conn_descriptor) {
        return DOCA_ERROR_NO_MEMORY;
    }

    DOCA_LOG_INFO("Start to establish RDMA connection with client [%d]", clt_id);

    /* Export RDMA connection details */
    result = doca_rdma_export(resources->rdma, &(resources->rdma_conn_descriptor),
                                &(resources->rdma_conn_descriptor_size), &resources->connections[clt_id]);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to export RDMA: %s", doca_error_get_descr(result));
        return result;
    }
    
    result = sock_recv_buffer(resources->remote_rdma_conn_descriptor,
                                &resources->remote_rdma_conn_descriptor_size,
                                MAX_RDMA_DESCRIPTOR_SZ, clt_sk_fd);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to write and read connection details from receiver: %s", doca_error_get_descr(result));
        return result;
    }

    result = sock_send_buffer(resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size, clt_sk_fd);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to send details from sender: %s", doca_error_get_descr(result));
        return result;
    }

    /* Connect RDMA RC connection */
    result = doca_rdma_connect(resources->rdma, resources->remote_rdma_conn_descriptor,
                                resources->remote_rdma_conn_descriptor_size, resources->connections[clt_id]);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to connect the sender's RDMA to the receiver's RDMA: %s",
                        doca_error_get_descr(result));

    DOCA_LOG_INFO("RDMA connection [%d] is establshed\n", clt_id);

    /* Free remote connection descriptor */
    free(resources->remote_rdma_conn_descriptor);
    resources->remote_rdma_conn_descriptor = NULL;

    return result;
}

static void
dne_state_changed_callback(const union doca_data user_data,
                                   struct doca_ctx *ctx,
                                   enum doca_ctx_states prev_state,
                                   enum doca_ctx_states next_state)
{
    (void)ctx;
    (void)prev_state;

    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;

    switch (next_state) {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("RDMA context has been stopped");
        /* We can stop progressing the PE */

        resources->run_pe_progress = false;
        break;
    case DOCA_CTX_STATE_STARTING:
        /* The context is in starting state, this is unexpected for CC server. */
        DOCA_LOG_ERR("RDMA context entered into starting state");
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("RDMA context is in RUNNING state. Establishing RC connections with clients...");
        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        DOCA_LOG_INFO("RDMA server context entered into stopping state. Terminating connections with clients (TODO).");
        break;
    default:
        break;
    }

    return;
}

int
create_server_socket(const char *ip, int port)
{
    int server_fd;
    int ret;
    int optval;
    struct sockaddr_in addr;
    
    server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (server_fd == -1) {
        DOCA_LOG_ERR("socket() error: %s", strerror(errno));
        return -1;
    }

    optval = 1;
    ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    if (ret == -1) {
        DOCA_LOG_ERR("setsockopt() error: %s", strerror(errno));
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    ret = bind(server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        DOCA_LOG_ERR("bind() error: %s", strerror(errno));
        return -1;
    }

    ret = listen(server_fd, BACKLOG);
    if (ret == -1) {
        DOCA_LOG_ERR("listen() error: %s", strerror(errno));
        return -1;
    }

    return server_fd;
}

void *
run_epoll_thread(void *args)
{
    struct epoll_params *epoll_thread_args = (struct epoll_params *) args;

    struct rdma_config    *cfg       = epoll_thread_args->cfg;
    struct rdma_resources *resources = epoll_thread_args->resources;
    doca_error_t result = DOCA_SUCCESS;

    struct epoll_event event, events[MAX_EVENTS];
    int rdma_cp_server_fd;
    int hpa_svr_fd, hpa_clt_fd = -1;

    /* Create server socket for RDMA control path */
    rdma_cp_server_fd = create_server_socket(cfg->sock_ip, cfg->sock_port);

    /* Create server socket for HPA control path */
    hpa_svr_fd = create_server_socket(cfg->sock_ip, HPA_SERVER_PORT);

    /* Create epoll */
    int epoll_fd = epoll_create1(0);

    /* Register server fds to epoll */
    event.events = EPOLLIN;
    event.data.fd = rdma_cp_server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, rdma_cp_server_fd, &event);

    event.events = EPOLLIN;
    event.data.fd = hpa_svr_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, hpa_svr_fd, &event);

    DOCA_LOG_INFO("DNE starts epoll event loop.");
    while (1) {
        int n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n_events == -1){
            DOCA_LOG_ERR("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        for (int i = 0; i < n_events; i++) {
            if (events[i].data.fd == rdma_cp_server_fd) {
                /* Accept a new control connection from PDIN worker */
                int rdma_cp_clt_fd = accept(rdma_cp_server_fd, NULL, NULL);
                DOCA_LOG_INFO("Accept a new control path connection from PDIN worker");

                /* Establish RC connection with PDIN worker */
                result = dne_connect_pdin_worker(resources, rdma_cp_clt_fd, resources->num_connection_established);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("DNE failed to establish RC connection [%u]: %s", resources->num_connection_established, doca_error_get_descr(result));
                }
                resources->num_connection_established++;

                /* Send DNE_ACK_READY to HPA (if already connected) */
                if (hpa_clt_fd > 0 && (resources->num_connection_established == 1)) {
                    int ack_code = DNE_ACK_READY;
                    ssize_t ret = sock_utils_write(hpa_clt_fd, (void *) &ack_code, sizeof(int));
                    if (ret > 0) {
                        DOCA_LOG_INFO("DNE returned DNE_ACK_READY [%d] to HPA.", ack_code);
                    } else {
                        DOCA_LOG_ERR("Failed to send DNE_ACK_READY to HPA.");
                    }
                }

                /* Save the client socket fd (for disconnection later) */
                pdin_clt_sks_md.clt_sk_fds[pdin_clt_sks_md.n_clts_connected] = rdma_cp_clt_fd;
                pdin_clt_sks_md.n_clts_connected++;

            } else if (events[i].data.fd == hpa_svr_fd) {
                /* Accept a new connection from HPA */
                hpa_clt_fd = accept(hpa_svr_fd, NULL, NULL);

                event.events = EPOLLIN;
                event.data.fd = hpa_clt_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, hpa_clt_fd, &event);
            } else if (events[i].data.fd == hpa_clt_fd && (events[i].events & EPOLLIN)) {
                /* Handle termination events from HPA client */
                int code;
                ssize_t bytes_read = sock_utils_read(hpa_clt_fd, (void *) &code, sizeof(int));

                if (bytes_read == 0) {
                    DOCA_LOG_WARN("HPA disconnected (fd: [%d])", hpa_clt_fd);
                    conn_close(epoll_fd, hpa_clt_fd);
                } else if (bytes_read < 0) {
                    if (errno == ECONNRESET || errno == EPIPE) {
                        DOCA_LOG_ERR("HPA disconnected unexpectedly (fd: [%d])", hpa_clt_fd);
                    } else {
                        DOCA_LOG_ERR("Recv error");
                    }
                    conn_close(epoll_fd, hpa_clt_fd);
                }

                if (code == HPA_SND_TERM) {
                    DOCA_LOG_INFO("DNE received HPA_SND_TERM [%d] from HPA.", code);
                } else {
                    DOCA_LOG_INFO("DNE received unexpected code [%d] from HPA (expected code: [%d]).", code, (int) HPA_SND_TERM);
                    continue;
                }

                /* TODO: Drain in-flight tasks before disconnecting */

                /* Disconnect RDMA connections with PDIN and send ACK to HPA */
                result = dne_disconnect_pdin_workers(resources);
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("DNE failed to disconnect RC connections: %s", doca_error_get_descr(result));
                }

                code = (int) DNE_ACK_TERM;
                ssize_t ret = sock_utils_write(hpa_clt_fd, (void *) &code, sizeof(int));
                if (ret > 0) {
                    DOCA_LOG_INFO("DNE returned DNE_ACK_TERM [%d] to HPA.", code);
                } else {
                    DOCA_LOG_ERR("Failed to send DNE_ACK_TERM to HPA.");
                }
            } else if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                DOCA_LOG_ERR("(EPOLLERR | EPOLLHUP) - Close the connection.");
                int ret = conn_close(epoll_fd, events[i].data.fd);
                if (ret == -1) {
                    DOCA_LOG_ERR("conn_close() error");
                }
            }
        }
    }

    close(rdma_cp_server_fd);
    close(epoll_fd);
}

doca_error_t
run_dne_server(void *cfg)
{
    doca_error_t result;
    struct rdma_config *config = (struct rdma_config *)cfg;

    struct rdma_resources resources;
    memset(&resources, 0, sizeof(struct rdma_resources));
    resources.cfg = config;
    resources.run_pe_progress = true;
    resources.remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);
    resources.num_connection_established = 0;

    struct rdma_cb_config cb_cfg = {
        .send_imm_task_comp_cb = basic_send_imm_completed_callback,
        .send_imm_task_comp_err_cb = basic_send_imm_completed_err_callback,
        .msg_recv_cb = server_rdma_recv_then_send_callback,
        .msg_recv_err_cb = rdma_recv_err_callback,
        .data_path_mode = false,
        .ctx_user_data = &resources,
        .doca_rdma_connect_request_cb = basic_rdma_connection_callback,
        .doca_rdma_connect_established_cb = basic_rdma_connection_established_callback,
        .doca_rdma_connect_failure_cb = basic_rdma_connection_failure,
        .doca_rdma_disconnect_cb = basic_rdma_disconnect_callback,
        .state_change_cb = dne_state_changed_callback,
    };

    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t total_memrange_size = (uint32_t) 2 * (uint32_t) config->msg_sz * (uint32_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS * (uint32_t) MAX_NUM_PDIN_WORKERS;

    DOCA_LOG_INFO("total_memrange_size: %u", total_memrange_size);

    /* Open DOCA device, configure mmap, mem range, create DOCA RDMA context, max num connections (2048) */
    result = allocate_rdma_resources(config, mmap_permissions, rdma_permissions, doca_rdma_cap_task_receive_is_supported,
                                     &resources, total_memrange_size, MAX_NUM_CONNECTIONS);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to allocate RDMA Resources: %s", doca_error_get_descr(result));
    }

    /* Configure send/recv tasks and callbacks */
    result = init_send_imm_rdma_resources_without_start(&resources, config, &cb_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init rdma server with error = %s", doca_error_get_name(result));
        return result;
    }

    /* Create DOCA buffer inventory */
    // uint64_t inv_num = (uint64_t) resources.cfg->n_thread * 2 * (uint64_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS;
    uint64_t inv_num = 2 * (uint64_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS;
    result = init_inventory(&resources.buf_inventory, inv_num);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init_inventory: %s", doca_error_get_descr(result));
        goto error;
    }

    /* Start RDMA context (must be done before establishing RC connections and submitting tasks) */
    result = doca_ctx_start(resources.rdma_ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start RDMA context: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create an epoll thread for establishing control path */
    struct epoll_params epoll_thread_args;
    epoll_thread_args.cfg = config;
    epoll_thread_args.resources = &resources;

    pthread_t epoll_thread;
    pthread_create(&epoll_thread, NULL, run_epoll_thread, &epoll_thread_args);

    /* Allocate send/recv bufs from DOCA buffer inventory and submit recv tasks */
    result = dne_alloc_bufs_and_submit_recv_tasks(&resources);
    JUMP_ON_DOCA_ERROR(result, error);

    DOCA_LOG_INFO("DNE begins polling DOCA PE.");
    while (resources.run_pe_progress == true) {
        doca_pe_progress(resources.pe);
    }
    DOCA_LOG_INFO("DNE stops polling DOCA PE.");

    pthread_join(epoll_thread, NULL);

    return DOCA_SUCCESS;

error:
    DOCA_LOG_INFO("DOCA RDMA context status change error.");
    doca_ctx_stop(resources.rdma_ctx);
    destroy_inventory(resources.buf_inventory);
    destroy_rdma_resources(&resources, resources.cfg);

    return result;
}

int
main(int argc, char **argv)
{
    struct rdma_config cfg;
    doca_error_t result;
    struct doca_log_backend *sdk_log;
    int exit_status = EXIT_FAILURE;

    set_default_config_value(&cfg);
    /* Register a logger backend */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    /* Register a logger backend for internal SDK errors and warnings */
    result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
    if (result != DOCA_SUCCESS)
        goto sample_exit;
    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
    if (result != DOCA_SUCCESS)
        goto sample_exit;

    DOCA_LOG_INFO("Starting DNE server");

    /* Parse cmdline/json arguments */
    result = doca_argp_init("doca_comch_ctrl_path_client", &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
        goto sample_exit;
    }

    result = register_rdma_common_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register parameters: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse input: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* Init. pdin_clt_sks_md */
    for (uint32_t j = 0; j < MAX_NUM_PDIN_WORKERS; j++ ) {
        pdin_clt_sks_md.clt_sk_fds[j] = -1;
    }
    pdin_clt_sks_md.n_clts_connected = 0;

    run_dne_server(&cfg);

    exit_status = EXIT_SUCCESS;

argp_cleanup:
    doca_argp_destroy();

sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("DNE finished successfully");
    else
        DOCA_LOG_INFO("DNE finished with errors");
    return exit_status;
}
