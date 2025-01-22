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

#define MAX_PORT_LEN 6
#define MAX_EVENTS 64

DOCA_LOG_REGISTER(RDMA_SERVER::MAIN);

struct pdin_rdma_md_s {
    void *ngx_http_request_pt; /* pointer to received HTTP request */
    void *pdin_rdma_handler_pt; /* pointer to callback handler */
    void *pdin_rdma_handler_log_pt; /* pointer to handler log */
    void *ngx_http_request_mempool_pt; /* pointer to request mempool */
};

uint32_t NUM_BUFS_PER_PDIN_WORKER_PROCESS = DEFAULT_RDMA_TASK_NUM;

uint32_t MAX_NUM_PDIN_WORKERS = 40;
struct {
    int clt_sk_fds[40];
    int n_clts_connected;
} clt_sks_md;

std::unordered_map<struct doca_buf*, struct doca_buf*> dpu_buf_to_host_buf;
std::unordered_map<struct doca_buf*, struct doca_buf*> dst_buf_to_src_buf;
std::unordered_map<struct doca_buf*, struct doca_rdma_task_receive*> dst_buf_to_recv_task;

int
int_to_port_str(int port, char *ret, size_t len)
{
    if (!ret) {
        DOCA_LOG_ERR("port buffer not valid");
        return -1;
    }

    if (len < MAX_PORT_LEN) {
        DOCA_LOG_ERR("char buffer too small");
        return -1;
    }

    snprintf(ret, MAX_PORT_LEN, "%d", port);
    return 0;
}

ssize_t
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

int
sock_utils_bind(char *ip, char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sock_fd = -1, ret = 0;
    int opt = 1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;

    ret = getaddrinfo(ip, port, &hints, &result);
    if (ret != 0) {
        DOCA_LOG_ERR("Error, fail to create sock bind");
        goto error;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock_fd < 0) {
            continue;
        }

        // Set SO_REUSEADDR to reuse the address
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            DOCA_LOG_ERR("%s: setsockopt(SO_REUSEADDR) failed", strerror(errno));
            close(sock_fd);
            continue;
        }

        ret = bind(sock_fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            /* bind success */
            break;
        }

        close(sock_fd);
        sock_fd = -1;
    }
    if (rp == NULL) {
        DOCA_LOG_ERR("Error, create socket");
        goto error;
    }

    freeaddrinfo(result);
    return sock_fd;

error:
    if (result) {
        freeaddrinfo(result);
    }
    if (sock_fd > 0) {
        close(sock_fd);
    }
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

    // result = doca_rdma_set_connection_state_callbacks(
    //     resources->rdma, cb_cfg->doca_rdma_connect_request_cb, cb_cfg->doca_rdma_connect_established_cb,
    //     cb_cfg->doca_rdma_connect_failure_cb, cb_cfg->doca_rdma_disconnect_cb);
    // if (result != DOCA_SUCCESS)
    // {
    //     DOCA_LOG_ERR("Failed to set rdma cm callback configuration, error: %s", doca_error_get_descr(result));
    //     return result;
    // }

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
rdma_server_alloc_bufs_and_submit_recv_tasks(struct rdma_resources *resources)
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

doca_error_t
rdma_server_multi_conn_recv_export_and_connect(struct rdma_resources *resources,
                                        struct doca_rdma_connection **connections,
                                        uint32_t n_connections)
{
    doca_error_t result = DOCA_SUCCESS;
    uint32_t i = 0;
    int sock_fd;

    resources->remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);
    if (!resources->remote_rdma_conn_descriptor) {
        return DOCA_ERROR_NO_MEMORY;
    }

    /* 1-by-1 to setup all the connections */
    for (i = 0; i < n_connections; i++) {
        DOCA_LOG_INFO("Start to establish RDMA connection [%d]", i);

        /* Ensure the control path has been established */
        while (clt_sks_md.clt_sk_fds[i] == -1) {
            DOCA_LOG_DBG("Control path with client [%u] is not ready.", i);
            sleep(0.1);
        }
        sock_fd = clt_sks_md.clt_sk_fds[i];

        /* Export RDMA connection details */
        result = doca_rdma_export(resources->rdma, &(resources->rdma_conn_descriptor),
                                  &(resources->rdma_conn_descriptor_size), &connections[i]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to export RDMA: %s", doca_error_get_descr(result));
            return result;
        }
        
        result = sock_recv_buffer(resources->remote_rdma_conn_descriptor,
                                  &resources->remote_rdma_conn_descriptor_size,
                                  MAX_RDMA_DESCRIPTOR_SZ, sock_fd);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to write and read connection details from receiver: %s", doca_error_get_descr(result));
            return result;
        }

        result = sock_send_buffer(resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size, sock_fd);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to send details from sender: %s", doca_error_get_descr(result));
            return result;
        }

        /* Connect RDMA RC connection */
        result = doca_rdma_connect(resources->rdma, resources->remote_rdma_conn_descriptor,
                                   resources->remote_rdma_conn_descriptor_size, connections[i]);
        if (result != DOCA_SUCCESS)
            DOCA_LOG_ERR("Failed to connect the sender's RDMA to the receiver's RDMA: %s",
                         doca_error_get_descr(result));

        DOCA_LOG_INFO("RDMA connection [%d] is establshed", i);
    }

    /* Free remote connection descriptor */
    free(resources->remote_rdma_conn_descriptor);
    resources->remote_rdma_conn_descriptor = NULL;

    return result;
}

static void
server_rdma_state_changed_callback(const union doca_data user_data,
                                   struct doca_ctx *ctx,
                                   enum doca_ctx_states prev_state,
                                   enum doca_ctx_states next_state)
{
    (void)ctx;
    (void)prev_state;

    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    doca_error_t result;

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
        DOCA_LOG_INFO("RDMA context is in RUNNING state. Establishing RC connections with [%u] clients...", resources->cfg->n_thread);

        /* Establish RC connection (data path) with RDMA clients */
        result = rdma_server_multi_conn_recv_export_and_connect(resources, resources->connections,
                                                         resources->cfg->n_thread);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_INFO("Failed to establish RC connection (data path) with RDMA clients");
        }

        /* Allocate send/recv bufs from DOCA buffer inventory and submit recv tasks */
        result = rdma_server_alloc_bufs_and_submit_recv_tasks(resources);
        JUMP_ON_DOCA_ERROR(result, error);

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

error:
    DOCA_LOG_INFO("DOCA RDMA context status change error.");
    doca_ctx_stop(ctx);
    destroy_inventory(resources->buf_inventory);
    destroy_rdma_resources(resources, resources->cfg);
}

doca_error_t
run_server(void *cfg)
{
    doca_error_t result;
    struct rdma_config *config = (struct rdma_config *)cfg;

    struct rdma_resources resources;
    memset(&resources, 0, sizeof(struct rdma_resources));
    resources.cfg = config;
    // resources.cfg->sock_fd = skt_fd;

    resources.run_pe_progress = true;
    resources.remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);

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
        .state_change_cb = server_rdma_state_changed_callback,
    };

    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t total_memrange_size = (uint32_t) 2 * (uint32_t) config->msg_sz * (uint32_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS * (uint32_t) MAX_NUM_PDIN_WORKERS;

    DOCA_LOG_INFO("total_memrange_size: %u", total_memrange_size);

    /* Open DOCA device, configure mmap, mem range, create DOCA RDMA context */
    result = allocate_rdma_resources(config, mmap_permissions, rdma_permissions, doca_rdma_cap_task_receive_is_supported,
                                     &resources, total_memrange_size, config->n_thread);
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
    uint64_t inv_num = (uint64_t) resources.cfg->n_thread * 2 * (uint64_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS;
    result = init_inventory(&resources.buf_inventory, inv_num);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init_inventory: %s", doca_error_get_descr(result));
        goto error;
    }

    result = doca_ctx_start(resources.rdma_ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to start RDMA context: %s", doca_error_get_descr(result));
        return result;
    }

    DOCA_LOG_INFO("Server joins the event loop.");
    while (resources.run_pe_progress == true) {
        doca_pe_progress(resources.pe);
    }
    DOCA_LOG_INFO("Server left the event loop");
    return DOCA_SUCCESS;

error:
    DOCA_LOG_INFO("DOCA RDMA context status change error.");
    destroy_inventory(resources.buf_inventory);
    destroy_rdma_resources(&resources, resources.cfg);

    return result;
}

void *
run_epoll_thread(void *arg)
{
    struct sockaddr *server_addr = (struct sockaddr *)arg;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    bind(server_fd, (struct sockaddr *)server_addr, sizeof(struct sockaddr));
    listen(server_fd, 128);

    int epoll_fd = epoll_create1(0);
    struct epoll_event event, events[MAX_EVENTS];

    event.events = EPOLLIN;
    event.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);

    /* Init. clt_sks_md */
    for (uint32_t j = 0; j < MAX_NUM_PDIN_WORKERS; j++ ) {
        clt_sks_md.clt_sk_fds[j] = -1;
    }
    clt_sks_md.n_clts_connected = 0;

    DOCA_LOG_INFO("Server starts epoll event loop.");
    while (1) {
        int n_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < n_events; i++) {
            if (events[i].data.fd == server_fd) {
                int client_fd = accept(server_fd, NULL, NULL); /* Accept a new connection from client */

                /* Save the client socket fd */
                clt_sks_md.clt_sk_fds[clt_sks_md.n_clts_connected] = client_fd;
                clt_sks_md.n_clts_connected++;
            } else {
                DOCA_LOG_ERR("Server epoll is only for control path connection establishment!");
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
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

    DOCA_LOG_INFO("Starting the sample");

    /* Parse cmdline/json arguments */
    result = doca_argp_init("doca_comch_ctrl_path_client", &cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
        goto sample_exit;
    }

    result = register_rdma_common_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register CC client sample parameters: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
        goto argp_cleanup;
    }

    /* Create an epoll thread for establishing control path */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    // server_addr.sin_addr.s_addr = INADDR_ANY;
    inet_pton(AF_INET, cfg.sock_ip, &(server_addr.sin_addr));
    server_addr.sin_port = htons(cfg.sock_port);

    pthread_t epoll_thread;
    pthread_create(&epoll_thread, NULL, run_epoll_thread, (void*) &server_addr);

    run_server(&cfg);

    pthread_join(epoll_thread, NULL);

    exit_status = EXIT_SUCCESS;

argp_cleanup:
    doca_argp_destroy();

sample_exit:
    if (exit_status == EXIT_SUCCESS)
        DOCA_LOG_INFO("Sample finished successfully");
    else
        DOCA_LOG_INFO("Sample finished with errors");
    return exit_status;
}
