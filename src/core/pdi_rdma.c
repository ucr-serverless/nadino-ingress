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

#include <ngx_event.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/un.h>

#include "pdi_rdma.h"
#include <doca_log.h>
#include <doca_argp.h>
#include <doca_buf_pool.h>

#include <ngx_http.h>
#include "pdi_http.h"

DOCA_LOG_REGISTER(WORKER::PDI_RDMA);
struct doca_log_backend *sdk_log;

#define RETRY_DELAY_US 5000 /* 5 milliseconds */
#define MAX_RETRIES 2000    /* 10s timeout    */

uint32_t NUM_BUFS_PER_PDIN_WORKER_PROCESS = DEFAULT_RDMA_TASK_NUM; /* DEFAULT_RDMA_TASK_NUM = 4096 */
struct doca_buf_pool* pdin_buf_pool;
int rdma_ctrl_path_sockfd;
struct rdma_resources *pdin_send_resources;


doca_error_t
pdin_allocate_doca_mmap(const uint32_t mmap_permissions, struct rdma_resources *resources, uint64_t m_size)
{
    doca_error_t result;

    /* Allocate memory for memory range */
    if (m_size == 0) {
        DOCA_LOG_ERR("Requested Memory Size is Zero.");
        return DOCA_ERROR_NO_MEMORY;
    }

    resources->mmap_memrange = calloc(m_size, sizeof(char));
    if (resources->mmap_memrange == NULL) {
        result = DOCA_ERROR_NO_MEMORY;
        DOCA_LOG_ERR("Failed to allocate memory for mmap_memrange: %s", doca_error_get_descr(result));
        return result;
    }

    /* Create mmap with allocated memory */
    result = create_local_mmap(&(resources->mmap), mmap_permissions, (void *)resources->mmap_memrange, m_size,
                               resources->doca_device);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create DOCA mmap: %s", doca_error_get_descr(result));
        goto free_memrange;
    }
    DOCA_LOG_INFO("mmap range is %p", resources->mmap_memrange);

    return result;

free_memrange:
    free(resources->mmap_memrange);
    return result;
}

static void 
PDIN_LOG_RDMA_HEADER(struct doca_buf *buf)
{
    doca_error_t result;
    struct pdin_rdma_md_s *md;

    result = doca_buf_get_data(buf, (void **) &md);
    if (result != DOCA_SUCCESS) {
        printf("Failed to get RDMA header from doca_buf: %s\n",
                        doca_error_get_descr(result));
    }
    DOCA_LOG_INFO("PDIN RDMA header: [r:%p] [handler:%p] [rlog:%p] [mp:%p]",
                  md->ngx_http_request_pt, md->pdin_rdma_handler_pt,
                  md->pdin_rdma_handler_log_pt, md->ngx_http_request_mempool_pt);
}

static uint32_t
pdin_buf_pool_get_num_free_elements(struct doca_buf_pool *buf_pool)
{
    doca_error_t result;
    uint32_t num_of_free_elements;
    result = doca_buf_pool_get_num_free_elements(buf_pool, &num_of_free_elements);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to get num of elts within buffer pool: %s", doca_error_get_descr(result));
        return result;
    }

    return num_of_free_elements;
}

static uint32_t
pdin_buf_pool_get_num_elements(struct doca_buf_pool *buf_pool)
{
    doca_error_t result;
    uint32_t num_of_elements;
    result = doca_buf_pool_get_num_elements(buf_pool, &num_of_elements);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to get num of elts within buffer pool: %s", doca_error_get_descr(result));
        return result;
    }

    return num_of_elements;
}

static size_t
pdin_buf_pool_get_element_alignment(struct doca_buf_pool *buf_pool)
{
    doca_error_t result;
    size_t element_alignment;
    result = doca_buf_pool_get_element_alignment(buf_pool, &element_alignment);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to get elt alignment from buffer pool: %s", doca_error_get_descr(result));
        return result;
    }

    return element_alignment;
}


static uint16_t
pdin_get_buf_refcount(struct doca_buf *buf)
{
    uint16_t refcount;
    doca_error_t result = doca_buf_get_refcount(buf, &refcount);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to get the reference count of the doca_buf: %s", doca_error_get_descr(result));
        return 0;
    }

    return refcount;
}

static uint16_t
pdin_dec_buf_refcount(struct doca_buf *buf)
{
    uint16_t refcount;
    doca_error_t result = doca_buf_dec_refcount(buf, &refcount);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to decrease the reference count of the doca_buf: %s", doca_error_get_descr(result));
        return 0;
    }

    /* "refcount" is the number of references BEFORE this operation took place */
    return refcount - 1;
}

static struct doca_buf*
pdin_doca_mempool_get(struct doca_buf_pool* buf_pool, size_t buf_set_data_len)
{
    doca_error_t result;
    struct doca_buf *buf;
    uint32_t num_of_free_elements;

    result = doca_buf_pool_get_num_free_elements(buf_pool, &num_of_free_elements);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to get num of elts within buffer pool: %s", doca_error_get_descr(result));
        return NULL;
    }
    // DOCA_LOG_INFO("The total number of free elements available for allocation: %u", num_of_free_elements);
    
    if (num_of_free_elements == 0) {
        DOCA_LOG_INFO("DOCA buffer pool has no buffers!");
        return NULL;
    }

    result = doca_buf_pool_buf_alloc(buf_pool, &buf);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Failed to acquire a doca_buf from buffer pool: %s", doca_error_get_descr(result));
        return NULL;
    }

    /* Set data length for TX buffers */
    if (buf_set_data_len > 0) {
        doca_buf_set_data_len(buf, buf_set_data_len);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_INFO("Failed to set data length: %s", doca_error_get_descr(result));
            return NULL;
        }
    }

    // print_doca_buf_len(buf);
    // size_t total_len;
    // doca_buf_get_len(buf, &total_len);

    // printf("doca_buf_get_len: %lu\n", total_len);

    return buf;
}

static doca_error_t
pdin_doca_mempool_create(size_t num_elements, size_t element_size, struct doca_buf_pool **buf_pool, struct doca_mmap* mmap, uint32_t proc_id)
{
    doca_error_t result;

    result = doca_buf_pool_create(num_elements, element_size, mmap, buf_pool);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to create buffer pool: %s", proc_id, doca_error_get_descr(result));
        return result;
    }

    result = doca_buf_pool_start(*buf_pool);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to start buffer pool: %s", proc_id, doca_error_get_descr(result));
        return result;
    }

    // DOCA_LOG_INFO("The element alignment of the DOCA buffer pool: %zu", pdin_buf_pool_get_element_alignment(*buf_pool));
    // DOCA_LOG_INFO("The number of created elements in the buffer pool: %u", pdin_buf_pool_get_num_elements(*buf_pool));
    // DOCA_LOG_INFO("The total number of free elements available for allocation: %u", pdin_buf_pool_get_num_free_elements(*buf_pool));

    return result;
}

void
pdin_send_http_response(const char* response, ngx_http_request_t *r)
{
    ngx_buf_t *b;
    ngx_chain_t out;

    if (response == NULL || ngx_strlen(response) == 0) {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = 0;
        r->header_only = 1;

        ngx_http_send_header(r);
        ngx_http_finalize_request(r, NGX_DONE);
    } else {
        r->headers_out.status = NGX_HTTP_OK;
        r->headers_out.content_length_n = ngx_strlen(response);
        r->headers_out.content_type.len = sizeof("text/plain") - 1;
        r->headers_out.content_type.data = (u_char *)"text/plain";

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        b->pos = (u_char *)response;
        b->last = b->pos + ngx_strlen(response);
        b->memory = 1;
        b->last_buf = 1;

        out.buf = b;
        out.next = NULL;

        ngx_http_send_header(r);
        ngx_http_output_filter(r, &out);
        ngx_http_finalize_request(r, NGX_DONE);
    }
}

static void
pdin_rdma_recv_handler(ngx_http_request_t *r)
{
    if (r->connection->destroyed) {
        r->connection->close = 1;
        r->connection->error = 1;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Connection already destroyed");
        return;
    }

    const char *response = "";
    pdin_send_http_response(response, r); /* Construct and send response */

    return;
}

static void
pdin_rdma_post_http_response(struct http_transaction *ht)
{
    void *r = ht->pdin_md.ngx_http_request_pt;
    // void *handler = ht->pdin_md.pdin_rdma_handler_pt;
    // void *log = ht->pdin_md.pdin_rdma_handler_log_pt;
    // void *pool = ht->pdin_md.ngx_http_request_mempool_pt;

    pdin_rdma_recv_handler((ngx_http_request_t *)r);

    return;
}

static void
pdin_parse_ob_route_id(struct http_transaction *txn)
{
    // printf("%s\n", txn->request);
    const char *string = strstr(txn->request, "/");

    if (string == NULL) {
        txn->route_id = 0;
    } else {
        // Skip consecutive slashes in one step
        string += strspn(string, "/");

        errno = 0;
        txn->route_id = strtol(string, NULL, 10);
        if (errno != 0) {
            txn->route_id = 0;
        }
    }

    // DOCA_LOG_INFO("Route ID: %d", txn->route_id);
}

void pdin_trim_header(char *request) {
    const char *target = "/rdma";
    char *pos = strstr(request, target);  // Find "/rdma"

    if (pos) {
        size_t len = strlen(target);
        memmove(pos, pos + len, strlen(pos + len) + 1); // Shift left
    }
}

static ngx_int_t
pdin_copy_http_request(ngx_http_request_t *r, struct http_transaction* txn)
{
    size_t offset = 0;

    char* request = txn->request;

    // Copy request line
    offset += ngx_snprintf((u_char *) request + offset, HTTP_MSG_LENGTH_MAX - offset,
                           "%V %V %V\r\n",
                           &r->method_name, &r->unparsed_uri, &r->http_protocol)
              - (u_char *) request;

    // Copy headers
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;
    for (ngx_uint_t i = 0; i < part->nelts; i++) {
        if (offset < HTTP_MSG_LENGTH_HEADER_MAX) {
            offset += ngx_snprintf((u_char *) request + offset, HTTP_MSG_LENGTH_HEADER_MAX - offset,
                                   "%V: %V\r\n", &header[i].key, &header[i].value)
                      - (u_char *) request;
        }
    }

    // Append blank line after headers
    if (offset < HTTP_MSG_LENGTH_HEADER_MAX) {
        request[offset++] = '\r';
        request[offset++] = '\n';
    }

    // Copy body if present
    if (r->request_body && r->request_body->bufs) {
        ngx_chain_t *cl = r->request_body->bufs;
        while (cl && offset < HTTP_MSG_LENGTH_MAX) {
            ngx_buf_t *b = cl->buf;
            size_t len = ngx_min((size_t)(b->last - b->pos), HTTP_MSG_LENGTH_MAX - offset);
            ngx_memcpy(request + offset, b->pos, len);
            offset += len;
            cl = cl->next;
        }
    }

    return NGX_OK;
}

void
pdin_rdma_send(void *ngx_http_request_pt, void *pdin_rdma_handler_pt,
               void *pdin_rdma_handler_log_pt, void *ngx_http_request_mempool_pt)
{
    doca_error_t result;
    struct doca_rdma_task_send_imm *send_task;
    struct http_transaction *ht;
    struct rdma_resources *resources = (struct rdma_resources *) ngx_cycle->rdma_resources;

    struct doca_buf *send_buf = pdin_doca_mempool_get(pdin_buf_pool, (size_t) resources->cfg->msg_sz);
    // DOCA_LOG_INFO("The reference count of the send_buf: %u", pdin_get_buf_refcount(send_buf));
    // DOCA_LOG_INFO("The reference count of the send_buf: %u", pdin_dec_buf_refcount(send_buf));

    /* Allocate and construct RDMA send task */
    result = doca_buf_get_data(send_buf, (void **) &ht);
    if (result != DOCA_SUCCESS) {
        printf("Worker [%u] failed to get buf data: %s\n",
                        resources->id, doca_error_get_descr(result));
    }

    ht->pdin_md.ngx_http_request_pt = ngx_http_request_pt; /* pointer to received HTTP request */
    ht->pdin_md.pdin_rdma_handler_pt = pdin_rdma_handler_pt; /* pointer to callback handler */
    ht->pdin_md.pdin_rdma_handler_log_pt = pdin_rdma_handler_log_pt; /* pointer to handler log */
    ht->pdin_md.ngx_http_request_mempool_pt = ngx_http_request_mempool_pt; /* pointer to request mempool */
    // DOCA_LOG_INFO("Sent PDIN RDMA header: [r:%p] [handler:%p] [rlog:%p] [mp:%p]",
    //         ngx_http_request_pt, pdin_rdma_handler_pt, pdin_rdma_handler_log_pt, ngx_http_request_mempool_pt);

    pdin_copy_http_request((ngx_http_request_t *)ngx_http_request_pt, ht);
    pdin_trim_header(ht->request);
    pdin_parse_ob_route_id(ht);

    union doca_data task_user_data;
    task_user_data.ptr = &resources->first_encountered_error;

    result = submit_send_imm_task(resources->rdma, resources->connections[0],
                                  send_buf, 0, task_user_data, &send_task);
    if (result != DOCA_SUCCESS) {
        printf("Worker [%u] failed to submit send_imm task: %s\n",
                        resources->id, doca_error_get_descr(result));
    }
}

void
pdin_send_imm_completed_callback(struct doca_rdma_task_send_imm *send_task,
                                  union doca_data task_user_data,
                                  union doca_data ctx_user_data)
{
    struct doca_buf *send_buf = (struct doca_buf *)doca_rdma_task_send_imm_get_src_buf(send_task);
    // (void)PDIN_LOG_RDMA_HEADER(send_buf);

    // DOCA_LOG_INFO("The reference count of the send_buf: %u", pdin_dec_buf_refcount(send_buf));

    doca_task_free(doca_rdma_task_send_imm_as_task(send_task));
    pdin_dec_buf_refcount(send_buf);
}

void
client_rdma_recv_callback(struct doca_rdma_task_receive *recv_task,
                                    union doca_data task_user_data,
                                    union doca_data ctx_user_data)
{
    doca_error_t result;
    struct rdma_resources *resources = (struct rdma_resources *)ctx_user_data.ptr;

    struct doca_buf *recv_buf = doca_rdma_task_receive_get_dst_buf(recv_task);

    /* Parse PDIN RDMA header */
    struct http_transaction *recv_data;
    result = doca_buf_get_data(recv_buf, (void **) &recv_data);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to get buf data: %s",
                        resources->id, doca_error_get_descr(result));
    }

    // DOCA_LOG_INFO("Received PDIN RDMA header: [r:%p] [handler:%p] [rlog:%p] [mp: %p]",
    //         recv_data->ngx_http_request_pt, recv_data->pdin_rdma_handler_pt,
    //         recv_data->pdin_rdma_handler_log_pt, recv_data->ngx_http_request_mempool_pt);

    /* Post HTTP response event to NGINX event loop */
    pdin_rdma_post_http_response(recv_data);

    doca_buf_reset_data_len(recv_buf);

    resources->n_received_req++;
    // DOCA_LOG_INFO("Worker [%u] completed [%d] recv tasks: recv_buf addr [%p], resource->dst_buf [%p]",
    //             resources->id, resources->n_received_req, recv_buf, resources->dst_buf);

    result = doca_task_submit(doca_rdma_task_receive_as_task(recv_task));
    JUMP_ON_DOCA_ERROR(result, free_task);

    return;

free_task:
    result = doca_buf_dec_refcount(recv_buf, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to decrease dst_buf count: %s",
                        resources->id, doca_error_get_descr(result));
        DOCA_ERROR_PROPAGATE(result, result);
    }

    doca_task_free(doca_rdma_task_receive_as_task(recv_task));
    doca_ctx_stop(resources->rdma_ctx);

    DOCA_LOG_INFO("Worker [%u] closed DOCA RDMA context", resources->id);
}

static doca_error_t
pdin_rdma_conn_and_alloc_bufs(struct rdma_resources* resources)
{
    doca_error_t result;
    struct doca_buf *recv_bufs[NUM_BUFS_PER_PDIN_WORKER_PROCESS];
    struct doca_rdma_task_receive *recv_tasks[NUM_BUFS_PER_PDIN_WORKER_PROCESS];

    /* Export RDMA connection details */
    result = doca_rdma_export(resources->rdma, &(resources->rdma_conn_descriptor),
                              &(resources->rdma_conn_descriptor_size), &(resources->connections[0]));
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to export RDMA: %s", resources->id, doca_error_get_descr(result));
    }

print_buffer_hex((resources->rdma_conn_descriptor), resources->rdma_conn_descriptor_size);

printf("%d\n", __LINE__);
    /* Send RDMA connection details to the DNE */
    /* result = write_read_connection(resources->cfg, resources, i); */
    result = sock_send_buffer(resources->rdma_conn_descriptor, resources->rdma_conn_descriptor_size, rdma_ctrl_path_sockfd);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to send details from sender: %s", resources->id, doca_error_get_descr(result));
    }
    DOCA_LOG_INFO("Worker [%u] send details to DNE", resources->id);

    /* Wait for RDMA connection details from the DNE */
    result = sock_recv_buffer(resources->remote_rdma_conn_descriptor,
                                &resources->remote_rdma_conn_descriptor_size,
                                MAX_RDMA_DESCRIPTOR_SZ, rdma_ctrl_path_sockfd);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to recv details from sender: %s", resources->id, doca_error_get_descr(result));
    }
    DOCA_LOG_INFO("exchanged RDMA info on [%u]", resources->id);

print_buffer_hex((resources->remote_rdma_conn_descriptor), resources->remote_rdma_conn_descriptor_size);

printf("%d\n", __LINE__);
    /* Establish RC connection with the DNE */
    result = doca_rdma_connect(resources->rdma, resources->remote_rdma_conn_descriptor,
                               resources->remote_rdma_conn_descriptor_size, resources->connections[0]);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to connect the receiver's RDMA to the sender's RDMA: %s",
                    resources->id, doca_error_get_descr(result));
        (void)doca_ctx_stop(doca_rdma_as_ctx(resources->rdma));
    }
printf("%d\n", __LINE__);
    uint64_t inv_num = 2 * (uint64_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS;    
    // DOCA_LOG_INFO("Worker [%u] allocates [%lu] DOCA bufs", resources->id, inv_num);
    result = init_inventory(&resources->buf_inventory, inv_num);
    JUMP_ON_DOCA_ERROR(result, error);

    result = init_inventory(&pdin_send_resources->buf_inventory, inv_num);
    JUMP_ON_DOCA_ERROR(result, error);
    DOCA_LOG_INFO("Worker [%u]'s RDMA client context is running", resources->id);

    /* Allocate recv buffers and submit recv tasks */
    union doca_data task_user_data;
    task_user_data.ptr = &resources->first_encountered_error;
    uint32_t buf_inv_offset;

    for (uint32_t i = 0; i < NUM_BUFS_PER_PDIN_WORKER_PROCESS; i++) {
        buf_inv_offset = i * resources->cfg->msg_sz;
        // DOCA_LOG_INFO("[%u] buf_inv_offset: %u", i, buf_inv_offset);
        result = get_buf_from_inv_with_zero_data_len(resources->buf_inventory, resources->mmap,
                                                    resources->mmap_memrange + buf_inv_offset,
                                                    resources->cfg->msg_sz,
                                                    &recv_bufs[i]);
        if (result != DOCA_SUCCESS) {
            LOG_ON_FAILURE(result);
            return result;
        }

        result = submit_recv_task(resources->rdma, recv_bufs[i], task_user_data, &recv_tasks[i]);
        LOG_ON_FAILURE(result);
    }

    DOCA_LOG_INFO("Worker [%u] submits all recv tasks", resources->id);

    /* Allocate buffers for the send task */
    size_t num_elements = (size_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS;
    size_t element_size = (size_t) pdin_send_resources->cfg->msg_sz;
    result = pdin_doca_mempool_create(num_elements, element_size, &pdin_buf_pool, pdin_send_resources->mmap, pdin_send_resources->id);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%u] failed to create DOCA mempool: %s", pdin_send_resources->id, doca_error_get_descr(result));
        return result;
    }

    DOCA_LOG_INFO("Worker [%u] creates [%u] buffers for send tasks", resources->id, pdin_buf_pool_get_num_elements(pdin_buf_pool));

error:
    return result;
};

static void
client_rdma_state_changed_callback(const union doca_data user_data,
                                   struct doca_ctx *ctx,
                                   enum doca_ctx_states prev_state,
                                   enum doca_ctx_states next_state)
{
    doca_error_t result;

    struct rdma_resources *resources = (struct rdma_resources *)user_data.ptr;
    (void)ctx;
    (void)prev_state;

    switch (next_state) {
    case DOCA_CTX_STATE_IDLE:
        DOCA_LOG_INFO("Worker [%u]'s DOCA RDMA client has been stopped", resources->id);
        /* We can stop progressing the PE */

        resources->run_pe_progress = false;
        break;
    case DOCA_CTX_STATE_STARTING:
        /**
         * The context is in starting state, this is unexpected for CC server.
         */
        // need to get the connection object first
        DOCA_LOG_INFO("Worker [%u]'s DOCA RDMA client switched to STARTING state", resources->id);
        break;
    case DOCA_CTX_STATE_RUNNING:
        DOCA_LOG_INFO("Worker [%u]'s DOCA RDMA client is in RUNNING state", resources->id);

        result = pdin_rdma_conn_and_alloc_bufs(resources);
        LOG_ON_FAILURE(result);
        break;
    case DOCA_CTX_STATE_STOPPING:
        /**
         * The context is in stopping, this can happen when fatal error encountered or when stopping context.
         * doca_pe_progress() will cause all tasks to be flushed, and finally transition state to idle
         */
        doca_buf_dec_refcount(resources->dst_buf, NULL);
        DOCA_LOG_INFO("Worker [%u]'s DOCA RDMA client switched to STOPPING state", resources->id);
        break;
    default:
        break;
    }
}

void
pdin_init_doca_rdma_client_ctx(ngx_int_t proc_id, void *cfg, ngx_cycle_t *cycle)
{
    doca_error_t result;
    struct rdma_config *config = (struct rdma_config *)cfg;

    /* Set rdma_ctrl_path_sockfd */
    rdma_ctrl_path_sockfd = config->sock_fd;

    struct rdma_resources *resources = malloc(sizeof(struct rdma_resources));
    memset(resources, 0, sizeof(struct rdma_resources));
    resources->id = proc_id;
    resources->run_pe_progress = true;
    resources->remote_rdma_conn_descriptor = malloc(MAX_RDMA_DESCRIPTOR_SZ);
    resources->cfg = config;

    uint32_t mmap_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;
    uint32_t rdma_permissions = DOCA_ACCESS_FLAG_LOCAL_READ_WRITE;

    DOCA_LOG_INFO("msg size in mempool; [%d]", config->msg_sz);
    uint64_t total_memrange_size = (uint32_t) 2 * (uint32_t) config->msg_sz * (uint32_t) NUM_BUFS_PER_PDIN_WORKER_PROCESS;
    
    /* DOCA dev, mmap, PE, DOCA RDMA ctx */
    result = allocate_rdma_resources(config, mmap_permissions, rdma_permissions,
                                     doca_rdma_cap_task_receive_is_supported,
                                     resources, total_memrange_size, (uint16_t) 1);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%ld] failed to allocate RDMA Resources: %s",
                        proc_id, doca_error_get_descr(result));
        return;
    }

    /* Allocate memory resources for send tasks */
    pdin_send_resources = malloc(sizeof(struct rdma_resources));
    memset(pdin_send_resources, 0, sizeof(struct rdma_resources));
    pdin_send_resources->id = proc_id;
    pdin_send_resources->cfg = config;
    pdin_send_resources->doca_device = resources->doca_device;
    result = pdin_allocate_doca_mmap(mmap_permissions, pdin_send_resources, total_memrange_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%ld] failed to allocate Send Resources: %s",
                        proc_id, doca_error_get_descr(result));
        return;
    }

    struct rdma_cb_config cb_cfg = {
        .send_imm_task_comp_cb = pdin_send_imm_completed_callback, /* doca_rdma_task_send_imm_set_conf */
        .send_imm_task_comp_err_cb = basic_send_imm_completed_err_callback,
        .msg_recv_cb = client_rdma_recv_callback, /* doca_rdma_task_receive_set_conf */
        .msg_recv_err_cb = rdma_recv_err_callback,
        .data_path_mode = false,
        .ctx_user_data = resources,
        .state_change_cb = client_rdma_state_changed_callback, /* doca_ctx_set_state_changed_cb */
    };

    /* recv task, send_imm task, state change */
    result = init_send_imm_rdma_resources(resources, config, &cb_cfg);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_INFO("Worker [%ld] failed to init rdma client with error = %s",
                        proc_id, doca_error_get_name(result));
        return;
    }

    DOCA_LOG_INFO("Worker [%ld] started DOCA RDMA client", proc_id);

    cycle->rdma_resources = resources;

    return;
}

void
pdin_destroy_doca_rdma_client_ctx(struct rdma_config *config, struct rdma_resources *resources)
{
    destroy_inventory(resources->buf_inventory);
    destroy_rdma_resources(resources, config);

    return;
}

static void
configure_keepalive(int sockfd)
{
    int optval;
    socklen_t optlen = sizeof(optval);

    // Enable TCP keep-alive
    optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        DOCA_LOG_INFO("setsockopt(SO_KEEPALIVE)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // Set TCP keep-alive parameters
    optval = 60; // Seconds before sending keepalive probes
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, optlen) < 0) {
        DOCA_LOG_INFO("setsockopt(TCP_KEEPIDLE)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    optval = 10; // Interval in seconds between keepalive probes
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, optlen) < 0) {
        DOCA_LOG_INFO("setsockopt(TCP_KEEPINTVL)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    optval = 5; // Number of unacknowledged probes before considering the connection dead
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &optval, optlen) < 0) {
        DOCA_LOG_INFO("setsockopt(TCP_KEEPCNT)");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

/*
 * This approach will attempt to connect to the server multiple times,
 * giving it some time to become ready. If the connection is not successful
 * within the specified number of retries, the function will return an error.
 */
static int
retry_connect(int sockfd, struct sockaddr *addr)
{
    int attempts = 0;
    int ret;

    do {
        ret = connect(sockfd, addr, sizeof(struct sockaddr_in));
        if (ret == 0) {
            break;
        } else {
            attempts++;
            DOCA_LOG_DBG("connect() error: %s. Retrying %d times ...", strerror(errno), attempts);
            usleep(RETRY_DELAY_US);
        }
    } while (ret == -1 && attempts < MAX_RETRIES);

    return ret;
}

int
pdin_rdma_ctrl_path_client_connect(char *server_ip, uint16_t server_port)
{
    DOCA_LOG_INFO("PDIN connects control path with worker node (%s:%u).", server_ip, server_port);

    struct sockaddr_in server_addr;
    int sockfd;
    int ret;
    int opt = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        DOCA_LOG_INFO("socket() error: %s", strerror(errno));
        return -1;
    }

    // Set SO_REUSEADDR to reuse the address
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        DOCA_LOG_INFO("setsockopt(SO_REUSEADDR) failed");
        close(sockfd);
        return -1;
    }

    configure_keepalive(sockfd);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    ret = retry_connect(sockfd, (struct sockaddr *)&server_addr);
    if (ret == -1) {
        DOCA_LOG_INFO("connect() timeout: %s", strerror(errno));
        return -1;
    }

    return sockfd;
}

ssize_t
pdin_rdma_ctrl_path_client_read(int sock_fd, void *buffer, size_t len)
{
    ssize_t nr, tot_read;
    char *buf = buffer; // avoid pointer arithmetic on void pointer
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

/*
 * Path to the RDMA configuration file.
 * 'sudo make install' copies conf/rdma.cfg to this location.
 * Change this macro if you install NGINX to a non-default prefix.
 */
#define RDMA_CFG_PATH       "/usr/local/nginx_fstack/conf/rdma.cfg"
#define RDMA_CFG_MAX_LINE   256
#define RDMA_CFG_MAX_VALUE  128

/*
 * load_rdma_cfg_file - Parse the RDMA configuration file and populate
 *                      string buffers for each RDMA connection parameter.
 *
 * The file uses a simple "key = value" format (one pair per line).
 * Lines beginning with '#' and blank lines are ignored.
 *
 * Recognised keys:
 *   device      - RDMA/DOCA device name        (passed to doca_argp as -d)
 *   msg_sz      - message size in bytes        (passed as -s)
 *   server_ip   - DNE server IP address        (passed as -a)
 *   server_port - DNE server TCP port          (passed as -p)
 *   gid_idx     - RDMA GID index               (passed as -g)
 *
 * Returns 0 on success, -1 if the file cannot be opened.
 */
static int
load_rdma_cfg_file(const char *path,
                   char *device,   size_t device_sz,
                   char *msg_sz,   size_t msg_sz_sz,
                   char *srv_ip,   size_t srv_ip_sz,
                   char *srv_port, size_t srv_port_sz,
                   char *gid_idx,  size_t gid_idx_sz)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "rdma config: cannot open '%s': %s\n", path, strerror(errno));
        return -1;
    }

    char line[RDMA_CFG_MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and blank lines */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r' || *p == '\0')
            continue;

        char key[RDMA_CFG_MAX_VALUE], val[RDMA_CFG_MAX_VALUE];
        if (sscanf(line, " %127[^= \t] = %127s", key, val) != 2)
            continue;

        if      (strcmp(key, "device")      == 0) snprintf(device,   device_sz,   "%s", val);
        else if (strcmp(key, "msg_sz")      == 0) snprintf(msg_sz,   msg_sz_sz,   "%s", val);
        else if (strcmp(key, "server_ip")   == 0) snprintf(srv_ip,   srv_ip_sz,   "%s", val);
        else if (strcmp(key, "server_port") == 0) snprintf(srv_port, srv_port_sz, "%s", val);
        else if (strcmp(key, "gid_idx")     == 0) snprintf(gid_idx,  gid_idx_sz,  "%s", val);
    }

    fclose(f);
    return 0;
}

void
pdin_init_rdma_config(struct rdma_config *cfg, ngx_int_t proc_id)
{
    doca_error_t result;

    /* Initialize rdma_config */
    set_default_config_value(cfg);

    /* Parse cmdline/json arguments */
    result = doca_argp_init("rdma client", cfg);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("Worker [%ld] failed to init ARGP resources: %s", proc_id, doca_error_get_descr(result));

    result = register_rdma_common_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Worker [%ld] failed to register RDMA client parameters: %s", proc_id, doca_error_get_descr(result));
        doca_argp_destroy();
    }

    /* Load RDMA connection parameters from the config file at runtime.
     * Fall back to the built-in defaults if the file cannot be read.
     * Edit conf/rdma.cfg (then run 'sudo make install') to change these
     * values without recompiling. */
    char cfg_device[RDMA_CFG_MAX_VALUE]   = "mlx5_2";
    char cfg_msg_sz[RDMA_CFG_MAX_VALUE]   = "31920";
    char cfg_srv_ip[RDMA_CFG_MAX_VALUE]   = "10.10.1.4";
    char cfg_srv_port[RDMA_CFG_MAX_VALUE] = "8084";
    char cfg_gid_idx[RDMA_CFG_MAX_VALUE]  = "3";

    if (load_rdma_cfg_file(RDMA_CFG_PATH,
                           cfg_device,   sizeof(cfg_device),
                           cfg_msg_sz,   sizeof(cfg_msg_sz),
                           cfg_srv_ip,   sizeof(cfg_srv_ip),
                           cfg_srv_port, sizeof(cfg_srv_port),
                           cfg_gid_idx,  sizeof(cfg_gid_idx)) != 0) {
        DOCA_LOG_WARN("Worker [%ld]: '%s' not found — using built-in RDMA defaults",
                      proc_id, RDMA_CFG_PATH);
    }

    /* Build the argument vector for doca_argp from the loaded config values. */
    char *argv[] = {
        "dummy",
        "-d", cfg_device,
        "-s", cfg_msg_sz,
        "-a", cfg_srv_ip,
        "-p", cfg_srv_port,
        "-g", cfg_gid_idx
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
        doca_argp_destroy();
    }

    DOCA_LOG_INFO("Print RDMA config:");
    DOCA_LOG_INFO("DOCA Device Name: %s", cfg->device_name);
    DOCA_LOG_INFO("DNE socket IP: %s", cfg->sock_ip);
    DOCA_LOG_INFO("DNE socket port: %d", cfg->sock_port);
    DOCA_LOG_INFO("Message size: %u", cfg->msg_sz);
    DOCA_LOG_INFO("the input msg_sz[%d] :sizeof http_transaction [%ld]", cfg->msg_sz, sizeof(struct http_transaction));

    if (cfg->msg_sz != sizeof(struct http_transaction))
    {
        DOCA_LOG_ERR("the input msg_sz[%d] is not equal to sizeof http_transaction [%ld]", cfg->msg_sz, sizeof(struct http_transaction));
        cfg->msg_sz = sizeof(struct http_transaction);

    }
    /* Establish control path (TCP) connection with backend DNEs to exchange RC metadata */
    cfg->sock_fd = pdin_rdma_ctrl_path_client_connect(cfg->sock_ip, (uint16_t) cfg->sock_port);
    if (cfg->sock_fd == -1) {
        DOCA_LOG_INFO("Worker [%ld] failed to connect with the DNE. Closing DOCA RDMA...", proc_id);
        exit(1);
    }

    struct sockaddr_in local_addr;
    socklen_t len = sizeof(local_addr);
    getsockname(cfg->sock_fd, (struct sockaddr*)&local_addr, &len);

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_addr.sin_addr, ip, sizeof(ip));
    DOCA_LOG_INFO("Local address: %s:%d\n", ip, ntohs(local_addr.sin_port));
    DOCA_LOG_INFO("Worker [%ld] established connection with the DNE", proc_id);
}

doca_error_t
pdin_create_doca_log_backend(void)
{
    doca_error_t result;

    /* Register a logger backend */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DOCA Log Backend Creation Standard finished with errors");

    /* Register a logger backend for internal SDK errors and warnings */
    result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DOCA Log Backend Creation with File SDK finished with errors");
    result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_ERROR);
    if (result != DOCA_SUCCESS)
        DOCA_LOG_ERR("DOCA Log Backend Set SDK Level finished with errors");

    return result;
}
