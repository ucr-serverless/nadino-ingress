#include <stdio.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "pdi_rdma.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/un.h>
#include <ngx_core.h>

#include "pdi_rdma_utils.h"


static int u_sockfd;
static int worker_msg_cnt;
#define UNIX_DOMAIN_SOCKET_NAME "/tmp/pd_ipc.sock"

static int round_cnt;
#define MAX_ROUNDS 1

static struct rte_ring *ngx_worker_rx_rings[100]; // TODO: replace 100 with max num of CPU cores
static struct rte_ring *ngx_worker_tx_rings[100]; // TODO: replace 100 with max num of CPU cores
#define NGX_WORKER_RING_SIZE 32
#define DUMMY_MSG_POOL "dummy_msg_pool"
#define MAX_PKT_BURST 16


/* Note: can be integrated with ff_msg
 * But it will require changing f-stack
 */
struct dummy_msg {
    /* Result of msg processing */
    int result;
    /* Length of segment buffer. */
    size_t buf_len;
    /* Address of segment buffer. */
    char *buf_addr;
    char *original_buf;
    size_t original_buf_len;

} __attribute__((packed)) __rte_cache_aligned;

static void
dummy_msg_init(struct rte_mempool *mp,
    __attribute__((unused)) void *opaque_arg,
    void *obj, __attribute__((unused)) unsigned i)
{
    struct dummy_msg *msg = (struct dummy_msg *)obj;
    msg->buf_addr = (char *)msg + sizeof(struct dummy_msg);
    msg->buf_len = mp->elt_size - sizeof(struct dummy_msg);
    msg->original_buf = NULL;
    msg->original_buf_len = 0;
}

static struct rte_ring *
create_ring(const char *name, unsigned count, int socket_id, unsigned flags)
{
    struct rte_ring *ring;

    if (name == NULL) {
        rte_exit(EXIT_FAILURE, "create ring failed, no name!\n");
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        ring = rte_ring_create(name, count, socket_id, flags);
    } else {
        ring = rte_ring_lookup(name);
    }

    if (ring == NULL) {
        rte_exit(EXIT_FAILURE, "create ring:%s failed!\n", name);
    }

    return ring;
}

struct dummy_msg *
dummy_msg_alloc(void)
{
    void *msg;
    if (rte_mempool_get(message_pool, &msg) < 0) {
        printf("get buffer from message pool failed.\n");
        return NULL;
    }

    return (struct dummy_msg *)msg;
}

void
dummy_msg_free_burst(struct dummy_msg **pkts_burst, uint16_t nb_pkts)
{
    int i;

    for (i = 0; i < nb_pkts; i++) {
        rte_mempool_put(message_pool, pkts_burst[i]);
    }
}

int
pdin_init_worker_rings(ngx_cycle_t *cycle)
{
    // Init global vars
    worker_msg_cnt = 0;
    round_cnt = 0;

    int workerid;
    char name_buf[RTE_RING_NAMESIZE];

    ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    /* Create dummy message buffer pool */
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        message_pool = rte_mempool_create(DUMMY_MSG_POOL,
           NGX_WORKER_RING_SIZE * 2 * ccf->worker_processes,
           MAX_MSG_BUF_SIZE, NGX_WORKER_RING_SIZE / 2, 0,
           NULL, NULL, dummy_msg_init, NULL,
           rte_socket_id(), 0);
    } else {
        message_pool = rte_mempool_lookup(DUMMY_MSG_POOL);
    }

    if (message_pool == NULL) {
        rte_panic("Create msg mempool failed\n");
    }

    /* Create rings according to NGINX workers actually running. */
    for (workerid = 0; workerid < ccf->worker_processes; workerid++) {
        snprintf(name_buf, RTE_RING_NAMESIZE, "ngx_worker_%d_rx_ring", workerid);
        ngx_worker_rx_rings[workerid] = create_ring(name_buf,
            NGX_WORKER_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (ngx_worker_rx_rings[workerid] == NULL)
            rte_panic("create ring:%s failed!\n", name_buf);

        printf("%d create ring: %s success, %u ring entries are now free!\n",
            getpid(), name_buf, rte_ring_free_count(ngx_worker_rx_rings[workerid]));

        snprintf(name_buf, RTE_RING_NAMESIZE, "ngx_worker_%d_tx_ring", workerid);
        ngx_worker_tx_rings[workerid] = create_ring(name_buf,
            NGX_WORKER_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (ngx_worker_tx_rings[workerid] == NULL)
            rte_panic("create ring:%s failed!\n", name_buf);

        printf("%d create ring:%s success, %u ring entries are now free!\n",
            getpid(), name_buf, rte_ring_free_count(ngx_worker_tx_rings[workerid]));
    }

    return 0;
}

/*
 * Function in RDMA backend to receive packets from NGX workers
 * and distribute them to serverless functions over RDMA
 */
uint16_t
pdin_rdma_tx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst)
{
    /* read msg from ring buf and to process */
    uint16_t nb_rb = 0;
    int i;
    char message[100];

    nb_rb = rte_ring_dequeue_burst(ngx_worker_tx_rings[proc_id],
        (void **)pkts_burst, MAX_PKT_BURST, NULL);

    for (i = 0; i < nb_rb; i++) {
        // handle_msg((struct dummy_msg *)pkts_burst[i], proc_id);
        printf("RDMA backend receives: %s\n", pkts_burst[i]->buf_addr);

        snprintf(message, 100, "I'm RDMA backend. Thank you for sharing message %d", i);
        strcpy(pkts_burst[i]->buf_addr, message);
    }

    return nb_rb;
}

/*
 * Function in RDMA backend to receive packets from serverless functions
 * and distribute them to NGX workers
 */
int
pdin_rdma_rx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst, uint16_t nb_pkts)
{
    /* TODO: read msg from RDMA NIC and to process */
    uint16_t nb_sent;

    // Distributed msg to NGX workers
    nb_sent = rte_ring_enqueue_burst(ngx_worker_rx_rings[proc_id],
        (void **)pkts_burst, nb_pkts, NULL);

    if (unlikely(nb_sent < nb_pkts)) {
        printf("!!!!!!! Packets dropped !!!!!!! \n");
        // TODO: handle dropped packets - pktmbuf_input_free_bulk, record drop rate
    }

    return 0;
}

/*
 * Function in NGX worker to receive packets from the RDMA backend
 */
uint16_t
pdin_ngx_rx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst)
{
    /* read msg from ring buf and to process */
    uint16_t nb_rb = 0;
    int i;

    nb_rb = rte_ring_dequeue_burst(ngx_worker_rx_rings[proc_id],
        (void **)pkts_burst, MAX_PKT_BURST, NULL);

    for (i = 0; i < nb_rb; ++i) {
        // handle_msg((struct dummy_msg *)pkts_burst[i], proc_id);
        printf("NGX Worker %ld receives response from RDMA: %s \n", proc_id, pkts_burst[i]->buf_addr);
    }

    return nb_rb;
}

/*
 * Function in the NGX worker to distribute packets to the RDMA backend
 */
int
pdin_ngx_tx_mgr(ngx_int_t proc_id, struct dummy_msg **pkts_burst, uint16_t nb_pkts)
{
    /* TODO: read msg from RDMA NIC and to process */
    uint16_t nb_sent;

    nb_sent = rte_ring_enqueue_burst(ngx_worker_tx_rings[proc_id],
        (void **)pkts_burst, nb_pkts, NULL);

    if (unlikely(nb_sent < nb_pkts)) {
        printf("!!!!!!! Packets drop !!!!!!! \n");
        // TODO: handle dropped packets - pktmbuf_input_free_bulk, record drop rate
    }

    return 0;
}


ngx_int_t
init_unix_domain_sock(ngx_cycle_t *cycle)
{
    unlink(UNIX_DOMAIN_SOCKET_NAME);

    struct sockaddr_un addr;

    u_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (u_sockfd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno, "socket() failed");
        return NGX_ERROR;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, UNIX_DOMAIN_SOCKET_NAME);

    if (bind(u_sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno, "bind() failed");
        close(u_sockfd);
        return NGX_ERROR;
    }

    return NGX_OK;
}

// NGINX worker sends messages to RDMA worker
void
ud_sock_send_message_to_worker(ngx_cycle_t *cycle)
{
    int msg_cnt = 100;
    char message[100];
    struct sockaddr_un addr;

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, UNIX_DOMAIN_SOCKET_NAME);

    if (worker_msg_cnt < msg_cnt) {
        snprintf(message, 100, "Hello from worker %d: %d", getpid(), worker_msg_cnt);
        sendto(u_sockfd, message, strlen(message), 0, (struct sockaddr *)&addr, sizeof(addr));
        worker_msg_cnt++;
    }
}

// RDMA worker receives messages from NGINX worker 
void
ud_sock_receive_message_from_worker()
{
    char buf[100];
    recvfrom(u_sockfd, buf, sizeof(buf), 0, NULL, NULL);
    ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0, "Received: %s", buf);
}

void
pdin_test_ngx_worker_tx()
{
    // send_message_to_worker(cycle);

    struct dummy_msg *pkts_burst[MAX_PKT_BURST];

    // TODO: integrate with ngx_handle_read_event(rev, flags)
    if (round_cnt < MAX_ROUNDS) {
        char message[100];
        int i;

        // Alloc mbuf and write mbuf
        for (i = 0; i < MAX_PKT_BURST; i++) {
            pkts_burst[i] = dummy_msg_alloc();
            snprintf(message, 100, "Hello from worker %ld [%d]: %d", ngx_worker, getpid(), i);
            // NOTE: "ngx_worker" is globally visiable to all procedures in a worker process
            strcpy(pkts_burst[i]->buf_addr, message);
        }

        // send msg to RDMA backend
        pdin_ngx_tx_mgr(ngx_worker, pkts_burst, MAX_PKT_BURST);
    }
}

void
pdin_test_ngx_worker_rx()
{
    struct dummy_msg *pkts_burst[MAX_PKT_BURST];

    // TODO: integrate with ngx_handle_write_event(wev, lowat)
    if (round_cnt < MAX_ROUNDS) {
        // recv msg from RDMA backend
        int nb_rb = pdin_ngx_rx_mgr(ngx_worker, pkts_burst);
        printf("NGX worker %ld received %d messages.\n", ngx_worker, nb_rb);
        if (nb_rb > 0)
            dummy_msg_free_burst(pkts_burst, nb_rb);

        round_cnt++;
    }
}

void
pdin_test_rdma_worker_bounce(ngx_cycle_t *cycle)
{
    // receive_message_from_worker();

    // printf("##### Run rdma_worker process_cycle_loop #####\n");
    // ngx_msleep(1000);

    ngx_core_conf_t *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    struct dummy_msg *pkts_burst[ccf->worker_processes][MAX_PKT_BURST];
    
    int i;
    for (i = 0; i < ccf->worker_processes; i++) {
        //TODO: poll NGINX workers' TX ring to see any message
        int nb_pkts = pdin_rdma_tx_mgr(i, pkts_burst[i]);

        //TODO: Send msg to serverless functions

        //TODO: Recv msg from serverless functions

        //TODO: Write msg to NGINX worker's RX ring.
        pdin_rdma_rx_mgr(i, pkts_burst[i], nb_pkts);
    }
}
