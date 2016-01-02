#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <rina/rina-ctrl.h>


/* IPC Manager data model. */
struct ipcm {
    int rfd;
};

static int
create_ipcp_resp(const char *buf, size_t len)
{
    return 0;
}

/* The signature of a response handler. */
typedef int (*rina_resp_handler_t)(const char *buf, size_t len);

/* The table containing all response handlers. */
static rina_resp_handler_t rina_handlers[] = {
    [RINA_CTRL_CREATE_IPCP_RESP] = create_ipcp_resp,
    [RINA_CTRL_MSG_MAX] = NULL,
};

void *evloop_function(void *arg)
{
    struct ipcm *ipcm = (struct ipcm *)arg;
    char buffer[1024];

    for (;;) {
        int ret;
        rina_msg_t msg_type;

        ret = read(ipcm->rfd, buffer, sizeof(buffer));
        if (ret < 0) {
            perror("read(rfd)");
            continue;
        }

        msg_type = *((rina_msg_t *)buffer);
        if (msg_type > RINA_CTRL_MSG_MAX || !rina_handlers[msg_type]) {
            printf("%s: Invalid message type [%d] received",__func__, msg_type);
            continue;
        }

        printf("Message type %d received from kernel\n", msg_type);

        ret = rina_handlers[msg_type](buffer, ret);
        if (ret) {
            printf("%s: Error while handling message type [%d]", __func__, msg_type);
        }
    }

    return NULL;
}

static void
rina_name_fill(struct rina_name *name, char *apn,
               char *api, char *aen, char *aei)
{
    name->apn = apn;
    name->apn_len = apn ? strlen(apn) : 0;
    name->api = api;
    name->api_len = api ? strlen(api) : 0;
    name->aen = aen;
    name->aen_len = aen ? strlen(aen) : 0;
    name->aei = aei;
    name->aei_len = aei ? strlen(aei) : 0;
}


/* Create an IPC process of type shim-dummy. */
static int
create_ipcp(struct ipcm *ipcm, const struct rina_name *name, uint8_t dif_type)
{
    struct rina_ctrl_create_ipcp msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RINA_CTRL_CREATE_IPCP;
    msg.name = *name;
    msg.dif_type = dif_type;

    ret = write(ipcm->rfd, &msg, sizeof(msg));
    if (ret != sizeof(msg)) {
        if (ret < 0) {
            perror("write(create_ipcp)");
        } else {
            printf("%s: Error: partial write [%u/%lu]\n", __func__,
                    ret, sizeof(msg));
        }
    }

    printf("IPC process successfully created\n");

    return ret;
}

static int
test(struct ipcm *ipcm)
{
    int ret;
    struct rina_name ipcp_name;

    /* Create an IPC process of type shim-dummy. */
    rina_name_fill(&ipcp_name, "prova.IPCP", "1", NULL, NULL);
    ret = create_ipcp(ipcm, &ipcp_name, DIF_TYPE_SHIM_DUMMY);

    return ret;
}

int main()
{
    struct ipcm ipcm;
    pthread_t evloop_th;
    int ret;

    /* Open the RINA control device. */
    ipcm.rfd = open("/dev/rina-ctrl", O_RDWR);
    if (ipcm.rfd < 0) {
        perror("open(/dev/rinactrl)");
        exit(EXIT_FAILURE);
    }

    /* Create and start the event-loop thread. */
    ret = pthread_create(&evloop_th, NULL, evloop_function, &ipcm);
    if (ret) {
        perror("pthread_create()");
        exit(EXIT_FAILURE);
    }

    test(&ipcm);

    ret = pthread_join(evloop_th, NULL);
    if (ret < 0) {
        perror("pthread_join()");
        exit(EXIT_FAILURE);
    }

    return 0;
}
