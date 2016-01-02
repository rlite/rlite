#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <rina/rina-ctrl.h>


/* Create an IPC process of type shim-dummy. */
static int
create_ipcp(int rfd, const struct rina_name *name, uint8_t dif_type)
{
    struct rina_ctrl_create_ipcp msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.msg_type = RINA_CTRL_CREATE_IPCP;
    msg.name = *name;
    msg.dif_type = dif_type;

    ret = write(rfd, &msg, sizeof(msg));
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
test(int rfd)
{
    int ret;
    struct rina_name ipcp_name;

    /* Create an IPC process of type shim-dummy. */
    ipcp_name.apn = "prova.IPCP";
    ipcp_name.apn_len = strlen(ipcp_name.apn);
    ipcp_name.api = "1";
    ipcp_name.api_len = strlen(ipcp_name.api);
    ipcp_name.aen = ipcp_name.aei = NULL;
    ipcp_name.aen_len = ipcp_name.aei_len = 0;
    ret = create_ipcp(rfd, &ipcp_name, DIF_TYPE_SHIM_DUMMY);

    return ret;
}

int main()
{
    int rfd;

    rfd = open("/dev/rina-ctrl", O_RDWR);
    if (rfd < 0) {
        perror("open(/dev/rinactrl)");
        exit(EXIT_FAILURE);
    }

    test(rfd);

    return 0;
}
