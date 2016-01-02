#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "uipcp-container.h"

/*static */int
parse_directory()
{
    const char *dirfile = "/etc/rlite/shim-inet4-dir";
    FILE *fin = fopen(dirfile, "r");
    char *linebuf = NULL;
    size_t sz;
    size_t n;

    if (!fin) {
        PE("Could not open directory file '%s'\n", dirfile);
        return -1;
    }

    while ((n = getline(&linebuf, &sz, fin)) > 0) {
        /* I know, strtok_r, strsep, etc. etc. I just wanted to have
         * some fun ;) */
        char *nm = linebuf;
        char *ip, *port, *eol;
        struct in_addr addr;
        struct rina_name appl_name;
        int ret;

        while (*nm != '\0' && isspace(*nm)) nm++;
        if (*nm == '\0') continue;

        ip = nm;
        while (*ip != '\0' && !isspace(*ip)) ip++;
        if (*ip == '\0') continue;

        *ip = '\0';
        ip++;
        while (*ip != '\0' && isspace(*ip)) ip++;
        if (*ip == '\0') continue;

        port = ip;
        while (*port != '\0' && !isspace(*port)) port++;
        if (*port == '\0') continue;

        *port = '\0';
        port++;
        while (*port != '\0' && isspace(*port)) port++;
        if (*port == '\0') continue;

        eol = port;
        while (*eol != '\0' && !isspace(*eol)) eol++;
        if (*eol != '\0') *eol = '\0';

        ret = inet_pton(AF_INET, ip, &addr);
        if (ret != 1) {
            PE("Invalid IP address '%s'\n", ip);
            continue;
        }

        ret = rina_name_from_string(nm, &appl_name);
        if (ret) {
            PE("Invalid name '%s'\n", nm);
            continue;
        }

        printf("oho '%s' '%s'[%d] '%d'\n", nm, ip, ret, atoi(port));
    }

    if (linebuf) {
        free(linebuf);
    }

    fclose(fin);

    return 0;
}

static int
shim_inet4_appl_register(struct rlite_evloop *loop,
                     const struct rina_msg_base_resp *b_resp,
                     const struct rina_msg_base *b_req)
{
    struct rlite_appl *application = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_appl_register *req =
                (struct rina_kmsg_appl_register *)b_resp;

    (void)req;
    (void)uipcp;

    return 0;
}

static int
shim_inet4_fa_req(struct rlite_evloop *loop,
             const struct rina_msg_base_resp *b_resp,
             const struct rina_msg_base *b_req)
{
    struct rlite_appl *application = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_req *req = (struct rina_kmsg_fa_req *)b_resp;

    PD("[uipcp %u] Got reflected message\n", uipcp->ipcp_id);

    assert(b_req == NULL);

    (void)req;
    (void)uipcp;

    return 0;
}

static int
shim_inet4_fa_req_arrived(struct rlite_evloop *loop,
                      const struct rina_msg_base_resp *b_resp,
                      const struct rina_msg_base *b_req)
{
    struct rlite_appl *application = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_req_arrived *req =
                    (struct rina_kmsg_fa_req_arrived *)b_resp;
    assert(b_req == NULL);

    PD("flow request arrived: [ipcp_id = %u, data_port_id = %u]\n",
            req->ipcp_id, req->port_id);

    (void)uipcp;

    return 0;
}

static int
shim_inet4_fa_resp(struct rlite_evloop *loop,
              const struct rina_msg_base_resp *b_resp,
              const struct rina_msg_base *b_req)
{
    struct rlite_appl *application = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_fa_resp *resp =
                (struct rina_kmsg_fa_resp *)b_resp;

    PD("[uipcp %u] Got reflected message\n", uipcp->ipcp_id);

    assert(b_req == NULL);

    (void)resp;

    return 0;
}

static int
shim_inet4_flow_deallocated(struct rlite_evloop *loop,
                       const struct rina_msg_base_resp *b_resp,
                       const struct rina_msg_base *b_req)
{
    struct rlite_appl *application = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(application, struct uipcp, appl);
    struct rina_kmsg_flow_deallocated *req =
                (struct rina_kmsg_flow_deallocated *)b_resp;

    (void)req;
    (void)uipcp;

    return 0;
}

static int
shim_inet4_init(struct uipcp *uipcp)
{
    return -1;
}

static int
shim_inet4_fini(struct uipcp *uipcp)
{
    return 0;
}

struct uipcp_ops shim_inet4_ops = {
    .init = shim_inet4_init,
    .fini = shim_inet4_fini,
    .appl_register = shim_inet4_appl_register,
    .fa_req = shim_inet4_fa_req,
    .fa_req_arrived = shim_inet4_fa_req_arrived,
    .fa_resp = shim_inet4_fa_resp,
    .flow_deallocated = shim_inet4_flow_deallocated,
};

