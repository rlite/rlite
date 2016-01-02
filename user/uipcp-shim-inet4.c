#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "rlite-list.h"
#include "uipcp-container.h"


struct inet4_bindpoint {
    int fd;
    struct sockaddr_in addr;
    char *appl_name_s;

    struct list_head node;
};

struct inet4_endpoint {
    int fd;
    struct sockaddr_in addr;
    unsigned int port_id;
    uint32_t kevent_id;

    struct list_head node;
};

struct shim_inet4 {
    struct list_head endpoints;
    struct list_head bindpoints;
    uint32_t kevent_id_cnt;
};

#define SHIM(_u)    ((struct shim_inet4 *)((_u)->priv))

static int
parse_directory(int addr2sock, struct sockaddr_in *addr,
                struct rina_name *appl_name)
{
    char *appl_name_s = NULL;
    const char *dirfile = "/etc/rlite/shim-inet4-dir";
    FILE *fin;
    char *linebuf = NULL;
    size_t sz;
    ssize_t n;
    int found = 0;

    if (addr2sock) {
        appl_name_s = rina_name_to_string(appl_name);
        if (!appl_name_s) {
            PE("Out of memory\n");
            return -1;
        }
    }

    fin = fopen(dirfile, "r");
    if (!fin) {
        PE("Could not open directory file '%s'\n", dirfile);
        if (appl_name_s) {
            free(appl_name_s);
        }
        return -1;
    }

    while (!found && (n = getline(&linebuf, &sz, fin)) > 0) {
        /* I know, strtok_r, strsep, etc. etc. I just wanted to have
         * some fun ;) */
        char *nm = linebuf;
        char *ip, *port, *eol;
        struct sockaddr_in cur_addr;
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

        memset(&cur_addr, 0, sizeof(cur_addr));
        cur_addr.sin_family = AF_INET;
        cur_addr.sin_port = htons(atoi(port));
        ret = inet_pton(AF_INET, ip, &cur_addr.sin_addr);
        if (ret != 1) {
            PE("Invalid IP address '%s'\n", ip);
            continue;
        }

        if (addr2sock) {
            if (strcmp(nm, appl_name_s) == 0) {
                memcpy(addr, &cur_addr, sizeof(cur_addr));
                found = 1;
            }

        } else { /* sock2addr */
            if (addr->sin_family == cur_addr.sin_family &&
                    addr->sin_port == cur_addr.sin_port &&
                    memcmp(&addr->sin_addr, &cur_addr.sin_addr,
                    sizeof(cur_addr.sin_addr)) == 0) {
                ret = rina_name_from_string(nm, appl_name);
                if (ret) {
                    PE("Invalid name '%s'\n", nm);
                }
                found = (ret == 0);
            }
        }

        NPD("dir '%s' '%s'[%d] '%d'\n", nm, ip, ret, atoi(port));
    }

    if (appl_name_s) {
        free(appl_name_s);
    }

    if (linebuf) {
        free(linebuf);
    }

    fclose(fin);

    return found ? 0 : -1;
}

static int
appl_name_to_sock_addr(const struct rina_name *appl_name,
                       struct sockaddr_in *addr)
{
    return parse_directory(1, addr, (struct rina_name *)appl_name);
}

static int
sock_addr_to_appl_name(const struct sockaddr_in *addr,
                       struct rina_name *appl_name)
{
    return parse_directory(0, (struct sockaddr_in *)addr, appl_name);
}

/* ep->addr must be filled in before calling this function */
static int
open_bound_socket(int *fd, struct sockaddr_in *addr)
{
    int enable = 1;

    *fd = socket(PF_INET, SOCK_STREAM, 0);

    if (*fd < 0) {
        PE("socket() failed [%d]\n", errno);
        return -1;
    }

    if (setsockopt(*fd, SOL_SOCKET, SO_REUSEADDR, &enable,
                   sizeof(enable))) {
        PE("setsockopt(SO_REUSEADDR) failed [%d]\n", errno);
        close(*fd);
        return -1;
    }

    if (bind(*fd, (struct sockaddr *)addr, sizeof(*addr))) {
        PE("bind() failed [%d]\n", errno);
        close(*fd);
        return -1;
    }

    return 0;
}

static void accept_conn(struct rlite_evloop *loop, int lfd);

static int
shim_inet4_appl_unregister(struct uipcp *uipcp,
                           struct rina_kmsg_appl_register *req)
{
    char *appl_name_s = rina_name_to_string(&req->appl_name);
    struct shim_inet4 *shim = SHIM(uipcp);
    struct inet4_bindpoint *bp;
    int ret = -1;

    if (!appl_name_s) {
        PE("Out of memory\n");
        return -1;
    }

    list_for_each_entry(bp, &shim->bindpoints, node) {
        if (strcmp(appl_name_s, bp->appl_name_s) == 0) {
            rlite_evloop_fdcb_del(&uipcp->appl.loop, bp->fd);
            list_del(&bp->node);
            close(bp->fd);
            free(bp->appl_name_s);
            free(bp);
            ret = 0;

            break;
        }
    }

    if (ret) {
        PE("Could not find endpoint for appl_name %s\n", appl_name_s);
    }

    if (appl_name_s) {
        free(appl_name_s);
    }

    return ret;
}

static int
shim_inet4_appl_register(struct rlite_evloop *loop,
                         const struct rina_msg_base_resp *b_resp,
                         const struct rina_msg_base *b_req)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    struct rina_kmsg_appl_register *req =
                (struct rina_kmsg_appl_register *)b_resp;
    struct shim_inet4 *shim = SHIM(uipcp);
    struct inet4_bindpoint *bp;
    int ret;

    if (!req->reg) {
        /* Process the unregistration. */
        return shim_inet4_appl_unregister(uipcp, req);
    }

    /* Process the registration. */

    bp = malloc(sizeof(*bp));
    if (!bp) {
        PE("Out of memory\n");
        goto err0;
    }

    bp->appl_name_s = rina_name_to_string(&req->appl_name);
    if (!bp->appl_name_s) {
        PE("Out of memory\n");
        goto err1;
    }

    ret = appl_name_to_sock_addr(&req->appl_name, &bp->addr);
    if (ret) {
        PE("Failed to get inet4 address from appl_name '%s'\n",
           bp->appl_name_s);
        goto err2;
    }

    /* Open a listening socket, bind() and listen(). */
    ret = open_bound_socket(&bp->fd, &bp->addr);
    if (ret) {
        goto err2;
    }

    if (listen(bp->fd, 5)) {
        PE("listen() failed [%d]\n", errno);
        goto err3;
    }

    /* The accept_conn() callback will be invoked on new incoming
     * connections. */
    rlite_evloop_fdcb_add(&uipcp->appl.loop, bp->fd, accept_conn);

    list_add_tail(&bp->node, &shim->bindpoints);

    /* Registration requires a response, while unregistrations doesn't. */
    return uipcp_appl_register_resp(uipcp, uipcp->ipcp_id,
                                    RLITE_SUCC, req);

err3:
    close(bp->fd);
err2:
    free(bp->appl_name_s);
err1:
    free(bp);
err0:
    return uipcp_appl_register_resp(uipcp, uipcp->ipcp_id,
                                    RLITE_ERR, req);
}

static int
shim_inet4_fa_req(struct rlite_evloop *loop,
                  const struct rina_msg_base_resp *b_resp,
                  const struct rina_msg_base *b_req)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl,
                                                  loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    struct rina_kmsg_fa_req *req = (struct rina_kmsg_fa_req *)b_resp;
    struct shim_inet4 *shim = SHIM(uipcp);
    struct sockaddr_in remote_addr;
    struct rina_flow_config cfg;
    struct inet4_endpoint *ep;
    int ret;

    PD("[uipcp %u] Got reflected message\n", uipcp->ipcp_id);

    assert(b_req == NULL);

    ep = malloc(sizeof(*ep));
    if (!ep) {
        PE("Out of memory\n");
        return -1;
    }
    memset(ep, 0, sizeof(*ep));

    ep->port_id = req->local_port;

    ret = appl_name_to_sock_addr(&req->local_appl, &ep->addr);
    if (ret) {
        PE("Failed to get inet4 address for local appl\n");
        goto err1;
    }

    ret = appl_name_to_sock_addr(&req->remote_appl, &remote_addr);
    if (ret) {
        PE("Failed to get inet4 address for remote appl\n");
        goto err1;
    }

    /* Open a client-side socket, bind() and connect(). */
    ret = open_bound_socket(&ep->fd, &ep->addr);
    if (ret) {
        goto err1;
    }

    /* Don't select() on ep->fd for incoming packets, that will be received in
     * kernel space. */

    if (connect(ep->fd, (const struct sockaddr *)&remote_addr,
                sizeof(remote_addr))) {
        PE("Failed to connect to remote addr\n");
        goto err2;
    }

    list_add_tail(&ep->node, &shim->endpoints);

    /* Succesfull connect() is interpreted as positive flow allocation response. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = ep->fd;
    uipcp_issue_fa_resp_arrived(uipcp, ep->port_id, 0, 0,
                                0, &cfg);
    return 0;

err2:
    close(ep->fd);
err1:
    free(ep);

    return -1;
}

static int
lfd_to_appl_name(struct shim_inet4 *shim, int lfd, struct rina_name *name)
{
    struct inet4_bindpoint *ep;

    list_for_each_entry(ep, &shim->bindpoints, node) {
        if (lfd == ep->fd) {
            return rina_name_from_string(ep->appl_name_s, name);
        }
    }

    return -1;
}

static void
accept_conn(struct rlite_evloop *loop, int lfd)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    struct shim_inet4 *shim = SHIM(uipcp);
    struct sockaddr_in remote_addr;
    socklen_t addrlen = sizeof(remote_addr);
    struct rina_name remote_appl, local_appl;
    struct inet4_endpoint *ep;
    struct rina_flow_config cfg;
    int sfd;

    /* First of all let's call accept, so that we consume the event
     * on lfd, independently of what happen next. This is important
     * in order to avoid spinning on this fd. */
    sfd = accept(lfd, (struct sockaddr *)&remote_addr, &addrlen);
    if (sfd < 0) {
        PE("Accept failed\n");
        return;
    }

    /* Lookup the local registered appl that is listening on lfd. */
    if (lfd_to_appl_name(shim, lfd, &local_appl)) {
        PE("Cannot find the local appl corresponding "
           "to fd %d\n", lfd);
        return;
    }

    ep = malloc(sizeof(*ep));
    if (!ep) {
        PE("Out of memory\n");
        return;
    }
    memset(ep, 0, sizeof(*ep));

    ep->fd = sfd;
    memcpy(&ep->addr, &remote_addr, sizeof(remote_addr));

    /* Lookup the remote IP address and port. */
    if (sock_addr_to_appl_name(&ep->addr, &remote_appl)) {
        PE("Failed to get appl_name from remote address\n");
        rina_name_free(&local_appl);
        free(ep);
        return;
    }

    ep->kevent_id = shim->kevent_id_cnt++;
    list_add_tail(&ep->node, &shim->endpoints);

    /* Push the file descriptor down to kernelspace. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd = ep->fd;
    uipcp_issue_fa_req_arrived(uipcp, ep->kevent_id, 0, 0,
                               &local_appl, &remote_appl, &cfg);
    rina_name_free(&local_appl);
    rina_name_free(&remote_appl);
}

static struct inet4_endpoint *
get_endpoint_by_kevent_id(struct shim_inet4 *shim, uint32_t kevent_id)
{
    struct inet4_endpoint *ep;

    list_for_each_entry(ep, &shim->endpoints, node) {
        if (kevent_id == ep->kevent_id) {
            return ep;
        }
    }

    return NULL;
}

static int
remove_endpoint_by_port_id(struct shim_inet4 *shim, unsigned int port_id)
{
    struct inet4_endpoint *ep;

    list_for_each_entry(ep, &shim->endpoints, node) {
        if (port_id == ep->port_id) {
            PD("Removing endpoint [port=%u,kevent_id=%u,sfd=%d]\n",
               ep->port_id, ep->kevent_id, ep->fd);
            close(ep->fd);
            free(ep);
            return 0;
        }
    }

    return -1;
}

static int
shim_inet4_fa_resp(struct rlite_evloop *loop,
                   const struct rina_msg_base_resp *b_resp,
                   const struct rina_msg_base *b_req)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    struct shim_inet4 *shim = SHIM(uipcp);
    struct rina_kmsg_fa_resp *resp = (struct rina_kmsg_fa_resp *)b_resp;
    struct inet4_endpoint *ep;

    PD("[uipcp %u] Got reflected message\n", uipcp->ipcp_id);

    assert(b_req == NULL);

    ep = get_endpoint_by_kevent_id(shim, resp->kevent_id);
    if (!ep) {
        PE("Cannot find endpoint corresponding to kevent-id '%d'\n",
           resp->kevent_id);
        return 0;
    }

    ep->port_id = resp->port_id;

    if (!resp->response) {
        /* If response is positive, there is nothing to do here. */
        return 0;
    }

    /* Negative response, we have to close the TCP/UDP connection. */
    PD("Removing endpoint [port=%u,kevent_id=%u,sfd=%d]\n",
            ep->port_id, ep->kevent_id, ep->fd);
    close(ep->fd);
    free(ep);

    return 0;
}

static int
shim_inet4_flow_deallocated(struct rlite_evloop *loop,
                       const struct rina_msg_base_resp *b_resp,
                       const struct rina_msg_base *b_req)
{
    struct rlite_appl *appl = container_of(loop, struct rlite_appl,
                                                   loop);
    struct uipcp *uipcp = container_of(appl, struct uipcp, appl);
    struct rina_kmsg_flow_deallocated *req =
                (struct rina_kmsg_flow_deallocated *)b_resp;
    struct shim_inet4 *shim = SHIM(uipcp);
    int ret;

    /* Close the TCP/UDP connection associated to this flow. */
    ret = remove_endpoint_by_port_id(shim, req->local_port_id);
    if (ret) {
        PE("Cannot find endpoint corresponding to port '%d'\n", req->local_port_id);
    }

    return 0;
}

static int
shim_inet4_init(struct uipcp *uipcp)
{
    struct shim_inet4 *shim = malloc(sizeof(*shim));

    if (!shim) {
        PE("Out of memory\n");
        return -1;
    }

    uipcp->priv = shim;

    list_init(&shim->endpoints);
    list_init(&shim->bindpoints);
    shim->kevent_id_cnt = 1;

    return 0;
}

static int
shim_inet4_fini(struct uipcp *uipcp)
{
    struct shim_inet4 *shim = SHIM(uipcp);
    struct list_head *elem;

    {
        struct inet4_bindpoint *bp;

        while ((elem = list_pop_front(&shim->bindpoints))) {
            bp = container_of(elem, struct inet4_bindpoint, node);
            close(bp->fd);
            free(bp->appl_name_s);
            free(bp);
        }
    }

    {
        struct inet4_endpoint *ep;

        while ((elem = list_pop_front(&shim->endpoints))) {
            ep = container_of(elem, struct inet4_endpoint, node);
            close(ep->fd);
            free(ep);
        }
    }

    free(shim);

    return 0;
}

struct uipcp_ops shim_inet4_ops = {
    .init = shim_inet4_init,
    .fini = shim_inet4_fini,
    .appl_register = shim_inet4_appl_register,
    .fa_req = shim_inet4_fa_req,
    .fa_resp = shim_inet4_fa_resp,
    .flow_deallocated = shim_inet4_flow_deallocated,
};

