#include <unistd.h>

#include "uipcp-normal.hpp"

using namespace std;


Neighbor::Neighbor(struct uipcp_rib *rib_, const struct rina_name *name)
{
    rib = rib_;
    ipcp_name = RinaName(name);
    flow_fd = -1;
    port_id = 0; /* Not valid. */
    conn = NULL;
    enrollment_state = NONE;
    memset(enroll_fsm_handlers, 0, sizeof(enroll_fsm_handlers));
    enroll_fsm_handlers[NONE] = &Neighbor::none;
    enroll_fsm_handlers[I_WAIT_CONNECT_R] = &Neighbor::i_wait_connect_r;
    enroll_fsm_handlers[S_WAIT_START] = &Neighbor::s_wait_start;
    enroll_fsm_handlers[I_WAIT_START_R] = &Neighbor::i_wait_start_r;
    enroll_fsm_handlers[S_WAIT_STOP_R] = &Neighbor::s_wait_stop_r;
    enroll_fsm_handlers[I_WAIT_STOP] = &Neighbor::i_wait_stop;
    enroll_fsm_handlers[I_WAIT_START] = &Neighbor::i_wait_start;
    enroll_fsm_handlers[ENROLLED] = &Neighbor::enrolled;
}

Neighbor::Neighbor(const Neighbor& other)
{
    rib = other.rib;
    ipcp_name = other.ipcp_name;
    flow_fd = other.flow_fd;
    port_id = other.port_id;
    enrollment_state = enrollment_state;
    conn = NULL;
    memcpy(enroll_fsm_handlers, other.enroll_fsm_handlers,
           sizeof(enroll_fsm_handlers));
}

Neighbor::~Neighbor()
{
    if (conn) {
        delete conn;
    }
    if (flow_fd != -1) {
        int ret = close(flow_fd);

        if (ret) {
            PE("Error deallocating N-1 flow fd %d\n",
               flow_fd);
        } else {
            PD("N-1 flow deallocated [fd=%d]\n", flow_fd);
        }
    }
}

const char *
Neighbor::enrollment_state_repr(state_t s) const
{
    switch (s) {
        case NONE:
            return "NONE";

        case I_WAIT_CONNECT_R:
            return "I_WAIT_CONNECT_R";

        case S_WAIT_START:
            return "S_WAIT_START";

        case I_WAIT_START_R:
            return "I_WAIT_START_R";

        case S_WAIT_STOP_R:
            return "S_WAIT_STOP_R";

        case I_WAIT_STOP:
            return "I_WAIT_STOP";

        case I_WAIT_START:
            return "I_WAIT_START";

        case ENROLLED:
            return "ENROLLED";

        default:
            assert(0);
    }

    return NULL;
}

int
Neighbor::send_to_port_id(CDAPMessage *m, int invoke_id,
                          const UipcpObject *obj) const
{
    char objbuf[4096];
    int objlen;
    char *serbuf = NULL;
    size_t serlen = 0;
    int ret;

    if (obj) {
        objlen = obj->serialize(objbuf, sizeof(objbuf));
        if (objlen < 0) {
            PE("serialization failed\n");
            return objlen;
        }

        m->set_obj_value(objbuf, objlen);
    }

    try {
        ret = conn->msg_ser(m, invoke_id, &serbuf, &serlen);
    } catch (std::bad_alloc) {
        ret = -1;
    }

    if (ret) {
        PE("message serialization failed\n");
        if (serbuf) {
            delete [] serbuf;
        }
        return -1;
    }

    ret = mgmt_write_to_local_port(rib->uipcp, port_id, serbuf, serlen);

    if (serbuf) {
        delete [] serbuf;
    }

    return ret;
}

void
Neighbor::abort()
{
    CDAPMessage m;
    int ret;

    PE("Aborting enrollment\n");

    if (enrollment_state == NONE) {
        return;
    }

    enrollment_state = NONE;

    m.m_release(gpb::F_NO_FLAGS);

    ret = send_to_port_id(&m, 0, NULL);
    if (ret) {
        PE("send_to_port_id() failed\n");
    }

    if (conn) {
        conn->reset();
    }
}

static void
enroll_timeout_cb(struct rlite_evloop *loop, void *arg)
{
    Neighbor *neigh = static_cast<Neighbor *>(arg);
    ScopeLock(neigh->rib->lock);

    (void)loop;
    PI("Enrollment timeout with neighbor '%s'\n",
       static_cast<string>(neigh->ipcp_name).c_str());
    neigh->abort();
}

void
Neighbor::enroll_tmr_start()
{
    enroll_timeout_id = rlite_evloop_schedule(&rib->uipcp->appl.loop, 1000,
                                              enroll_timeout_cb, this);
}

void
Neighbor::enroll_tmr_stop()
{
    rlite_evloop_schedule_canc(&rib->uipcp->appl.loop, enroll_timeout_id);
}

int
Neighbor::none(const CDAPMessage *rm)
{
    CDAPMessage m;
    int ret;
    state_t next_state;
    int invoke_id = 0;

    if (rm == NULL) {
        /* (1) I --> S: M_CONNECT */

        CDAPAuthValue av;
        struct rlite_ipcp *ipcp;
        struct rina_name dst_name;

        ipcp = rib->ipcp_info();

        rina_name_fill(&dst_name, ipcp_name.apn.c_str(),
                       ipcp_name.api.c_str(), ipcp_name.aen.c_str(),
                        ipcp_name.aei.c_str());

        /* We are the enrollment initiator, let's send an
         * M_CONNECT message. */
        conn = new CDAPConn(flow_fd, 1);

        ret = m.m_connect(gpb::AUTH_NONE, &av, &ipcp->ipcp_name,
                          &dst_name);
        rina_name_free(&dst_name);

        if (ret) {
            PE("M_CONNECT creation failed\n");
            abort();
            return -1;
        }

        next_state = I_WAIT_CONNECT_R;

    } else {
        /* (1) S <-- I: M_CONNECT
         * (2) S --> I: M_CONNECT_R */

        /* We are the enrollment slave, let's send an
         * M_CONNECT_R message. */
        assert(rm->op_code == gpb::M_CONNECT); /* Rely on CDAP fsm. */
        ret = m.m_connect_r(rm, 0, string());
        if (ret) {
            PE("M_CONNECT_R creation failed\n");
            abort();
            return -1;
        }

        invoke_id = rm->invoke_id;

        next_state = S_WAIT_START;
    }

    ret = send_to_port_id(&m, invoke_id, NULL);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    enroll_tmr_start();
    enrollment_state = next_state;

    return 0;
}

int
Neighbor::i_wait_connect_r(const CDAPMessage *rm)
{
    /* (2) I <-- S: M_CONNECT_R
     * (3) I --> S: M_START */
    struct rlite_ipcp *ipcp;
    EnrollmentInfo enr_info;
    CDAPMessage m;
    int ret;

    assert(rm->op_code == gpb::M_CONNECT_R); /* Rely on CDAP fsm. */

    if (rm->result) {
        PE("Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        abort();
        return 0;
    }

    m.m_start(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
              0, 0, string());

    ipcp = rib->ipcp_info();

    enr_info.address = ipcp->ipcp_addr;
    enr_info.lower_difs = rib->lower_difs;

    ret = send_to_port_id(&m, 0, &enr_info);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    enroll_tmr_stop();
    enroll_tmr_start();
    enrollment_state = I_WAIT_START_R;

    return 0;
}

int
Neighbor::s_wait_start(const CDAPMessage *rm)
{
    /* (3) S <-- I: M_START
     * (4) S --> I: M_START_R
     * (5) S --> I: M_CREATE
     * (6) S --> I: M_STOP */
    struct rlite_ipcp *ipcp;
    const char *objbuf;
    size_t objlen;
    bool has_address;
    int ret;

    if (rm->op_code != gpb::M_START) {
        PE("M_START expected\n");
        abort();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);
    CDAPMessage m;

    has_address = (enr_info.address != 0);

    if (!has_address) {
        /* Assign an address to the initiator. */
        enr_info.address = rib->address_allocate();
    }

    /* Add the initiator to the set of candidate neighbors. */
    NeighborCandidate cand;

    cand.apn = ipcp_name.apn;
    cand.api = ipcp_name.api;
    cand.address = enr_info.address;
    cand.lower_difs = enr_info.lower_difs;
    rib->cand_neighbors[static_cast<string>(ipcp_name)] = cand;

    m.m_start_r(gpb::F_NO_FLAGS, 0, string());

    ret = send_to_port_id(&m, rm->invoke_id, &enr_info);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    if (has_address) {
        /* Send DIF static information. */
    }

    /* Send my neighbors, including a neighbor representing
     * myself. */
    NeighborCandidateList ncl;
    RinaName cand_name;

    for (map<string, NeighborCandidate>::iterator cit =
                rib->cand_neighbors.begin();
                        cit != rib->cand_neighbors.end(); cit++) {
        ncl.candidates.push_back(cit->second);
    }

    ipcp = rib->ipcp_info();
    cand = NeighborCandidate();
    cand_name = RinaName(&ipcp->ipcp_name);
    cand.apn = cand_name.apn;
    cand.api = cand_name.api;
    cand.address = ipcp->ipcp_addr;
    cand.lower_difs = rib->lower_difs;
    ncl.candidates.push_back(cand);

    m = CDAPMessage();
    m.m_create(gpb::F_NO_FLAGS, obj_class::neighbors, obj_name::neighbors,
               0, 0, string());
    ret = send_to_port_id(&m, 0, &ncl);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    /* Send my DFT. */
    DFTSlice dft_slice;
    for (map< string, DFTEntry >::iterator e = rib->dft.begin();
                                            e != rib->dft.end(); e++) {
        dft_slice.entries.push_back(e->second);
    }

    m = CDAPMessage();
    m.m_create(gpb::F_NO_FLAGS, obj_class::dft, obj_name::dft,
               0, 0, string());
    ret = send_to_port_id(&m, 0, &dft_slice);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    /* Stop the enrollment. */
    enr_info.start_early = true;

    m = CDAPMessage();
    m.m_stop(gpb::F_NO_FLAGS, obj_class::enrollment, obj_name::enrollment,
             0, 0, string());

    ret = send_to_port_id(&m, 0, &enr_info);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    enroll_tmr_stop();
    enroll_tmr_start();
    enrollment_state = S_WAIT_STOP_R;

    return 0;
}

int
Neighbor::i_wait_start_r(const CDAPMessage *rm)
{
    /* (4) I <-- S: M_START_R */
    const char *objbuf;
    size_t objlen;

    if (rm->op_code != gpb::M_START_R) {
        PE("M_START_R expected\n");
        abort();
        return 0;
    }

    if (rm->result) {
        PE("Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        abort();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START_R does not contain a nested message\n");
        abort();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);

    /* The slave may have specified an address for us. */
    if (enr_info.address) {
        rib->set_address(enr_info.address);
    }

    enroll_tmr_stop();
    enroll_tmr_start();
    enrollment_state = I_WAIT_STOP;

    return 0;
}

int
Neighbor::i_wait_stop(const CDAPMessage *rm)
{
    /* (6) I <-- S: M_STOP
     * (7) I --> S: M_STOP_R */
    const char *objbuf;
    size_t objlen;
    CDAPMessage m;
    int ret;

    /* Here M_CREATE messages from the slave are accepted and
     * dispatched to the rib. */
    if (rm->op_code == gpb::M_CREATE) {
        return rib->cdap_dispatch(rm, this);
    }

    if (rm->op_code != gpb::M_STOP) {
        PE("M_STOP expected\n");
        abort();
        return 0;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_STOP does not contain a nested message\n");
        abort();
        return 0;
    }

    EnrollmentInfo enr_info(objbuf, objlen);

    /* Update our address according to what received from the
     * neighbor. */
    if (enr_info.address) {
        rib->set_address(enr_info.address);
    }

    /* If operational state indicates that we (the initiator) are already
     * DIF member, we can send our dynamic information to the slave. */

    /* Here we may M_READ from the slave. */

    m.m_stop_r(gpb::F_NO_FLAGS, 0, string());

    ret = send_to_port_id(&m, rm->invoke_id, NULL);
    if (ret) {
        PE("send_to_port_id() failed\n");
        abort();
        return 0;
    }

    if (enr_info.start_early) {
        PI("Initiator is allowed to start early\n");
        enroll_tmr_stop();
        enrollment_state = ENROLLED;

        /* Add a new LowerFlow entry to the RIB, corresponding to
         * the new neighbor. */
        rib->add_lower_flow(enr_info.address, *this);

        remote_sync_rib();

    } else {
        PI("Initiator is not allowed to start early\n");
        enroll_tmr_stop();
        enroll_tmr_start();
        enrollment_state = I_WAIT_START;
    }

    return 0;
}

int
Neighbor::s_wait_stop_r(const CDAPMessage *rm)
{
    /* (7) S <-- I: M_STOP_R */
    /* (8) S --> I: M_START(status) */
    struct rlite_ipcp *ipcp;
    CDAPMessage m;
    int ret;

    if (rm->op_code != gpb::M_STOP_R) {
        PE("M_START_R expected\n");
        abort();
        return 0;
    }

    if (rm->result) {
        PE("Neighbor returned negative response [%d], '%s'\n",
           rm->result, rm->result_reason.c_str());
        abort();
        return 0;
    }

    /* This is not required if the initiator is allowed to start
     * early. */
    m.m_start(gpb::F_NO_FLAGS, obj_class::status, obj_name::status,
              0, 0, string());

    ret = send_to_port_id(&m, 0, NULL);
    if (ret) {
        PE("send_to_port_id failed\n");
        abort();
        return ret;
    }

    enroll_tmr_stop();
    enrollment_state = ENROLLED;

    /* Add a new LowerFlow entry to the RIB, corresponding to
     * the new neighbor. */
    ipcp = rib->ipcp_info();
    rib->add_lower_flow(ipcp->ipcp_addr, *this);

    remote_sync_rib();

    return 0;
}

int
Neighbor::i_wait_start(const CDAPMessage *rm)
{
    /* Not yet implemented. */
    assert(false);
    return 0;
}

int
Neighbor::enrolled(const CDAPMessage *rm)
{
    if (rm->op_code == gpb::M_START && rm->obj_class == obj_class::status
                && rm->obj_name == obj_name::status) {
        /* This is OK, but we didn't need it, as
         * we started early. */
        PI("Ignoring M_START(status)\n");
        return 0;
    }

    /* We are enrolled to this neighbor, so we can dispatch its
     * CDAP message to the RIB. */
    return rib->cdap_dispatch(rm, this);
}

int
Neighbor::enroll_fsm_run(const CDAPMessage *rm)
{
    state_t old_state = enrollment_state;
    int ret;

    assert(enrollment_state >= NONE &&
           enrollment_state < ENROLLMENT_STATE_LAST);
    assert(enroll_fsm_handlers[enrollment_state]);

    if (!rm && enrollment_state != NONE) {
        PI("Enrollment already in progress, current state "
            "is %s\n", enrollment_state_repr(enrollment_state));
        return 0;
    }

    ret = (this->*(enroll_fsm_handlers[enrollment_state]))(rm);

    if (old_state != enrollment_state) {
        PI("switching state %s --> %s\n",
             enrollment_state_repr(old_state),
             enrollment_state_repr(enrollment_state));
    }

    return ret;
}

int Neighbor::remote_sync_obj(bool create, const string& obj_class,
                          const string& obj_name,
                          const UipcpObject *obj_value) const
{
    CDAPMessage m;
    int ret;

    if (enrollment_state != ENROLLED) {
        /* Skip this one since it's not enrolled yet. */
        return 0;
    }

    if (create) {
        m.m_create(gpb::F_NO_FLAGS, obj_class, obj_name,
                0, 0, "");

    } else {
        m.m_delete(gpb::F_NO_FLAGS, obj_class, obj_name,
                0, 0, "");
    }

    ret = send_to_port_id(&m, 0, obj_value);
    if (ret) {
        PE("send_to_port_id() failed\n");
    }

    return ret;
}

int Neighbor::remote_sync_rib() const
{
    int ret = 0;

    PD("Starting RIB sync with neighbor '%s'\n",
       static_cast<string>(ipcp_name).c_str());

    {
        LowerFlowList lfl;

        for (map<string, LowerFlow>::iterator mit = rib->lfdb.begin();
                mit != rib->lfdb.end(); mit++) {
            lfl.flows.push_back(mit->second);
        }

        ret |= remote_sync_obj(true, obj_class::lfdb, obj_name::lfdb,
                               &lfl);
    }

    {
        DFTSlice dft_slice;

        for (map< string, DFTEntry >::iterator e = rib->dft.begin();
                e != rib->dft.end(); e++) {
            dft_slice.entries.push_back(e->second);
        }

        ret |= remote_sync_obj(true, obj_class::dft, obj_name::dft,
                               &dft_slice);
    }

    {
        NeighborCandidateList ncl;
        NeighborCandidate cand;
        RinaName cand_name;
        struct rlite_ipcp *ipcp;

        /* My neighbors. */
        for (map<string, NeighborCandidate>::iterator cit =
                rib->cand_neighbors.begin();
                cit != rib->cand_neighbors.end(); cit++) {
            ncl.candidates.push_back(cit->second);
        }

        /* A neighbor representing myself. */
        ipcp = rib->ipcp_info();
        cand_name = RinaName(&ipcp->ipcp_name);
        cand.apn = cand_name.apn;
        cand.api = cand_name.api;
        cand.address = ipcp->ipcp_addr;
        cand.lower_difs = rib->lower_difs;
        ncl.candidates.push_back(cand);

        ret |= remote_sync_obj(true, obj_class::lfdb, obj_name::lfdb,
                               &ncl);
    }

    PD("Finished RIB sync with neighbor '%s'\n",
       static_cast<string>(ipcp_name).c_str());

    return ret;
}

Neighbor *
uipcp_rib::get_neighbor(const struct rina_name *neigh_name)
{
    RinaName _neigh_name_(neigh_name);
    string neigh_name_s = static_cast<string>(_neigh_name_);

    if (!neighbors.count(neigh_name_s)) {
        neighbors[neigh_name_s] =
                Neighbor(this, neigh_name);
    }

    return &neighbors[neigh_name_s];
}

int
uipcp_rib::del_neighbor(const RinaName& neigh_name)
{
    map<string, Neighbor>::iterator mit =
                    neighbors.find(static_cast<string>(neigh_name));

    if (mit == neighbors.end()) {
        return -1;
    }

    neighbors.erase(mit);

    return 0;
}

uint64_t
uipcp_rib::lookup_neighbor_address(const RinaName& neigh_name) const
{
    map< string, NeighborCandidate >::const_iterator
            mit = cand_neighbors.find(static_cast<string>(neigh_name));

    if (mit != cand_neighbors.end()) {
        return mit->second.address;
    }

    return 0;
}

RinaName
uipcp_rib::lookup_neighbor_by_address(uint64_t address)
{
    map<string, NeighborCandidate>::iterator nit;

    for (nit = cand_neighbors.begin(); nit != cand_neighbors.end(); nit++) {
        if (nit->second.address == address) {
            return RinaName(nit->second.apn, nit->second.api,
                            string(), string());
        }
    }

    return RinaName();
}

static string
common_lower_dif(const list<string> l1, const list<string> l2)
{
    for (list<string>::const_iterator i = l1.begin(); i != l1.end(); i++) {
        for (list<string>::const_iterator j = l2.begin(); j != l2.end(); j++) {
            if (*i == *j) {
                return *i;
            }
        }
    }

    return string();
}

int
uipcp_rib::neighbors_handler(const CDAPMessage *rm, Neighbor *neigh)
{
    struct rlite_ipcp *ipcp;
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        PE("M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        PE("M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    ipcp = ipcp_info();

    NeighborCandidateList ncl(objbuf, objlen);
    RinaName my_name = RinaName(&ipcp->ipcp_name);

    for (list<NeighborCandidate>::iterator neigh = ncl.candidates.begin();
                                neigh != ncl.candidates.end(); neigh++) {
        RinaName neigh_name = RinaName(neigh->apn, neigh->api, string(),
                                       string());
        string key = static_cast<string>(neigh_name);
        map< string, NeighborCandidate >::iterator mit = cand_neighbors.find(key);

        if (neigh_name == my_name) {
            /* Skip myself (as a neighbor of the slave). */
            continue;
        }

        if (add) {
            string common_dif = common_lower_dif(neigh->lower_difs, lower_difs);
            if (common_dif == string()) {
                PD("Neighbor %s discarded because there are no lower DIFs in "
                        "common with us\n", key.c_str());
                continue;
            }

            cand_neighbors[key] = *neigh;
            PD("Candidate neighbor %s %s remotely\n", key.c_str(),
                    (mit != cand_neighbors.end() ? "updated" : "added"));

        } else {
            if (mit == cand_neighbors.end()) {
                PI("Candidate neighbor does not exist\n");
            } else {
                cand_neighbors.erase(mit);
                PD("Candidate neighbor %s removed remotely\n", key.c_str());
            }

        }
    }

    return 0;
}

map<string, Neighbor>::iterator
uipcp_rib::lookup_neigh_by_port_id(unsigned int port_id)
{
    for (map<string, Neighbor>::iterator neigh = neighbors.begin();
                        neigh != neighbors.end(); neigh++) {
        if (neigh->second.port_id == port_id) {
            return neigh;
        }
    }

    return neighbors.end();
}

map<string, Neighbor>::iterator
uipcp_rib::lookup_neigh_by_name(const RinaName& name)
{
    return neighbors.find(name);
}

int
Neighbor::alloc_flow(struct rina_name *supp_dif_name)
{
    struct rlite_ipcp *info;
    unsigned int port_id_;
    struct rina_name neigh_name;
    int flow_fd_;
    int ret;

    if (has_mgmt_flow()) {
        PI("Management flow already allocated\n");
        return 0;
    }

    info = rib->ipcp_info();
    ipcp_name.rina_name_fill(&neigh_name);

    /* Allocate a flow for the enrollment. */
    ret = rlite_flow_allocate(&rib->uipcp->appl, supp_dif_name, 0, NULL,
                         &info->ipcp_name, &neigh_name, NULL,
                         &port_id_, 2000, info->ipcp_id);
    rina_name_free(&neigh_name);
    if (ret) {
        PE("Failed to allocate a flow towards neighbor\n");
        return -1;
    }

    flow_fd_ = rlite_open_appl_port(port_id_);
    if (flow_fd_ < 0) {
        PE("Failed to access the flow towards the neighbor\n");
        return -1;
    }

    port_id = port_id_;
    flow_fd = flow_fd_;

    PD("N-1 flow allocated [fd=%d, port_id=%u]\n", flow_fd,
       port_id);


    return 0;
}

int
normal_ipcp_enroll(struct uipcp *uipcp, struct rina_cmsg_ipcp_enroll *req)
{
    uipcp_rib *rib = UIPCP_RIB(uipcp);
    Neighbor *neigh;
    int ret;

    neigh = rib->get_neighbor(&req->neigh_ipcp_name);
    if (!neigh) {
        PE("Failed to add neighbor\n");
        return -1;
    }

    ret = neigh->alloc_flow(&req->supp_dif_name);
    if (ret) {
        return ret;
    }

    assert(neigh->has_mgmt_flow());

    /* Start the enrollment procedure as initiator. */
    neigh->enroll_fsm_run(NULL);

    return 0;
}

int
rib_neigh_set_port_id(struct uipcp_rib *rib,
                      const struct rina_name *neigh_name,
                      unsigned int neigh_port_id)
{
    Neighbor *neigh = rib->get_neighbor(neigh_name);

    if (!neigh) {
        PE("Failed to get neighbor\n");
        return -1;
    }

    neigh->port_id = neigh_port_id;

    return 0;
}

int
rib_neigh_set_flow_fd(struct uipcp_rib *rib,
                      const struct rina_name *neigh_name,
                      int neigh_fd)
{
    Neighbor *neigh = rib->get_neighbor(neigh_name);

    if (!neigh) {
        PE("Failed to get neighbor\n");
    }

    neigh->flow_fd = neigh_fd;

    PD("N-1 flow allocated [fd=%d, port_id=%u]\n", neigh->flow_fd,
       neigh->port_id);

    return 0;
}

