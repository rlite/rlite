/*
 * Application registration support for normal uipcps.
 *
 * Copyright (C) 2015-2016 Nextworks
 * Author: Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This file is part of rlite.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <ctime>
#include <iterator>
#include <cstdlib>

#include "uipcp-normal.hpp"

using namespace std;

static uint64_t
time64()
{
    struct timespec tv;

    if (clock_gettime(CLOCK_MONOTONIC, &tv)) {
        perror("clock_gettime() failed");
        tv.tv_sec  = 0;
        tv.tv_nsec = 0;
    }

    return (tv.tv_sec << 32) | (tv.tv_nsec & ((1L << 32) - 1L));
}

class FullyReplicatedDFT : public DFT {
    /* Directory Forwarding Table, mapping application name (std::string)
     * to a set of nodes that registered that name. All nodes are considered
     * equivalent. */
    std::multimap<std::string, DFTEntry> dft_table;

public:
    RL_NODEFAULT_NONCOPIABLE(FullyReplicatedDFT);
    FullyReplicatedDFT(struct uipcp_rib *_ur) : DFT(_ur) {}
    ~FullyReplicatedDFT() {}

    void dump(std::stringstream &ss) const override;

    int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                     const rlm_addr_t preferred, uint32_t cookie) override;
    int appl_register(const struct rl_kmsg_appl_register *req) override;
    void update_address(rlm_addr_t new_addr) override;
    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override;
    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;

    /* Helper function shared with CentralizedFaultTolerantDFT::Replica. */
    void mod_table(const DFTEntry &e, bool add, DFTSlice *added,
                   DFTSlice *removed);
};

int
FullyReplicatedDFT::lookup_entry(const std::string &appl_name,
                                 rlm_addr_t &dstaddr,
                                 const rlm_addr_t preferred, uint32_t cookie)
{
    /* Fetch all entries that hold 'appl_name'. */
    auto range = dft_table.equal_range(appl_name);
    int d;

    d = distance(range.first, range.second);

    if (d == 0) {
        /* No entry. */
        return -1;
    }

    auto mit = range.first;

    if (d > 1) {
        if (preferred) {
            /* Only accept the preferred address. */

            for (; mit != range.second; mit++) {
                if (mit->second.address == preferred) {
                    break;
                }
            }
        } else {
            /* Load balance by selecting an entry based on
             * the cookie value. */
            cookie %= d;
            while (cookie > 0 && mit != range.second) {
                mit++;
                cookie--;
            }
        }

        assert(mit != range.second);
    }

    dstaddr = mit->second.address;

    return 0;
}

int
FullyReplicatedDFT::appl_register(const struct rl_kmsg_appl_register *req)
{
    multimap<string, DFTEntry>::iterator mit;
    string appl_name(req->appl_name);
    struct uipcp *uipcp = rib->uipcp;
    DFTSlice dft_slice;
    DFTEntry dft_entry;

    dft_entry.address   = rib->myaddr;
    dft_entry.appl_name = RinaName(appl_name);
    dft_entry.timestamp = time64();
    dft_entry.local     = true;

    /* Get all the entries for 'appl_name', and see if there
     * is an entry associated to this uipcp. */
    auto range = dft_table.equal_range(appl_name);
    for (mit = range.first; mit != range.second; mit++) {
        if (mit->second.address == rib->myaddr) {
            break;
        }
    }

    if (req->reg) {
        if (mit != range.second) { /* local collision */
            UPE(uipcp, "Application %s already registered on this uipcp\n",
                appl_name.c_str());
            return uipcp_appl_register_resp(uipcp, RLITE_ERR, req->event_id,
                                            req->appl_name);
        }

        if (req->reg) {
            /* Registration requires a response, while unregistrations doesn't.
             * Respond to the client before committing to the RIB, because the
             * response may fail. */
            int ret = uipcp_appl_register_resp(uipcp, RLITE_SUCC, req->event_id,
                                               req->appl_name);
            if (ret) {
                return ret;
            }
        }

        /* Insert the object into the RIB. */
        dft_table.insert(make_pair(appl_name, dft_entry));
    } else {
        if (mit == range.second) {
            UPE(uipcp, "Application %s was not registered here\n",
                appl_name.c_str());
            return 0;
        }

        /* Remove from the RIB. */
        dft_table.erase(mit);
    }

    dft_slice.entries.push_back(dft_entry);

    UPD(uipcp, "Application %s %sregistered\n", appl_name.c_str(),
        req->reg ? "" : "un");

    rib->neighs_sync_obj_all(req->reg != 0, obj_class::dft, obj_name::dft,
                             &dft_slice);

    return 0;
}

/* Tries ot add or remove an entry 'e' from the DFT multimap. If not nullptr,
 * the entries added and/or removed are appended to 'added' and 'removed'
 * respectively. */
void
FullyReplicatedDFT::mod_table(const DFTEntry &e, bool add, DFTSlice *added,
                              DFTSlice *removed)
{
    string key = static_cast<string>(e.appl_name);
    auto range = dft_table.equal_range(key);
    multimap<string, DFTEntry>::iterator mit;
    struct uipcp *uipcp = rib->uipcp;

    for (mit = range.first; mit != range.second; mit++) {
        if (mit->second.address == e.address) {
            break;
        }
    }

    if (add) {
        bool collision = (mit != range.second);

        if (!collision || e.timestamp > mit->second.timestamp) {
            if (collision) {
                /* Remove the collided entry. */
                if (removed) {
                    removed->entries.push_back(mit->second);
                }
                dft_table.erase(mit);
            }
            dft_table.insert(make_pair(key, e));
            if (added) {
                added->entries.push_back(e);
            }
            UPD(uipcp, "DFT entry %s --> %lu %s remotely\n", key.c_str(),
                e.address, (collision ? "updated" : "added"));
        }

    } else {
        if (mit == range.second) {
            UPI(uipcp, "DFT entry does not exist\n");
        } else {
            dft_table.erase(mit);
            if (removed) {
                removed->entries.push_back(e);
            }
            UPD(uipcp, "DFT entry %s --> %lu removed remotely\n", key.c_str(),
                e.address);
        }
    }
}

int
FullyReplicatedDFT::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    struct uipcp *uipcp = rib->uipcp;
    const char *objbuf;
    size_t objlen;
    bool add = true;

    if (rm->op_code != gpb::M_CREATE && rm->op_code != gpb::M_DELETE) {
        UPE(uipcp, "M_CREATE or M_DELETE expected\n");
        return 0;
    }

    if (rm->op_code == gpb::M_DELETE) {
        add = false;
    }

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(uipcp, "M_START does not contain a nested message\n");
        abort();
        return 0;
    }

    DFTSlice dft_slice(objbuf, objlen);
    DFTSlice prop_dft_add, prop_dft_del;

    for (const DFTEntry &e : dft_slice.entries) {
        mod_table(e, add, &prop_dft_add, &prop_dft_del);
    }

    /* Propagate the DFT entries update to the other neighbors,
     * except for who told us. */
    if (prop_dft_add.entries.size()) {
        rib->neighs_sync_obj_excluding(nf->neigh, true, obj_class::dft,
                                       obj_name::dft, &prop_dft_add);
    }

    if (prop_dft_del.entries.size()) {
        rib->neighs_sync_obj_excluding(nf->neigh, false, obj_class::dft,
                                       obj_name::dft, &prop_dft_del);
    }

    return 0;
}

void
FullyReplicatedDFT::update_address(rlm_addr_t new_addr)
{
    DFTSlice prop_dft;
    DFTSlice del_dft;

    /* Update all the DFT entries corresponding to application that are
     * registered within us. */
    for (auto &kve : dft_table) {
        if (kve.second.local && kve.second.address == rib->myaddr) {
            del_dft.entries.push_back(kve.second);
            kve.second.address   = new_addr;
            kve.second.timestamp = time64();
            prop_dft.entries.push_back(kve.second);
            UPD(rib->uipcp, "Updated address for DFT entry %s\n",
                kve.first.c_str());
        }
    }

    /* Disseminate the update. */
    if (prop_dft.entries.size()) {
        rib->neighs_sync_obj_all(true, obj_class::dft, obj_name::dft,
                                 &prop_dft);
    }

    if (del_dft.entries.size()) {
        rib->neighs_sync_obj_all(false, obj_class::dft, obj_name::dft,
                                 &del_dft);
    }
}

void
FullyReplicatedDFT::dump(stringstream &ss) const
{
    ss << "Directory Forwarding Table:" << endl;
    for (const auto &kve : dft_table) {
        const DFTEntry &entry = kve.second;

        ss << "    Application: " << static_cast<string>(entry.appl_name)
           << ", Address: " << entry.address
           << ", Timestamp: " << entry.timestamp << endl;
    }

    ss << endl;
}

int
FullyReplicatedDFT::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    int ret = 0;

    for (auto eit = dft_table.begin(); eit != dft_table.end();) {
        DFTSlice dft_slice;

        while (dft_slice.entries.size() < limit && eit != dft_table.end()) {
            dft_slice.entries.push_back(eit->second);
            eit++;
        }

        ret |= nf->neigh->neigh_sync_obj(nf, true, obj_class::dft,
                                         obj_name::dft, &dft_slice);
    }

    return ret;
}

/* Propagate local entries (i.e. the ones corresponding to locally
 * registered applications) to all our neighbors. */
int
FullyReplicatedDFT::neighs_refresh(size_t limit)
{
    int ret = 0;

    for (auto eit = dft_table.begin(); eit != dft_table.end();) {
        DFTSlice dft_slice;

        while (dft_slice.entries.size() < limit && eit != dft_table.end()) {
            if (eit->second.local) {
                dft_slice.entries.push_back(eit->second);
            }
            eit++;
        }

        if (dft_slice.entries.size()) {
            ret |= rib->neighs_sync_obj_all(true, obj_class::dft, obj_name::dft,
                                            &dft_slice);
        }
    }

    return ret;
}

class CentralizedFaultTolerantDFT : public DFT {
    /* An instance of this class can be a state machine replica or it can just
     * be a client that will redirect requests to one of the replicas. */

    /* In case of state machine replica, a pointer to a Raft state
     * machine. */
    class Replica : public raft::RaftSM {
        CentralizedFaultTolerantDFT *parent = nullptr;

        /* The structure of a DFT command (i.e. a log entry for the Raft SM). */
        struct Command {
            rlm_addr_t address;
            char name[63];
            uint8_t opcode;
            static constexpr uint8_t OpcodeSet = 1;
            static constexpr uint8_t OpcodeDel = 2;
        } __attribute__((packed));
        static_assert(sizeof(struct Command) == sizeof(Command::address) +
                                                    sizeof(Command::name) +
                                                    sizeof(Command::opcode),
                      "Invalid memory layout for class Replica::Command");

        /* Timer needed by the Raft state machine. */
        std::unique_ptr<TimeoutEvent> timer;
        raft::RaftTimerType timer_type;

        /* State machine implementation. Just reuse the implementation of
         * a fully replicated DFT. */
        std::unique_ptr<FullyReplicatedDFT> impl;

    public:
        Replica(CentralizedFaultTolerantDFT *dft)
            : raft::RaftSM(std::string("ceft-dft-") + dft->rib->myname,
                           dft->rib->myname,
                           std::string("/tmp/ceft-dft-") +
                               std::to_string(dft->rib->uipcp->id) +
                               std::string("-") + dft->rib->myname,
                           sizeof(Command), std::cerr, std::cout),
              parent(dft),
              impl(make_unique<FullyReplicatedDFT>(dft->rib)){};
        int process_sm_output(raft::RaftSMOutput out);
        int process_timeout();
        int apply(const char *const serbuf) override;
        int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                         const rlm_addr_t preferred, uint32_t cookie)
        {
            return impl->lookup_entry(appl_name, dstaddr, preferred, cookie);
        }
        int appl_register(const struct rl_kmsg_appl_register *req);
        int rib_handler(const CDAPMessage *rm, NeighFlow *nf);
        void dump(std::stringstream &ss) const { impl->dump(ss); };
    };
    std::unique_ptr<Replica> raft;

    /* In case of client, a pointer to client-side data structures. */
    class Client {
        CentralizedFaultTolerantDFT *parent = nullptr;
        std::list<raft::ReplicaId> replicas;
        /* The leader, if we know who it is, otherwise the empty
         * string. */
        raft::ReplicaId leader_id;
        std::unique_ptr<TimeoutEvent> timer;

        struct PendingReq {
            gpb::opCode_t op_code;
            std::string appl_name;
            raft::ReplicaId replica;
            uint32_t kevent_id;
            std::chrono::system_clock::time_point t;
            PendingReq() = default;
            PendingReq(gpb::opCode_t op, const std::string &a,
                       const raft::ReplicaId &r, uint32_t event_id)
                : op_code(op), appl_name(a), replica(r), kevent_id(event_id)
            {
                t = std::chrono::system_clock::now();
            }
        };
        std::unordered_map</*invoke_id*/ int, PendingReq> pending;

        void rearm_pending_timer();

    public:
        Client(CentralizedFaultTolerantDFT *dft,
               std::list<raft::ReplicaId> names)
            : parent(dft), replicas(std::move(names))
        {
        }
        int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                         const rlm_addr_t preferred, uint32_t cookie);
        int appl_register(const struct rl_kmsg_appl_register *req);
        int rib_handler(const CDAPMessage *rm, NeighFlow *nf);
        int process_timeout();
    };
    std::unique_ptr<Client> client;

public:
    RL_NODEFAULT_NONCOPIABLE(CentralizedFaultTolerantDFT);
    CentralizedFaultTolerantDFT(struct uipcp_rib *_ur) : DFT(_ur) {}
    int param_changed(const std::string &param_name) override;
    void dump(std::stringstream &ss) const override
    {
        if (client) {
            ss << "Directory Forwarding Table: not available locally" << endl
               << endl;
        } else {
            raft->dump(ss);
        }
    }

    int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                     const rlm_addr_t preferred, uint32_t cookie) override
    {
        if (client) {
            return client->lookup_entry(appl_name, dstaddr, preferred, cookie);
        }
        return raft->lookup_entry(appl_name, dstaddr, preferred, cookie);
    }
    int appl_register(const struct rl_kmsg_appl_register *req) override
    {
        if (client) {
            return client->appl_register(req);
        }
        return raft->appl_register(req);
    }
    void update_address(rlm_addr_t new_addr) override;
    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override
    {
        if (client) {
            return client->rib_handler(rm, nf);
        }
        return raft->rib_handler(rm, nf);
    }
};

int
CentralizedFaultTolerantDFT::param_changed(const std::string &param_name)
{
    list<raft::ReplicaId> peers;

    if (param_name != "replicas") {
        return -1;
    }

    UPD(rib->uipcp, "replicas = %s\n", param_name.c_str());
    peers = strsplit(param_name, ',');

    auto it = peers.begin();
    for (; it != peers.end(); it++) {
        if (*it == rib->myname) {
            /* I'm one of the replicas. Create a Raft state machine and
             * initialize it. */
            client.reset();
            raft = make_unique<Replica>(this);
            peers.erase(it); /* remove myself */

            raft::RaftSMOutput out;
            if (raft->init(peers, &out)) {
                UPE(rib->uipcp, "Failed to init Raft state machine for DFT\n");
                return -1;
            }
            UPI(rib->uipcp, "Raft replica initialized\n");
            assert(raft != nullptr && client == nullptr);
            return raft->process_sm_output(std::move(out));
        }
    }

    /* I'm not one of the replicas. I'm just a client. */
    assert(it == peers.end());
    raft.reset();
    client = make_unique<Client>(this, std::move(peers));
    UPI(rib->uipcp, "Client initialized\n");
    assert(raft == nullptr && client != nullptr);

    return 0;
}

void
CentralizedFaultTolerantDFT::update_address(rlm_addr_t new_addr)
{
    UPE(rib->uipcp, "Missing implementation\n");
}

/* Rearm the timer according to the older pending request (i.e. the next one
 * that is expiring). */
void
CentralizedFaultTolerantDFT::Client::rearm_pending_timer()
{
    if (pending.empty()) {
        timer = nullptr;
    } else {
        auto t_min = std::chrono::system_clock::time_point::max();
        for (const auto &kv : pending) {
            if (kv.second.t < t_min) {
                t_min = kv.second.t;
            }
        }
        timer = make_unique<TimeoutEvent>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now() + std::chrono::seconds(3) -
                t_min),
            parent->rib->uipcp, this, [](struct uipcp *uipcp, void *arg) {
                auto cli =
                    static_cast<CentralizedFaultTolerantDFT::Client *>(arg);
                cli->timer->fired();
                cli->process_timeout();
            });
    }
}

int
CentralizedFaultTolerantDFT::Client::lookup_entry(const std::string &appl_name,
                                                  rlm_addr_t &dstaddr,
                                                  const rlm_addr_t preferred,
                                                  uint32_t cookie)
{
    /* Prepare an M_READ for a read operation. If we know who is the leader,
     * we send it to the leader only; otherwise we send it to all the replicas.
     */
    for (const auto &r : replicas) {
        if (leader_id.empty() || r == leader_id) {
            auto m = make_unique<CDAPMessage>();
            gpb::opCode_t op_code;
            int invoke_id;
            int ret;

            m->m_read(obj_class::dft, obj_name::dft + "/" + appl_name);
            op_code = m->op_code;

            ret = parent->rib->send_to_dst_node(std::move(m), r, nullptr,
                                                &invoke_id);
            if (ret) {
                return ret;
            }
            pending[invoke_id] =
                std::move(PendingReq(op_code, appl_name, r, 0));
        }
    }

    rearm_pending_timer();

    UPI(parent->rib->uipcp, "Read request for '%s' issued\n",
        appl_name.c_str());

    // TODO fill dstaddr

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::appl_register(
    const struct rl_kmsg_appl_register *req)
{
    string appl_name(req->appl_name);

    /* Prepare an M_WRITE or M_DELETE message for a write/delete operation.
     * If we know who is the leader, we send it to the leader only; otherwise
     * we send it to all the replicas. */
    for (const auto &r : replicas) {
        if (leader_id.empty() || r == leader_id) {
            auto m = make_unique<CDAPMessage>();
            gpb::opCode_t op_code;
            DFTEntry dft_entry;
            int invoke_id;
            int ret;

            if (req->reg) {
                m->m_write(obj_class::dft, obj_name::dft);
            } else {
                m->m_delete(obj_class::dft, obj_name::dft);
            }
            op_code             = m->op_code;
            dft_entry.address   = parent->rib->myaddr;
            dft_entry.appl_name = RinaName(appl_name);
            dft_entry.timestamp = time64();

            ret = parent->rib->send_to_dst_node(std::move(m), r, &dft_entry,
                                                &invoke_id);
            if (ret) {
                return ret;
            }
            pending[invoke_id] =
                std::move(PendingReq(op_code, appl_name, r, req->event_id));
        }
    }

    rearm_pending_timer();

    UPI(parent->rib->uipcp, "Write request '%s <= %lu' issued\n",
        appl_name.c_str(), parent->rib->myaddr);

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::process_timeout()
{
    std::lock_guard<std::mutex> guard(parent->rib->mutex);

    /* We got a timeout, let's forget about the current leader. */
    leader_id.clear();
    rearm_pending_timer();
    UPE(parent->rib->uipcp, "Missing implementation\n");
    return 0;
}

int
CentralizedFaultTolerantDFT::Client::rib_handler(const CDAPMessage *rm,
                                                 NeighFlow *nf)
{
    struct uipcp *uipcp = parent->rib->uipcp;

    /* We expect a M_WRITE_R corresponding to the M_WRITE or M_DELETE sent by
     * Client::appl_register(). */
    if (rm->op_code != gpb::M_WRITE_R && rm->op_code != gpb::M_DELETE_R) {
        UPE(uipcp, "M_WRITE_R or M_DELETE_R expected\n");
        return 0;
    }

    /* Lookup rm->invoke_id in the pending map and erase it. */
    auto pi = pending.find(rm->invoke_id);
    if (pi == pending.end()) {
        UPE(uipcp, "Cannot find pending request with invoke id %d\n",
            rm->invoke_id);
        return 0;
    }

    /* Check that rm->op_code is consistent with the pending request. */
    if (pi->second.op_code != rm->op_code) {
        UPE(uipcp, "Opcode mismatch for request with invoke id %d\n",
            rm->invoke_id);
        return 0;
    }

    /* We assume it was the leader to answer. So now we know who the leader is.
     */
    leader_id = pi->second.replica;
    UPD(uipcp, "Application %s %sregistration %s\n",
        pi->second.appl_name.c_str(), rm->op_code == gpb::M_WRITE_R ? "" : "un",
        rm->result ? "failed" : "was successful");
    if (rm->op_code == gpb::M_WRITE_R) {
        /* Registrations need a response. */
        uipcp_appl_register_resp(uipcp, rm->result ? RLITE_ERR : RLITE_SUCC,
                                 pi->second.kevent_id,
                                 pi->second.appl_name.c_str());
    }
    pending.erase(pi);

    return 0;
}

int
CentralizedFaultTolerantDFT::Replica::process_sm_output(raft::RaftSMOutput out)
{
    int ret = 0;

    for (auto &pair : out.output_messages) {
        raft::RaftMessage *msg = pair.second.get();
        const auto *rv  = dynamic_cast<const raft::RaftRequestVote *>(msg);
        const auto *rvr = dynamic_cast<const raft::RaftRequestVoteResp *>(msg);
        auto *ae        = dynamic_cast<raft::RaftAppendEntries *>(msg);
        const auto *aer =
            dynamic_cast<const raft::RaftAppendEntriesResp *>(msg);
        auto m = make_unique<CDAPMessage>();
        std::unique_ptr<UipcpObject> obj;
        std::string obj_class;

        if (rv) {
            auto mm            = make_unique<RaftRequestVote>();
            mm->term           = rv->term;
            mm->candidate_id   = rv->candidate_id;
            mm->last_log_index = rv->last_log_index;
            mm->last_log_term  = rv->last_log_term;
            obj                = std::move(mm);
            obj_class          = obj_class::raft_req_vote;
        } else if (rvr) {
            auto mm          = make_unique<RaftRequestVoteResp>();
            mm->term         = rvr->term;
            mm->vote_granted = rvr->vote_granted;
            obj              = std::move(mm);
            obj_class        = obj_class::raft_req_vote_resp;
        } else if (ae) {
            auto mm            = make_unique<RaftAppendEntries>();
            mm->term           = ae->term;
            mm->leader_id      = ae->leader_id;
            mm->leader_commit  = ae->leader_commit;
            mm->prev_log_index = ae->prev_log_index;
            mm->prev_log_term  = ae->prev_log_term;
            mm->entries        = std::move(ae->entries);
            obj                = std::move(mm);
            obj_class          = obj_class::raft_append_entries;
        } else if (aer) {
            auto mm         = make_unique<RaftAppendEntriesResp>();
            mm->term        = aer->term;
            mm->follower_id = aer->follower_id;
            mm->log_index   = aer->log_index;
            mm->success     = aer->success;
            obj             = std::move(mm);
            obj_class       = obj_class::raft_append_entries_resp;
        } else {
            assert(false);
        }

        m->m_write(obj_class, obj_name::dft);
        ret |= parent->rib->send_to_dst_node(std::move(m), pair.first,
                                             obj.get(), nullptr);
    }

    for (const auto &cmd : out.timer_commands) {
        switch (cmd.action) {
        case raft::RaftTimerAction::Stop:
            timer = nullptr;
            break;
        case raft::RaftTimerAction::Restart:
            timer = make_unique<TimeoutEvent>(
                std::chrono::milliseconds(cmd.milliseconds), parent->rib->uipcp,
                this, [](struct uipcp *uipcp, void *arg) {
                    auto replica =
                        static_cast<CentralizedFaultTolerantDFT::Replica *>(
                            arg);
                    replica->timer->fired();
                    replica->process_timeout();
                });
            timer_type = cmd.type;
            break;
        default:
            assert(false);
            break;
        }
    }

    return ret;
}

int
CentralizedFaultTolerantDFT::Replica::process_timeout()
{
    std::lock_guard<std::mutex> guard(parent->rib->mutex);
    raft::RaftSMOutput out;

    timer_expired(timer_type, &out);

    return process_sm_output(std::move(out));
}

int
CentralizedFaultTolerantDFT::Replica::appl_register(
    const struct rl_kmsg_appl_register *req)
{
    raft::RaftSMOutput out;
    Command c;
    int ret;

    if (!leader()) {
        UPW(parent->rib->uipcp, "Missing implementation for non-leaders\n");
        return 0;
    }

    /* Fill in the command struct (already serialized). */
    c.address = parent->rib->myaddr;
    strncpy(c.name, req->appl_name, sizeof(c.name));
    c.opcode = req->reg ? Command::OpcodeSet : Command::OpcodeDel;

    /* Submit the command to the raft state machine. */
    ret = submit(reinterpret_cast<const char *const>(&c), &out);
    if (ret) {
        UPE(parent->rib->uipcp,
            "Failed to submit application %sregistration for '%s' to the raft "
            "state machine\n",
            req->reg ? "" : "un", req->appl_name);
        return -1;
    }

    /* Complete raft processing. */
    return process_sm_output(std::move(out));
}

/* Apply a command to the replicated state machine. We just pass the command
 * to the same multimap implementation used by the fully replicated DFT. */
int
CentralizedFaultTolerantDFT::Replica::apply(const char *const serbuf)
{
    auto c = reinterpret_cast<const Command *const>(serbuf);
    DFTEntry e;

    e.address   = c->address;
    e.appl_name = RinaName(c->name);
    e.timestamp = time64();
    e.local     = false;

    assert(c->opcode == Command::OpcodeSet || c->opcode == Command::OpcodeDel);

    impl->mod_table(e, c->opcode == Command::OpcodeSet, nullptr, nullptr);

    return 0;
}

int
CentralizedFaultTolerantDFT::Replica::rib_handler(const CDAPMessage *rm,
                                                  NeighFlow *nf)
{
    struct uipcp *uipcp = parent->rib->uipcp;
    const char *objbuf;
    raft::RaftSMOutput out;
    size_t objlen;
    int ret;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(uipcp, "No object value found\n");
        return 0;
    }

    if (rm->obj_class == obj_class::dft) {
        /* We expect a M_WRITE or M_DELETE as sent by Client::appl_register().
         */
        if (rm->op_code != gpb::M_WRITE && rm->op_code != gpb::M_DELETE) {
            UPE(uipcp, "M_WRITE(dft) or M_DELETE(dft) expected\n");
            return 0;
        }

        if (!leader()) {
            /* We are not the leader, we need to forward it to the leader node.
             */
            UPW(uipcp, "Missing code to forward request to the leader\n");
            // TODO send_to_dst_node()
            return 0;
        }

        /* We are the leader. Let's submit the request to the Raft state
         * machine. */

        DFTEntry dft_entry(objbuf, objlen);
        string appl_name(static_cast<string>(dft_entry.appl_name));
        Command c;

        /* Fill in the command struct (already serialized). */
        c.address = dft_entry.address;
        strncpy(c.name, appl_name.c_str(), sizeof(c.name));
        c.opcode = rm->op_code == gpb::M_WRITE ? Command::OpcodeSet
                                               : Command::OpcodeDel;

        /* Submit the command to the raft state machine. */
        ret = submit(reinterpret_cast<const char *const>(&c), &out);
        if (ret) {
            UPE(parent->rib->uipcp,
                "Failed to submit application %sregistration for '%s' to the "
                "raft "
                "state machine\n",
                rm->op_code == gpb::M_WRITE ? "" : "un", appl_name.c_str());
            return -1;
        }
    } else {
        if (rm->obj_class == obj_class::raft_req_vote) {
            auto rv = make_unique<raft::RaftRequestVote>();

            RaftRequestVote mm(objbuf, objlen);
            rv->term           = mm.term;
            rv->candidate_id   = mm.candidate_id;
            rv->last_log_index = mm.last_log_index;
            rv->last_log_term  = mm.last_log_term;
            ret                = request_vote_input(*rv, &out);

        } else if (rm->obj_class == obj_class::raft_req_vote_resp) {
            auto rvr = make_unique<raft::RaftRequestVoteResp>();

            RaftRequestVoteResp mm(objbuf, objlen);
            rvr->term         = mm.term;
            rvr->vote_granted = mm.vote_granted;
            ret               = request_vote_resp_input(*rvr, &out);

        } else if (rm->obj_class == obj_class::raft_append_entries) {
            auto ae = make_unique<raft::RaftAppendEntries>();

            RaftAppendEntries mm(objbuf, objlen);
            ae->term           = mm.term;
            ae->leader_id      = mm.leader_id;
            ae->leader_commit  = mm.leader_commit;
            ae->prev_log_index = mm.prev_log_index;
            ae->prev_log_term  = mm.prev_log_term;
            ae->entries        = std::move(mm.entries);
            ret                = append_entries_input(*ae, &out);

        } else if (rm->obj_class == obj_class::raft_append_entries_resp) {
            auto aer = make_unique<raft::RaftAppendEntriesResp>();

            RaftAppendEntriesResp mm(objbuf, objlen);
            aer->term        = mm.term;
            aer->follower_id = mm.follower_id;
            aer->log_index   = mm.log_index;
            aer->success     = mm.success;
            ret              = append_entries_resp_input(*aer, &out);
        } else {
            UPE(uipcp, "Unexpected object class '%s'\n", rm->obj_class.c_str());
            return 0;
        }
        if (ret) {
            UPE(uipcp, "Failed to submit message %s to the RaftSM\n",
                rm->obj_class.c_str());
        }
    }

    /* Complete raft processing. */
    return process_sm_output(std::move(out));
}

void
uipcp_rib::dft_lib_init()
{
    available_policies["dft"].insert(
        PolicyBuilder("fully-replicated", [](uipcp_rib *rib) {
            rib->dft = make_unique<FullyReplicatedDFT>(rib);
        }));
    available_policies["dft"].insert(
        PolicyBuilder("centralized-fault-tolerant", [](uipcp_rib *rib) {
            rib->dft = make_unique<CentralizedFaultTolerantDFT>(rib);
        }));
}
