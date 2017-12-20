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
                     const rlm_addr_t preferred,
                     uint32_t cookie) const override;
    int appl_register(const struct rl_kmsg_appl_register *req) override;
    void update_address(rlm_addr_t new_addr) override;
    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override;
    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;
};

int
FullyReplicatedDFT::lookup_entry(const std::string &appl_name,
                                 rlm_addr_t &dstaddr,
                                 const rlm_addr_t preferred,
                                 uint32_t cookie) const
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
            return uipcp_appl_register_resp(uipcp, uipcp->id, RLITE_ERR, req);
        }

        if (req->reg) {
            /* Registration requires a response, while unregistrations doesn't.
             * Respond to the client before committing to the RIB, because the
             * response may fail. */
            int ret =
                uipcp_appl_register_resp(uipcp, uipcp->id, RLITE_SUCC, req);
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

    UPD(uipcp, "Application %s %sregistered %s uipcp %d\n", appl_name.c_str(),
        req->reg ? "" : "un", req->reg ? "to" : "from", uipcp->id);

    rib->neighs_sync_obj_all(req->reg != 0, obj_class::dft, obj_name::dft,
                             &dft_slice);

    return 0;
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
        string key = static_cast<string>(e.appl_name);
        auto range = dft_table.equal_range(key);
        multimap<string, DFTEntry>::iterator mit;

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
                    dft_table.erase(mit);
                    prop_dft_del.entries.push_back(e);
                }
                dft_table.insert(make_pair(key, e));
                prop_dft_add.entries.push_back(e);
                UPD(uipcp, "DFT entry %s --> %lu %s remotely\n", key.c_str(),
                    e.address, (collision ? "updated" : "added"));
            }

        } else {
            if (mit == range.second) {
                UPI(uipcp, "DFT entry does not exist\n");
            } else {
                dft_table.erase(mit);
                prop_dft_del.entries.push_back(e);
                UPD(uipcp, "DFT entry %s --> %lu removed remotely\n",
                    key.c_str(), e.address);
            }
        }
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
    class Replica : public RaftSM {
        CentralizedFaultTolerantDFT *parent = nullptr;

        /* The structure of a DFT command (i.e. a log entry for the Raft SM). */
        struct Command {
            rlm_addr_t address;
            char name[63];
            uint8_t opcode;
        } __attribute__((packed));

        /* State machine implementation. Just reuse the implementation of
         * a fully replicated DFT. */
        std::unique_ptr<FullyReplicatedDFT> impl;

    public:
        Replica(CentralizedFaultTolerantDFT *dft)
            : RaftSM(std::string("ceft-dft-") + dft->rib->myname,
                     dft->rib->myname,
                     std::string("/tmp/ceft-dft-") +
                         std::to_string(dft->rib->uipcp->id) +
                         std::string("-") + dft->rib->myname,
                     sizeof(Command), std::cerr, std::cout),
              parent(dft),
              impl(make_unique<FullyReplicatedDFT>(dft->rib)){};
        int process_sm_output(RaftSMOutput out);
        int apply(const char *const serbuf) override { return 0; };
        int dft_set(const struct rl_kmsg_appl_register *req);
    };
    std::unique_ptr<Replica> raft;

    /* In case of client, a pointer to client-side data structures. */
    class Client {
        CentralizedFaultTolerantDFT *parent = nullptr;
        std::list<ReplicaId> replicas;

        struct PendingReq {
            std::string appl_name;
            ReplicaId replica;
            PendingReq() = default;
            PendingReq(const std::string &a, const ReplicaId &r)
                : appl_name(a), replica(r)
            {
            }
        };
        std::unordered_map</*invoke_id*/ int, PendingReq> pending;

    public:
        Client(CentralizedFaultTolerantDFT *dft, std::list<ReplicaId> names)
            : parent(dft), replicas(std::move(names))
        {
        }
        int dft_set(const struct rl_kmsg_appl_register *req);
    };
    std::unique_ptr<Client> client;

public:
    RL_NODEFAULT_NONCOPIABLE(CentralizedFaultTolerantDFT);
    CentralizedFaultTolerantDFT(struct uipcp_rib *_ur) : DFT(_ur) {}
    int param_changed(const std::string &param_name) override;
    void dump(std::stringstream &ss) const override;

    int lookup_entry(const std::string &appl_name, rlm_addr_t &dstaddr,
                     const rlm_addr_t preferred,
                     uint32_t cookie) const override;
    int appl_register(const struct rl_kmsg_appl_register *req) override;
    void update_address(rlm_addr_t new_addr) override;
    int rib_handler(const CDAPMessage *rm, NeighFlow *nf) override;
    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;
};

int
CentralizedFaultTolerantDFT::param_changed(const std::string &param_name)
{
    list<ReplicaId> peers;

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

            RaftSMOutput out;
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
CentralizedFaultTolerantDFT::dump(std::stringstream &ss) const
{
    UPE(rib->uipcp, "Missing implementation");
}

int
CentralizedFaultTolerantDFT::lookup_entry(const std::string &appl_name,
                                          rlm_addr_t &dstaddr,
                                          const rlm_addr_t preferred,
                                          uint32_t cookie) const
{
    UPW(rib->uipcp, "Missing implementation");
    return -1;
}

int
CentralizedFaultTolerantDFT::appl_register(
    const struct rl_kmsg_appl_register *req)
{
    if (client) {
        return client->dft_set(req);
    }
    return raft->dft_set(req);
}

void
CentralizedFaultTolerantDFT::update_address(rlm_addr_t new_addr)
{
    UPE(rib->uipcp, "Missing implementation\n");
}

int
CentralizedFaultTolerantDFT::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    UPW(rib->uipcp, "Missing implementation\n");
    return 0;
}

int
CentralizedFaultTolerantDFT::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    return 0; /* Nothing to do. */
}

int
CentralizedFaultTolerantDFT::neighs_refresh(size_t limit)
{
    return 0; /* Nothing to do. */
}

int
CentralizedFaultTolerantDFT::Client::dft_set(
    const struct rl_kmsg_appl_register *req)
{
    string appl_name(req->appl_name);
    auto m              = make_unique<CDAPMessage>();
    ReplicaId r         = replicas.front();
    rlm_addr_t dst_addr = parent->rib->lookup_node_address(r);
    DFTEntry dft_entry;
    int invoke_id;
    int ret;

    if (dst_addr == RL_ADDR_NULL) {
        UPI(parent->rib->uipcp, "Failed to find address for replica %s\n",
            r.c_str());
        return -1;
    }

    m->m_write(obj_class::dft, obj_name::dft);
    dft_entry.address   = parent->rib->myaddr;
    dft_entry.appl_name = RinaName(appl_name);
    dft_entry.timestamp = time64();

    ret = parent->rib->send_to_dst_addr(std::move(m), dst_addr, &dft_entry,
                                        &invoke_id);
    if (ret) {
        return ret;
    }
    pending[invoke_id] = std::move(PendingReq(appl_name, r));

    UPI(parent->rib->uipcp,
        "Write request '%s <= %lu' issued (invoke_id = %d)\n",
        appl_name.c_str(), parent->rib->myaddr, invoke_id);

    return 0;
}

int
CentralizedFaultTolerantDFT::Replica::process_sm_output(RaftSMOutput out)
{
    // TODO
    for (const auto &msg : out.output_messages) {
        (void)msg;
    }
    for (const auto &cmd : out.timer_commands) {
        (void)cmd;
    }
    return 0;
}

int
CentralizedFaultTolerantDFT::Replica::dft_set(
    const struct rl_kmsg_appl_register *req)
{
    UPW(parent->rib->uipcp, "Missing implementation");
    return -1;
}

void
dft_lib_init()
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
