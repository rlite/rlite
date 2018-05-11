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
#include <chrono>

#include "uipcp-normal.hpp"
#include "uipcp-normal-ceft.hpp"
#include "Raft.pb.h"

using namespace std;

namespace Uipcps {

class FullyReplicatedDFT : public DFT {
    /* Directory Forwarding Table, mapping application name (std::string)
     * to a set of nodes that registered that name. All nodes are considered
     * equivalent. */
    std::multimap<std::string, std::unique_ptr<gpb::DFTEntry>> dft_table;
    uint64_t seqnum_next = 1;

public:
    RL_NODEFAULT_NONCOPIABLE(FullyReplicatedDFT);
    FullyReplicatedDFT(UipcpRib *_ur) : DFT(_ur) {}
    ~FullyReplicatedDFT() {}

    void dump(std::stringstream &ss) const override;

    int lookup_req(const std::string &appl_name, std::string *dst_node,
                   const std::string &preferred, uint32_t cookie) override;
    int appl_register(const struct rl_kmsg_appl_register *req) override;
    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh,
                    rlm_addr_t src_addr) override;
    int sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                   unsigned int limit) const override;
    int neighs_refresh(size_t limit) override;

    /* Helper function shared with CentralizedFaultTolerantDFT::Replica. */
    void mod_table(const gpb::DFTEntry &e, bool add, gpb::DFTSlice *added,
                   gpb::DFTSlice *removed);
};

int
FullyReplicatedDFT::lookup_req(const std::string &appl_name,
                               std::string *dst_node,
                               const std::string &preferred, uint32_t cookie)
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
        if (!preferred.empty()) {
            /* Only accept the preferred address. */

            for (; mit != range.second; mit++) {
                if (mit->second->ipcp_name() == preferred) {
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

    *dst_node = mit->second->ipcp_name();

    return 0;
}

int
FullyReplicatedDFT::appl_register(const struct rl_kmsg_appl_register *req)
{
    auto dft_entry = make_unique<gpb::DFTEntry>();
    multimap<string, std::unique_ptr<gpb::DFTEntry>>::iterator mit;
    string appl_name(req->appl_name);
    struct uipcp *uipcp = rib->uipcp;
    gpb::DFTSlice dft_slice;

    dft_entry->set_ipcp_name(rib->myname);
    dft_entry->set_allocated_appl_name(apname2gpb(appl_name));
    dft_entry->set_seqnum(seqnum_next++);

    /* Get all the entries for 'appl_name', and see if there
     * is an entry associated to this uipcp. */
    auto range = dft_table.equal_range(appl_name);
    for (mit = range.first; mit != range.second; mit++) {
        if (mit->second->ipcp_name() == rib->myname) {
            break;
        }
    }

    *dft_slice.add_entries() = *dft_entry;

    if (req->reg) {
        if (mit != range.second) { /* local collision */
            UPE(uipcp, "Application %s already registered on this uipcp\n",
                appl_name.c_str());
            return uipcp_appl_register_resp(uipcp, RLITE_ERR, req->hdr.event_id,
                                            req->appl_name);
        }

        if (req->reg) {
            /* Registration requires a response, while unregistrations doesn't.
             * Respond to the client before committing to the RIB, because the
             * response may fail. */
            int ret = uipcp_appl_register_resp(
                uipcp, RLITE_SUCC, req->hdr.event_id, req->appl_name);
            if (ret) {
                return ret;
            }
        }

        /* Insert the object into the RIB. */

        dft_table.insert(make_pair(appl_name, std::move(dft_entry)));
    } else {
        if (mit == range.second) {
            UPE(uipcp, "Application %s was not registered here\n",
                appl_name.c_str());
            return 0;
        }

        /* Remove from the RIB. */
        dft_table.erase(mit);
    }

    UPD(uipcp, "Application %s %sregistered\n", appl_name.c_str(),
        req->reg ? "" : "un");

    rib->neighs_sync_obj_all(req->reg != 0, ObjClass, TableName, &dft_slice);

    return 0;
}

/* Tries ot add or remove an entry 'e' from the DFT multimap. If not nullptr,
 * the entries added and/or removed are appended to 'added' and 'removed'
 * respectively. */
void
FullyReplicatedDFT::mod_table(const gpb::DFTEntry &e, bool add,
                              gpb::DFTSlice *added, gpb::DFTSlice *removed)
{
    string key = apname2string(e.appl_name());
    auto range = dft_table.equal_range(key);
    multimap<string, std::unique_ptr<gpb::DFTEntry>>::iterator mit;
    struct uipcp *uipcp = rib->uipcp;

    for (mit = range.first; mit != range.second; mit++) {
        if (mit->second->ipcp_name() == e.ipcp_name()) {
            break;
        }
    }

    if (add) {
        bool collision = (mit != range.second);

        if (!collision || e.seqnum() > mit->second->seqnum()) {
            if (collision) {
                /* Remove the collided entry. */
                if (removed) {
                    *removed->add_entries() = *mit->second;
                }
                dft_table.erase(mit);
            }
            dft_table.insert(make_pair(key, make_unique<gpb::DFTEntry>(e)));
            if (added) {
                *added->add_entries() = e;
            }
            UPD(uipcp, "DFT entry %s --> %s %s remotely\n", key.c_str(),
                e.ipcp_name().c_str(), (collision ? "updated" : "added"));
        }

    } else {
        if (mit == range.second) {
            UPI(uipcp, "DFT entry does not exist\n");
        } else {
            dft_table.erase(mit);
            if (removed) {
                *removed->add_entries() = e;
            }
            UPD(uipcp, "DFT entry %s --> %s removed remotely\n", key.c_str(),
                e.ipcp_name().c_str());
        }
    }
}

int
FullyReplicatedDFT::rib_handler(const CDAPMessage *rm,
                                std::shared_ptr<NeighFlow> const &nf,
                                std::shared_ptr<Neighbor> const &neigh,
                                rlm_addr_t src_addr)
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

    gpb::DFTSlice dft_slice;
    gpb::DFTSlice prop_dft_add, prop_dft_del;

    dft_slice.ParseFromArray(objbuf, objlen);
    for (const gpb::DFTEntry &e : dft_slice.entries()) {
        mod_table(e, add, &prop_dft_add, &prop_dft_del);
    }

    /* Propagate the DFT entries update to the other neighbors,
     * except for who told us. */
    if (prop_dft_add.entries_size() > 0) {
        rib->neighs_sync_obj_excluding(neigh, true, ObjClass, TableName,
                                       &prop_dft_add);
    }

    if (prop_dft_del.entries_size() > 0) {
        rib->neighs_sync_obj_excluding(neigh, false, ObjClass, TableName,
                                       &prop_dft_del);
    }

    return 0;
}

void
FullyReplicatedDFT::dump(stringstream &ss) const
{
    ss << "Directory Forwarding Table:" << endl;
    for (const auto &kve : dft_table) {
        const auto &entry = kve.second;

        ss << "    Application: " << apname2string(entry->appl_name())
           << ", Remote node: " << entry->ipcp_name()
           << ", Seqnum: " << entry->seqnum() << endl;
    }

    ss << endl;
}

int
FullyReplicatedDFT::sync_neigh(const std::shared_ptr<NeighFlow> &nf,
                               unsigned int limit) const
{
    int ret = 0;

    for (auto eit = dft_table.begin(); eit != dft_table.end();) {
        gpb::DFTSlice dft_slice;

        while (dft_slice.entries_size() < static_cast<int>(limit) &&
               eit != dft_table.end()) {
            *dft_slice.add_entries() = *eit->second;
            eit++;
        }

        ret |= nf->sync_obj(true, ObjClass, TableName, &dft_slice);
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
        gpb::DFTSlice dft_slice;

        while (dft_slice.entries_size() < static_cast<int>(limit) &&
               eit != dft_table.end()) {
            if (eit->second->ipcp_name() == rib->myname) { /* local */
                *dft_slice.add_entries() = *eit->second;
            }
            eit++;
        }

        if (dft_slice.entries_size()) {
            ret |=
                rib->neighs_sync_obj_all(true, ObjClass, TableName, &dft_slice);
        }
    }

    return ret;
}

class CentralizedFaultTolerantDFT : public DFT {
    /* An instance of this class can be a state machine replica or it can just
     * be a client that will redirect requests to one of the replicas. */

    /* In case of state machine replica, a pointer to a Raft state
     * machine. */
    class Replica : public CeftReplica {
        /* The structure of a DFT command (i.e. a log entry for the Raft SM). */
        struct Command {
            char appl_name[32];
            char ipcp_name[31];
            uint8_t opcode;
            static constexpr uint8_t OpcodeSet = 1;
            static constexpr uint8_t OpcodeDel = 2;
        } __attribute__((packed));
        static_assert(sizeof(Command) == sizeof(Command::ipcp_name) +
                                             sizeof(Command::appl_name) +
                                             sizeof(Command::opcode),
                      "Invalid memory layout for class Replica::Command");

        /* State machine implementation. Just reuse the implementation of
         * a fully replicated DFT. */
        std::unique_ptr<FullyReplicatedDFT> impl;

        uint64_t seqnum_next = 1;

    public:
        Replica(CentralizedFaultTolerantDFT *dft)
            : CeftReplica(dft->rib, std::string("ceft-dft-") + dft->rib->myname,
                          dft->rib->myname,
                          std::string("/tmp/ceft-dft-") +
                              std::to_string(dft->rib->uipcp->id) +
                              std::string("-") + dft->rib->myname,
                          sizeof(Command), DFT::TableName),
              impl(make_unique<FullyReplicatedDFT>(dft->rib)){};
        int apply(const char *const serbuf) override;
        int process_rib_msg(
            const CDAPMessage *rm, rlm_addr_t src_addr,
            std::vector<std::unique_ptr<char[]>> *commands) override;
        int lookup_req(const std::string &appl_name, std::string *dst_node,
                       const std::string &preferred, uint32_t cookie)
        {
            return impl->lookup_req(appl_name, dst_node, preferred, cookie);
        }
        void dump(std::stringstream &ss) const { impl->dump(ss); };
    };
    std::unique_ptr<Replica> raft;

    /* In case of client, a pointer to client-side data structures. */
    class Client : public CeftClient {
        uint64_t seqnum_next = 1;

        struct PendingReq : public CeftClient::PendingReq {
            std::string appl_name;
            uint32_t kevent_id;
            PendingReq() = default;
            PendingReq(gpb::OpCode op_code, const std::string &appl_name,
                       uint32_t kevent_id)
                : CeftClient::PendingReq(op_code),
                  appl_name(appl_name),
                  kevent_id(kevent_id)
            {
            }
            std::unique_ptr<CeftClient::PendingReq> clone() const override
            {
                return make_unique<PendingReq>(*this);
            }
        };

    public:
        Client(CentralizedFaultTolerantDFT *dft,
               std::list<raft::ReplicaId> names)
            : CeftClient(dft->rib, std::move(names))
        {
        }
        int process_rib_msg(const CDAPMessage *rm,
                            CeftClient::PendingReq *const bpr,
                            rlm_addr_t src_addr) override;
        int lookup_req(const std::string &appl_name, std::string *dst_node,
                       const std::string &preferred, uint32_t cookie);
        int appl_register(const struct rl_kmsg_appl_register *req);
    };
    std::unique_ptr<Client> client;

public:
    RL_NODEFAULT_NONCOPIABLE(CentralizedFaultTolerantDFT);
    CentralizedFaultTolerantDFT(UipcpRib *_ur) : DFT(_ur) {}
    int reconfigure() override;
    void dump(std::stringstream &ss) const override
    {
        if (raft) {
            raft->dump(ss);
        } else {
            ss << "Directory Forwarding Table: not available locally" << endl
               << endl;
        }
    }

    int lookup_req(const std::string &appl_name, std::string *dst_node,
                   const std::string &preferred, uint32_t cookie) override
    {
        if (raft) {
            return raft->lookup_req(appl_name, dst_node, preferred, cookie);
        }
        return client->lookup_req(appl_name, dst_node, preferred, cookie);
    }
    int appl_register(const struct rl_kmsg_appl_register *req) override
    {
        if (raft) {
            /* We may be the leader or a follower, but here we can behave as as
             * any client to improve code reuse. We also set the leader, since
             * we know it.
             */
            client->set_leader_id(raft->leader_name());
        }
        return client->appl_register(req);
    }
    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh, rlm_addr_t src_addr)
    {
        if (!raft || (rm->obj_class == ObjClass && rm->is_response())) {
            /* We may be a replica (raft != nullptr), but if this is a response
             * to a request done by us with the role of simple clients we
             * forward it to the client handler. */
            return client->rib_handler(rm, nf, neigh, src_addr);
        }

        return raft->rib_handler(rm, nf, neigh, src_addr);
    }
};

int
CentralizedFaultTolerantDFT::reconfigure()
{
    list<raft::ReplicaId> peers;
    string replicas;

    replicas = rib->get_param_value<std::string>(DFT::Prefix, "replicas");
    if (replicas.empty()) {
        UPW(rib->uipcp, "replicas param not configured\n");
    } else {
        UPD(rib->uipcp, "replicas = %s\n", replicas.c_str());
    }
    peers = strsplit(replicas, ',');

    /* Create the client anyway. */
    client = make_unique<Client>(this, peers);
    UPI(rib->uipcp, "Client initialized\n");

    /* See if I'm also one of the replicas. */
    auto it = peers.begin();
    for (; it != peers.end(); it++) {
        if (*it == rib->myname) {
            /* I'm one of the replicas. Create a Raft state machine and
             * initialize it. */
            raft = make_unique<Replica>(this);
            peers.erase(it); /* remove myself */

            return raft->init(peers);
        }
    }

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::lookup_req(const std::string &appl_name,
                                                std::string *dst_node,
                                                const std::string &preferred,
                                                uint32_t cookie)
{
    /* Prepare an M_READ for a read operation. */
    auto m = make_unique<CDAPMessage>();

    m->m_read(ObjClass, TableName + "/" + appl_name);

    auto pr = make_unique<PendingReq>(m->op_code, appl_name, 0);
    int ret = send_to_replicas(std::move(m), std::move(pr), OpSemantics::Get);
    if (ret) {
        return ret;
    }

    UPI(rib->uipcp, "Read request for '%s' issued\n", appl_name.c_str());

    /* Inform the caller that we issued the request, but the
     * response will come later. */
    *dst_node = std::string();

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::appl_register(
    const struct rl_kmsg_appl_register *req)
{
    /* Prepare an M_WRITE or M_DELETE message for a write/delete operation. */
    string appl_name(req->appl_name);
    auto m = make_unique<CDAPMessage>();
    int ret;

    if (req->reg) {
        m->m_write(ObjClass, TableName);
    } else {
        m->m_delete(ObjClass, TableName);
    }

    auto pr = make_unique<PendingReq>(m->op_code, appl_name, req->hdr.event_id);
    gpb::DFTEntry dft_entry;

    dft_entry.set_ipcp_name(rib->myname);
    dft_entry.set_allocated_appl_name(apname2gpb(appl_name));
    dft_entry.set_seqnum(seqnum_next++);
    ret = rib->obj_serialize(m.get(), &dft_entry);
    if (ret) {
        return ret;
    }

    ret = send_to_replicas(std::move(m), std::move(pr), OpSemantics::Put);
    if (ret) {
        return ret;
    }

    if (req->reg) {
        UPD(rib->uipcp, "Write request '%s <= %llu' issued\n",
            appl_name.c_str(), (long long unsigned)rib->myaddr);
    } else {
        UPD(rib->uipcp, "Write request 'delete %s' issued\n",
            appl_name.c_str());
    }

    return 0;
}

int
CentralizedFaultTolerantDFT::Client::process_rib_msg(
    const CDAPMessage *rm, CeftClient::PendingReq *const bpr,
    rlm_addr_t src_addr)
{
    PendingReq const *pr = dynamic_cast<PendingReq *>(bpr);
    struct uipcp *uipcp  = rib->uipcp;

    switch (rm->op_code) {
    case gpb::M_WRITE_R:
    case gpb::M_DELETE_R:
        if (rm->op_code == gpb::M_WRITE_R) {
            /* Registrations need a response. */
            uipcp_appl_register_resp(uipcp, rm->result ? RLITE_ERR : RLITE_SUCC,
                                     pr->kevent_id, pr->appl_name.c_str());
        }
        UPD(uipcp, "Application %s %sregistration %s\n", pr->appl_name.c_str(),
            rm->op_code == gpb::M_WRITE_R ? "" : "un",
            rm->result ? "failed" : "was successful");
        break;
    case gpb::M_READ_R: {
        std::string remote_node;

        if (rm->result) {
            UPD(uipcp, "Lookup of name '%s' failed remotely [%s]\n",
                pr->appl_name.c_str(), rm->result_reason.c_str());
        } else {
            rm->get_obj_value(remote_node);
            UPD(uipcp, "Lookup of name '%s' resolved to node '%s'\n",
                pr->appl_name.c_str(), remote_node.c_str());
        }
        rib->dft_lookup_resolved(pr->appl_name, remote_node);
        break;
    }
    default:
        assert(false);
    }

    return 0;
}

/* Apply a command to the replicated state machine. We just pass the command
 * to the same multimap implementation used by the fully replicated DFT. */
int
CentralizedFaultTolerantDFT::Replica::apply(const char *const serbuf)
{
    auto c = reinterpret_cast<const Command *const>(serbuf);
    gpb::DFTEntry e;

    e.set_ipcp_name(c->ipcp_name);
    e.set_allocated_appl_name(apname2gpb(c->appl_name));
    e.set_seqnum(seqnum_next++);
    assert(c->opcode == Command::OpcodeSet || c->opcode == Command::OpcodeDel);
    impl->mod_table(e, c->opcode == Command::OpcodeSet, nullptr, nullptr);

    return 0;
}

int
CentralizedFaultTolerantDFT::Replica::process_rib_msg(
    const CDAPMessage *rm, rlm_addr_t src_addr,
    std::vector<std::unique_ptr<char[]>> *commands)
{
    struct uipcp *uipcp = rib->uipcp;
    const char *objbuf  = nullptr;
    size_t objlen       = 0;

    if (rm->obj_class != ObjClass) {
        UPE(uipcp, "Unexpected object class '%s'\n", rm->obj_class.c_str());
        return 0;
    }

    /* We expect an obj_value if this is not a DFT read request. */
    if (rm->op_code != gpb::M_READ) {
        rm->get_obj_value(objbuf, objlen);
        if (!objbuf) {
            UPE(uipcp, "No object value found\n");
            return 0;
        }
    }

    if (!leader() && rm->op_code != gpb::M_READ) {
        /* We are not the leader and this is not a read request. We
         * need to deny the request to preserve consistency. */
        UPD(uipcp, "Ignoring request, let the leader answer\n");
        return 0;
    }

    /* Either we are the leader (so we can go ahead and serve the request),
     * or this is a read request that we can serve because it's ok to be
     * eventually consistent. */

    if (rm->op_code == gpb::M_WRITE || rm->op_code == gpb::M_DELETE) {
        /* We received an M_WRITE or M_DELETE as sent by
         * Client::appl_register(). We are the leader. Let's submit the
         * request to the Raft state machine. */
        gpb::DFTEntry dft_entry;
        string appl_name;
        auto cbuf  = std::unique_ptr<char[]>(new char[sizeof(Command)]);
        Command *c = reinterpret_cast<Command *>(cbuf.get());

        dft_entry.ParseFromArray(objbuf, objlen);
        appl_name = apname2string(dft_entry.appl_name());
        /* Fill in the command struct (already serialized). */
        strncpy(c->ipcp_name, dft_entry.ipcp_name().c_str(),
                sizeof(c->ipcp_name));
        strncpy(c->appl_name, appl_name.c_str(), sizeof(c->appl_name));
        c->opcode = rm->op_code == gpb::M_WRITE ? Command::OpcodeSet
                                                : Command::OpcodeDel;

        commands->push_back(std::move(cbuf));
    } else if (rm->op_code == gpb::M_READ) {
        /* We received an an M_READ sent by Client::lookup_req().
         * Recover the application name, look it up in the DFT and
         * reply. */
        auto m = make_unique<CDAPMessage>();
        std::string remote_node;
        string appl_name;
        int ret;

        appl_name = rm->obj_name.substr(rm->obj_name.rfind("/") + 1);
        ret       = impl->lookup_req(appl_name, &remote_node,
                               /*preferred=*/std::string(), /*cookie=*/0);
        m->m_read_r(rm->obj_class, rm->obj_name, /*obj_inst=*/0,
                    /*result=*/ret ? -1 : 0,
                    /*result_reason=*/ret ? "No match found" : string());
        m->invoke_id = rm->invoke_id;
        m->set_obj_value(remote_node);
        rib->send_to_dst_addr(std::move(m), src_addr);
    } else {
        UPE(uipcp, "M_WRITE(dft) or M_DELETE(dft) expected\n");
        return 0;
    }

    return 0;
}

void
UipcpRib::dft_lib_init()
{
    available_policies[DFT::Prefix].insert(PolicyBuilder(
        "fully-replicated",
        [](UipcpRib *rib) { rib->dft = make_unique<FullyReplicatedDFT>(rib); },
        {DFT::TableName}));
    available_policies[DFT::Prefix].insert(PolicyBuilder(
        "centralized-fault-tolerant",
        [](UipcpRib *rib) {
            rib->dft = make_unique<CentralizedFaultTolerantDFT>(rib);
        },
        {DFT::TableName}));
}

} // namespace Uipcps
