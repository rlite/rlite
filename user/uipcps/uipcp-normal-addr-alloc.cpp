#include <sstream>
#include <string>
#include <unistd.h>

#include "uipcp-normal.hpp"

using namespace std;

class DistributedAddrAllocator : public AddrAllocator {
    /* Table used to carry on distributed address allocation.
     * It maps (address allocated) --> (requestor address). */
    std::unordered_map<rlm_addr_t, AddrAllocRequest> addr_alloc_table;

public:
    RL_NODEFAULT_NONCOPIABLE(DistributedAddrAllocator);
    DistributedAddrAllocator(uipcp_rib *_ur) : AddrAllocator(_ur) {}
    ~DistributedAddrAllocator() {}

    void dump(std::stringstream &ss) const override;
    rlm_addr_t allocate() override;
    int rib_handler(const CDAPMessage *rm, std::shared_ptr<NeighFlow> const &nf,
                    std::shared_ptr<Neighbor> const &neigh,
                    rlm_addr_t src_addr) override;
    int sync_neigh(NeighFlow *nf, unsigned int limit) const override;
};

void
DistributedAddrAllocator::dump(std::stringstream &ss) const
{
    ss << "Address Allocation Table:" << endl;
    for (const auto &kva : addr_alloc_table) {
        ss << "    Address: " << kva.first
           << ", Requestor: " << kva.second.requestor << endl;
    }

    ss << endl;
}

int
DistributedAddrAllocator::sync_neigh(NeighFlow *nf, unsigned int limit) const
{
    int ret = 0;

    for (auto ati = addr_alloc_table.begin(); ati != addr_alloc_table.end();) {
        AddrAllocEntries l;

        while (l.entries.size() < limit && ati != addr_alloc_table.end()) {
            l.entries.push_back(ati->second);
            ati++;
        }

        ret |= nf->neigh->neigh_sync_obj(nf, true, obj_class::addr_alloc_table,
                                         obj_name::addr_alloc_table, &l);
    }

    return ret;
}

rlm_addr_t
DistributedAddrAllocator::allocate()
{
    rlm_addr_t modulo = addr_alloc_table.size() + 1;
    const int inflate = 2;
    rlm_addr_t addr   = RL_ADDR_NULL;
    int nack_wait_secs =
        rib->get_param_value<int>("address-allocator", "nack-wait-secs");

    if ((modulo << inflate) <= modulo) { /* overflow */
        modulo = ~((rlm_addr_t)0);
        UPD(rib->uipcp, "overflow\n");
    } else {
        modulo <<= inflate;
    }

    srand((unsigned int)rib->myaddr);

    for (;;) {
        /* Randomly pick an address in [0 .. modulo-1]. */
        addr = rand() % modulo;

        /* Discard the address if it is invalid, or it is already (or possibly)
         * in use by us or another IPCP in the DIF. */
        if (!addr || addr == rib->myaddr || addr_alloc_table.count(addr) > 0 ||
            rib->lookup_neighbor_by_address(addr) != string()) {
            continue;
        }

        UPD(rib->uipcp, "Trying with address %lu\n", (unsigned long)addr);
        addr_alloc_table[addr] = AddrAllocRequest(addr, rib->myaddr);

        for (const auto &kvn : rib->neighbors) {
            if (kvn.second->enrollment_complete()) {
                AddrAllocRequest aar;
                CDAPMessage m;
                int ret;

                m.m_create(obj_class::addr_alloc_req,
                           obj_name::addr_alloc_table);
                aar.requestor = rib->myaddr;
                aar.address   = addr;
                ret = kvn.second->mgmt_conn()->send_to_port_id(&m, 0, &aar);
                if (ret) {
                    UPE(rib->uipcp, "Failed to send msg to neighbot [%s]\n",
                        strerror(errno));
                    return 0;
                } else {
                    UPD(rib->uipcp,
                        "Sent address allocation request to neigh %s, "
                        "(addr=%lu,requestor=%lu)\n",
                        kvn.second->ipcp_name.c_str(),
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                }
            }
        }

        rib->unlock();
        /* Wait a bit for possible negative responses. */
        sleep(nack_wait_secs);
        rib->lock();

        /* If the request is still there, then we consider the allocation
         * complete. */
        auto mit = addr_alloc_table.find(addr);
        if (mit != addr_alloc_table.end() &&
            mit->second.requestor == rib->myaddr) {
            addr_alloc_table[addr].pending = false;
            UPD(rib->uipcp, "Address %lu allocated\n", (unsigned long)addr);
            break;
        }
    }

    return addr;
}

int
DistributedAddrAllocator::rib_handler(const CDAPMessage *rm,
                                      std::shared_ptr<NeighFlow> const &nf,
                                      std::shared_ptr<Neighbor> const &neigh,
                                      rlm_addr_t src_addr)
{
    bool create;
    const char *objbuf;
    size_t objlen;

    rm->get_obj_value(objbuf, objlen);
    if (!objbuf) {
        UPE(rib->uipcp, "No object value found\n");
        return 0;
    }

    switch (rm->op_code) {
    case gpb::M_CREATE:
        create = true;
        break;
    case gpb::M_DELETE:
        create = false;
        break;
    default:
        UPE(rib->uipcp, "M_CREATE/M_DELETE expected\n");
        return 0;
    }

    if (rm->obj_class == obj_class::addr_alloc_req) {
        /* This is an address allocation request or a negative
         * address allocation response. */
        bool propagate = false;
        bool cand_neigh_conflict;
        AddrAllocRequest aar(objbuf, objlen);

        /* Lookup the address contained in the request into the allocation
         * table and among the neighbor candidates. Also check if the proposed
         * address conflicts with our own address. */
        auto mit = addr_alloc_table.find(aar.address);
        cand_neigh_conflict =
            aar.address == rib->myaddr ||
            rib->lookup_neighbor_by_address(aar.address) != string();

        switch (rm->op_code) {
        case gpb::M_CREATE:
            if (!cand_neigh_conflict && mit == addr_alloc_table.end()) {
                /* New address allocation request, no conflicts. */
                addr_alloc_table[aar.address] = aar;
                UPD(rib->uipcp,
                    "Address allocation request ok, (addr=%lu,"
                    "requestor=%lu)\n",
                    (long unsigned)aar.address, (long unsigned)aar.requestor);
                propagate = true;

            } else if (cand_neigh_conflict ||
                       mit->second.requestor != aar.requestor) {
                /* New address allocation request, but there is a conflict. */
                std::unique_ptr<CDAPMessage> m = make_unique<CDAPMessage>();
                int ret;

                UPI(rib->uipcp,
                    "Address allocation request conflicts, (addr=%lu,"
                    "requestor=%lu)\n",
                    (long unsigned)aar.address, (long unsigned)aar.requestor);
                m->m_delete(obj_class::addr_alloc_req,
                            obj_name::addr_alloc_table);
                ret = rib->send_to_dst_addr(std::move(m), aar.requestor, &aar);
                if (ret) {
                    UPE(rib->uipcp, "Failed to send message to %lu [%s]\n",
                        (unsigned long)aar.requestor, strerror(errno));
                }
            } else {
                /* We have already seen this request, don't propagate. */
            }
            break;

        case gpb::M_DELETE:
            if (mit != addr_alloc_table.end()) {
                if (mit->second.pending) {
                    /* Negative feedback on a flow allocation request. */
                    addr_alloc_table.erase(aar.address);
                    propagate = true;
                    UPI(rib->uipcp,
                        "Address allocation request deleted, "
                        "(addr=%lu,requestor=%lu)\n",
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                } else {
                    /* Late negative feedback. This is a serious problem
                     * that we don't manage for now. */
                    UPE(rib->uipcp,
                        "Conflict on a committed address! "
                        "Part of the network may be "
                        "unreachable "
                        "(addr=%lu,requestor=%lu)\n",
                        (long unsigned)aar.address,
                        (long unsigned)aar.requestor);
                }
            }
            break;

        default:
            assert(0);
        }

        if (propagate) {
            /* nf can be nullptr for M_DELETE messages */
            rib->neighs_sync_obj_excluding(neigh.get(), create, rm->obj_class,
                                           rm->obj_name, &aar);
        }

    } else if (rm->obj_class == obj_class::addr_alloc_table) {
        /* This is a synchronization operation targeting our
         * address allocation table. */
        AddrAllocEntries aal(objbuf, objlen);
        AddrAllocEntries prop_aal;

        for (const AddrAllocRequest &r : aal.entries) {
            auto mit = addr_alloc_table.find(r.address);

            if (rm->op_code == gpb::M_CREATE) {
                if (mit == addr_alloc_table.end() ||
                    mit->second.requestor != r.requestor) {
                    addr_alloc_table[r.address] = r; /* overwrite */
                    prop_aal.entries.push_back(r);
                    UPD(rib->uipcp,
                        "Address allocation entry created (addr=%lu,"
                        "requestor=%lu)\n",
                        (long unsigned)r.address, (long unsigned)r.requestor);
                }
            } else { /* M_DELETE */
                if (mit != addr_alloc_table.end() &&
                    mit->second.requestor == r.requestor) {
                    addr_alloc_table.erase(r.address);
                    prop_aal.entries.push_back(r);
                    UPD(rib->uipcp,
                        "Address allocation entry deleted (addr=%lu,"
                        "requestor=%lu)\n",
                        (long unsigned)r.address, (long unsigned)r.requestor);
                }
            }
        }

        if (prop_aal.entries.size() > 0) {
            assert(nf);
            rib->neighs_sync_obj_excluding(neigh.get(), create, rm->obj_class,
                                           rm->obj_name, &prop_aal);
        }

    } else {
        UPE(rib->uipcp, "Unexpected object class %s\n", rm->obj_class.c_str());
    }

    return 0;
}

class ManualAddrAllocator : public DistributedAddrAllocator {
public:
    RL_NODEFAULT_NONCOPIABLE(ManualAddrAllocator);
    ManualAddrAllocator(uipcp_rib *_ur) : DistributedAddrAllocator(_ur) {}
    rlm_addr_t allocate() override { return RL_ADDR_NULL; }
};

void
uipcp_rib::addra_lib_init()
{
    available_policies["address-allocator"].insert(
        PolicyBuilder("manual", [](uipcp_rib *rib) {
            rib->addra = make_unique<ManualAddrAllocator>(rib);
        }));
    available_policies["address-allocator"].insert(
        PolicyBuilder("distributed", [](uipcp_rib *rib) {
            rib->addra = make_unique<DistributedAddrAllocator>(rib);
        }));
}
