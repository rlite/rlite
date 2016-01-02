#include <ctime>

#include "uipcp-rib.hpp"

using namespace std;


static uint64_t time64()
{
    struct timespec tv;

    if (clock_gettime(CLOCK_MONOTONIC, &tv)) {
        PE("clock_gettime() failed\n");
        tv.tv_sec = 0;
        tv.tv_nsec = 0;
    }

    return (tv.tv_sec << 32) | (tv.tv_nsec & ((1L << 32) - 1L));
}

uint64_t
uipcp_rib::dft_lookup(const RinaName& appl_name) const
{
    map< string, DFTEntry >::const_iterator mit
         = dft.find(static_cast<string>(appl_name));

    if (mit == dft.end()) {
        return 0;
    }

    return mit->second.address;
}

int
uipcp_rib::dft_set(const RinaName& appl_name, uint64_t remote_addr)
{
    string key = static_cast<string>(appl_name);
    DFTEntry entry;

    entry.address = remote_addr;
    entry.appl_name = appl_name;
    entry.timestamp = time64();

    dft[key] = entry;

    PD("[uipcp %u] setting DFT entry '%s' --> %llu\n", uipcp->ipcp_id,
       key.c_str(), (long long unsigned)entry.address);

    return 0;
}

int
uipcp_rib::application_register(int reg, const RinaName& appl_name)
{
    map< string, DFTEntry >::iterator mit;
    uint64_t local_addr;
    string name_str;
    int ret;
    bool create = true;
    DFTSlice dft_slice;
    DFTEntry dft_entry;

    ret = rlite_lookup_ipcp_addr_by_id(&uipcp->appl.loop,
                                          uipcp->ipcp_id,
                                          &local_addr);
    assert(!ret);

    dft_entry.address = local_addr;
    dft_entry.appl_name = appl_name;
    dft_entry.timestamp = time64();
    name_str = static_cast<string>(dft_entry.appl_name);

    mit = dft.find(name_str);

    if (reg) {
        if (mit != dft.end()) {
            PE("Application %s already registered on uipcp with address "
                    "[%llu], my address being [%llu]\n", name_str.c_str(),
                    (long long unsigned)mit->second.address,
                    (long long unsigned)local_addr);
            return -1;
        }

        /* Insert the object into the RIB. */
        dft.insert(make_pair(name_str, dft_entry));

    } else {
        if (mit == dft.end()) {
            PE("Application %s was not registered here\n",
                name_str.c_str());
            return -1;
        }

        /* Remove the object from the RIB. */
        dft.erase(mit);
        create = false;
    }

    dft_slice.entries.push_back(dft_entry);

    PD("Application %s %sregistered %s uipcp %d\n",
            name_str.c_str(), reg ? "" : "un", reg ? "to" : "from",
            uipcp->ipcp_id);

    remote_sync_all(create, obj_class::dft, obj_name::dft, &dft_slice);

    return 0;
}

int
uipcp_rib::dft_handler(const CDAPMessage *rm, Neighbor *neigh)
{
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

    DFTSlice dft_slice(objbuf, objlen);
    DFTSlice prop_dft;

    for (list<DFTEntry>::iterator e = dft_slice.entries.begin();
                                e != dft_slice.entries.end(); e++) {
        string key = static_cast<string>(e->appl_name);
        map< string, DFTEntry >::iterator mit = dft.find(key);

        if (add) {
            if (mit == dft.end() || e->timestamp > mit->second.timestamp) {
                dft[key] = *e;
                prop_dft.entries.push_back(*e);
                PD("DFT entry %s %s remotely\n", key.c_str(),
                        (mit != dft.end() ? "updated" : "added"));
            }

        } else {
            if (mit == dft.end()) {
                PI("DFT entry does not exist\n");
            } else {
                dft.erase(mit);
                prop_dft.entries.push_back(*e);
                PD("DFT entry %s removed remotely\n", key.c_str());
            }

        }
    }

    if (prop_dft.entries.size()) {
        /* Propagate the DFT entries update to the other neighbors,
         * except for the one. */
        remote_sync_excluding(neigh, add, obj_class::dft,
                              obj_name::dft, &prop_dft);

    }

    return 0;
}

