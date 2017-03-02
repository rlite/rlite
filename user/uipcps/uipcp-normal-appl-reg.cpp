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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */


#include <ctime>

#include "uipcp-normal.hpp"

using namespace std;


static uint64_t time64()
{
    struct timespec tv;

    if (clock_gettime(CLOCK_MONOTONIC, &tv)) {
        perror("clock_gettime() failed");
        tv.tv_sec = 0;
        tv.tv_nsec = 0;
    }

    return (tv.tv_sec << 32) | (tv.tv_nsec & ((1L << 32) - 1L));
}

int
dft::lookup_entry(const std::string& appl_name, rlm_addr_t& dstaddr) const
{
    map< string, DFTEntry >::const_iterator mit
         = dft_table.find(appl_name);

    if (mit == dft_table.end()) {
        return -1;
    }

    dstaddr = mit->second.address;

    return 0;
}

int
dft::set_entry(const std::string& appl_name, rlm_addr_t remote_addr)
{
    DFTEntry entry;

    entry.address = remote_addr;
    entry.appl_name = RinaName(appl_name);
    entry.timestamp = time64();

    dft_table[appl_name] = entry;

    UPD(rib->uipcp, "[uipcp %u] setting DFT entry '%s' --> %llu\n",
        rib->uipcp->id, appl_name.c_str(), (long long unsigned)entry.address);

    return 0;
}

int
dft::appl_register(const struct rl_kmsg_appl_register *req)
{
    map< string, DFTEntry >::iterator mit;
    string appl_name(req->appl_name);
    struct uipcp *uipcp = rib->uipcp;
    bool create = true;
    DFTSlice dft_slice;
    DFTEntry dft_entry;

    dft_entry.address = rib->myaddr;
    dft_entry.appl_name = RinaName(appl_name);
    dft_entry.timestamp = time64();
    dft_entry.local = true;

    mit = dft_table.find(appl_name);

    if (req->reg) {
        if (mit != dft_table.end()) {
            UPE(uipcp, "Application %s already registered on uipcp with address "
                    "[%llu], my address being [%llu]\n", appl_name.c_str(),
                    (long long unsigned)mit->second.address,
                    (long long unsigned)rib->myaddr);
            return uipcp_appl_register_resp(uipcp, uipcp->id,
                                            RLITE_ERR, req);
        }

        /* Insert the object into the RIB. */
        dft_table.insert(make_pair(appl_name, dft_entry));

    } else {
        if (mit == dft_table.end()) {
            UPE(uipcp, "Application %s was not registered here\n",
                appl_name.c_str());
            return 0;
        }

        /* Remove the object from the RIB. */
        dft_table.erase(mit);
        create = false;
    }

    dft_slice.entries.push_back(dft_entry);

    UPD(uipcp, "Application %s %sregistered %s uipcp %d\n",
            appl_name.c_str(), req->reg ? "" : "un", req->reg ? "to" : "from",
            uipcp->id);

    rib->neighs_sync_obj_all(create, obj_class::dft, obj_name::dft, &dft_slice);

    if (req->reg) {
        /* Registration requires a response, while unregistrations doesn't. */
        return uipcp_appl_register_resp(uipcp, uipcp->id,
                                        RLITE_SUCC, req);
    }

    return 0;
}

int
uipcp_rib::dft_handler(const CDAPMessage *rm, NeighFlow *nf)
{
    return dft.rib_handler(rm, nf);
}

int
dft::rib_handler(const CDAPMessage *rm, NeighFlow *nf)
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
    DFTSlice prop_dft;

    for (list<DFTEntry>::iterator e = dft_slice.entries.begin();
                                e != dft_slice.entries.end(); e++) {
        string key = static_cast<string>(e->appl_name);
        map< string, DFTEntry >::iterator mit = dft_table.find(key);

        if (add) {
            if (mit == dft_table.end() || e->timestamp > mit->second.timestamp) {
                dft_table[key] = *e;
                prop_dft.entries.push_back(*e);
                UPD(uipcp, "DFT entry %s %s remotely\n", key.c_str(),
                        (mit != dft_table.end() ? "updated" : "added"));
            }

        } else {
            if (mit == dft_table.end()) {
                UPI(uipcp, "DFT entry does not exist\n");
            } else {
                dft_table.erase(mit);
                prop_dft.entries.push_back(*e);
                UPD(uipcp, "DFT entry %s removed remotely\n", key.c_str());
            }

        }
    }

    if (prop_dft.entries.size()) {
        /* Propagate the DFT entries update to the other neighbors,
         * except for the one. */
        rib->neighs_sync_obj_excluding(nf->neigh, add, obj_class::dft,
                              obj_name::dft, &prop_dft);

    }

    return 0;
}

void
dft::update_address(rlm_addr_t new_addr)
{
    map< string, DFTEntry >::iterator mit;
    DFTSlice prop_dft;

    /* Update all the DFT entries corresponding to application that are
     * registered within us. */
    for (mit = dft_table.begin(); mit != dft_table.end(); mit ++) {
        if (mit->second.address == rib->myaddr) {
            mit->second.address = new_addr;
            mit->second.timestamp = time64();
            prop_dft.entries.push_back(mit->second);
            UPD(rib->uipcp, "Updated address for DFT entry %s\n",
                mit->first.c_str());
        }
    }

    /* Disseminate the update. */
    if (prop_dft.entries.size()) {
        rib->neighs_sync_obj_all(true, obj_class::dft, obj_name::dft, &prop_dft);
    }
}

void
dft::dump(stringstream &ss) const
{
    ss << "Directory Forwarding Table:" << endl;
    for (map<string, DFTEntry>::const_iterator
            mit = dft_table.begin(); mit != dft_table.end(); mit++) {
        const DFTEntry& entry = mit->second;

        ss << "    Application: " << static_cast<string>(entry.appl_name)
            << ", Address: " << entry.address << ", Timestamp: "
                << entry.timestamp << endl;
    }

    ss << endl;
}
