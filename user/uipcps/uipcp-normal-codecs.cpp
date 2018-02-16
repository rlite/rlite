/*
 * Serialization of RIB objects.
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

#include <iostream>
#include <list>
#include <set>
#include <string>
#include <sstream>

#include "rlite/common.h"
#include "rlite/utils.h"
#include "rlite/cpputils.hpp"

#include "uipcp-normal-codecs.hpp"

#include "BaseRIB.pb.h"
#include "Raft.pb.h"

using namespace std;

static int
ser_common(::google::protobuf::MessageLite &gm, char *buf, int size)
{
    if (gm.ByteSize() > size) {
        PE("User buffer too small [%u/%u]\n", gm.ByteSize(), size);
        return -1;
    }

    gm.SerializeToArray(buf, size);

    return gm.ByteSize();
}

RinaName::RinaName(const std::string &apn_, const std::string &api_,
                   const std::string &aen_, const std::string &aei_)
{
    apn = apn_;
    api = api_;
    aen = aen_;
    aei = aei_;
}

RinaName::RinaName(const struct rina_name *name)
{
    apn = name->apn ? string(name->apn) : string();
    api = name->api ? string(name->api) : string();
    aen = name->aen ? string(name->aen) : string();
    aei = name->aei ? string(name->aei) : string();
}

RinaName::RinaName(const string &str)
{
    rina_components_from_string(str, apn, api, aen, aei);
}

RinaName::RinaName(const char *str)
{
    if (str == nullptr) {
        str = "";
    }
    rina_components_from_string(string(str), apn, api, aen, aei);
}

RinaName::operator std::string() const
{
    return rina_string_from_components(apn, api, aen, aei);
}

bool
RinaName::operator==(const RinaName &other) const
{
    return api == other.api && apn == other.apn && aen == other.aen &&
           aei == other.aei;
}

bool
RinaName::operator!=(const RinaName &other) const
{
    return !(*this == other);
}

int
RinaName::rina_name_fill(struct rina_name *rn)
{
    return ::rina_name_fill(rn, apn.c_str(), api.c_str(), aen.c_str(),
                            aei.c_str());
}

static void
gpb2Property(Property &p, const gpb::Property &gm)
{
    p.name  = gm.name();
    p.value = gm.value();
}

static int
Property2gpb(const Property &p, gpb::Property &gm)
{
    gm.set_name(p.name);
    gm.set_value(p.value);

    return 0;
}

Property::Property(const char *buf, unsigned int size)
{
    gpb::Property gm;

    gm.ParseFromArray(buf, size);

    gpb2Property(*this, gm);
}

int
Property::serialize(char *buf, unsigned int size) const
{
    gpb::Property gm;

    Property2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

static void
gpb2PolicyDescr(PolicyDescr &p, const gpb::PolicyDescr &gm)
{
    p.name      = gm.name();
    p.impl_name = gm.impl_name();
    p.version   = gm.version();

    for (int i = 0; i < gm.parameters_size(); i++) {
        p.parameters.emplace_back();
        gpb2Property(p.parameters.back(), gm.parameters(i));
    }
}

static int
PolicyDescr2gpb(const PolicyDescr &p, gpb::PolicyDescr &gm)
{
    gm.set_name(p.name);
    gm.set_impl_name(p.impl_name);
    gm.set_version(p.version);

    for (const Property &pr : p.parameters) {
        gpb::Property *param;

        param = gm.add_parameters();
        Property2gpb(pr, *param);
    }

    return 0;
}

PolicyDescr::PolicyDescr(const char *buf, unsigned int size)
{
    gpb::PolicyDescr gm;

    gm.ParseFromArray(buf, size);

    gpb2PolicyDescr(*this, gm);
}

int
PolicyDescr::serialize(char *buf, unsigned int size) const
{
    gpb::PolicyDescr gm;

    PolicyDescr2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

AData::AData(const char *buf, unsigned int size)
{
    gpb::AData gm;

    gm.ParseFromArray(buf, size);

    src_addr = gm.src_addr();
    dst_addr = gm.dst_addr();
    cdap     = std::move(
        msg_deser_stateless(gm.cdap_msg().data(), gm.cdap_msg().size()));
}

int
AData::serialize(char *buf, unsigned int size) const
{
    gpb::AData gm;
    char *serbuf = nullptr;
    size_t serlen;
    int ret;

    gm.set_src_addr(src_addr);
    gm.set_dst_addr(dst_addr);
    if (cdap) {
        msg_ser_stateless(cdap.get(), &serbuf, &serlen);
        gm.set_cdap_msg(serbuf, serlen);
    }

    ret = ser_common(gm, buf, size);

    if (serbuf) {
        delete[] serbuf;
    }

    return ret;
}

static void
gpb2AddrAllocRequest(AddrAllocRequest &a, const gpb::AddrAllocRequest &gm)
{
    a.requestor = gm.requestor();
    a.address   = gm.address();
}

static int
AddrAllocRequest2gpb(const AddrAllocRequest &a, gpb::AddrAllocRequest &gm)
{
    gm.set_requestor(a.requestor);
    gm.set_address(a.address);

    return 0;
}

AddrAllocRequest::AddrAllocRequest(const char *buf, unsigned int size)
{
    gpb::AddrAllocRequest gm;

    gm.ParseFromArray(buf, size);

    gpb2AddrAllocRequest(*this, gm);
}

int
AddrAllocRequest::serialize(char *buf, unsigned int size) const
{
    gpb::AddrAllocRequest gm;

    AddrAllocRequest2gpb(*this, gm);

    return ser_common(gm, buf, size);
}

AddrAllocEntries::AddrAllocEntries(const char *buf, unsigned int size)
{
    gpb::AddrAllocEntries gm;

    gm.ParseFromArray(buf, size);

    for (int i = 0; i < gm.entries_size(); i++) {
        entries.emplace_back();
        gpb2AddrAllocRequest(entries.back(), gm.entries(i));
    }
}

int
AddrAllocEntries::serialize(char *buf, unsigned int size) const
{
    gpb::AddrAllocEntries gm;

    for (const AddrAllocRequest &r : entries) {
        gpb::AddrAllocRequest *gr;
        int ret;

        gr  = gm.add_entries();
        ret = AddrAllocRequest2gpb(r, *gr);
        if (ret) {
            return ret;
        }
    }

    return ser_common(gm, buf, size);
}

RaftRequestVote::RaftRequestVote(const char *buf, unsigned int size)
{
    gpb::RaftRequestVote gm;

    gm.ParseFromArray(buf, size);

    term           = gm.term();
    candidate_id   = gm.candidate_id();
    last_log_index = gm.last_log_index();
    last_log_term  = gm.last_log_term();
}

int
RaftRequestVote::serialize(char *buf, unsigned int size) const
{
    gpb::RaftRequestVote gm;

    gm.set_term(term);
    gm.set_candidate_id(candidate_id);
    gm.set_last_log_index(last_log_index);
    gm.set_last_log_term(last_log_term);

    return ser_common(gm, buf, size);
}

RaftRequestVoteResp::RaftRequestVoteResp(const char *buf, unsigned int size)
{
    gpb::RaftRequestVoteResp gm;

    gm.ParseFromArray(buf, size);

    term         = gm.term();
    vote_granted = gm.vote_granted();
}

int
RaftRequestVoteResp::serialize(char *buf, unsigned int size) const
{
    gpb::RaftRequestVoteResp gm;

    gm.set_term(term);
    gm.set_vote_granted(vote_granted);

    return ser_common(gm, buf, size);
}

RaftAppendEntries::RaftAppendEntries(const char *buf, unsigned int size)
{
    gpb::RaftAppendEntries gm;

    gm.ParseFromArray(buf, size);

    term           = gm.term();
    leader_id      = gm.leader_id();
    leader_commit  = gm.leader_commit();
    prev_log_index = gm.prev_log_index();
    prev_log_term  = gm.prev_log_term();

    for (int i = 0; i < gm.entries_size(); i++) {
        size_t bufsize = gm.entries(i).buffer().size();
        auto bufcopy   = std::unique_ptr<char[]>(new char[bufsize]);
        memcpy(bufcopy.get(), gm.entries(i).buffer().data(), bufsize);
        entries.push_back(
            std::make_pair(gm.entries(i).term(), std::move(bufcopy)));
        EntrySize = bufsize;
    }
}

int
RaftAppendEntries::serialize(char *buf, unsigned int size) const
{
    gpb::RaftAppendEntries gm;

    gm.set_term(term);
    gm.set_leader_id(leader_id);
    gm.set_leader_commit(leader_commit);
    gm.set_prev_log_index(prev_log_index);
    gm.set_prev_log_term(prev_log_term);

    assert(EntrySize != 0);
    for (const auto &p : entries) {
        gpb::RaftLogEntry *ge;

        ge = gm.add_entries();
        ge->set_term(p.first);
        ge->set_buffer(p.second.get(), EntrySize);
    }

    return ser_common(gm, buf, size);
}

RaftAppendEntriesResp::RaftAppendEntriesResp(const char *buf, unsigned int size)
{
    gpb::RaftAppendEntriesResp gm;

    gm.ParseFromArray(buf, size);

    term        = gm.term();
    follower_id = gm.follower_id();
    log_index   = gm.log_index();
    success     = gm.success();
}

int
RaftAppendEntriesResp::serialize(char *buf, unsigned int size) const
{
    gpb::RaftAppendEntriesResp gm;

    gm.set_term(term);
    gm.set_follower_id(follower_id);
    gm.set_log_index(log_index);
    gm.set_success(success);

    return ser_common(gm, buf, size);
}

gpb::APName *
RinaName2gpb(const RinaName &name)
{
    gpb::APName *gan = new gpb::APName();

    gan->set_ap_name(name.apn);
    gan->set_ap_instance(name.api);
    gan->set_ae_name(name.aen);
    gan->set_ae_instance(name.aei);

    return gan;
}

std::string
gpb2string(const gpb::APName &gname)
{
    return rina_string_from_components(gname.ap_name(), gname.ap_instance(),
                                       gname.ae_name(), gname.ae_instance());
}
