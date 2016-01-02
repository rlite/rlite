#ifndef __UIPCP_CODECS_H__
#define __UIPCP_CODECS_H__

#include <stdint.h>
#include <list>
#include <string>

#include "rinalite/rinalite-common.h"


struct UipcpObject {
    virtual int serialize(char *buf, unsigned int size) const = 0;
    virtual ~UipcpObject() { }
};

struct EnrollmentInfo : public UipcpObject {
    uint64_t address;
    std::list< std::string > lower_difs;
    bool start_early;

    EnrollmentInfo() : address(0), start_early(false) { }
    EnrollmentInfo(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct RinaName {
    std::string apn;
    std::string api;
    std::string aen;
    std::string aei;

    RinaName() { }
    RinaName(const std::string& apn_,
             const std::string& api_,
             const std::string& aen_,
             const std::string& aei_);
    RinaName(const struct rina_name *name);
    operator std::string() const;
    bool operator==(const RinaName& other);
    bool operator!=(const RinaName& other);
};

struct DFTEntry : public UipcpObject {
    RinaName appl_name;
    uint64_t address;
    uint64_t timestamp;

    DFTEntry() : address(0), timestamp(0) { }
    DFTEntry(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct DFTSlice : public UipcpObject {
    std::list<DFTEntry> entries;

    DFTSlice() { }
    DFTSlice(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct NeighborCandidate : public UipcpObject {
    std::string apn;
    std::string api;
    uint64_t address;
    std::list<std::string> lower_difs;

    NeighborCandidate() { }
    NeighborCandidate(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct NeighborCandidateList : public UipcpObject {
    std::list<NeighborCandidate> candidates;

    NeighborCandidateList() { }
    NeighborCandidateList(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct LowerFlow : public UipcpObject {
    uint64_t local_addr;
    uint64_t remote_addr;
    unsigned int cost;
    unsigned int seqnum;
    bool state;
    unsigned int age;

    LowerFlow() { }
    LowerFlow(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;

    operator std::string() const;
};

struct LowerFlowList : public UipcpObject {
    std::list<LowerFlow> flows;

    LowerFlowList() { }
    LowerFlowList(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct Property : public UipcpObject {
    std::string name;
    std::string value;

    Property() { }
    Property(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

struct QosSpec : public UipcpObject {
    std::string name;
    uint32_t qos_id;
    uint64_t avg_bw;
    uint64_t avg_sdu_bw;
    uint64_t peak_bw_duration;
    uint64_t peak_sdu_bw_duration;
    double undetected_bit_error_rate;
    bool partial_delivery;
    bool in_order_delivery;
    int32_t max_sdu_gap;
    uint32_t delay;
    uint32_t jitter;
    std::list<Property> extra_parameters;

    QosSpec() { }
    QosSpec(const char *buf, unsigned int size);
    int serialize(char *buf, unsigned int size) const;
};

#endif  /* __UIPCP_CODECS_H__ */
