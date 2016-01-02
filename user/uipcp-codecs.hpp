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

#endif  /* __UIPCP_CODECS_H__ */
