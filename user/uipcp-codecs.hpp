#ifndef __UIPCP_CODECS_H__
#define __UIPCP_CODECS_H__

#include <stdint.h>
#include <list>
#include <string>

struct EnrollmentInfo {
    uint64_t address;
    std::list< std::string > lower_difs;
    bool start_early;

    EnrollmentInfo() : address(0), start_early(false) { }
    EnrollmentInfo(const char *buf, unsigned int size);
    unsigned int serialize(char *buf, unsigned int size) const;
};

#endif  /* __UIPCP_CODECS_H__ */
