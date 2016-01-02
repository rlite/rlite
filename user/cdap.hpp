#ifndef __RINALITE_CDAP_H__
#define __RINALITE_CDAP_H__

#include <string>
#include <set>

#include "rinalite/rinalite-common.h"
#include "CDAP.pb.h"

struct AuthValue {
    std::string name;
    std::string password;
    std::string other;
};

class CDAPManager {
    std::set<int> pending_invoke_ids;
    int invoke_id_next;
    int max_pending_ops;

public:
    CDAPManager();
    int get_invoke_id();
};

/* Internal representation of a CDAP message. */
struct CDAPMessage {
    int                 abs_syntax;
    gpb::authTypes_t    auth_mech;
    struct AuthValue    auth_value;
    struct rina_name    src_appl;
    struct rina_name    dst_appl;
    std::string              filter;
    gpb::flagValues_t   flags;
    int                 invoke_id;
    std::string              obj_class;
    long                obj_inst;
    std::string              obj_name;
    gpb::opCode_t       op_code;
    int                 result;
    std::string              result_reason;
    int                 scope;
    long                version;

    enum obj_value_t {
        NONE,
        I32,
        I64,
        BYTES,
        FLOAT,
        DOUBLE,
        BOOL,
        STRING,
    };

    bool is(obj_value_t tt) const { return obj_value.ty == tt; }

    void print() const;

    CDAPMessage(gpb::opCode_t);
    ~CDAPMessage();

    CDAPMessage(const gpb::CDAPMessage& gm);
    operator gpb::CDAPMessage() const;

private:
    /* Representation of the object value. */
    struct {
        obj_value_t         ty;
        union {
            int32_t         i32; /* intval and sintval */
            int64_t         i64; /* int64val and sint64val */
            float           fp_single;
            double          fp_double;
            bool            boolean;
        } u;
        std::string              str; /* strval and byteval */
    }                   obj_value;

    CDAPMessage() { } /* This cannot be called. */
};

int cdap_msg_send(const struct CDAPMessage *m, int fd);
struct CDAPMessage * cdap_msg_recv(int fd);

int cdap_m_connect_send(CDAPManager *mgr, int fd,
                        gpb::authTypes_t auth_mech,
                        const struct AuthValue *auth_value,
                        const struct rina_name *local_appl,
                        const struct rina_name *remote_appl);

int cdap_m_connect_r_send(CDAPManager *mgr, int fd,
                          const struct CDAPMessage *req);

#endif /* __RINALITE_CDAP_H__ */
