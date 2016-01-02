#ifndef __RINALITE_CDAP_H__
#define __RINALITE_CDAP_H__

#include <string>
#include <set>

#include "rlite/common.h"
#include "CDAP.pb.h"


struct CDAPAuthValue {
    std::string name;
    std::string password;
    std::string other;

    bool empty() const { return name == std::string() &&
                         password == std::string() &&
                         other == std::string(); }
};

class InvokeIdMgr {
    std::set<int> pending_invoke_ids;
    int invoke_id_next;
    int max_pending_ops;
    std::set<int> pending_invoke_ids_remote;

    int __put_invoke_id(std::set<int> &pending, int invoke_id);

public:
    InvokeIdMgr();
    int get_invoke_id();
    int put_invoke_id(int invoke_id);
    int get_invoke_id_remote(int invoke_id);
    int put_invoke_id_remote(int invoke_id);

};

class CDAPConn {
    InvokeIdMgr invoke_id_mgr;

    enum {
        NONE = 1,
        AWAITCON,
        CONNECTED,
        AWAITCLOSE,
    } state;

    const char *conn_state_repr(int st);

    int conn_fsm_run(struct CDAPMessage *m, bool sender);

public:
    CDAPConn(int fd, long version);
    ~CDAPConn();

    /* @invoke_id is not meaningful for request messages. */
    int msg_send(struct CDAPMessage *m, int invoke_id);
    int msg_ser(struct CDAPMessage *m, int invoke_id,
                char **buf, size_t *len);

    struct CDAPMessage * msg_recv();
    struct CDAPMessage * msg_deser(const char *serbuf, size_t serlen);

    void reset();

    struct rina_name local_appl;
    struct rina_name remote_appl;
    int fd;
    long version;
};

struct CDAPMessage *msg_deser_stateless(const char *serbuf, size_t serlen);

int msg_ser_stateless(struct CDAPMessage *m, char **buf, size_t *len);

/* Internal representation of a CDAP message. */
struct CDAPMessage {
    int                 abs_syntax;
    gpb::authTypes_t    auth_mech;
    CDAPAuthValue       auth_value;
    struct rina_name    src_appl;
    struct rina_name    dst_appl;
    std::string         filter;
    gpb::flagValues_t   flags;
    int                 invoke_id;
    std::string         obj_class;
    long                obj_inst;
    std::string         obj_name;
    gpb::opCode_t       op_code;
    int                 result;
    std::string         result_reason;
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
    bool is_request() const { return !is_response(); }
    bool is_response() const { return op_code & 0x1; }

    void print() const;

    CDAPMessage();
    ~CDAPMessage();

    CDAPMessage(const gpb::CDAPMessage& gm);
    operator gpb::CDAPMessage() const;

    bool valid(bool check_invoke_id) const;

    void get_obj_value(int32_t& v) const
    {
        v = 0;
        if (obj_value.ty == I32) {
            v = obj_value.u.i32;
        }
    }

    void set_obj_value(int32_t v)
    {
        obj_value.ty = I32;
        obj_value.u.i32 = v;
    }

    void get_obj_value(int64_t& v) const
    {
        v = 0;
        if (obj_value.ty == I64) {
            v = obj_value.u.i64;
        }
    }

    void set_obj_value(int64_t v)
    {
        obj_value.ty = I64;
        obj_value.u.i64 = v;
    }

    void get_obj_value(float& v) const
    {
        v = 0.0;
        if (obj_value.ty == FLOAT) {
            v = obj_value.u.fp_single;
        }
    }

    void set_obj_value(float v)
    {
        obj_value.ty = FLOAT;
        obj_value.u.fp_single = v;
    }

    void get_obj_value(double& v) const
    {
        v = 0.0;
        if (obj_value.ty == DOUBLE) {
            v = obj_value.u.fp_double;
        }
    }

    void set_obj_value(double v)
    {
        obj_value.ty = DOUBLE;
        obj_value.u.fp_double = v;
    }

    void get_obj_value(bool& v) const
    {
        v = false;
        if (obj_value.ty == BOOL) {
            v = obj_value.u.boolean;
        }
    }

    void set_obj_value(bool v)
    {
        obj_value.ty = BOOL;
        obj_value.u.boolean = v;
    }

    void get_obj_value(std::string& v) const
    {
        v = std::string();
        if (obj_value.ty == STRING) {
            v = obj_value.str;
        }
    }

    void set_obj_value(const std::string& v)
    {
        obj_value.ty = STRING;
        obj_value.str = v;
    }

    void set_obj_value(const char *v)
    {
        obj_value.ty = STRING;
        obj_value.str = std::string(v);
    }

    void get_obj_value(const char *& p, size_t& l) const
    {
        p = NULL;
        l = 0;
        if (obj_value.ty == BYTES) {
            p = obj_value.u.buf.ptr;
            l = obj_value.u.buf.len;
        }
    }

    void set_obj_value(const char *buf, size_t len)
    {
        obj_value.ty = BYTES;
        obj_value.u.buf.ptr = const_cast<char *>(buf);
        obj_value.u.buf.len = len;
        obj_value.u.buf.owned = false;
    }

    int m_connect(gpb::authTypes_t auth_mech,
                  const struct CDAPAuthValue *auth_value,
                  const struct rina_name *local_appl,
                  const struct rina_name *remote_appl);

    int m_connect_r(const struct CDAPMessage *req, int result,
                    const std::string& result_reason);

    int m_release(gpb::flagValues_t flags);

    int m_release_r(gpb::flagValues_t flags, int result,
                    const std::string& result_reason);

    int m_create(gpb::flagValues_t flags,
                 const std::string& obj_class,
                 const std::string& obj_name, long obj_inst,
                 int scope, const std::string& filter);

    int m_create_r(gpb::flagValues_t flags, const std::string& obj_class,
                   const std::string& obj_name, long obj_inst,
                   int result, const std::string& result_reason);

    int m_delete(gpb::flagValues_t flags,
                 const std::string& obj_class,
                 const std::string& obj_name, long obj_inst,
                 int scope, const std::string& filter);

    int m_delete_r(gpb::flagValues_t flags, const std::string& obj_class,
                   const std::string& obj_name, long obj_inst,
                   int result, const std::string& result_reason);

    int m_read(gpb::flagValues_t flags,
               const std::string& obj_class,
               const std::string& obj_name, long obj_inst,
               int scope, const std::string& filter);

    int m_read_r(gpb::flagValues_t flags, const std::string& obj_class,
                 const std::string& obj_name, long obj_inst,
                 int result, const std::string& result_reason);

    int m_write(gpb::flagValues_t flags,
                const std::string& obj_class,
                const std::string& obj_name, long obj_inst,
                int scope, const std::string& filter);

    int m_write_r(gpb::flagValues_t flags, int result,
                  const std::string& result_reason);

    int m_cancelread(gpb::flagValues_t flags);

    int m_cancelread_r(gpb::flagValues_t flags, int result,
                       const std::string& result_reason);

    int m_start(gpb::flagValues_t flags,
               const std::string& obj_class,
               const std::string& obj_name, long obj_inst,
               int scope, const std::string& filter);

    int m_start_r(gpb::flagValues_t flags, int result,
                  const std::string& result_reason);

    int m_stop(gpb::flagValues_t flags,
               const std::string& obj_class,
               const std::string& obj_name, long obj_inst,
               int scope, const std::string& filter);

    int m_stop_r(gpb::flagValues_t flags, int result,
                 const std::string& result_reason);

private:
    int m_common(gpb::flagValues_t flags,
                 const std::string& obj_class,
                 const std::string& obj_name, long obj_inst,
                 int scope, const std::string& filter,
                 gpb::opCode_t op_code);

    int m_common_r(gpb::flagValues_t flags,
                   const std::string& obj_class,
                   const std::string& obj_name, long obj_inst,
                   int result, const std::string& result_reason,
                   gpb::opCode_t op_code);

    int __m_write(gpb::flagValues_t flags,
                  const std::string& obj_class,
                  const std::string& obj_name, long obj_inst,
                  int scope, const std::string& filter);

    /* Representation of the object value. */
    struct {
        obj_value_t         ty;
        union {
            int32_t         i32; /* intval and sintval */
            int64_t         i64; /* int64val and sint64val */
            float           fp_single;
            double          fp_double;
            bool            boolean;
            struct {
                char *ptr;
                size_t len;
                bool owned;
            } buf; /* byteval */
        } u;
        std::string              str; /* strval */
    }                   obj_value;
};

#endif /* __RINALITE_CDAP_H__ */
