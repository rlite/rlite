#ifndef __RLITE_CDAP_H__
#define __RLITE_CDAP_H__

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

    CDAPConn(const CDAPConn& o);

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

    bool is_type(obj_value_t tt) const;
    bool is_request() const { return !is_response(); }
    bool is_response() const { return op_code & 0x1; }

    void print() const;

    CDAPMessage();
    CDAPMessage(const CDAPMessage& o);
    CDAPMessage& operator=(const CDAPMessage& o);
    ~CDAPMessage();

    CDAPMessage(const gpb::CDAPMessage& gm);
    operator gpb::CDAPMessage() const;

    bool valid(bool check_invoke_id) const;

    void get_obj_value(int32_t& v) const;
    void set_obj_value(int32_t v);
    void get_obj_value(int64_t& v) const;
    void set_obj_value(int64_t v);
    void get_obj_value(float& v) const;
    void set_obj_value(float v);
    void get_obj_value(double& v) const;
    void set_obj_value(double v);
    void get_obj_value(bool& v) const;
    void set_obj_value(bool v);
    void get_obj_value(std::string& v) const;
    void set_obj_value(const std::string& v);
    void set_obj_value(const char *v);
    void get_obj_value(const char *& p, size_t& l) const;
    void set_obj_value(const char *buf, size_t len);

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

    void copy(const CDAPMessage& o);
    void destroy();

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
        std::string         str; /* strval */
    } obj_value;
};

#endif /* __RLITE_CDAP_H__ */
