#include <iostream>
#include <string>

#include "rinalite/rinalite-common.h"
#include "CDAP.pb.h"

using namespace std;


/* Internal representation of a CDAP message. */
struct CDAPMessage {
    int                 abs_syntax;
    gpb::authTypes_t    auth_mech;
    struct {
        string auth_name;
        string auth_password;
        string auth_other;
    }                   auth_value;
    struct rina_name    local_appl;
    struct rina_name    remote_appl;
    string              filter;
    gpb::flagValues_t   flags;
    int                 invoke_id;
    string              obj_class;
    long                obj_inst;
    string              obj_name;
    gpb::opCode_t       op_code;
    int                 result;
    string              result_reason;
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

private:
    /* Representation of the object value. */
    struct {
        obj_value_t         ty;
        union {
            int32_t         i32; /* intval and sintval */
            int64_t         i64; /* int64val and sint64val */
            void            *bytes;
            float           fp_single;
            double          fp_double;
            bool            boolean;
        } u;
        string              str; /* strval */
    }                   obj_value;
};

int main()
{
    gpb::CDAPMessage gm;
    CDAPMessage m;

    (void)gm;
    (void)m;

    return 0;
}
