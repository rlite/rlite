#include <iostream>
#include <string>

#include "rinalite/rinalite-common.h"
#include "rinalite/rinalite-utils.h"
#include "CDAP.pb.h"

using namespace std;


/* Internal representation of a CDAP message. */
struct CDAPMessage {
    int                 abs_syntax;
    gpb::authTypes_t    auth_mech;
    struct {
        string name;
        string password;
        string other;
    }                   auth_value;
    struct rina_name    src_appl;
    struct rina_name    dst_appl;
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

    CDAPMessage(gpb::opCode_t);
    CDAPMessage(const gpb::CDAPMessage& gm);

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
        string              str; /* strval and byteval */
    }                   obj_value;

    CDAPMessage() { } /* This cannot be called. */
};

CDAPMessage::CDAPMessage(gpb::opCode_t op_code_arg)
{
    op_code = op_code_arg;
    obj_value.ty = NONE;
}

CDAPMessage::CDAPMessage(const gpb::CDAPMessage& gm)
{
    const char *apn, *api, *aen, *aei;
    gpb::objVal_t objvalue = gm.objvalue();

    abs_syntax = gm.abssyntax();
    op_code = gm.opcode();
    invoke_id = gm.invokeid();
    flags = gm.flags();
    obj_class = gm.objclass();
    obj_name = gm.objname();
    obj_inst = gm.objinst();

    /* Decode object value. */
    if (objvalue.has_intval()) {
        obj_value.u.i32 = objvalue.intval();
        obj_value.ty = I32;

    } else if (objvalue.has_sintval()) {
        obj_value.u.i32 = objvalue.sintval();
        obj_value.ty = I32;

    } else if (objvalue.has_int64val()) {
        obj_value.u.i64 = objvalue.int64val();
        obj_value.ty = I64;

    } else if (objvalue.has_sint64val()) {
        obj_value.u.i64 = objvalue.sint64val();
        obj_value.ty = I64;

    } else if (objvalue.has_strval()) {
        obj_value.str = objvalue.strval();
        obj_value.ty = STRING;

    } else if (objvalue.has_floatval()) {
        obj_value.u.fp_single = objvalue.floatval();
        obj_value.ty = FLOAT;

    } else if (objvalue.has_doubleval()) {
        obj_value.u.fp_double = objvalue.doubleval();
        obj_value.ty = DOUBLE;

    } else if (objvalue.has_boolval()) {
        obj_value.u.boolean = objvalue.boolval();
        obj_value.ty = BOOL;

    } else if (objvalue.has_byteval()) {
        obj_value.str = objvalue.byteval();
        obj_value.ty = BYTES;

    } else {
        obj_value.ty = NONE;
    }

    result = gm.result();
    scope = gm.scope();
    filter = gm.filter();

    auth_mech = gm.authmech();
    auth_value.name = gm.authvalue().authname();
    auth_value.password = gm.authvalue().authpassword();
    auth_value.other = gm.authvalue().authother();

    apn = gm.has_destapname() ? gm.destapname().c_str() : NULL;
    api = gm.has_destapinst() ? gm.destapinst().c_str() : NULL;
    aen = gm.has_destaename() ? gm.destaename().c_str() : NULL;
    aei = gm.has_destaeinst() ? gm.destaeinst().c_str() : NULL;
    rina_name_fill(&dst_appl, apn, api, aen, aei);

    apn = gm.has_srcapname() ? gm.srcapname().c_str() : NULL;
    api = gm.has_srcapinst() ? gm.srcapinst().c_str() : NULL;
    aen = gm.has_srcaename() ? gm.srcaename().c_str() : NULL;
    aei = gm.has_srcaeinst() ? gm.srcaeinst().c_str() : NULL;
    rina_name_fill(&src_appl, apn, api, aen, aei);

    result_reason = gm.resultreason();
    version = gm.version();
}

int main()
{
    gpb::CDAPMessage gm;
    CDAPMessage m(gpb::M_CONNECT);

    (void)gm;
    (void)m;

    return 0;
}
