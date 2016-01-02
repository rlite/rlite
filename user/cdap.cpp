#include <iostream>
#include <string>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include "rinalite/rinalite-common.h"
#include "rinalite/rinalite-utils.h"
#include "cdap.hpp"

using namespace std;


#define CDAP_ABS_SYNTAX    73

static const char *opcode_names_table[] = {
    [gpb::M_CONNECT] = "M_CONNECT",
    [gpb::M_CONNECT_R] = "M_CONNECT_R",
    [gpb::M_RELEASE] = "M_RELEASE",
    [gpb::M_RELEASE_R] = "M_RELEASE_R",
    [gpb::M_CREATE] = "M_CREATE",
    [gpb::M_CREATE_R] = "M_CREATE_R",
    [gpb::M_DELETE] = "M_DELETE",
    [gpb::M_DELETE_R] = "M_DELETE_R",
    [gpb::M_READ] = "M_READ",
    [gpb::M_READ_R] = "M_READ_R",
    [gpb::M_CANCELREAD] = "M_CANCELREAD",
    [gpb::M_CANCELREAD_R] = "M_CANCELREAD_R",
    [gpb::M_WRITE] = "M_WRITE",
    [gpb::M_WRITE_R] = "M_WRITE_R",
    [gpb::M_START] = "M_START",
    [gpb::M_START_R] = "M_START_R",
    [gpb::M_STOP] = "M_STOP",
    [gpb::M_STOP_R] = "M_STOP_R",
};

#define MAX_CDAP_OPCODE gpb::M_STOP_R
#define MAX_CDAP_FIELD  gpb::CDAPMessage::kVersionFieldNumber

#define FLNUM(_FL)  gpb::CDAPMessage::k##_FL##FieldNumber

#define ENTRY_FILL(FL, OP, VA)   \
        tab[((MAX_CDAP_OPCODE + 1) * FLNUM(FL) + gpb::OP)] = VA

#define CAN_EXIST       0
#define MUST_EXIST      1
#define MUST_NOT_EXIST  2

#define COMBO(FL, OP)   \
        ((MAX_CDAP_OPCODE + 1) * FLNUM(FL) + OP)

#define TAB_FILL(FL, VA)    \
        for (unsigned _i = gpb::M_CONNECT; _i <= MAX_CDAP_OPCODE; _i++) tab[COMBO(FL, _i)] = VA

struct CDAPValidationTable {
    char tab[(MAX_CDAP_OPCODE + 1) * (1 + MAX_CDAP_FIELD)];

    CDAPValidationTable();

    bool check(int field, const char *flname, gpb::opCode_t op, bool observed);
};

bool CDAPValidationTable::check(int field, const char *flname,
                                gpb::opCode_t op, bool observed)
{
    char expected = tab[(MAX_CDAP_OPCODE + 1) * field + op];

    if (expected == MUST_EXIST && !observed) {
        PE("%s: Invalid message: %s must contain field %s\n",
            __func__, opcode_names_table[op], flname);
        return false;
    }

    if (expected == MUST_NOT_EXIST && observed) {
        PE("%s: Invalid message: %s must not contain field %s\n",
            __func__, opcode_names_table[op], flname);
        return false;
    }

    return true;
}

CDAPValidationTable::CDAPValidationTable()
{
    /* abs_syntax */
    TAB_FILL(AbsSyntax, MUST_NOT_EXIST);
    ENTRY_FILL(AbsSyntax, M_CONNECT, MUST_EXIST);
    ENTRY_FILL(AbsSyntax, M_CONNECT_R, MUST_EXIST);

    /* auth_mech */
    TAB_FILL(AuthMech, MUST_NOT_EXIST);
    ENTRY_FILL(AuthMech, M_CONNECT, 0);
    ENTRY_FILL(AuthMech, M_CONNECT_R, 0);

    /* auth_value */
    TAB_FILL(AuthValue, MUST_NOT_EXIST);
    ENTRY_FILL(AuthValue, M_CONNECT, 0);
    ENTRY_FILL(AuthValue, M_CONNECT_R, 0);

    /* src_appl */
    TAB_FILL(SrcApName, MUST_NOT_EXIST);
    ENTRY_FILL(SrcApName, M_CONNECT, MUST_EXIST);
    ENTRY_FILL(SrcApName, M_CONNECT_R, MUST_EXIST);

    /* dst_appl */
    TAB_FILL(DestApName, MUST_NOT_EXIST);
    ENTRY_FILL(DestApName, M_CONNECT, MUST_EXIST);
    ENTRY_FILL(DestApName, M_CONNECT_R, MUST_EXIST);

    /* filter */
    ENTRY_FILL(Filter, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_CONNECT_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_RELEASE_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_CREATE, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_CREATE_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_DELETE_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_READ_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_CANCELREAD, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_CANCELREAD_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_WRITE_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_START_R, MUST_NOT_EXIST);
    ENTRY_FILL(Filter, M_STOP_R, MUST_NOT_EXIST);

    /* invoke_id */
    ENTRY_FILL(InvokeID, M_CONNECT, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_CONNECT_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_RELEASE_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_CREATE_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_DELETE_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_READ_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_CANCELREAD, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_CANCELREAD_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_WRITE_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_START_R, MUST_EXIST);
    ENTRY_FILL(InvokeID, M_STOP_R, MUST_EXIST);

    /* obj_class */
    ENTRY_FILL(ObjClass, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(ObjClass, M_CONNECT_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjClass, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(ObjClass, M_RELEASE_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjClass, M_CANCELREAD, MUST_NOT_EXIST);
    ENTRY_FILL(ObjClass, M_CANCELREAD_R, MUST_NOT_EXIST);

    /* obj_inst */
    ENTRY_FILL(ObjInst, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(ObjInst, M_CONNECT_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjInst, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(ObjInst, M_RELEASE_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjInst, M_CANCELREAD, MUST_NOT_EXIST);
    ENTRY_FILL(ObjInst, M_CANCELREAD_R, MUST_NOT_EXIST);

    /* obj_name */
    ENTRY_FILL(ObjName, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(ObjName, M_CONNECT_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjName, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(ObjName, M_RELEASE_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjName, M_CANCELREAD, MUST_NOT_EXIST);
    ENTRY_FILL(ObjName, M_CANCELREAD_R, MUST_NOT_EXIST);

    /* obj_value */
    ENTRY_FILL(ObjValue, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(ObjValue, M_CONNECT_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjValue, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(ObjValue, M_RELEASE_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjValue, M_WRITE, MUST_EXIST);
    ENTRY_FILL(ObjValue, M_DELETE_R, MUST_NOT_EXIST);
    ENTRY_FILL(ObjValue, M_CANCELREAD, MUST_NOT_EXIST);
    ENTRY_FILL(ObjValue, M_CANCELREAD_R, MUST_NOT_EXIST);

    /* op_code */
    TAB_FILL(OpCode, MUST_EXIST);

    /* result */
    ENTRY_FILL(Result, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_CREATE, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_DELETE, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_READ, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_WRITE, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_START, MUST_NOT_EXIST);
    ENTRY_FILL(Result, M_STOP, MUST_NOT_EXIST);

    /* result_reason */
    ENTRY_FILL(ResultReason, M_CONNECT, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_RELEASE, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_CREATE, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_DELETE, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_READ, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_WRITE, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_START, MUST_NOT_EXIST);
    ENTRY_FILL(ResultReason, M_STOP, MUST_NOT_EXIST);

    /* scope */
    TAB_FILL(Scope, MUST_NOT_EXIST);
    ENTRY_FILL(Scope, M_CREATE, 0);
    ENTRY_FILL(Scope, M_DELETE, 0);
    ENTRY_FILL(Scope, M_READ, 0);
    ENTRY_FILL(Scope, M_WRITE, 0);
    ENTRY_FILL(Scope, M_START, 0);
    ENTRY_FILL(Scope, M_STOP, 0);

    /* version */
    ENTRY_FILL(Version, M_CONNECT, MUST_EXIST);
    ENTRY_FILL(Version, M_CONNECT_R, MUST_EXIST);
}

static struct CDAPValidationTable vt;

CDAPConn::CDAPConn(int arg_fd, long arg_version)
{
    invoke_id_next = 1;
    max_pending_ops = 5;

    fd = arg_fd;
    version = arg_version;
    memset(&local_appl, 0, sizeof(local_appl));
    memset(&remote_appl, 0, sizeof(remote_appl));
    state = NONE;
}

CDAPConn::~CDAPConn()
{
    rina_name_free(&local_appl);
    rina_name_free(&remote_appl);
}

int
CDAPConn::__put_invoke_id(set<int>& pending, int invoke_id)
{
    if (!pending.count(invoke_id)) {
        return -1;
    }

    pending.erase(invoke_id);

    PD("%s: put %d\n", __func__, invoke_id);

    return 0;
}

int
CDAPConn::get_invoke_id()
{
    int ret;

    while (pending_invoke_ids.count(invoke_id_next)) {
        invoke_id_next++;
    }

    ret = invoke_id_next++;
    pending_invoke_ids.insert(ret);

    PD("%s: got %d\n", __func__, ret);

    return ret;
}

int
CDAPConn::put_invoke_id(int invoke_id)
{
    return __put_invoke_id(pending_invoke_ids, invoke_id);
}

int
CDAPConn::get_invoke_id_remote(int invoke_id)
{
    if (pending_invoke_ids_remote.count(invoke_id)) {
        return -1;
    }

    pending_invoke_ids_remote.insert(invoke_id);

    PD("%s: got %d\n", __func__, invoke_id);

    return 0;
}

int
CDAPConn::put_invoke_id_remote(int invoke_id)
{
    return __put_invoke_id(pending_invoke_ids_remote, invoke_id);
}

CDAPMessage::CDAPMessage()
{
    abs_syntax = 0;
    auth_mech = gpb::AUTH_NONE;
    memset(&src_appl, 0, sizeof(src_appl));
    memset(&dst_appl, 0, sizeof(dst_appl));
    flags = gpb::F_NO_FLAGS;
    invoke_id = 0;
    obj_inst = 0;
    op_code = gpb::M_CONNECT;
    obj_value.ty = NONE;
    result = 0;
    scope = 0;
    version = 0;
}

CDAPMessage::~CDAPMessage()
{
    rina_name_free(&src_appl);
    rina_name_free(&dst_appl);
    if (obj_value.ty == BYTES && obj_value.u.buf.owned
                && obj_value.u.buf.ptr) {
        delete obj_value.u.buf.ptr;
    }
}

CDAPMessage::CDAPMessage(const gpb::CDAPMessage& gm)
{
    const char *apn, *api, *aen, *aei;
    gpb::objVal_t objvalue = gm.objvalue();
    int ret;

    abs_syntax = gm.abssyntax();
    op_code = gm.opcode();
    invoke_id = gm.invokeid();
    flags = gm.flags();
    obj_class = gm.objclass();
    obj_name = gm.objname();
    obj_inst = gm.objinst();

    /* Convert object value. */
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
        obj_value.u.buf.ptr = new char[objvalue.byteval().size()];
        if (!obj_value.u.buf.ptr) {
            PE("%s: BYTES object allocation failed\n", __func__);
            obj_value.ty = NONE;
        } else {
            memcpy(obj_value.u.buf.ptr, objvalue.byteval().data(),
                   objvalue.byteval().size());
            obj_value.u.buf.len = objvalue.byteval().size();
            obj_value.u.buf.owned = true;
            obj_value.ty = BYTES;
        }

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

#define safe_c_string(_s) ((_s) ? (_s) : "")

CDAPMessage::operator gpb::CDAPMessage() const
{
    gpb::CDAPMessage gm;
    gpb::objVal_t *objvalue = new gpb::objVal_t();
    gpb::authValue_t *authvalue = new gpb::authValue_t();

    if (!objvalue || !authvalue) {
        PE("%s: Out of memory\n", __func__);
        if (objvalue) delete objvalue;
        if (authvalue) delete authvalue;

        return gpb::CDAPMessage();
    }

    gm.set_abssyntax(abs_syntax);
    gm.set_opcode(op_code);
    gm.set_invokeid(invoke_id);
    gm.set_flags(flags);
    gm.set_objclass(obj_class);
    gm.set_objname(obj_name);
    gm.set_objinst(obj_inst);

    /* Convert object value. */
    switch (obj_value.ty) {
        case I32:
            objvalue->set_intval(obj_value.u.i32);
            break;

        case I64:
            objvalue->set_int64val(obj_value.u.i64);
            break;

        case STRING:
            objvalue->set_strval(obj_value.str);
            break;

        case FLOAT:
            objvalue->set_floatval(obj_value.u.fp_single);
            break;

        case DOUBLE:
            objvalue->set_doubleval(obj_value.u.fp_double);
            break;

        case BOOL:
            objvalue->set_boolval(obj_value.u.boolean);
            break;

        case BYTES:
            objvalue->set_byteval(obj_value.u.buf.ptr, obj_value.u.buf.len);
            break;
    }

    if (obj_value.ty != NONE) {
        gm.set_allocated_objvalue(objvalue);
    }

    gm.set_result(result);
    gm.set_scope(scope);
    gm.set_filter(filter);
    gm.set_authmech(auth_mech);

    authvalue->set_authname(auth_value.name);
    authvalue->set_authpassword(auth_value.password);
    authvalue->set_authother(auth_value.other);
    gm.set_allocated_authvalue(authvalue);

    gm.set_destapname(std::string(safe_c_string(dst_appl.apn)));
    gm.set_destapinst(std::string(safe_c_string(dst_appl.api)));
    gm.set_destaename(std::string(safe_c_string(dst_appl.aen)));
    gm.set_destaeinst(std::string(safe_c_string(dst_appl.aei)));

    gm.set_srcapname(std::string(safe_c_string(src_appl.apn)));
    gm.set_srcapinst(std::string(safe_c_string(src_appl.api)));
    gm.set_srcaename(std::string(safe_c_string(src_appl.aen)));
    gm.set_srcaeinst(std::string(safe_c_string(src_appl.aei)));

    gm.set_resultreason(result_reason);
    gm.set_version(version);

    return gm;
}

bool
CDAPMessage::valid(bool check_invoke_id) const
{
    bool ret = true;

    ret = ret && vt.check(FLNUM(AbsSyntax), "abs_syntax", op_code,
                          abs_syntax != 0);

    ret = ret && vt.check(FLNUM(AuthMech), "auth_mech", op_code,
                          auth_mech != gpb::AUTH_NONE);

    ret = ret && vt.check(FLNUM(AuthValue), "auth_value", op_code,
                          !auth_value.empty());

    ret = ret && vt.check(FLNUM(SrcApName), "src_appl", op_code,
                          rina_name_valid(&src_appl));

    ret = ret && vt.check(FLNUM(DestApName), "dst_appl", op_code,
                          rina_name_valid(&dst_appl));

    ret = ret && vt.check(FLNUM(Filter), "filter", op_code,
                          filter != string());

    if (check_invoke_id) {
        ret = ret && vt.check(FLNUM(InvokeID), "invoke_id", op_code,
                              invoke_id != 0);
    }

    ret = ret && vt.check(FLNUM(ObjClass), "obj_class", op_code,
                          obj_class != string());

    ret = ret && vt.check(FLNUM(ObjInst), "obj_inst", op_code,
                          obj_inst != 0);

    ret = ret && vt.check(FLNUM(ObjName), "obj_name", op_code,
                          obj_name != string());

    ret = ret && vt.check(FLNUM(ObjValue), "obj_value", op_code,
                          obj_value.ty != NONE);

    ret = ret && vt.check(FLNUM(Result), "result", op_code,
                          result != 0);

    ret = ret && vt.check(FLNUM(ResultReason), "result_reason", op_code,
                          result_reason != string());

    ret = ret && vt.check(FLNUM(Scope), "scope", op_code,
                          scope != 0);

    ret = ret && vt.check(FLNUM(Version), "version", op_code,
                          version != 0);

    if ((obj_class != string()) != (obj_name != string())) {
        PE("%s: Invalid message: if obj_class is specified, also obj_name "
                "must be, and the other way around\n", __func__);
        return false;
    }

    return ret;
}

void
CDAPMessage::print() const
{
    char *name;

    PD("CDAP Message { ");
    PD("abs_syntax: %d, ", abs_syntax);
    if (op_code <= MAX_CDAP_OPCODE) {
        PD("op_code: %s, ", opcode_names_table[op_code]);
    }
    PD("invoke_id: %d, ", invoke_id);

    if (flags != gpb::F_NO_FLAGS) {
        PD("flags: %04x, ", flags);
    }

    if (obj_class != string()) {
        PD("obj_class: %s, ", obj_class.c_str());
    }

    if (obj_name != string()) {
        PD("obj_name: %s, ", obj_name.c_str());
    }

    if (obj_inst) {
        PD("obj_inst: %ld, ", obj_inst);
    }

    /* Print object value. */
    switch (obj_value.ty) {
        case I32:
            PD("obj_value: %d, ", obj_value.u.i32);
            break;

        case I64:
            PD("obj_value: %lld, ", (long long)obj_value.u.i64);
            break;

        case STRING:
            PD("obj_value: %s, ", obj_value.str.c_str());
            break;

        case FLOAT:
            PD("obj_value: %f,", obj_value.u.fp_single);
            break;

        case DOUBLE:
            PD("obj_value: %f, ", obj_value.u.fp_double);
            break;

        case BOOL:
            PD("obj_value: %s, ", (obj_value.u.boolean ? "true" : "false"));
            break;

        case BYTES:
            PD("obj_value: %d bytes at %p, ", obj_value.u.buf.len,
                                              obj_value.u.buf.ptr);
            break;
    }


    if (result) {
        PD("result: %d, ", result);
    }

    if (scope) {
        PD("scope: %d, ", scope);
    }

    if (filter != string()) {
        PD("filter: %s, ", filter.c_str());
    }

    if (auth_mech != gpb::AUTH_NONE) {
        PD("auth_mech: %d, ", auth_mech);
        PD("auth_value: name='%s' pwd='%s' other='%s', ",
                auth_value.name.c_str(), auth_value.password.c_str(),
                auth_value.other.c_str());
    }

    if (rina_name_valid(&dst_appl)) {
        name = rina_name_to_string(&dst_appl);
        PD("dst_appl: %s, ", name);
        if (name) {
            free(name);
        }
    }

    if (rina_name_valid(&src_appl)) {
        name = rina_name_to_string(&src_appl);
        PD("src_appl: %s, ", name);
        if (name) {
            free(name);
        }
    }

    if (result_reason != string()) {
        PD("result_reason: %s, ", result_reason.c_str());
    }

    PD("version: %ld, ", version);

    PD("}\n");
}

int
CDAPConn::conn_fsm_run(struct CDAPMessage *m, bool sender)
{
    const char *action = sender ? "send" : "receive";
    int old_state = state;

    if (m->op_code > MAX_CDAP_OPCODE) {
        PE("%s: Invalid opcode %d\n", __func__, m->op_code);
        return -1;
    }

    switch (m->op_code) {
        case gpb::M_CONNECT:
            {
                struct rina_name *local, *remote;
                int ret;

                if (state != NONE) {
                    PE("%s: Cannot %s M_CONNECT message: Invalid state %d\n",
                            __func__, action, state);
                    return -1;
                }

                if (sender) {
                    local = &m->src_appl;
                    remote = &m->dst_appl;
                } else {
                    local = &m->dst_appl;
                    remote = &m->src_appl;
                }
                ret = rina_name_copy(&local_appl, local);
                ret |= rina_name_copy(&remote_appl, remote);
                if (ret) {
                    rina_name_free(&local_appl);
                    rina_name_free(&remote_appl);
                    return ret;
                }

                state = AWAITCON;
            }
            break;

        case gpb::M_CONNECT_R:
            if (state != AWAITCON) {
                PE("%s: Cannot %s M_CONNECT_R message: Invalid state %d\n",
                                    __func__, action, state);
                return -1;
            }
            state = CONNECTED;
            break;

        case gpb::M_RELEASE:
            if (state != CONNECTED) {
                PE("%s: Cannot %s M_RELEASE message: Invalid state %d\n",
                                    __func__, action, state);
                return -1;
            }
            rina_name_free(&local_appl);
            rina_name_free(&remote_appl);
            state = AWAITCLOSE;
            break;

        case gpb::M_RELEASE_R:
            if (state != AWAITCLOSE) {
                PE("%s: Cannot %s M_RELEASE message: Invalid state %d\n",
                                    __func__, action, state);
                return -1;
            }
            state = NONE;
            break;

        default:
            /* All the operational messages. */
            if (state != CONNECTED) {
                PE("%s: Cannot %s %s message: Invalid state %d\n",
                    __func__, action, opcode_names_table[m->op_code], state);
                return -1;
            }
    }

    if (old_state != state) {
        PD("%s: Connection state %d --> %d\n", __func__, old_state, state);
    }

    return 0;
}

int
CDAPConn::msg_ser(struct CDAPMessage *m, int invoke_id,
                  char **buf, size_t *len)
{
    gpb::CDAPMessage gm;

    *buf = NULL;
    *len = 0;

    m->version = version;

    if (!m->valid(false)) {
        return -1;
    }

    /* Run CDAP connection state machine (sender side). */
    if (conn_fsm_run(m, true)) {
        return -1;
    }

    if (m->is_request()) {
        /* CDAP request message (M_*). */
        m->invoke_id = get_invoke_id();

    } else {
        /* CDAP response message (M_*_R). */
        m->invoke_id = invoke_id;
        if (put_invoke_id_remote(m->invoke_id)) {
           PE("%s: Invoke id %d does not match any pending request\n",
                __func__, m->invoke_id);
        }
    }

    gm = static_cast<gpb::CDAPMessage>(*m);

    *len = gm.ByteSize();
    *buf = new char[*len];

    if (!(*buf)) {
        PE("%s: Out of memory\n", __func__);
        return ENOMEM;
    }

    gm.SerializeToArray(*buf, *len);

    return 0;
}

int
CDAPConn::msg_send(struct CDAPMessage *m, int invoke_id)
{
    size_t serlen;
    char *serbuf;
    int n;

    n = msg_ser(m, invoke_id, &serbuf, &serlen);
    if (n) {
        return 0;
    }

    n = write(fd, serbuf, serlen);
    if (n != serlen) {
        if (n < 0) {
            perror("write(cdap_msg)");
        } else {
            PE("%s: Partial write %d/%d\n", __func__, n, serlen);
        }
        return -1;
    }

    delete serbuf;

    return 0;
}

struct CDAPMessage *
CDAPConn::msg_deser(char *serbuf, size_t serlen)
{
    struct CDAPMessage *m;
    gpb::CDAPMessage gm;

    gm.ParseFromArray(serbuf, serlen);

    m = new CDAPMessage(gm);
    if (!m) {
        PE("%s: Out of memory\n", __func__);
    }

    if (!m->valid(true)) {
        delete m;
        return NULL;
    }

    /* Run CDAP connection state machine (receiver side). */
    if (conn_fsm_run(m, false)) {
        delete m;
        return NULL;
    }

    if (m->is_response()) {
        /* CDAP request message (M_*). */
        if (put_invoke_id(m->invoke_id)) {
            PE("%s: Invoke id %d does not match any pending request\n",
                __func__);
            delete m;
            m = NULL;
        }

    } else {
        /* CDAP response message (M_*_R). */
        if (get_invoke_id_remote(m->invoke_id)) {
            PE("%s: Invoke id %d already used remotely\n");
            delete m;
            m = NULL;
        }
    }

    return m;
}

struct CDAPMessage *
CDAPConn::msg_recv()
{
    char serbuf[4096];
    int n;

    n = read(fd, serbuf, sizeof(serbuf));
    if (n < 0) {
        perror("read(cdap_msg)");
        return NULL;
    }

    return msg_deser(serbuf, n);
}

int
CDAPMessage::m_connect(gpb::authTypes_t auth_mech_,
                       const struct CDAPAuthValue *auth_value_,
                       const struct rina_name *local_appl,
                       const struct rina_name *remote_appl)
{
    int ret;

    op_code = gpb::M_CONNECT;
    abs_syntax = CDAP_ABS_SYNTAX;
    auth_mech = auth_mech_;
    auth_value = *auth_value_;
    ret = rina_name_copy(&src_appl, local_appl);
    ret |= rina_name_copy(&dst_appl, remote_appl);

    if (ret) {
        PE("%s: Out of memory\n", __func__);
        return ret;
    }

    return 0;
}

int
CDAPMessage::m_connect_r(const struct CDAPMessage *req, int result_,
                      const std::string& result_reason_)
{
    int ret;

    op_code = gpb::M_CONNECT_R;
    abs_syntax = CDAP_ABS_SYNTAX;
    auth_mech = req->auth_mech;
    auth_value = req->auth_value;
    ret = rina_name_copy(&src_appl, &req->dst_appl);
    ret |= rina_name_copy(&dst_appl, &req->src_appl);

    result = result_;
    result_reason = result_reason_;

    if (ret) {
        PE("%s: Out of memory\n", __func__);
        return ret;
    }

    return 0;
}

int
CDAPMessage::m_release(gpb::flagValues_t flags_)
{
    op_code = gpb::M_RELEASE;
    flags = flags_;

    return 0;
}

int
CDAPMessage::m_release_r(const struct CDAPMessage *req,
                      gpb::flagValues_t flags_, int result_,
                      const std::string& result_reason_)
{
    op_code = gpb::M_RELEASE_R;
    flags = flags_;

    result = result_;
    result_reason = result_reason_;

    return 0;
}

int
CDAPMessage::m_common(gpb::flagValues_t flags_,
                   const std::string& obj_class_,
                   const std::string& obj_name_, long obj_inst_,
                   int scope_, const std::string& filter_,
                   gpb::opCode_t op_code_)
{
    op_code = op_code_;
    flags = flags_;
    obj_class = obj_class_;
    obj_name = obj_name_;
    obj_inst = obj_inst_;
    scope = scope_;
    filter = filter_;

    return 0;
}

int
CDAPMessage::m_common_r(const struct CDAPMessage *req,
                     gpb::flagValues_t flags_,
                     const std::string& obj_class_,
                     const std::string& obj_name_, long obj_inst_,
                     int result_, const std::string& result_reason_,
                     gpb::opCode_t op_code_)
{
    op_code = op_code_;
    flags = flags_;
    obj_class = obj_class_;
    obj_name = obj_name_;
    obj_inst = obj_inst_;

    result = result_;
    result_reason = result_reason_;

    return 0;
}

int
CDAPMessage::m_create(gpb::flagValues_t flags,
                      const std::string& obj_class,
                      const std::string& obj_name, long obj_inst,
                      int scope, const std::string& filter)
{
    return m_common(flags, obj_class, obj_name,
                    obj_inst, scope, filter, gpb::M_CREATE);
}

int
CDAPMessage::m_create_r(const struct CDAPMessage *req,
                     gpb::flagValues_t flags, const std::string& obj_class,
                     const std::string& obj_name, long obj_inst,
                     int result, const std::string& result_reason)
{
    return m_common_r(req, flags, obj_class, obj_name, obj_inst,
                      result, result_reason, gpb::M_CREATE_R);
}

int
CDAPMessage::m_delete(gpb::flagValues_t flags,
                   const std::string& obj_class,
                   const std::string& obj_name, long obj_inst,
                   int scope, const std::string& filter)
{
    return m_common(flags, obj_class, obj_name,
                    obj_inst, scope, filter, gpb::M_DELETE);
}

int
CDAPMessage::m_delete_r(const struct CDAPMessage *req,
                     gpb::flagValues_t flags, const std::string& obj_class,
                     const std::string& obj_name, long obj_inst,
                     int result, const std::string& result_reason)
{
    return m_common_r(req, flags, obj_class, obj_name, obj_inst,
                      result, result_reason, gpb::M_DELETE_R);
}

int
CDAPMessage::m_read(gpb::flagValues_t flags,
                 const std::string& obj_class,
                 const std::string& obj_name, long obj_inst,
                 int scope, const std::string& filter)
{
    return m_common(flags, obj_class, obj_name,
                    obj_inst, scope, filter, gpb::M_READ);
}

int
CDAPMessage::m_read_r(const struct CDAPMessage *req,
                     gpb::flagValues_t flags, const std::string& obj_class,
                     const std::string& obj_name, long obj_inst,
                     int result, const std::string& result_reason)
{
    return m_common_r(req, flags, obj_class, obj_name, obj_inst,
                      result, result_reason, gpb::M_READ_R);
}

int
CDAPMessage::m_write(gpb::flagValues_t flags_,
                     const std::string& obj_class_,
                     const std::string& obj_name_, long obj_inst_,
                     int scope_, const std::string& filter_)
{
    op_code = gpb::M_WRITE;
    flags = flags_;
    obj_class = obj_class_;
    obj_name = obj_name_;
    obj_inst = obj_inst_;
    scope = scope_;
    filter = filter_;

    return 0;
}

int
CDAPMessage::m_write_r(const struct CDAPMessage *req,
                    gpb::flagValues_t flags_, int result_,
                    const std::string& result_reason_)
{
    op_code = gpb::M_WRITE_R;
    flags = flags_;

    result = result_;
    result_reason = result_reason_;

    return 0;
}

int
CDAPMessage::m_cancelread(gpb::flagValues_t flags_)
{
    op_code = gpb::M_CANCELREAD;
    flags = flags_;

    return 0;
}

int
CDAPMessage::m_cancelread_r(const struct CDAPMessage *req,
                         gpb::flagValues_t flags_, int result_,
                         const std::string& result_reason_)
{
    op_code = gpb::M_CANCELREAD_R;
    flags = flags_;

    result = result_;
    result_reason = result_reason_;

    return 0;
}

int
CDAPMessage::m_start(gpb::flagValues_t flags,
                  const std::string& obj_class,
                  const std::string& obj_name, long obj_inst,
                  int scope, const std::string& filter)
{
    return m_common(flags, obj_class, obj_name,
                    obj_inst, scope, filter, gpb::M_START);
}

int
CDAPMessage::m_start_r(const struct CDAPMessage *req,
                    gpb::flagValues_t flags_, int result_,
                    const std::string& result_reason_)
{
    op_code = gpb::M_START_R;
    flags = flags_;

    result = result_;
    result_reason = result_reason_;

    return 0;
}

int
CDAPMessage::m_stop(gpb::flagValues_t flags,
                 const std::string& obj_class,
                 const std::string& obj_name, long obj_inst,
                 int scope, const std::string& filter)
{
    return m_common(flags, obj_class, obj_name,
                    obj_inst, scope, filter, gpb::M_STOP);
}

int
CDAPMessage::m_stop_r(const struct CDAPMessage *req,
                    gpb::flagValues_t flags_, int result_,
                    const std::string& result_reason_)
{
    op_code = gpb::M_STOP_R;
    flags = flags_;

    result = result_;
    result_reason = result_reason_;

    return 0;
}
