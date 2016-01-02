#include <string>
#include <fstream>

#include "uipcp-normal.hpp"

using namespace std;


/* Helper function that emulates Python's str.strip(). */
static void
string_strip(string& s)
{
    unsigned int i;
    unsigned int j;

    for (i = 0; i < s.size() && isspace(s[i]); i++) {
    }

    if (i == s.size()) {
        return;
    }

    s = s.substr(i);

    for (j = s.size() - 1; j >= i && isspace(s[j]); j--) {
    }

    s = s.substr(0, j + 1);
}

static int
parse_flowcfg_bool(const string& param, const string& value,
                   uint8_t *field, const string& fieldname)
{
    if (param != fieldname) {
        return -1;
    }

    *field = (value == "true");
    return 0;
}

static int
parse_flowcfg_int(const string& param, const string& value,
                  int *field, const string& fieldname)
{
    if (param != fieldname) {
        return -1;
    }

    *field = atoi(value.c_str());

    return 0;
}

static int
update_qos_cube(struct rina_flow_config& flowcfg, const string& param,
                   const string& value)
{
    int field_int;

    if (!parse_flowcfg_bool(param, value, &flowcfg.partial_delivery,
                                            "partial_delivery")) {
        return 0;
    }

    if (!parse_flowcfg_bool(param, value, &flowcfg.incomplete_delivery,
                                            "incomplete_delivery")) {
        return 0;
    }

    if (!parse_flowcfg_bool(param, value, &flowcfg.in_order_delivery,
                                            "in_order_delivery")) {
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int, "max_sdu_gap")) {
        flowcfg.max_sdu_gap = field_int;
        if (flowcfg.max_sdu_gap != ((uint64_t)-1)) {
            flowcfg.dtcp_present = 1;
        }
        return 0;
    }

    if (!parse_flowcfg_bool(param, value, &flowcfg.dtcp_present,
                                                    "dtcp_present")) {
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int, "dtcp.intial_a")) {
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.initial_a = field_int;
        return 0;
    }

    if (!parse_flowcfg_bool(param, value, &flowcfg.dtcp.flow_control,
                                                "dtcp.flow_control")) {
        flowcfg.dtcp_present = 1;
        return 0;
    }

    if (!parse_flowcfg_bool(param, value, &flowcfg.dtcp.rtx_control,
                                            "dtcp.rtx_control")) {
        flowcfg.dtcp_present = 1;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int, "dtcp.fc.sending_rate")) {
        flowcfg.dtcp.fc.fc_type = RINA_FC_T_RATE;
        flowcfg.dtcp.flow_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.fc.cfg.r.sending_rate = field_int;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int, "dtcp.fc.time_period")) {
        flowcfg.dtcp.fc.fc_type = RINA_FC_T_RATE;
        flowcfg.dtcp.flow_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.fc.cfg.r.time_period = field_int;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int, "dtcp.fc.max_cwq_len")) {
        flowcfg.dtcp.fc.fc_type = RINA_FC_T_WIN;
        flowcfg.dtcp.flow_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.fc.cfg.w.max_cwq_len = field_int;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int,
                                            "dtcp.fc.initial_credit")) {
        flowcfg.dtcp.fc.fc_type = RINA_FC_T_WIN;
        flowcfg.dtcp.flow_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.fc.cfg.w.initial_credit = field_int;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int,
                                        "dtcp.rtx.max_time_to_retry")) {
        flowcfg.dtcp.rtx_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.rtx.max_time_to_retry = field_int;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int,
                                            "dtcp.rtx.data_rxms_max")) {
        flowcfg.dtcp.rtx_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.rtx.data_rxms_max = field_int;
        return 0;
    }

    if (!parse_flowcfg_int(param, value, &field_int,
                                            "dtcp.rtx.initial_tr")) {
        flowcfg.dtcp.rtx_control = 1;
        flowcfg.dtcp_present = 1;
        flowcfg.dtcp.rtx.initial_tr = field_int;
        return 0;
    }

    return -1;
}
int
uipcp_rib::load_qos_cubes(const char *filename)
{
    ifstream fin(filename);
    unsigned int cnt = 1;
    string line;

    if (fin.fail()) {
        PE("Failed to find qoscubes file %s\n", filename);
        return -1;
    }

    for (; getline(fin, line); cnt++) {
        string param, value, cubename;
        size_t pos;

        string_strip(line);
        if (line.size() == 0) {
            continue;
        }

        pos = line.find('=');
        if (pos == string::npos || pos < 1 || line.rfind('=') != pos
                || pos + 1 >= line.size()) {
            PE("Invalid specification at line %u\n", cnt);
            continue;
        }

        param = line.substr(0, pos - 1);
        value = line.substr(pos + 1);
        string_strip(param);
        string_strip(value);

        pos = param.find('.');
        if (pos == string::npos || pos < 1 || pos + 1 >= param.size()) {
            PE("Invalid specification at line %u\n", cnt);
            continue;
        }
        cubename = param.substr(0, pos);
        param = param.substr(pos + 1);
        string_strip(cubename);
        string_strip(param);

        update_qos_cube(qos_cubes[cubename], param, value);
    }

    fin.close();

    return 0;
}

