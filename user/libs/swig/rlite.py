# Simple python API for rlite, which is higher level than rlite_raw
#
# Written by: Vincenzo Maffione <v.maffione@gmail.com>

import rlite_raw as rl


class RinaName:

    def __init__(self, apn = None, api = None, aen = None, aei = None):
        self.nm_ = rl.rina_name()
        rl.rina_name_fill(self.nm_, apn, api, aen, aei)


    def __del__(self):
        rl.rina_name_free(self.nm_)


    def __repr__(self):
        return rl.rina_name_to_string(self.nm_)


    def set(self, apn = None, api = None, aen = None, aei = None):
        self.__del__()
        self.__init__(apn, api, aen, aei)



class RliteFlowSpec:

    def __init__(self, cubename = None):
        self.fp_ = rl.rlite_flow_spec()
        self.set(cubename)

    def set(self, cubename = None):
        if cubename:
            self.fp_.cubename = cubename
        else:
            rl.rl_flow_spec_default(self.fp_)

    def __repr__(self):
        return "Cubename[%s]" % (self.fp_.cubename, )



class RliteCtrl:

    def __init__(self):
        self.rc = rl.rlite_ctrl()
        ret = rl.rl_ctrl_init(self.rc, None)
        if ret:
            raise Exception("Failed to open rlite ctrl device")
        self.registered = 0


    def __del__(self):
        rl.rl_ctrl_fini(self.rc)


    def register(self, dif, local_name):
        ret = rl.rl_ctrl_register(self.rc, dif, local_name.nm_)
        if ret:
            return Exception("Failed to register %s to DIF %s" % (dif, local_name))
        self.registered += 1


    def unregister(self, dif, local_name):
        ret = rl.rl_ctrl_unregister(self.rc, dif, local_name.nm_)
        if ret:
            return Exception("Failed to unregister %s to DIF %s" % (dif, local_name))
        self.registered -= 1


    def flow_accept(self):
        if self.registered < 1:
            return Exception("No name registered yet")

        fd = rl.rl_ctrl_flow_accept(self.rc)
        if fd < 0:
            return Exception("Failed to accept flow")

        return fd


    def flow_alloc(self, dif, local_name, remote_name, flow_spec = None):
        if flow_spec == None:
            flow_spec = RliteFlowSpec()

        fd = rl.rl_ctrl_flow_alloc(self.rc, dif, local_name.nm_, remote_name.nm_, flow_spec.fp_)
        if fd < 0:
            return Exception("Failed to allocate flow")

        return fd
