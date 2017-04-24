#!/usr/bin/env python

#
# Author: Vincenzo Maffione <v.maffione@gmail.com>
#

import multiprocessing
import subprocess
import argparse
import re
import os
import pickle


def stats_init(x):
    x['kpps'] =  []
    x['mbps'] = []
    x['packets'] = []
    x['transactions'] = []
    x['latency'] = []


description = "Python script to perform automated tests based on rinaperf"
epilog = "2017 Vincenzo Maffione <v.maffione@gmail.com>"

argparser = argparse.ArgumentParser(description = description,
                                    epilog = epilog)
argparser.add_argument('--size-min', type = int, default = 2,
                       help = "Minimum size for the test")
argparser.add_argument('--size-max', type = int, default = 1400,
                       help = "Maximum size for the test")
argparser.add_argument('--size-step', type = int, default = 10,
                       help = "Packet size increment")
argparser.add_argument('--trials', type = int, default = 3,
                       help = "Number of trials for each combination of parameters")
argparser.add_argument('--count', type = int, default = 100000,
                       help = "Packet/transaction count for each test")
argparser.add_argument('-f', '--flow-control', action='store_true',
                       help = "Enable flow control")
argparser.add_argument('-g', '--max-sdu-gap', type = int, default = -1,
                       help = "Max SDU gap")
argparser.add_argument('-t', '--test-type', type = str, default = "perf",
                       help = "Test type", choices = ["perf", "rr"])
argparser.add_argument('--load', type = str, help = "Dump file to recover")
args = argparser.parse_args()


if args.load:
    fin = open(args.load, 'rb')
    sndstats = pickle.load(fin)
    rcvstats = pickle.load(fin)
    fin.close()
    print("Restarting from")
    print(sndstats)
    print(rcvstats)
else:
    sndstats = dict()
    rcvstats = dict()
    stats_init(sndstats)
    stats_init(rcvstats)

# build QoS
qos = ""
if args.flow_control:
    qos += " -f"
if args.max_sdu_gap >= 0:
    qos += " -g %s" % args.max_sdu_gap

try:
    for sz in range(args.size_min, args.size_max, args.size_step):
        cmd = ("rinaperf -s %s -t %s -c %s %s"
                % (sz, args.test_type, args.count, qos))
        print("Running: %s" % cmd)
        for t in range(args.trials):
            out = subprocess.check_output(cmd.split())
            out = out.decode('ascii')
            outl = out.split('\n')

            if args.test_type == 'perf':

                if len(outl) < 4:
                    print(out)
                    continue

                m = re.match(r'^Sender\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)', outl[2])
                if m is None:
                    print(out)
                    continue

                packets = int(m.group(1))
                kpps = float(m.group(2))
                mbps = float(m.group(3))
                sndstats['packets'].append(packets)
                sndstats['kpps'].append(kpps)
                sndstats['mbps'].append(mbps)

                m = re.match(r'^Receiver\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)', outl[3])
                if m is None:
                    print(out)
                    continue

                packets = int(m.group(1))
                kpps = float(m.group(2))
                mbps = float(m.group(3))
                rcvstats['packets'].append(packets)
                rcvstats['kpps'].append(kpps)
                rcvstats['mbps'].append(mbps)

                print("%d/%d pkts %.3f/%.3f Kpps %.3f/%.3f Mbps" %
                        (sndstats['packets'][-1], rcvstats['packets'][-1],
                            sndstats['kpps'][-1], rcvstats['kpps'][-1],
                            sndstats['mbps'][-1], rcvstats['mbps'][-1]))

            elif args.test_type == 'rr':

                if len(outl) < 3:
                    print(out)
                    continue

                m = re.match(r'^Sender\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+)', outl[2])
                if m is None:
                    print(out)
                    continue

                transactions = int(m.group(1))
                kpps = float(m.group(2))
                mbps = float(m.group(3))
                latency = int(m.group(4))
                sndstats['transactions'].append(transactions)
                sndstats['kpps'].append(kpps)
                sndstats['mbps'].append(mbps)
                sndstats['latency'].append(latency)

                print("%d transactions %.3f Kpps %.3f Mbps %d ns" %
                        (sndstats['transactions'][-1], sndstats['kpps'][-1],
                            sndstats['mbps'][-1], sndstats['latency'][-1]))

            else:
                assert(False)

except KeyboardInterrupt:
    pass

# dump results
fout = open('perftests.dump', 'wb')
pickle.dump(sndstats, fout)
pickle.dump(rcvstats, fout)
fout.close()
