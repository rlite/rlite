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
                       help = "Number of trials for each combination "
                              "of parameters")
argparser.add_argument('-c', '--count', type = int, default = 100000,
                       help = "Packet/transaction count for each test")
argparser.add_argument('-g', '--max-sdu-gap', type = int, default = -1,
                       help = "Max SDU gap")
argparser.add_argument('-t', '--test-type', type = str, default = "perf",
                       help = "Test type", choices = ["perf", "rr"])
argparser.add_argument('-d', '--dif', type = str,
                        help = "DIF to use for the tests")
argparser.add_argument('--load', type = str, help = "Dump file to recover")
argparser.add_argument('--dump', type = str, help = "Dump file to output",
                        default = 'perftests.dump')
args = argparser.parse_args()


if args.load:
    fin = open(args.load, 'rb')
    stats = pickle.load(fin)
    fin.close()
    print("Restarting from")
    print(stats)
else:
    stats = dict()
    stats['size'] = []
    stats['snd_kpps'] =  []
    stats['rcv_kpps'] =  []
    stats['snd_mbps'] = []
    stats['rcv_mbps'] = []
    stats['snd_packets'] = []
    stats['rcv_packets'] = []
    stats['snd_transactions'] = []
    stats['snd_latency'] = []


# build QoS
qosarg = ""
if args.max_sdu_gap >= 0:
    qosarg += " -g %s" % args.max_sdu_gap

difarg = ""
if args.dif:
    difarg = " -d %s" % args.dif

try:
    for sz in range(args.size_min, args.size_max, args.size_step):
        cmd = ("rinaperf -s %s -t %s -c %s %s %s"
                % (sz, args.test_type, args.count, qosarg, difarg))
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
                stats['snd_packets'].append(packets)
                stats['snd_kpps'].append(kpps)
                stats['snd_mbps'].append(mbps)

                m = re.match(r'^Receiver\s+(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)', outl[3])
                if m is None:
                    print(out)
                    continue

                packets = int(m.group(1))
                kpps = float(m.group(2))
                mbps = float(m.group(3))
                stats['rcv_packets'].append(packets)
                stats['rcv_kpps'].append(kpps)
                stats['rcv_mbps'].append(mbps)

                stats['size'].append(sz)

                print("%d/%d pkts %.3f/%.3f Kpps %.3f/%.3f Mbps" %
                        (stats['snd_packets'][-1], stats['rcv_packets'][-1],
                            stats['snd_kpps'][-1], stats['rcv_kpps'][-1],
                            stats['snd_mbps'][-1], stats['rcv_mbps'][-1]))

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
                stats['snd_transactions'].append(transactions)
                stats['snd_kpps'].append(kpps)
                stats['snd_mbps'].append(mbps)
                stats['snd_latency'].append(latency)

                stats['size'].append(sz)

                print("%d transactions %.3f Kpps %.3f Mbps %d ns" %
                        (stats['snd_transactions'][-1], stats['snd_kpps'][-1],
                            stats['snd_mbps'][-1], stats['snd_latency'][-1]))

            else:
                assert(False)

except KeyboardInterrupt:
    pass

# dump results
fout = open(args.dump, 'wb')
pickle.dump(stats, fout)
pickle.dump(stats, fout)
fout.close()
