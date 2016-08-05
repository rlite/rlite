# Requires the following packages
#  math/py-matplotlib
#  math/py-numpy

import matplotlib.pyplot as plt
import numpy as np
import sys
import re


# set default values
title = 'Input'
ylabel = 'y'
xlabel = 'x'
legend = 'upper left'
#linestyles = ['x', '--', ':', 'o', 'v', 's', '+', '1', '2', '3', '4' ]
linestyles = ['x-', '^-', 'o-', 's-', 'v-', '2-', '3-', '4-']
#for more linestyles see "http://matplotlib.org/api/pyplot_api.html#matplotlib.pyplot.plot"

x = []
y = []
for line in sys.stdin:
    line = line.replace('\n', '').replace('\t', ' ')
    tup = line.split()
    x.append(float(tup[0]))
    y.append(float(tup[1]))

# Graphics
plt.title(title)
if xlabel:
    plt.xlabel(xlabel, fontsize=18)
plt.ylabel(ylabel, fontsize=18)
#plt.ylim([0, best_result * 1.1])
leg = []
lab = []

xspan = x[-1] - x[0]
LEFT_OFFSET = 0.05*xspan
plt.xlim([x[0]-LEFT_OFFSET, x[-1]+LEFT_OFFSET])

# make plots in blue or black ?
#style = '.-'
style = '.'
pl = plt.plot(x, y, style, linewidth=2,
                markersize = 2, antialiased=True)
leg.append(pl[0])
lab.append('independent variable')

plt.legend(leg, lab, legend, prop={'size': 16})
plt.show()  #debug
#outfn = sys.argv[1].rsplit('.',1)[0]
#plt.savefig(outfn + '.eps')

