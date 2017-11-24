if (!exists("unrelfile")) unrelfile='out1.txt'
if (!exists("relfile")) relfile='out2.txt'

set title "Throughput tests"
set xlabel "Packet size (bytes)"
set ylabel "Throughput (Gbps)"
set grid xtics lw 1 lt 0
set grid ytics lw 1 lt 0
set xtics 0,100,1500
set ytics 0,1,13
set key left top
plot unrelfile using 1:($7/1000) title 'Unreliable sender' with linespoints, unrelfile using 1:($9/1000) title 'Unreliable receiver' with linespoints, relfile using 1:($7/1000) title 'Reliable sender/receiver' with linespoints,
pause -1
