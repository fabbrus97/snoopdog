#module to read the smartphone accelerometer
import subprocess
import math
from datetime import datetime
from matplotlib import pyplot as plt

TIMEOUT = 20
command = "adb shell dumpsys sensorservice | grep -A50 'accel:' | sed 's/.*(//g' | sed 's/)/,/g'"
#the above command takes the data of the sensorservice, takes only the accelerometer data, then
#with sed removes some characters at the beginning of the line and substitute a ')' with a ','

raw = []
readings = []
start = datetime.now()
s_now = 0 #DEBUG
while True:
    cmdout = subprocess.run(command.split(" "), capture_output=True)
    raw.append(cmdout.stdout)
    now = datetime.now()
    if (now - start).seconds > s_now: #DEBUG
        print(s_now)
        s_now = (now - start).seconds 

    if (now - start).seconds > TIMEOUT:
        break

for r in raw:
    accel_per_sec = 0
    sec = -1
    r_counter = 0
    for line in r.decode('ascii').split('\n'):
        if line.startswith("ts"):
            r_counter += 1
            l = line.split(",")
            if sec == -1:
                sec = int(float(l[0].replace("ts=", "")))
            
            _s = int(float(l[0].replace("ts=", "")))
            if _s != sec:
                readings.append(accel_per_sec/r_counter)
                r_counter = 0
                accel_per_sec = math.sqrt(float(l[2])**2 + float(l[3])**2 + float(l[4])**2)
                sec = _s
            else:
                accel_per_sec += math.sqrt(float(l[2])**2 + float(l[3])**2 + float(l[4])**2)


plt.scatter(range(0, len(readings)), readings)
plt.show()