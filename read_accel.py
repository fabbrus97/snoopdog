#module to read the smartphone accelerometer
import subprocess
import math
from datetime import datetime
from matplotlib import pyplot as plt

TIMEOUT = 20
folder = "/sdcard/snoopdogg/" 
out_file = f"{folder}accel.out"
script_name = "android.sh"

cmd_mkdir = f"adb shell mkdir {folder}"                      #create working directory on device
cmd_rm = f"adb shell rm {out_file}"                          #delete output file on device
cmd_push = f"adb push {script_name} {folder}"                #load script on device
cmd_script = f"adb shell sh {folder}{script_name} & echo $!" #launch script and print pid on device
cmd_dl = f"adb pull {out_file}"                              #download output file
cmd_polish = f"sed 's/.*(//g' accel.out | sed 's/)/,/g'"     #clean the output file

setup_cmd = [cmd_mkdir, cmd_rm, cmd_push]

def setup():
    for cmd in setup_cmd:
        subprocess.run(cmd.split(" "))

def runscript():
    cmdout = subprocess.run(cmd_script.split(" "), capture_output=True)
    cmdout = cmdout.decode("ascii") #script pid
    print("Started process", cmdout, "on device")
    return cmdout 

def killscript(pid):
    cmd_kill = f"adb shell kill {pid}"

def connect2device(ip):
    cmd_connect = f"adb connect {ip}"

def get_data():
    subprocess.run(cmd_dl.split(" "))
    subprocess.run(cmd_polish.split(" "))
    file = open("accel.out")
    data = file.readlines()
    file.close()


    readings_ts = []
    accel_per_sec = 0
    sec = -1
    r_counter = 0
    for line in data:
        if line.startswith("ts"):
            r_counter += 1
            l = line.split(",")
            if sec == -1:
                sec = int(float(l[0].replace("ts=", "")))
            
            _s = int(float(l[0].replace("ts=", "")))
            if _s != sec:
                ts = l[1].replace(" wall=", "") ; ts = ts[ts.find("."):len(ts)]
                d = {} ; d[ts] = accel_per_sec/r_counter
                readings_ts.append(d)

                r_counter = 0
                accel_per_sec = math.sqrt(float(l[2])**2 + float(l[3])**2 + float(l[4])**2)
                sec = _s
            else:
                accel_per_sec += math.sqrt(float(l[2])**2 + float(l[3])**2 + float(l[4])**2)

    return readings_ts