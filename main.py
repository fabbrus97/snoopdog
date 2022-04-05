from threading import Thread
from statsmodels.tsa.stattools import grangercausalitytests
import pyshark
import pandas as pd
import math
import datetime
import subprocess
import sys
import read_accel


TIMEOUT = 50 #seconds to capture/record video

def sniff(interface):
    print ("Sniff started 👃🔴")

    output_file = "/tmp/mycapture.pcap"
    command = f"sudo tshark -i {interface} -a duration:{TIMEOUT} -F pcap -w {output_file}" 
    subprocess.run(command.split(" "))
    capture = pyshark.FileCapture(output_file)
    capture.load_packets()
    
    sources = {}
    start_time = int(float(capture[0].sniff_timestamp))

    i = 0
    for frame in capture:
        print(i, "/", len(capture), end="\r")
        i += 1
        try:
            sa = frame.wlan.get("sa")
            if not sa: #some packets do not have 'sa' field but 'ta' for reasons?
                sa = frame.wlan.get("ta")
                if not sa:
                    continue #we don't have a valid source address
            fl = int(frame.length)
            _time = int(float(frame.sniff_timestamp))

            if sources.get(sa): #source address
                if _time - sources[sa]["time"] == 0:

                    sources[sa]["bytes_per_seconds"][sources[sa]["time"] - start_time] += fl
                elif _time - sources[sa]["time"] == 1:
                    sources[sa]["time"] = _time
                    sources[sa]["bytes_per_seconds"].append(fl)
                else: 
                    for i in range(sources[sa]["time"], _time):
                        sources[sa]["bytes_per_seconds"].append(0)
                    sources[sa]["time"] = _time
                    sources[sa]["bytes_per_seconds"].append(fl)
            
            else:
                sources[sa] = {
                    "bytes_per_seconds": [int(frame.length)],
                    "time": int(float(capture[0].sniff_timestamp))
                    }
        except Exception as e:
            pass
        
        
    print("Sniff terminated 👃⚪")
    return sources
    

class RecordVideo(Thread):
    def __init__(self, name, camera):
        Thread.__init__(self)
        self.name = name
        self.camera = camera
        self.frames = []
        self.FILENAME = "/tmp/snoopdog.mp4"
    
    def run(self):
        raw = []
        readings = []
        start = datetime.now()
        while True:
            cmdout = subprocess.run(command.split(" "), capture_output=True)
            raw.append(cmdout.stdout)
            now = datetime.now()

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

        self.frames = readings

        print("Thread ", self.name, " terminated 📹⚪")

        """
        print ("Thread '" + self.name + "' started 📹🔴")
        command = f"ffmpeg -y -t {TIMEOUT} -i {self.camera} -vcodec h264 {self.FILENAME} -pix_fmt yuv420p -f sdl 'snoopdog'"
        
        subprocess.run(command.split(" "), capture_output=True)


        command = f"ffprobe -show_frames -print_format json {self.FILENAME}"
        cmdout = subprocess.run(command.split(" "), capture_output=True)

        frames = json.loads(cmdout.stdout) 

        sizes = {}

        for frame in frames["frames"]:
            ts = int(float(frame["best_effort_timestamp_time"]))
            if not sizes.get(ts):
                sizes[ts] = 0
            sizes[ts] += int(frame["pkt_size"])

        self.frames = list(sizes.values())

        print("Thread ", self.name, " terminated 📹⚪")
        """

if len(sys.argv) < 2:
    print("Wrong number of argumens!")
    print(f"Usage: {sys.argv[0]} network_card device")
    print(f"e.g.: {sys.argv[0]} eth0 192.168.1.2:5555")
    sys.exit(1)

card  = sys.argv[1]
device = sys.argv[2]

command = f"./list_channels.sh {card}"
#channels = subprocess.run(command.split(" "), capture_output=True) TODO


# channels = str(channels.stdout)

# channels = channels.split("\\n"); channels = channels[0:-1]

# channels[0] = channels[0][ (len(channels[0])-1) : len(channels[0]) ]

# print(f"{len(channels)} channels found!")

channels = [36] #TODO 

read_accel.connect2device(device)
read_accel.setup()
read_accel.runscript()

sniffed_channels = []

for channel in channels:
    print("🔍 Start monitoring on channel", channel)
    #now we lose connection to the device
    command = f"airmon-ng start {card} {channel}"

    if not card.endswith("mon"):
        card += "mon"
    
    subprocess.run(command.split(" "), stdout=subprocess.DEVNULL)

    #rv = RecordVideo("record_video", video)
    sniff_data = sniff(card)

    sniffed_channels.append(sniff_data)
    
    input("\nPress enter to continue")

read_accel.killscript()
accel_data = read_accel.get_data()

for packets in sniffed_channels:
    a_data = []
    packet_data = []
    for s in packets:
        
        i = 0
        timestamp = sniff.packets[s]["time"]
        j = 0 #index for accel data
        for a in accel_data:
            if accel_data.get(timestamp):
                break
            j += 1
        

        for i in range(j, TIMEOUT):
            a_data.append(list(accel_data[i].values())[0])
        
        packet_data = sniff.packets[s]["bytes_per_seconds"]

        d = {'frame': a_data, 'packet': packet_data}
        df = pd.DataFrame(data=d)
        try:
            gtests = grangercausalitytests(df[['frame', 'packet']], maxlag=5, verbose=False)
            #lag = 1
            for lag in gtests:
                if (gtests[lag][0]["ssr_ftest"][1] < 0.08):
                    print(f"👀👀 Is spying! (lag{lag}, device: {s})")
                    
        except Exception as e:
            
            pass


command = f"airmon-ng stop {card}"
subprocess.run(command.split(" "), stdout=subprocess.DEVNULL)
