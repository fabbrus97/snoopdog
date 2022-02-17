from threading import Thread
from statsmodels.tsa.stattools import grangercausalitytests
import pyshark
import pandas as pd
import datetime
import subprocess
import json
import sys


TIMEOUT = 50 #seconds to capture/record video

class Sniff(Thread):
    def __init__(self, name, interface):
        Thread.__init__(self)
        self.name = name
        self.interface = interface
        self.packets = {}
    
    def run(self):
        print ("Thread '" + self.name + "' started 👃🔴")
        
        output_file = "/tmp/mycapture.pcap"
        command = f"sudo tshark -i {self.interface} -a duration:{TIMEOUT} -F pcap -w {output_file}" 
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
            
            
        self.packets = sources
        print("Thread ", self.name, " terminated 👃⚪")


class RecordVideo(Thread):
    def __init__(self, name, camera):
        Thread.__init__(self)
        self.name = name
        self.camera = camera
        self.frames = []
        self.FILENAME = "/tmp/snoopdog.mp4"
    
    def run(self):
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

if len(sys.argv) < 2:
    print("Wrong number of argumens!")
    print(f"Usage: {sys.argv[0]} network_card video_device")
    print(f"e.g.: {sys.argv[0]} eth0 /dev/video0")
    sys.exit(1)

card  = sys.argv[1]
video = sys.argv[2]

command = f"./list_channels.sh {card}"
channels = subprocess.run(command.split(" "), capture_output=True)


channels = str(channels.stdout)

channels = channels.split("\\n"); channels = channels[0:-1]

channels[0] = channels[0][ (len(channels[0])-1) : len(channels[0]) ]

print(f"{len(channels)} channels found!")

channels = [36] #TODO 

for channel in channels:
    print("🔍 Start monitoring on channel", channel)
    command = f"airmon-ng start {card} {channel}"

    if not card.endswith("mon"):
        card += "mon"
    
    subprocess.run(command.split(" "), stdout=subprocess.DEVNULL)

    rv = RecordVideo("record_video", video)
    sniff = Sniff("sniff", card)

    rv.start(); sniff.start(); sniff.join(); rv.join()

    for s in sniff.packets:
        packet_data = []
        i = 0
        while i < len(rv.frames) and i < len(sniff.packets[s]["bytes_per_seconds"]):
            packet_data.append(sniff.packets[s]["bytes_per_seconds"][i])
            i += 1

        d = {'frame': rv.frames[0:i], 'packet': packet_data}
        df = pd.DataFrame(data=d)
        try:
            gtests = grangercausalitytests(df[['frame', 'packet']], maxlag=5, verbose=False)
            #lag = 1
            for lag in gtests:
                if (gtests[lag][0]["ssr_ftest"][1] < 0.08):
                    print(f"👀👀 Is spying! (lag{lag}, device: {s})")
                    
        except Exception as e:
            
            pass
    
    input("\nPress enter to continue")

command = f"airmon-ng stop {card}"
subprocess.run(command.split(" "), stdout=subprocess.DEVNULL)
