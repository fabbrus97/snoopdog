
# Snoopdog 
Snoopdog is a framework to detect if there is a bug spying on us. For reference, check out Singh et al., «I Always Feel Like Somebody’s Sensing Me! A Framework to Detect, Identify, and Localize Clandestine Wireless Sensors».

In this repository there is a simple python implementation; it only checks if there is a camera sniffing the wifi. The ground sensor is a smartphone to detect if the user is moving. 

### Prerequisites
To run this project, some python dependencies are needed: 

* ```statsmodel```
* ```pyshark```

Furthermore, you will need ```tshark ``` to run ```pyshark```, ```adb```  to get accelerometer data and ```airmon-ng``` to set your wireless card in capture mode.

### How it works
Just launch the program with:

				sudo -E python3 main.py

The program will scan all the available network frequencies, and wait for you to record your movements: you must stay still, then do some jumping jacks a couple of time for every frequency found. 

At the end of the analysis, if the probability p in the granger causality test for some gap is less than 0.05, the program will warn you that somebody may be spying on you.
