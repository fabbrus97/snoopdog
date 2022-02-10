from threading import Thread
import pyshark
import cv2

TIMEOUT = 50 #seconds to capture/record video

class sniff(Thread):
    def __init__(self, name, interface):
        Thread.__init__(self)
        self.name = name
        self.interface = interface
        self.packet = []
    
    def run(self):
        print ("Thread '" + self.name + "' started")
        capture = pyshark.LiveCapture(interface=self.interface)
        capture.sniff(timeout=TIMEOUT)
        self.packet = capture

class record_video(Thread):
    def __init__(self, name, camera):
        Thread.__init__(self)
        self.name = name
        self.camera = camera
        self.packet = []
    
    def run(self):
        print ("Thread '" + self.name + "' started")
        cap = cv2.VideoCapture(self.camera)
        while(1): 
        # reads frame from a camera 
        ret,frame = cap.read() 
        # Display the frame
        cv2.imshow('Camera',frame) 
        # Wait for 25ms
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break
            
    # release the camera from video capture
    cap.release() 

    # De-allocate any associated memory usage 
    cv2.destroyAllWindows() 