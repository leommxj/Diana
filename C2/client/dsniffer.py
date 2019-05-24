from scapy.all import *
from threading import Thread, Event
from time import sleep
import sqlite3
import re

class DSniffer(Thread):
    def  __init__(self, interface, finder_code, db_file):
        super(DSniffer,self).__init__()

        self.daemon = True

        self.interface = interface
        self.stop_sniffer = Event()
        self.finder_code = finder_code
        self.db_file = db_file

    def run(self):
        sniff(
            iface=self.interface,
            prn=self.on,
            stop_filter=self.should_stop_sniffer,
            store=0
        )
    
    def add_finder(self, code):
        self.finder_code.append(code)


    def join(self, timeout=None):
        self.stop_sniffer.set()
        super(DSniffer,self).join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def on(self, pkt):
        src=pkt.sprintf("%IP.src%")
        dst=pkt.sprintf("%IP.dst%")
        sport=pkt.sprintf("%IP.sport%")
        dport=pkt.sprintf("%IP.dport%")
        raw=pkt.sprintf("%Raw.load%")
        for c in self.finder_code:
            info = ""
            isLeak = False
            exec(c)
            if isLeak == True:
                c = sqlite3.connect(self.db_file, isolation_level=None).cursor()
                c.execute("INSERT INTO DATA(TIME,FROMIP,TOIP,INFO,STATUS) VALUES (?,?,?,?,0)",(time.time(),src,dst,info))