import tornado.ioloop
import tornado.web
import sqlite3
import os
import json
import base64
import sys
import time

DB_FILE = "./data.db"
password="test1"

def xor(input, password):
    r = []
    for i in range(len(input)):
        r.append(chr(ord(input[i]) ^ ord(password[i % len(password)])))
    return "".join(r)


def init_db():
    if os.path.isfile(DB_FILE):
        return sqlite3.connect(DB_FILE, isolation_level=None)
    db_conn = sqlite3.connect(DB_FILE, isolation_level=None)
    c = db_conn.cursor()
    c.execute('''CREATE TABLE SHEEP
        (ID INTEGER PRIMARY KEY NOT NULL,
        DEVICE TEXT NOT NULL,
        TIME TEXT NOT NULL,
        FROMIP TEXT NOT NULL,
        TOIP TEXT NOT NULL,
        INFO TEXT NOT NULL);''')
    c.execute('''CREATE TABLE COMMANDS
        (ID INTEGER PRIMARY KEY NOT NULL,
        Command TEXT NOT NULL,
        PARAM TEXT NOT NULL,
        Status INT NOT NULL);''')
    # c.execute('''CREATE TABLE DATA();
    #     ''')
    c.close()
    return db_conn

class SheepWallHandler(tornado.web.RequestHandler):
    def initialize(self, db_conn):
        self.db = db_conn

    def get(self):
        self.render("Wall.html")

    def post(self):
        c = self.db.cursor()
        r = []
        cursor = c.execute("SELECT id,device,time,fromip,toip,info FROM SHEEP")
        for row in cursor:
            r.append({"id":row[0],"device":row[1],"time":time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(row[2]))),"from":row[3],"to":row[4],"info":row[5]})
        rr = {"code":0,"msg":"","count":len(r),"data":r}
        self.write(json.dumps(rr))


class CommHandler(tornado.web.RequestHandler):
    def initialize(self, db_conn):
        self.db = db_conn

    def get(self,uri):
        global password
        data = json.loads(xor(base64.b64decode(uri).decode("latin1"), password))
        c = self.db.cursor()
        print(data)
        for i in data[1:]:
            c.execute("INSERT INTO SHEEP(device,time,fromip,toip,info) VALUES(?,?,?,?,?)",(i['device'],i['time'],i['fromip'],i['toip'],i['info']))
        cursor = c.execute("SELECT Command,param,id FROM COMMANDS WHERE Status=0")
        commands = []
        for row in cursor:
            commands.append({row[0]:row[1]})
            c.execute("UPDATE COMMANDS SET Status=1 WHERE id=?",(row[2],))
        self.write(base64.b64encode(xor(json.dumps(commands),password).encode("latin1")))


class CommandHandler(tornado.web.RequestHandler):
    def initialize(self, db_conn):
        self.db = db_conn

    def get(self):
        c = self.db.cursor()
        cursor = c.execute("SELECT id,Command,param,status FROM COMMANDS")
        r = []
        for row in cursor:
            r.append({"id":row[0],"command":row[1],"param":row[2],"status":"已执行" if row[3]==1 else "等待执行"})
        c.close()
        rr = {"code":0,"msg":"","count":len(r),"data":r}
        self.write(json.dumps(rr))

    def post(self):
        c = self.db.cursor()
        new_command = self.get_body_argument("command")
        new_param = self.get_body_argument("param")
        c.execute("INSERT INTO COMMANDS(Command,Param,Status) VALUES(?,?,0)",(new_command,new_param,))
        c.close()
        self.write("Success")

class ClearHandler(tornado.web.RequestHandler):
    def initialize(self, db_conn):
        self.db = db_conn
    
    def get(self):
        c = self.db.cursor()
        c.execute("DELETE FROM sqlite_sequence WHERE name = 'sheep';")
        c.execute("DELETE FROM sqlite_sequence WHERE name = 'commands';")
        c.commit()
        c.close()


if __name__ == "__main__":
    db_conn = init_db()
    app = tornado.web.Application([
        (r"/Wall", SheepWallHandler, dict(db_conn=db_conn)),
        (r"/Commands", CommandHandler, dict(db_conn=db_conn)),
        (r"/Clear", ClearHandler, dict(db_conn=db_conn)),
        (r"/(.*)", CommHandler, dict(db_conn=db_conn)),
    ])
    app.listen(80)
    tornado.ioloop.IOLoop.current().start()