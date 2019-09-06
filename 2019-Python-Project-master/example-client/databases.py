import sqlite3
import nacl.signing
import nacl.encoding
import cherrypy
from datetime import datetime

def initdatabases():
    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users' ''')

    if c.fetchone()[0] > 0:
        conn.close()
        return
    else:
        c.execute("create table users (signingKey text not null, username blob not null, password blob not null)")

    conn.close()

def initContentFiltering():

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='filtering' ''')

    if c.fetchone()[0] > 0:
        conn.close()
    else:
        c.execute("create table filtering (id integer primary key autoincrement, badWord text not null, goodWord text not null)")
        conn.close()
        addDataToFilter()


def addDataToFilter():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("insert into filtering (badWord, goodWord) values ('fuck', 'f***')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('raj', 'Mr.gymshark')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('bitch', 'b****')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('cunt', 'c***')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('shit', 's***')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('nigger', 'n*****')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('nigga', 'n****')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('slut', 's***')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('whore', 'w****')")
    conn.commit()
    c.execute("insert into filtering (badWord, goodWord) values ('dick', 'd***')")
    conn.commit()
    conn.close()

def initmessages():
    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='publicbroadcast' ''')

    if c.fetchone()[0] > 0:
        conn.close()
        return
    else:
        c.execute("create table publicbroadcast (id integer primary key autoincrement, username text not null, "
                  "message text, created_time text not null, pubkey text not null)")

    conn.close()

def initprivatemessages():
    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='privateMessage' ''')

    if c.fetchone()[0] > 0:
        conn.close()
        return
    else:
        c.execute("create table privateMessage (id integer primary key autoincrement, target_username text not null, "
                  "username text not null, "
                  "message text, created_time text not null, pubkey text not null)")

    conn.close()

def checkUser(username, password):

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT signingKey FROM users WHERE username=? and password=?", (username, password))

    rows = c.fetchone()

    if rows is not None:
        strHold = rows[0]
        hold = str(strHold)
        hold_loaded = str.encode(hold)
        signing_key_generated = nacl.signing.SigningKey(hold_loaded, encoder=nacl.encoding.HexEncoder)
        cherrypy.session['signing_key'] = signing_key_generated
        conn.commit()
        conn.close()
         # pulling previous signing key from the data base
    else:
        signing_key = nacl.signing.SigningKey.generate()
        cherrypy.session['signing_key'] = signing_key
        adduser(signing_key, username, password)
        conn.commit()
        conn.close()


def adduser(signing_key, username, password):

    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    signing_key_hex = signing_key.encode(encoder=nacl.encoding.HexEncoder)
    signing_key_str = signing_key_hex.decode('utf-8')

    c.execute("insert into users (signingKey, username, password) values (?,?,?)", (signing_key_str, username, password))

    conn.commit()
    conn.close()

def recievePublicMessage(username, message, time, pubkey):

    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    message = message.replace("<","")
    message = message.replace(">","")


    c.execute("insert into publicbroadcast (username, message, created_time, pubkey) values (?,?,?,?)", (username, message, time, pubkey))

    conn.commit()
    conn.close()

def recievePrivateMessage(target_username, username, message, time, pubkey):

    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute("insert into privateMessage (target_username, username, message, created_time, pubkey) values (?,?,?,?,?)", (target_username, username, message, time, pubkey))

    conn.commit()
    conn.close()

def readPublicBroadcast():

    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute('SELECT * FROM publicbroadcast ORDER BY id DESC')
    data = c.fetchall()
    c.execute('SELECT * FROM filtering')
    filtering_val = c.fetchall()
    Page = '<table align="center" class="table">'
    for row in data:
        stamp = datetime.fromtimestamp(float(row[3]))
        stamp_trimmed, cutt_off = (str(stamp)).split(".")
        string_out = row[2]
        for record in filtering_val:
            if (row[2].lower()).find(record[1]) != -1:
                string = row[2].lower()
                string_out = string.replace(record[1], record[2])

        Page += '<tr><td></td><td></td><td></td><td><td></td><td></td><td></td><td>'
        Page += '<a style="color:grey">' + stamp_trimmed + '</a>' + ' <h4>' + row[1] + '</h4>' + string_out
        Page += '</td><td></td></td><td></td><td></td><td></td></td><td></td></tr>'

    Page += '</table>'

    return Page

def searchPublicBroadcast(toFind):

    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute('SELECT * FROM publicbroadcast ORDER BY id DESC')
    data = c.fetchall()
    c.execute('SELECT * FROM filtering')
    filtering_val = c.fetchall()
    Page = '<table align="center" class="table">'
    resultFound = 0

    for row in data:
        stamp = datetime.fromtimestamp(float(row[3]))
        stamp_trimmed, cutt_off = (str(stamp)).split(".")
        if (row[2].lower()).find(toFind.lower()) != -1 or (row[1].lower()).find(toFind.lower()) != -1:
            resultFound += 1
            string_out = row[2]
            for record in filtering_val:
                if (row[2].lower()).find(record[1]) != -1:
                    string = row[2].lower()
                    string_out = string.replace(record[1], record[2])

            Page += '<tr><td></td><td></td><td></td><td>'
            Page += '<a style="color:grey">' + stamp_trimmed + '</a>' +'<h4>' + row[1] + '</h4>' + string_out
            Page += '</td><td></td></td><td></td><td></td></tr>'

    Page += '</table>'

    if resultFound == 0:
        Page += '<div align="center"><td>No post contains your search</br>'
        Page += 'Feel free to search for another</td></div>'

    return Page

def readPrivateBroadcast(username, targetUser):

    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute('SELECT * FROM privateMessage ORDER BY id DESC')
    data = c.fetchall()

    Page = '<table align="center" class="table">'

    i = 0

    for row in data:
        try:
            if (cherrypy.session['username'] == row[2] and targetUser == row[1]) or (cherrypy.session['username'] == row[1] and targetUser == row[2]):
                message_bytes = bytes(row[3], encoding='utf-8')
                privateKey = cherrypy.session['signing_key'].to_curve25519_private_key()
                unseal_box = nacl.public.SealedBox(privateKey)
                decrypted_message = unseal_box.decrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
                message = decrypted_message.decode('utf-8')
                i += 1

                try:
                    stamp = datetime.fromtimestamp(float(row[4]))
                    stamp_trimmed, cutt_off = (str(stamp)).split(".")
                except:
                    print("no message")

                c.execute('SELECT * FROM filtering')
                filtering_val = c.fetchall()
                string_out = message
                for record in filtering_val:
                    if (message.lower()).find(record[1]) != -1:
                        string_out = (message.lower()).replace(record[1], record[2])
                        message = string_out

                if cherrypy.session['username'] == row[2]:
                    Page += '<tr><td></td><td></td><td align="right">'
                    Page += '<a style="color:grey">' + stamp_trimmed + '</a>' +'<h4>' + row[2] + '</h4>' + string_out
                    Page += '</td><td></td><td></td></tr>'
                else:
                    Page += '<tr><td></td><td></td><td>'
                    Page += '<a style="color:grey">' + stamp_trimmed + '</a>' +'<h4>' + row[2] + '</h4>' + string_out + '</br>'
                    Page += '</td><td></td><td></td></tr>'

        except:
            print("not your message")

    Page += '</table>'

    if i == 0:
        Page += '<div align="center"><td>No previous conversation recorded</br>'
        Page += 'check if user exists and is online to Private Message</td></div>'

    conn.close()
    return Page

def initActiveUser():
    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='usersActive' ''')

    if c.fetchone()[0] > 0:
        conn.close()
        return
    else:
        c.execute("create table usersActive (username text not null, address text not null, location text not null,"
                  " incomingKey text not null, lastUpdate text not null, status text not null)")

    conn.close()

def updateActiveUsers(users):
    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute('DELETE FROM usersActive')
    conn.commit()

    for row in users:
        try:
            c.execute("insert into usersActive (username, address, location, incomingKey, lastUpdate, status)"
                      " values (?,?,?,?,?,?)", (row['username'], row['connection_address'], row['connection_location'], row['incoming_pubkey'], row['connection_updated_at'], row['status']))
            conn.commit()
        except sqlite3.IntegrityError:
            print("eh")

    conn.close()

def readActiveUsers():
    conn = sqlite3.connect("database.db")

    c = conn.cursor()

    c.execute('SELECT username FROM usersActive')

    data = c.fetchall()

    x = []

    for row in data:
        x.append(row[0])

    return x
