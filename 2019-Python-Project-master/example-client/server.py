import cherrypy
import urllib.request
import json
import requests
import base64
import nacl.encoding
import nacl.signing
import htmlbody
import databases
import time
import socket
import sqlite3

cherrypySession = []
IP_port = socket.gethostbyname(socket.gethostname()) + ":10050"
Connection_type = 0

print(IP_port)



startHTML = """<html><head><title>CS302 example</title><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script></head><body>"""
# loginHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/loginForm.css' /></head><body>"

class MainApp(object):
    # CherryPy Configuration
    cp_config = {'tools.encode.on': True,
                 'tools.encode.encoding': 'utf-8',
                 'tools.sessions.on': 'True',
                 }



    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML
        try:
            Page += htmlbody.homePage
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text because you've logged in! <a href='/signout'>Sign out</a>"
        except KeyError:  # There is no username

            raise cherrypy.HTTPRedirect('/login')

        return Page

    @cherrypy.expose
    def status(self):
        try:
            reportToServer()
            Page = startHTML
            Page += htmlbody.homePage
            Page += '<div align="center">'
            Page += '<div align="center"><a class="navbar-brand">MANAGE STATUS</a></div>'
            Page += '<form action="/manageStatus" method="post">'
            Page += '<input type="submit" name="status" value="online"/><input type="submit"  name="status" value="busy"/><input type="submit"  name="status" value="away"/><input type="submit"  name="status" value="offline"/></form>'
            Page += '</div>'
        except KeyError:
            raise cherrypy.HTTPRedirect('/login')

        return Page

    @cherrypy.expose
    def manageStatus(self, status):

        changeStatus(status)
        raise cherrypy.HTTPRedirect('/status')


    @cherrypy.expose
    def public(self):
        try:
            reportToServer()
            print("made it into broadcast")
            Page = startHTML
            Page += htmlbody.homePage
            Page += '<div align="center"><a class="navbar-brand">POST TO PEERS</a></div>'
            Page += '<form action="/publicMessage" method="post" enctype="multipart/form-data">'
            Page += '<div align ="center"><input type="text" name="message" placeholder="public broadcast"/><input type="submit" value="SEND"/></form></div>'
            Page += '<form action="/search_post">'
            Page += '<div align="center"><a class="navbar-brand">FILTER POSTS</a></div>'
            Page += '<div align ="center"><input type="text" name="searchpost" placeholder="search post"/><input type="submit" value="SEARCH"/></form></div>'
            Page += '<div align="center"><a class="navbar-brand">PUBLIC BROADCASTS RECIEVED</a></div>'
            Page += databases.readPublicBroadcast()

            return Page
        except KeyError:
            raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def search_post(self, searchpost):
        try:
            reportToServer()
            Page = startHTML
            Page += htmlbody.homePage
            Page += '<div align="center"><a class="navbar-brand">POST TO PEERS</a></div>'
            Page += '<form action="/publicMessage" method="post" enctype="multipart/form-data">'
            Page += '<div align ="center"><input type="text" name="message" placeholder="public broadcast"/><input type="submit" value="SEND"/></form></div>'
            Page += '<form action="/search_post">'
            Page += '<div align="center"><a class="navbar-brand">FILTER POSTS</a></div>'
            Page += '<div align ="center"><input type="text" name="searchpost" placeholder="search post"/><input type="submit" value="SEARCH"/></form></div>'
            Page += '<div align="center"><a class="navbar-brand">PUBLIC BROADCASTS RECIEVED</a></div>'
            Page += databases.searchPublicBroadcast(searchpost)
            return Page
        except KeyError:
            raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def publicMessage(self, message):
        try:
            reportToServer()
            sendPublicBroadcast(message)
            print("IM BROADCASTING")
            print(message)
            raise cherrypy.HTTPRedirect('/public')
        except KeyError:
            raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def private(self):

        try:
            #cherrypy.session['currentConvo']
            raise cherrypy.HTTPRedirect('/privateStarted')
        except:
            try:
                reportToServer()
                print("made it into broadcast")

                Page = startHTML
                Page += htmlbody.homePage
                Page += '<form action="/privateMessageConvo">'
                Page += '<div align ="center"><input type="text" name="SearchConvo" placeholder="search for user to PM"/><input type="submit" value="SEARCH"/></form></div>'

                return Page
            except:
                raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def privateStarted(self):
        try:
            reportToServer()
            Page = startHTML
            Page += htmlbody.homePage
            Page += '<form action="/privateMessageConvo">'
            Page += '<div align ="center"><input type="text" name="SearchConvo" placeholder="search for user to PM"/><input type="submit" value="SEARCH"/></form></div>'
            Page += '<form action="/privateMessage" method="post" enctype="multipart/form-data">'
            Page += '<div align="center"><a class="navbar-brand">CHOSEN CHAT</a></div>'
            Page += '<div align ="center"><input type="text" name="targetUser" value="' + cherrypy.session['currentConvo'] + '"/><input type="text" name="message" placeholder="type reply"/><input type="submit" value="SEND"/></form></div>'
            Page += '<div align="center"><a class="navbar-brand">PRIVATE CONVERSATION</a></div>'
            Page += databases.readPrivateBroadcast(cherrypy.session['username'], cherrypy.session['currentConvo'])

            return Page
        except:
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def privateMessageConvo(self, SearchConvo):
        try:
            reportToServer()
            cherrypy.session['currentConvo'] = SearchConvo
            Page = startHTML
            Page += htmlbody.homePage
            Page += '<form action="/privateMessageConvo">'
            Page += '<div align ="center"><input type="text" name="SearchConvo" placeholder="search for user to PM"/><input type="submit" value="SEARCH"/></form></div>'
            Page += '<form action="/privateMessage" method="post" enctype="multipart/form-data">'
            Page += '<div align="center"><a class="navbar-brand">CHOSEN CHAT</a></div>'
            Page += '<div align ="center"><input type="text" name="targetUser" value="' + SearchConvo + '"/><input type="text" name="message" placeholder="type reply"/><input type="submit" value="SEND"/></form></div>'
            Page += '<div align="center"><a class="navbar-brand">PRIVATE CONVERSATION</a></div>'
            Page += databases.readPrivateBroadcast(cherrypy.session['username'], SearchConvo)

            return Page
        except KeyError:
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def privateMessage(self, message, targetUser):
        try:
            sendPrivateMessage(targetUser, message)
            print("Private Message Sent")
            raise cherrypy.HTTPRedirect('/privateStarted')
        except KeyError:
            raise cherrypy.HTTPRedirect('/index')


    @cherrypy.expose
    def users(self):
        try:
            reportToServer()
            print("made it into broadcast")

            Page = startHTML
            Page += htmlbody.homePage
            Page += '<div align="center"><a class="navbar-brand">ACTIVE USERS</a></div>'
            Page += '<form action="/search_user">'
            Page += '<div align ="center"><input type="text" name="searchuser" placeholder="search username"/><input type="submit" value="SEARCH"/></form></div>'
            Page += htmlbody.userTableHeaders

            userList = listUsers()

            for user in userList:
                Page +="""<tr">
                            <td>"""+str(user["username"])+"""</td>
                            <td></td>
                            <td>"""+str(user["status"])+"""</td>
                            <td></td>
                            <td>"""+str(user["connection_location"])+"""</td>
                            <td></td>
                            <td>"""+str(user["connection_address"])+"""</td>
                            <td></td>
                            <td>"""+str(user["connection_updated_at"])+"""</td>
                            <td></td>
                            <td>"""+str(user["incoming_pubkey"])+"""</td>
                            </tr>"""

            Page += '</table>'

            return Page
        except KeyError:
            raise cherrypy.HTTPRedirect('/login')

    @cherrypy.expose
    def search_user(self, searchuser):
        try:
            reportToServer()
            print("made it into broadcast")

            Page = startHTML
            Page += htmlbody.homePage
            Page += '<div align="center"><a class="navbar-brand">ACTIVE USERS</a></div>'
            Page += '<form action="/search_user">'
            Page += '<div align ="center"><input type="text" name="searchuser" placeholder="search username"/><input type="submit" value="SEARCH"/></form></div>'
            Page += htmlbody.userTableHeaders

            userList = listUsers()
            userFound = 0
            for user in userList:
                if (user["username"].lower()).find(searchuser.lower()) != -1:
                    userFound = 1
                    Page +="""<tr">
                                <td>"""+str(user["username"])+"""</td>
                                <td></td>
                                <td>"""+str(user["status"])+"""</td>
                                <td></td>
                                <td>"""+str(user["connection_location"])+"""</td>
                                <td></td>
                                <td>"""+str(user["connection_address"])+"""</td>
                                <td></td>
                                <td>"""+str(user["connection_updated_at"])+"""</td>
                                <td></td>
                                <td>"""+str(user["incoming_pubkey"])+"""</td>
                                </tr>"""

            Page += '</table>'

            if userFound == 0:
                Page += '<div align="center"><h5>User is not Online (or typo made in search)</h5></div>'

            return Page
        except KeyError:
            raise cherrypy.HTTPRedirect('/login')


    @cherrypy.expose
    def login(self, bad_attempt=0):
        databases.initdatabases()
        databases.initmessages()
        databases.initprivatemessages()
        databases.initContentFiltering()
        databases.initActiveUser()
        Page = startHTML
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += htmlbody.loginForm
        # Page += 'Username: <input type="text" name="username"/><br/>'
        # Page += 'Password: <input type="text" name="password"/>'
        # Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        try:
            loadAPI_key(username, password)
            databases.checkUser(username, password)
            print("API KEY")
            signing_key = cherrypy.session['signing_key']

            pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
            pubkey_hex_str = pubkey_hex.decode('utf-8')

            message_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
            signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
            signature_hex_str = signed.signature.decode('utf-8')

            addPubkey(pubkey_hex_str, signature_hex_str)

            error = authoriseUserLogin(pubkey_hex_str)

            headers = {
                'X-username': username,
                'X-apikey': cherrypy.session['api_key'],
                'Content-Type': 'application/json; charset=utf-8',
            }

            loginserver_record_get = requests.get(url="http://cs302.kiwi.land/api/get_loginserver_record", headers=headers).json()
            loginserver_record = loginserver_record_get["loginserver_record"]

            print(error)
            if error != 1:
                cherrypy.session['pubkey_hex_str'] = pubkey_hex_str
                cherrypy.session['signature_hex_str'] = signature_hex_str
                cherrypy.session['loginserver_record'] = loginserver_record
                getListAPI()
                userList = listUsers()
                requests.get(url="http://cs302.kiwi.land/api/check_pubkey", headers=headers)
                ping()
                raise cherrypy.HTTPRedirect('/')
            else:
                raise cherrypy.HTTPRedirect('/login?bad_attempt=1')
        except:
            raise cherrypy.HTTPRedirect('/index')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


# Functions after this point implement APIS

def ping_check(address):
    url = "http://"+str(address)+"/api/ping_check"

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    myTime = str(time.time())

    payload = {
        "my_time": myTime,
        "connection_address": IP_port,
        "connection_location": Connection_type,
    }

    payloadJSON = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payloadJSON, headers=headers)
        response = urllib.request.urlopen(req, timeout=1)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        JSON_object = json.loads(data.decode(encoding))
        serverRecord = JSON_object["response"]
        print(serverRecord)
        if serverRecord == "ok":
            return 1
        else:
            return 0

        response.close()
        print("We pinging \n")
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        print("Failed key add \n")
        return 0
    except:
        return 0


def changeStatus(status):
    url = "http://cs302.kiwi.land/api/report"

    # STUDENT TO UPDATE THESE...

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        # STUDENT TO COMPLETE THIS...
        "connection_address": IP_port,
        "connection_location": Connection_type,
        "incoming_pubkey": cherrypy.session['pubkey_hex_str'],
        "status": status,
    }
    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
        print('we in boys')
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        return 1

def reportToServer():
    url = "http://cs302.kiwi.land/api/report"

    # STUDENT TO UPDATE THESE...

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    users = listUsers()
    for row in users:
        if cherrypy.session['username'].lower() == row['username'].lower():
            status = row['status']

    try:
        payload = {
            # STUDENT TO COMPLETE THIS...
            "connection_address": IP_port,
            "connection_location": Connection_type,
            "incoming_pubkey": cherrypy.session['pubkey_hex_str'],
            "status": status,
        }
    except UnboundLocalError:
        raise cherrypy.HTTPRedirect('/index')

    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
        print('we in boys')
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        return 1

def loadAPI_key(username, password):
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    # create HTTP BASIC authorization header
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
    }
    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        JSON_object = json.loads(data.decode(encoding))
        api_key = JSON_object["api_key"]
        cherrypy.session['api_key'] = api_key
        cherrypy.session['username'] = username
        cherrypy.session['password'] = password
        cherrypySession.clear()
        cherrypySession.append(api_key)
        cherrypySession.append(username)
        print("user details saved")
        response.close()
        print("Added API key successfully \n")
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        print("Failed APIkey add \n")
    except:
        raise cherrypy.HTTPRedirect('/index')

def sendPrivateMessage(targetUser, message_input):

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    myTime = str(time.time())

    message = bytes(message_input, encoding='utf-8')  # add html to take input

    userList = listUsers()

    userOnline = 0

    for user in userList:

        if user["username"] == targetUser:
            userOnline = 1
            print(user["username"])
            ping_check(user['connection_address'])
            url = "http://" + str(user['connection_address']) + "/api/rx_privatemessage"
            # r = requests.get(url="http://" + str(user['connection_address']) + "/api/loginserver_pubkey").json()  # somehow make it find pubkey for user to pm
            loginserver_pubkey = user["incoming_pubkey"]


    if userOnline == 0:
        print("not online")
        return

    verifyKey = nacl.signing.VerifyKey(loginserver_pubkey, encoder=nacl.encoding.HexEncoder)
    publickey = verifyKey.to_curve25519_public_key()

    sealed_box = nacl.public.SealedBox(publickey)
    encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
    message_b = encrypted.decode('utf-8')

    signature_bytes = bytes(str(cherrypy.session['loginserver_record']) + loginserver_pubkey + str(targetUser) + message_b + myTime, encoding='utf-8')
    signature = cherrypy.session['signing_key'].sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signature.signature.decode()

    payload = {
        "loginserver_record": cherrypy.session['loginserver_record'],
        "target_pubkey": loginserver_pubkey,
        "target_username": str(targetUser),
        "encrypted_message": message_b,
        "sender_created_at": myTime,
        "signature": signature_hex_str
    }

    payload = json.dumps(payload).encode('utf-8')


    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req, timeout=2)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()

        userList = listUsers()
        userFound = 0
        for user in userList:
            if user["username"] == cherrypy.session['username']:
                print(user["username"])
                loginserver_pubkey = user["incoming_pubkey"]
                userFound = 1

        if userFound == 0:
            print("not online")
            return

        verifyKey = nacl.signing.VerifyKey(loginserver_pubkey, encoder=nacl.encoding.HexEncoder)
        publickey = verifyKey.to_curve25519_public_key()

        sealed_box = nacl.public.SealedBox(publickey)
        encrypted = sealed_box.encrypt(message, encoder=nacl.encoding.HexEncoder)
        message_b = encrypted.decode('utf-8')

        databases.recievePrivateMessage(str(targetUser), cherrypy.session['username'], message_b, myTime, loginserver_pubkey)
        print("Successfully broadcasted private message \n")
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        print("Private broadcast failed \n")
        return 1
    except:
        return 1


def listUsers():

    # try:
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    r = requests.get(url="http://cs302.kiwi.land/api/list_users", headers=headers).json()
    data = r["users"]
    #try:
    databases.updateActiveUsers(data)
    databases.readActiveUsers()
    #except sqlite3.OperationalError:
        #print("DATABASE Locked")

    return data
    # except:
    print("Error finding user list")


def addPubkey(pubkey_hex_str, signature_hex_str):
    url = "http://cs302.kiwi.land/api/add_pubkey"

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    # Generate a new random signing key

    payload = {
        "pubkey": pubkey_hex_str,
        "username": cherrypy.session['username'],
        "signature": signature_hex_str,
    }
    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        JSON_object = json.loads(data.decode(encoding))
        serverRecord = JSON_object["loginserver_record"]
        response.close()
        print("Added key successfully \n")
        # broadcastMsg(user, pwd, pubkey_hex_str, signing_key)
        return serverRecord
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        print("Failed key add \n")
        return 1

def getListAPI():
    r = requests.get(url="http://cs302.kiwi.land/api/list_apis").json()
    print(r)


def ping():
    url = "http://cs302.kiwi.land/api/ping"

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        "pubkey": cherrypy.session['pubkey_hex_str'],
        "signature": cherrypy.session['signature_hex_str'],
    }

    payloadJSON = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payloadJSON, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
        print("We pinging \n")
        # broadcastMsg(user, pwd, pubkey_hex_str, signing_key)
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        print("Failed key add \n")
        return 1

def authoriseUserLogin(pubkey_hex_str):
    url = "http://cs302.kiwi.land/api/report"

    # STUDENT TO UPDATE THESE...

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    payload = {
        # STUDENT TO COMPLETE THIS...
        "connection_address": IP_port,
        "connection_location": Connection_type,
        "incoming_pubkey": pubkey_hex_str,
    }
    payload = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()
        print('we in boys')
        return 0
    except urllib.error.HTTPError as error:
        print(error.read())
        ##exit()
        return 1

    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

def sendPublicBroadcast(message):

    # create HTTP BASIC authorization header
    headers = {
        'X-username': cherrypy.session['username'],
        'X-apikey': cherrypy.session['api_key'],
        'Content-Type': 'application/json; charset=utf-8',
    }

    message_str = str(message)

    myTime = str(time.time())

    signature_bytes = bytes(str(cherrypy.session['loginserver_record']) + message_str + myTime, encoding='utf-8')

    signature = cherrypy.session['signing_key'].sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signature.signature.decode()

    userList = listUsers()

    print(userList)

    payload = {
        "loginserver_record": cherrypy.session['loginserver_record'],
        "message": message_str,
        "sender_created_at": myTime,
        "signature": signature_hex_str
    }
    payload = json.dumps(payload).encode('utf-8')

    for user in userList:

        url = "http://" + str(user['connection_address']) + "/api/rx_broadcast"
        print(url)
        try:
            req = urllib.request.Request(url, data=payload, headers=headers)
            response = urllib.request.urlopen(req, timeout=2)
            data = response.read()  # read the received bytes
            encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
            response.close()
            print("Successfully broadcasted \n")
        except urllib.error.HTTPError as error:
            print(error.read())
            ##exit()
            print("Broadcast failed \n")
        except:
            print("Broadcast failed \n")
