import cherrypy
import urllib.request
import json
import requests
import base64
import nacl.encoding
import nacl.signing
import htmlbody
import databases
import server
import time
import binascii



startHTML = """<html><head><title>CS302 example</title><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script></head><body>"""

class ApiApp(object):
    # CherryPy Configuration
    cp_config = {'tools.encode.on': True,
                 'tools.encode.encoding': 'utf-8',
                 'tools.sessions.on': 'True',
                 }

    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_broadcast(self):
        try:
            data = cherrypy.request.json
            string_toSplit = data["loginserver_record"]
            username, pubkey, server_time, signature = string_toSplit.split(",")

            verify_key = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
            sig_a = binascii.unhexlify(data["signature"])

            signature_recon = str(data["loginserver_record"] + data["message"] + data["sender_created_at"])
            sig_b = bytes(signature_recon, encoding='utf-8')

            verify_key.verify(sig_b, sig_a, encoder=nacl.encoding.RawEncoder)

            response = {
                "response": "ok"
            }

            databases.recievePublicMessage(username, data["message"], server_time, pubkey)
            print("SUCCESSFUL")
        except:
            print("FAIL")
            response = {
                "response": "error"
            }

        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def rx_privatemessage(self):
        try:
            data = cherrypy.request.json
            loginserver_record = data["loginserver_record"]
            username, pubkey, server_time, signature = loginserver_record.split(",")
            target_pubkey = data["target_pubkey"]
            target_username = data["target_username"]
            encrypted_message = data["encrypted_message"]
            sender_created_at = data["sender_created_at"]
            signature = data["signature"]

            verify_key = nacl.signing.VerifyKey(pubkey, encoder=nacl.encoding.HexEncoder)
            sig_a = binascii.unhexlify(data["signature"])

            signature_recon = str(data["loginserver_record"] + data["target_pubkey"] + data["target_username"] + data["encrypted_message"] + data["sender_created_at"])
            sig_b = bytes(signature_recon, encoding='utf-8')

            verify_key.verify(sig_b, sig_a, encoder=nacl.encoding.RawEncoder)

            response = {
                "response":"ok",
            }
            databases.recievePrivateMessage(target_username, username, encrypted_message, server_time, pubkey)
            print("RECIEVED PM")
        except:
            print("FAILED PM")
            response = {
                "response":"error"
            }

        return response

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def ping_check(self):

        myTime = str(time.time())
        users = databases.readActiveUsers()


        payload = {
            "response": "ok",
            "my_time": myTime,
            "my_active_username": users,
        }

        return payload



