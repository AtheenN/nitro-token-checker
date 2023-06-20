import os
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
from uuid import uuid4  # gen random guid
import platform  # check platform
import subprocess  # needed for mac device

try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        os.system("pip install pywin32")
        os.system("pip install pycryptodome")
        os.system("pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)

try:  # Connection check
    s = requests.Session()  # Session
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(5)
    os._exit(1)


class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(2)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("init".encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                time.sleep(3)
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            time.sleep(3)
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("register".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("successfully registered")
            self.__load_user_data(json["info"])
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("upgrade".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("successfully upgraded user")
            print("please restart program and login")
            time.sleep(2)
            os._exit(1)
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("login".encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            #print("successfully logged in")
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("license".encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("successfully logged into license")
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("var".encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("getvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(f"NOTE: This is commonly misunderstood. This is for user variables, not the normal variables.\nUse keyauthapp.var(\"{var_name}\") for normal variables");
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("setvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("ban".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("file".encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("webhook".encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "body": encryption.encrypt(body, self.enckey, init_iv),
            "conttype": encryption.encrypt(conttype, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("check".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("checkblacklist".encode()),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("log".encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("fetchOnline".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None  # THIS IS ISSUE ON KEYAUTH SERVER SIDE 6.8.2022, so it will return none if it is not an array.
            else:
                return json["users"]
        else:
            return None

    def chatGet(self, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatget".encode()),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatsend".encode()),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(2)
            os._exit(1)

    def changeUsername(self, username):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("changeUsername".encode()),
            "newUsername": username,
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            print("successfully Changed Username")
        else:
            print(json["message"])
            os._exit(1)        
            
    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print("Request timed out")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""
    #egion user_data

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid



class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            time.sleep(5)
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            time.sleep(5)
            os._exit(1)

import sys
import time
import platform
import os
import hashlib
from time import sleep
from datetime import datetime
import json

# import json as jsond
# ^^ only for auto login/json writing/reading

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA

if sys.version_info.minor < 10:  # Python version check (Bypass Patch)
    print("[Security] - Python 3.10 or higher is recommended. The bypass will not work on 3.10+")
    print("You are using Python {}.{}".format(sys.version_info.major, sys.version_info.minor))

if platform.system() == 'Windows':
    os.system('cls & title Boostio Checker')  # clear console, change title

print("Initializing")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest



time.sleep(3)


gray_code = "\033[90m"
from colorama import Fore
import time
print(f"""{Fore.CYAN}
████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗     █████╗ ██╗ ██████╗ 
╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║    ██╔══██╗██║██╔═══██╗
   ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║    ███████║██║██║   ██║
   ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║    ██╔══██║██║██║   ██║
   ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║    ██║  ██║██║╚██████╔╝
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝    ╚═╝  ╚═╝╚═╝ ╚═════╝ 
                                        made by AtheenN /jpn0ph
    
    {Fore.RESET}""")
time.sleep(1)
print(f"[Never expiring]")


import requests
from datetime import datetime, timezone
import threading
from colorama import Fore, Style
import ctypes
import json
from discord_webhook import DiscordWebhook
def formatter_one():
    with open("tokens.txt", "r+") as file:
        lines = file.readlines()
        file.seek(0)  # Move the file pointer to the beginning

        for line in lines:
            parts = line.split(":")
            if len(parts) >= 3:
                token = parts[2].strip()
                formatted_line = f"{token}\n"
            else:
                formatted_line = line  # Keep the line unchanged if it only contains the token

            file.write(formatted_line)

        file.truncate()  # Remove any remaining content after the new lines

formatter_one()


def blur_token(token):
    # Replace the characters in the middle of the token with asterisks
    blurred_token = token[:5] + '*' * 10 + token[-5:]
    return blurred_token

def set_console_title(title):
    ctypes.windll.kernel32.SetConsoleTitleW(title)

with open('proxies.txt', 'r') as f:
    proxies = [line.strip() for line in f.readlines()]

from datetime import datetime, timezone
import requests
import json
from colorama import Fore, init
from requests.exceptions import ProxyError
import urllib3

current_time = datetime.now()
formatted_time = current_time.strftime("%H:%M:%S")
#print(formatted_time)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init()
def check_nitro_expiration(token, thread_index, valid_tokens, locked_tokens, invalid_tokens, nitro_tokens_1m, nitro_tokens_3m, valid_tokens_expiring, no_nitro):
    with open('proxies.txt', 'r') as f:
        proxies = [line.strip() for line in f.readlines()]  # Remove leading/trailing whitespace or newline characters

    headers = {
        "Authorization": token
    }

    blurred_token = blur_token(token.strip())

    proxy = proxies.pop(0)
    proxies.append(proxy)

    session = requests.Session()
    session.proxies = {
        "http": proxy,
        "https": proxy
    }

    response = session.get("https://discord.com/api/v9/users/@me/billing/subscriptions", headers=headers)
    boost_data = session.get(f"https://discord.com/api/v9/users/@me/guilds/premium/subscription-slots", headers={'Authorization': token})

    if boost_data.status_code == 200:
        jsx = json.loads(boost_data.text)
        hm = 0
        timeTill = "No cooldown"  # Initialize timeTill with "No cooldown" by default

        try:
            for i in jsx:
                if not i['canceled']:
                    hm += 1
                    if i['cooldown_ends_at'] is not None:
                        expr = datetime.strptime(i['cooldown_ends_at'], '%Y-%m-%dT%H:%M:%S.%f%z')
                        timeTill = expr - datetime.now(timezone.utc)
                        timeTill = str(timeTill).split('.')[0]
                    else:
                        timeTill = "No cooldown"
                        with open("not-used.txt", 'w') as f:
                            f.write(f'{token}\n')

        except Exception as e:
            x = 1
            x += 1
            # print(f"An error occurred while checking Nitro boost data for token {token}: {e}")
            # Handle the exception appropriately

    if response.status_code == 200:
        subscriptions = response.json()
        if subscriptions:
            subscription = subscriptions[0]  # Assuming there is only one subscription
            trial_ends_at = datetime.fromisoformat(subscription["trial_ends_at"]).replace(tzinfo=timezone.utc)
            current_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            remaining_days = (trial_ends_at - current_date).days

            if remaining_days >= 25:
                valid_tokens.append(blurred_token)
                print(f"{Fore.CYAN}[{thread_index}] {Fore.RESET} | {Fore.GREEN}SUCCESS {Fore.RESET}> Token: {blurred_token} {Fore.CYAN}> Days: {remaining_days}{Fore.RESET} | Cooldown: {'No cooldown' if timeTill is None else timeTill}{Fore.RESET}")
                with open(f'{remaining_days}.txt', 'a+', encoding='utf-8') as f:
                    f.writelines(f"{token}\n")
            else:
                valid_tokens_expiring.append(blurred_token)
                print(f"{Fore.CYAN}[{thread_index}] {Fore.RESET} | {Fore.YELLOW}SUCCESS {Fore.RESET}> Token: {blurred_token} {Fore.CYAN}> Days: {remaining_days} | {Fore.GREEN}Cooldown: {'No cooldown' if timeTill is None else timeTill}{Fore.RESET}")
                with open(f'{remaining_days}.txt', 'a+', encoding='utf-8') as f:
                    f.writelines(f"{token}\n")
        else:
            no_nitro.append(blurred_token)
            print(f"{Fore.CYAN}[{thread_index}] {Fore.RESET} | {Fore.YELLOW}FAIL {Fore.RESET}> Token: {blurred_token} No Nitro found{Fore.RESET}")
            with open('nonitro.txt', 'a+', encoding='utf-8') as f:
                f.write(f"{token}\n")

    elif response.status_code == 403:
        locked_tokens.append(blurred_token)
        print(f"{Fore.YELLOW}[{thread_index}] | WRN > Token: {blurred_token} is locked!{Fore.RESET}")
        with open(f'locked.txt', 'a+', encoding='utf-8') as f:
            f.writelines(f"{token}\n")

    elif response.status_code == 401:
        invalid_tokens.append(blurred_token)
        print(f"{Fore.CYAN}[{thread_index}] {Fore.RESET} | {Fore.RED}INVALID {Fore.RESET}> Token: {blurred_token} is invalid{Fore.RESET}")
        with open(f'invalid.txt', 'a+', encoding='utf-8') as f:
            f.writelines(f"{token}\n")

    set_console_title(f"Boostio Checker | Nitro: {len(valid_tokens)} | Normal: {len(no_nitro)} | Invalid: {len(invalid_tokens)} | Locked: {len(locked_tokens)}")
    

def main():
    with open('tokens.txt', 'r') as f:
        tokens = f.readlines()

    valid_tokens = []
    locked_tokens = []
    valid_tokens_expiring = []
    invalid_tokens = []
    no_nitro = []
    nitro_tokens_1m = []
    nitro_tokens_3m = []

    threads = []
    for index, token in enumerate(tokens, start=1):
        token = token.strip()
        t = threading.Thread(target=check_nitro_expiration, args=(token, index, valid_tokens, locked_tokens, invalid_tokens, nitro_tokens_1m, nitro_tokens_3m, valid_tokens_expiring, no_nitro))
        threads.append(t)
        t.start()


    for thread in threads:
        thread.join()

    


if __name__ == "__main__":
    main()
    input(f"{Fore.CYAN}[-] {Style.BRIGHT}{Fore.GREEN}WRN {gray_code} > {Fore.RESET}{gray_code}Finished checking!")
    