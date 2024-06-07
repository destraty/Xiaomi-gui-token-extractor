import base64
import hashlib
import json
import os
import random
import time
from getpass import getpass

import requests
from Crypto.Cipher import ARC4


class XiaomiCloudConnector:

    def __init__(self, username, password):
        self._username = username
        self._password = password
        self._agent = self.generate_agent()
        self._device_id = self.generate_device_id()
        self._session = requests.session()
        self._sign = None
        self._ssecurity = None
        self.userId = None
        self._cUserId = None
        self._passToken = None
        self._location = None
        self._code = None
        self._serviceToken = None

    def login_step_1(self):
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        cookies = {
            "userId": self._username
        }
        response = self._session.get(url, headers=headers, cookies=cookies)
        valid = response.status_code == 200 and "_sign" in self.to_json(response.text)
        if valid:
            self._sign = self.to_json(response.text)["_sign"]
        return valid

    def login_step_2(self):
        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(str.encode(self._password)).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": self._username,
            "_sign": self._sign,
            "_json": "true"
        }
        response = self._session.post(url, headers=headers, params=fields)
        valid = response is not None and response.status_code == 200
        if valid:
            json_resp = self.to_json(response.text)
            valid = "ssecurity" in json_resp and len(str(json_resp["ssecurity"])) > 4
            if valid:
                self._ssecurity = json_resp["ssecurity"]
                self.userId = json_resp["userId"]
                self._cUserId = json_resp["cUserId"]
                self._passToken = json_resp["passToken"]
                self._location = json_resp["location"]
                self._code = json_resp["code"]
            else:
                if "notificationUrl" in json_resp:
                    print("Two factor authentication required, please use following url and restart extractor:")
                    print(json_resp["notificationUrl"])
                    print()
        return valid

    def login_step_3(self):
        headers = {
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = self._session.get(self._location, headers=headers)
        if response.status_code == 200:
            self._serviceToken = response.cookies.get("serviceToken")
        return response.status_code == 200

    def login(self):
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self._session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="mi.com")
        self._session.cookies.set("deviceId", self._device_id, domain="xiaomi.com")
        if not self.login_step_1():
            print("Invalid username.")
            return False
        if not self.login_step_2():
            print("Invalid login or password.")
            return False
        if not self.login_step_3():
            print("Unable to get service token.")
            return False
        return True



    def get_homes(self, country):
        url = self.get_api_url(country) + "/v2/homeroom/gethome"
        params = {
            "data": '{"fg": true, "fetch_share": true, "fetch_share_dev": true, "limit": 300, "app_ver": 7}'}
        return self.execute_api_call_encrypted(url, params)

    def get_devices(self, country, home_id, owner_id):
        url = self.get_api_url(country) + "/v2/home/home_device_list"
        params = {
            "data": '{"home_owner": ' + str(owner_id) +
                    ',"home_id": ' + str(home_id) +
                    ',  "limit": 200,  "get_split_device": true, "support_smart_home": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def get_dev_cnt(self, country):
        url = self.get_api_url(country) + "/v2/user/get_device_cnt"
        params = {
            "data": '{ "fetch_own": true, "fetch_share": true}'
        }
        return self.execute_api_call_encrypted(url, params)

    def execute_api_call_encrypted(self, url, params):
        headers = {
            "Accept-Encoding": "identity",
            "User-Agent": self._agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
            "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
        }
        cookies = {
            "userId": str(self.userId),
            "yetAnotherServiceToken": str(self._serviceToken),
            "serviceToken": str(self._serviceToken),
            "locale": "en_GB",
            "timezone": "GMT+02:00",
            "is_daylight": "1",
            "dst_offset": "3600000",
            "channel": "MI_APP_STORE"
        }
        millis = round(time.time() * 1000)
        nonce = self.generate_nonce(millis)
        signed_nonce = self.signed_nonce(nonce)
        fields = self.generate_enc_params(url, "POST", signed_nonce, nonce, params, self._ssecurity)
        response = self._session.post(url, headers=headers, cookies=cookies, params=fields)
        if response.status_code == 200:
            decoded = self.decrypt_rc4(self.signed_nonce(fields["_nonce"]), response.text)
            return json.loads(decoded)
        return None

    @staticmethod
    def get_api_url(country):
        return "https://" + ("" if country == "cn" else (country + ".")) + "api.io.mi.com/app"

    def signed_nonce(self, nonce):
        hash_object = hashlib.sha256(base64.b64decode(self._ssecurity) + base64.b64decode(nonce))
        return base64.b64encode(hash_object.digest()).decode('utf-8')

    @staticmethod
    def generate_nonce(millis):
        nonce_bytes = os.urandom(8) + (int(millis / 60000)).to_bytes(4, byteorder='big')
        return base64.b64encode(nonce_bytes).decode()

    @staticmethod
    def generate_agent():
        agent_id = "".join(map(lambda i: chr(i), [random.randint(65, 69) for _ in range(13)]))
        return f"Android-7.1.1-1.0.0-ONEPLUS A3010-136-{agent_id} APP/xiaomi.smarthome APPV/62830"

    @staticmethod
    def generate_device_id():
        return "".join(map(lambda i: chr(i), [random.randint(97, 122) for _ in range(6)]))

    @staticmethod
    def generate_enc_signature(url, method, signed_nonce, params):
        signature_params = [str(method).upper(), url.split("com")[1].replace("/app/", "/")]
        for k, v in params.items():
            signature_params.append(f"{k}={v}")
        signature_params.append(signed_nonce)
        signature_string = "&".join(signature_params)
        return base64.b64encode(hashlib.sha1(signature_string.encode('utf-8')).digest()).decode()

    @staticmethod
    def generate_enc_params(url, method, signed_nonce, nonce, params, ssecurity):
        params['rc4_hash__'] = XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params)
        for k, v in params.items():
            params[k] = XiaomiCloudConnector.encrypt_rc4(signed_nonce, v)
        params.update({
            'signature': XiaomiCloudConnector.generate_enc_signature(url, method, signed_nonce, params),
            'ssecurity': ssecurity,
            '_nonce': nonce,
        })
        return params

    @staticmethod
    def to_json(response_text):
        return json.loads(response_text.replace("&&&START&&&", ""))

    @staticmethod
    def encrypt_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return base64.b64encode(r.encrypt(payload.encode())).decode()

    @staticmethod
    def decrypt_rc4(password, payload):
        r = ARC4.new(base64.b64decode(password))
        r.encrypt(bytes(1024))
        return r.encrypt(base64.b64decode(payload))


def print_tabbed(value, tab):
    print(" " * tab + value)


def print_entry(key, value, tab):
    if value:
        print_tabbed(f'{key + ":": <10}{value}', tab)


def main():
    servers = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]
    servers_str = ", ".join(servers)

    username = input("Username (email or user ID):\n")
    password = getpass("Password:\n")
    server = input(f"Server (one of: {servers_str}):\n")

    while server not in servers:
        server = input(f"Invalid server provided. Valid values: {servers_str}\nServer:\n")
    servers = [server]

    connector = XiaomiCloudConnector(username, password)
    print("Logging in...")
    logged = connector.login()
    if not logged:
        print("Unable to log in.")
        return
    print("Successfully logged in.\n")

    def print_device_info(device):
        """Prints detailed information about a single device."""
        print_tabbed("---------", 3)
        for key, value in device.items():
            if key in ["name", "did", "mac", "localip", "token", "model"]:
                print_entry(key.upper(), value, 3)
        print_tabbed("---------", 3)

    def process_home(home, current_server, connector):
        """Processes a single home and prints its devices."""
        devices = connector.get_devices(current_server, home['home_id'], home['home_owner'])
        if devices is not None and devices["result"]["device_info"]:
            print(f'Devices found for server "{current_server}" @ home "{home["home_id"]}":')
            for device in devices["result"]["device_info"]:
                print_device_info(device)
        else:
            print(f"No devices found for server '{current_server}' @ home '{home['home_id']}'.")

    for current_server in servers:
        hh = []

        homes = connector.get_homes(current_server)
        if homes is not None:
            for h in homes['result']['homelist']:
                hh.append({'home_id': h['id'], 'home_owner': connector.userId})

        dev_cnt = connector.get_dev_cnt(current_server)
        if dev_cnt is not None:
            for h in dev_cnt["result"]["share"]["share_family"]:
                hh.append({'home_id': h['home_id'], 'home_owner': h['home_owner']})

        if not hh:
            print(f'No homes found for server "{current_server}".')
            continue

        for home in hh:
            process_home(home, current_server, connector)

    print()
    print("Press ENTER to finish")
    input()


if __name__ == "__main__":
    main()
