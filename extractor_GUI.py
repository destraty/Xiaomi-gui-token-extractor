import base64
import hashlib
import json
import os
import pickle
import random
import time

import tkinter as tk
from tkinter import ttk
import sv_ttk
from tkinter import messagebox
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
            messagebox.showerror("ERROR", "Invalid username.")
            return False
        if not self.login_step_2():
            messagebox.showerror("ERROR", "Invalid login or password.")
            return False
        if not self.login_step_3():
            messagebox.showerror("ERROR", "Unable to get service token.")
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


class DeviceCard(tk.Frame):
    def __init__(self, parent, text):
        super().__init__(parent)
        self.pack(fill=tk.BOTH, expand=True)
        self.label = ttk.Label(self, text=text)
        self.label.pack(pady=10)


class DeviceViewer(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.tree = ttk.Treeview(self,
                                 columns=("Name", "ID", "MAC", "Local IP", "Token", "Model", "Online"),
                                 show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col, command=lambda _col=col: self.treeview_sort_column(_col, False))
        self.tree.pack(fill=tk.BOTH, expand=True)

    def treeview_sort_column(self, col, reverse):
        ls = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        ls.sort(reverse=reverse)
        for index, (val, k) in enumerate(ls):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.treeview_sort_column(col, not reverse))

    def add_device(self, device):
        keys = device.keys()
        self.tree.insert("", tk.END,
                         iid=device["did"],
                         text="",
                         values=(device["name"] if "name" in keys else "",
                                 device["did"] if "did" in keys else "",
                                 device["mac"] if "mac" in keys else "",
                                 device["localip"] if "localip" in keys else "",
                                 device["token"] if "token" in keys else "",
                                 device["model"] if "model" in keys else "",
                                 device["isOnline"] if "isOnline" in keys else ""))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Xiaomi Cloud Connector")
        self.geometry("800x600")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self.configure(background="#f0f0f0")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(5, weight=1)

        self.username_label = ttk.Label(self, text="Username/ID:")
        self.username_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.username_entry = ttk.Entry(self)
        self.username_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.password_label = ttk.Label(self, text="Password:")
        self.password_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.password_entry = ttk.Entry(self, show="*")
        self.password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        self.remember_me_var = tk.BooleanVar()
        self.remember_me_check = ttk.Checkbutton(self, text="Remember me", variable=self.remember_me_var)
        self.remember_me_check.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        self.server_label = ttk.Label(self, text="Server:")
        self.servers = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2", "cn"]
        self.server_var = tk.StringVar(self)
        self.server_var.set(self.servers[0])
        self.server_dropdown = ttk.OptionMenu(self, self.server_var, *self.servers)
        self.server_dropdown.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

        self.submit_button = ttk.Button(self, text="Log In", command=self.submit)
        self.submit_button.grid(row=4, column=0, columnspan=2, padx=20, pady=20, sticky="ew")

        self.device_viewer = DeviceViewer(self)
        self.device_viewer.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)

    def load_credentials(self):
        try:
            with open('credentials.pkl', 'rb') as file:
                return pickle.load(file)
        except FileNotFoundError:
            return {}

    def save_credentials(self, username, password):
        data = {'username': username, 'password': password}
        with open('credentials.pkl', 'wb') as file:
            pickle.dump(data, file)

    def submit(self):
        def update_device_viewer(self, devices):
            self.device_viewer.tree.delete(*self.device_viewer.tree.get_children())
            for device in devices:
                self.device_viewer.add_device(device)

        remember_me = self.remember_me_var.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        server = self.server_var.get()

        credentials = self.load_credentials()
        if remember_me and credentials.get('username') == username and credentials.get('password') == password:
            self.username_entry.insert(0, credentials['username'])
            self.password_entry.insert(0, credentials['password'])
            print("Using saved credentials.")
            return

        connector = XiaomiCloudConnector(username, password)
        connector.login()
        hh = []

        homes = connector.get_homes(server)
        if homes is not None:
            for h in homes['result']['homelist']:
                hh.append({'home_id': h['id'], 'home_owner': connector.userId})

        dev_cnt = connector.get_dev_cnt(server)
        if dev_cnt is not None:
            for h in dev_cnt["result"]["share"]["share_family"]:
                hh.append({'home_id': h['home_id'], 'home_owner': h['home_owner']})

        if not hh:
            messagebox.showwarning("Be careful!", f'No homes found for server "{server}".')
            return

        for home in hh:
            devices = connector.get_devices(server, home['home_id'], home['home_owner'])
            if devices is not None and devices["result"]["device_info"]:
                update_device_viewer(self, devices["result"]["device_info"])

        if remember_me:
            self.save_credentials(username, password)


if __name__ == "__main__":
    app = App()
    sv_ttk.set_theme("dark")
    credentials = app.load_credentials()
    if credentials:
        app.username_entry.insert(0, credentials['username'])
        app.password_entry.insert(0, credentials['password'])
    app.mainloop()
