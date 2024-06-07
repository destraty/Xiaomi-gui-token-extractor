# Xiaomi-gui-token-extractor

This program allows you, without changing the temperature, to automatically receive all tokens for all Xiaomi WIFI devices and all encryption keys for BLE devices in one click. 

>You will need to provide your credentials __(email/phone number/Xiaomi Account ID and Password)__ from the Xiaomi cloud to log in.

This is a modification of [this](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor) program. I refactored the entire code, added some features that, as for me, were missing in the original application, for example, GUI, saving the login and password for the account, a tabular view of the output data, etc.

# Instalation
## Windows
Just download ```xiaomi-gui-token-extractor.exe``` file [from here](https://github.com/destraty/Xiaomi-gui-token-extractor/releases/latest). Enjoy)
## Linux

## Manul install/For develop
1. Clone git repository:
```shell
git clone https://github.com/destraty/Xiaomi-gui-token-extractor
cd Xiaomi-gui-token-extractor
```
2. Activate venv and install requirements:
```shell
python -m venv env
source env/bin/activate
pip install -r requirements.txt
```
3. Run the app:
```shell
python extractor_GUI.py
```

# Console version
If you don't need a GUI, or your system doesn't have a GUI and you just want to get your tokens, there is a console version for you. 

Again, this is a fork of the above application, I just refactored the code and it became better and faster)

## Windows
Download ```extractor_console.exe``` file [from here](https://github.com/destraty/Xiaomi-gui-token-extractor/releases/latest). Enjoy)

## Linux
