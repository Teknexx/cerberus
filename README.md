# Cerberus
Cerberus is a Python client-server program to implement a complex port knocking system preventing playback attacks on an exposed server. The program can be used with a password (client need to have root privileges) or without.
The server need to run the server-side program, and then the client have to use the client-side as Python module to whitelist his IP, with specifying a list of ports to knock synchronised with the server, a port to open after the knocking and a password if password mode is enabled. The whitelist can have Time-To-Leave with a crontab task.

# Usage
## Server-side
```bash
python3 cerberus_server.py config.ini
```
Or with the service :
```bash
systemctl start cerberus
```

## Client-side
In a Python script
```python
import cerberus_client as crb
crb.knocking("DestinationIP", Destination_Port, [Port_list])
crb.knocking_with_pass("DestinationIP", Destination_Port, [Port_list], "Password") # With root privileges
```

# Example
## Server-side
```bash
nano /root/cerberus/config_example.ini
	[GLOBAL]
	INTERFACE = ens3
	LOGS_FILE_PATH = /var/cerberus.log
	REJECT_TIME = 30
	
	[PASS]
	PORT_PASS = 9988, 56, 212
	MODE_PASS = True
	PASSWORD = GigaS3cure!

python3 cerberus_server.py config_example.ini
	INI: 2023-05-18 17:27:11.022107  -  Cerberus started listening
	...
```

## Client-side
In a Python script
```python
import cerberus_client as crb
crb.knocking_with_pass("45.125.76.98", 22, [9988, 56, 212], "GigaS3cure!")
	Collecting public IP...
	Collected !
	Packet with pass sent to port 22 on 45.125.76.98
	Packet with pass sent to port 9988 on 45.125.76.98
	Packet with pass sent to port 56 on 45.125.76.98
	Packet with pass sent to port 212 on 45.125.76.98
```

# Installation
## Automatic
You can automaticlly install Cerberus with the following command
```bash
tar -xzvf cerberus.tar.gz -C /root/cerberus
cd /root/cerberus
bash install.sh
```

## Manual (recommanded)
### Untar
Untar the file into the root directory
```bash
tar -xzvf cerberus.tar.gz -C /root/cerberus
cd /root/cerberus
```

### Install Python dependencies
```bash
pip3 install scapy resquests
```

### Config file
Create or modify the config file **config.ini** as following :
```bash
[GLOBAL]
# Listening interface
INTERFACE = eth0
# Path to the logs file
LOGS_FILE_PATH = /var/log/cerberus.log
# Max timeout in seconds between the first and the last packet
REJECT_TIME = 60

[PASS]
# Port list
PORT_PASS = 11, 22, 33, 44, 55
# Mode pass that add a string as password (user need to be root)
MODE_PASS = True
# Password string
PASSWORD = password
```

### Firewall and crontab
First, config correctly your iptables firewall parameters (choose if you want to keep port opened).
Second, save your iptables parameters :
```bash
iptables-save > /root/cerberus/iptables.save
```
Third, create a crontab task (This step is optional if you don't want to have whitelist with TTL) :
```bash
crontab -e
```
And add the following line to reset whitelist every hours
```bash
0 * * * * /sbin/iptables-restore < /root/cerberus/iptables.save
```

### Use Cerberus as a service
```bash
nano /root/cerberus/start_cerberus_service
	cd /root/cerberus
	python3 cerberus_server.py config.ini
```
Create a service file
```bash
nano /etc/systemd/system/cerberus.service
```
And add the following lines
```bash
[Unit]  
Description=Cerberus Service  
After=network.target  
StartLimitIntervalSec=0  
  
[Service]  
Type=simple  
Restart=always  
RestartSec=1  
User=root  
ExecStart=bash /root/cerberus/start_cerberus_service  
  
[Install]  
WantedBy=multi-user.target
```
Finally, start the service
```bash
systemctl daemon-reload  
systemctl enable cerberus.service  
systemctl start cerberus.service
```
