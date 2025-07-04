# PGUP: Pretty Good User Privacy for 5G-enabled Secure Mobile Communication Protocols

## Project Overview
This code implements the **PGUP: Pretty Good User Privacy for 5G-enabled Secure Mobile Communication Protocols**.


## Basic Requirements


### Hardware Requirements
- Two Laptop/PC or a Single Powerful Laptop/PC.
  - CPU: 8 cores x86_64 @ 3.5 GHz
  - RAM: 32 GB
- Two USRP B210.

### Software Requirements
- Ubuntu 22.04 LTS
- OpenAirInterface

### Estimated Time and Storage Consumption
For a single experiment, it might require 1 minutes for the whole system.




## Runing


### Run OAI CN5G

```bash
cd ~/oai-cn5g
docker compose up -d
```

### Run OAI gNB

```bash
cd ~/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-softmodem -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.usrpb210.conf --gNBs.[0].min_rxtxtime 6 -E --continuous-tx
```





### OAI UE
```bash
cd ~/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --ue-fo-compensation -E --uicc0.imsi 001010000000001
```


## Set up the environment

#### OpenAirInterface
Build OAI gNB and OAI nrUE:
```bash
cd ~/openairinterface5g/cmake_targets
./build_oai -w USRP --ninja --nrUE --gNB --build-lib "nrscope" -C
```

#### PGUP Extension
```bash
g++ PGUP.cpp -o PGUP libPKWLib.a -lssl -lcrypto -lcryptopp -I/home/$USER/Desktop/PGUP/cpp_lib
```


### Testing the Environment

#### Run OAI CN5G

```bash
cd ~/oai-cn5g
docker compose up -d
```

#### Run OAI gNB

```bash
cd ~/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-softmodem -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.usrpb210.conf --gNBs.[0].min_rxtxtime 6 -E --continuous-tx
```





#### OAI UE
```bash
cd ~/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --ue-fo-compensation -E --uicc0.imsi 001010000000001
```


### Useful Commond for Fail Points
This is the commond that kill all OpenAirInterface related process.
```bash
sudo kill -9 $(ps aux | grep 'nr-' | awk '{print $2}')
```






