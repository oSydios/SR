
# IDS: How tu run

## HOST MACHINE SIDE

1 Download PCAP file from wednesday [PCAP WEDNESDAY](http://205.174.165.80/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/PCAPs/)

2 Install Scapy
```
pip install scapy
```

3 Install [NPCAP](https://npcap.com/#download) to successfully send packets to the VM

4 Download [Sender Script](https://github.com/oSydios/SR/blob/main/sender.py) and make sure that all your files are in the correct directories.


## VM MACHINE (KALI LINUX) SIDE

1 Install Tshark
```
sudo apt install tshark -y

sudo usermod -aG wireshark auser
```

2 Install Java & Python dependencies
```
sudo apt install python3 python3-pip openjdk-11-jre
```

3 Create a virtual environment 
```
python3 -m venv ids_venv

source ids_venv/bin/activate
```

4 Install python libraries
```
pip install pandas numpy scikit-learn joblib
```

5 Exit virtual environment
```
deactivate
```

6 Download [Cicflowmeter](https://drive.google.com/file/d/1eR3v4Bq3Sal3RpzaXpIWUyswGWCzCfi9/view)

7 Download [Model](https://github.com/oSydios/SR/blob/main/decision_tree_model.pkl), [Feature Min-Max](https://github.com/oSydios/SR/blob/main/feature_min_max.csv), [Feature Order](https://github.com/oSydios/SR/blob/main/feature_order.pkl), [IDS](https://github.com/oSydios/SR/blob/main/ids_sim.py) and [Full Script](https://github.com/oSydios/SR/blob/main/full_ids.sh) and make sure that all your files are in the correct directories.  

8 Make the file executable
```
chmod +x full_ids_run.sh
```

9 Turn off the VM and Put network in Host-only Adapter



# Execution Phase

1 At the vm run the [Full Script](https://github.com/oSydios/SR/blob/main/full_ids.sh) previous downloaded

2 At the host machine run the [Sender Script](https://github.com/oSydios/SR/blob/main/sender.py)




