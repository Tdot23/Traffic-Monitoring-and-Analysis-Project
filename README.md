# Traffic-Monitoring-and-Analysis-Project
Cyber Security Operation Center Project Documentation
# Project Overview
## Objective
### The main goal in this project is to set up a robust Security Information and Event Management (SIEM) system for a small company's network. This system will efficiently gather and securely store logs from various sources, providing various dashboards for thorough analysis. Additionally, implement an Intrusion Detection System/Intrusion Prevention System (IDS/IPS) to detect and respond to simulated attacks on the network. The IDS/IPS will send logs to the SIEM for dashboarding. We have chosen Splunk for our SIEM and Snort for our IDS. 
## Network Configuration
<img width="900" alt="network configuration" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/9c0ecb75-d924-4f7a-a816-c8e4eb07101a">

## Project Components

### 1. Splunk (SIEM System): Splunk is a robust Security Information and Event Management (SIEM) system, designed for collecting, indexing, and analyzing machine-generated data. It efficiently gathers logs from various sources like Windows Server, Linux Servers (Ubuntu, Ubuntu2), Cisco Router, Web Server (Apache2 on Ubuntu), and IDS (Snort on Ubuntu2), providing comprehensive visibility into our network and system activities. 
#### 1.1 Log Collection: Splunk efficiently collects logs from various sources, enhancing visibility into network and system activities, including Windows and Linux servers, Cisco routers, web servers, and our IDS (Snort) 
#### 1.2 Robust Log Storage and Indexing: Splunk ensures efficient log management through centralized storage and indexing mechanisms. Centralized storage and indexing enable quick and efficient search capabilities for logs from various sources. 
#### 1.3 Data Visualization Dashboards: Splunk empowers users to create custom data visualization dashboards, facilitating real-time monitoring and analysis of security events. The user-friendly interface enhances the interpretation of data for both analysts and decision-makers. 
### 2. Snort (IDS): Snort is an open-source Intrusion Detection System (IDS) that specializes in analyzing network traffic for potential security threats. It uses signature-based detection for real-time identification of known patterns of attacks or malicious activities.
#### 2.1 Intrusion Detection: Snort actively monitors our networks traffic, employing our custom rules found in /etc/snort/rules/local.rules. This real-time analysis ensures prompt detection and response to security incidents. 
### 3. Log Sources 
#### Various log sources include Windows Server (Windows Event & Security), Ubuntu Server (Syslog & Apache2), Ubuntu2 Server (Syslog & Snort), and Cisco Router (Syslog). 
### 4. Network Topology 
#### A visual representation of the network structure. 
<img width="707" alt="toptoptop" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/a94860a2-ef5e-4bd5-a8f7-61f82fb19210">

### 5. Simulated Attacks 
#### Executing different attack scenarios like SYN Flood’s and Brute Force from the Kali Linux VM against different VM’s in our network. The IDS (snort) will be configured to detect and log these incidents for analysis. Logs will be sent to Splunk for dashboarding. 
### 5.1 Attack Types 
#### SSH Brute Force is when an attacker attempts to gain unauthorized access to a system or network by systematically guessing usernames and passwords for SSH (Secure Shell) authentication.  
#### FTP Brute Force is when an attacker attempts to gain unauthorized access to FTP servers by systematically guessing usernames and passwords.  
#### DDOS (Distributed Denial-of-Service) is a malicious attempt to disrupt the normal traffic of a targeted server, service, or network by overwhelming it with a flood of internet traffic from multiple sources, making it unavailable to its intended users. 
# Implementation Steps 
## 1. Setting Up VMs 
### Virtual Machines (VMs) were provisioned using OpenNebula, and they were assigned addresses from a custom addressing block of 192.168.1.0/24. The deployment included configuring the hosts with static IP addresses in accordance with the chosen network configuration. The default gateway for the VMs was set to 192.168.1.1.
## 2. Installing and Configuring SIEM System
### 2.1 Splunk installation on the Windows Server VM from Splunk Official Website 
<img width="783" alt="splunk step 2" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/efd889b2-572e-4134-afe9-cfa648311389">

- Create an account on Splunk Website (Splunk.com) and download Splunk Enterprise 

<img width="962" alt="splunk step 4" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/c418a9d9-907a-4700-9a09-084b0f436eb4">

- Download for your OS 

<img width="255" alt="install 3" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/5539cc51-f10d-4a8a-b7ca-cae810ff6934"> <img width="255" alt="install 4" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/78c26064-bb63-40c0-9d77-f23669ba30d2">


- Follow installation wizard (default) Installs Splunk Enterprise in \Program Files\Splunk on the drive that booted your Windows machine. 


<img width="255" alt="install 1 " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/40f49a5f-049c-43ff-b6c4-dd5f7b687604"> <img width="255" alt="install 2" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/21ca09ac-7f85-4372-9a3c-885780a87786">


- Configure Splunk Enterprise to run as the Local System user. Prompts you to create a Splunk administrator password. You must do this before the installation can continue. 

<img width="255" alt="install 5" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/41e97525-51e1-4dba-8271-033b916fcaaf"> <img width="255" alt="install 6" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/99a3d36f-f3d7-44c4-9fb3-448cfb711cf7">

- Create a Start Menu shortcut for the software Install and Finish 

<img width="600" alt="splunk login" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/7685f844-f3a2-488c-860d-7cc23d8f3b37">

- Log in with created username and password. 
### 2.2 Open port 9997 to receive data from forwarders. (Ubuntu, Ubuntu2).

<img width="800" alt="addnnew " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/ea8431bd-260e-4b65-83f2-560f42b21c10">

- In top right corner select settings>forwarding&receiving>+ add new to receive data on TCP port 9997 

### 2.3 Configuration of Splunk to log local Windows Server Events. 

<img width="829" alt="spunk 1 " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/0c61eba4-db3d-422e-bd23-88447ca23353"> <img width="836" alt="spunk local" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/7355d141-4178-4b8a-a6d9-8f5be87d77a1">

- In top right corner select settings>data inputs>Local event log collection and choose desired sources.

### 2.4 Accept logs from Cisco router at 192.168.1.2 on udp port 5141.  

<img width="829" alt="spunk 1 " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/0c61eba4-db3d-422e-bd23-88447ca23353"> <img width="843" alt="udp" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/07688bca-bbb1-4dbd-8321-a8e0e07b4303">

- In top right corner select settings>data inputs>udp> config udp port 5141 to receive logs from cisco router at 192.168.1.2 

### 2.5 Installed Snort Alert Splunk App for Dashboarding  


<img width="322" alt="splunk snort" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/80323b6e-a03d-4b40-becf-78162eab4321"> <img width="340" alt="snort splunk" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/e417ab57-a41b-4a34-8cc9-f9d92098c973">

- Find more apps > search snort > install Snort Alert for Splunk.

### 2.6 Forwarding logs from Ubuntu 
#### /var/log/apache2 (Web), /var/log/auth.log (Syslog). 

<img width="367" alt="ubuntu" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/436d67b8-b1b5-4ab9-b632-3821ffb848a5">

- Logs being forwarded from ubuntu server via Splunk universal forwarder config found at /opt/splunkforwarder/etc/apps/search/local/inputs.conf 

### 2.7 Forwarding logs from Ubuntu2 
#### /var/log/snort (IDS), /var/log/auth.log (Syslog). 

<img width="338" alt="ubuntu2" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/f2fac7db-b994-4e5c-adb9-6cf8cbac6965">

- Logs being forwarded from ubuntu2 via Splunk universal forwarder config found at /opt/splunkforwarder/etc/apps/search/local/inputs.conf   

### 2.8 Creation of indexes, sourcetypes and dashboards for each log source. 

<img width="960" alt="splunk configed" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/19a8af0a-fd83-4c47-b28b-ba8d36d6dea8">


<img width="500" alt="summary" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/e7b571a4-f1f0-4be6-a387-ae2b266c3ad1"> <img width="250" alt="6dashboards" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/d3217492-9040-401d-8a7a-f20e71698ffb">

- Splunk set up, data sources, summary, and dashboards 

## 3. Implementing Snort IDS 
### 3.1 Install Snort 



- Enter command sudo apt-get update && sudo apt-get upgrade –y to update and upgrade your ubuntu before Snort installation.



- Enter command sudo apt install snort. 



 



- Back up the original configuration file located at /etc/snort/snort.conf using sudo cp /etc/snort/snort.conf /etc/snort/snort.conf.back 
- Clear all preconfigured rules from the snort.conf file.

### 3.2 Configure local.rules 

<img width="800" alt="local rules" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/3c9ea104-91a7-4952-8a1e-da07208d1e96">

- Enter command sudo nano /etc/snort/rules/local.rules to access local rules file 

- Here you can add your own custom snort rules, or you can import community rules from www.snort.com  

## 4. Configuring Log Sources 
### 4.1 Splunk configuration to collect local Windows Server Event and Security logs 

<img width="836" alt="spunk local" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/7355d141-4178-4b8a-a6d9-8f5be87d77a1">

- In top right corner select settings>data inputs>Local log event collection select local windows sources 

### 4.2 Splunk Forwarder installation on Ubuntu Server
#### Configuration to send Apache2 (/var/log/apache2) & Syslog (/var/log/auth/log) to Splunk at 192.168.1.19.

<img width="745" alt="uni forwarder" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/04285cb3-f5d3-420c-aaa0-6e4968673340">

- Download with wget -O splunkforwarder-9.2.0.1-d8ae995bf219-linux-2.6-amd64.deb https://download.splunk.com/products/universalforwarder/releases/9.2.0.1/linux/splunkforwarder-9.2.0.1-d8ae995bf219-linux-2.6-amd64.deb  
- unzip with sudo dpkg -i splunkforwarder-9.2.0.1-d8ae995bf219-linux-2.6-amd64.deb   
- cd /opt/splunkforwarder/bin  
- sudo ./splunk start

 <img width="745" alt="ftttpday" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/5c39421d-b67e-404b-9627-402f73dde538"> 

- Add forward server and logs to monitor with sudo ./splunk add forward-server and sudo ./spunk add monitor commands

### 4.3 Splunk Forwarder installation on Ubuntu2 Server 
#### Configuration to send Snort (/var/log/snort) & Syslog (/var/log/auth/log) to Splunk at 192.168.1.19.  

<img width="745" alt="uni forwarder" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/04285cb3-f5d3-420c-aaa0-6e4968673340">

- Download with wget -O splunkforwarder-9.2.0.1-d8ae995bf219-linux-2.6-amd64.deb https://download.splunk.com/products/universalforwarder/releases/9.2.0.1/linux/splunkforwarder-9.2.0.1-d8ae995bf219-linux-2.6-amd64.deb  
- unzip with sudo dpkg -i splunkforwarder-9.2.0.1-d8ae995bf219-linux-2.6-amd64.deb   
- cd /opt/splunkforwarder/bin  
- sudo ./splunk start

  <img width="800" alt="ftoday" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/d30ac124-398c-429d-b1c2-15f2aee66ab3">

- Add forward server and logs to monitor with sudo ./splunk add forward-server and sudo ./spunk add monitor commands  

<img width="367" alt="ubuntu" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/436d67b8-b1b5-4ab9-b632-3821ffb848a5"> <img width="338" alt="ubuntu2" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/f2fac7db-b994-4e5c-adb9-6cf8cbac6965">

- Confirmation of logs being forwarded on ubuntu and ubuntu2 /opt/splunkforwarder/apps/search/local/inputs.conf

### 4.4 Cisco Router Logging 
#### Issued command logging host 192.168.1.19 transport udp 5141 on cisco router. 

<img width="695" alt="router logss" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/76b6abb0-6728-4b3a-87fe-67a91559a596">

- Router logging commands pointing to udp port 5141 of Splunk sever

## 5. Simulating Attacks 
#### Attacks to be executed using ./metro provided by adot8 via GitHub 


<img width="750" alt="metro" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/15fe03a1-d3a1-4d66-9110-d575f8540d7f">

- Pulled Metro from GitHub. Metro is a bash script created by adot8 to simulate attacks using various tools 

- Installed Metro: git clone https://github.com/adot8/metro.git > chmod +x setup.sh > sudo ./setup.sh. To run Metro: cd /metro > ./metro -i eth0 > choose attack

### 5.1 Executed a SYN Flood attack  
#### hping3 -c $packets -d $size -S -p 80 --flood $target_ip -V 
<img width="961" alt="syn flood attack" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/6cbe8e19-2ab0-4e93-a154-aab7a3117c29">
<img width="961" alt="syn flood" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/5628965f-872e-4be8-8520-75a027145e8a">

- SYN Flood attack with Metro on port 80 using hping3 against 192.168.1.200 used default settings in Metro and alerts showing on ubuntu2 snort 



### 5.2 Executed a SSH Brute force attack
#### hydra -v -L $user_file -P $pass_file SSH://$target_ip:22 -o credentials.txt 

<img width="961" alt="ssh attack" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/0b46929a-7df9-46b8-ad86-8b802b848629">
<img width="961" alt="ssh attack results " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/2ef380d3-5d16-4d1a-bf90-b2c1e98d3b9b">

- Brute Force attack with Metro on port 22 using hydra against 192.168.1.100 used default metro settings and alerts showing on ubuntu2 snort 
### 5.3 Executed an FTP brute force attack
#### hydra -v -L $user_file -P $pass_file FTP://$target_ip:21 -o credentials.txt 

<img width="961" alt="ftp attack" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/c1a262ff-8179-4400-aefb-69f960a75edb">
<img width="961" alt="ftp attack results " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/52b50947-967f-485e-a7f5-a7c2d33c5999">

- Brute force attack with Metro on port 21 using hydra against 192.168.1.200 used Metro changed SSH default to FTP and alerts showing on ubuntu2 snort  

## 6. Dashboards 
#### Utilization of Splunk’s tools to craft dashboards for visualizing logs and events. We used Splunk's integrated Snort app for Snort dashboarding. Created custom Dashboards for Ubuntu and Ubuntu2 syslog to show events by time, top commands used and top users. Created Custom Apache2 Dashboard to show events by time and logs. Created Windows Security Dashboard showing logon attempts, used privileges and logon events over time. Created Splunk Statistics Dashboard showing top sources. Created Cisco Router Dashboard showing simple logs. These dashboards help in the ease of monitoring critical parts of the network quickly and effectively. 

- Log into your Splunk enterprise account and click search & reporting


- Click dashboards


- Click create new dashboard


- Click edit on the top right


- Click source to edit the script for the type of graph you want to create


- Paste your own dashboards script or copy and paste a script from the internet for a pre-made custom dashboard

<img width="960" alt="ubuntu syslog" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/1085eefd-1918-4e01-a6a7-e9b4718426c9">
<img width="960" alt="apache2" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/832179b6-00ea-49ca-b354-ca053fe89ad5">

- Example of Ubuntu Syslog & Apache2 dashboards

<img width="960" alt="security dashboard" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/c71a5489-891a-45fb-b6fa-7f714ce116df">
<img width="960" alt="router router" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/6c7f7c0f-e2d7-448b-88ab-7d334acdab51">

- Example of Windows Security and Router dashboards

<img width="960" alt="attack" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/3146606e-d8c1-4e0c-aa2e-ed18a04670bc">
<img width="960" alt="dahsborad 1" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/01841afa-cef0-4a79-9bc5-0aa73b29b495">

- Example of Snort dashboards on Splunk showing alerts 






## Bonus (Advanced Features) 

### Active Directory 
#### Active Directory (AD) is a directory service developed by Microsoft for Windows domain networks. It is a centralized and hierarchical database that stores information about network resources, such as computers, users, groups, and other devices, within a network. Active Directory provides authentication and authorization mechanisms, allowing administrators to manage and control access to resources across the network. Active Directory plays a crucial role in enterprise environments by providing a centralized platform for managing and securing network resources, simplifying administrative tasks, and enabling features such as single sign-on (SSO) and directory-based authentication. It is widely used in businesses and organizations that rely on Windows-based infrastructure for their IT operations. 

## Integrating Ubuntu1 and Ubuntu2 Linux machines into Windows Active Directory Domain.
### 1. Windows Server 2019 Configuration 


- Within server manager on dashboard click manage (top right) 


 
- Click install roles and features 


- Role-based or feature-based installation and click next


- Select a server and click next


- Select Active Directory Domain Services and DNS Server


- Click install and wait for installation to finish



- Select “Promote this server to a domain controller



- Add a new forest and enter your domain name



- Create a password and leave the rest as default



- Click next



- Click install to finish

  For testing purposes, create a new user in Active Directory.


- Click tools and select Active Directory Users and Computers



- Select domain, then right click Users, and select New then select User



- Fill out the necessary information to create the new user

### 2. Windows 10 Configuration 


- Go to settings then click systems then click about and select join a domain


- Enter the user account and set the account type


- Enter user information to join domain and click ok


- Enter domain name and hit next to join

### 3. Linux Configurations 



- In the Ubuntu machine and open the wired settings and select the IPv4 tab and enter the IP address of the Windows Server 2019 as the DNS IP address for the Ubuntu machine


- Install the necessary packages and content and then search for domain through realm and join. 
- Enter command Sudo apt -y install realmd sssd sssd-tools libnss-sss libpam-sss adcli samba-common-bin oddjob oddjob-mkhomedir packagekit 
- Realm discover tyrinethan.com [domain name] 
- Realm join tyrinethan.com [domain name]



- Verify if it is possible to retrieve an Active Directory user information
- Enter command Id a.mitt@tyrinethan.com [username@domain]




- Test login as an Active Directory user
- Su – a.mitt@tyrinethan.com [username@domain] 


### Active Directory Logs Example

<img width="800" alt="log testing " src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/cd9b6c58-4d4e-4ee6-8fb6-4201bf3d6c8b"> 
<img width="941" alt="not auths" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/a700153c-2eb6-41d3-83b2-92ecaddeb2e9">
<img width="800" alt="notaloowed" src="https://github.com/Tdot23/Traffic-Monitoring-and-Analysis-Project/assets/162403774/9aa242de-83c0-4b36-8a71-7338c758d458">

## DNS
### 1. Create Host A within DNS Forward Look Up Zone 

#### DNS stands for Domain Name System. It is a hierarchical decentralized naming 
system for computers, services, or any resource connected to the Internet or a private 
network. The primary function of DNS is to translate human-friendly domain names, such 
as www.example.com, into numerical IP addresses, such as 192.0.2.1, which are used by 
computers to identify each other on the network. A forward lookup zone is a component 
of the Domain Name System (DNS) that is responsible for translating domain names into IP 
addresses. It is the process of mapping a domain name (like example.com) to its 
corresponding IP address (such as 192.0.2.1).



- On server manager dashboard click tools and select DNS


- Expand MYSERVER, then right click domain name and select New Host (A or AAAA)



- Fill in the necessary information and click add host


### Sources

- https://github.com/adot8/metro 
- https://docs.splunk.com/Documentation/Splunk/9.2.0/Installation/InstallonWindows 
- https://www.groovypost.com/howto/join-a-windows-10-client-domain/ 
- https://www.snort.org/ 
- https://www.server-world.info/en/note?os=Ubuntu_22.04&p=realmd 
- https://docs.snort.org/rules/ 
- https://docs.splunk.com/Documentation/SplunkCloud/latest/SearchTutorial/Createnewdashboard 
- Forwarding Snort Logs To Splunk (youtube.com) 
- Setting Up Splunk (youtube.com) 
- Getting Data into Splunk using Universal Forwarders (youtube.com) 
