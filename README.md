👨‍💻 # Build-ElasticStack-ELK-Lab 🚀
--- 
## Objective 🎯


The Build-ElasticStack-ELK-Lab project aimed to create a controlled environment for simulating and detecting cyber attacks. The main focus was on ingesting and analyzing logs within a Security Information and Event Management (SIEM) system, while generating test telemetry to replicate real-world attack scenarios. This hands-on experience was designed to enhance understanding of network security, attack patterns, and defensive strategies.

## Skills Learned 🔍

- Advanced understanding of SIEM concepts and practical application.
- Proficiency in analyzing and interpreting network logs.
- Ability to generate and recognize attack signatures and patterns.
- Enhanced knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.
---
 ## Tools Used 🔧

- Security Information and Event Management (SIEM) system for log ingestion and analysis.
- Telemetry generation tools to create realistic network traffic and attack scenarios.
```bash
  
   ```
Steps
---
## setup Kibana in ubuntu and Configure Elasticsearch

Elasticsearch components are not included in Ubuntu's default package repositories. However, they can be installed via APT by adding Elastic’s official package source. To ensure security and prevent package spoofing, all packages are signed with a GPG key, allowing the package manager to verify their authenticity. To proceed with the installation, let's import the public GPG key and add the Elastic package source list.<br>

```powershell
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
   ```
![image](https://github.com/user-attachments/assets/96ffc58c-3234-4915-bd10-7584c2b7c105)<br>

- <a href="https://artifacts.elastic.co/GPG-KEY-elasticsearch">elasticsearch</a>: Elasticsearch’s public GPG key, a cryptographic "signature" used to verify the authenticity of packages.<br>

- `--dearmor`: Converts the GPG key from human-readable text to binary format because Debian’s apt expects keys in binary format for verification.<br>

Next, let's add Elasticsearch Repository to APT Sources:<br>
```powershell
  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
   ```
![image](https://github.com/user-attachments/assets/604bd51d-836f-4d68-a79e-de6d1f96d94b)<br>
- The `[signed-by=...]` option ensures packages from this repository are verified using the GPG key.<br>
- Here I'm telling apt where to find Elasticsearch packages<a href="https://artifacts.elastic.co/packages/8.x/apt">Link</a>.<br>
  Next, let's update our APT packages index with the new Elastic source:<br>
  ```powershell
  sudo apt-get update
   ```
  ![image](https://github.com/user-attachments/assets/d881c16a-8d7b-4fbe-8a08-6a065b725a7b)<br>
Next, let's install the Elasticsearch Debian package.<br>
```powershell
  sudo apt-get install elasticsearch
   ```
![image](https://github.com/user-attachments/assets/d78dac33-dd56-4391-8702-9c120fa860fa)<br>
Next, we need to update the elasticsearch.yml with following network host and port configurations.<br>
```powershell
  sudo nano /etc/elasticsearch/elasticsearch.yml
   ```
![image](https://github.com/user-attachments/assets/373732e5-a223-46ef-8a93-de270f34dd6b)<br>
Now, let's enable Elasticsearch to start automatically on system boot.<br>
```powershell
  sudo systemctl daemon-reload
  sudo systemctl enable elasticsearch
   ```
![image](https://github.com/user-attachments/assets/9384052b-6bb4-4b1b-89b5-a7cd53bc664d)<br>
Next, let's start the elasticsearch Service:<br>
```powershell
  sudo systemctl start elasticsearch
  sudo systemctl status elasticsearch
   ```
![image](https://github.com/user-attachments/assets/b9ed7e64-12fd-48f1-82a7-bf12f8f6e2b5)<br>
Now, we need to confirm that Elasticsearch is running correctly and is accessible via HTTPS on `localhost:9200`.<br>
![Inked1_1-1](https://github.com/user-attachments/assets/bc1fa39f-0d3d-4fa0-9982-2c23753347cb)<br>

We can also confirm the service is up and accessible using this command:<br>
```powershell
   sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200
   ```
![2](https://github.com/user-attachments/assets/8f7a7af7-1af9-485d-b306-f789ec7a33fc)<br>

The file `/etc/elasticsearch/certs/http_ca.crt` is the CA certificate generated during Elasticsearch installation.<br>
Now, let's install and configure Kibana. It is part of the Elastic Stack, so it uses the same repository we added for Elasticsearch.<br>
```powershell
  sudo apt-get install kibana
   ```
Now, we need to edit `kibana.yml`  file to determine how it connects to Elasticsearch and how it behaves.<br>
```powershell
  sudo nano /etc/kibana/kibana.yml
   ```
![image](https://github.com/user-attachments/assets/e981d63e-0ed1-474a-b244-47ce618a1add)<br>
- `server.port: 5601` : the port on which Kibana will run
- `server.host: "0.0.0.0"` : the IP address Kibana will bind to (Setting this to `0.0.0.0` allows Kibana to be accessed from other machines on the network.)
- `elasticsearch.hosts: ["http://localhost:9200"]` : the Elasticsearch instance Kibana will connect to
  Next, let's enable Kibana to ensures it starts automatically when the system boots.<br>
  ```powershell
  sudo systemctl enable kibana
   ```
  Then, let's start the Kibana service:<br>
  ```powershell
  sudo systemctl start kibana
   ```
  ![image](https://github.com/user-attachments/assets/7de9a6a9-10d6-46e4-b4d6-868484862542)<br>
Now, let's make sure Kibana is running:<br>
![image](https://github.com/user-attachments/assets/4d33d94b-a4fd-4905-99f7-aed3457ab842)<br>
Now, we need to generate an enrollment token for Kibana and using it to securely connect Kibana to Elasticsearch.<br>
```powershell
  sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
   ```
![image](https://github.com/user-attachments/assets/480f6257-f75d-4314-91f9-497372adfb4c)<br>
Next, let's open Kibana, enter the copied token into the input field, and click Configure Elastic to proceed.<br>
![image](https://github.com/user-attachments/assets/e4b06d6b-de3f-46b5-8efd-9d3cf6b35417)<br>
After this Kibana prompted for Verification code.
![image](https://github.com/user-attachments/assets/e902fee1-84fd-436a-bf12-a18e4ff3b84b)<br>
To generate Verification code , we need to navigate to Kibana installation directory and execute the following script.<br>
```powershell
   sudo /usr/share/kibana/bin/kibana-verification-code
   ```
![image](https://github.com/user-attachments/assets/5daf9210-5507-49b4-87d2-3e0cb3da088f)<br>
![image](https://github.com/user-attachments/assets/8c591721-a78b-4c40-afc3-6656e5b93972)<br>
Next, let's proceed with logging in using the provided username and password.<br>
![image](https://github.com/user-attachments/assets/899cf33d-9d7c-485b-b36b-bfd2f55aecb0)<br>
![image](https://github.com/user-attachments/assets/9d75e15f-4d7e-4aa8-92f7-77f307c27a8d)<br>

---

## Configure Fluent-Bit to send logs to ELK
![image](https://github.com/user-attachments/assets/2b4309dd-875c-4e35-a104-892fec6ca77b)<br>

### Prerequisites:
![3](https://github.com/user-attachments/assets/ff39ac1e-1f98-429a-aca5-b204f3b5e8e0)<br>
the example from <a href="https://docs.fluentbit.io/manual/installation/windows#configuration">doc-Fluent-Bit</a><br>
Let's begin by installing Fluent-Bit on Windows.<br>
```powershell
   [SERVICE]
    # Flush
    # =====
    # set an interval of seconds before to flush records to a destination
    flush        5

    # Daemon
    # ======
    # instruct Fluent Bit to run in foreground or background mode.
    daemon       Off

    # Log_Level
    # =========
    # Set the verbosity level of the service, values can be:
    #
    # - error
    # - warning
    # - info
    # - debug
    # - trace
    #
    # by default 'info' is set, that means it includes 'error' and 'warning'.
    log_level    info

    # Parsers File
    # ============
    # specify an optional 'Parsers' configuration file
    parsers_file parsers.conf

    # Plugins File
    # ============
    # specify an optional 'Plugins' configuration file to load external plugins.
    plugins_file plugins.conf

    # HTTP Server
    # ===========
    # Enable/Disable the built-in HTTP Server for metrics
    http_server  Off
    http_listen  0.0.0.0
    http_port    2020

    # Storage
    # =======
    # Fluent Bit can use memory and filesystem buffering based mechanisms
    #
    # - https://docs.fluentbit.io/manual/administration/buffering-and-storage
    #
    # storage metrics
    # ---------------
    # publish storage pipeline metrics in '/api/v1/storage'. The metrics are
    # exported only if the 'http_server' option is enabled.
    #
    storage.metrics on

[INPUT]
    Name         winlog
    Channels     Setup,Windows PowerShell
    Interval_Sec 1

[OUTPUT]
    name  stdout
    match *
   ```
Let's begin by installing Fluent-Bit on Windows in the websit<br>
![4](https://github.com/user-attachments/assets/1332f277-3aa8-4cda-b223-869472fc1884)<br>
after the download file <br>
![image](https://github.com/user-attachments/assets/0e750052-153c-479a-a828-5ee955589d44)<br>
We have a log file named `network_sample.log` that we need to be ingested into the ELK stack. To ensure accurate data extraction, we will begin by crafting an appropriate regular expression to parse the required information.<br>
#### what is regex<br>
A regular expression (regex) is a sequence of characters that defines a search pattern. It is used to match, extract, or manipulate specific parts of text. Regex is particularly useful for working with unstructured or semi-structured log data, where patterns need to be identified or extracted.<br>
```bash
  SRC=(?<src_ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+DST=(?<dst_ip>\d{1,3}.\d{1,3}.\d{1,3}.
\d{1,3})\s+PROTO=(?<protocol>\w+)\s+SPT=(?<src_port>\d+)?\s+DPT=(?<dst_port>\d+)?\s+
LEN=(?<lenght>\d+)?\s+ACTION=(?<action>\w+)
   ```
![image](https://github.com/user-attachments/assets/89f9d9e4-527c-4c6d-b7ca-df49b1845f0a)<br>
A line does not match the current regular expression. Let's create a new one to accommodate it.<br>
```bash
  SRC=(?<src_ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s+DST=(?<dst_ip>\d{1,3}.\d{1,3}.\d{1,3}.
\d{1,3})\s+PROTO=(?<protocol>\w+)\s+TYPE=(?<type>\w+)\s+CODE=(?<code>\d+)\s+ID=(?<id>\d
+)\s+ACTION=(?<action>\w+)
   ```
![image](https://github.com/user-attachments/assets/418cf426-adbe-4337-b285-07d03f941162)<br>
Note: the Regex quick reference<br>
![5](https://github.com/user-attachments/assets/957acd41-73c5-4cfd-8f67-8e01d4dd7be4)<br>
Next, we need to modify the `parsers.conf` file located in `C:\Program Files\fluent-bit\conf`.<br>
![image](https://github.com/user-attachments/assets/56ccf7fa-b838-44d4-a3e0-4e1f672d06b1)<br>
Next, we need to configure the `fluent-bit.conf` file, located at `C:\Program Files\fluent-bit\conf`, to forward logs to the ELK stack.<br>
```bash
  [INPUT]
    Name         tail
    Parser       firewall-logs-1
    Path         C:\Users\NV\Downloads\network_sample.log
    Tag          firewall.logs-1

[INPUT]
    Name         tail
    Parser       firewall-logs-2
    Path         C:\Users\NV\Downloads\network_sample.log
    Tag          firewall.logs-2
    
[OUTPUT]
    name    	  es
    match   	  *
    Host    	  192.168.204.146
    Port    	  9200
    Match   	  *
    HTTP_User     elastic
    HTTP_Passwd   =Op+25maKY3GqC=IrV7m
    tls           on
    tls.verify    off 
    Trace_Output  on 
    Suppress_Type_Name on
   ```
![image](https://github.com/user-attachments/assets/fc313f2d-6e29-4a50-8ff6-228c6bfa8374)<br>
This configuration is for Fluent Bit to read logs from a file (`C:/Users/NV/Downloads/network_sample.log`) and forward them to an Elasticsearch instance.<br>

- `name tail`: The `tail` input plugin reads log files line by line, similar to the `tail -f` command in Linux.
- `parser firewall-logs-1`: Defines the parser used for processing log entries. The `firewall-logs` parser is specified in the parsers.conf file to extract structured fields from the logs efficiently.
- path `C:/Users/NV/Downloads/network_sample.log`: The path to the log file to monitor. Fluent Bit will read new lines appended to this file.

  For the `OUTPUT`:<br>
- `name es`: The es output plugin sends logs to Elasticsearch.

- `Host 192.168.204.146`: The IP address or hostname of the Elasticsearch server.

- `Port 9200`: The port where Elasticsearch is listening (default is 9200).

- `tls on`: Enables TLS/SSL encryption for communication with Elasticsearch.

- `tls.verify off`: Disables certificate verification.

- `Trace_Output on`: Enables verbose logging for debugging purposes.

Now, let's run Fluent Bit:<br> 
```powershell
   & 'C:\Program Files\fluent-bit\bin\fluent-bit.exe' -c 'C:\Program Files\fluent-bit\conf\fluent-bit.conf'
   ```
![image](https://github.com/user-attachments/assets/93fdde05-4bcf-46e6-acaf-646413f062a3)<br>
We need to duplicate specific lines within the network_sample.log file and save the changes.<br>

Let's confirm whether the logs are successfully being forwarded to ELK.<br>
![image](https://github.com/user-attachments/assets/315bd877-4361-45e4-bee0-c8b183f44b3f)<br>
![image](https://github.com/user-attachments/assets/0c93bb22-3166-414d-ab58-593bf8782f6b)<br>

---
## Set up Winlogbeat and Filebeat for log collection

### Winlogbeat
We will begin by installing Winlogbeat on our Windows machine.<br>
<a hrfe="https://www.elastic.co/downloads/beats/winlogbeat">Winlogbeat</a><br>
![6](https://github.com/user-attachments/assets/0f8b0259-cefb-4e7b-886f-cd24764ea158)<br>
after download we need to extract the contents into `C:\Program Files`<br>
![image](https://github.com/user-attachments/assets/aad45036-4dcf-42f9-8e14-85296bdaec26)<br>
Next, let's run the following commands to install the service.<br>
```powershell
   PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
   ```
![image](https://github.com/user-attachments/assets/b688a4b1-914a-4b2b-b6e7-3958e87c79dc)<br>
Next, we need to modify the winlogbeat.yml configuration file to enable the Windows event logs we want to collect:<br>
![image](https://github.com/user-attachments/assets/92981da3-0faf-4cf1-a82e-b57ead1c8cb4)
Event IDs:<br>

- `4688`: A new process has been created.

- `4624`: An account was successfully logged on.

- `4625`: An account failed to log on.

- `4720`: A user account was created.

- `1102`: The audit log was cleared

Next, let's update the Elasticsearch output section:<br>
![image](https://github.com/user-attachments/assets/5ad945cb-0ce4-4a97-926c-45a1aafb12e6)
- `ssl.verification_mode`: none → This will bypass the certificate check.<br>

- `protocol: "https"` → This tells Winlogbeat to use the HTTPS protocol when connecting.<br>

This configures Winlogbeat to securely (or at least over HTTPS, though without SSL verification) send logs to a specific Elasticsearch server using a username and password.<br>

Now, we need to test the configuration file to identify any potential issues.<br>
```powershell
  .\winlogbeat.exe test config -c .\winlogbeat.yml -e
   ```
![image](https://github.com/user-attachments/assets/95745514-d111-41fa-8bd5-c3e648b1735a)<br>
We can also test the connection to our output by running:<br>
```powershell
  .\winlogbeat.exe test output -c .\winlogbeat.yml -e
   ```
![image](https://github.com/user-attachments/assets/6ea83476-162f-4f49-a447-ccc23d409154)<br>
Next, we need to start the winlogbeat service:<br>
```powershell
  Start-Service winlogbeat
Get-Service winlogbeat
   ```
![image](https://github.com/user-attachments/assets/eb0feb43-d89b-4ff3-9f8d-36173dfc6df3)<br>
Next, we need to run Winlogbeat using the winlogbeat.yml configuration file and shows real-time logs in the console.<br>
```powershell
  .\winlogbeat.exe -c .\winlogbeat.yml -e
   ```
![image](https://github.com/user-attachments/assets/b8c406f2-49f8-47e8-80a1-f6a9d94977fc)<br>
- `.\winlogbeat.exe` → Runs the Winlogbeat program to collect windows logs.

- `-c .\winlogbeat.yml` → Uses the winlogbeat.yml file for configuration (tells Winlogbeat where to send logs, like Logstash).

-  `-e` → Shows log messages on the screen instead of saving them to a file

 Now, let's verify that the logs are properly displayed in Kibana.<br>
 ![image](https://github.com/user-attachments/assets/c3a05bed-f8f5-4686-b769-c42b787fd18f)<br>
then we can run `HOSTNAME.EXE`<br>
![image](https://github.com/user-attachments/assets/18c3c919-d1fd-442a-8ace-b2d3f762436b)<br>

---
### Filebeat
![7](https://github.com/user-attachments/assets/e8e61549-09c2-4755-8d6a-8747d68fdb9a)<br>
Filebeat, as the name implies, `hips log files`. In an ELK-based logging pipeline, Filebeat plays the role of the logging agent—installed on the machine generating the log files, tailing them, and forwarding the data to either Logstash for more advanced processing or directly into Elasticsearch for indexing.<br>
Now , we need to install Filebeat useed commandline and Let's start by adding Elastic’s GPG key to verify the packages:<br>
```bash
  wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elastic-keyring.gpg
   ```
![image](https://github.com/user-attachments/assets/0fac454f-0083-4f80-bd76-8222a1316edd)<br>
Next, we need to add the Elastic repository to our system:<br>
```bash
  echo "deb [signed-by=/usr/share/keyrings/elastic-keyring.gpg] 
https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee 
/etc/apt/sources.list.d/elastic-8.x.list
   ```
![image](https://github.com/user-attachments/assets/99a91634-3cef-43d6-99f6-4eb53784614a)<br>
Next, let's update the package list and install Filebeat.<br>

```bash
  sudo apt update && sudo apt install filebeat
   ```
![image](https://github.com/user-attachments/assets/3346bd13-ce53-4cb0-902c-6a685e145080)<br>
The next step is to open the Filebeat configuration file.<br>
```bash
  sudo nano /etc/filebeat/filebeat.yml
   ```
![image](https://github.com/user-attachments/assets/52e850b1-ac15-43b4-b51c-b2ca7828bf2d)<br>
Filebeat is configured to read logs from system logs `(/var/log/*.log)`.<br>

Now we need to edit the file also to send logs directly to Elasticsearch.<br>
![image](https://github.com/user-attachments/assets/2a3369e1-d3b3-4792-859c-b3e6ccb3385c)<br>
Next, we need to start the Filebeat service and configure it to launch automatically at system startup.<br>
```bash
  sudo systemctl start filebeat
  sudo systemctl enable filebeat
  sudo systemctl status filebeat
   ```
![image](https://github.com/user-attachments/assets/d2ee2329-9522-4518-9871-6078cc7fb2b3)<br>
Let's check the Filebeat configuration for any errors.<br>
```bash
  sudo filebeat test config
   ```
Let's also test the connection to Elasticsearch by running:<br>
```bash
  sudo filebeat test output
   ```
![image](https://github.com/user-attachments/assets/9c35c279-9c0d-41f7-bab4-d830476d70e3)<br>
Let's verify whether the logs are being displayed in ELK.<br>
![image](https://github.com/user-attachments/assets/822fd89b-0432-4eac-aa90-065115626a73)<br>
![image](https://github.com/user-attachments/assets/812201e8-ab08-4ce8-b50e-b9888a8e63dc)<br>


---
## Send Logs from Winlogbeat through Logstash to ELK
I have successfully installed Elasticsearch and Kibana on an Ubuntu machine. Now, I would like to install Logstash on a separate Ubuntu machine.<br>
```bash
  sudo apt update && sudo apt install logstash -y
   ```
Logstash needs a configuration file to tell it where to receive logs from and where to send them. So let's make a new one for Winlogbeat.<br>
```bash
  sudo nano /etc/logstash/conf.d/winlogbeat.conf
   ```
![image](https://github.com/user-attachments/assets/ae06f38b-c8fb-43ea-ba27-a4689eb74b71)<br>
Replace the IP address, username, and password with your own credentials.<br>

Before starting Logstash, let's check if the configuration is correct:<br>
```bash
  sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
   ```
![image](https://github.com/user-attachments/assets/aec7cedf-195a-4a6c-9792-b15499a466b5)<br>
`"Configuration OK"`, the config is good!<br>
This command will parse the configuration files (including any files in `/etc/logstash/conf.d/`) and report any errors or warnings.<br>

- `-t` → It parses and validates all the configuration files (found in the directory specified by `--path.settings`, such as `/etc/logstash`) to check for syntax errors or misconfigurations, then exits once testing is complete. This is useful because it allows us to ensure the configuration is correct before we start processing events.<br>
Now let's start and enable Logstash.<br>
```bash
  sudo systemctl start logstash.service
  sudo systemctl enable logstash.service
  sudo systemctl status logstash.service
   ```
![image](https://github.com/user-attachments/assets/50a634bf-0fa3-4537-b254-9e432e1df1d9)<br>
Next, we need to configure Logstash to listen for incoming data from Winlogbeat on port 5044.<br>
```bash
  /usr/share/logstash/bin/logstash -f /etc/logstash/conf.d/winlogbeat.conf
   ```
![image](https://github.com/user-attachments/assets/a2529b81-df49-4e9b-9707-b8a9b6659350)<br>
When you run this command:<br>
1- Logstash will start and load the configuration from `/etc/logstash/conf.d/winlogbeat.conf`.<br>
2- It will begin listening for incoming data (from Winlogbeat on port `5044`).<br>
3- It will process the data according to the configuration and send it to the specified output ( Elasticsearch).<br>
Let's verify if there are any issues.<br>
```bash
  sudo journalctl -u logstash --no-pager --lines=50
   ```
![image](https://github.com/user-attachments/assets/98a0e041-bb41-49bc-acb9-cda637ee823e)<br>
This command displays the most recent 50 log lines from the Logstash service. <br>
Now we need to configure Winlogbeat to Send Logs to Logstash.<br>
```bash
  .\notepad.exe 'C:\Program Files\Winlogbeat\winlogbeat.yml'
   ```
![image](https://github.com/user-attachments/assets/31e18c18-bff9-465e-a3cc-e17d99816e06)<br>
We need to replace with our Logstash machine's IP.<br>
Next let's test the configuration:<br>
```bash
  .\winlogbeat.exe test config -c .\winlogbeat.yml
   ```
![image](https://github.com/user-attachments/assets/ecf57c87-65bc-4018-bfa1-2b098b70f6a4)<br>
Next, let's start the service:<br>
```bash
  Start-Service winlogbeat
  Get-service winlogbeat
   ```
![image](https://github.com/user-attachments/assets/9ad88547-b404-44ca-966e-e85c280d4151)<br>
Before sending logs, let's check the connection to the configured output (Logstash) is established.<br>
```bash
.\winlogbeat.exe test output
   ```
![image](https://github.com/user-attachments/assets/e31f3c59-fc1f-45da-a028-7074154da82d)<br>
This command verifies if Winlogbeat can successfully send logs to the configured destination.<br>
Next, we need to run Winlogbeat using the winlogbeat.yml configuration file and shows real-time logs in the console.<br>
```bash
.\winlogbeat.exe -c .\winlogbeat.yml -e 
   ```
![image](https://github.com/user-attachments/assets/7ae0fcec-1fd7-4af4-88fd-3470c2f0c550)<br>
- `.\winlogbeat.exe` → Runs the Winlogbeat program to collect windows logs.<br>
- `-c .\winlogbeat.yml` → Uses the winlogbeat.yml file for configuration (tells Winlogbeat where to send logs, like Logstash).<br>
- `-e` → Shows log messages on the screen instead of saving them to a file.<br>
We now need to confirm whether ELK successfully receives logs from Logstash.<br>
From Stack Management  → Index Management<br>
![image](https://github.com/user-attachments/assets/1188f177-0a95-467e-9a2f-e226cfa58c40)<br>
Let's create an index and review the logs on the Discover page.<br>
![image](https://github.com/user-attachments/assets/2a6ec345-a2a6-448d-9134-0f4699f30d0c)<br>
```bash
HOSTNAME.EXE
   ```
![image](https://github.com/user-attachments/assets/abacc0da-2515-4f15-b948-9171567a8b03)<br>
![image](https://github.com/user-attachments/assets/6d1a8506-1cbc-42ed-abc6-e1269022f85d)<br>


--- 

## Enable Windows Audit Policy & Winlogbeat
### Prerequisites 🔧
We have successfully set up Elasticsearch and Kibana on the Ubuntu machine. The next step is to install Winlogbeat and configure it to send logs to the ELK stack. However, before proceeding with the installation, we need to apply specific policies to the Sales OU that was previously created.<br>
#### `Process Creation Logging`:
```bash
Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > 
System Audit Policies - Local Group Policy Object > Detailed Tracking
   ```
![image](https://github.com/user-attachments/assets/2b8d376d-d807-48b9-b3bd-66c558fc7572)<br>
Let's call it Audit Logging.<br>
![image](https://github.com/user-attachments/assets/250418b3-569b-4cef-a020-e55be462e861)<br><br>
![image](https://github.com/user-attachments/assets/ee413402-671a-4620-909c-a3db428da877)<br>
![image](https://github.com/user-attachments/assets/9e962349-dd35-4c3c-9f85-cb2274f5508f)<br>
![image](https://github.com/user-attachments/assets/3d8a8f29-55d7-449e-bfc3-a414ed601519)<br>
#### `Logon and Authentication Auditing:`<br>
```bash
Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > 
System Audit Policies - Local Group Policy Object > Logon/Logoff
   ```
![image](https://github.com/user-attachments/assets/d88ca56c-9099-4b62-a360-92b96d710d57)<br>
![image](https://github.com/user-attachments/assets/a5af2841-41de-44ed-b977-02ce9361b183)<br><br>
![image](https://github.com/user-attachments/assets/4537f7dd-2fcc-4c70-a586-cf3eb491ca14)<br>
![image](https://github.com/user-attachments/assets/7e7d83be-3534-4856-ab8b-7fa4fcf82062)<br>
![image](https://github.com/user-attachments/assets/83a4f9c2-703f-49cf-8922-76d4babf2c60)<br>
Next, we need to run the following command on the client machine to apply the policy:<br>
```bash
   gpupdate /force
   ```
![image](https://github.com/user-attachments/assets/87ef0f12-9f9a-40ab-956d-460d379c102d)<br>
Next, we need to configure Winlogbeat on the Windows Client.<br>
![image](https://github.com/user-attachments/assets/c4209804-8638-4550-afe6-37e0810105ad)<br>
Next, let's start the service:<br>
```bash
   Start-Service winlogbeat
   Get-service winlogbeat
   ```
![image](https://github.com/user-attachments/assets/68ac3a6d-180c-4198-ac40-d7f1f48f8786)<br>
Next, we will proceed with testing the configuration.<br>
```bash
   .\winlogbeat.exe test config -c .\winlogbeat.yml
   ```
![image](https://github.com/user-attachments/assets/3346fabb-7ab6-42c4-82af-d756acf91c22)<br>
Before sending logs, let's check the connection to the configured output (Elasticsearch) is established.<br>
```bash
   .\winlogbeat.exe test output
   ```
![image](https://github.com/user-attachments/assets/479d7966-b6cb-4558-819d-f5169c6fa19d)<br>
This command verifies if Winlogbeat can successfully send logs to the configured destination.<br>
Next, we need to start Winlogbeat using the `winlogbeat.yml` configuration file to capture and display real-time logs in the console.<br>
```bash
   .\winlogbeat.exe -c .\winlogbeat.yml -e
   ```
![image](https://github.com/user-attachments/assets/c5b06993-269a-4479-8506-327fed7ee5df)<br>
- `.\winlogbeat.exe` → Runs the Winlogbeat program to collect windows logs.<br>

- `-c .\winlogbeat.yml` → Uses the winlogbeat.yml file for configuration (tells Winlogbeat where to send logs, like Elasticsearch).<br>

- `-e` → Shows log messages on the screen instead of saving them to a file.<br>
We now need to confirm whether ELK successfully receives logs from Winlogbeat.<br>

From Stack Management  → Index Management <br>

![image](https://github.com/user-attachments/assets/66c9bd0b-05a6-4f26-9250-ea9883b11cb4)<br>
![image](https://github.com/user-attachments/assets/64c85c4e-f749-4d06-853b-ec815e9c150a)<br>
Let's apply filters based on specific Event IDs.<br>
![image](https://github.com/user-attachments/assets/e4e2a17f-b1af-42c6-988b-92857893286f)<br>
`4688`:A new process has been created.<br>
![image](https://github.com/user-attachments/assets/6cd0ddab-b118-40aa-89a1-cc09d6693e33)<br>
`4624`: An account was successfully logged on.<br>
![image](https://github.com/user-attachments/assets/43adc2a6-ffbf-4b21-b2d0-f9c27657cff8)<br>
`4672`: Special privileges assigned to new logon.<br>
Let's create a dashboard that visualizes data of the Client01 machine.<br>
![image](https://github.com/user-attachments/assets/f39e1b5e-ca26-4c1d-8c81-378921c0fa50)<br>


--- 
