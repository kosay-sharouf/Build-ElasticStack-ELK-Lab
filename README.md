![2](https://github.com/user-attachments/assets/7e5c79ae-476d-4f94-b116-aa67981d6203)👨‍💻 # Build-ElasticStack-ELK-Lab 🚀
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
