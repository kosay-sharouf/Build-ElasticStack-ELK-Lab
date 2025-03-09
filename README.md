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
![image](https://github.com/user-attachments/assets/96ffc58c-3234-4915-bd10-7584c2b7c105)

- <a href="https://artifacts.elastic.co/GPG-KEY-elasticsearch">elasticsearch</a>: Elasticsearch’s public GPG key, a cryptographic "signature" used to verify the authenticity of packages.

- `--dearmor`: Converts the GPG key from human-readable text to binary format because Debian’s apt expects keys in binary format for verification.

Next, let's add Elasticsearch Repository to APT Sources:
```powershell
  echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
   ```
![image](https://github.com/user-attachments/assets/604bd51d-836f-4d68-a79e-de6d1f96d94b)
- The `[signed-by=...]` option ensures packages from this repository are verified using the GPG key.
- Here I'm telling apt where to find Elasticsearch packages<a href="https://artifacts.elastic.co/packages/8.x/apt">Link</a>.
  Next, let's update our APT packages index with the new Elastic source:
  ```powershell
  sudo apt-get update
   ```
  ![image](https://github.com/user-attachments/assets/d881c16a-8d7b-4fbe-8a08-6a065b725a7b)
Next, let's install the Elasticsearch Debian package.
```powershell
  sudo apt-get install elasticsearch
   ```
![image](https://github.com/user-attachments/assets/d78dac33-dd56-4391-8702-9c120fa860fa)
Next, we need to update the elasticsearch.yml with following network host and port configurations.
```powershell
  sudo nano /etc/elasticsearch/elasticsearch.yml
   ```
![image](https://github.com/user-attachments/assets/373732e5-a223-46ef-8a93-de270f34dd6b)
Now, let's enable Elasticsearch to start automatically on system boot.
```powershell
  sudo systemctl daemon-reload
  sudo systemctl enable elasticsearch
   ```
![image](https://github.com/user-attachments/assets/9384052b-6bb4-4b1b-89b5-a7cd53bc664d)
Next, let's start the elasticsearch Service:
```powershell
  sudo systemctl start elasticsearch
  sudo systemctl status elasticsearch
   ```
![image](https://github.com/user-attachments/assets/b9ed7e64-12fd-48f1-82a7-bf12f8f6e2b5)
Now, we need to confirm that Elasticsearch is running correctly and is accessible via HTTPS on `localhost:9200`.
![image](https://github.com/user-attachments/assets/1276315d-22ce-48cf-94b3-16b3be1bbb7e)
We can also confirm the service is up and accessible using this command:
```powershell
   sudo curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200
   ```
