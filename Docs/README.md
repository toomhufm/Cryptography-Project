# Efficient and Secure File Transfer in Cloud Through Hybrid Encryption Using CP-ABE

## Abstract
Cloud services are already hiring information thanks to recent developments in cloud computing. Users may get low-cost storage using cloud services like Dropbox and Google Drive. Here, we give a security mechanism that offers a higher level of protection and access control. 

## Scenario
In this scenario, a finance company is using a cloud service to store their private digital assets ( contracts, internal documentation, etc). Therefore, they will be facing several security issues like data breach, insider threat. 


<p align="center">
  <img src="https://user-images.githubusercontent.com/92283038/231777466-f807a84c-b556-45aa-88bd-ba196d392caa.png" />
</p>

| Subject     | Description |
| ----------- | ----------- |
|Related-Party | Data owner, cloud Service, recipients, attacker|
| Goal | Prevent user private data from being viewed by unassociated person|

| Security Goals| 
| ----------- |
| Data Confidentiality | 
| Data Intergity |
| Access Control |
## Solution

To fullfill the security goals we proposed before, our solution is using Ciphertext-Policies Attributes-Based Encryption ( CP-ABE )

The Figure 1 describes how CP-ABE work. 
The encrypted data requires some certain attributes of the user in order to decrypt. For example, to be able to decrypt this data, user must have role President or name is Alice and location is Ha Noi.
![image](https://user-images.githubusercontent.com/92283038/231779474-eed588ea-849d-4eed-a5b7-8eee1ad6736a.png)


<p align="center"> 
<img src="https://user-images.githubusercontent.com/92283038/231779378-8bc46e7f-bc74-4c46-b7de-785dc02123bf.png">
<p align="center">Figure 1. CP-ABE</p>
</p>

### Why we choose CP-ABE?

1.Data confidentiality:

Data Confidentiality is a set of rules or a promise that limits access or places restrictions on certain types of information. In cloud, the data was encrypted by the data owner and unauthorized parties including the cloud cannot know the information about the encrypted data hence data confidentiality is maintained.

2. Secured access control:

Secured Access Control is any mechanism by which a cloud system grants or revokes the right to access some data, or perform some action. In cloud users are granted with different access right to access data to provide security.

3. User revocation:

If the user quits the system, the scheme can revoke his access right from the system directly. The revocable user cannot access any stored data, because his access right was revoked.


<p align="center"> 
<img src="https://user-images.githubusercontent.com/92283038/231780537-6b19041d-c456-40b8-b9a1-ff03cfb4dac0.png">
<p align="center">Figure 2. Mechanism Workflow </p>
</p>




## Implementation Plan

### Tools and resources
|   Tools and resources   | Description |
| ----------- | ----------- |
|Python | Programming Language|
| flask | Python Framework for Python Web Application | 
| PyCrypto| Python Library for Cryptography |
| MySQL | Data Storage | 
| Google Drive API | Interact with Google Drive Service | 


### Tasks chart

|   Name   | ID | Frontend Development | Backend Development| Presentation |
| ----------- | ----------- |  :----------: | :----------: | :----------: |
| Nguyễn Trần Anh Đức | 21521964 | X| X | X |
| Nguyễn Hữu Tiến | 21520479 | X | X |  |
| Lê Thanh Duẩn | 19521370 | | X | | 
