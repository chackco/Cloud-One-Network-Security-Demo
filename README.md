# Cloud One: Network Security demo

Spins up a Network Security demo environment. This includes:

1. `NetworkSecurityRole` IAM role
2. Network Security AWS connector
3. Reduced Network Security appliance size (suitable for lab environments) 
4. CloudWatch logging
5. Public Linux instance running DVWA

# Setup

1. Generate a Cloud One API key. Export it as an environment variable:
   
```
export C1_KEY=<API_KEY>
```

2. Clone the repo

3. Spin up the environment:
   
```
git clone https://github.com/OzNetNerd/Cloud-One-Network-Security-Demo.git
cd Cloud-One-Network-Security-Demo/src
python c1ns_lab.py <AWS_SSH_KEY_NAME>
```

### Example run

```
Getting AWS account details...
Region: ap-southeast-2, Account ID: 922275582614
Getting Network Security details...
Network Security Account ID: 737318609257, External ID: 6cd37248-e354-4aa1-a6dd-e9b72950481a
Creating cross account role...
Created stack: NetworkSecurityRole
Stack "NetworkSecurityRole" already exists
Network Security role ARN: arn:aws:iam::922275582614:role/NetworkSecurityRole
Creating Network Security AWS Connector...
Done
Spinning up vulnerable lab environment...
Created stack: c1ns-demo-infra
Stack "c1ns-demo-infra" already exists
Done
Spinning up C1NS appliance...
IGW ID: igw-0b975aedbdfed3037
Generated CFN stack
Creating C1NS appliance stack...
Created stack: c1ns-appliance
Stack "c1ns-appliance" already exists
Done
```

# Attacks 

Navigate to the CloudFormation "Outputs" tab, then complete one or both of the below attacks.

## Curl

Run the `curl` command. 

## SQL Injection

1. Browse to the `DvwaPublicIp` URL.

2. Log in with the following credentials: `admin` and `password`

3. Click `SQL Injection` and in the `User ID` field, enter the following string:

```
%' or '0'='0`
```

## Protection

To block the SQL attacks, set the following Network Security rules to `block`: 

* 3593 
* 5674


## Logging

1. Navigate to CloudWatch. Search for the `network_security_logs` log group.
2. Locate the `inspection_event` log stream. 
3. Browse the logs until you find entries such as this:

```
{
    "version": "2",
    "accountid": "<ACCOUNT_ID>",
    "sequence": "4",
    "severity": "1",
    "filter": "5674: HTTP: SQL Injection (Boolean Identity)",
    "protocol": "http",
    "src-ip": "<ATTACKER_IP>",
    "src-port": "28898",
    "dst-ip": "10.0.0.95",
    "dst-port": "80",
    "hitcount": "1",
    "action": "Block",
    "uri-ipaddress": "<ATTACKER_IP>",
    "http-method": "GET",
    "http-hosttrunc": "no",
    "http-hostname": "54-153-179-28",
    "http-uritrunc": "no",
    "http-uri": "/vulnerabilities/sqli/?id=1&Submit=Submit"
}
```
