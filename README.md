# 🛠️ Active Directory Automation Script with Vault + Excel/CSV Support

This tool automates **Active Directory user operations** (create, modify, delete, group assignments) using data from `.csv` or `.xlsx` files.

🧠 Secrets (LDAP server, domain user, password) are securely fetched from **HashiCorp Vault**.

---

## 🔐 Prerequisites

- Python 3.8+
- Active Directory connectivity
- HashiCorp Vault with the following secret:

```json
Path: secret/ad/config
{
  "ldap_server": "dc01.corp.local",
  "domain_user": "CORP\\adminuser",
  "domain_pass": "YourSecurePassword"
}


## File Structure
├── ad_user_manager.py
├── vault_config.yaml
├── users.xlsx or users.csv
├── requirements.txt
├── logs/
│   └── ad_tasks.log


## Input file format:

| action | cn    | display\_name | password   | ou                        | attr  | value            | add\_to\_groups | remove\_from\_groups |
| ------ | ----- | ------------- | ---------- | ------------------------- | ----- | ---------------- | --------------- | -------------------- |
| create | jdoe  | John Doe      | Welcome\@1 | OU=Users,DC=corp,DC=local |       |                  | DevTeam,QA      |                      |
| modify | jdoe  |               |            |                           | title | Senior Developer | DevOps          | QA                   |
| delete | temp1 |               |            |                           |       |                  |                 |                      |


## Usage :
python ad_user_manager.py --vault vault_config.yaml --users users.xlsx

## Features:
🔐 Secure credential retrieval via HashiCorp Vault

📥 Supports both Excel (.xlsx) and CSV (.csv) input

📂 Daily rotating log file in logs/ad_tasks.log

⚠️ Error handling and logging for each operation

✅ Group add/remove support