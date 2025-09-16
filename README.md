# Wazuh-AbuseIPDB-Office365 Integration

## Table of Contents

* [Introduction](#introduction)
* [Prerequisites](#prerequisites)
* [Installation and Configuration](#installation-and-configuration)

  * [Installing Wazuh](#installing-wazuh)
  * [Initial Wazuh Configuration](#initial-wazuh-configuration)
  * [Using the Integration Files](#using-the-integration-files)
* [Integration Steps](#integration-steps)
* [Integration Testing](#integration-testing)
* [Sources](#sources)

---

## Introduction

This integration enriches **Office 365 failed login events** in Wazuh with **IP reputation data from AbuseIPDB**.

When a failed login is detected in Office 365 logs, the Client IP is automatically queried against AbuseIPDB. If the IP has a high abuse confidence score, Wazuh generates an alert enriched with details such as:

* Abuse confidence score
* ISP
* Country
* Domain
* Last reported time

This helps security teams quickly identify suspicious login attempts and prioritize investigation.

---

## Prerequisites

* **Wazuh Manager** v4.7.0 or later
* **Office 365 integration** enabled in Wazuh (logs forwarded and parsed)
* **AbuseIPDB API key** (register at [AbuseIPDB](https://www.abuseipdb.com/))
* Tested on **Wazuh version 4.12**

---

## Installation and Configuration

### Installing Wazuh

A standard Wazuh installation is assumed. If Wazuh is not installed, follow the official guide: [Wazuh Installation Documentation](https://documentation.wazuh.com/current/installation-guide/index.html)

### Initial Wazuh Configuration

Ensure that Office 365 logs are being correctly collected and parsed. You should already see alerts for **failed logins** in your Wazuh Dashboard before enabling this integration.

### Using the Integration Files

This repository provides:

* **`custom-abuseipdb.py`** → Python script that queries AbuseIPDB
* **`local_rules.xml`** → Custom Wazuh rules to generate alerts based on AbuseIPDB results

Steps:

1. Copy `custom-abuseipdb.py` to the integrations folder:

   ```bash
   chmod 750 /var/ossec/integrations/custom-abuseipdb.py
   chown root:wazuh /var/ossec/integrations/custom-abuseipdb.py
   ```

2. Add the integration to `/var/ossec/etc/ossec.conf`:

   ```xml
   <integration>
     <name>custom-abuseipdb</name>
     <hook_url>https://api.abuseipdb.com/api/v2/check</hook_url>
     <api_key>YOUR_ABUSEIPDB_API_KEY</api_key>
     <rule_id>91534</rule_id>
     <alert_format>json</alert_format>
   </integration>
   ```

> You can add additional Office 365 rules if you want the integration to trigger for more events, or specify groups for targeted alerts.

3. Copy `local_rules.xml` to:

   ```bash
   /var/ossec/etc/rules/local_rules.xml
   ```

> Modify the rules in `local_rules.xml` according to your requirements.

4. Restart the Wazuh Manager:

   ```bash
   systemctl restart wazuh-manager
   ```

---

## Integration Steps

1. Office 365 failed login events are ingested by Wazuh.
2. The integration script extracts the source IP (`ClientIP` or `ClientIPAddress`).
3. The script queries AbuseIPDB for the IP reputation.
4. Wazuh enriches the alert with AbuseIPDB data.
5. Custom rules raise alerts if the confidence score indicates malicious activity.

---

## Integration Testing

1. Generate a failed Office 365 login attempt from a test account. For example:

```json
{"integration":"office365","office365":{"AppAccessContext":{"APIId":"9d6d-4c70-b22a-34c7ea72d73d","ClientAppId":"6326e366-9d6d-4c70-b22a-34c7ea72d73d","IssuedAtTime":"2025-08-12T03:30:06","UniqueTokenId":"90c5c1c5-f767-4ac3-8845-d5683cc6d"},"CreationTime":"2025-08-12T03:30:07","Id":"cf89-4784-7f8f-08ddd95088dd","Operation":"Update","OrganizationId":"5622ad4e-cf23-49a9-8a97-2fe4f267e0f5","RecordType":2,"ResultStatus":"Failed","UserKey":"366-9d6d-4c70-b22a-34c7ea72d73d","UserType":5,"Version":1,"Workload":"Exchange","ClientIP":"123.58.209.224","UserId":"xyz@abc.com","ActorInfoString":"Client=REST;Client=RESTSystem;UserAgent=[NoUserAgent][AppId=9d6d-4c70-b22a-34c7ea72d73d];","AppId":"9d6d-4c70-b22a-34c7ea72d73d","ClientAppId":"9d6d-4c70-b22a-34c7ea72d73d","ClientIPAddress":"123.58.209.224","ClientInfoString":"Client=REST;Client=RESTSystem;;","ClientRequestId":"012178f7-8783-41dc-8a8d-9105d9efcc17","ExternalAccess":false,"InternalLogonType":0,"LogonType":0,"LogonUserSid":"S-1-5-21-1466721135-3797337417-3004919804-11037310","MailboxGuid":"c2f3803f-3ddd-441a-bdc0-e5f1bcd21387","MailboxOwnerSid":"S-1-5-21-1466721135-3797337417-3004919804-11037310","MailboxOwnerUPN":"xyz@abc.com","OrganizationName":"abcltd.onmicrosoft.com","OriginatingServer":"TY2PPF958A0EDC6 (15.20.4200.000)\\r\\n","TokenTenantId":"8a97-2fe4f267e0f5","Item":{"Attachments":"image001.png (6076b)","Id":"RgAAAADFQfS0nuYeRJYvbUzcSkV8BwAyvQC+7F1UR4cEmOL/orypAAAAAAENAAAyvQC+7F1UR4cEmOL/orypAARRtCr8AAAP","ImmutableId":"qmYRzZvIAKoAL8RaDQAyvQC+7F1UR4cEmOL/orypAAYgXk+LAAAP","InternetMessageId":"<SE2PPF9B114191AC565C60BF3CDA9A8D73F9D28A@S2765652F9B114191A.apcprd04.prod.outlook.com>","IsRecord":false,"ParentFolder":{"Id":"nuYeRJYvbUzcSkV8AQAyvQC+7F1UR4cEmOL/orypAAAAAAENAAAC","Path":"\\\\Calendar"},"SizeInBytes":53207,"Subject":"2W Electronic cluster assembly line NPD demand vs capacity discussion"},"ModifiedProperties":["RecipientCollection"],"Subscription":"Audit.Exchange","FailureReason":"AuthenticationFailed"}}
```

2. Check logs for AbuseIPDB integration event data:

```json
{"timestamp":"2025-09-16T07:25:20.470+0000","agent":{"id":"000","name":"Server1"},"manager":{"name":"Server1"},"id":"1758007520.38217","full_log":"{\"abuseipdb\": {\"found\": 1, \"source\": {\"alert_id\": \"1758007517.38217\", \"rule\": \"91534\", \"description\": \"Office 365: Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.\", \"full_log\": \"\", \"srcip\": \"123.58.209.224\"}, \"abuse_confidence_score\": 100, \"country_code\": \"HK\", \"usage_type\": \"Data Center/Web Hosting/Transit\", \"isp\": \"UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED\", \"domain\": \"ucloud.cn\", \"total_reports\": 5726, \"last_reported_at\": \"2025-09-16T07:00:19+00:00\"}, \"integration\": \"custom-abuseipdb\"}","decoder":{"name":"json"},"data":{"abuseipdb":{"found":"1","source":{"alert_id":"1758007517.38217","rule":"91534","description":"Office 3 65: Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.","srcip":"123.58.209.224"},"abuse_confidence_score":"100","country_code":"HK","usage_type":"Data Center/Web Hosting/Transit","isp":"UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED","domain":"ucloud.cn","total_reports":"5726","last_reported_at":"2025-09-16T07:00:19+00:00"},"integration":"custom-abuseipdb"},"location":"abuseipdb"}
```

3. Confirm the Wazuh Dashboard shows enriched alerts.
<img width="1919" height="892" alt="image" src="https://github.com/user-attachments/assets/ea841b6f-58d8-4324-94b2-6f4931b25b3c" />


---

## Sources

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)

---
