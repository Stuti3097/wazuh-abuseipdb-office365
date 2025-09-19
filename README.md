# AbuseIPDB Office 365 Integration

## Overview

This integration enriches **Office 365 failed login events** in Wazuh with **IP reputation data from AbuseIPDB**.

When a failed login is detected in Office 365 logs, the source IP (`ClientIP` or `ClientIPAddress`) is automatically queried against AbuseIPDB. If the IP has a high abuse confidence score, Wazuh generates an enriched alert including:

* Abuse confidence score
* ISP
* Country
* Domain
* Last reported time

This enables security teams to quickly identify suspicious login attempts and prioritize investigation.

---

## Prerequisites

* **Wazuh version:** Tested with Wazuh 4.12
* **Office 365 integration** enabled and logs forwarded into Wazuh
* **AbuseIPDB API key** (register at [AbuseIPDB](https://www.abuseipdb.com/))

---

## Repository Structure

```
integrations/
└── abuseipdb_office365/
    ├── ruleset/
    │   └── rules/
    │       └── local_rules.xml
    ├── integrations/
    │   └── custom-abuseipdb.py
    └── README.md
```

* `ruleset/rules/local_rules.xml`: Custom rules to trigger alerts based on AbuseIPDB reputation results.
* `integrations/custom-abuseipdb.py`: Python integration script that queries AbuseIPDB.
* `README.md`: Documentation for installation, configuration, and testing.

---

## Installation and Configuration

### 1. Install Wazuh

A standard Wazuh installation is assumed. If Wazuh is not installed, refer to the [official documentation](https://documentation.wazuh.com/current/installation-guide/index.html).

### 2. Configure Office 365 Logs

Ensure Office 365 failed login events are being collected and parsed. You should see failed login alerts in the Wazuh Dashboard before enabling this integration.

### 3. Deploy Integration Files

1. Copy the integration script:

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

3. Copy the rules file:

```bash
cp ruleset/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml
```

> Modify the rules if you want the integration to trigger for more Office 365 events.

4. Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```

---

## How It Works

1. Office 365 failed login events are ingested by Wazuh.
2. The integration script extracts the source IP.
3. The script queries AbuseIPDB.
4. Wazuh enriches the alert with AbuseIPDB results.
5. Rules generate alerts when the abuse confidence score is high.

---

## Testing

1. Simulate a failed Office 365 login event from a test account.
2. Check Wazuh logs for AbuseIPDB enrichment (example output):

```json
{
  "abuseipdb": {
    "found": 1,
    "srcip": "123.58.209.224",
    "abuse_confidence_score": 100,
    "country_code": "HK",
    "isp": "UCLOUD INFORMATION TECHNOLOGY (HK) LIMITED",
    "domain": "ucloud.cn",
    "total_reports": 5726,
    "last_reported_at": "2025-09-16T07:00:19+00:00"
  },
  "integration": "custom-abuseipdb"
}
```

3. Verify enriched alerts in the Wazuh Dashboard.

![dashboard\_example](https://github.com/user-attachments/assets/ea841b6f-58d8-4324-94b2-6f4931b25b3c)

---

## Sources

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [AbuseIPDB API Documentation](https://docs.abuseipdb.com/)
