# Microsoft Sentinel SIEM + Honeypot Lab (Zero-Cost Cloud Deployment)

## Overview

This project demonstrates the end-to-end deployment of a **cloud-based SIEM and honeypot environment using Microsoft Sentinel**, built entirely with **Azure free credits and completed with $0 out-of-pocket cost**.

The lab combines **cloud security architecture, log ingestion, threat hunting, KQL querying, data enrichment, and honeypot exposure** to simulate how a SOC analyst monitors and investigates real-world activity.

---

## Objectives

* Build a fully functional **SIEM using Microsoft Sentinel**
* Deploy a **cloud honeypot** to attract and observe unsolicited activity
* Ingest Windows security logs into **Log Analytics Workspace**
* Perform **threat hunting using KQL**
* Enrich events with **GeoIP data using watchlists**
* Demonstrate understanding of **detections, analytics rules, and incidents**
* Complete the entire project with **zero Azure charges**

---

## Architecture

**Cloud Platform:** Microsoft Azure
**SIEM:** Microsoft Sentinel
**Log Store:** Log Analytics Workspace (LAW)
**Honeypot:** Windows Server 2022 VM (intentionally exposed)
**Network:** Azure Virtual Network + Network Security Group
**Enrichment:** GeoIP Watchlist

### Data Flow

Internet → Honeypot VM → Windows Security Logs → Log Analytics Workspace → Microsoft Sentinel → KQL Analysis

---

## Environment Setup

### 1. Cloud Infrastructure

* Created a dedicated **resource group** for isolation and cost control
* Deployed a **Windows Server 2022 virtual machine**
* Configured **Virtual Network and Network Security Group (NSG)**

### 2. Honeypot Configuration

The VM was intentionally configured as a **honeypot** to attract traffic:

* Opened inbound access at the NSG level
* Allowed RDP connectivity
* Disabled Windows Firewall on all profiles
* Assigned a public IP address
* Verified reachability via ICMP (ping)

This setup simulates a **misconfigured or exposed server**, commonly targeted on the internet.

---

## SIEM Deployment

* Created a **Log Analytics Workspace**
* Connected the Windows VM to the workspace
* Enabled **Microsoft Sentinel** on the workspace
* Verified security telemetry ingestion

---

## Cost Management (Zero Cost)

* Used only Azure free credits
* No paid Sentinel features enabled
* No sustained ingestion beyond lab testing
* All resources deleted after documentation
* Final billing balance: **$0.00**

---

## Log Sources Ingested

* Windows Security Event Logs (`SecurityEvent`)
* Authentication attempts
* Successful and failed logons
* Process creation events
* System and account activity

---

## KQL Threat Hunting Queries

### 1. Event Distribution Analysis

Identifies which security events are most common.

```kql
SecurityEvent
| summarize Count = count() by EventID
| order by Count desc
```

---

### 2. Failed Login Detection (Brute-Force Indicator)

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Account
| order by FailedAttempts desc
```

---

### 3. Successful Authentication Monitoring

```kql
SecurityEvent
| where EventID == 4624
| project TimeGenerated, Account, LogonType, Computer, IpAddress
| order by TimeGenerated desc
```

---

### 4. Process Creation Monitoring

Tracks executed processes and parent-child relationships.

```kql
SecurityEvent
| where EventID == 4688
| project TimeGenerated, Account, Computer, NewProcessName, ParentProcessName
| order by TimeGenerated desc
```

---

### 5. Log Volume Over Time

```kql
SecurityEvent
| summarize Events = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

---

## GeoIP Enrichment (Watchlist + Honeypot)

A **GeoIP watchlist** was imported and used to enrich failed login attempts originating from the honeypot.

```kql
let GeoIPDB = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| evaluate ipv4_lookup(GeoIPDB, IpAddress, network)
| summarize FailureCount = count()
  by IpAddress, latitude, longitude, cityname, countryname
| project FailureCount,
         AttackerIp = IpAddress,
         latitude,
         longitude,
         city = cityname,
         country = countryname,
         friendly_location = strcat(cityname, " (", countryname, ")")
```

This demonstrates:

* Honeypot activity correlation
* IP enrichment
* Geolocation awareness
* SOC-style investigation workflows

---

## Analytics Rules & Detections

* Reviewed Microsoft Sentinel **Analytics Rules**
* Left rules intentionally **disabled** to document a baseline SIEM state
* Demonstrates understanding of:

  * Difference between logs, detections, and incidents
  * Detection engineering lifecycle
  * When alerts should be enabled in production environments

---

## Skills Demonstrated

* Cloud security architecture (Azure)
* SIEM deployment and configuration
* Honeypot design and exposure
* Log ingestion and normalization
* Threat hunting with KQL
* Data enrichment using watchlists
* Network security (NSG, firewall behavior)
* Cost-controlled security engineering
* SOC-level documentation and analysis

---

## Cleanup & Decommissioning

* Deleted VM, disks, public IPs, NSGs, VNets
* Removed Log Analytics Workspace
* Disabled Microsoft Sentinel
* Verified no active resources
* Confirmed **$0.00 total charges**

---

## Key Takeaway

This lab demonstrates how a **SOC analyst or cloud security engineer** can design, monitor, and investigate a **realistic attack surface** using modern SIEM tooling — **without spending money**.

---

Here is a **clean, SOC-grade “Lessons Learned” section** you can **paste directly** into your `INVESTIGATION.md` or `README.md`.
It’s written to sound **professional, reflective, and original** — not tutorial-like.

---

## Lessons Learned

1. **SIEM effectiveness depends on data quality, not just alerts**
   This lab reinforced that meaningful security monitoring starts with validating log ingestion and understanding raw telemetry. Before enabling any detections, confirming log sources, schemas, and event coverage is critical.

2. **Not every suspicious event is an incident**
   Failed authentication attempts and exposed services are common on the internet. Context, correlation, and outcome analysis are required before escalating activity to an incident. The absence of compromise indicators is as important as detecting noise.

3. **KQL is a core SOC skill, not an optional one**
   Writing and refining KQL queries enabled precise threat hunting, event baselining, and correlation. Manual queries provided better insight than relying solely on prebuilt detections, reflecting real-world SOC workflows.

4. **Honeypots generate signal, but also false positives**
   Exposing a system intentionally attracts unsolicited activity, but much of it is automated scanning or self-generated noise. Analysts must distinguish between opportunistic probing and meaningful threats.

5. **Data enrichment significantly improves investigation context**
   GeoIP enrichment using watchlists added geographic context that improved understanding of authentication activity. Enrichment does not confirm malicious intent but helps analysts prioritize and reason about events.

6. **Cloud misconfigurations directly increase attack surface**
   Intentionally permissive NSG rules and disabled host firewalls demonstrated how small configuration changes can drastically alter exposure. This highlights the importance of secure-by-default cloud architectures.

7. **Zero incidents does not mean zero value**
   Even without triggered incidents, the lab provided valuable insight into normal behavior, baseline activity, and detection readiness. Effective SOC work often involves validating that controls are functioning before incidents occur.

8. **Cost awareness is part of security engineering**
   Building, operating, and decommissioning the entire environment using free Azure credits emphasized the importance of cost control. Proper resource scoping and cleanup are essential operational skills.

9. **Clean teardown is as important as deployment**
   Deleting all resources after documentation ensured no lingering exposure or cost. Responsible decommissioning is a critical but often overlooked part of cloud security operations.

---

## License

This project is original work created by Moustafa Mohamed and is licensed under the MIT License.
All analysis, queries, architecture, and documentation were independently designed and implemented.

