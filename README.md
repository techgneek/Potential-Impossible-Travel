
# 🚨 Potential Impossible Travel – Sentinel Detection & Investigation

**Author:** James Moore  
**Date:** May 5, 2025  
**Type:** Detection & Incident Response  
**Tools:** Microsoft Sentinel, KQL, Azure AD   
**MITRE ATT&CK Mapping:**  T1078: Valid Accounts & T1110: Brute Force (supporting context if credentials were stolen)

![ChatGPT Image May 5, 2025, 02_01_07 AM](https://github.com/user-attachments/assets/731de3ce-68df-45a7-ae28-c85c6a8e5674)

---

## 📘 Scenario Overview

Some organizations have strict policies against account sharing, VPN obfuscation, or logins from outside designated regions. This lab focuses on identifying **"impossible travel"** — when a single user logs in from two or more distant geographic locations within a short timeframe.  

The goal is to detect suspicious login behavior using **SigninLogs**, trigger an alert in **Microsoft Sentinel**, and conduct a full investigation to determine whether the activity is benign or malicious.

---

## 🔍 Step 1: Query for Impossible Travel (30-day Range)

This KQL query detects users logging in from more than one location within the last 30 days:

```kql
let TimePeriodThreshold = timespan(30d);
let NumberOfDifferentLocationsAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, 
    City = tostring(parse_json(LocationDetails).city), 
    State = tostring(parse_json(LocationDetails).state), 
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

📌 **Sample Output**

![Potential Travel Query Results](./Screen%20Shot%202025-05-05%20at%201.15.12%20AM.png)

<img width="850" alt="Screen Shot 2025-05-05 at 1 15 39 AM" src="https://github.com/user-attachments/assets/135cde0f-763f-43f0-8750-bde5992a8449" />

---

## 🔎 Step 2: Investigate a Specific User

We focused on a user account that triggered the alert for potential impossible travel.

**Targeted Account:**
`4b6170f4076f94d321c7b7949d7aa81d2ec0d018b3a955f949f3a9e53e8ee05f@lognpacific.com`

```kql
let TimePeriodThreshold = timespan(30d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == "4b6170f4076f94d321c7b7949d7aa81d2ec0d018b3a955f949f3a9e53e8ee05f@lognpacific.com"
| project TimeGenerated, UserPrincipalName, 
    City = tostring(parse_json(LocationDetails).city), 
    State = tostring(parse_json(LocationDetails).state), 
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

📌 **Login Activity Timeline**

![User Login Timeline](./Screen%20Shot%202025-05-05%20at%201.15.39%20AM.png)

<img width="850" alt="Screen Shot 2025-05-05 at 1 15 12 AM" src="https://github.com/user-attachments/assets/77423562-4085-4729-b772-7b8577277f3d" />

---

## 🧪 Investigation Findings

The user logged in from **Boydton, Virginia** and **Levittown, New York** within a 3-hour period. All locations were within the **United States**, and login behavior appeared consistent with normal travel or expected remote access patterns.

✅ **Determination:** True Positive, but **Benign**
🔒 **Action Taken:** No containment necessary. The account was **not disabled**.

---

## 🛡️ Containment, Eradication, and Recovery

No malicious behavior was detected.
The alert was closed as **Benign Positive**.

✔️ No need for isolation
✔️ No password reset or account disablement

---

## 🧭 Post-Incident Recommendations

We recommend the following improvements for enhanced security posture:

* 🔐 **Implement geofencing** to restrict login access to approved countries
* ⚙️ Regularly monitor login anomalies using automated Sentinel rules
* 🗺️ Evaluate VPN usage policy and adjust alert thresholds accordingly

---

## 📘 References

* MITRE ATT\&CK Framework – [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/)
* Microsoft Documentation – [SigninLogs Reference](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-sign-ins-log-schema)
* NIST 800-61 – Incident Handling Guide

---
