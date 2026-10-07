# THREAT HUNT REPORT

---

# 1. FRONT MATTER AND DOCUMENT CONTROL

| | |
|---|---|
| Report title | Harborlight Dental - Akira Ransomware Compromise |
| Hunt ID | HD-HUNT-2026-001 |
| Author | Casey Scott Ledbetter |
| Version | 1.0 |
| Date issued (UTC) | 2026-10-06 |
| Classification / handling | TLP:RED / Strictly Confidential |
| Distribution | Incident Response Team, IT Leadership |

**Revision history**

| Version | Date (UTC) | Author | Change |
|---|---|---|---|
| 1.0 | 2026-10-06 | Casey Scott Ledbetter | Initial report and handover to IR |

# 2. EXECUTIVE SUMMARY

I conducted a threat hunt across the Harborlight Dental estate targeting signs of post-compromise activity following anomalous alerts on BACKOFFICE-PC1. My hunt confirmed a complete, multi-stage ransomware compromise by an actor deploying the Akira ransomware variant.

I tracked the attacker gaining initial access via BACKOFFICE-PC1, bypassing local User Account Control, and dumping local credentials. I traced their lateral movement to the Domain Controller (ADDC01) where they extracted the Active Directory database, achieving full domain compromise. Before the ransomware deployment, I observed the attacker staging and exfiltrating sensitive data (including PatientData) using archiving tools and legitimate cloud sync utilities, and establishing persistence by creating a rogue domain admin account (`svc_sql`). I confirmed the actor concluded the attack by wiping event logs, deleting shadow copies, and executing the Akira encryptor across the estate. I am closing this hunt and formally handing it over to Incident Response.

# 3. OVERVIEW METADATA

| | |
|---|---|
| Hunt type | Hypothesis-driven |
| Trigger | Anomalous process execution alerts on BACKOFFICE-PC1 |
| Period hunted (UTC) | 2026-02-03 00:00:00 to 2026-02-04 23:59:59 |
| Estate in scope | BACKOFFICE-PC1, HL-FS01, ADDC01 |
| Analyst(s) | Casey Scott Ledbetter |
| Time spent | 4 hours |

# 4. HYPOTHESIS AND ABLE SCOPE

**Hypothesis:** An external threat actor compromised a workstation, escalated privileges, moved laterally to compromise the domain, and executed a double-extortion ransomware playbook (exfiltration followed by encryption).

**ABLE:**

| | |
|---|---|
| **A**ctor | Unattributed (Akira Ransomware Affiliate) |
| **B**ehaviour | UAC bypasses, credential dumping, rogue account creation, archiving/exfiltration, and volume shadow copy deletion. |
| **L**ocation | Workstations (BACKOFFICE-PC1), File Servers (HL-FS01), and Domain Controllers (ADDC01). |
| **E**vidence | Sysmon Event ID 1 (Process Creation) for LolBins, Event ID 11 for `.akira` files, and Event IDs 8/10 for LSASS access. |

# 5. THREAT INTEL INPUTS

| Input | Source / link | How it shaped the hunt |
|---|---|---|
| Akira Ransomware Playbook | CISA / Industry reporting | Directed my search for dual-use tools (rclone, megasync), AD enumeration, and log clearing via `wevtutil`. |

# 6. SCOPE, DATA SOURCES AND BLIND SPOTS

| Data source | Platform | Period available | Confidence in coverage |
|---|---|---|---|
| Sysmon | Microsoft Sentinel | 30 Days | High |
| Windows Security Events | Microsoft Sentinel | 30 Days | Medium |

**Blind spots.** Network packet capture (PCAP) and firewall egress logs were not analyzed. I confirmed tools like `rclone` and `curl` were executed, but without network egress logs, I cannot definitively quantify the exact byte count of exfiltrated data, only what was staged.

# 7. EXECUTION

## 7.1 Tracing Initial Privilege Escalation

**Question:** How did the attacker escalate privileges on the initial beachhead (BACKOFFICE-PC1)?

```kql
HarborlightDental_CL
| where host == "BACKOFFICE-PC1"
| where EventID == 1
| where CommandLine has "reg add" and CommandLine has "ms-settings"
| project EventTime, Image, CommandLine
| order by EventTime asc
```

[📸 SCREENSHOT: Execute the ms-settings / reg add query above. Capture the results showing the UAC bypass execution.]

**Returned:** Hits for registry modifications targeting ms-settings.
**Read:** I concluded the attacker utilized known UAC bypass techniques to execute payloads with High Integrity.

## 7.2 Confirming Credential Dumping

**Question:** Did the attacker steal local credentials to enable lateral movement?

```kql
HarborlightDental_CL
| where host == "BACKOFFICE-PC1" and EventID == 10
| extend SourceImage = extract("SourceImage'>([^<]+)", 1, EventData_Xml)
| extend TargetImage = extract("TargetImage'>([^<]+)", 1, EventData_Xml)
| where TargetImage has "lsass.exe"
| project EventTime, SourceImage, TargetImage, granted_access
```

[📸 SCREENSHOT: Execute the LSASS access query above. Capture the results showing the malicious source process accessing LSASS memory.]

**Returned:** Source processes successfully accessing lsass.exe.
**Read:** I confirmed the attacker performed OS credential dumping on the beachhead to harvest credentials.

## 7.3 Confirming Domain Compromise

**Question:** Did the attacker successfully access domain credentials on the Domain Controller?

```kql
HarborlightDental_CL
| where host == "ADDC01"
| where EventID == 1
| where CommandLine has_any ("ntdsutil", "vssadmin", "ntds.dit", "dcsync", "secretsdump", "diskshadow")
| project EventTime, Image, CommandLine
| order by EventTime asc
```
> 📸 **SCREENSHOT:** Execute the ntdsutil query above. Capture the output proving the attacker extracted the Active Directory database.

**Returned:** Execution of ntdsutil to extract the ntds.dit database.

**Read:** I determined the attacker achieved full domain compromise by extracting the Active Directory credential database.

## 7.4 Data Exfiltration

**Question:** Was sensitive data staged and exfiltrated out of the network?

```kusto
HarborlightDental_CL
| where EventID == 1
| where OriginalFileName has_any ("rclone", "megasync", "curl", "7z", "rar")
| project EventTime, host, Image, OriginalFileName, CommandLine
| order by EventTime
```

> 📸 **SCREENSHOT:** Execute the exfiltration query above. Capture the rows showing rclone and 7z execution.

**Returned:** Execution of 7z targeting PatientData and rclone configurations.

**Read:** I confirmed the first half of the double-extortion playbook. Patient data was archived and prepped for exfiltration.

## 7.5 Persistence Mechanisms

**Question:** Did the attacker leave behind active backdoor accounts?

```kusto
HarborlightDental_CL
| where CommandLine has "svc_sql" or CommandLine has "New-ADUser" or (CommandLine has "net user" and CommandLine has "/add")
| project EventTime, host, Image, CommandLine
| order by EventTime asc
```

> 📸 **SCREENSHOT:** Execute the svc_sql persistence query above. Capture the evidence showing the rogue account creation for the IR team.

**Returned:** Commands confirming the addition of the svc_sql account to domain groups.

**Read:** I verified the attacker established persistent Domain Admin access via a newly created service account.

## 7.6 Defense Evasion and Impact

**Question:** Did the attacker inhibit system recovery and deploy ransomware?

```kusto
HarborlightDental_CL
| where CommandLine has_any ("vssadmin", "shadowcopy", "wbadmin", "bcdedit", "delete shadows", "recoveryenabled")
| project EventTime, host, Image, CommandLine
| order by EventTime asc
```

> 📸 **SCREENSHOT:** Execute the vssadmin query above. Capture the shadow copy deletion commands.

```kusto
HarborlightDental_CL
| where File_Name endswith ".akira" or TargetFilename endswith ".akira" or CommandLine has ".akira"
| project EventTime, host, Image, CommandLine
```

> 📸 **SCREENSHOT:** Execute the .akira query above. Capture the results proving the final encryption payload executed across the hosts.

**Returned:** Volume shadow copy deletions and commands/files referencing .akira.

**Read:** I observed the attacker successfully wiped recovery points and deployed the Akira encryptor.

## 7.7 Dead ends

| Hypothesis tested | Query | Result | Why rejected |
|---|---|---|---|
| Target files encrypted natively | `where File_Name endswith ".akira" \| summarize DistinctEncryptedFiles = dcount(EncryptedFile)` | Returned 28 instead of 27. | Coalescing fields inadvertently included a dir command execution output by the attacker. I refined the logic to strictly trace File Create events. |

---

## 8. UTC Timeline

| Time (UTC) | Event | Source | Evidence ref |
|---|---|---|---|
| 2026-02-03 21:13:00 | Initial execution and UAC bypass on BACKOFFICE-PC1 | Sysmon (Event ID 1) | Section 7.1 |
| 2026-02-03 21:14:00 | LSASS memory accessed for credential dumping | Sysmon (Event ID 10) | Section 7.2 |
| 2026-02-03 21:15:00 | Extraction of NTDS.dit on ADDC01 | Sysmon (Event ID 1) | Section 7.3 |
| 2026-02-03 21:21:56 | Creation of svc_sql domain admin account | Sysmon (Event ID 1) | Section 7.5 |
| 2026-02-03 21:23:00 | Archiving of PatientData (7z) and staging (rclone) | Sysmon (Event ID 1) | Section 7.4 |
| 2026-02-03 21:25:00 | Event logs cleared (wevtutil cl) and shadows deleted | Sysmon (Event ID 1) | Section 7.6 |
| 2026-02-04 05:14:15 | Akira ransomware encryptor executed (updater.exe) | Sysmon (Event ID 11) | Section 7.6 |

---

## 9. Findings

### F1 -- Workstation Compromise and Privilege Escalation

- **State it:** The attacker bypassed User Account Control on BACKOFFICE-PC1 to achieve elevated execution.
- **Show it:** Sysmon Event 1 shows `reg add` commands modifying `ms-settings` to spawn High Integrity processes. Reference query in Section 7.1.
- **Interpret it:** This allowed the attacker to run subsequent tools (like credential dumpers) that require administrative rights on the beachhead system.

### F2 -- Full Domain Compromise

- **State it:** The attacker extracted the Active Directory database from the Domain Controller.
- **Show it:** Sysmon Event 1 on ADDC01 records `ntdsutil` being used to create media and extract `ntds.dit`. Reference query in Section 7.3.
- **Interpret it:** The attacker possesses the password hashes for all domain users, granting them persistent, unrestricted lateral movement capabilities.

### F3 -- Persistence via Rogue Account

- **State it:** The attacker created a highly privileged backdoor account.
- **Show it:** Command line logs show `net user svc_sql /add /domain` followed by commands elevating its permissions. Reference query in Section 7.5.
- **Interpret it:** Even if the initial access vector is closed and compromised passwords are reset, the attacker will retain Domain Admin access via svc_sql.

### F4 -- Double Extortion (Theft and Encryption)

- **State it:** Sensitive data was archived for exfiltration, and systems were subsequently encrypted.
- **Show it:** Logs indicate `7z.exe` was used to archive PatientData, followed by the creation/referencing of files ending in `.akira`. Reference queries in Sections 7.4 and 7.6.
- **Interpret it:** This confirms a severe business impact. Patient data has likely been stolen (triggering regulatory notification requirements), and local data is held for ransom.

### 9.x Negative Findings

| Looked for | Where | Method applied | Conclusion |
|---|---|---|---|
| Broad automated worming | Entire estate | Searched for SMB/RPC scanning from BACKOFFICE-PC1 | The attacker appeared to move deliberately and manually via WMI/WinRM rather than deploying a noisy automated lateral movement worm. |

---

## 10. Hypothesis Outcome

**Outcome:** Proved.

**Justification:** My telemetry analysis definitively proves the attacker gained access, escalated privileges, dumped domain credentials, staged patient data for exfiltration, established persistence, and deployed Akira ransomware.

---

## 11. ATT&CK Coverage

### Observed

| Tactic | Technique | ID | Evidence ref |
|---|---|---|---|
| Privilege Escalation | Bypass User Account Control | T1548.002 | F1 / Section 7.1 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | F1 / Section 7.2 |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 | F2 / Section 7.3 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | Query History |
| Impact | Inhibit System Recovery (Shadow Copies) | T1490 | F4 / Section 7.6 |
| Impact | Data Encrypted for Impact | T1486 | F4 / Section 7.6 |

### Hunted, not observed

| Tactic | Technique | ID | Why it was in scope |
|---|---|---|---|
| Lateral Movement | Exploitation of Remote Services | T1210 | I searched for spoolsv.exe anomalies to check for PrintNightmare/RPC exploits; activity was attributed to normal admin tooling or alternate lateral movement. |

---

## 12. Detection and Telemetry Gaps

| Gap | Impact | Fix | Owner |
|---|---|---|---|
| Missing Network Egress Logs | I cannot confirm exact byte count or external destination of exfiltrated data. | Ingest firewall traffic and DNS logs into Sentinel. | Security Engineering |

---

## 13. New Detections Authored

| Name | Logic summary | Data source | Tuning caveats | Status |
|---|---|---|---|---|
| Suspicious NTDS Extraction | Alerts on ntdsutil or vssadmin executed with ntds.dit in command line. | Sysmon / EDR | May trigger on legitimate Domain Controller backup software; requires exclusion for authorized backup service accounts. | Proposed |
| UAC Bypass via Fodhelper | Alerts on execution of fodhelper.exe spawning unexpected child processes. | Sysmon / EDR | Rare false positives; requires baseline of legitimate admin activity. | Proposed |

---

## 14. Handover to IR

| Field | Details |
|---|---|
| Compromise confirmed | Yes |
| Handed to | Incident Response Team |
| Time of handover (UTC) | 2026-10-06 |
| Immediate risks flagged | Domain is fully compromised (NTDS extracted). Active backdoor (svc_sql) exists. Patient data successfully accessed. |

---

## 15. Next-Hunt Leads

| Lead | Why it is worth hunting | Data needed |
|---|---|---|
| Initial Access Vector | I need to determine exactly how the beachhead machine was compromised (phishing payload vs browser exploit) to plug the hole. | Email gateway logs, proxy logs, browser history from BACKOFFICE-PC1. |

---

## 16. Appendices

- **A.** Full queries (Refer to Section 7)
- **B.** Reference list (CISA Akira Ransomware Advisory, MITRE ATT&CK v14)

---

*LOG(N) Pacific Cyber Range. Hunt report shaped to PEAK (Splunk SURGe) and TaHiTI.*

