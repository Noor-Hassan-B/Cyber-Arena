# Documented Attack Scenarios & Multi-Source Datasets

This document provides complete forensic walkthroughs for the three pre-packaged multi-source attack scenarios included with the platform.

---

## Scenario 1: SCN-APT29-GHOST
### "Operation GhostToken: Hybrid Enterprise Infiltration"
- **Threat Actor Archetype:** APT29 / Cozy Bear (State-Sponsored Espionage)
- **Target Environment:** Hybrid Enterprise (Active Directory on-premise + AWS Cloud Infrastructure)
- **Attack Vector:** Spearphishing Document with Macro -> In-Memory PowerShell -> AWS STS Cloud Exfiltration
- **Calculated Confidence Score:** 0.94 (Critical Severity)

### Attack Sequence Walkthrough:
1. **Initial Access (`T1566.001` - Spearphishing Attachment):**  
   Victim employee `sarah.connor` downloads and opens `Q4_Executive_Bonus_Matrix.docm` on finance workstation `WKSTN-FIN-04` (`[EVT-APT-001]`).
2. **Execution (`T1059.001` - PowerShell Execution):**  
   `winword.exe` spawns a hidden, AMSI-bypassed PowerShell download cradle executing base64 payload from `185.220.101.5` (`[EVT-APT-002]`).
3. **Command & Control (`T1071.001` - Web Protocols):**  
   `WKSTN-FIN-04` establishes periodic TLS 1.3 encrypted beaconing to `c2-telemetry-sync.net` with 12% jitter (`[EVT-APT-003]`).
4. **Credential Access (`T1003.001` - LSASS Memory Dumping):**  
   Adversary uses `rundll32.exe comsvcs.dll` to dump process memory of `lsass.exe` to `C:\Users\Public\lsass.dmp` (`[EVT-APT-004]`).
5. **Credential Access (`T1558.003` - Kerberoasting):**  
   Adversary requests RC4-encrypted Kerberos service tickets for `svc_sqladmin` against Domain Controller `DC01.corp.local` (`[EVT-APT-005]`).
6. **Lateral Movement (`T1047` - Windows Management Instrumentation):**  
   Remote WMI invocation pivots execution from `WKSTN-FIN-04` to `DC01.corp.local` executing secondary stager `srvmgr.exe` (`[EVT-APT-006]`).
7. **Discovery / Credential Access (`T1552.001` - Credentials in Files):**  
   Attacker reads plaintext AWS credentials located in `C:\Users\sarah.connor\.aws\credentials` (`[EVT-APT-007]`).
8. **Privilege Escalation (`T1078.004` - Cloud Accounts Compromise):**  
   Adversary external IP `185.220.101.5` calls AWS STS `AssumeRole` to assume `ProductionDataOpsRole` without MFA (`[EVT-APT-008]`).
9. **Collection (`T1530` - Data from Cloud Storage):**  
   Massive `GetObject` operations against S3 bucket `corp-prod-financial-snapshots` downloading 1.49 GB of customer Parquet files (`[EVT-APT-009]`).
10. **Exfiltration (`T1048` - Exfiltration Over Alternative Protocol):**  
    1.54 GB transferred across network egress gateway to foreign IP `91.240.118.12` in Switzerland (`[EVT-APT-010]`).

---

## Scenario 2: SCN-RANSOM-BLACKCAT
### "Double-Extortion Ransomware Campaign"
- **Threat Actor Archetype:** ALPHV / BlackCat
- **Target Environment:** On-Premise Enterprise File & Backup Infrastructure
- **Attack Vector:** VPN Credential Stuffing -> Admin RDP -> Shadow Copy Purge -> File Encryption
- **Calculated Confidence Score:** 0.98 (Critical Severity)

### Attack Sequence Walkthrough:
1. **Initial Access (`T1133` - External Remote Services):**  
   Attacker brute-forces perimeter Fortinet VPN gateway from IP `194.26.29.112` using harvested credentials for `svc_backup` (`[EVT-RSM-001]`).
2. **Lateral Movement (`T1021.001` - Remote Desktop Protocol):**  
   Direct RDP connection (Logon Type 10) initiated from the VPN gateway to enterprise file repository `SRV-FILE-01` (`[EVT-RSM-002]`).
3. **Discovery (`T1046` - Network Service Discovery):**  
   SYN port scan sweep across internal subnet `10.0.2.0/24` identifying reachable SMB shares (`[EVT-RSM-003]`).
4. **Defense Evasion (`T1490` - Inhibit System Recovery):**  
   Execution of `vssadmin.exe delete shadows /all /quiet` deleting 18 Volume Shadow Copies to prevent disaster recovery (`[EVT-RSM-004]`).
5. **Defense Evasion (`T1562.001` - Disable or Modify Tools):**  
   Execution of `net stop WinDefend & sc config WinDefend start= disabled` terminating endpoint security (`[EVT-RSM-005]`).
6. **Exfiltration (`T1567.002` - Exfiltration to Cloud Storage):**  
   Execution of `mega-cmd.exe` exfiltrating 4.2 GB of corporate spreadsheets to Mega cloud storage (`[EVT-RSM-006]`).
7. **Impact (`T1486` - Data Encrypted for Impact):**  
   Multi-threaded encryptor detonate across `C:\Shares`, encrypting 42,918 files with `.alphv` extension and dropping `HOW_TO_RESTORE.txt` (`[EVT-RSM-007]`).

---

## Scenario 3: SCN-CLOUD-CRYPTOMINE
### "Cloud-Native IAM Hijack & Compute Hijacking"
- **Threat Actor Archetype:** TeamTNT / Cloud Threat Group
- **Target Environment:** Amazon Web Services (AWS) Cloud
- **Attack Vector:** Leaked Git Token -> AdministratorAccess Attachment -> CloudTrail Sabotage -> GPU Mining Fleet
- **Calculated Confidence Score:** 0.91 (High Severity)

### Attack Sequence Walkthrough:
1. **Persistence (`T1098` - Account Manipulation):**  
   Compromised CI/CD developer key used from external IP `198.51.100.77` to create secondary access key `AKIAIOSFODNN7EXAMPLE` (`[EVT-CLD-001]`).
2. **Privilege Escalation (`T1078.004` - Cloud Accounts Compromise):**  
   Unauthorized AWS IAM `AttachUserPolicy` attaching `AdministratorAccess` (`[EVT-CLD-002]`).
3. **Defense Evasion (`T1562.008` - Disable Cloud Logs):**  
   CloudTrail `StopLogging` executed on `production-audit-trail` to blind security operations (`[EVT-CLD-003]`).
4. **Impact (`T1496` - Resource Hijacking):**  
   EC2 `RunInstances` API call provisioning 16 GPU-accelerated `g4dn.12xlarge` instances across `eu-west-1` (`[EVT-CLD-004]`).
5. **Impact (`T1496` - Resource Hijacking):**  
   XMRig instances direct continuous high-hashrate (98.4 MH/s) stratum TCP outbound traffic to `xmr.pool.minergate.com` (`[EVT-CLD-005]`).
