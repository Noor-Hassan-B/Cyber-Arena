// =========================================================================
// MITRE ATT&CK Enterprise Framework Reference
// =========================================================================

export const MITRE_TACTICS = [
  { id: 'TA0001', name: 'Initial Access', description: 'Techniques that use various entry vectors to gain an initial foothold.' },
  { id: 'TA0002', name: 'Execution', description: 'Techniques that result in adversary-controlled code running on a local or remote system.' },
  { id: 'TA0003', name: 'Persistence', description: 'Techniques that adversaries use to keep access across restarts and changed credentials.' },
  { id: 'TA0004', name: 'Privilege Escalation', description: 'Techniques that adversaries use to gain higher-level permissions.' },
  { id: 'TA0005', name: 'Defense Evasion', description: 'Techniques that adversaries use to avoid detection throughout their compromise.' },
  { id: 'TA0006', name: 'Credential Access', description: 'Techniques for stealing credentials like account names and passwords.' },
  { id: 'TA0007', name: 'Discovery', description: 'Techniques with which adversaries observe the environment and gain knowledge.' },
  { id: 'TA0008', name: 'Lateral Movement', description: 'Techniques that adversaries use to enter and control remote systems on a network.' },
  { id: 'TA0009', name: 'Collection', description: 'Techniques adversaries may use to gather information and sources of information.' },
  { id: 'TA0011', name: 'Command and Control', description: 'Techniques that adversaries use to communicate with systems under their control.' },
  { id: 'TA0010', name: 'Exfiltration', description: 'Techniques that adversaries may use to steal data from your network.' },
  { id: 'TA0040', name: 'Impact', description: 'Techniques that adversaries use to disrupt availability or compromise integrity.' }
];

export const MITRE_TECHNIQUES_CATALOG = {
  'T1566.001': { name: 'Spearphishing Attachment', tactic: 'Initial Access', sub: 'Spearphishing Attachment', severity: 'medium' },
  'T1133': { name: 'External Remote Services', tactic: 'Initial Access', sub: 'VPN / RDP Gateway', severity: 'high' },
  'T1059.001': { name: 'PowerShell Execution', tactic: 'Execution', sub: 'PowerShell Command Injection', severity: 'high' },
  'T1047': { name: 'Windows Management Instrumentation', tactic: 'Execution', sub: 'Remote WMI Execution', severity: 'critical' },
  'T1098': { name: 'Account Manipulation', tactic: 'Persistence', sub: 'IAM Account Key Addition', severity: 'medium' },
  'T1078.004': { name: 'Cloud Accounts Compromise', tactic: 'Privilege Escalation', sub: 'STS AssumeRole Abuse', severity: 'high' },
  'T1562.001': { name: 'Disable or Modify Tools', tactic: 'Defense Evasion', sub: 'Stop Antivirus Services', severity: 'high' },
  'T1562.008': { name: 'Disable Cloud Logs', tactic: 'Defense Evasion', sub: 'Stop CloudTrail Logging', severity: 'critical' },
  'T1490': { name: 'Inhibit System Recovery', tactic: 'Defense Evasion', sub: 'Delete Volume Shadow Copies', severity: 'critical' },
  'T1003.001': { name: 'LSASS Memory Dumping', tactic: 'Credential Access', sub: 'MiniDump comsvcs.dll', severity: 'critical' },
  'T1558.003': { name: 'Kerberoasting', tactic: 'Credential Access', sub: 'Service Ticket RC4 Request', severity: 'high' },
  'T1552.001': { name: 'Credentials In Files', tactic: 'Credential Access', sub: 'Plaintext AWS Credentials', severity: 'medium' },
  'T1046': { name: 'Network Service Discovery', tactic: 'Discovery', sub: 'Subnet Port Sweep', severity: 'low' },
  'T1021.001': { name: 'Remote Desktop Protocol', tactic: 'Lateral Movement', sub: 'Logon Type 10 Lateral', severity: 'high' },
  'T1530': { name: 'Data from Cloud Storage', tactic: 'Collection', sub: 'Bulk S3 GetObject Download', severity: 'critical' },
  'T1071.001': { name: 'Web Protocols (C2)', tactic: 'Command and Control', sub: 'HTTPS Dynamic DNS Beacon', severity: 'high' },
  'T1048': { name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', sub: 'Outbound High-Volume HTTPS', severity: 'critical' },
  'T1567.002': { name: 'Exfiltration to Cloud Storage', tactic: 'Exfiltration', sub: 'Mega Cloud Sync Utility', severity: 'high' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact', sub: 'Ransomware Mass Encryption', severity: 'critical' },
  'T1496': { name: 'Resource Hijacking', tactic: 'Impact', sub: 'Monero GPU Mining Fleet', severity: 'critical' }
};
