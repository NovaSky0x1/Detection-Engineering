# LimaCharlie D&R Rules

Custom detection and response rules for [LimaCharlie](https://limacharlie.io) EDR.

**Author:** Josh Strickland — Threat Hunter & Detection Engineer  
**Total Rules:** 42

## Structure

```
├── cloud/
│   ├── google-workspace/   # 3 rules — email forwarding, delegation, OAuth
│   └── m365/               # 27 rules — BEC, identity, persistence, privilege escalation
├── endpoint/
│   └── windows/            # 4 custom rules — ClickFix, NetSupport RAT, NTUSER.MAN, React2Shell
│       └── sigma/          # 5 converted Sigma rules — DNS, csc.exe, msdt, UAC bypass, verclsid
└── operational/            # 3 rules — sensor deployment, sealing, uninstall
```

## Categories

### `cloud/google-workspace/`
| Rule | Severity |
|------|----------|
| Email Forwarding Enabled | High |
| Gmail Delegation Added | Critical |
| OAuth Application Authorized (Baseline) | Low |

### `cloud/m365/`
| Rule | Severity |
|------|----------|
| Admin Consent Granted to Application | High |
| AiTM Session Token Replay | Critical |
| Application Consent Granted | Medium |
| Audit Log Settings Modified | Critical |
| Device Code Flow Authentication | High |
| Dynamic Group Membership Rule Modified | High |
| Group Assigned to Directory Role | Critical |
| Inbound Connector Created or Modified | Critical |
| Inbox Forwarding Rule Created | High |
| Inbox Rule with Deletion or Hide Actions | High |
| Login After MFA Change from Different IP | High |
| Login After Password Change from Different IP | High |
| Mailbox Permission Added | Medium |
| Mailbox Server-Side Forwarding Configured | High |
| Member Added to Privileged Group | Critical |
| MFA Method Added or Modified | Medium |
| Multiple Failed Logins Followed by Success | High |
| Nested Group Added to Privileged Group | High |
| New Application Added | Medium |
| Outlook Client Inbox Rule with Forwarding | High |
| Rapid IP Switching on Login | Medium |
| Service Principal Added | Medium |
| Service Principal Credential Added | High |
| Suspicious User Agent on Login | Medium |
| Temporary Access Pass Created | High |
| Temporary Access Pass Used | Medium |
| Workload Identity Federation Credential Added | Critical |

### `endpoint/windows/`
| Rule | Severity |
|------|----------|
| NTUSER.MAN Mandatory Profile Persistence | High |
| NetSupport RAT Activity | High |
| Potential ClickFix Chain | High |
| React2Shell - Node.js execSync (CVE-2025-55182) | Critical |

### `endpoint/windows/sigma/`
| Rule | Severity |
|------|----------|
| Suspicious DNS Query for IP Lookup Service APIs | Medium |
| Dynamic .NET Compilation Via Csc.EXE | Medium |
| Potential Arbitrary Command Execution Using Msdt.EXE | High |
| UAC Bypass via ICMLuaUtil | High |
| Verclsid.exe Runs COM Object | Medium |

### `operational/`
| Rule | Severity |
|------|----------|
| Deploy Sysmon | — |
| Seal Sensors Upon Deployment | — |
| Uninstall Windows Agent | Low |

## MITRE ATT&CK Coverage

Rules are mapped to MITRE ATT&CK techniques in each rule's metadata. Coverage spans:

- **Initial Access** — Phishing (T1566), Exploit Public-Facing Application (T1190)
- **Execution** — Command and Scripting Interpreter (T1059)
- **Persistence** — Account Manipulation (T1098), Boot/Logon Autostart (T1547)
- **Privilege Escalation** — Valid Accounts (T1078), UAC Bypass (T1548)
- **Defense Evasion** — Impair Defenses (T1562), Indicator Removal (T1070)
- **Credential Access** — Steal Web Session Cookie (T1539), Brute Force (T1110)
- **Collection** — Email Collection (T1114)
- **Exfiltration** — Automated Exfiltration (T1020)
- **Command and Control** — Remote Access Software (T1219)

## Rule Format

Each `.yaml` file contains a single D&R rule with `detect` and `respond` sections compatible with LimaCharlie's rule engine.

```yaml
detect:
  event: NEW_PROCESS
  op: and
  rules:
    - ...

respond:
  - action: report
    metadata:
      author: Josh Strickland
      severity: high
    name: Rule Name
```
