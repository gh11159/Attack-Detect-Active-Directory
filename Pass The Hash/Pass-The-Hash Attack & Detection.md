Pass the Hash (T1550.002) abuses **NTLM authentication** instead of needing a plaintext password you authenticate directly using the **NTLM hash**. Windows accepts the hash as valid proof of identity.

**Lab Setup**
Pass the Hash requires no additional lab configuration. The User's NTLM hash obtained from Various Attacks such as DCSync, Running Responder, Inveigh, SMB Solicitation, dumping registry/memory cached hashes is used directly for authentication.

**Attack**
Get The NTLM Hash`impacket-secretsdump redteam.local/dcreplicate:"Password123"@$IP`
![[Dump Hash.png]]

Authenticating Via NTLM Hash: `evil-winrm -i $IP -u "Administrator" -H "$HASH$"`![description[WinRM auth.png]]

**Detection**

Custom Wazuh Rule
```xml
<rule id="100014" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4624$</field>
  <field name="win.eventdata.logonType">^3$</field>
  <field name="win.eventdata.authenticationPackageName">^NTLM$</field>
  <field name="win.eventdata.targetUserName">^Administrator$</field>
  <description>Possible Pass the Hash NTLM network logon as Administrator from $(win.eventdata.ipAddress)</description>
  <mitre>
    <id>T1550.002</id>
  </mitre>
</rule>
```

| Field                                     | Value                   | Meaning                         |
| ----------------------------------------- | ----------------------- | ------------------------------- |
| `if_sid 60103`                            | Windows Security Events | Parent rule                     |
| `win.system.eventID`                      | 4624                    | Successful logon event          |
| `win.eventdata.logonType`                 | 3                       | Network logon not interactive   |
| `win.eventdata.authenticationPackageName` | NTLM                    | Forced NTLM instead of Kerberos |
| `win.eventdata.targetUserName`            | Administrator           | Privileged account targeted     |
| `level 12`                                | High Severity           |                                 |
| `T1550.002`                               | MITRE ATT&CK ID         | Pass the Hash                   |

NTLM Authentication to a user with Admin level privileges.
![[Active Directory/Pass The Hash/screenshots/Wazuh.png]]

**Mitigations**

| Mitigation                                       | Detail                                                                                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **Disable NTLM**                                 | Where possible disable NTLM authentication domain-wide and enforce Kerberos only. This completely eliminates Pass the Hash as an attack vector |
| **Protected Users Security Group**               | Add privileged accounts to the Protected Users group forces Kerberos authentication and prevents NTLM fallback for those accounts              |
| **Credential Guard**                             | Enable Windows Credential Guard to protect NTLM hashes in memory prevents hash extraction via tools like Mimikatz                              |
| **Local Administrator Password Solution (LAPS)** | Deploy LAPS to ensure every machine has a unique local Administrator password prevents lateral movement even if one hash is compromised        |
| **Least Privilege**                              | Limit accounts with administrative privileges the fewer privileged accounts exist the smaller the Pass the Hash attack surface                 |
| **Network Segmentation**                         | Restrict NTLM authentication to necessary network paths only limits where a captured hash can be used                                          |

