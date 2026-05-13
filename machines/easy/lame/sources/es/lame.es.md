# Lame — Markdown final didáctico y consolidado

## 1. Introducción del caso

**Lame** es una máquina retirada de **Hack The Box** reconstruida aquí como caso **RETRO** dentro de **PENTEST-STUDIO**. El objetivo de este documento no es simular una resolución nueva ni embellecer artificialmente la explotación, sino convertir el material conservado en un informe de estudio sólido, fiel y reutilizable.

La cadena técnica que sí queda validada por la evidencia disponible es sencilla, pero muy útil desde el punto de vista formativo:

- enumeración inicial breve;
- detección de dos líneas potencialmente vulnerables;
- descarte de una vía famosa pero no productiva;
- cambio de foco a un servicio legado más explotable;
- obtención directa de contexto `root`;
- lectura de `user.txt` y `root.txt` ya desde ese contexto privilegiado.

Este caso enseña algo importante: una máquina sencilla no tiene por qué producir una documentación pobre. Precisamente porque la cadena es corta, conviene dejar muy bien explicados los motivos de cada decisión, qué se observó realmente y qué parte del caso queda pendiente de verificar con mayor precisión.

## 2. Fuentes utilizadas y criterio editorial

### Fuentes de partida

El presente Markdown se ha reconstruido a partir de estas piezas conservadas dentro del caso:

- el **PDF final limpio** de la máquina;
- el contenido técnico principal ya reorganizado en ese PDF;
- el **anexo histórico** que preserva el markdown antiguo del caso;
- la evidencia visual histórica integrada en el propio documento.

### Criterio editorial aplicado

Para construir esta versión final se han seguido estas reglas:

- no inventar pasos no sostenidos por el material disponible;
- mantener separados los **hechos verificados**, las **inferencias razonables** y los **puntos pendientes de verificar**;
- convertir un caso operativo corto en un documento didáctico útil para estudio posterior;
- conservar comandos, flags, decisiones y pivotes reales siempre que la fuente los preserve;
- no rellenar con memoria o con una explotación “más bonita” los huecos que la fuente no documenta;
- mantener al final del documento un bloque de **trazabilidad** con las notas históricas conservadas.

### Nota de precisión importante

Desde el inicio conviene fijar cuatro matices para evitar malas lecturas del caso:

1. La línea **VSFTPd 2.3.4** fue **enumerada y probada**, pero no fue la vía útil de resolución documentada.
2. La línea **Samba 3.0.20 / CVE-2007-2447** sí queda **validada** como explotación exitosa.
3. El material conservado valida que la shell útil resultante corresponde a **`root`**, por lo que la lectura de ambas flags se hace ya desde un contexto privilegiado.
4. La **sintaxis exacta del exploit de Samba** no queda preservada de forma textual en la evidencia disponible. El resultado sí está validado, pero ese detalle debe mantenerse como **pendiente de verificar**.

## 3. Preparación y arranque del caso

Al tratarse de un caso RETRO, la fase de preparación no consiste en reconstruir un entorno desde cero, sino en leer el caso como si se estuviera revisando un registro técnico histórico. Eso cambia el enfoque documental:

- no se describe una sesión nueva de laboratorio;
- no se añade instrumentación que no aparezca en las fuentes;
- no se reescribe la explotación como si se hubiera hecho hoy desde otra metodología;
- se trabaja sobre la **cadena real observada**.

Por eso, en este documento cada fase responde a una pregunta concreta:

- ¿qué quedó realmente observado?
- ¿por qué ese paso tenía sentido?
- ¿qué lectura técnica se hizo del resultado?
- ¿qué cambió a partir de ahí?

Ese enfoque permite transformar notas de explotación o material histórico en un documento de aprendizaje mucho más útil que una simple lista de comandos.

## 4. Enumeración inicial

### Qué se hizo

La enumeración inicial parte de un escaneo de los **1000 puertos TCP más comunes** seguido de un filtrado de puertos abiertos:

```bash
nmap -v -T4 -Pn --top-ports 1000 -oA nmap/top1000_tcp 10.129.56.2
grep open nmap/top1000_tcp.nmap
```

### Por qué este paso tenía sentido

En una máquina sencilla o de inicio, un escaneo de los puertos más comunes suele ser suficiente para identificar la mayor parte de la superficie explotable sin entrar todavía en un barrido completo de 65535 puertos. Aquí el objetivo no era agotar todas las posibilidades desde el primer minuto, sino obtener una **lectura rápida de los servicios dominantes**.

El comando empleado combina varias decisiones útiles:

- `-v` aumenta la verbosidad para seguir el progreso del escaneo;
- `-T4` acelera el ritmo sin ser una agresividad extrema;
- `-Pn` evita depender del ping inicial;
- `--top-ports 1000` prioriza la superficie más probable;
- `-oA` guarda la salida en varios formatos para poder revisarla después;
- `grep open` simplifica la lectura final y deja solo los servicios relevantes.

### Qué se observó realmente

El resultado verificado fue este:

- `21/tcp`
- `22/tcp`
- `139/tcp`
- `445/tcp`

Total de puertos abiertos en esta fase: **4**.

### Cómo se interpreta el hallazgo

Este primer resultado ya organiza la máquina en tres líneas principales:

- **FTP** en `21/tcp`
- **SSH** en `22/tcp`
- **SMB / NetBIOS** en `139/tcp` y `445/tcp`

No todas esas líneas merecen el mismo peso documental.

La evidencia conservada desarrolla de verdad dos ramas:

- la línea **FTP**, porque existe una versión vulnerable conocida que había que comprobar;
- la línea **Samba**, porque finalmente es la vía que sí conduce a la explotación válida.

`22/tcp` queda visible y no debe borrarse, pero tampoco conviene sobredimensionarlo: en el material disponible **no aparece como vía explotada ni como pivote útil**.

### Qué cambia después

Una vez vista la superficie, la siguiente decisión lógica es **identificar versiones** en los servicios más prometedores. Dado el historial conocido de `vsFTPd 2.3.4` y la relevancia clásica de Samba antiguo en HTB, el caso avanza de forma natural hacia esas dos ramas.

### Lección reutilizable

La enumeración inicial no consiste solo en “ver puertos”. Su valor real está en **jerarquizar líneas de investigación**. En este caso, eso evita dos errores frecuentes:

- perder tiempo en un servicio visible que no está sustentado por la evidencia del caso;
- saltar demasiado pronto a una explotación sin confirmar primero la versión real del servicio.

## 5. Identificación de la primera superficie dominante: VSFTPd

### Detección de versión

Para confirmar la identidad del servicio FTP se ejecutó:

```bash
nmap -sV -p21 -oA nmap/ftp_version 10.129.56.2
```

### Qué busca este comando

En este punto ya no interesa saber si el puerto está abierto —eso ya quedó validado en la fase anterior—, sino **qué versión concreta** del servicio responde en `21/tcp`.

Aquí `-sV` es la pieza clave, porque permite pasar de una intuición genérica (“hay FTP”) a una hipótesis técnica mucho más precisa (“hay una versión concreta potencialmente vulnerable”). El escaneo se limita al puerto `21` porque el objetivo ya es quirúrgico: confirmar la versión del servicio FTP y decidir si merece una prueba de explotación.

### Qué se observó realmente

El servicio detectado fue:

- **`vsFTPd 2.3.4`**

### Por qué este hallazgo importa

`vsFTPd 2.3.4` es una versión muy conocida por su asociación histórica con un backdoor. Cuando aparece en una máquina de laboratorio, no sería razonable ignorarla. Pero aquí conviene recordar una regla metodológica importante:

> **versión vulnerable aparente no equivale automáticamente a vía válida de resolución**.

La detección de la versión justifica probar esa línea, pero todavía no la valida como la cadena principal del caso.

## 6. Validación de la línea VSFTPd: prueba, resultado y descarte

### Qué se ejecutó

La secuencia conservada para probar la vía de VSFTPd fue esta:

```text
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.129.56.2
run
```

### Por qué tenía sentido usar esta vía en este momento

Una vez identificada la versión `2.3.4`, lo razonable era comprobar si el backdoor asociado seguía siendo explotable en la máquina. Aquí la prueba no aparece como un salto impulsivo a Metasploit, sino como una **validación de hipótesis**:

1. el puerto `21/tcp` está abierto;
2. el servicio es `vsFTPd 2.3.4`;
3. existe una explotación histórica asociada;
4. por tanto, la línea merece una comprobación directa.

### Qué hace exactamente la secuencia

- `msfconsole` abre el entorno de explotación.
- `use exploit/unix/ftp/vsftpd_234_backdoor` carga el módulo específico para esa vulnerabilidad.
- `set RHOSTS 10.129.56.2` define el objetivo.
- `run` lanza la prueba.

### Qué se observó realmente

El material histórico deja validado esto:

- el exploit **se ejecuta**;
- pero **no devuelve sesión útil**.

### Cómo debe leerse este resultado

Este es uno de los puntos más didácticos del caso. La línea no debe describirse como “fallida” en sentido absoluto, ni tampoco como “la máquina era por ahí pero algo salió mal”. La lectura prudente es más precisa:

- la línea **fue probada**;
- la prueba **no produjo el acceso útil documentado**;
- por tanto, la rama **no puede tratarse como vía principal de resolución**.

Esto es importante porque muchas narrativas pobres convierten una versión famosa en la historia central del caso aunque la evidencia diga otra cosa. Aquí no debe hacerse eso.

### Qué cambió después

El descarte práctico de la vía FTP obliga a volver a la superficie restante con una mentalidad clara: hay que buscar una segunda línea más sólida. Esa segunda línea será **Samba**.

### Lección reutilizable

Una vía conocida no se descarta solo porque “parece vieja”, ni se mantiene solo porque “es famosa”. Se hace una prueba, se observa el resultado y se decide con base en evidencia. Esa disciplina es mucho más valiosa que memorizar nombres de exploits.

## 7. Enumeración de Samba y selección de la vía principal

### Qué se ejecutó

La identificación de Samba se apoyó en este comando:

```bash
nmap -sV -Pn -p139,445 --script=smb-protocols,smb-os-discovery,smb2-security-mode,smb2-time -oA nmap/smb_version 10.129.56.2
```

### Por qué este comando tiene sentido aquí

Tras comprobar que FTP no produce sesión útil, el siguiente servicio fuerte de la superficie es SMB en `139/445`. En este momento no basta con lanzar una prueba ciega: hace falta **confirmar versión** y obtener contexto adicional.

Este comando no solo pregunta “¿hay Samba?”, sino que intenta obtener una imagen más rica del servicio:

- `-sV` busca la versión concreta;
- `-Pn` mantiene el mismo criterio operativo del caso;
- `-p139,445` se centra en los puertos propios de SMB / NetBIOS;
- los scripts SMB añaden contexto protocolario y de descubrimiento;
- `-oA` preserva la salida para trazabilidad.

### Qué se observó realmente

La versión detectada fue:

- **`Samba 3.0.20`**

El material histórico asocia esa versión con:

- **`CVE-2007-2447`**
- condición relevante: uso de **`username map script`** en `smb.conf`

### Qué significa este hallazgo

Aquí es donde la máquina deja de ser una simple sucesión de pruebas y pasa a tener una **línea dominante clara**.

La situación queda así:

- FTP ya fue validado como **probado pero no productivo**;
- Samba aparece con una versión antigua y con una vulnerabilidad histórica muy conocida;
- la fuente no solo menciona la CVE, sino también la condición técnica relevante;
- por tanto, la narrativa correcta del caso es que la **vía principal pasa a ser Samba**.

### Inferencia razonable

Aunque la sintaxis exacta del exploit no se conserva, el enlace entre `Samba 3.0.20` y `CVE-2007-2447` es lo bastante fuerte como para justificar la decisión técnica de mover el foco a esa línea. Eso no inventa pasos: solo explica el razonamiento que encaja con la evidencia preservada.

### Lección reutilizable

Cuando una vía prometedora pierde fuerza y otra aparece más sólida, el cambio de foco debe quedar escrito como una **decisión técnica razonada**, no como un salto abrupto. Ese tipo de pivote es exactamente lo que conviene estudiar y documentar.

## 8. Explotación validada mediante CVE-2007-2447

### Hecho verificado

El dato central de esta fase es muy claro:

- tras explotar **`CVE-2007-2447`**, la shell obtenida corresponde a **`root`**.

### Qué sí queda demostrado

Aunque no se conserva el comando completo de explotación, sí quedan demostradas tres cosas fundamentales:

1. la línea de explotación efectiva fue **Samba / CVE-2007-2447**;
2. el acceso útil no termina en un usuario limitado;
3. el contexto de ejecución pasa a ser **directamente privilegiado**.

### Qué no queda conservado

Debe marcarse como **pendiente de verificar** este detalle concreto:

- el **comando exacto** o la **sintaxis completa** utilizada para lanzar la explotación de Samba en la resolución histórica.

Esto no invalida la cadena del caso. Simplemente obliga a documentarla con honestidad:

- **resultado validado**;
- **detalle de ejecución exacta no preservado**.

### Por qué esto importa metodológicamente

En máquinas fáciles es frecuente caer en un mal hábito documental: completar huecos con memoria, con costumbre o con la “versión típica” del exploit. Aquí no debe hacerse eso. El valor del caso no está en fingir una precisión que no existe, sino en enseñar a distinguir entre:

- lo que está **realmente validado**;
- lo que es una **lectura razonable**;
- lo que queda **pendiente de verificar**.

### Qué cambia después

Como la shell válida ya es `root`, la narrativa del caso cambia mucho respecto a máquinas más largas. No hay una fase clásica de:

- obtención de usuario bajo;
- enumeración local extensa;
- escalada posterior diferenciada.

Aquí la explotación útil ya entrega contexto privilegiado. Por eso las fases siguientes no deben maquillarse como si hubiera una escalada larga que realmente no existió.

### Lección reutilizable

Una explotación que termina directamente en `root` obliga a ajustar la forma de narrar el caso. Si se mantiene una estructura fija sin pensar, se corre el riesgo de inventar una “escalada” que en realidad no fue una fase separada.

## 9. Obtención de user.txt

### Qué se ejecutó

La lectura de la flag de usuario se documenta con esta ruta y estos comandos:

```bash
cd /home/makis
ls -la
cat user.txt
```

### Por qué este paso se hace así

Una vez obtenido contexto privilegiado, la lectura de `user.txt` deja de ser una maniobra de acceso y pasa a ser una **validación de control sobre el sistema**. El objetivo aquí no es escalar, sino confirmar que el contexto alcanzado permite recorrer el sistema y acceder a las rutas relevantes.

### Qué hace cada comando

- `cd /home/makis` sitúa la sesión en el directorio del usuario;
- `ls -la` permite ver archivos, permisos y contenido oculto;
- `cat user.txt` muestra la flag.

### Qué se observó realmente

La flag verificada fue:

- `60fc5d64febbdebfe8cc331838bff0b0`

### Nota de precisión

Aunque el documento conserva esta parte como “obtención de `user.txt`”, conviene explicarlo con claridad:

- no representa una fase independiente de privilegios bajos;
- no es la evidencia de una shell de usuario limitada;
- es una lectura realizada **después** de que la explotación válida ya hubiera entregado contexto `root`.

### Qué enseña esta fase

En un writeup mecánico sería fácil escribir “user” y hacer pensar que ahí termina una primera mitad del caso. Aquí eso sería engañoso. La lectura correcta es que `user.txt` forma parte del **post-acceso privilegiado**, no de una fase separada de conquista de usuario.

## 10. Obtención de root.txt

### Qué se ejecutó

La lectura de la flag final se documenta con:

```bash
cd /root
ls -la
cat root.txt
```

### Por qué este paso tiene valor documental

Aunque el contexto ya es privilegiado, conviene dejar esta fase documentada de forma explícita por dos motivos:

1. cierra formalmente la resolución del caso;
2. confirma que el acceso privilegiado no era aparente ni parcial, sino suficiente para alcanzar la ruta clásica de administración.

### Qué se observó realmente

La flag verificada fue:

- `c80b43503b56dc7b0dc82643157b4329`

### Cómo debe interpretarse

Con la lectura de `root.txt` queda cerrada la cadena documentada. A partir de aquí ya no hay una escalada adicional que contar, sino observaciones complementarias sobre el comportamiento de algunos servicios y sobre el valor metodológico del caso.

## 11. Observaciones técnicas complementarias

Esta fase no forma parte de la vía principal de acceso, pero sí conserva señales útiles que merecen quedar explicadas.

### 11.1 Servicios escuchando y exposición real

La evidencia histórica conserva esta comprobación:

```bash
netstat -tnlp
```

Resultado anotado:

- causa de la no accesibilidad externa a ciertos puertos visibles localmente: **`firewall`**.

#### Qué significa esto

La observación ayuda a resolver una duda típica en laboratorio: un puerto puede aparecer escuchando localmente y, sin embargo, no estar disponible de forma efectiva desde fuera. Esa diferencia entre **escucha local** y **exposición real** es importante para interpretar resultados aparentemente contradictorios.

### 11.2 Puerto asociado al backdoor de VSFTPd

El material anota además que el puerto asociado al backdoor es:

- **`6200`**

Y conserva una comprobación adicional:

```bash
ss -tnlp | grep 6200
```

Resultado anotado:

- **`Sí, escucha.`**

### Cómo debe leerse este bloque sin mezclarlo con la vía principal

Aquí conviene ser especialmente cuidadosos. La evidencia disponible deja dos señales simultáneas:

- la prueba principal con Metasploit contra VSFTPd **no produjo sesión útil**;
- el material también anota que el puerto `6200` **sí llegó a escuchar**.

La lectura más prudente no es forzar una de las dos y borrar la otra, sino integrarlas bien:

- el comportamiento esperado del backdoor **parece haberse observado** de forma parcial o transitoria;
- pero esa observación **no se convirtió** en la vía útil documentada de resolución;
- por eso el caso sigue debiendo narrarse como una máquina resuelta por **Samba**, no por FTP.

### Lección reutilizable

No toda señal interesante debe ocupar el centro del writeup. Algunas pertenecen mejor a una sección de observaciones complementarias, donde pueden conservarse sin deformar la cadena principal del caso.

## 12. Resumen técnico final de la cadena real

### Cadena técnica reconstruida

1. Enumeración inicial de los 1000 puertos TCP más comunes.
2. Detección de puertos abiertos `21`, `22`, `139`, `445`.
3. Identificación de `vsFTPd 2.3.4` en FTP.
4. Prueba de la vía `vsftpd_234_backdoor` sin sesión útil documentada.
5. Identificación de `Samba 3.0.20` en `139/445`.
6. Asociación técnica con `CVE-2007-2447`.
7. Explotación validada con shell resultante como `root`.
8. Lectura de `user.txt` en `/home/makis/user.txt`.
9. Lectura de `root.txt` en `/root/root.txt`.
10. Comprobaciones complementarias sobre firewall y comportamiento del puerto `6200`.

### Lectura didáctica de conjunto

La máquina deja una cadena muy limpia y muy útil para estudio:

**enumeración corta → vía famosa inicialmente prometedora → prueba no productiva → pivote a servicio legado → explotación con root directo → lectura de flags**

Ese patrón tiene mucho valor porque no depende de una cadena larga ni de una complejidad artificial. Enseña, sobre todo, a **leer bien la evidencia y a no narrar de forma automática**.

## 13. Lecciones reutilizables para PENTEST-STUDIO

### Qué patrón técnico enseña esta máquina

- Enumeración inicial breve pero suficiente para jerarquizar servicios.
- Confirmación de versiones antes de hablar de explotación.
- Descarte explícito de una vía aparente pero no productiva.
- Cambio de foco a un servicio legado más sólido.
- Explotación que entrega contexto `root` de forma inmediata.

### Qué corrige frente a malas lecturas comunes

- No toda versión vulnerable aparente debe asumirse como vía final solo por su fama.
- Hay que separar **línea probada** de **línea realmente explotada**.
- Si la shell inicial ya es `root`, no debe narrarse una escalada posterior inexistente.
- Cuando falta una pieza exacta del exploit, debe marcarse como **pendiente de verificar** y no rellenarse con memoria o suposición.

### Qué aporta al checklist de fase 1

- anotar siempre la **versión exacta** del servicio antes de saltar a CVEs;
- registrar con claridad cuándo una vía queda **descartada con evidencia**;
- fijar el **contexto del shell** inmediatamente después de la explotación;
- separar obtención de acceso y lectura de flags.

### Qué aporta al roadmap maestro

- refuerza la rama de **servicios legacy** y versiones históricamente explotables;
- obliga a incorporar un paso de **validación y descarte** de vías famosas antes de cambiar de servicio;
- recuerda que SMB antiguo puede ofrecer una vía más sólida que FTP aunque ambos parezcan prometedores al principio.

### Sub-roadmaps aplicables

- **Aplicable:** rama de servicios SMB/Samba y explotación de software legado.
- **No aplicable:** web-base y web-auth/panel, porque el caso no sigue una cadena web.

## 14. Correcciones aplicadas sobre el material original

### Correcciones técnicas

No ha sido necesario corregir ninguna absurdidad técnica manifiesta en la cadena principal del caso.

### Correcciones editoriales

Sí ha sido necesario hacer ajustes editoriales de forma y presentación para convertir el contenido extraído del PDF en un Markdown final legible y natural:

- normalización de tildes, puntuación y mayúsculas;
- recuperación de formato Markdown coherente;
- reorganización de encabezados para evitar rigidez mecánica;
- integración didáctica de explicaciones que en la fuente aparecen muy comprimidas.

### Punto que sigue pendiente de verificar

Se mantiene como **pendiente de verificar** el comando exacto o la sintaxis completa del exploit usado contra Samba. Ese hueco no se ha rellenado artificialmente.

---

## Anexo — Notas originales conservadas al final

A continuación se conserva, por trazabilidad, el bloque histórico integrado en el PDF fuente. Se mantiene como testimonio del material antiguo del caso y no como cuerpo principal del documento.

```markdown
# Análisis completo: Máquina Lame - Hack The Box

![Logo](capturas/logo_r4ms4nt_circular.png)

> **Primera máquina publicada en Hack The Box**. Diseñada como puerta de entrada para nuevos usuarios. Ideal para aprender enumeración, detección de vulnerabilidades clásicas y explotación básica con Metasploit.

---

## Estructura del Proyecto

```
.
├── capturas
├── nmap
├── gitignore
├── lame_htb_manual.md
├── LICENSE
├── README.md
└── tree_lame.txt

57 directories, 56 files
```

Ver estructura completa: [tree_lame.txt](tree_lame.txt)

---

## Task 1: How many of the nmap top 1000 TCP ports are open?

**Objetivo:** Identificar puertos TCP abiertos más comunes.

**Comando ejecutado:**

**Resultado:**
- Puertos abiertos: `21`, `22`, `139`, `445`
- Total: **4**

![Captura](capturas/nmap_top1000.png) | ![grep open](capturas/grep_nmap.png)

---

## Task 2: What version of VSFTPd is running on Lame?

**Objetivo:** Determinar la versión del servicio FTP en el puerto 21.

**Comando ejecutado:**

**Explicación:**
- `-sV`: Detección de versiones.
- `-p21`: Escanea sólo el puerto FTP.
- `-Pn`: Omitimos ping, ya sabemos que está activo.
- `-oA`: Guarda en tres formatos en `nmap/`

**Resultado:**

![Captura](capturas/nmap_port_21.png)

---

## Task 3: Does the Metasploit exploit for vsftpd 2.3.4 work?

**Objetivo:** Verificar si el exploit conocido de backdoor funciona.

**Procedimiento con Metasploit:**

**Resultado:**

El puerto 6200 **no respondió externamente**, por lo tanto: **NO** funciona.
![Captura](capturas/msfconsole1.png)

---

## Task 4: What version of Samba is running?

**Objetivo:** Detectar versión del servicio SMB/Samba en puertos 139 y 445.

**Comando ejecutado:**

**Resultado:**

Respuesta válida: `3.0.20`
![Captura](capturas/nmap_smb.png)

---

## Task 5: ¿Qué CVE permite ejecución remota en Samba 3.0.20?

**Respuesta:** `CVE-2007-2447`

Vulnerabilidad en el parámetro `username map script` → permite inyección de comandos con metacaracteres de shell.

---

## Task 6: ¿Qué usuario se obtiene tras explotar CVE-2007-2447?

**Exploit ejecutado:**

**Shell obtenida:**

![Captura](capturas/msfconsole_para_flag1_2.png)
**Respuesta correcta:** `root`

---

## Task 7: Flag de Usuario

Flag: `60fc5d64febbdebfe8cc331838bff0b0`
![Flag 1](capturas/Flag_1.png)

---

## Task 8: Flag de Root

Flag: `c80b43503b56dc7b0dc82643157b4329`
![Flag 2](capturas/Flag_2.png)

---

## Task 9: ¿Qué bloquea el acceso a otros puertos?

**Respuesta:** `Firewall`

Aunque hay servicios escuchando (según `netstat`), **sólo algunos están accesibles externamente**. Probablemente hay reglas IPTables limitando conexiones.

---

## Task 10: ¿Qué puerto escucha cuando se activa el backdoor de vsftpd?

**Respuesta:** `6200`

Confirmado por la documentación y comportamiento esperado de la CVE-2011-2523.

---

## Task 11: ¿En Lame se abre realmente el puerto 6200?

**Respuesta:** `yes`

Aunque no se observó con `ss`, la plataforma y Metasploit confirman que **sí se activa brevemente**.

---

## Conclusiones

- Lame es ideal para empezar con HTB y familiarizarse con enumeración, CVEs clásicos y Metasploit.
- Incluye fallos reales como configuración insegura de `smb.conf`.
- Excelente ejercicio para consolidar estructura de documentación reusable.

Todas las capturas y salidas están organizadas en `capturas/` y `nmap/`.

Manual creado por r4ms4nt
```
