# Initial Enumeration

---

Durante una evaluación, podemos obtener una shell de bajo privilegio en un host Windows (unido al dominio o no) y necesitamos realizar una escalada de privilegios para avanzar en nuestro acceso. Comprometer completamente el host puede darnos acceso a archivos/sistemas compartidos sensibles, permitirnos capturar tráfico para obtener más credenciales, o conseguir credenciales que nos ayuden a avanzar más en el acceso o incluso escalar directamente a Domain Admin en un entorno de Active Directory. Podemos escalar privilegios a uno de los siguientes dependiendo de la configuración del sistema y el tipo de datos que encontremos:

|                                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| La cuenta de `NT AUTHORITY\SYSTEM` altamente privilegiada, o la cuenta [LocalSystem](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account), es una cuenta con más privilegios que una cuenta de administrador local y se usa para ejecutar la mayoría de los servicios de Windows. |
| La cuenta local de `administrator` integrada. Algunas organizaciones deshabilitan esta cuenta, pero muchas no lo hacen. No es raro ver esta cuenta reutilizada en múltiples sistemas en un entorno de cliente.                                                                                            |
| Otra cuenta local que sea miembro del grupo local de `Administrators`. Cualquier cuenta en este grupo tendrá los mismos privilegios que la cuenta de `administrator` integrada.                                                                                                                           |
| Un usuario de dominio estándar (no privilegiado) que sea parte del grupo local de `Administrators`.                                                                                                                                                                                                       |
| Un administrador de dominio (altamente privilegiado en el entorno de Active Directory) que sea parte del grupo local de `Administrators`.                                                                                                                                                                 |

La enumeración es clave para la escalada de privilegios. Cuando obtenemos acceso inicial a la shell del host, es vital ganar conciencia situacional y descubrir detalles relacionados con la versión del sistema operativo, nivel de parches, software instalado, privilegios actuales, membresías de grupo, y más. Vamos a revisar algunos de los puntos clave de datos que deberíamos revisar después de obtener acceso inicial. Esta no es una lista exhaustiva, y los diversos scripts/herramientas de enumeración que cubrimos en la sección anterior cubren todos estos puntos de datos y muchos más. No obstante, es esencial entender cómo realizar estas tareas manualmente, especialmente si nos encontramos en un entorno donde no podemos cargar herramientas debido a restricciones de red, falta de acceso a internet, o protecciones en su lugar.

Esta [referencia de comandos de Windows](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) es muy útil para realizar tareas de enumeración manual.

---

## Key Data Points

`OS name`: Conocer el tipo de sistema operativo Windows (workstation o server) y nivel (Windows 7 o 10, Server 2008, 2012, 2016, 2019, etc.) nos dará una idea de los tipos de herramientas que pueden estar disponibles (como la versión de `PowerShell`, o la falta de ella en sistemas heredados). Esto también identificaría la versión del sistema operativo para la cual pueden haber exploits públicos disponibles.

`Version`: Al igual que con la versión del OS (sistema operativo), pueden existir exploits públicos que apunten a una vulnerabilidad en una versión específica de Windows. Los exploits del sistema Windows pueden causar inestabilidad del sistema o incluso un fallo completo. Ten cuidado al ejecutarlos en cualquier sistema de producción, y asegúrate de entender completamente el exploit y las posibles ramificaciones antes de ejecutar uno.

`Running Services`: Conocer qué servicios están ejecutándose en el host es importante, especialmente aquellos que se ejecutan como `NT AUTHORITY\SYSTEM` o una cuenta de nivel administrador. Un servicio mal configurado o vulnerable que se ejecute en el contexto de una cuenta privilegiada puede ser una victoria fácil para la escalada de privilegios.

Vamos a ver esto más a fondo.

---

## System Information

Examinar el sistema en sí nos dará una mejor idea de la versión exacta del sistema operativo, hardware en uso, programas instalados y actualizaciones de seguridad. Esto nos ayudará a enfocar nuestra búsqueda de parches faltantes y CVEs asociados que podamos utilizar para escalar privilegios. Usar el comando [tasklist](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist) para ver los procesos en ejecución nos dará una mejor idea de qué aplicaciones están ejecutándose actualmente en el sistema.

### Tasklist

```r
C:\htb> tasklist /svc

Image Name                     PID Services
========================= ======== ============================================
System Idle Process              0 N/A
System                           4 N/A
smss.exe                       316 N/A
csrss.exe                      424 N/A
wininit.exe                    528 N/A
csrss.exe                      540 N/A
winlogon.exe                   612 N/A
services.exe                   664 N/A
lsass.exe                      672 KeyIso, SamSs, VaultSvc
svchost.exe                    776 BrokerInfrastructure, DcomLaunch, LSM,
                                   PlugPlay, Power, SystemEventsBroker
svchost.exe                    836 RpcEptMapper, RpcSs
LogonUI.exe                    952 N/A
dwm.exe                        964 N/A
svchost.exe                    972 TermService
svchost.exe                   1008 Dhcp, EventLog, lmhosts, TimeBrokerSvc
svchost.exe                    364 NcbService, PcaSvc, ScDeviceEnum, TrkWks,
                                   UALSVC, UmRdpService
<...SNIP...>

svchost.exe                   1468 Wcmsvc
svchost.exe                   1804 PolicyAgent
spoolsv.exe                   1884 Spooler
svchost.exe                   1988 W3SVC, WAS
svchost.exe                   1996 ftpsvc
svchost.exe                   2004 AppHostSvc
FileZilla Server.exe          1140 FileZilla Server
inetinfo.exe                  1164 IISADMIN
svchost.exe                   1736 DiagTrack
svchost.exe                   2084 StateRepository, tiledatamodelsvc
VGAuthService.exe             2100 VGAuthService
vmtoolsd.exe                  2112 VMTools
MsMpEng.exe                   2136 WinDefend

<...SNIP...>

FileZilla Server Interfac     5628 N/A
jusched.exe                   5796 N/A
cmd.exe                       4132 N/A
conhost.exe                   4136 N/A
TrustedInstaller.exe          1120 TrustedInstaller
TiWorker.exe                  1816 N/A
WmiApSrv.exe                  2428 wmiApSrv
tasklist.exe                  3596 N/A
```

Es esencial familiarizarse con los procesos estándar de Windows como [Session Manager Subsystem (smss.exe)](https://en.wikipedia.org/wiki/Session_Manager_Subsystem), [Client Server Runtime Subsystem (csrss.exe)](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem), [WinLogon (winlogon.exe)](https://en.wikipedia.org/wiki/Winlogon), [Local Security Authority Subsystem Service (LSASS)](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service), y [Service Host (svchost.exe)](https://en.wikipedia.org/wiki/Svchost.exe), entre otros y los servicios asociados con ellos. Poder identificar rápidamente procesos/servicios estándar ayudará a acelerar nuestra enumeración y nos permitirá centrarnos en procesos/servicios no estándar, los cuales pueden abrir un camino de escalada de privilegios. En el ejemplo anterior, estaríamos más interesados en el servidor FTP de `FileZilla` ejecutándose e intentaríamos enumerar la versión para buscar vulnerabilidades públicas o configuraciones erróneas como el acceso anónimo a FTP, lo cual podría llevar a la exposición de datos sensibles o más.

Otros procesos como `MsMpEng.exe`, Windows Defender, son interesantes porque pueden ayudarnos a mapear qué protecciones están en su lugar en el host objetivo que podríamos tener que evadir/esquivar.

### Display All Environment Variables

Las variables de entorno explican mucho sobre la configuración del host. Para obtener una impresión de ellas, Windows proporciona el comando `set`. Una de las variables más pasadas por alto es `PATH`. En la salida a continuación, no hay nada fuera de lo común. Sin embargo, no es raro encontrar administradores (o aplicaciones) que modifican el `PATH`. Un ejemplo común es colocar Python o Java en el path, lo cual permitiría la ejecución de archivos Python o .JAR. Si la carpeta colocada en el PATH es escribible por tu usuario, puede ser posible realizar DLL Injections contra otras aplicaciones. Recuerda, al ejecutar un programa, Windows busca ese programa en el CWD (Directorio de Trabajo Actual) primero, luego desde el PATH de izquierda a derecha. Esto significa que si el path personalizado está colocado a la izquierda (antes de C:\Windows\System32), es mucho más peligroso que a la derecha.

Además del PATH, `set` también puede proporcionar otra información útil como el HOME DRIVE. En empresas, esto será a menudo un recurso compartido de archivos. Navegar al recurso compartido de archivos en sí puede revelar otros directorios que pueden ser accesibles. No es raro poder acceder a un "Directorio de TI", el cual contiene una hoja de inventario que incluye contraseñas. Adicionalmente, los recursos compartidos se utilizan para directorios de inicio, por lo que el usuario puede iniciar sesión en otras computadoras y tener la misma experiencia/archivos/escritorio/etc. ([Roaming Profiles](https://docs.microsoft.com/en-us/windows-server/storage/folder-redirection/folder-redirection-rup-overview)). Esto también puede significar que el usuario lleva consigo elementos maliciosos. Si se coloca un archivo en `USERPROFILE\AppData\Microsoft\Windows\Start Menu\Programs\Startup`, cuando el usuario inicie sesión en otra máquina, este archivo se ejecutará.

```r
C:\htb> set

ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\Administrator\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=WINLPE-SRV01
ComSpec=C:\Windows\system32\cmd.exe
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
LOCALAPPDATA=C:\Users\Administrator\AppData\Local
LOGONSERVER=\\WINLPE-SRV01
NUMBER_OF_PROCESSORS=6
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\Administrator\AppData\Local\Microsoft\WindowsApps;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
PROCESSOR_LEVEL=23
PROCESSOR_REVISION=3100
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SESSIONNAME=Console
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
TMP=C:\Users\ADMINI~1\AppData\Local\Temp\1
USERDOMAIN=WINLPE-SRV01
USERDOMAIN_ROAMINGPROFILE=WINLPE-SRV01
USERNAME=Administrator
USERPROFILE=C:\Users\Administrator
windir=C:\Windows 
```

### View Detailed Configuration Information

El comando `systeminfo` mostrará si el sistema ha sido parcheado recientemente y si es una VM. Si el sistema no ha sido parcheado recientemente, obtener acceso de nivel administrador puede ser tan simple como ejecutar un exploit conocido. Busca los KBs instalados bajo [HotFixes](https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix) para tener una idea de cuándo se ha parcheado el sistema. Esta información no siempre está presente, ya que es posible ocultar parches de software a los no administradores. El `System Boot Time` y la `OS Version` también pueden verificarse para tener una idea del nivel de parches. Si el sistema no ha sido reiniciado en más de seis meses, es probable que tampoco se esté parcheando.

Además, muchas guías dirán que la información de red es importante ya que podría indicar una máquina con múltiples redes conectadas. En general, cuando se trata de empresas, los dispositivos solo tendrán acceso a otras redes mediante una regla de firewall y no tendrán un cable físico conectado a ellas.

```r
C:\htb> systeminfo

Host Name:                 WINLPE-SRV01
OS Name:                   Microsoft Windows Server 2016 Standard
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00376-30000-00299-AA303
Original Install Date:     3/24/2021, 3:46:32 PM
System Boot Time:          3/25/2021, 9:24:36 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              3 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
                           [03]: AMD64 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.16707776.B64.2008070230, 8/7/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     6,143 MB
Available Physical Memory: 3,474 MB
Virtual Memory: Max Size:  10,371 MB
Virtual Memory: Available: 7,544 MB
Virtual Memory: In Use:    2,827 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WINLPE-SRV01
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB3199986
                           [02]: KB5001078
                           [03]: KB4103723
Network Card(s):           2 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.43.8
                                 [02]: fe80::e4db:5ea3:2775:8d4d
                                 [03]: dead:beef::e4db:5ea3:2775:8d4d
                           [02]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet1
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.20.56
                                 [02]: fe80::f055:fefd:b1b:9919
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

### Patches and Updates

Si `systeminfo` no muestra los hotfixes, pueden ser consultados con [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page) usando el binario de WMI-Command con [QFE (Quick Fix Engineering)](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering) para mostrar parches.

```r
C:\htb> wmic qfe

Caption                                     CSName        Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status
http://support.microsoft.com/?kbid=3199986  WINLPE-SRV01  Update                        KB3199986               NT AUTHORITY\SYSTEM  11/21/2016
https://support.microsoft.com/help/5001078  WINLPE-SRV01  Security Update               KB5001078               NT AUTHORITY\SYSTEM  3/25/2021
http://support.microsoft.com/?kbid=4103723  WINLPE-SRV01  Security Update               KB4103723               NT AUTHORITY\SYSTEM  3/25/2021
```

Podemos hacer esto con PowerShell también usando el cmdlet [Get-Hotfix](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.1).

```r
PS C:\htb> Get-HotFix | ft -AutoSize

Source       Description     HotFixID  InstalledBy                InstalledOn
------       -----------     --------  -----------                -----------
WINLPE-SRV01 Update          KB3199986 NT AUTHORITY\SYSTEM        11/21/2016 12:00:00 AM
WINLPE-SRV01 Update          KB4054590 WINLPE-SRV01\Administrator 3/30/2021 12:00:00 AM
WINLPE-SRV01 Security Update KB5001078 NT AUTHORITY\SYSTEM        3/25/2021 12:00:00 AM
WINLPE-SRV01 Security Update KB3200970 WINLPE-SRV01\Administrator 4/13/2021 12:00:00 AM
```

### Installed Programs

WMI también puede usarse para mostrar el software instalado.

 Esta información a menudo puede guiarnos hacia exploits difíciles de encontrar. ¿Está instalado `FileZilla`/`Putty`/etc? Ejecuta `LaZagne` para verificar si están instaladas credenciales almacenadas para esas aplicaciones. Además, algunos programas pueden estar instalados y ejecutándose como un servicio que es vulnerable.

```r
C:\htb> wmic product get name

Name
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.24.28127
Java 8 Update 231 (64-bit)
Microsoft Visual C++ 2019 X86 Additional Runtime - 14.24.28127
VMware Tools
Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.24.28127
Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.24.28127
Java Auto Updater

<SNIP>
```

Podemos hacer esto con PowerShell también usando el cmdlet [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1).

```r
PS C:\htb> Get-WmiObject -Class Win32_Product |  select Name, Version

Name                                                                    Version
----                                                                    -------
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
Microsoft OLE DB Driver for SQL Server                                  18.3.0.0
Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219             10.0.40219
Microsoft Help Viewer 2.3                                               2.3.28107
Microsoft Visual C++ 2010  x86 Redistributable - 10.0.40219             10.0.40219
Microsoft Visual C++ 2013 x86 Minimum Runtime - 12.0.21005              12.0.21005
Microsoft Visual C++ 2013 x86 Additional Runtime - 12.0.21005           12.0.21005
Microsoft Visual C++ 2019 X64 Additional Runtime - 14.28.29914          14.28.29914
Microsoft ODBC Driver 13 for SQL Server                                 13.2.5026.0
SQL Server 2016 Database Engine Shared                                  13.2.5026.0
SQL Server 2016 Database Engine Services                                13.2.5026.0
SQL Server Management Studio for Reporting Services                     15.0.18369.0
Microsoft SQL Server 2008 Setup Support Files                           10.3.5500.0
SSMS Post Install Tasks                                                 15.0.18369.0
Microsoft VSS Writer for SQL Server 2016                                13.2.5026.0
Java 8 Update 231 (64-bit)                                              8.0.2310.11
Browser for SQL Server 2016                                             13.2.5026.0
Integration Services                                                    15.0.2000.130

<SNIP>

```

### Display Running Processes

El comando [netstat](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) mostrará conexiones TCP y UDP activas, lo que nos dará una mejor idea de qué servicios están escuchando en qué puerto(s) tanto localmente como accesibles desde el exterior. Podemos encontrar un servicio vulnerable solo accesible al host local (cuando se inicia sesión en el host) que podemos explotar para escalar privilegios.

### Netstat

```r
PS C:\htb> netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1096
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1433           0.0.0.0:0              LISTENING       3520
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       968
<...SNIP...>
```

---

## User & Group Information

Los usuarios son a menudo el eslabón más débil en una organización, especialmente cuando los sistemas están configurados y parcheados correctamente. Es esencial comprender los usuarios y grupos en el sistema, miembros de grupos específicos que pueden proporcionarnos acceso de nivel administrador, la información de políticas de contraseñas y cualquier usuario que haya iniciado sesión y que podamos atacar. Podemos encontrar el sistema bien parcheado, pero el directorio de usuario de un miembro del grupo de administradores locales es navegable y contiene un archivo de contraseñas como `logins.xlsx`, lo que resulta en una victoria muy fácil.

### Logged-In Users

Siempre es importante determinar qué usuarios están conectados a un sistema. ¿Están inactivos o activos? ¿Podemos determinar en qué están trabajando? Aunque es más difícil de lograr, a veces podemos atacar directamente a los usuarios para escalar privilegios o obtener más acceso. Durante un compromiso evasivo, necesitaríamos proceder con cuidado en un host con otros usuarios trabajando activamente en él para evitar la detección.

```r
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         rdp-tcp#2           1  Active          .  3/25/2021 9:27 AM
```

### Current User

Cuando obtenemos acceso a un host, siempre debemos verificar primero bajo qué contexto de usuario se está ejecutando nuestra cuenta. A veces, ¡ya somos SYSTEM o equivalente! Si obtenemos acceso como una cuenta de servicio, podemos tener privilegios como `SeImpersonatePrivilege`, que a menudo pueden ser fácilmente abusados para escalar privilegios usando una herramienta como [Juicy Potato](https://github.com/ohpe/juicy-potato).

```r
C:\htb> echo %USERNAME%

htb-student 
```

### Current User Privileges

Como se mencionó anteriormente, conocer los privilegios que tiene nuestro usuario puede ayudar enormemente a escalar privilegios. Veremos privilegios de usuario individuales y caminos de escalada más adelante en este módulo.

```r
C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### Current User Group Information

¿Nuestro usuario ha heredado algún derecho a través de su membresía de grupo? ¿Están privilegiados en el entorno de Active Directory, lo cual podría aprovecharse para obtener acceso a más sistemas?

```r
C:\htb> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
```

### Get All Users

Conocer qué otros usuarios están en el sistema también es importante. Si obtuvimos acceso a RDP en un host usando credenciales que capturamos para un usuario `bob`, y vemos un usuario `bob_adm` en el grupo de administradores locales, vale la pena verificar la reutilización de credenciales. ¿Podemos acceder al directorio de perfil de usuario para cualquier usuario importante? Podemos encontrar archivos valiosos como scripts con contraseñas o claves SSH en la carpeta Desktop, Documents o Downloads de un usuario.

```r
C:\htb> net user

User accounts for \\WINLPE-SRV01

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
helpdesk                 htb-student              jordan
sarah                    secsvc
The command completed successfully.
```

### Get All Groups

Conocer qué grupos no estándar están presentes en el host puede ayudarnos a determinar para qué se usa el host, cuán accesado está, o incluso puede llevar a descubrir una configuración errónea como todos los usuarios del dominio en los grupos de Remote Desktop o administradores locales.

```r
C:\htb> net localgroup

Aliases for \\WINLPE-SRV01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Administrators
*Backup Operators
*Certificate Service DCOM Access
*Cryptographic Operators
*Distributed COM Users
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Power Users
*Print Operators
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Storage Replica Administrators
*System Managed Accounts Group
*Users
The command completed successfully.
```

### Details About a Group

Vale la pena revisar los detalles de cualquier grupo no estándar. Aunque es poco probable, podemos encontrar una contraseña u otra información interesante almacenada en la descripción del grupo. Durante nuestra enumeración, podemos descubrir credenciales de otro usuario no administrador que es miembro de un grupo local que puede ser aprovechado para escalar privilegios.

```r
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
helpdesk
sarah
secsvc
The command completed successfully. 
```

### Get Password Policy & Other Account Information

```r
C:\htb> net accounts

Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
```

---

## Moving On

Como se dijo antes, esta no es una lista exhaustiva de comandos de enumeración. Las herramientas que discutimos en la sección anterior ayudarán en gran medida a acelerar el proceso de enumeración y asegurarse de que sea completo sin dejar piedra sin remover. Hay muchas hojas de trucos disponibles para ayudarnos, como [esta](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md). Estudia las herramientas y sus salidas y comienza a hacer tu propia hoja de trucos de comandos, para que esté disponible en caso de que encuentres un entorno que requiera mayormente o toda enumeración manual.