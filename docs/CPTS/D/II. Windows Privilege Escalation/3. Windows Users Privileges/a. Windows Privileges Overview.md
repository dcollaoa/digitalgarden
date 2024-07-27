[Privileges](https://docs.microsoft.com/en-us/windows/win32/secauthz/privileges) en Windows son derechos que una cuenta puede recibir para realizar una variedad de operaciones en el sistema local, como gestionar servicios, cargar drivers, apagar el sistema, depurar una aplicación, y más. Los privileges son diferentes de los access rights, que un sistema utiliza para otorgar o denegar acceso a objetos securables. Los privileges de usuario y grupo se almacenan en una base de datos y se otorgan a través de un access token cuando un usuario inicia sesión en un sistema. Una cuenta puede tener local privileges en una computadora específica y diferentes privileges en distintos sistemas si la cuenta pertenece a un Active Directory domain. Cada vez que un usuario intenta realizar una acción con privilegios, el sistema revisa el access token del usuario para ver si la cuenta tiene los privileges necesarios y, de ser así, verifica si están habilitados. La mayoría de los privileges están deshabilitados por defecto. Algunos pueden habilitarse abriendo un cmd.exe o una consola de PowerShell con privilegios administrativos, mientras que otros pueden habilitarse manualmente.

El objetivo de una assessment es a menudo obtener acceso administrativo a un sistema o múltiples sistemas. Supongamos que podemos iniciar sesión en un sistema como usuario con un conjunto específico de privileges. En ese caso, podemos aprovechar esta funcionalidad integrada para escalar privileges directamente o utilizar los privileges asignados a la cuenta objetivo para avanzar en nuestro acceso en busca de nuestro objetivo final.

---

## Windows Authorization Process

Los security principals son cualquier cosa que pueda ser autenticada por el sistema operativo Windows, incluyendo cuentas de usuario y computadora, procesos que se ejecutan en el contexto de seguridad de otra cuenta de usuario/computadora, o los security groups a los que pertenecen estas cuentas. Los security principals son la forma principal de controlar el acceso a recursos en hosts de Windows. Cada security principal es identificado por un [Security Identifier (SID)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows) único. Cuando se crea un security principal, se le asigna un SID que permanece asignado a ese principal durante su vida útil.

El siguiente diagrama recorre el proceso de autorización y control de acceso de Windows a un alto nivel, mostrando, por ejemplo, el proceso que se inicia cuando un usuario intenta acceder a un objeto securable como una carpeta en un recurso compartido de archivos. Durante este proceso, el access token del usuario (incluyendo su user SID, SIDs para cualquier grupo al que pertenezca, lista de privileges y otra información de acceso) se compara con las [Access Control Entries (ACEs)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries) dentro del [security descriptor](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors) del objeto (que contiene información de seguridad sobre un objeto securable como los access rights otorgados a usuarios o grupos). Una vez completada esta comparación, se toma una decisión para otorgar o denegar el acceso. Todo este proceso ocurre casi instantáneamente cada vez que un usuario intenta acceder a un recurso en un host de Windows. Como parte de nuestras actividades de enumeration y privilege escalation, intentamos usar y abusar de los access rights e insertarnos en este proceso de autorización para avanzar en nuestro acceso hacia nuestro objetivo.

![image](https://academy.hackthebox.com/storage/modules/67/auth_process.png)

[Image source](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals)

---

## Rights and Privileges in Windows

Windows contiene muchos grupos que otorgan a sus miembros poderosos rights y privileges. Muchos de estos pueden ser abusados para escalar privileges tanto en un host de Windows independiente como en un entorno de Active Directory domain. En última instancia, estos pueden ser utilizados para obtener Domain Admin, local administrator, o SYSTEM privileges en una estación de trabajo, servidor o Domain Controller (DC) de Windows. Algunos de estos grupos se enumeran a continuación.

| **Group**              | **Description**                                                                                                                                                                  |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Default Administrators | Domain Admins y Enterprise Admins son grupos "super".                                                                                                                            |
| Server Operators       | Los miembros pueden modificar servicios, acceder a comparticiones SMB y hacer copias de seguridad de archivos.                                                                   |
| Backup Operators       | Los miembros pueden iniciar sesión en DCs localmente y deben considerarse Domain Admins. Pueden hacer copias de sombra de la base de datos SAM/NTDS, leer el registro remotamente y acceder al sistema de archivos en el DC a través de SMB. A veces, este grupo se agrega al grupo local Backup Operators en sistemas que no son DCs. |
| Print Operators        | Los miembros pueden iniciar sesión en DCs localmente y "engañar" a Windows para que cargue un driver malicioso.                                                                   |
| Hyper-V Administrators | Si hay DCs virtuales, cualquier administrador de virtualización, como los miembros de Hyper-V Administrators, debe considerarse Domain Admins.                                    |
| Account Operators      | Los miembros pueden modificar cuentas y grupos no protegidos en el dominio.                                                                                                      |
| Remote Desktop Users   | Los miembros no reciben permisos útiles por defecto, pero a menudo se les otorgan derechos adicionales como `Allow Login Through Remote Desktop Services` y pueden moverse lateralmente usando el protocolo RDP.               |
| Remote Management Users| Los miembros pueden iniciar sesión en DCs con PSRemoting (a veces este grupo se agrega al grupo de administración remota local en sistemas que no son DCs).                        |
| Group Policy Creator Owners | Los miembros pueden crear nuevos GPOs pero necesitarían permisos adicionales para vincular GPOs a un contenedor como un dominio u OU.                                            |
| Schema Admins          | Los miembros pueden modificar la estructura del Active Directory schema y backdoor cualquier grupo/GPO que se creará agregando una cuenta comprometida al ACL del objeto predeterminado.                            |
| DNS Admins             | Los miembros pueden cargar un DLL en un DC, pero no tienen los permisos necesarios para reiniciar el servidor DNS. Pueden cargar un DLL malicioso y esperar un reinicio como mecanismo de persistencia. Cargar un DLL a menudo resultará en que el servicio se bloquee. Una forma más confiable de explotar este grupo es [crear un WPAD record](https://cube0x0.github.io/Pocing-Beyond-DA/).      |

---

## User Rights Assignment

Dependiendo de la pertenencia a grupos y otros factores como los privileges asignados a través de políticas de dominio y locales (Group Policy), los usuarios pueden tener varios rights asignados a su cuenta. Este artículo de Microsoft sobre [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) proporciona una explicación detallada de cada uno de los user rights que se pueden configurar en Windows, así como consideraciones de seguridad aplicables a cada derecho. A continuación se presentan algunos de los key user rights assignments, que son configuraciones aplicadas al localhost. Estos derechos permiten a los usuarios realizar tareas en el sistema, como iniciar sesión local o remotamente, acceder al host desde la red, apagar el servidor, etc.

|Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)|Setting Name|Standard Assignment|Description|
|---|---|---|---|
|SeNetworkLogonRight|[Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network)|Administrators, Authenticated Users|Determina qué usuarios pueden conectarse al dispositivo desde la red. Esto es requerido por protocolos de red como SMB, NetBIOS, CIFS y COM+.|
|SeRemoteInteractiveLogonRight|[Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services)|Administrators, Remote Desktop Users|Esta configuración de política determina qué usuarios o grupos pueden acceder a la pantalla de inicio de sesión de un dispositivo remoto a través de una conexión de Remote Desktop Services. Un usuario puede establecer una conexión de Remote Desktop Services con un servidor en particular, pero no puede iniciar sesión en la consola de ese mismo servidor.|
|SeBackupPrivilege|[Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories)|Administrators|Este user right determina qué usuarios pueden omitir los permisos de archivos y directorios, registro y otros objetos persistentes con el propósito de respaldar el sistema.|
|SeSecurityPrivilege|[Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log)|Administrators|Esta configuración de política determina qué usuarios pueden especificar opciones de auditoría de acceso a objetos para recursos individuales como archivos, objetos de Active Directory y claves de registro. Estos objetos especifican sus listas de control de acceso del sistema (SACL). Un usuario asignado a este user right también puede ver y borrar el Security log en el Event Viewer.|
|SeTakeOwnershipPrivilege|[Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects)|Administrators|Esta configuración de política determina qué usuarios pueden asumir la propiedad de cualquier objeto securable en el dispositivo, incluidos los objetos de Active Directory, archivos y carpetas NTFS, impresoras, claves de registro, servicios, procesos y subprocesos.|
|SeDebugPrivilege|[Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs)|Administrators|Esta configuración de política determina qué usuarios pueden adjuntar o abrir cualquier proceso, incluso un proceso que no poseen. Los desarrolladores que están depurando sus aplicaciones no necesitan este user right. Los desarrolladores que están depurando nuevos componentes del sistema necesitan este user right. Este user right proporciona acceso a componentes del sistema operativo sensibles y críticos.|
|SeImpersonatePrivilege|[Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication)|Administrators, Local Service, Network Service, Service|Esta configuración de política determina qué programas pueden hacerse pasar por un usuario u otra cuenta especificada y actuar en nombre del usuario.|
|SeLoadDriverPrivilege|[Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers)|Administrators|Esta configuración de política determina qué usuarios pueden cargar y descargar dinámicamente controladores de dispositivos. Este user right no es necesario si un controlador firmado para el nuevo hardware ya existe en el archivo driver.cab en el dispositivo. Los controladores de dispositivos se ejecutan como código con privilegios elevados.|
|SeRestorePrivilege|[Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories)|Administrators|Esta configuración de seguridad determina qué usuarios pueden omitir los permisos de archivos, directorios, registros y otros objetos persistentes cuando restauran archivos y directorios respaldados. Determina qué usuarios pueden establecer security principals válidos como propietarios de un objeto.|

Más información puede encontrarse [aquí](https://4sysops.com/archives/user-rights-assignment-in-windows-server-2016/).

Escribir el comando `whoami /priv` te dará una lista de todos los user rights asignados a tu usuario actual. Algunos derechos solo están disponibles para usuarios administrativos y solo se pueden listar/aprovechar cuando se ejecuta una sesión de cmd o PowerShell elevada. Estos conceptos de derechos elevados y [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) son características de seguridad introducidas con Windows Vista para restringir por defecto las aplicaciones de ejecutarse con permisos completos a menos que sea necesario. Si comparamos y contrastamos los derechos disponibles para nosotros como administradores en una consola no elevada vs. una consola elevada, veremos que difieren drásticamente.

A continuación se muestran los derechos disponibles para una cuenta de administrador local en un sistema Windows.

### Local Admin User Rights - Elevated

Si ejecutamos una ventana de comandos elevada, podemos ver la lista completa de derechos disponibles para nosotros:

```r
PS C:\htb> whoami 

winlpe-srv01\administrator


PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled 
```

Cuando un privilege se enumera para nuestra cuenta en el estado `Disabled`, significa que nuestra cuenta tiene el privilege específico asignado. Sin embargo, no se puede usar en un access token para realizar las acciones asociadas hasta que se habilite. Windows no proporciona un comando integrado o cmdlet de PowerShell para habilitar privileges, por lo que necesitamos algunos scripts para ayudarnos. Veremos formas de abusar de varios privileges a lo largo de este módulo y diversas formas de habilitar privileges específicos dentro de nuestro proceso actual. Un ejemplo es este [script](https://www.powershellgallery.com/packages/PoshPrivilege/0.3.0.0/Content/Scripts%5CEnable-Privilege.ps1) de PowerShell que se puede utilizar para habilitar ciertos privileges, o este [script](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) que se puede utilizar para ajustar los token privileges.

Un usuario estándar, en contraste, tiene muchos menos derechos.

### Standard User Rights

```r
PS C:\htb> whoami 

winlpe-srv01\htb-student


PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Los user rights aumentan en función de los grupos en los que se encuentran o los privileges asignados. A continuación se muestra un ejemplo de los derechos otorgados a los usuarios en el grupo `Backup Operators`. Los usuarios en este grupo tienen otros derechos que UAC actualmente restringe. Sin embargo, podemos ver en este comando que tienen el [SeShutdownPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/shut-down-the-system), lo que significa que pueden apagar un domain controller, lo que podría causar una interrupción masiva del servicio si inician sesión localmente en un domain controller (no a través de RDP o WinRM).

### Backup Operators Rights

```r
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

---

## Detection

Este [post](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) vale la pena leer para obtener más información sobre los privileges en Windows, así como la detección y prevención de abusos, específicamente registrando el evento [4672: Special privileges assigned to new logon](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672), que generará un evento si se asignan ciertos privileges sensibles a una nueva sesión de inicio de sesión. Esto se puede afinar de muchas maneras, como monitorear privileges que nunca deberían asignarse o aquellos que solo deberían asignarse a cuentas específicas.

---

## Moving On

Como atacantes y defensores, necesitamos revisar la membresía de estos grupos. No es raro encontrar usuarios aparentemente de bajo privilegio agregados a uno o más de estos grupos, lo que puede usarse para comprometer un solo host o acceder más dentro de un entorno de Active Directory. Discutiremos las implicaciones de algunos de los derechos más comunes y realizaremos ejercicios sobre cómo escalar privileges si obtenemos acceso a un usuario con algunos de estos derechos asignados a su cuenta.