Existen muchos otros tipos de archivos que podemos encontrar en un sistema local o en unidades de red compartidas que pueden contener credenciales o información adicional que puede ser utilizada para escalar privilegios. En un entorno de Active Directory, podemos usar una herramienta como [Snaffler](https://github.com/SnaffCon/Snaffler) para rastrear unidades de red compartidas en busca de extensiones de archivos interesantes como `.kdbx`, `.vmdk`, `.vdhx`, `.ppk`, etc. Podemos encontrar un disco duro virtual que podemos montar y extraer hashes de contraseñas de administrador local, una clave privada de SSH que puede ser utilizada para acceder a otros sistemas, o instancias de usuarios almacenando contraseñas en documentos de Excel/Word, blocs de notas de OneNote, o incluso el clásico archivo `passwords.txt`. He realizado muchas pruebas de penetración donde una contraseña encontrada en una unidad compartida o unidad local llevó a acceso inicial o escalada de privilegios. Muchas compañías proporcionan a cada empleado una carpeta en una unidad compartida mapeada a su user id, es decir, la carpeta `bjones` en la compartición `users` en un servidor llamado `FILE01` con permisos aplicados laxamente (es decir, todos los Domain Users con acceso de lectura a todas las carpetas de usuario). A menudo encontramos a los usuarios guardando datos personales sensibles en estas carpetas, sin saber que son accesibles para todos en la red y no solo locales a su workstation.

---

## Manually Searching the File System for Credentials

Podemos buscar en el sistema de archivos o en la unidad compartida manualmente usando los siguientes comandos de [este cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#search-for-a-file-with-a-certain-filename)

### Search File Contents for String - Example 1

```r
C:\htb> cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt

stuff.txt
```

### Search File Contents for String - Example 2

```r
C:\htb> findstr /si password *.xml *.ini *.txt *.config

stuff.txt:password: l#-x9r11_2_GL!
```

### Search File Contents for String - Example 3

```r
C:\htb> findstr /spin "password" *.*

stuff.txt:1:password: l#-x9r11_2_GL!
```

### Search File Contents with PowerShell

También podemos buscar usando PowerShell de varias maneras. Aquí hay un ejemplo.

```r
PS C:\htb> select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password

stuff.txt:1:password: l#-x9r11_2_GL!
```

### Search for File Extensions - Example 1

```r
C:\htb> dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*

c:\inetpub\wwwroot\web.config
```

### Search for File Extensions - Example 2

```r
C:\htb> where /R C:\ *.config

c:\inetpub\wwwroot\web.config
```

De manera similar, podemos buscar en el sistema de archivos ciertas extensiones de archivo con un comando como:

### Search for File Extensions Using PowerShell

```r
PS C:\htb> Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore


    Directory: C:\inetpub\wwwroot


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/25/2021   9:59 AM            329 web.config

<SNIP>
```

---

## Sticky Notes Passwords

Las personas a menudo usan la aplicación StickyNotes en las workstations de Windows para guardar contraseñas y otra información, sin darse cuenta de que es un archivo de base de datos. Este archivo se encuentra en `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` y siempre vale la pena buscarlo y examinarlo.

### Looking for StickyNotes DB Files

```r
PS C:\htb> ls
 
 
    Directory: C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState
 
 
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         5/25/2021  11:59 AM          20480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
-a----         5/25/2021  11:59 AM            982 Ecs.dat
-a----         5/25/2021  11:59 AM           4096 plum.sqlite
-a----         5/25/2021  11:59 AM          32768 plum.sqlite-shm
-a----         5/25/2021  12:00 PM         197792 plum.sqlite-wal
```

Podemos copiar los tres archivos `plum.sqlite*` a nuestro sistema y abrirlos con una herramienta como [DB Browser for SQLite](https://sqlitebrowser.org/dl/) y ver la columna `Text` en la tabla `Note` con la consulta `select Text from Note;`.

![image](https://academy.hackthebox.com/storage/modules/67/stickynote.png)

### Viewing Sticky Notes Data Using PowerShell

Esto también puede hacerse con PowerShell utilizando el módulo [PSSQLite](https://github.com/RamblingCookieMonster/PSSQLite). Primero, importa el módulo, apunta a una fuente de datos (en este caso, el archivo de base de datos SQLite utilizado por la aplicación StickyNotes), y finalmente consulta la tabla `Note` y busca cualquier dato interesante. Esto también puede hacerse desde nuestra máquina de ataque después de descargar el archivo `.sqlite` o remotamente vía WinRM.

```r
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS C:\htb> cd .\PSSQLite\
PS C:\htb> Import-Module .\PSSQLite.psd1
PS C:\htb> $db = 'C:\Users\htb-student\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite'
PS C:\htb> Invoke-SqliteQuery -Database $db -Query "SELECT Text FROM Note" | ft -wrap
 
Text
----
\id=de368df0-6939-4579-8d38-0fda521c9bc4 vCenter
\id=e4adae4c-a40b-48b4-93a5-900247852f96
\id=1a44a631-6fff-4961-a4df-27898e9e1e65 root:Vc3nt3R_adm1n!
\id=c450fc5f-dc51-4412-b4ac-321fd41c522a Thycotic demo tomorrow at 10am
```

### Strings to View DB File Contents

También podemos copiarlos a nuestra máquina de ataque y buscar en los datos utilizando el comando `strings`, que puede ser menos eficiente dependiendo del tamaño de la base de datos.

```r
 strings plum.sqlite-wal

CREATE TABLE "Note" (
"Text" varchar ,
"WindowPosition" varchar ,
"IsOpen" integer ,
"IsAlwaysOnTop" integer ,
"CreationNoteIdAnchor" varchar ,
"Theme" varchar ,
"IsFutureNote" integer ,
"RemoteId" varchar ,
"ChangeKey" varchar ,
"LastServerVersion" varchar ,
"RemoteSchemaVersion" integer ,
"IsRemoteDataInvalid" integer ,
"PendingInsightsScan" integer ,
"Type" varchar ,
"Id" varchar primary key not null ,
"ParentId" varchar ,
"CreatedAt" bigint ,
"DeletedAt" bigint ,
"UpdatedAt" bigint )'
indexsqlite_autoindex_Note_1Note
af907b1b-1eef-4d29-b238-3ea74f7ffe5caf907b1b-1eef-4d29-b238-3ea74f7ffe5c
U	af907b1b-1eef-4d29-b238-3ea74f7ffe5c
Yellow93b49900-6530-42e0-b35c-2663989ae4b3af907b1b-1eef-4d29-b238-3ea74f7ffe5c
U	93b49900-6530-42e0-b35c-2663989ae4b3


< SNIP >

\id=011f29a4-e37f-451d-967e-c42b818473c2 vCenter
\id=34910533-ddcf-4ac4-b8ed-3d1f10be9e61 alright*
\id=ffaea2ff-b4fc-4a14-a431-998dc833208c root:Vc3nt3R_adm1n!ManagedPosition=Yellow93b49900-6530-42e0-b35c-2663989ae4b3af907b1b-1eef-4d29-b238-3ea74f7ffe5c

<SNIP >
```

---

## Other Files of Interest

### Other Interesting Files

Algunos otros archivos en los que podemos encontrar credenciales incluyen los siguientes:

```r
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
```

Algunos de los scripts de enumeración de escalada de privilegios listados anteriormente en este módulo buscan la mayoría, si no todos, los archivos/extensiones mencionados en esta sección. Sin embargo, debemos entender cómo buscar estos manualmente y no solo confiar en herramientas. Además, podemos encontrar archivos interesantes que los scripts de enumeración no buscan y desear modificar los scripts para incluirlos.