Las vulnerabilidades son comúnmente descubiertas por personas que usan y entienden la tecnología, un protocolo o un servicio. A medida que avanzamos en este campo, encontraremos diferentes servicios con los que interactuar, y necesitaremos evolucionar y aprender nuevas tecnologías constantemente.

Para tener éxito al atacar un servicio, necesitamos conocer su propósito, cómo interactuar con él, qué herramientas podemos usar y qué podemos hacer con él. Esta sección se centrará en servicios comunes y cómo podemos interactuar con ellos.

## File Share Services

Un file sharing service es un tipo de servicio que proporciona, media y monitorea la transferencia de archivos de computadora. Hace años, las empresas comúnmente usaban solo servicios internos para compartir archivos, como SMB, NFS, FTP, TFTP, SFTP, pero a medida que la adopción de la nube crece, la mayoría de las empresas ahora también tienen servicios en la nube de terceros como Dropbox, Google Drive, OneDrive, SharePoint, u otras formas de almacenamiento de archivos como AWS S3, Azure Blob Storage o Google Cloud Storage. Estaremos expuestos a una mezcla de servicios de compartición de archivos internos y externos, y necesitamos estar familiarizados con ellos.

Esta sección se centrará en servicios internos, pero esto puede aplicarse al almacenamiento en la nube sincronizado localmente en servidores y estaciones de trabajo.

## Server Message Block (SMB)

SMB se usa comúnmente en redes Windows, y a menudo encontraremos carpetas compartidas en una red Windows. Podemos interactuar con SMB usando la GUI, CLI o herramientas. Cubramos algunas formas comunes de interactuar con SMB usando Windows y Linux.

### Windows

Hay diferentes formas de interactuar con una carpeta compartida usando Windows, y exploraremos un par de ellas. En la GUI de Windows, podemos presionar `[WINKEY] + [R]` para abrir el cuadro de diálogo Ejecutar y escribir la ubicación de la carpeta compartida, por ejemplo: `\\192.168.220.129\Finance\`

![text](https://academy.hackthebox.com/storage/modules/116/windows_run_sharefolder2.jpg)

Supongamos que la carpeta compartida permite autenticación anónima, o estamos autenticados con un usuario que tiene privilegios sobre esa carpeta compartida. En ese caso, no recibiremos ninguna solicitud de autenticación, y se mostrará el contenido de la carpeta compartida.

![image](https://academy.hackthebox.com/storage/modules/116/finance_share_folder2.jpg)

Si no tenemos acceso, recibiremos una solicitud de autenticación.

![text](https://academy.hackthebox.com/storage/modules/116/auth_request_share_folder2.jpg)

Windows tiene dos shells de línea de comandos: el [Command shell](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands) y [PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/overview). Cada shell es un programa de software que proporciona comunicación directa entre nosotros y el sistema operativo o la aplicación, proporcionando un entorno para automatizar operaciones de TI.

Discutamos algunos comandos para interactuar con file share usando Command Shell (`CMD`) y `PowerShell`. El comando [dir](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/dir) muestra una lista de archivos y subdirectorios de un directorio.

### Windows CMD - DIR

```r
C:\htb> dir \\192.168.220.129\Finance\

Volume in drive \\192.168.220.129\Finance has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\192.168.220.129\Finance

02/23/2022  11:35 AM    <DIR>          Contracts
               0 File(s)          4,096 bytes
               1 Dir(s)  15,207,469,056 bytes free
```

El comando [net use](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/gg651155(v=ws.11)) conecta una computadora a un recurso compartido o la desconecta de él, o muestra información sobre conexiones de computadora. Podemos conectarnos a un file share con el siguiente comando y mapear su contenido a la letra de unidad `n`.

### Windows CMD - Net Use

```r
C:\htb> net use n: \\192.168.220.129\Finance

The command completed successfully.
```

También podemos proporcionar un nombre de usuario y una contraseña para autenticarnos en el recurso compartido.

```r
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123

The command completed successfully.
```

Con la carpeta compartida mapeada como la unidad `n`, podemos ejecutar comandos de Windows como si esta carpeta compartida estuviera en nuestra computadora local. Vamos a encontrar cuántos archivos contiene la carpeta compartida y sus subdirectorios.

### Windows CMD - DIR

```r
C:\htb> dir n: /a-d /s /b | find /c ":\"

29302
```

Encontramos 29,302 archivos. Desglosamos el comando:

```r
dir n: /a-d /s /b | find /c ":\"
```

| **Sintaxis** | **Descripción** |
| --- | --- |
| `dir` | Aplicación |
| `n:` | Directorio o unidad a buscar |
| `/a-d` | `/a` es el atributo y `-d` significa no directorios |
| `/s` | Muestra archivos en un directorio especificado y todos los subdirectorios |
| `/b` | Usa formato simple (sin información de encabezado ni resumen) |

El siguiente comando `| find /c ":\\"` procesa la salida de `dir n: /a-d /s /b` para contar cuántos archivos existen en el directorio y subdirectorios. Puedes usar `dir /?` para ver la ayuda completa. Buscar entre 29,302 archivos lleva tiempo, los scripts y utilidades de línea de comandos pueden ayudarnos a acelerar la búsqueda. Con `dir` podemos buscar nombres específicos en archivos como:

- cred
- password
- users
- secrets
- key
- Common File Extensions for source code such as: .cs, .c, .go, .java, .php, .asp, .aspx, .html.

```r
C:\htb>dir n:\*cred* /s /b

n:\Contracts\private\credentials.txt


C:\htb>dir n:\*secret* /s /b

n:\Contracts\private\secret.txt
```

Si queremos buscar una palabra específica dentro de un archivo de texto, podemos usar [findstr](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr).

### Windows CMD - Findstr

```r
c:\htb>findstr /s /i cred n:\*.*

n:\Contracts\private\secret.txt:file with all credentials
n:\Contracts\private\credentials.txt:admin:SecureCredentials!
```

Podemos encontrar más ejemplos de `findstr` [aquí](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/findstr#examples).

### Windows PowerShell

PowerShell fue diseñado para extender las capacidades del Command shell para ejecutar comandos de PowerShell llamados `cmdlets`. Los cmdlets son similares a los comandos de Windows pero proporcionan un lenguaje de scripting más extensible. Podemos ejecutar tanto comandos de Windows como cmdlets de PowerShell en PowerShell, pero el Command shell solo puede ejecutar comandos de Windows y no cmdlets de PowerShell. Replicamos los mismos comandos ahora usando PowerShell.

### Windows PowerShell

```r
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

    Directory: \\192.168.220.129\Finance

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         2/23/2022   3:27 PM                Contracts
```

En lugar de `net use`, podemos usar `New-PSDrive` en PowerShell.

```r
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

Para proporcionar un nombre de usuario y contraseña con Powershell, necesitamos crear un [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential). Ofrece una forma centralizada de gestionar nombres de usuario, contraseñas y credenciales.

### Windows PowerShell - PSCredential Object

```r
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\

Finance
```

En PowerShell, podemos usar el comando `Get-ChildItem` o la variante corta `gci` en lugar del comando `dir`.

### Windows PowerShell - GCI

```r
PS C:\htb> N:
PS N:\> (Get-ChildItem -File -Recurse | Measure-Object).Count

29302
```

Podemos usar la propiedad `-Include` para encontrar elementos específicos del directorio especificado por el parámetro Path.

```r
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```

El cmdlet `Select-String` usa coincidencias de expresiones regulares para buscar patrones de texto en cadenas de entrada y archivos. Podemos usar `Select-String` similar a `grep` en UNIX o `findstr.exe` en Windows.

### Windows PowerShell - Select-String

```r
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

CLI permite que las operaciones de TI automaticen tareas rutinarias como la gestión de cuentas de usuario, las copias de seguridad nocturnas o la interacción con muchos archivos. Podemos realizar operaciones de manera más eficiente utilizando scripts que la interfaz de usuario o GUI.

### Linux

Las máquinas Linux (UNIX) también pueden usarse para explorar y montar comparticiones SMB. Ten en cuenta que esto se puede hacer ya sea que el servidor de destino sea una máquina Windows o un servidor Samba. Aunque algunas distribuciones de Linux admiten una GUI, nos centraremos en las utilidades y herramientas de línea de comandos de Linux para interactuar con SMB. Cubramos cómo montar comparticiones SMB para interactuar con directorios y archivos localmente.

### Linux - Mount

```r
sudo mkdir /mnt/Finance
sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```

Como alternativa, podemos usar un archivo de credenciales.

```r
mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```

El archivo `credentialfile` debe estar estructurado así:

### CredentialFile

```r
username=plaintext
password=Password123
domain=.
```

Nota: Necesitamos instalar `cifs-utils` para conectarnos a una carpeta compartida SMB. Para instalarlo, podemos ejecutar desde la línea de comandos `sudo apt install cifs-utils`.

Una vez montada una carpeta compartida, puedes usar herramientas comunes de Linux como `find` o `grep` para interactuar con la estructura de archivos. Busquemos un nombre de archivo que contenga la cadena `cred`:

### Linux - Find

```r
find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

A continuación, busquemos archivos que contengan la cadena `cred`:

```r
grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```

## Other Services

Hay otros servicios de compartición de archivos como FTP, TFTP y NFS que podemos adjuntar (montar) utilizando diferentes herramientas y comandos. Sin embargo, una vez que montemos un servicio de compartición de archivos, debemos entender que podemos usar las herramientas disponibles en Linux o Windows para interactuar con archivos y directorios. A medida que descubramos nuevos servicios de compartición de archivos, necesitaremos investigar cómo funcionan y qué herramientas podemos usar para interactuar con ellos.

### Email

Normalmente necesitamos dos protocolos para enviar y recibir mensajes, uno para enviar y otro para recibir. El Simple Mail Transfer Protocol (SMTP) es un protocolo de entrega de correo electrónico utilizado para enviar correo a través de Internet. Asimismo, debe usarse un protocolo de apoyo para recuperar un correo electrónico de un servicio. Hay dos protocolos principales que podemos usar: POP3 e IMAP.

Podemos usar un cliente de correo como [Evolution](https://wiki.gnome.org/Apps/Evolution), el administrador de información personal oficial y cliente de correo para el entorno de escritorio GNOME. Podemos interactuar con un servidor de correo para enviar o recibir mensajes con un cliente de correo. Para instalar Evolution, podemos usar el siguiente comando:

### Linux - Install Evolution

```r
sudo apt-get install evolution
...SNIP...
```

Nota: Si aparece un error al iniciar evolution que indica "bwrap: Can't create file at ...", usa este comando para iniciar evolution `export WEBKIT_FORCE_SANDBOX=0 && evolution`.

### Video - Connecting to IMAP and SMTP using Evolution

Haz clic en la imagen a continuación para ver una breve demostración en video.

[![Evolution](https://academy.hackthebox.com/storage/modules/116/ConnectToIMAPandSMTP.jpg)](https://www.youtube.com/watch?v=xelO2CiaSVs)

Podemos usar el nombre de dominio o la dirección IP del servidor de correo. Si el servidor utiliza SMTPS o IMAPS, necesitaremos el método de cifrado apropiado (TLS en un puerto dedicado o STARTTLS después de conectarnos). Podemos usar la opción `Check for Supported Types` en autenticación para confirmar si el servidor admite nuestro método seleccionado.

### Databases

Las bases de datos se utilizan comúnmente en empresas, y la mayoría de las compañías las usan para almacenar y gestionar información. Hay diferentes tipos de bases de datos, como bases de datos jerárquicas, NoSQL (o no relacionales) y bases de datos SQL relacionales. Nos centraremos en las bases de datos SQL relacionales y las dos bases de datos relacionales más comunes llamadas MySQL y MSSQL. Tenemos tres formas comunes de interactuar con bases de datos:

|||
| --- | --- |
| `1.` | Command Line Utilities (`mysql` o `sqsh`) |
| `2.` | Una aplicación GUI para interactuar con bases de datos como HeidiSQL, MySQL Workbench o SQL Server Management Studio. |
| `3.` | Lenguajes de programación |

### MySQL example

![text](https://academy.hackthebox.com/storage/modules/116/3_way_to_interact_with_MySQL.png)

Exploremos utilidades de línea de comandos y una aplicación GUI.

## Command Line Utilities

### MSSQL

Para interactuar con [MSSQL (Microsoft SQL Server)](https://www.microsoft.com/en-us/sql-server/sql-server-downloads) con Linux, podemos usar [sqsh](https://en.wikipedia.org/wiki/Sqsh) o [sqlcmd](https://docs.microsoft.com/en-us/sql/tools/sqlcmd-utility) si estás usando Windows. `Sqsh` es mucho más que un prompt amigable. Está destinado a proporcionar gran parte de la funcionalidad proporcionada por un shell de comandos, como variables, alias, redirección, pipes, control de trabajos, historial, sustitución de comandos y configuración dinámica. Podemos iniciar una sesión interactiva de SQL de la siguiente manera:

### Linux - SQSH

```r
sqsh -S 10.129.20.13 -U username -P Password123
```

La utilidad `sqlcmd` te permite ingresar declaraciones Transact-SQL, procedimientos del sistema y archivos de script a través de una variedad de modos disponibles:

- En el símbolo del sistema.
- En Query Editor en modo SQLCMD.
- En un archivo de script de Windows.
- En un paso de trabajo del Agente SQL Server en un trabajo del sistema operativo (Cmd.exe).

### Windows - SQLCMD

```r
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

Para aprender más sobre el uso de `sqlcmd`, puedes ver la [documentación de Microsoft](https://docs.microsoft.com/en-us/sql/ssms/scripting/sqlcmd-use-the-utility).

### MySQL

Para interactuar con [MySQL](https://en.wikipedia.org/wiki/MySQL), podemos usar los binarios de MySQL para Linux (`mysql`) o Windows (`mysql.exe`). MySQL viene preinstalado en algunas distribuciones de Linux, pero podemos instalar los binarios de MySQL para Linux o Windows usando esta [guía](https://dev.mysql.com/doc/mysql-getting-started/en/#mysql-getting-started-installing). Inicia una sesión interactiva de SQL usando Linux:

### Linux - MySQL

```r
mysql -u username -pPassword123 -h 10.129.20.13
```

Podemos iniciar fácilmente una sesión interactiva de SQL usando Windows:

### Windows - MySQL

```r
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```

### GUI Application

Los motores de bases de datos comúnmente tienen su propia aplicación GUI. MySQL tiene [MySQL Workbench](https://dev.mysql.com/downloads/workbench/) y MSSQL tiene [SQL Server Management Studio o SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms), podemos instalar esas herramientas en nuestro host de ataque y conectarnos a la base de datos. SSMS solo es compatible con Windows. Una alternativa es usar

 herramientas comunitarias como [dbeaver](https://github.com/dbeaver/dbeaver). [dbeaver](https://github.com/dbeaver/dbeaver) es una herramienta de base de datos multiplataforma para Linux, macOS y Windows que admite la conexión a múltiples motores de base de datos como MSSQL, MySQL, PostgreSQL, entre otros, lo que facilita que nosotros, como atacantes, interactuemos con servidores de bases de datos comunes.

Para instalar [dbeaver](https://github.com/dbeaver/dbeaver) usando un paquete Debian, podemos descargar el paquete release .deb desde [https://github.com/dbeaver/dbeaver/releases](https://github.com/dbeaver/dbeaver/releases) y ejecutar el siguiente comando:

### Install dbeaver

```r
sudo dpkg -i dbeaver-<version>.deb
```

Para iniciar la aplicación, usa:

### Run dbeaver

```r
dbeaver &
```

Para conectarse a una base de datos, necesitaremos un conjunto de credenciales, la IP de destino y el número de puerto de la base de datos, y el motor de la base de datos al que intentamos conectarnos (MySQL, MSSQL u otro).

### Video - Connecting to MSSQL DB using dbeaver

Haz clic en la imagen a continuación para ver una breve demostración en video de la conexión a una base de datos MSSQL usando `dbeaver`.

[![MSSQL](https://academy.hackthebox.com/storage/modules/116/ConnectToMSSQL.jpg)](https://www.youtube.com/watch?v=gU6iQP5rFMw)

Haz clic en la imagen a continuación para ver una breve demostración en video de la conexión a una base de datos MySQL usando `dbeaver`.

### Video - Connecting to MySQL DB using dbeaver

[![MYSQL](https://academy.hackthebox.com/storage/modules/116/ConnectToMYSQL.jpg)](https://www.youtube.com/watch?v=PeuWmz8S6G8)

Una vez que tengamos acceso a la base de datos usando una utilidad de línea de comandos o una aplicación GUI, podemos usar declaraciones comunes de [Transact-SQL](https://docs.microsoft.com/en-us/sql/t-sql/statements/statements?view=sql-server-ver15) para enumerar bases de datos y tablas que contengan información sensible como nombres de usuario y contraseñas. Si tenemos los privilegios correctos, podríamos potencialmente ejecutar comandos como la cuenta de servicio de MSSQL. Más adelante en este módulo, discutiremos declaraciones comunes de Transact-SQL y ataques para las bases de datos MSSQL y MySQL.

## Tools

Es crucial familiarizarse con las utilidades de línea de comandos predeterminadas disponibles para interactuar con diferentes servicios. Sin embargo, a medida que avanzamos en el campo, encontraremos herramientas que pueden ayudarnos a ser más eficientes. La comunidad comúnmente crea esas herramientas. Aunque, eventualmente, tendremos ideas sobre cómo una herramienta puede mejorarse o para crear nuestras propias herramientas, incluso si no somos desarrolladores a tiempo completo, cuanto más nos familiaricemos con el hacking. Cuanto más aprendemos, más nos encontramos buscando una herramienta que no existe, lo que puede ser una oportunidad para aprender y crear nuestras herramientas.

### Tools to Interact with Common Services

|**SMB**|**FTP**|**Email**|**Databases**|
|---|---|---|---|
|[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)|[ftp](https://linux.die.net/man/1/ftp)|[Thunderbird](https://www.thunderbird.net/en-US/)|[mssql-cli](https://github.com/dbcli/mssql-cli)|
|[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)|[lftp](https://lftp.yar.ru/)|[Claws](https://www.claws-mail.org/)|[mycli](https://github.com/dbcli/mycli)|
|[SMBMap](https://github.com/ShawnDEvans/smbmap)|[ncftp](https://www.ncftp.com/)|[Geary](https://wiki.gnome.org/Apps/Geary)|[mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)|
|[Impacket](https://github.com/SecureAuthCorp/impacket)|[filezilla](https://filezilla-project.org/)|[MailSpring](https://getmailspring.com/)|[dbeaver](https://github.com/dbeaver/dbeaver)|
|[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)|[crossftp](http://www.crossftp.com/)|[mutt](http://www.mutt.org/)|[MySQL Workbench](https://dev.mysql.com/downloads/workbench/)|
|[smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)||[mailutils](https://mailutils.org/)|[SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms)|
|||[sendEmail](https://github.com/mogaal/sendemail)||
|||[swaks](http://www.jetmore.org/john/code/swaks/)||
|||[sendmail](https://en.wikipedia.org/wiki/Sendmail)||

---

## General Troubleshooting

Dependiendo de la versión de Windows o Linux con la que estemos trabajando o atacando, podemos encontrar diferentes problemas al intentar conectarnos a un servicio.

Algunas razones por las que podríamos no tener acceso a un recurso:

- Authentication
- Privileges
- Network Connection
- Firewall Rules
- Protocol Support

Ten en cuenta que podemos encontrar diferentes errores dependiendo del servicio que estamos atacando. Podemos usar los códigos de error a nuestro favor y buscar documentación oficial o foros donde las personas hayan resuelto un problema similar al nuestro.