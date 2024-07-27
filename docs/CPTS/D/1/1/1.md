La cuenta `root` en los sistemas Linux proporciona acceso administrativo completo al sistema operativo. Durante una evaluación, es posible que obtengas una shell de bajo privilegio en un host Linux y necesites realizar una escalada de privilegios a la cuenta `root`. Comprometer completamente el host nos permitiría capturar tráfico y acceder a archivos sensibles, lo que podría ser utilizado para obtener más acceso dentro del entorno. Además, si la máquina Linux está unida a un dominio, podemos obtener el hash NTLM y comenzar a enumerar y atacar el Active Directory.

---

## Enumeration

La enumeración es clave para la escalada de privilegios. Existen varios scripts auxiliares (como [LinEnum](https://github.com/rebootuser/LinEnum)) que ayudan con la enumeración. Aún así, también es importante entender qué piezas de información buscar y poder realizar tu propia enumeración manualmente. Cuando obtengas acceso inicial a la shell del host, es importante revisar varios detalles clave.

`OS Version`: Conocer la distribución (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) te dará una idea de los tipos de herramientas que pueden estar disponibles. Esto también identificaría la versión del sistema operativo, para la cual podrían existir exploits públicos disponibles.

`Kernel Version`: Al igual que con la versión del sistema operativo, pueden existir exploits públicos que apunten a una vulnerabilidad en una versión específica del kernel. Los exploits del kernel pueden causar inestabilidad en el sistema o incluso un bloqueo completo. Ten cuidado al ejecutar estos contra cualquier sistema en producción y asegúrate de entender completamente el exploit y sus posibles ramificaciones antes de ejecutarlo.

`Running Services`: Conocer qué servicios están ejecutándose en el host es importante, especialmente aquellos que se ejecutan como `root`. Un servicio mal configurado o vulnerable que se ejecute como `root` puede ser una victoria fácil para la escalada de privilegios. Se han descubierto fallos en muchos servicios comunes como Nagios, Exim, Samba, ProFTPd, etc. Existen PoCs de exploits públicos para muchos de ellos, como CVE-2016-9566, una vulnerabilidad de escalada de privilegios local en Nagios Core < 4.2.4.

### List Current Processes

```r
ps aux | grep root

root         1  1.3  0.1  37656  5664 ?        Ss   23:26   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    23:26   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    23:26   0:00 [ksoftirqd/0]
root         4  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/0:0]
root         5  0.0  0.0      0     0 ?        S<   23:26   0:00 [kworker/0:0H]
root         6  0.0  0.0      0     0 ?        S    23:26   0:00 [kworker/u8:0]
root         7  0.0  0.0      0     0 ?        S    23:26   0:00 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    23:26   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    23:26   0:00 [migration/0]

<SNIP>
```

`Installed Packages and Versions`: Al igual que con los servicios en ejecución, es importante verificar si hay paquetes desactualizados o vulnerables que puedan ser fácilmente aprovechados para la escalada de privilegios. Un ejemplo es Screen, que es un multiplexor de terminal común (similar a tmux). Permite iniciar una sesión y abrir muchas ventanas o terminales virtuales en lugar de abrir múltiples sesiones de terminal. La versión 4.05.00 de Screen sufre de una vulnerabilidad de escalada de privilegios que puede ser fácilmente aprovechada para escalar privilegios.

`Logged in Users`: Conocer qué otros usuarios están conectados al sistema y qué están haciendo puede dar una mayor visión sobre posibles movimientos laterales locales y caminos de escalada de privilegios.

### List Current Processes

```r
ps au

USER       		PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root      		1256  0.0  0.1  65832  3364 tty1     Ss   23:26   0:00 /bin/login --
cliff.moore     1322  0.0  0.1  22600  5160 tty1     S    23:26   0:00 -bash
shared     		1367  0.0  0.1  22568  5116 pts/0    Ss   23:27   0:00 -bash
root      		1384  0.0  0.1  52700  3812 tty1     S    23:29   0:00 sudo su
root      		1385  0.0  0.1  52284  3448 tty1     S    23:29   0:00 su
root      		1386  0.0  0.1  21224  3764 tty1     S+   23:29   0:00 bash
shared     		1397  0.0  0.1  37364  3428 pts/0    R+   23:30   0:00 ps au
```

`User Home Directories`: ¿Son accesibles los directorios home de otros usuarios? Las carpetas home de usuarios también pueden contener claves SSH que pueden ser utilizadas para acceder a otros sistemas o scripts y archivos de configuración que contengan credenciales. No es raro encontrar archivos que contienen credenciales que pueden ser aprovechadas para acceder a otros sistemas o incluso para entrar en el entorno de Active Directory.

### Home Directory Contents

```r
ls /home

backupsvc  bob.jones  cliff.moore  logger  mrb3n  shared  stacey.jenkins
```

Podemos revisar directorios de usuarios individuales y verificar si los archivos como `.bash_history` son legibles y contienen comandos interesantes, buscar archivos de configuración y verificar si podemos obtener copias de las claves SSH de un usuario.

### User's Home Directory Contents

```r
ls -la /home/stacey.jenkins/

total 32
drwxr-xr-x 3 stacey.jenkins stacey.jenkins 4096 Aug 30 23:37 .
drwxr-xr-x 9 root           root           4096 Aug 30 23:33 ..
-rw------- 1 stacey.jenkins stacey.jenkins   41 Aug 30 23:35 .bash_history
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  220 Sep  1  2015 .bash_logout
-rw-r--r-- 1 stacey.jenkins stacey.jenkins 3771 Sep  1  2015 .bashrc
-rw-r--r-- 1 stacey.jenkins stacey.jenkins   97 Aug 30 23:37 config.json
-rw-r--r-- 1 stacey.jenkins stacey.jenkins  655 May 16  2017 .profile
drwx------ 2 stacey.jenkins stacey.jenkins 4096 Aug 30 23:35 .ssh
```

Si encuentras una clave SSH para tu usuario actual, esto podría ser usado para abrir una sesión SSH en el host (si SSH está expuesto externamente) y obtener una sesión estable y completamente interactiva. Las claves SSH podrían ser aprovechadas para acceder a otros sistemas dentro de la red también. Al mínimo, verifica la caché ARP para ver qué otros hosts están siendo accedidos y cruza estos con cualquier clave privada SSH utilizable.

### SSH Directory Contents

```r
ls -l ~/.ssh

total 8
-rw------- 1 mrb3n mrb3n 1679 Aug 30 23:37 id_rsa
-rw-r--r-- 1 mrb3n mrb3n  393 Aug 30 23:37 id_rsa.pub
```

También es importante revisar el historial bash de un usuario, ya que pueden estar pasando contraseñas como argumento en la línea de comandos, trabajando con repositorios git, configurando trabajos cron, y más. Revisar lo que el usuario ha estado haciendo puede darte una considerable visión sobre el tipo de servidor en el que te encuentras y dar una pista sobre caminos de escalada de privilegios.

### Bash History

```r
history

    1  id
    2  cd /home/cliff.moore
    3  exit
    4  touch backup.sh
    5  tail /var/log

/apache2/error.log
    6  ssh ec2-user@dmz02.inlanefreight.local
    7  history
```

`Sudo Privileges`: ¿Puede el usuario ejecutar algún comando ya sea como otro usuario o como `root`? Si no tienes credenciales para el usuario, puede que no sea posible aprovechar los permisos `sudo`. Sin embargo, a menudo las entradas de sudoer incluyen `NOPASSWD`, lo que significa que el usuario puede ejecutar el comando especificado sin ser solicitado por una contraseña. No todos los comandos que podamos ejecutar como `root` llevarán a la escalada de privilegios. No es raro obtener acceso como un usuario con privilegios `sudo` completos, lo que significa que pueden ejecutar cualquier comando como `root`. Emitir un simple comando `sudo su` te dará inmediatamente una sesión `root`.

### Sudo - List User's Privileges

```r
sudo -l

Matching Defaults entries for sysadm on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User sysadm may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/tcpdump
```

`Configuration Files`: Los archivos de configuración pueden contener una gran cantidad de información. Vale la pena buscar en todos los archivos que terminen en extensiones como `.conf` y `.config`, buscando nombres de usuario, contraseñas y otros secretos.

`Readable Shadow File`: Si el archivo shadow es legible, podrás reunir hashes de contraseñas para todos los usuarios que tienen una contraseña configurada. Aunque esto no garantiza un acceso adicional, estos hashes pueden ser sometidos a un ataque de fuerza bruta fuera de línea para recuperar la contraseña en texto claro.

`Password Hashes in /etc/passwd`: Ocasionalmente, verás hashes de contraseñas directamente en el archivo `/etc/passwd`. Este archivo es legible por todos los usuarios, y al igual que con los hashes en el archivo `shadow`, estos pueden ser sometidos a un ataque de fuerza bruta fuera de línea. Esta configuración, aunque no es común, a veces puede ser vista en dispositivos integrados y enrutadores.

### Passwd

```r
cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
<...SNIP...>
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
mrb3n:x:1000:1000:mrb3n,,,:/home/mrb3n:/bin/bash
colord:x:111:118:colord colour management daemon,,,:/var/lib/colord:/bin/false
backupsvc:x:1001:1001::/home/backupsvc:
bob.jones:x:1002:1002::/home/bob.jones:
cliff.moore:x:1003:1003::/home/cliff.moore:
logger:x:1004:1004::/home/logger:
shared:x:1005:1005::/home/shared:
stacey.jenkins:x:1006:1006::/home/stacey.jenkins:
sysadm:$6$vdH7vuQIv6anIBWg$Ysk.UZzI7WxYUBYt8WRIWF0EzWlksOElDE0HLYinee38QI1A.0HW7WZCrUhZ9wwDz13bPpkTjNuRoUGYhwFE11:1007:1007::/home/sysadm:
```

`Cron Jobs`: Los trabajos cron en los sistemas Linux son similares a las tareas programadas de Windows. A menudo se configuran para realizar tareas de mantenimiento y copias de seguridad. En conjunto con otras configuraciones incorrectas, como rutas relativas o permisos débiles, se pueden aprovechar para escalar privilegios cuando se ejecuta el trabajo cron programado.

### Cron Jobs

```r
ls -la /etc/cron.daily/

total 60
drwxr-xr-x  2 root root 4096 Aug 30 23:49 .
drwxr-xr-x 93 root root 4096 Aug 30 23:47 ..
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Sep 26  2017 apt-compat
-rwx--x--x  1 root root  379 Aug 30 23:49 backup
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 27  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common
```

`Unmounted File Systems and Additional Drives`: Si descubres y puedes montar un disco adicional o un sistema de archivos no montado, es posible que encuentres archivos sensibles, contraseñas o copias de seguridad que puedan ser aprovechadas para escalar privilegios.

### File Systems & Additional Drives

```r
lsblk

NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
sda      8:0    0   30G  0 disk 
├─sda1   8:1    0   29G  0 part /
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1  848M  0 rom  
```

`SETUID and SETGID Permissions`: Los binarios se configuran con estos permisos para permitir que un usuario ejecute un comando como `root`, sin tener que otorgar acceso a nivel `root` al usuario. Muchos binarios contienen funcionalidades que pueden ser explotadas para obtener una shell de `root`.

`Writeable Directories`: Es importante descubrir qué directorios son escribibles si necesitas descargar herramientas al sistema. Puedes descubrir un directorio escribible donde un trabajo cron coloca archivos, lo que proporciona una idea de la frecuencia con la que se ejecuta el trabajo cron y podría ser utilizado para elevar privilegios si el script que ejecuta el trabajo cron también es escribible.

### Find Writable Directories

```r
find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null

/dmz-backups
/tmp
/tmp/VMwareDnD
/tmp/.XIM-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-TIecv0/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/proc
/dev/mqueue
/dev/shm
/var/tmp
/var/tmp/systemd-private-8a2c51fcbad240d09578916b47b0bb17-systemd-timesyncd.service-hm6Qdl/tmp
/var/crash
/run/lock
```

`Writeable Files`: ¿Hay algún script o archivo de configuración que sea escribible por todos? Aunque alterar archivos de configuración puede ser extremadamente destructivo, puede haber casos donde una pequeña modificación pueda abrir más acceso. Además, cualquier script que se ejecute como `root` usando trabajos cron puede ser modificado ligeramente para agregar un comando.

### Find Writable Files

```r
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

/etc/

cron.daily/backup
/dmz-backups/backup.sh
/proc
/sys/fs/cgroup/memory/init.scope/cgroup.event_control

<SNIP>

/home/backupsvc/backup.sh

<SNIP>
```

---

## Moving on

Como hemos visto, existen varias técnicas de enumeración manual que podemos realizar para obtener información que informe sobre varios ataques de escalada de privilegios. Existen una variedad de técnicas que pueden ser aprovechadas para realizar escaladas de privilegios locales en Linux, las cuales cubriremos en las siguientes secciones.