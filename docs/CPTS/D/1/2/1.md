Enumeration es clave para la escalada de privilegios. Existen varios scripts auxiliares (como [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) y [LinEnum](https://github.com/rebootuser/LinEnum)) que ayudan con la enumeración. Sin embargo, también es importante entender qué piezas de información buscar y ser capaz de realizar la enumeración manualmente. Cuando obtienes acceso inicial al shell del host, es importante verificar varios detalles clave.

`OS Version`: Conocer la distribución (Ubuntu, Debian, FreeBSD, Fedora, SUSE, Red Hat, CentOS, etc.) te dará una idea de los tipos de herramientas que pueden estar disponibles. Esto también identificará la versión del sistema operativo, para la cual puede haber exploits públicos disponibles.

`Kernel Version`: Al igual que con la versión del sistema operativo, puede haber exploits públicos que apunten a una vulnerabilidad en una versión específica del kernel. Los exploits del kernel pueden causar inestabilidad en el sistema o incluso un bloqueo completo. Ten cuidado al ejecutarlos contra cualquier sistema en producción y asegúrate de comprender completamente el exploit y las posibles repercusiones antes de ejecutar uno.

`Running Services`: Saber qué servicios están ejecutándose en el host es importante, especialmente aquellos que se ejecutan como root. Un servicio mal configurado o vulnerable que se ejecute como root puede ser una victoria fácil para la escalada de privilegios. Se han descubierto fallas en muchos servicios comunes como Nagios, Exim, Samba, ProFTPd, etc. Existen PoC de exploits públicos para muchos de ellos, como CVE-2016-9566, una falla de escalada de privilegios local en Nagios Core < 4.2.4.

---

## Gaining Situational Awareness

Supongamos que acabamos de obtener acceso a un host Linux explotando una vulnerabilidad de carga de archivos no restringida durante un External Penetration Test. Después de establecer nuestro reverse shell (e idealmente algún tipo de persistencia), deberíamos comenzar recopilando algunos conceptos básicos sobre el sistema con el que estamos trabajando.

Primero, responderemos a la pregunta fundamental: ¿Con qué sistema operativo estamos tratando? Si llegamos a un host CentOS o Red Hat Enterprise Linux, nuestra enumeración probablemente será ligeramente diferente a si llegamos a un host basado en Debian como Ubuntu. Si llegamos a un host como FreeBSD, Solaris, o algo más oscuro como el sistema operativo propietario de HP HP-UX o el sistema operativo IBM AIX, los comandos con los que trabajaríamos probablemente serían diferentes. Aunque los comandos pueden ser diferentes y puede que necesitemos buscar una referencia de comandos en algunos casos, los principios son los mismos. Para nuestros propósitos, comenzaremos con un objetivo Ubuntu para cubrir tácticas y técnicas generales. Una vez que aprendamos los conceptos básicos y los combinemos con una nueva forma de pensar y las etapas del Penetration Testing Process, no debería importar en qué tipo de sistema Linux caigamos porque tendremos un proceso completo y repetible.

Existen muchas cheat sheets para ayudar con la enumeración de sistemas Linux y algunos bits de información que nos interesan tendrán dos o más formas de obtenerse. En este módulo cubriremos una metodología que probablemente pueda ser utilizada para la mayoría de sistemas Linux que encontremos en el campo. Dicho esto, asegúrate de entender qué hacen los comandos y cómo ajustarlos o encontrar la información que necesitas de una manera diferente si un comando en particular no funciona. Desafíate durante este módulo a probar cosas de varias maneras para practicar tu metodología y ver qué funciona mejor para ti. Cualquiera puede volver a escribir comandos de una cheat sheet, pero una comprensión profunda de lo que estás buscando y cómo obtenerlo nos ayudará a tener éxito en cualquier entorno.

Normalmente querríamos ejecutar algunos comandos básicos para orientarnos:

- `whoami` - qué usuario estamos ejecutando
- `id` - a qué grupos pertenece nuestro usuario
- `hostname` - cuál es el nombre del servidor. ¿Podemos recopilar algo del sistema de nombres?
- `ifconfig` o `ip -a` - en qué subred hemos aterrizado, ¿tiene el host NICs adicionales en otras subredes?
- `sudo -l` - ¿puede nuestro usuario ejecutar algo con sudo (como otro usuario o como root) sin necesidad de una contraseña? Esto a veces puede ser la victoria más fácil y podemos hacer algo como `sudo su` y caer directamente en un shell root.

Incluir capturas de pantalla de la información anterior puede ser útil en un informe del cliente para proporcionar evidencia de una Remote Code Execution (RCE) exitosa e identificar claramente el sistema afectado. Ahora pasemos a nuestra enumeración más detallada y paso a paso.

Comenzaremos verificando qué sistema operativo y versión estamos tratando.

```r
cat /etc/os-release

NAME="Ubuntu"
VERSION="20.04.4 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.4 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
```

Podemos ver que el objetivo está ejecutando [Ubuntu 20.04.4 LTS ("Focal Fossa")](https://releases.ubuntu.com/20.04/). Para cualquier versión que encontremos, es importante ver si estamos tratando con algo desactualizado o mantenido. Ubuntu publica su [release cycle](https://ubuntu.com/about/release-cycle) y a partir de esto podemos ver que "Focal Fossa" no alcanza el fin de vida hasta abril de 2030. A partir de esta información, podemos suponer que no encontraremos una vulnerabilidad bien conocida en el Kernel porque el cliente ha estado manteniendo su activo orientado a internet parcheado, pero aún así buscaremos independientemente.

Luego, querríamos verificar el PATH de nuestro usuario actual, que es donde el sistema Linux busca cada vez que se ejecuta un comando para cualquier ejecutable que coincida con el nombre de lo que escribimos, es decir, `id` que en este sistema está ubicado en `/usr/bin/id`. Como veremos más adelante en este módulo, si la variable PATH para un usuario objetivo está mal configurada, podríamos aprovecharla para escalar privilegios. Por ahora, lo anotaremos y lo agregaremos a nuestra herramienta de toma de notas preferida.

```r
echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

También podemos verificar todas las variables de entorno que están configuradas para nuestro usuario actual, podríamos tener suerte y encontrar algo sensible allí como una contraseña. Lo anotaremos y seguiremos adelante.

```r
env

SHELL=/bin/bash
PWD=/home/htb-student
LOGNAME=htb-student
XDG_SESSION_TYPE=tty
MOTD_SHOWN=pam
HOME=/home/htb-student
LANG=en_US.UTF-8

<SNIP>
```

A continuación, anotemos la versión del Kernel. Podemos hacer algunas búsquedas para ver si el objetivo está ejecutando un Kernel vulnerable (que aprovecharemos más adelante en el módulo) que tenga algún PoC de exploit público conocido. Podemos hacer esto de varias maneras, otra forma sería `cat /proc/version` pero usaremos el comando `uname -a`.

```r
uname -a

Linux nixlpe02 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

Podemos reunir información adicional sobre el host en sí, como el tipo de CPU/versión:

```r
lscpu 

Architecture:                    x86_64
CPU op-mode(s):                  32-bit, 64-bit
Byte Order:                      Little Endian
Address sizes:                   43 bits physical, 48 bits virtual
CPU(s):                          2
On-line CPU(s) list:             0,1
Thread(s) per core:              1
Core(s) per socket:              2
Socket(s):                       1
NUMA node(s):                    1
Vendor ID:                       AuthenticAMD
CPU family:                      23
Model:                           49
Model name:                      AMD EPYC 7302P 16-Core Processor
Stepping:                        0
CPU MHz:                         2994.375
BogoMIPS:                        5988.75
Hypervisor vendor:               VMware

<SNIP>
```

¿Qué shells de inicio de sesión existen en el servidor? Anótalos y destaca que tanto Tmux como Screen están disponibles para nosotros.

```r
cat /etc/shells

# /etc/shells: valid login shells
/bin/sh
/bin/bash
/usr/bin/bash
/bin/rbash
/usr/bin/rbash
/bin/dash
/usr/bin/dash
/usr/bin/tmux
/usr/bin/screen
```

También deberíamos verificar si hay alguna defensa en su lugar y podemos enumerar cualquier información sobre ellas. Algunas cosas a buscar incluyen:

- [Exec Shield](https://en.wikipedia.org/wiki/Exec_Shield)
- [iptables](https://linux.die.net/man/8/iptables)
- [AppArmor](https://apparmor.net/)
- [SELinux](https://www.redhat.com/en/topics/linux/what-is-selinux)
- [Fail2ban](https://github.com/fail2ban/fail2ban)
- [Snort](https://www.snort.org/faq/what-is-snort)
- [Uncomplicated Firewall (ufw)](https://wiki.ubuntu.com/UncomplicatedFirewall)

A menudo no tendremos los privilegios para enumerar las configuraciones de estas protecciones, pero saber qué, si alguna, están en su lugar, puede ayudarnos a no perder tiempo en ciertas tareas.

A continuación, podemos echar un vistazo a las unidades y cualquier compartición en el sistema. Primero, podemos usar el comando `lsblk` para enumerar información sobre los dispositivos de bloque en el sistema (discos duros, unidades USB, unidades ópticas, etc.). Si descubrimos y podemos montar una unidad adicional o un sistema de archivos no montado, podríamos encontrar archivos sensibles, contraseñas o copias de seguridad que puedan aprovecharse para escalar privilegios.

```r
lsblk

NAME                      MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT
loop0                       7:0    0   55M  1 loop /snap/core18/1705
loop1                       7:1    0   69M  1 loop /snap/lxd/14804
loop2                       7:2    0   47M  1 loop /snap/snapd/16292
loop3                       7:3    0  103M  1 loop /snap/lxd/23339
loop4                       7:4    0   62M  1 loop /snap/core20/1587
loop5                       7:5    0 55.6M  1 loop /snap/core18/2538
sda                         8:0    0   20G  0 disk 
├─sda1                      8:1    0    1M  0 part 
├─sda2                      8:2    0    1G  0 part /boot
└─sda3                      8:3    0   19G  0 part 
  └─ubuntu--vg-ubuntu--lv 253:0    0   18G  0 lvm  /
sr0                        11:0    1  908M  0 rom 
```

El comando `lpstat` puede usarse para encontrar información sobre cualquier impresora conectada al sistema. Si hay trabajos de impresión activos o en cola, ¿podemos acceder a algún tipo de información sensible?

También deberíamos verificar las unidades montadas y no montadas. ¿Podemos montar una unidad no montada y acceder a datos sensibles? ¿Podemos encontrar algún tipo de credenciales en `fstab` para unidades montadas buscando con grep palabras comunes como password, username, credential, etc. en `/etc/fstab`?

```r
cat /etc/fstab

# /etc/fstab: static file system information.
#
# Use 'blkid' to print the universally unique identifier for a
# device; this may be used with UUID= as a more robust way to name devices
# that works even if disks are added and removed. See fstab(5).
#
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
# / was on /dev/ubuntu-vg/ubuntu-lv during curtin installation
/dev/disk/by-id/dm-uuid-LVM-BdLsBLE4CvzJUgtkugkof4S0dZG7gWR8HCNOlRdLWoXVOba2tYUMzHfFQAP9ajul / ext4 defaults 0 0
# /boot was on /dev/sda2 during curtin installation
/dev/disk/by-uuid/20b1770d-a233-4780-900e-7c99bc974346 /boot ext4 defaults 0 0
```

Consulta la tabla de enrutamiento escribiendo `route` o `netstat -rn`. Aquí podemos ver qué otras redes están disponibles a través de qué interfaz.

```r
route

Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         _gateway        0.0.0.0         UG    0      0        0 ens192
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 ens192
```

En un entorno de dominio, definitivamente querríamos verificar `/etc/resolv.conf` si el host está configurado para usar DNS interno, podríamos usar esto como punto de partida para consultar el entorno de Active Directory.

También querríamos verificar la tabla arp para ver con qué otros hosts ha estado comunicándose el objetivo.

```r
arp -a

_gateway (10.129.0.1) at 00:50:56:b9:b9:fc [ether] on ens192
```

La enumeración del entorno también incluye conocimiento sobre los usuarios que existen en el sistema objetivo. Esto se debe a que los usuarios individuales a menudo se configuran durante

 la instalación de aplicaciones y servicios para limitar los privilegios del servicio. La razón de esto es mantener la seguridad del sistema en sí. Porque si un servicio se ejecuta con los privilegios más altos (`root`) y esto es controlado por un atacante, el atacante automáticamente tiene los derechos más altos sobre todo el sistema. Todos los usuarios en el sistema están almacenados en el archivo `/etc/passwd`. El formato nos da alguna información, como:

1. Username
2. Password
3. User ID (UID)
4. Group ID (GID)
5. User ID info
6. Home directory
7. Shell

### Existing Users

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
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
bjones:x:1001:1001::/home/bjones:/bin/sh
administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
logger:x:1005:1005::/home/logger:/bin/sh
shared:x:1006:1006::/home/shared:/bin/sh
stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
htb-student:x:1008:1008::/home/htb-student:/bin/bash
<SNIP>
```

Ocasionalmente, veremos hashes de contraseñas directamente en el archivo `/etc/passwd`. Este archivo es legible por todos los usuarios y, al igual que con los hashes en el archivo `/etc/shadow`, estos pueden ser sometidos a un ataque de fuerza bruta offline. Esta configuración, aunque no es común, a veces puede verse en dispositivos embebidos y routers.

```r
cat /etc/passwd | cut -f1 -d:

root
daemon
bin
sys

...SNIP...

mrb3n
lxd
bjones
administrator.ilfreight
backupsvc
cliff.moore
logger
shared
stacey.jenkins
htb-student
```

En Linux, se pueden utilizar varios algoritmos de hash diferentes para hacer que las contraseñas sean irreconocibles. Identificarlos a partir de los primeros bloques de hash puede ayudarnos a usarlos y trabajar con ellos más tarde si es necesario. Aquí hay una lista de los más utilizados:

|**Algorithm**|**Hash**|
|---|---|
|Salted MD5|`$1$`...|
|SHA-256|`$5$`...|
|SHA-512|`$6$`...|
|BCrypt|`$2a$`...|
|Scrypt|`$7$`...|
|Argon2|`$argon2i$`...|

También querríamos verificar qué usuarios tienen shells de inicio de sesión. Una vez que veamos qué shells están en el sistema, podemos verificar cada versión en busca de vulnerabilidades. Porque versiones desactualizadas, como Bash versión 4.1, son vulnerables a un exploit `shellshock`.

```r
grep "*sh$" /etc/passwd

root:x:0:0:root:/root:/bin/bash
mrb3n:x:1000:1000:mrb3n:/home/mrb3n:/bin/bash
bjones:x:1001:1001::/home/bjones:/bin/sh
administrator.ilfreight:x:1002:1002::/home/administrator.ilfreight:/bin/sh
backupsvc:x:1003:1003::/home/backupsvc:/bin/sh
cliff.moore:x:1004:1004::/home/cliff.moore:/bin/bash
logger:x:1005:1005::/home/logger:/bin/sh
shared:x:1006:1006::/home/shared:/bin/sh
stacey.jenkins:x:1007:1007::/home/stacey.jenkins:/bin/bash
htb-student:x:1008:1008::/home/htb-student:/bin/bash
```

Cada usuario en los sistemas Linux está asignado a un grupo o grupos específicos y, por lo tanto, recibe privilegios especiales. Por ejemplo, si tenemos una carpeta llamada `dev` solo para desarrolladores, un usuario debe estar asignado al grupo correspondiente para acceder a esa carpeta. La información sobre los grupos disponibles se puede encontrar en el archivo `/etc/group`, que nos muestra tanto el nombre del grupo como los nombres de los usuarios asignados.

### Existing Groups

```r
cat /etc/group

root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,htb-student
tty:x:5:syslog
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:htb-student
floppy:x:25:
tape:x:26:
sudo:x:27:mrb3n,htb-student
audio:x:29:pulse
dip:x:30:htb-student
www-data:x:33:
...SNIP...
```

El archivo `/etc/group` lista todos los grupos en el sistema. Luego, podemos usar el comando [getent](https://man7.org/linux/man-pages/man1/getent.1.html) para listar miembros de cualquier grupo interesante.

```r
getent group sudo

sudo:x:27:mrb3n
```

También podemos verificar qué usuarios tienen una carpeta bajo el directorio `/home`. Querríamos enumerar cada uno de estos para ver si alguno de los usuarios del sistema está almacenando algún dato sensible, archivos que contengan contraseñas. Deberíamos verificar si archivos como `.bash_history` son legibles y contienen algún comando interesante y buscar archivos de configuración. No es raro encontrar archivos que contengan credenciales que puedan aprovecharse para acceder a otros sistemas o incluso ingresar al entorno de Active Directory. También es importante verificar las claves SSH para todos los usuarios, ya que estas podrían usarse para lograr persistencia en el sistema, potencialmente para escalar privilegios o para ayudar con pivoting y port forwarding más hacia la red interna. Al menos, verifica la caché ARP para ver qué otros hosts están siendo accedidos y cruza referencia estos contra cualquier clave SSH privada utilizable.

```r
ls /home

administrator.ilfreight  bjones       htb-student  mrb3n   stacey.jenkins
backupsvc                cliff.moore  logger       shared
```

Finalmente, podemos buscar cualquier "low hanging fruit" como archivos de configuración y otros archivos que puedan contener información sensible. Los archivos de configuración pueden contener una gran cantidad de información. Vale la pena buscar en todos los archivos que terminen en extensiones como .conf y .config, en busca de nombres de usuario, contraseñas y otros secretos.

Si hemos reunido alguna contraseña, deberíamos probarlas en este momento para todos los usuarios presentes en el sistema. La reutilización de contraseñas es común, ¡así que podríamos tener suerte!

En Linux, hay muchos lugares diferentes donde dichos archivos pueden estar almacenados, incluidos los sistemas de archivos montados. Un sistema de archivos montado es un sistema de archivos que está adjunto a un directorio particular en el sistema y se accede a través de ese directorio. Muchos sistemas de archivos, como ext4, NTFS y FAT32, pueden montarse. Cada tipo de sistema de archivos tiene sus propios beneficios y desventajas. Por ejemplo, algunos sistemas de archivos solo pueden ser leídos por el sistema operativo, mientras que otros pueden ser leídos y escritos por el usuario. Los sistemas de archivos que pueden ser leídos y escritos por el usuario se llaman sistemas de archivos de lectura/escritura. Montar un sistema de archivos permite al usuario acceder a los archivos y carpetas almacenados en ese sistema de archivos. Para montar un sistema de archivos, el usuario debe tener privilegios de root. Una vez montado un sistema de archivos, puede ser desmontado por el usuario con privilegios de root. Podríamos tener acceso a dichos sistemas de archivos y encontrar información sensible, documentación o aplicaciones allí.

### Mounted File Systems

```r
df -h

Filesystem      Size  Used Avail Use% Mounted on
udev            1,9G     0  1,9G   0% /dev
tmpfs           389M  1,8M  388M   1% /run
/dev/sda5        20G  7,9G   11G  44% /
tmpfs           1,9G     0  1,9G   0% /dev/shm
tmpfs           5,0M  4,0K  5,0M   1% /run/lock
tmpfs           1,9G     0  1,9G   0% /sys/fs/cgroup
/dev/loop0      128K  128K     0 100% /snap/bare/5
/dev/loop1       62M   62M     0 100% /snap/core20/1611
/dev/loop2       92M   92M     0 100% /snap/gtk-common-themes/1535
/dev/loop4       55M   55M     0 100% /snap/snap-store/558
/dev/loop3      347M  347M     0 100% /snap/gnome-3-38-2004/115
/dev/loop5       47M   47M     0 100% /snap/snapd/16292
/dev/sda1       511M  4,0K  511M   1% /boot/efi
tmpfs           389M   24K  389M   1% /run/user/1000
/dev/sr0        3,6G  3,6G     0 100% /media/htb-student/Ubuntu 20.04.5 LTS amd64
/dev/loop6       50M   50M     0 100% /snap/snapd/17576
/dev/loop7       64M   64M     0 100% /snap/core20/1695
/dev/loop8       46M   46M     0 100% /snap/snap-store/599
/dev/loop9      347M  347M     0 100% /snap/gnome-3-38-2004/119
```

Cuando un sistema de archivos se desmonta, ya no es accesible por el sistema. Esto puede hacerse por varias razones, como cuando se retira un disco, o un sistema de archivos ya no es necesario. Otra razón puede ser que archivos, scripts, documentos y otra información importante no deben montarse y visualizarse por un usuario estándar. Por lo tanto, si podemos extender nuestros privilegios al usuario `root`, podríamos montar y leer estos sistemas de archivos nosotros mismos. Los sistemas de archivos desmontados pueden verse de la siguiente manera:

### Unmounted File Systems

```r
cat /etc/fstab | grep -v "#" | column -t

UUID=5bf16727-fcdf-4205-906c-0620aa4a058f  /          ext4  errors=remount-ro  0  1
UUID=BE56-AAE0                             /boot/efi  vfat  umask=0077         0  1
/swapfile                                  none       swap  sw                 0  0
```

Muchos archivos y carpetas se mantienen ocultos en un sistema Linux para que no sean obvios y se evite la edición accidental. Hay muchas más razones además de las mencionadas hasta ahora para mantener dichos archivos y carpetas ocultos. Sin embargo, necesitamos poder localizar todos los archivos y carpetas ocultos porque a menudo pueden contener información sensible, incluso si solo tenemos permisos de lectura.

### All Hidden Files

```r
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student

-rw-r--r-- 1 htb-student htb-student 3771 Nov 27 11:16 /home/htb-student/.bashrc
-rw-rw-r-- 1 htb-student htb-student 180 Nov 27 11:36 /home/htb-student/.wget-hsts
-rw------- 1 htb-student htb-student 387 Nov 27 14:02 /home/htb-student/.bash_history
-rw-r--r-- 1 htb-student htb-student 807 Nov 27 11:16 /home/htb-student/.profile
-rw-r--r-- 1 htb-student htb-student 0 Nov 27 11:31 /home/htb-student/.sudo_as_admin_successful
-rw-r--r-- 1 htb-student htb-student 220 Nov 27 11:16 /home/htb-student/.bash_logout
-rw-rw-r-- 1 htb-student htb-student 162 Nov 28 13:26 /home/htb-student/.notes
```

### All Hidden Directories

```r
find / -type d -name ".*" -ls 2>/dev/null

   684822      4 drwx------   3 htb-student htb-student     4096 Nov 28 12:32 /home/htb-student/.gnupg
   790793      4 drwx------   2 htb-student htb-student     4096 Okt 27 11:31 /home/htb-student/.ssh
   684804      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.cache
   790827      4 drwxrwxr-x   8 htb-student htb-student     4096 Okt 27 11:32 /home/htb-student/CVE-2021-3156/.git
   684796      4 drwx------  10 htb-student htb-student     4096 Okt 27 11:30 /home/htb-student/.config
   655426      4 drwxr-xr-x   3 htb-student htb-student     4096 Okt 27 11:19 /home/htb-student/.local
   524808      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.cache
   544027      4 drwxr-xr-x   7 gdm         gdm             4096 Okt 27 11:19 /var/lib/gdm3/.config
   544028      4 drwxr-xr-x   3 gdm         gdm             4096 Aug 31 08:54 /var/lib/gdm3/.local
   524938      4 drwx------   2 colord      colord          4096 Okt 27 11:19 /var/lib/colord/.cache
     1408      2 dr-xr-xr-x   1 htb-student htb-student     2048 Aug 31 09:17 /media/htb-student/Ubuntu\ 20.04.5\ LTS\ amd64/.disk
   280101      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.font-unix
   262364      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.ICE-unix
   262362      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:32 /tmp/.X11-unix
   280103      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.Test-unix
   262830      4 drwxrwxrwt   2 root        root            4096 Nov 28 12:31 /tmp/.XIM-unix
   661820      4 drwxr-xr-x   5 root        root            4096 Aug 31 08:55 /usr/lib/modules/5.15.0-46-generic/vdso/.build-id
   666709      4 drwxr-xr-x   5 root        root            4096 Okt 27 11:18 /usr/lib/modules/5.15.0-52-generic/vdso/.build-id
   657527      4 drwxr-xr-x 170 root        root            4096 Aug 31 08:55 /usr/lib/debug/.build-id
```

Además, hay tres carpetas predeterminadas destinadas a archivos temporales. Estas carpetas son visibles para todos los usuarios y pueden leerse. Además, se pueden encontrar logs temporales o salida de scripts. Tanto `/tmp` como `/var/tmp` se utilizan para almacenar datos temporalmente. Sin embargo, la diferencia clave es cuánto tiempo se almacenan los datos en estos sistemas de archivos. El tiempo de retención de datos para `/var/tmp` es mucho más largo que el del directorio `/tmp`. Por defecto, todos los archivos y datos almacenados en /var/tmp se retienen hasta por 30 días. En /tmp, en cambio, los datos se eliminan automáticamente después de diez días.

Además, todos los archivos temporales almacenados en el directorio `/tmp` se eliminan inmediatamente cuando el sistema se reinicia. Por lo tanto, el directorio `/var/tmp` es utilizado por programas para almacenar datos que deben mantenerse temporalmente entre reinicios.

### Temporary Files

```r
ls -l /tmp /var/tmp /dev/shm

/dev/shm:
total 0

/tmp:
total 52
-rw------- 1 htb-student htb-student    0 Nov 28 12:32 config-err-v8LfEU
drwx------ 3 root        root        4096 Nov 28 12:37 snap.snap-store
drwx------ 2 htb-student htb-student 4096 Nov 28 12:32 ssh-OKlLKjlc98xh
<SNIP>
drwx------ 2 htb-student htb-student 4096 Nov 28 12:37 tracker-extract-files.1000
drwx------ 2 gdm         gdm         4096 Nov 28 12:31 tracker-extract-files.125

/var/tmp:
total 28
drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-colord.service-RrPcyi
drwx------ 3 root root 4096 Nov 28 12:31 systemd-private-7b455e62ec09484b87eff41023c4ca53-ModemManager.service-4Rej9e
...SNIP...
```

---

## Moving On

Hemos obtenido una visión inicial del entorno y (con suerte) algunos puntos de datos sensibles o útiles que pueden ayudarnos a escalar privilegios o incluso a movernos lateralmente en la red interna. A continuación, enfocaremos nuestra atención en los permisos y verificaremos qué directorios, scripts, binarios, etc. podemos leer y escribir con los privilegios de nuestro usuario actual.

Aunque nos estamos enfocando en la enumeración manual en este módulo, vale la pena ejecutar el script [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) en este punto en una evaluación del mundo real para tener la mayor cantidad de datos posible para examinar. A menudo podemos encontrar una victoria fácil, pero tener esta salida a mano puede a veces descubrir problemas matizados que nuestra enumeración manual pasó por alto. Sin embargo, deberíamos practicar nuestra enumeración manual tanto como sea posible y crear (y seguir añadiendo a) nuestra propia cheat sheet de comandos clave (y alternativas para diferentes sistemas operativos Linux). Empezaremos a desarrollar nuestro propio estilo, preferencia de comandos, e incluso ver algunas áreas que podemos comenzar a scriptar por nosotros mismos. Las herramientas son excelentes y tienen su lugar, pero donde muchas fallan es en poder realizar una tarea determinada cuando una herramienta falla o no podemos introducirla en el sistema.