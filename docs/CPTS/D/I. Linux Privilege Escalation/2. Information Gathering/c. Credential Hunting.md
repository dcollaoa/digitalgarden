Cuando estás enumerando un sistema, es importante anotar cualquier credential. Estas pueden encontrarse en archivos de configuración (`.conf`, `.config`, `.xml`, etc.), shell scripts, el archivo de historial de bash de un usuario, archivos de respaldo (`.bak`), dentro de archivos de base de datos o incluso en archivos de texto. Las credentials pueden ser útiles para escalar a otros usuarios o incluso root, acceder a bases de datos y otros sistemas dentro del entorno.

El directorio /var típicamente contiene el web root para cualquier servidor web que esté ejecutándose en el host. El web root puede contener database credentials u otros tipos de credentials que pueden aprovecharse para obtener más acceso. Un ejemplo común es encontrar MySQL database credentials dentro de archivos de configuración de WordPress:

```r
htb_student@NIX02:~$ cat wp-config.php | grep 'DB_USER\|DB_PASSWORD'

define( 'DB_USER', 'wordpressuser' );
define( 'DB_PASSWORD', 'WPadmin123!' );
```

Los directorios de spool o mail, si son accesibles, también pueden contener información valiosa o incluso credentials. Es común encontrar credentials almacenadas en archivos en el web root (por ejemplo, MySQL connection strings, archivos de configuración de WordPress).

```r
htb_student@NIX02:~$  find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/python3/debian_config
/etc/kbd/config
/etc/manpath.config
/boot/config-4.4.0-116-generic
/boot/grub/i386-pc/configfile.mod
/sys/devices/pci0000:00/0000:00:00.0/config
/sys/devices/pci0000:00/0000:00:01.0/config
<SNIP>
```

---

## SSH Keys

También es útil buscar en el sistema claves privadas de SSH accesibles. Podemos localizar una clave privada de otro usuario con más privilegios que podemos usar para conectarnos de nuevo a la máquina con privilegios adicionales. A veces también podemos encontrar SSH keys que pueden usarse para acceder a otros hosts en el entorno. Siempre que encuentres SSH keys, revisa el archivo `known_hosts` para encontrar objetivos. Este archivo contiene una lista de public keys de todos los hosts a los que el usuario se ha conectado en el pasado y puede ser útil para movimiento lateral o para encontrar datos en un host remoto que se puedan usar para realizar privilege escalation en nuestro objetivo.

```r
htb_student@NIX02:~$  ls ~/.ssh

id_rsa  id_rsa.pub  known_hosts
```