Al final de la última sección, establecimos una sesión shell con el objetivo. Inicialmente, nuestra shell estaba limitada (a veces llamada jail shell), por lo que usamos Python para generar una TTY bourne shell que nos dio acceso a más comandos y un prompt desde el cual trabajar. Esta será probablemente una situación que encontraremos más y más mientras practicamos en Hack The Box y en el mundo real en compromisos.

Puede haber ocasiones en las que aterricemos en un sistema con una shell limitada y Python no esté instalado. En estos casos, es bueno saber que podríamos usar varios métodos diferentes para generar una shell interactiva. Vamos a examinar algunos de ellos.

Sabe que siempre que veamos `/bin/sh` o `/bin/bash`, esto también podría reemplazarse con el binario asociado con el lenguaje intérprete de shell presente en ese sistema. Con la mayoría de los sistemas Linux, es probable que nos encontremos con `bourne shell` (`/bin/sh`) y `bourne again shell` (`/bin/bash`) presentes en el sistema de forma nativa.

---

## /bin/sh -i

Este comando ejecutará el intérprete de comandos especificado en la ruta en modo interactivo (`-i`).

### Interactive

```r
/bin/sh -i
sh: no job control in this shell
sh-4.2$
```

---

## Perl

Si el lenguaje de programación [Perl](https://www.perl.org/) está presente en el sistema, estos comandos ejecutarán el intérprete de comandos especificado.

### Perl To Shell

```r
perl —e 'exec "/bin/sh";'
```

```r
perl: exec "/bin/sh";
```

El comando directamente arriba debe ejecutarse desde un script.

---

## Ruby

Si el lenguaje de programación [Ruby](https://www.ruby-lang.org/en/) está presente en el sistema, este comando ejecutará el intérprete de comandos especificado:

### Ruby To Shell

```r
ruby: exec "/bin/sh"
```

El comando directamente arriba debe ejecutarse desde un script.

---

## Lua

Si el lenguaje de programación [Lua](https://www.lua.org/) está presente en el sistema, podemos usar el método `os.execute` para ejecutar el intérprete de comandos especificado usando el comando completo a continuación:

### Lua To Shell

```r
lua: os.execute('/bin/sh')
```

El comando directamente arriba debe ejecutarse desde un script.

---

## AWK

[AWK](https://man7.org/linux/man-pages/man1/awk.1p.html) es un lenguaje de procesamiento y escaneo de patrones similar a C presente en la mayoría de los sistemas basados en UNIX/Linux, ampliamente utilizado por desarrolladores y administradores de sistemas para generar informes. También se puede usar para generar una shell interactiva. Esto se muestra en el script corto de awk a continuación:

### AWK To Shell

```r
awk 'BEGIN {system("/bin/sh")}'
```

---

## Find

[Find](https://man7.org/linux/man-pages/man1/find.1.html) es un comando presente en la mayoría de los sistemas Unix/Linux, ampliamente utilizado para buscar archivos y directorios utilizando varios criterios. También se puede usar para ejecutar aplicaciones e invocar un intérprete de comandos.

### Using Find For A Shell

```r
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

Este uso del comando find está buscando cualquier archivo listado después de la opción `-name`, luego ejecuta `awk` (`/bin/awk`) y ejecuta el mismo script que discutimos en la sección awk para ejecutar un intérprete de comandos.

---

## Using Exec To Launch A Shell

```r
find . -exec /bin/sh \; -quit
```

Este uso del comando find usa la opción de ejecución (`-exec`) para iniciar directamente el intérprete de comandos. Si `find` no puede encontrar el archivo especificado, entonces no se obtendrá ninguna shell.

---

## VIM

Sí, podemos configurar el lenguaje intérprete de comandos desde dentro del popular editor de texto basado en línea de comandos `VIM`. Esta es una situación muy específica en la que nos encontraríamos necesitando usar este método, pero es bueno saberlo por si acaso.

### Vim To Shell

```r
vim -c ':!/bin/sh'
```

### Vim Escape

```r
vim
:set shell=/bin/sh
:shell
```

---

## Execution Permissions Considerations

Además de conocer todas las opciones mencionadas anteriormente, debemos tener en cuenta los permisos que tenemos con la cuenta de la sesión shell. Siempre podemos intentar ejecutar este comando para listar las propiedades y permisos del archivo que nuestra cuenta tiene sobre cualquier archivo o binario dado:

### Permissions

```r
ls -la <path/to/fileorbinary>
```

También podemos intentar ejecutar este comando para verificar qué permisos de `sudo` tiene la cuenta en la que aterrizamos:

### Sudo -l

```r
sudo -l
Matching Defaults entries for apache on ILF-WebSrv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User apache may run the following commands on ILF-WebSrv:
    (ALL : ALL) NOPASSWD: ALL
```

El comando sudo -l arriba necesitará una shell interactiva estable para ejecutarse. Si no estás en una shell completa o en una shell inestable, es posible que no obtengas ningún retorno de ella. No solo considerar los permisos nos permitirá ver qué comandos podemos ejecutar, sino que también puede comenzar a darnos una idea de los vectores potenciales que nos permitirán escalar privilegios.