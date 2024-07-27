## HTTP/S

La transferencia web es la forma más común en que la mayoría de las personas transfieren archivos porque `HTTP`/`HTTPS` son los protocolos más comunes permitidos a través de los firewalls. Otro gran beneficio es que, en muchos casos, el archivo estará encriptado en tránsito. No hay nada peor que estar en una prueba de penetración, y el IDS de la red del cliente detecta un archivo sensible siendo transferido en texto plano y nos preguntan por qué enviamos una contraseña a nuestro servidor en la nube sin usar encriptación.

Ya hemos discutido el uso del módulo de Python3 [uploadserver](https://github.com/Densaugeo/uploadserver) para configurar un servidor web con capacidades de carga, pero también podemos usar Apache o Nginx. Esta sección cubrirá la creación de un servidor web seguro para operaciones de carga de archivos.

---

## Nginx - Enabling PUT

Una buena alternativa para transferir archivos a `Apache` es [Nginx](https://www.nginx.com/resources/wiki/) porque la configuración es menos complicada, y el sistema de módulos no lleva a problemas de seguridad como puede hacerlo `Apache`.

Al permitir cargas `HTTP`, es crucial estar 100% seguros de que los usuarios no puedan cargar web shells y ejecutarlos. `Apache` facilita mucho esto, ya que el módulo `PHP` ejecuta cualquier cosa que termine en `PHP`. Configurar `Nginx` para usar PHP no es tan simple.

### Crear un Directorio para Manejar Archivos Cargados

```r
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```

### Cambiar el Propietario a www-data

```r
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

### Crear Archivo de Configuración de Nginx

Crea el archivo de configuración de Nginx creando el archivo `/etc/nginx/sites-available/upload.conf` con el contenido:

```r
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

### Crear Symlink de Nuestro Sitio al Directorio sites-enabled

```r
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

### Iniciar Nginx

```r
sudo systemctl restart nginx.service
```

Si obtenemos mensajes de error, revisa `/var/log/nginx/error.log`. Si usas Pwnbox, veremos que el puerto 80 ya está en uso.

### Verificando Errores

```r
tail -2 /var/log/nginx/error.log

2020/11/17 16:11:56 [emerg] 5679#5679: bind() to 0.0.0.0:`80` failed (98: A`ddress already in use`)
2020/11/17 16:11:56 [emerg] 5679#5679: still could not bind()
```

```r
ss -lnpt | grep 80

LISTEN 0      100          0.0.0.0:80        0.0.0.0:*    users:(("python",pid=`2811`,fd=3),("python",pid=2070,fd=3),("python",pid=1968,fd=3),("python",pid=1856,fd=3))
```

```r
ps -ef | grep 2811

user65      2811    1856  0 16:05 ?        00:00:04 `python -m websockify 80 localhost:5901 -D`
root        6720    2226  0 16:14 pts/0    00:00:00 grep --color=auto 2811
```

Vemos que ya hay un módulo escuchando en el puerto 80. Para solucionar esto, podemos eliminar la configuración predeterminada de Nginx, que se enlaza en el puerto 80.

### Eliminar la Configuración Predeterminada de Nginx

```r
sudo rm /etc/nginx/sites-enabled/default
```

Ahora podemos probar la carga usando `cURL` para enviar una solicitud `PUT`. En el siguiente ejemplo, subiremos el archivo `/etc/passwd` al servidor y lo llamaremos users.txt.

### Subir Archivo Usando cURL

```r
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```

```r
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 

user65:x:1000:1000:,,,:/home/user65:/bin/bash
```

Una vez que esto funcione, una buena prueba es asegurarse de que la lista de directorios no esté habilitada navegando a `http://localhost/SecretUploadDirectory`. Por defecto, con `Apache`, si accedemos a un directorio sin un archivo de índice (index.html), listará todos los archivos. Esto es malo para nuestro caso de uso de exfiltración de archivos porque la mayoría de los archivos son de naturaleza sensible, y queremos hacer todo lo posible para ocultarlos. Gracias a `Nginx` siendo minimalista, características como esa no están habilitadas por defecto.

---

## Using Built-in Tools

En la próxima sección, introduciremos el tema de "Living off the Land" o el uso de utilidades integradas de Windows y Linux para realizar actividades de transferencia de archivos. Volveremos a este concepto repetidamente a lo largo de los módulos en el Penetration Tester path cuando cubramos tareas como escalada de privilegios en Windows y Linux y enumeración y explotación de Active Directory.