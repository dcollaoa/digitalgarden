El uso de la encriptación de archivos a menudo sigue siendo insuficiente en asuntos `privados` y `empresariales`. Incluso hoy en día, los correos electrónicos que contienen solicitudes de empleo, extractos de cuentas o contratos a menudo se envían sin cifrar. Esto es extremadamente negligente y, en muchos casos, incluso punible por la ley. Por ejemplo, el GDPR exige el requisito de almacenamiento y transmisión cifrados de datos personales en la Unión Europea. Especialmente en casos empresariales, esto es bastante diferente para los correos electrónicos. Hoy en día, es bastante común comunicar temas `confidenciales` o enviar datos `sensibles` `por correo electrónico`. Sin embargo, los correos electrónicos no son mucho más seguros que las postales, que pueden ser interceptadas si el atacante está bien posicionado.

Cada vez más empresas están aumentando sus precauciones e infraestructura de seguridad informática a través de cursos de capacitación y seminarios de concienciación sobre seguridad. Como resultado, se está volviendo cada vez más común que los empleados de la empresa cifren/encoden archivos sensibles. No obstante, incluso estos pueden ser descifrados y leídos con la elección correcta de listas y herramientas. En muchos casos, se utiliza `symmetric encryption` como `AES-256` para almacenar de forma segura archivos o carpetas individuales. Aquí, se utiliza la `same key` para cifrar y descifrar un archivo.

Por lo tanto, para el envío de archivos, se utiliza `asymmetric encryption`, en la cual se requieren `dos claves separadas`. El remitente cifra el archivo con la `public key` del destinatario. El destinatario, a su vez, puede descifrar el archivo utilizando una `private key`.

---

## Hunting for Encoded Files

Muchas extensiones de archivo diferentes pueden identificar estos tipos de archivos cifrados/encodificados. Por ejemplo, se puede encontrar una lista útil en [FileInfo](https://fileinfo.com/filetypes/encoded). Sin embargo, para nuestro ejemplo, solo veremos los archivos más comunes como los siguientes:

### Hunting for Files

```r
cry0l1t3@unixclient:~$ for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

File extension:  .xls

File extension:  .xls*

File extension:  .xltx

File extension:  .csv
/home/cry0l1t3/Docs/client-emails.csv
/home/cry0l1t3/ruby-2.7.3/gems/test-unit-3.3.4/test/fixtures/header-label.csv
/home/cry0l1t3/ruby-2.7.3/gems/test-unit-3.3.4/test/fixtures/header.csv
/home/cry0l1t3/ruby-2.7.3/gems/test-unit-3.3.4/test/fixtures/no-header.csv
/home/cry0l1t3/ruby-2.7.3/gems/test-unit-3.3.4/test/fixtures/plus.csv
/home/cry0l1t3/ruby-2.7.3/test/win32ole/orig_data.csv

File extension:  .od*
/home/cry0l1t3/Docs/document-temp.odt
/home/cry0l1t3/Docs/product-improvements.odp
/home/cry0l1t3/Docs/mgmt-spreadsheet.ods
...SNIP...
```

Si encontramos extensiones de archivo en el sistema con las que no estamos familiarizados, podemos usar los motores de búsqueda que conocemos para averiguar la tecnología detrás de ellos. Después de todo, hay cientos de diferentes extensiones de archivo y no se espera que alguien las conozca todas de memoria. Sin embargo, primero debemos saber cómo encontrar la información relevante que nos ayudará. Nuevamente, podemos usar los pasos que ya cubrimos en las secciones de `Credential Hunting` o repetirlos para encontrar claves SSH en el sistema.

### Hunting for SSH Keys

```r
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"

/home/cry0l1t3/.ssh/internal_db:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/cry0l1t3/.ssh/SSH.private:1:-----BEGIN OPENSSH PRIVATE KEY-----
/home/cry0l1t3/Mgmt/ceil.key:1:-----BEGIN OPENSSH PRIVATE KEY-----
```

La mayoría de las claves SSH que encontraremos hoy en día están cifradas. Podemos reconocer esto por el encabezado de la clave SSH, ya que esto muestra el método de cifrado en uso.

### Encrypted SSH Keys

```r
cry0l1t3@unixclient:~$ cat /home/cry0l1t3/.ssh/SSH.private

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2109D25CC91F8DBFCEB0F7589066B2CC

8Uboy0afrTahejVGmB7kgvxkqJLOczb1I0/hEzPU1leCqhCKBlxYldM2s65jhflD
4/OH4ENhU7qpJ62KlrnZhFX8UwYBmebNDvG12oE7i21hB/9UqZmmHktjD3+OYTsD
...SNIP...
```

Si vemos un encabezado como este en una clave SSH, en la mayoría de los casos no podremos usarla inmediatamente sin una acción adicional. Esto se debe a que las claves SSH cifradas están protegidas con una frase de contraseña que debe ingresarse antes de su uso. Sin embargo, muchos a menudo son descuidados en la selección de la contraseña y su complejidad porque SSH se considera un protocolo seguro, y muchos no saben que incluso `AES-128-CBC` puede ser descifrado.

---

## Cracking with John

`John The Ripper` tiene muchos scripts diferentes para generar hashes a partir de archivos que luego podemos usar para descifrar. Podemos encontrar estos scripts en nuestro sistema utilizando el siguiente comando.

### John Hashing Scripts

```r
locate *2john*

/usr/bin/bitlocker2john
/usr/bin/dmg2john
/usr/bin/gpg2john
/usr/bin/hccap2john
/usr/bin/keepass2john
/usr/bin/putty2john
/usr/bin/racf2john
/usr/bin/rar2john
/usr/bin/uaf2john
/usr/bin/vncpcap2john
/usr/bin/wlanhcx2john
/usr/bin/wpapcap2john
/usr/bin/zip2john
/usr/share/john/1password2john.py
/usr/share/john/7z2john.pl
/usr/share/john/DPAPImk2john.py
/usr/share/john/adxcsouf2john.py
/usr/share/john/aem2john.py
/usr/share/john/aix2john.pl
/usr/share/john/aix2john.py
/usr/share/john/andotp2john.py
/usr/share/john/androidbackup2john.py
...SNIP...
```

Podemos convertir muchos formatos diferentes en hashes individuales e intentar descifrar las contraseñas con esto. Luego, podemos abrir, leer y usar el archivo si tenemos éxito. Hay un script de Python llamado `ssh2john.py` para claves SSH, que genera los hashes correspondientes para claves SSH cifradas, que luego podemos almacenar en archivos.

```r
ssh2john.py SSH.private > ssh.hash
cat ssh.hash 

ssh.private:$sshng$0$8$1C258238FD2D6EB0$2352$f7b...SNIP...
```

Luego, debemos personalizar los comandos de acuerdo con la lista de contraseñas y especificar nuestro archivo con los hashes como el objetivo a descifrar. Después de eso, podemos mostrar los hashes descifrados especificando el archivo hash y usando la opción `--show`.

### Cracking SSH Keys

```r
john --wordlist=rockyou.txt ssh.hash

Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
1234         (SSH.private)
1g 0:00:00:00 DONE (2022-02-08 03:03) 16.66g/s 1747Kp/s 1747Kc/s 1747KC/s Knightsing..Babying
Session completed
```

```r
john ssh.hash --show

SSH.private:1234

1 password hash cracked, 0 left
```

---

## Cracking Documents

En el transcurso de nuestra carrera, nos encontraremos con muchos documentos diferentes,

 que también están protegidos por contraseña para evitar el acceso de personas no autorizadas. Hoy en día, la mayoría de las personas utilizan archivos Office y PDF para intercambiar información y datos comerciales.

Casi todos los informes, documentación y hojas de información se pueden encontrar en forma de DOCs de Office y PDFs. Esto se debe a que ofrecen la mejor representación visual de la información. John proporciona un script de Python llamado `office2john.py` para extraer hashes de todos los documentos de Office comunes que luego se pueden alimentar en John o Hashcat para el descifrado fuera de línea. El procedimiento para descifrarlos sigue siendo el mismo.

### Cracking Microsoft Office Documents

```r
office2john.py Protected.docx > protected-docx.hash
cat protected-docx.hash

Protected.docx:$office$*2007*20*128*16*7240...SNIP...8a69cf1*98242f4da37d916305d8e2821360773b7edc481b
```

```r
john --wordlist=rockyou.txt protected-docx.hash

Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2007 for all loaded hashes
Cost 2 (iteration count) is 50000 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1234             (Protected.docx)
1g 0:00:00:00 DONE (2022-02-08 01:25) 2.083g/s 2266p/s 2266c/s 2266C/s trisha..heart
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```r
john protected-docx.hash --show

Protected.docx:1234
```

### Cracking PDFs

```r
pdf2john.py PDF.pdf > pdf.hash
cat pdf.hash 

PDF.pdf:$pdf$2*3*128*-1028*1*16*7e88...SNIP...bd2*32*a72092...SNIP...0000*32*c48f001fdc79a030d718df5dbbdaad81d1f6fedec4a7b5cd980d64139edfcb7e
```

```r
john --wordlist=rockyou.txt pdf.hash

Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 3 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1234             (PDF.pdf)
1g 0:00:00:00 DONE (2022-02-08 02:16) 25.00g/s 27200p/s 27200c/s 27200C/s bulldogs..heart
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed
```

```r
john pdf.hash --show

PDF.pdf:1234

1 password hash cracked, 0 left
```

Una de las principales dificultades en este proceso es la generación y mutación de listas de contraseñas. Esto es un requisito previo para descifrar con éxito las contraseñas de todos los archivos y puntos de acceso protegidos por contraseña. Esto se debe a que, en la mayoría de los casos, ya no es suficiente usar una lista de contraseñas conocida, ya que estas son conocidas por los sistemas y a menudo son reconocidas y bloqueadas por los mecanismos de seguridad integrados. Este tipo de archivos puede ser más difícil de descifrar (o no descifrable en un tiempo razonable) porque los usuarios pueden verse obligados a seleccionar una contraseña más larga, generada aleatoriamente o una frase de contraseña. Sin embargo, siempre vale la pena intentar descifrar documentos protegidos por contraseña, ya que pueden contener datos sensibles que podrían ser útiles para ampliar nuestro acceso.