[John the Ripper](https://github.com/openwall/john) (`JTR` o `john`) es una herramienta esencial de pentesting utilizada para comprobar la fortaleza de las contraseñas y descifrar contraseñas cifradas (o en hash) utilizando ataques de fuerza bruta o ataques de diccionario. Es un software de código abierto desarrollado inicialmente para sistemas basados en UNIX y lanzado por primera vez en 1996. Se ha convertido en un pilar para los profesionales de la seguridad debido a sus diversas capacidades. Se recomienda la variante "Jumbo" para aquellos en el campo de la seguridad, ya que tiene optimizaciones de rendimiento y características adicionales, como listas de palabras multilingües y soporte para arquitecturas de 64 bits. Esta versión es más efectiva para descifrar contraseñas con mayor precisión y rapidez.

Con esto, podemos utilizar diversas herramientas para convertir diferentes tipos de archivos y hashes en un formato que sea utilizable por John. Además, el software se actualiza regularmente para mantenerse al día con las tendencias y tecnologías de seguridad actuales, asegurando la seguridad del usuario.

---

## Encryption Technologies

|**Encryption Technology**|**Description**|
|---|---|
|`UNIX crypt(3)`|Crypt(3) es un sistema de cifrado UNIX tradicional con una clave de 56 bits.|
|`Traditional DES-based`|El cifrado basado en DES utiliza el algoritmo Data Encryption Standard para cifrar datos.|
|`bigcrypt`|Bigcrypt es una extensión del cifrado tradicional basado en DES. Utiliza una clave de 128 bits.|
|`BSDI extended DES-based`|El cifrado basado en DES extendido de BSDI es una extensión del cifrado tradicional basado en DES y utiliza una clave de 168 bits.|
|`FreeBSD MD5-based` (Linux & Cisco)|El cifrado basado en MD5 de FreeBSD utiliza el algoritmo MD5 para cifrar datos con una clave de 128 bits.|
|`OpenBSD Blowfish-based`|El cifrado basado en Blowfish de OpenBSD utiliza el algoritmo Blowfish para cifrar datos con una clave de 448 bits.|
|`Kerberos/AFS`|Kerberos y AFS son sistemas de autenticación que utilizan cifrado para asegurar la comunicación entre entidades.|
|`Windows LM`|El cifrado Windows LM utiliza el algoritmo Data Encryption Standard para cifrar datos con una clave de 56 bits.|
|`DES-based tripcodes`|Los tripcodes basados en DES se utilizan para autenticar usuarios basándose en el algoritmo Data Encryption Standard.|
|`SHA-crypt hashes`|Los hashes SHA-crypt se utilizan para cifrar datos con una clave de 256 bits y están disponibles en versiones más recientes de Fedora y Ubuntu.|
|`SHA-crypt` y `SUNMD5 hashes` (Solaris)|Los hashes SHA-crypt y SUNMD5 utilizan los algoritmos SHA-crypt y MD5 para cifrar datos con una clave de 256 bits y están disponibles en Solaris.|
|`...`|y muchos más.|

---

## Attack Methods

### Dictionary Attacks

Los ataques de diccionario implican el uso de una lista pre-generada de palabras y frases (conocida como diccionario) para intentar descifrar una contraseña. Esta lista de palabras y frases a menudo se adquiere de diversas fuentes, como diccionarios públicos disponibles, contraseñas filtradas o incluso compradas a empresas especializadas. El diccionario se utiliza para generar una serie de cadenas que luego se comparan con las contraseñas en hash. Si se encuentra una coincidencia, la contraseña se descifra, proporcionando acceso al atacante al sistema y los datos almacenados en él. Este tipo de ataque es altamente efectivo. Por lo tanto, es esencial tomar las medidas necesarias para asegurar que las contraseñas se mantengan seguras, como utilizar contraseñas complejas y únicas, cambiarlas regularmente y utilizar autenticación de dos factores.

### Brute Force Attacks

Los ataques de fuerza bruta implican intentar cada combinación posible de caracteres que podría formar una contraseña. Este es un proceso extremadamente lento, y usar este método generalmente solo es aconsejable si no hay otras alternativas. También es importante notar que cuanto más larga y compleja sea la contraseña, más difícil será descifrarla y más tiempo tomará agotar todas las combinaciones. Por esta razón, se recomienda encarecidamente que las contraseñas tengan al menos 8 caracteres de longitud, con una combinación de letras, números y símbolos.

### Rainbow Table Attacks

Los ataques de tabla arcoíris implican el uso de una tabla precomputada de hashes y sus correspondientes contraseñas en texto plano, lo cual es un método mucho más rápido que un ataque de fuerza bruta. Sin embargo, este método está limitado por el tamaño de la tabla arcoíris: cuanto más grande sea la tabla, más contraseñas y hashes podrá almacenar. Además, debido a la naturaleza del ataque, es imposible utilizar tablas arcoíris para determinar el texto plano de hashes no incluidos ya en la tabla. Como resultado, los ataques de tabla arcoíris solo son efectivos contra hashes ya presentes en la tabla, lo que hace que cuanto más grande sea la tabla, más exitoso sea el ataque.

---

## Cracking Modes

`Single Crack Mode` es uno de los modos más comunes de John utilizados al intentar descifrar contraseñas utilizando una sola lista de contraseñas. Es un ataque de fuerza bruta, lo que significa que se prueban todas las contraseñas en la lista, una por una, hasta encontrar la correcta. Este método es el más básico y directo para descifrar contraseñas y, por lo tanto, es una opción popular para aquellos que desean acceder a un sistema seguro. Sin embargo, está lejos de ser el método más eficiente, ya que puede tomar un tiempo indefinido descifrar una contraseña, dependiendo de la longitud y complejidad de la contraseña en cuestión. La sintaxis básica para el comando es:

### Single Crack Mode

```r
john --format=<hash_type> <hash or hash_file>
```

Por ejemplo, si tenemos un archivo llamado `hashes_to_crack.txt` que contiene hashes `SHA-256`, el comando para descifrarlos sería:

```r
john --format=sha256 hashes_to_crack.txt
```

- `john` es el comando para ejecutar el programa John the Ripper
- `--format=sha256` especifica que el formato de hash es SHA-256
- `hashes.txt` es el nombre del archivo que contiene los hashes a descifrar

Cuando ejecutamos el comando, John leerá los hashes del archivo especificado y luego intentará descifrarlos comparándolos con las palabras en su lista de palabras incorporada y cualquier lista de palabras adicional especificada con la opción `--wordlist`. Además, utilizará cualquier regla establecida con la opción `--rules` (si se dan reglas) para generar más contraseñas candidatas.

El proceso de descifrar las contraseñas puede ser `muy lento`, ya que la cantidad de tiempo necesario para descifrar una contraseña depende de múltiples factores, como la complejidad de la contraseña, la configuración de la máquina y el tamaño de la lista de palabras. Descifrar contraseñas es casi una cuestión de suerte. Porque la contraseña en sí puede ser muy simple, pero si usamos una lista incorrecta donde la palabra no está presente o no puede ser generada por John, eventualmente fallaremos en descifrar la contraseña.

John enviará las contraseñas descifradas a la consola y al archivo "john.pot" (`~/.john/john.pot`) en el directorio home del usuario actual. Además, continuará descifrando los hashes restantes en segundo plano, y podemos verificar el progreso ejecutando el comando `john --show`. Para maximizar las posibilidades de éxito, es importante asegurarse de que las listas de palabras y reglas utilizadas sean completas y estén actualizadas.

### Cracking with John

|**Hash Format**|**Example Command**|**Description**|
|---|---|---|
|afs|`john --format=afs hashes_to_crack.txt`|AFS (Andrew File System) password hashes|
|bfegg|`john --format=bfegg hashes_to_crack.txt`|bfegg hashes used in Eggdrop IRC bots|
|bf|`john --format=bf hashes_to_crack.txt`|Blowfish-based crypt(3) hashes|
|bsdi|`john --format=bsdi hashes_to_crack.txt`|BSDi crypt(3) hashes|
|crypt(3)|`john --format=crypt hashes_to_crack.txt`|Traditional Unix crypt(3) hashes|
|des|`john --format=des hashes_to_crack.txt`|Traditional DES-based crypt(3) hashes|
|dmd5|`john --format=dmd5 hashes_to_crack.txt`|DMD5 (Dragonfly BSD MD5) password hashes|
|dominosec|`john --format=dominosec hashes_to_crack.txt`|IBM Lotus Domino 6/7 password hashes|
|EPiServer SID hashes|`john --format=episerver hashes_to_crack.txt`|EPiServer SID (Security Identifier) password hashes|
|hdaa|`john --format=hdaa hashes_to_crack.txt`|hdaa password hashes used in Openwall GNU/Linux|
|hmac-md5|`john --format=hmac-md5 hashes_to_crack.txt`|hmac-md5 password hashes|
|hmailserver|`john --format=hmailserver hashes_to_crack.txt`|hmailserver password hashes|
|ipb2|`john --format=ip

b2 hashes_to_crack.txt`|Invision Power Board 2 password hashes|
|krb4|`john --format=krb4 hashes_to_crack.txt`|Kerberos 4 password hashes|
|krb5|`john --format=krb5 hashes_to_crack.txt`|Kerberos 5 password hashes|
|LM|`john --format=LM hashes_to_crack.txt`|LM (Lan Manager) password hashes|
|lotus5|`john --format=lotus5 hashes_to_crack.txt`|Lotus Notes/Domino 5 password hashes|
|mscash|`john --format=mscash hashes_to_crack.txt`|MS Cache password hashes|
|mscash2|`john --format=mscash2 hashes_to_crack.txt`|MS Cache v2 password hashes|
|mschapv2|`john --format=mschapv2 hashes_to_crack.txt`|MS CHAP v2 password hashes|
|mskrb5|`john --format=mskrb5 hashes_to_crack.txt`|MS Kerberos 5 password hashes|
|mssql05|`john --format=mssql05 hashes_to_crack.txt`|MS SQL 2005 password hashes|
|mssql|`john --format=mssql hashes_to_crack.txt`|MS SQL password hashes|
|mysql-fast|`john --format=mysql-fast hashes_to_crack.txt`|MySQL fast password hashes|
|mysql|`john --format=mysql hashes_to_crack.txt`|MySQL password hashes|
|mysql-sha1|`john --format=mysql-sha1 hashes_to_crack.txt`|MySQL SHA1 password hashes|
|NETLM|`john --format=netlm hashes_to_crack.txt`|NETLM (NT LAN Manager) password hashes|
|NETLMv2|`john --format=netlmv2 hashes_to_crack.txt`|NETLMv2 (NT LAN Manager version 2) password hashes|
|NETNTLM|`john --format=netntlm hashes_to_crack.txt`|NETNTLM (NT LAN Manager) password hashes|
|NETNTLMv2|`john --format=netntlmv2 hashes_to_crack.txt`|NETNTLMv2 (NT LAN Manager version 2) password hashes|
|NEThalfLM|`john --format=nethalflm hashes_to_crack.txt`|NEThalfLM (NT LAN Manager) password hashes|
|md5ns|`john --format=md5ns hashes_to_crack.txt`|md5ns (MD5 namespace) password hashes|
|nsldap|`john --format=nsldap hashes_to_crack.txt`|nsldap (OpenLDAP SHA) password hashes|
|ssha|`john --format=ssha hashes_to_crack.txt`|ssha (Salted SHA) password hashes|
|NT|`john --format=nt hashes_to_crack.txt`|NT (Windows NT) password hashes|
|openssha|`john --format=openssha hashes_to_crack.txt`|OPENSSH private key password hashes|
|oracle11|`john --format=oracle11 hashes_to_crack.txt`|Oracle 11 password hashes|
|oracle|`john --format=oracle hashes_to_crack.txt`|Oracle password hashes|
|pdf|`john --format=pdf hashes_to_crack.txt`|PDF (Portable Document Format) password hashes|
|phpass-md5|`john --format=phpass-md5 hashes_to_crack.txt`|PHPass-MD5 (Portable PHP password hashing framework) password hashes|
|phps|`john --format=phps hashes_to_crack.txt`|PHPS password hashes|
|pix-md5|`john --format=pix-md5 hashes_to_crack.txt`|Cisco PIX MD5 password hashes|
|po|`john --format=po hashes_to_crack.txt`|Po (Sybase SQL Anywhere) password hashes|
|rar|`john --format=rar hashes_to_crack.txt`|RAR (WinRAR) password hashes|
|raw-md4|`john --format=raw-md4 hashes_to_crack.txt`|Raw MD4 password hashes|
|raw-md5|`john --format=raw-md5 hashes_to_crack.txt`|Raw MD5 password hashes|
|raw-md5-unicode|`john --format=raw-md5-unicode hashes_to_crack.txt`|Raw MD5 Unicode password hashes|
|raw-sha1|`john --format=raw-sha1 hashes_to_crack.txt`|Raw SHA1 password hashes|
|raw-sha224|`john --format=raw-sha224 hashes_to_crack.txt`|Raw SHA224 password hashes|
|raw-sha256|`john --format=raw-sha256 hashes_to_crack.txt`|Raw SHA256 password hashes|
|raw-sha384|`john --format=raw-sha384 hashes_to_crack.txt`|Raw SHA384 password hashes|
|raw-sha512|`john --format=raw-sha512 hashes_to_crack.txt`|Raw SHA512 password hashes|
|salted-sha|`john --format=salted-sha hashes_to_crack.txt`|Salted SHA password hashes|
|sapb|`john --format=sapb hashes_to_crack.txt`|SAP CODVN B (BCODE) password hashes|
|sapg|`john --format=sapg hashes_to_crack.txt`|SAP CODVN G (PASSCODE) password hashes|
|sha1-gen|`john --format=sha1-gen hashes_to_crack.txt`|Generic SHA1 password hashes|
|skey|`john --format=skey hashes_to_crack.txt`|S/Key (One-time password) hashes|
|ssh|`john --format=ssh hashes_to_crack.txt`|SSH (Secure Shell) password hashes|
|sybasease|`john --format=sybasease hashes_to_crack.txt`|Sybase ASE password hashes|
|xsha|`john --format=xsha hashes_to_crack.txt`|xsha (Extended SHA) password hashes|
|zip|`john --format=zip hashes_to_crack.txt`|ZIP (WinZip) password hashes|

### Wordlist Mode

`Wordlist Mode` se utiliza para descifrar contraseñas utilizando múltiples listas de palabras. Es un ataque de diccionario, lo que significa que intentará todas las palabras en las listas una por una hasta encontrar la correcta. Generalmente se utiliza para descifrar múltiples hashes de contraseñas utilizando una lista de palabras o una combinación de listas de palabras. Es más efectivo que el Single Crack Mode porque utiliza más palabras, pero sigue siendo relativamente básico. La sintaxis básica para el comando es:

```r
john --wordlist=<wordlist_file> --rules <hash_file>
```

Primero, especificamos el archivo de lista de palabras o archivos a utilizar para descifrar los hashes de contraseñas. Las listas de palabras pueden estar en formato de texto plano, con una palabra por línea. Se pueden especificar múltiples listas de palabras separándolas con una coma. Luego podemos especificar un conjunto de reglas o aplicar las reglas de manipulación integradas a las palabras en la lista de palabras. Estas reglas generan contraseñas candidatas utilizando transformaciones como agregar números, capitalizar letras y agregar caracteres especiales.

### Incremental Mode

`Incremental Mode` es un modo avanzado de John utilizado para descifrar contraseñas utilizando un conjunto de caracteres. Es un ataque híbrido, lo que significa que intentará coincidir la contraseña intentando todas las combinaciones posibles de caracteres del conjunto de caracteres. Este modo es el más efectivo pero el más lento de todos los modos de John. Este modo funciona mejor cuando sabemos cuál podría ser la contraseña, ya que intentará todas las combinaciones posibles en secuencia, comenzando con una sola combinación de caracteres y aumentando con cada iteración. Esto lo hace mucho más rápido que el ataque de fuerza bruta, donde todas las combinaciones se prueban aleatoriamente. Además, el modo incremental también puede utilizarse para descifrar contraseñas débiles, que pueden ser difíciles de descifrar utilizando los modos estándar de John. La principal diferencia entre el modo incremental y el modo de lista de palabras es la fuente de las conjeturas de contraseñas. El modo incremental genera las conjeturas sobre la marcha, mientras que el modo de lista de palabras utiliza una lista predefinida de palabras. Al mismo tiempo, el modo de crack único se utiliza para verificar una sola contraseña contra un hash.

La sintaxis para ejecutar John the Ripper en modo incremental es la siguiente:

### Incremental Mode in John

```r
john --incremental <hash_file>
```

Usando este comando leeremos los hashes en el archivo de hash especificado y luego generaremos todas las combinaciones posibles de caracteres, comenzando con un solo carácter e incrementando con cada iteración. Es importante tener en cuenta que este modo es `altamente intensivo en recursos` y puede tardar mucho en completarse, dependiendo de la complejidad de las contraseñas, la configuración de la máquina y el número de caracteres establecidos. Además, es importante tener en cuenta que el conjunto de caracteres predeterminado está limitado a `a-zA-Z0-9`. Por lo tanto, si intentamos descifrar contraseñas complejas con caracteres especiales, necesitamos utilizar un conjunto de caracteres personalizado.

---

## Cracking Files

También es posible descifrar incluso archivos protegidos por contraseña o cifrados con John. Utilizamos herramientas adicionales que procesan los archivos dados y producen hashes con los que John puede trabajar. Detecta automáticamente los

 formatos e intenta descifrarlos. La sintaxis para esto puede verse así:

### Cracking Files with John

```r
cry0l1t3@htb:~$ <tool> <file_to_crack> > file.hash
cry0l1t3@htb:~$ pdf2john server_doc.pdf > server_doc.hash
cry0l1t3@htb:~$ john server_doc.hash
                # OR
cry0l1t3@htb:~$ john --wordlist=<wordlist.txt> server_doc.hash 
```

Además, podemos utilizar diferentes modos para esto con nuestras listas de palabras y reglas personales. Hemos creado una lista que incluye muchas pero no todas las herramientas que se pueden utilizar para John:

|**Tool**|**Description**|
|---|---|
|`pdf2john`|Convierte documentos PDF para John|
|`ssh2john`|Convierte claves privadas SSH para John|
|`mscash2john`|Convierte hashes MS Cash para John|
|`keychain2john`|Convierte archivos keychain de OS X para John|
|`rar2john`|Convierte archivos RAR para John|
|`pfx2john`|Convierte archivos PKCS#12 para John|
|`truecrypt_volume2john`|Convierte volúmenes TrueCrypt para John|
|`keepass2john`|Convierte bases de datos KeePass para John|
|`vncpcap2john`|Convierte archivos VNC PCAP para John|
|`putty2john`|Convierte claves privadas PuTTY para John|
|`zip2john`|Convierte archivos ZIP para John|
|`hccap2john`|Convierte capturas de handshake WPA/WPA2 para John|
|`office2john`|Convierte documentos MS Office para John|
|`wpa2john`|Convierte handshakes WPA/WPA2 para John|

Más de estas herramientas se pueden encontrar en `Pwnbox` de la siguiente manera:

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

En este módulo, trabajaremos mucho con John y, por lo tanto, deberíamos saber de qué es capaz esta herramienta.