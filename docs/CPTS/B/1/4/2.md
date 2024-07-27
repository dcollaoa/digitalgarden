Las distribuciones basadas en Linux pueden usar muchos mecanismos de autenticación diferentes. Uno de los mecanismos más comúnmente utilizados y estándar es [Pluggable Authentication Modules](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html) (`PAM`). Los módulos utilizados para esto se llaman `pam_unix.so` o `pam_unix2.so` y se encuentran en `/usr/lib/x86_x64-linux-gnu/security/` en las distribuciones basadas en Debian. Estos módulos gestionan la información del usuario, la autenticación, las sesiones, las contraseñas actuales y las antiguas. Por ejemplo, si queremos cambiar la contraseña de nuestra cuenta en el sistema Linux con `passwd`, se llama a PAM, que toma las precauciones adecuadas y almacena y maneja la información en consecuencia.

El módulo estándar `pam_unix.so` para la gestión utiliza llamadas API estandarizadas de las bibliotecas del sistema y archivos para actualizar la información de la cuenta. Los archivos estándar que se leen, gestionan y actualizan son `/etc/passwd` y `/etc/shadow`. PAM también tiene muchos otros módulos de servicio, como LDAP, mount o Kerberos.

---

## Passwd File

El archivo `/etc/passwd` contiene información sobre cada usuario existente en el sistema y puede ser leído por todos los usuarios y servicios. Cada entrada en el archivo `/etc/passwd` identifica a un usuario en el sistema. Cada entrada tiene siete campos que contienen una forma de base de datos con información sobre el usuario en particular, donde un colon (`:`) separa la información. En consecuencia, una entrada puede verse algo así:

### Passwd Format

|`cry0l1t3`|`:`|`x`|`:`|`1000`|`:`|`1000`|`:`|`cry0l1t3,,,`|`:`|`/home/cry0l1t3`|`:`|`/bin/bash`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Nombre de usuario||Información de la contraseña||UID||GID||Nombre completo/comentarios||Directorio home||Shell|

El campo más interesante para nosotros es el campo de información de la contraseña en esta sección porque puede haber diferentes entradas aquí. Uno de los casos más raros que podemos encontrar solo en sistemas muy antiguos es el hash de la contraseña cifrada en este campo. Los sistemas modernos tienen los valores hash almacenados en el archivo `/etc/shadow`, al cual volveremos más adelante. No obstante, `/etc/passwd` es legible a nivel del sistema, lo que da a los atacantes la posibilidad de descifrar las contraseñas si se almacenan aquí.

Normalmente, encontramos el valor `x` en este campo, lo que significa que las contraseñas se almacenan en forma cifrada en el archivo `/etc/shadow`. Sin embargo, también puede ser que el archivo `/etc/passwd` sea escribible por error. Esto nos permitiría borrar este campo para el usuario `root`, de modo que el campo de información de la contraseña esté vacío. Esto hará que el sistema no envíe un aviso de contraseña cuando un usuario intente iniciar sesión como `root`.

### Editing /etc/passwd - Before

```r
root:x:0:0:root:/root:/bin/bash
```

### Editing /etc/passwd - After

```r
root::0:0:root:/root:/bin/bash
```

### Root without Password

```r
[cry0l1t3@parrot]─[~]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash


[cry0l1t3@parrot]─[~]$ su

[root@parrot]─[/home/cry0l1t3]#
```

Aunque los casos mostrados raramente ocurrirán, aún debemos prestar atención y buscar brechas de seguridad porque hay aplicaciones que requieren que configuremos permisos específicos para carpetas enteras. Si el administrador tiene poca experiencia con Linux o las aplicaciones y sus dependencias, es posible que el administrador otorgue permisos de escritura al directorio `/etc` y olvide corregirlos.

---

## Shadow File

Dado que leer los valores hash de las contraseñas puede poner en peligro todo el sistema, se desarrolló el archivo `/etc/shadow`, que tiene un formato similar al de `/etc/passwd` pero es solo responsable de las contraseñas y su gestión. Contiene toda la información de las contraseñas para los usuarios creados. Por ejemplo, si no hay una entrada en el archivo `/etc/shadow` para un usuario en `/etc/passwd`, el usuario se considera inválido. El archivo `/etc/shadow` también es solo legible por usuarios que tienen derechos de administrador. El formato de este archivo está dividido en `nueve campos`:

### Shadow Format

|`cry0l1t3`|`:`|`$6$wBRzy$...SNIP...x9cDWUxW1`|`:`|`18937`|`:`|`0`|`:`|`99999`|`:`|`7`|`:`|`:`|`:`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Nombre de usuario||Contraseña cifrada||Último cambio de contraseña||Edad mínima de la contraseña||Edad máxima de la contraseña||Periodo de advertencia|Periodo de inactividad|Fecha de expiración|No utilizado|

### Shadow File

```r
[cry0l1t3@parrot]─[~]$ sudo cat /etc/shadow

root:*:18747:0:99999:7:::
sys:!:18747:0:99999:7:::
...SNIP...
cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
```

Si el campo de la contraseña contiene un carácter, como `!` o `*`, el usuario no puede iniciar sesión con una contraseña de Unix. Sin embargo, aún se pueden usar otros métodos de autenticación para iniciar sesión, como Kerberos o autenticación basada en claves. El mismo caso se aplica si el campo de `contraseña cifrada` está vacío. Esto significa que no se requiere una contraseña para el inicio de sesión. Sin embargo, puede llevar a que ciertos programas nieguen el acceso a funciones. La `contraseña cifrada` también tiene un formato particular por el cual podemos obtener alguna información:

- `$<tipo>$<sal>` `$<cifrado>$<hash>`

Como podemos ver aquí, las contraseñas cifradas están divididas en tres partes. Los tipos de cifrado nos permiten distinguir entre los siguientes:

### Algorithm Types

- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512

Por defecto, el método de cifrado SHA-512 (`$6$`) se utiliza en las últimas distribuciones de Linux. También encontraremos los otros métodos de cifrado que podemos intentar descifrar en sistemas más antiguos. Discutiremos cómo funciona el descifrado más adelante.

---

## Opasswd

La biblioteca PAM (`pam_unix.so`) puede prevenir el uso de contraseñas antiguas. El archivo donde se almacenan las contraseñas antiguas es el `/etc/security/opasswd`. También se requieren permisos de administrador/root para leer el archivo si los permisos para este archivo no se han cambiado manualmente.

### Reading /etc/security/opasswd

```r
sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```

Al mirar el contenido de este archivo, podemos ver que contiene varias entradas para el usuario `cry0l1t3`, separadas por una coma (`,`). Otro punto crítico a tener en cuenta es el tipo de hash que se ha utilizado. Esto se debe a que el algoritmo `MD5` (`$1$`) es mucho más fácil de descifrar que SHA-512. Esto es especialmente importante para identificar contraseñas antiguas y tal vez incluso su patrón porque a menudo se utilizan en varios servicios o aplicaciones. Aumentamos la probabilidad de adivinar la contraseña correcta muchas veces basándonos en su patrón.

---

## Cracking Linux Credentials

Una vez que hemos recopilado algunos hashes, podemos intentar descifrarlos de diferentes maneras para obtener las contraseñas en texto claro.

### Unshadow

```r
sudo cp /etc/passwd /tmp/passwd.bak 
sudo cp /etc/shadow /tmp/shadow.bak 
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

### Hashcat - Cracking Unshadowed Hashes

```r
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

### Hashcat - Cracking MD5 Hashes

```r
cat md5-hashes.list

qNDkF0zJ3v8ylCOrKB0kt0
E9uMSmiQeRh4pAAgzuvkq1
```

```r
hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```