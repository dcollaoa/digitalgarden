
Después de ver algunas formas de explotar las vulnerabilidades de **Verb Tampering**, veamos cómo podemos protegernos contra estos tipos de ataques previniendo el **Verb Tampering**. Las configuraciones inseguras y la codificación insegura son las que generalmente introducen vulnerabilidades de **Verb Tampering**. En esta sección, veremos ejemplos de código y configuraciones vulnerables y discutiremos cómo podemos parchearlos.

---

## Insecure Configuration

Las vulnerabilidades de **HTTP Verb Tampering** pueden ocurrir en la mayoría de los servidores web modernos, incluyendo `Apache`, `Tomcat` y `ASP.NET`. La vulnerabilidad generalmente ocurre cuando limitamos la autorización de una página a un conjunto particular de verbos/métodos HTTP, dejando los otros métodos restantes desprotegidos.

El siguiente es un ejemplo de una configuración vulnerable para un servidor web Apache, que se encuentra en el archivo de configuración del sitio (por ejemplo, `000-default.conf`), o en un archivo de configuración de página web `.htaccess`:

```r
<Directory "/var/www/html/admin">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile /etc/apache2/.htpasswd
    <Limit GET>
        Require valid-user
    </Limit>
</Directory>
```

Como podemos ver, esta configuración está estableciendo las configuraciones de autorización para el directorio web `admin`. Sin embargo, dado que se está utilizando la palabra clave `<Limit GET>`, la configuración `Require valid-user` solo se aplicará a las solicitudes `GET`, dejando la página accesible a través de solicitudes `POST`. Incluso si se especificaran ambos, `GET` y `POST`, esto dejaría la página accesible a través de otros métodos, como `HEAD` u `OPTIONS`.

El siguiente ejemplo muestra la misma vulnerabilidad para una configuración de servidor web `Tomcat`, que se puede encontrar en el archivo `web.xml` para una aplicación web Java específica:

```r
<security-constraint>
    <web-resource-collection>
        <url-pattern>/admin/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```

Podemos ver que la autorización está siendo limitada solo al método `GET` con `http-method`, lo que deja la página accesible a través de otros métodos HTTP.

Finalmente, el siguiente es un ejemplo para una configuración `ASP.NET` que se encuentra en el archivo `web.config` de una aplicación web:

```r
<system.web>
    <authorization>
        <allow verbs="GET" roles="admin">
            <deny verbs="GET" users="*">
        </deny>
        </allow>
    </authorization>
</system.web>
```

Una vez más, el alcance de `allow` y `deny` está limitado al método `GET`, lo que deja la aplicación web accesible a través de otros métodos HTTP.

Los ejemplos anteriores muestran que no es seguro limitar la configuración de autorización a un verbo HTTP específico. Es por esto que siempre debemos evitar restringir la autorización a un método HTTP particular y siempre permitir/negar todos los verbos y métodos HTTP.

Si queremos especificar un solo método, podemos usar palabras clave seguras, como `LimitExcept` en Apache, `http-method-omission` en Tomcat y `add`/`remove` en ASP.NET, que cubren todos los verbos excepto los especificados.

Finalmente, para evitar ataques similares, generalmente debemos `considerar deshabilitar/denegar todas las solicitudes HEAD` a menos que sean específicamente requeridas por la aplicación web.

---

## Insecure Coding

Si bien identificar y parchear configuraciones de servidores web inseguras es relativamente fácil, hacer lo mismo para el código inseguro es mucho más desafiante. Esto se debe a que, para identificar esta vulnerabilidad en el código, necesitamos encontrar inconsistencias en el uso de parámetros HTTP a lo largo de las funciones, ya que en algunos casos, esto puede llevar a funcionalidades y filtros desprotegidos.

Consideremos el siguiente código `PHP` de nuestro ejercicio `File Manager`:

```r
if (isset($_REQUEST['filename'])) {
    if (!preg_match('/[^A-Za-z0-9. _-]/', $_POST['filename'])) {
        system("touch " . $_REQUEST['filename']);
    } else {
        echo "Malicious Request Denied!";
    }
}
```

Si solo estuviéramos considerando vulnerabilidades de **Command Injection**, diríamos que esto está codificado de manera segura. La función `preg_match` busca correctamente caracteres especiales no deseados y no permite que la entrada vaya al comando si se encuentran caracteres especiales. Sin embargo, el error fatal en este caso no se debe a **Command Injections**, sino a la `inconsistent use of HTTP methods`.

Vemos que el filtro `preg_match` solo verifica caracteres especiales en los parámetros `POST` con `$_POST['filename']`. Sin embargo, el comando final `system` usa la variable `$_REQUEST['filename']`, que cubre tanto los parámetros `GET` como `POST`. Entonces, en la sección anterior, cuando estábamos enviando nuestra entrada maliciosa a través de una solicitud `GET`, no fue detenida por la función `preg_match`, ya que los parámetros `POST` estaban vacíos y, por lo tanto, no contenían caracteres especiales. Una vez que llegamos a la función `system`, sin embargo, se utilizaron los parámetros encontrados en la solicitud, y nuestros parámetros `GET` se usaron en el comando, lo que eventualmente llevó a una **Command Injection**.

Este ejemplo básico nos muestra cómo las pequeñas inconsistencias en el uso de métodos HTTP pueden llevar a vulnerabilidades críticas. En una aplicación web de producción, estos tipos de vulnerabilidades no serán tan obvios. Probablemente estarían dispersos a lo largo de la aplicación web y no estarán en dos líneas consecutivas como tenemos aquí. En cambio, la aplicación web probablemente tendrá una función especial para verificar inyecciones y una función diferente para crear archivos. Esta separación de código hace que sea difícil detectar este tipo de inconsistencias y, por lo tanto, pueden sobrevivir hasta la producción.

Para evitar vulnerabilidades de **HTTP Verb Tampering** en nuestro código, `debemos ser consistentes con el uso de métodos HTTP` y asegurarnos de que siempre se utilice el mismo método para cualquier funcionalidad específica a lo largo de la aplicación web. Siempre se recomienda `expandir el alcance de las pruebas en los filtros de seguridad` probando todos los parámetros de solicitud. Esto se puede hacer con las siguientes funciones y variables:

| Language | Function                     |
|----------|------------------------------|
| PHP      | `$_REQUEST['param']`         |
| Java     | `request.getParameter('param')` |
| C#       | `Request['param']`           |

Si nuestro alcance en funciones relacionadas con la seguridad cubre todos los métodos, deberíamos evitar tales vulnerabilidades o elusión de filtros.