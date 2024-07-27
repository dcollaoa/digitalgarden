El protocolo `HTTP` funciona aceptando varios métodos HTTP como `verbs` al inicio de una solicitud HTTP. Dependiendo de la configuración del servidor web, las aplicaciones web pueden estar programadas para aceptar ciertos métodos HTTP para sus diversas funcionalidades y realizar una acción particular según el tipo de solicitud.

Mientras que los programadores principalmente consideran los dos métodos HTTP más comúnmente usados, `GET` y `POST`, cualquier cliente puede enviar cualquier otro método en sus solicitudes HTTP y luego ver cómo el servidor web maneja estos métodos. Supongamos que tanto la aplicación web como el servidor web de back-end están configurados solo para aceptar solicitudes `GET` y `POST`. En ese caso, el envío de una solicitud diferente causará que se muestre una página de error del servidor web, lo cual no es una vulnerabilidad grave en sí misma (además de proporcionar una mala experiencia de usuario y potencialmente conducir a la divulgación de información). Por otro lado, si las configuraciones del servidor web no están restringidas a aceptar solo los métodos HTTP requeridos por el servidor web (por ejemplo, `GET`/`POST`), y la aplicación web no está desarrollada para manejar otros tipos de solicitudes HTTP (por ejemplo, `HEAD`, `PUT`), entonces podríamos explotar esta configuración insegura para obtener acceso a funcionalidades a las que no tenemos acceso, o incluso eludir ciertos controles de seguridad.

---

## HTTP Verb Tampering

Para entender `HTTP Verb Tampering`, primero debemos aprender sobre los diferentes métodos aceptados por el protocolo HTTP. HTTP tiene [9 verbos diferentes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) que pueden ser aceptados como métodos HTTP por los servidores web. Aparte de `GET` y `POST`, los siguientes son algunos de los verbos HTTP comúnmente utilizados:

|Verbo|Descripción|
|---|---|
|`HEAD`|Idéntico a una solicitud GET, pero su respuesta solo contiene los `headers`, sin el cuerpo de la respuesta|
|`PUT`|Escribe el payload de la solicitud en la ubicación especificada|
|`DELETE`|Elimina el recurso en la ubicación especificada|
|`OPTIONS`|Muestra diferentes opciones aceptadas por un servidor web, como verbos HTTP aceptados|
|`PATCH`|Aplica modificaciones parciales al recurso en la ubicación especificada|

Como puedes imaginar, algunos de los métodos anteriores pueden realizar funcionalidades muy sensibles, como escribir (`PUT`) o eliminar (`DELETE`) archivos en el directorio webroot en el servidor de back-end. Como se discutió en el módulo [Web Requests](https://academy.hackthebox.com/course/preview/web-requests), si un servidor web no está configurado de manera segura para gestionar estos métodos, podemos usarlos para obtener control sobre el servidor de back-end. Sin embargo, lo que hace que los ataques de HTTP Verb Tampering sean más comunes (y, por lo tanto, más críticos) es que son causados por una configuración incorrecta, ya sea en el servidor web de back-end o en la aplicación web, cualquiera de las cuales puede causar la vulnerabilidad.

---

## Insecure Configurations

Las configuraciones inseguras del servidor web causan el primer tipo de vulnerabilidades de HTTP Verb Tampering. La configuración de autenticación de un servidor web puede estar limitada a métodos HTTP específicos, lo que dejaría algunos métodos HTTP accesibles sin autenticación. Por ejemplo, un administrador del sistema puede usar la siguiente configuración para requerir autenticación en una página web en particular:

```r
<Limit GET POST>
    Require valid-user
</Limit>
```

Como podemos ver, aunque la configuración especifica solicitudes `GET` y `POST` para el método de autenticación, un atacante aún puede usar un método HTTP diferente (como `HEAD`) para eludir este mecanismo de autenticación por completo, como veremos en la siguiente sección. Esto finalmente lleva a una elusión de autenticación y permite a los atacantes acceder a páginas web y dominios a los que no deberían tener acceso.

---

## Insecure Coding

Las prácticas de codificación insegura causan el otro tipo de vulnerabilidades de HTTP Verb Tampering (aunque algunos pueden no considerar esto como Verb Tampering). Esto puede ocurrir cuando un desarrollador web aplica filtros específicos para mitigar ciertas vulnerabilidades sin cubrir todos los métodos HTTP con ese filtro. Por ejemplo, si se encuentra que una página web es vulnerable a una vulnerabilidad de SQL Injection, y el desarrollador de back-end mitiga la vulnerabilidad de SQL Injection aplicando los siguientes filtros de sanitización de entrada:

```r
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}
```

Podemos ver que el filtro de sanitización solo se está probando en el parámetro `GET`. Si las solicitudes GET no contienen ningún carácter malo, entonces la consulta se ejecutaría. Sin embargo, cuando se ejecuta la consulta, se están utilizando los parámetros `$_REQUEST["code"]`, que también pueden contener parámetros `POST`, lo que lleva a una inconsistencia en el uso de HTTP Verbs. En este caso, un atacante puede usar una solicitud `POST` para realizar SQL injection, en cuyo caso los parámetros `GET` estarían vacíos (no incluirían ningún carácter malo). La solicitud pasaría el filtro de seguridad, lo que haría que la función aún sea vulnerable a SQL Injection.

Aunque ambas vulnerabilidades mencionadas se encuentran en el ámbito público, la segunda es mucho más común, ya que se debe a errores cometidos en la codificación, mientras que la primera generalmente se evita mediante configuraciones seguras del servidor web, ya que la documentación a menudo advierte sobre ello. En las siguientes secciones, veremos ejemplos de ambos tipos y cómo explotarlos.