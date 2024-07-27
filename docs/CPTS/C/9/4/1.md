Debemos tener ahora una comprensión sólida de cómo ocurren las vulnerabilidades de inyección de comandos y cómo ciertos métodos de mitigación, como los filtros de caracteres y comandos, pueden ser evadidos. Esta sección discutirá los métodos que podemos usar para prevenir vulnerabilidades de inyección de comandos en nuestras aplicaciones web y configurar adecuadamente el servidor web para evitarlas.

---

## System Commands

Siempre debemos evitar usar funciones que ejecuten comandos del sistema, especialmente si estamos utilizando input del usuario con ellas. Incluso cuando no estamos introduciendo directamente el input del usuario en estas funciones, un usuario puede ser capaz de influir indirectamente en ellas, lo que eventualmente puede llevar a una vulnerabilidad de inyección de comandos.

En lugar de usar funciones de ejecución de comandos del sistema, debemos usar funciones integradas que realicen la funcionalidad necesaria, ya que los lenguajes back-end suelen tener implementaciones seguras de este tipo de funcionalidades. Por ejemplo, supongamos que queríamos probar si un host en particular está vivo con `PHP`. En ese caso, podríamos usar la función `fsockopen` en su lugar, la cual no debería ser explotable para ejecutar comandos del sistema arbitrarios.

Si necesitáramos ejecutar un comando del sistema y no se puede encontrar una función integrada para realizar la misma funcionalidad, nunca debemos usar directamente el input del usuario con estas funciones, sino que siempre debemos validar y sanitizar el input del usuario en el back-end. Además, debemos tratar de limitar nuestro uso de este tipo de funciones tanto como sea posible y solo usarlas cuando no haya una alternativa integrada a la funcionalidad que requerimos.

---

## Input Validation

Ya sea que usemos funciones integradas o funciones de ejecución de comandos del sistema, siempre debemos validar y luego sanitizar el input del usuario. La validación de input se realiza para asegurarse de que coincide con el formato esperado para el input, de modo que la solicitud se deniegue si no coincide. En nuestra aplicación web de ejemplo, vimos que había un intento de validación de input en el front-end, pero la validación de input debe hacerse tanto en el front-end como en el back-end.

En `PHP`, como en muchos otros lenguajes de desarrollo web, hay filtros integrados para una variedad de formatos estándar, como correos electrónicos, URLs e incluso IPs, que se pueden usar con la función `filter_var`, como sigue:

```r
if (filter_var($_GET['ip'], FILTER_VALIDATE_IP)) {
    // call function
} else {
    // deny request
}
```

Si quisiéramos validar un formato no estándar diferente, entonces podríamos usar una expresión regular `regex` con la función `preg_match`. Lo mismo se puede lograr con `JavaScript` tanto para el front-end como para el back-end (es decir, `NodeJS`), como sigue:

```r
if(/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip)){
    // call function
}
else{
    // deny request
}
```

Al igual que con `PHP`, con `NodeJS`, también podemos usar librerías para validar varios formatos estándar, como [is-ip](https://www.npmjs.com/package/is-ip) por ejemplo, que podemos instalar con `npm`, y luego usar la función `isIp(ip)` en nuestro código. Puedes leer los manuales de otros lenguajes, como [.NET](https://learn.microsoft.com/en-us/aspnet/web-pages/overview/ui-layouts-and-themes/validating-user-input-in-aspnet-web-pages-sites) o [Java](https://docs.oracle.com/cd/E13226_01/workshop/docs81/doc/en/workshop/guide/netui/guide/conValidatingUserInput.html?skipReload=true), para saber cómo validar el input del usuario en cada lenguaje respectivo.

---

## Input Sanitization

La parte más crítica para prevenir cualquier vulnerabilidad de inyección es la sanitización del input, lo que significa eliminar cualquier carácter especial innecesario del input del usuario. La sanitización del input siempre se realiza después de la validación del input. Incluso después de haber validado que el input del usuario proporcionado está en el formato adecuado, todavía debemos realizar la sanitización y eliminar cualquier carácter especial no requerido para el formato específico, ya que hay casos en los que la validación del input puede fallar (por ejemplo, un regex incorrecto).

En nuestro código de ejemplo, vimos que cuando tratábamos con filtros de caracteres y comandos, se estaban colocando en una lista negra ciertas palabras y buscándolas en el input del usuario. En general, este no es un enfoque lo suficientemente bueno para prevenir inyecciones, y deberíamos usar funciones integradas para eliminar cualquier carácter especial. Podemos usar `preg_replace` para eliminar cualquier carácter especial del input del usuario, como sigue:

```r
$ip = preg_replace('/[^A-Za-z0-9.]/', '', $_GET['ip']);
```

Como podemos ver, el regex anterior solo permite caracteres alfanuméricos (`A-Za-z0-9`) y permite un carácter punto (`.`) según se requiera para las IPs. Cualquier otro carácter será eliminado de la cadena. Lo mismo se puede hacer con `JavaScript`, como sigue:

```r
var ip = ip.replace(/[^A-Za-z0-9.]/g, '');
```

También podemos usar la librería DOMPurify para un back-end `NodeJS`, como sigue:

```r
import DOMPurify from 'dompurify';
var ip = DOMPurify.sanitize(ip);
```

En ciertos casos, podemos querer permitir todos los caracteres especiales (por ejemplo, comentarios de usuario), entonces podemos usar la misma función `filter_var` que usamos con la validación de input, y usar el filtro `escapeshellcmd` para escapar cualquier carácter especial, para que no puedan causar inyecciones. Para `NodeJS`, simplemente podemos usar la función `escape(ip)`. Sin embargo, como hemos visto en este módulo, escapar caracteres especiales generalmente no se considera una práctica segura, ya que a menudo puede ser evadido a través de varias técnicas.

Para más información sobre validación y sanitización de input de usuario para prevenir inyecciones de comandos, puedes referirte al módulo [Secure Coding 101: JavaScript](https://academy.hackthebox.com/course/preview/secure-coding-101-javascript), que cubre cómo auditar el código fuente de una aplicación web para identificar vulnerabilidades de inyección de comandos, y luego trabaja en parchear adecuadamente estos tipos de vulnerabilidades.

---

## Server Configuration

Finalmente, debemos asegurarnos de que nuestro servidor back-end esté configurado de manera segura para reducir el impacto en caso de que el servidor web sea comprometido. Algunas de las configuraciones que podemos implementar son:

- Usar el firewall de aplicaciones web incorporado del servidor web (por ejemplo, en Apache `mod_security`), además de un WAF externo (por ejemplo, `Cloudflare`, `Fortinet`, `Imperva`..)

- Seguir el [Principio del Menor Privilegio (PoLP)](https://en.wikipedia.org/wiki/Principle_of_least_privilege) ejecutando el servidor web como un usuario de bajo privilegio (por ejemplo, `www-data`)

- Prevenir que ciertas funciones sean ejecutadas por el servidor web (por ejemplo, en PHP `disable_functions=system,...`)

- Limitar el alcance accesible por la aplicación web a su carpeta (por ejemplo, en PHP `open_basedir = '/var/www/html'`)

- Rechazar solicitudes codificadas doblemente y caracteres no ASCII en URLs

- Evitar el uso de librerías y módulos sensibles/desactualizados (por ejemplo, [PHP CGI](https://www.php.net/manual/en/install.unix.commandline.php))

Al final, incluso después de todas estas mitigaciones y configuraciones de seguridad, debemos realizar las técnicas de penetration testing que aprendimos en este módulo para ver si alguna funcionalidad de la aplicación web aún puede ser vulnerable a la inyección de comandos. Dado que algunas aplicaciones web tienen millones de líneas de código, cualquier error en cualquier línea de código puede ser suficiente para introducir una vulnerabilidad. Por lo tanto, debemos tratar de asegurar la aplicación web complementando las mejores prácticas de codificación segura con pruebas de penetración exhaustivas.