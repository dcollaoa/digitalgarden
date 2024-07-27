Ahora, deberíamos tener una buena comprensión de lo que es una vulnerabilidad XSS y sus diferentes tipos, cómo detectar una vulnerabilidad XSS y cómo explotar las vulnerabilidades XSS. Concluiremos el módulo aprendiendo cómo defendernos contra las vulnerabilidades XSS.

Como se discutió anteriormente, las vulnerabilidades XSS están principalmente vinculadas a dos partes de la aplicación web: un `Source` como un campo de entrada de usuario y un `Sink` que muestra los datos de entrada. Estos son los dos puntos principales en los que debemos centrarnos para asegurar, tanto en el front-end como en el back-end.

El aspecto más importante de la prevención de vulnerabilidades XSS es la correcta sanitización y validación de entradas tanto en el front-end como en el back-end. Además de eso, se pueden tomar otras medidas de seguridad para ayudar a prevenir ataques XSS.

---

## Front-end

Dado que el front-end de la aplicación web es donde se toman la mayoría (pero no todas) de las entradas de usuario, es esencial sanitizar y validar las entradas de usuario en el front-end utilizando JavaScript.

### Validación de Entradas

Por ejemplo, en el ejercicio de la sección `XSS Discovery`, vimos que la aplicación web no nos permitirá enviar el formulario si el formato del correo electrónico es inválido. Esto se hizo con el siguiente código JavaScript:

```javascript
function validateEmail(email) {
    const re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test($("#login input[name=email]").val());
}
```

Como podemos ver, este código está probando el campo de entrada `email` y devolviendo `true` o `false` dependiendo de si coincide con la validación Regex de un formato de correo electrónico.

### Sanitización de Entradas

Además de la validación de entradas, siempre debemos asegurarnos de no permitir ninguna entrada con código JavaScript, escapando cualquier carácter especial. Para esto, podemos utilizar la biblioteca JavaScript [DOMPurify](https://github.com/cure53/DOMPurify), como sigue:

```html
<script type="text/javascript" src="dist/purify.min.js"></script>
let clean = DOMPurify.sanitize(dirty);
```

Esto escapará cualquier carácter especial con una barra invertida `\`, lo cual debería ayudar a asegurar que un usuario no envíe ninguna entrada con caracteres especiales (como código JavaScript), previniendo así vulnerabilidades como DOM XSS.

### Entrada Directa

Finalmente, siempre debemos asegurarnos de nunca usar la entrada del usuario directamente dentro de ciertas etiquetas HTML, como:

1. Código JavaScript `<script></script>`
2. Código de Estilo CSS `<style></style>`
3. Campos de Etiqueta/Atributo `<div name='INPUT'></div>`
4. Comentarios HTML `<!-- -->`

Si la entrada del usuario va en cualquiera de los ejemplos anteriores, puede inyectar código JavaScript malicioso, lo que puede llevar a una vulnerabilidad XSS. Además de esto, debemos evitar el uso de funciones JavaScript que permitan cambiar texto en bruto de los campos HTML, como:

- `DOM.innerHTML`
- `DOM.outerHTML`
- `document.write()`
- `document.writeln()`
- `document.domain`

Y las siguientes funciones de jQuery:

- `html()`
- `parseHTML()`
- `add()`
- `append()`
- `prepend()`
- `after()`
- `insertAfter()`
- `before()`
- `insertBefore()`
- `replaceAll()`
- `replaceWith()`

Ya que estas funciones escriben texto en bruto en el código HTML, si alguna entrada del usuario va en ellas, puede incluir código JavaScript malicioso, lo que lleva a una vulnerabilidad XSS.

---

## Back-end

En el otro extremo, también debemos asegurarnos de prevenir vulnerabilidades XSS con medidas en el back-end para prevenir vulnerabilidades Stored y Reflected XSS. Como vimos en el ejercicio de la sección `XSS Discovery`, aunque tenía validación de entrada en el front-end, esto no fue suficiente para prevenir la inyección de un payload malicioso en el formulario. Por lo tanto, también debemos tener medidas de prevención de XSS en el back-end. Esto se puede lograr con la Sanitización y Validación de Entradas y Salidas, la Configuración del Servidor y Herramientas de Back-end que ayuden a prevenir vulnerabilidades XSS.

### Validación de Entradas

La validación de entradas en el back-end es bastante similar a la del front-end, y utiliza Regex o funciones de bibliotecas para asegurarse de que el campo de entrada es lo que se espera. Si no coincide, entonces el servidor back-end lo rechazará y no lo mostrará.

Un ejemplo de validación de correo electrónico en un back-end PHP es el siguiente:

```php
if (filter_var($_GET['email'], FILTER_VALIDATE_EMAIL)) {
    // do task
} else {
    // reject input - do not display it
}
```

Para un back-end NodeJS, podemos usar el mismo código JavaScript mencionado anteriormente para el front-end.

### Sanitización de Entradas

Cuando se trata de sanitización de entradas, el back-end juega un papel vital, ya que la sanitización de entradas en el front-end puede ser fácilmente evadida enviando solicitudes `GET` o `POST` personalizadas. Afortunadamente, hay bibliotecas muy fuertes para varios lenguajes de back-end que pueden sanitizar adecuadamente cualquier entrada del usuario, de modo que aseguremos que no pueda ocurrir ninguna inyección.

Por ejemplo, para un back-end PHP, podemos usar la función `addslashes` para sanitizar la entrada del usuario escapando caracteres especiales con una barra invertida:

```php
addslashes($_GET['email'])
```

En cualquier caso, la entrada directa del usuario (e.g. `$_GET['email']`) nunca debe mostrarse directamente en la página, ya que esto puede llevar a vulnerabilidades XSS.

Para un back-end NodeJS, también podemos usar la biblioteca [DOMPurify](https://github.com/cure53/DOMPurify) como hicimos con el front-end, de la siguiente manera:

```javascript
import DOMPurify from 'dompurify';
var clean = DOMPurify.sanitize(dirty);
```

### Codificación de Salida HTML

Otro aspecto importante a tener en cuenta en el back-end es la `Codificación de Salida`. Esto significa que tenemos que codificar cualquier carácter especial en sus códigos HTML, lo cual es útil si necesitamos mostrar la entrada completa del usuario sin introducir una vulnerabilidad XSS. Para un back-end PHP, podemos usar las funciones `htmlspecialchars` o `htmlentities`, las cuales codifican ciertos caracteres especiales en sus códigos HTML (e.g. `<` en `&lt`), para que el navegador los muestre correctamente, pero no causen ninguna inyección de ningún tipo:

```php
htmlentities($_GET['email']);
```

Para un back-end NodeJS, podemos usar cualquier biblioteca que haga codificación HTML, como `html-entities`, de la siguiente manera:

```javascript
import encode from 'html-entities';
encode('<'); // -> '&lt;'
```

Una vez que aseguramos que toda la entrada del usuario está validada, sanitizada y codificada en la salida, deberíamos reducir significativamente el riesgo de tener vulnerabilidades XSS.

### Configuración del Servidor

Además de lo anterior, hay ciertas configuraciones del servidor web back-end que pueden ayudar a prevenir ataques XSS, como:

- Usar HTTPS en todo el dominio.
- Usar encabezados de prevención de XSS.
- Usar el tipo de contenido apropiado para la página, como `X-Content-Type-Options=nosniff`.
- Usar opciones de `Content-Security-Policy`, como `script-src 'self'`, que solo permite scripts alojados localmente.
- Usar las flags de cookie `HttpOnly` y `Secure` para prevenir que JavaScript lea las cookies y solo transportarlas a través de HTTPS.

Además de lo anterior, tener un buen `Web Application Firewall (WAF)` puede reducir significativamente las posibilidades de explotación XSS, ya que detectará automáticamente cualquier tipo de inyección que pase por solicitudes HTTP y rechazará automáticamente tales solicitudes. Además, algunos frameworks proporcionan protección XSS incorporada, como [ASP.NET](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-7.0).

Al final, debemos hacer nuestro mejor esfuerzo para asegurar nuestras aplicaciones web contra vulnerabilidades XSS usando estas técnicas de prevención de XSS. Incluso después de todo esto, debemos practicar todas las habilidades que aprendimos en este módulo e intentar identificar y explotar vulnerabilidades XSS en cualquier campo de entrada potencial, ya que la codificación segura y las configuraciones seguras aún pueden dejar brechas y vulnerabilidades que pueden ser explotadas. Si practicamos la defensa del sitio web utilizando técnicas tanto `ofensivas` como `defensivas`, deberíamos alcanzar un nivel confiable de seguridad contra las vulnerabilidades XSS.