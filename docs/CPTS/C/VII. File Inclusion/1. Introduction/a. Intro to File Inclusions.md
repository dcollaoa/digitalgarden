
Muchas lenguajes modernos de back-end, como `PHP`, `Javascript` o `Java`, utilizan parámetros HTTP para especificar lo que se muestra en la página web, lo que permite construir páginas web dinámicas, reduce el tamaño total del script y simplifica el código. En tales casos, los parámetros se utilizan para especificar qué recurso se muestra en la página. Si estas funcionalidades no se codifican de manera segura, un atacante puede manipular estos parámetros para mostrar el contenido de cualquier archivo local en el servidor de alojamiento, lo que lleva a una vulnerabilidad de [Local File Inclusion (LFI)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion).

---

## Local File Inclusion (LFI)

El lugar más común donde encontramos LFI es en los motores de plantillas. Para que la mayoría de la aplicación web tenga el mismo aspecto al navegar entre páginas, un motor de plantillas muestra una página que muestra las partes estáticas comunes, como el `header`, `navigation bar` y `footer`, y luego carga dinámicamente otro contenido que cambia entre páginas. De lo contrario, cada página en el servidor necesitaría ser modificada cuando se realicen cambios en cualquiera de las partes estáticas. Por esta razón, a menudo vemos un parámetro como `/index.php?page=about`, donde `index.php` establece contenido estático (por ejemplo, header/footer) y luego solo obtiene el contenido dinámico especificado en el parámetro, que en este caso puede leerse desde un archivo llamado `about.php`. Como tenemos control sobre la porción `about` de la solicitud, es posible que la aplicación web obtenga otros archivos y los muestre en la página.

Las vulnerabilidades de LFI pueden llevar a la divulgación del código fuente, la exposición de datos sensibles e incluso la ejecución remota de código en ciertas condiciones. La filtración del código fuente puede permitir a los atacantes probar el código en busca de otras vulnerabilidades, lo que puede revelar vulnerabilidades desconocidas anteriormente. Además, la filtración de datos sensibles puede permitir a los atacantes enumerar el servidor remoto en busca de otras debilidades o incluso filtrar credenciales y claves que les permitan acceder directamente al servidor remoto. En condiciones específicas, LFI también puede permitir a los atacantes ejecutar código en el servidor remoto, lo que puede comprometer todo el servidor back-end y cualquier otro servidor conectado a él.

---

## Ejemplos de Código Vulnerable

Veamos algunos ejemplos de código vulnerable a la Inclusión de Archivos para entender cómo ocurren estas vulnerabilidades. Como se mencionó anteriormente, las vulnerabilidades de inclusión de archivos pueden ocurrir en muchos de los servidores web y marcos de desarrollo más populares, como `PHP`, `NodeJS`, `Java`, `.Net` y muchos otros. Cada uno de ellos tiene un enfoque ligeramente diferente para incluir archivos locales, pero todos comparten una cosa en común: cargar un archivo desde una ruta especificada.

Tal archivo podría ser un header dinámico o un contenido diferente basado en el idioma especificado por el usuario. Por ejemplo, la página puede tener un parámetro GET `?language`, y si un usuario cambia el idioma desde un menú desplegable, entonces se devolverá la misma página pero con un parámetro `language` diferente (por ejemplo, `?language=es`). En tales casos, cambiar el idioma puede cambiar el directorio desde el cual la aplicación web está cargando las páginas (por ejemplo, `/en/` o `/es/`). Si tenemos control sobre la ruta que se está cargando, entonces podríamos explotar esta vulnerabilidad para leer otros archivos y potencialmente alcanzar la ejecución remota de código.

### PHP

En `PHP`, podemos usar la función `include()` para cargar un archivo local o remoto mientras cargamos una página. Si la `path` pasada a la `include()` se toma de un parámetro controlado por el usuario, como un parámetro `GET`, y el código no filtra y sanitiza explícitamente la entrada del usuario, entonces el código se vuelve vulnerable a la Inclusión de Archivos. El siguiente fragmento de código muestra un ejemplo de esto:

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

Vemos que el parámetro `language` se pasa directamente a la función `include()`. Entonces, cualquier ruta que pasemos en el parámetro `language` se cargará en la página, incluyendo cualquier archivo local en el servidor back-end. Esto no es exclusivo de la función `include()`, ya que hay muchas otras funciones de PHP que llevarían a la misma vulnerabilidad si tuviéramos control sobre la ruta pasada a ellas. Tales funciones incluyen `include_once()`, `require()`, `require_once()`, `file_get_contents()` y varias otras también.

**Nota:** En este módulo, nos enfocaremos principalmente en aplicaciones web PHP que se ejecutan en un servidor back-end Linux. Sin embargo, la mayoría de las técnicas y ataques funcionarían en la mayoría de los otros marcos, por lo que nuestros ejemplos serían los mismos con una aplicación web escrita en cualquier otro lenguaje.

### NodeJS

Al igual que en el caso de PHP, los servidores web NodeJS también pueden cargar contenido basado en parámetros HTTP. El siguiente es un ejemplo básico de cómo un parámetro GET `language` se utiliza para controlar qué datos se escriben en una página:

```javascript
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```

Como podemos ver, cualquier parámetro pasado desde la URL se utiliza por la función `readfile`, que luego escribe el contenido del archivo en la respuesta HTTP. Otro ejemplo es la función `render()` en el marco `Express.js`. El siguiente ejemplo muestra el uso del parámetro `language` para determinar de qué directorio debe obtener la página `about.html`:

```javascript
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});
```

A diferencia de nuestros ejemplos anteriores, donde los parámetros GET se especificaban después de un carácter (`?`) en la URL, el ejemplo anterior toma el parámetro de la ruta URL (por ejemplo, `/about/en` o `/about/es`). Como el parámetro se utiliza directamente dentro de la función `render()` para especificar el archivo renderizado, podemos cambiar la URL para mostrar un archivo diferente.

### Java

El mismo concepto se aplica a muchos otros servidores web. Los siguientes ejemplos muestran cómo las aplicaciones web para un servidor web Java pueden incluir archivos locales basados en el parámetro especificado, utilizando la función `include`:

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

La función `include` puede tomar un archivo o una URL de página como argumento y luego renderiza el objeto en la plantilla del front-end, similar a los que vimos anteriormente con NodeJS. La función `import` también puede usarse para renderizar un archivo local o una URL, como en el siguiente ejemplo:

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```

### .NET

Finalmente, tomemos un ejemplo de cómo pueden ocurrir vulnerabilidades de Inclusión de Archivos en aplicaciones web .NET. La función `Response.WriteFile` funciona de manera muy similar a todos nuestros ejemplos anteriores, ya que toma una ruta de archivo como entrada y escribe su contenido en la respuesta. La ruta puede recuperarse de un parámetro GET para cargar contenido dinámico, como sigue:

```csharp
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

Además, la función `@Html.Partial()` también puede usarse para renderizar el archivo especificado como parte de la plantilla del front-end, similar a lo que vimos anteriormente:

```csharp
@Html.Partial(HttpContext.Request.Query['language'])
```

Finalmente, la función `include` puede usarse para renderizar archivos locales o URLs remotas, y también puede ejecutar los archivos especificados:

```html
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

## Read vs Execute

De todos los ejemplos anteriores, podemos ver que las vulnerabilidades de Inclusión de Archivos pueden ocurrir en cualquier servidor web y cualquier marco de desarrollo, ya que todos ellos proporcionan funcionalidades para cargar contenido dinámico y manejar plantillas del front-end.

Lo más importante a tener en cuenta es que algunas de las funciones anteriores solo leen el contenido de los archivos especificados, mientras que otras también ejecutan los archivos especificados. Además, algunas de ellas permiten especificar URLs remotas, mientras que otras solo funcionan con archivos locales en el servidor back-end.

La siguiente tabla muestra qué funciones pueden ejecutar archivos y cuáles solo leen el contenido de los archivos:

| **Function**                    | **Read Content** | **Execute** | **Remote URL** |
|---------------------------------|------------------|-------------|----------------|
| **PHP**                         |                  |             |                |
| `include()`/`include_once()`    | ✅               | ✅          | ✅             |
| `require()`/`require_once()`    | ✅               | ✅          | ❌             |
| `file_get_contents()`           | ✅               | ❌          | ✅             |
| `fopen()`/`file()`              | ✅               | ❌          | ❌             |
| **NodeJS**                      |                  |             |                |
| `fs.readFile()`                 | ✅               | ❌         

 | ❌             |
| `fs.sendFile()`                 | ✅               | ❌          | ❌             |
| `res.render()`                  | ✅               | ✅          | ❌             |
| **Java**                        |                  |             |                |
| `include`                       | ✅               | ❌          | ❌             |
| `import`                        | ✅               | ✅          | ✅             |
| **.NET**                        |                  |             |                |
| `@Html.Partial()`               | ✅               | ❌          | ❌             |
| `@Html.RemotePartial()`         | ✅               | ❌          | ✅             |
| `Response.WriteFile()`          | ✅               | ❌          | ❌             |
| `include`                       | ✅               | ✅          | ✅             |

Esta es una diferencia significativa a tener en cuenta, ya que ejecutar archivos puede permitirnos ejecutar funciones y eventualmente llevar a la ejecución de código, mientras que solo leer el contenido del archivo solo nos permitiría leer el código fuente sin ejecutar código. Además, si tuviéramos acceso al código fuente en un ejercicio de whitebox o en una auditoría de código, conocer estas acciones nos ayuda a identificar posibles vulnerabilidades de Inclusión de Archivos, especialmente si tienen entrada controlada por el usuario.

En todos los casos, las vulnerabilidades de Inclusión de Archivos son críticas y pueden eventualmente llevar a comprometer todo el servidor back-end. Incluso si solo pudiéramos leer el código fuente de la aplicación web, aún podría permitirnos comprometer la aplicación web, ya que podría revelar otras vulnerabilidades mencionadas anteriormente, y el código fuente también podría contener claves de bases de datos, credenciales de administrador u otra información sensible.