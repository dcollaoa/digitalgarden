Una vulnerabilidad de Command Injection es una de las más críticas. Permite ejecutar comandos del sistema directamente en el servidor de alojamiento, lo que podría llevar a comprometer toda la red. Si una aplicación web utiliza la entrada controlada por el usuario para ejecutar un comando del sistema en el servidor de back-end para recuperar y devolver una salida específica, podríamos inyectar un payload malicioso para subvertir el comando previsto y ejecutar nuestros comandos.

---

## What are Injections

Las vulnerabilidades de inyección se consideran el riesgo número 3 en [OWASP's Top 10 Web App Risks](https://owasp.org/www-project-top-ten/), dado su alto impacto y lo comunes que son. La inyección ocurre cuando la entrada controlada por el usuario se interpreta erróneamente como parte de la consulta web o el código que se está ejecutando, lo que puede llevar a subvertir el resultado previsto de la consulta a un resultado diferente que es útil para el atacante.

Hay muchos tipos de inyecciones encontradas en aplicaciones web, dependiendo del tipo de consulta web que se esté ejecutando. Los siguientes son algunos de los tipos más comunes de inyecciones:

| Injection                           | Description                                                               |
| ----------------------------------- | ------------------------------------------------------------------------- |
| OS Command Injection                | Ocurre cuando la entrada del usuario se usa directamente como parte de un comando del sistema operativo. |
| Code Injection                      | Ocurre cuando la entrada del usuario se usa directamente dentro de una función que evalúa código. |
| SQL Injections                      | Ocurre cuando la entrada del usuario se usa directamente como parte de una consulta SQL. |
| Cross-Site Scripting/HTML Injection | Ocurre cuando la entrada exacta del usuario se muestra en una página web. |

Hay muchos otros tipos de inyecciones además de las anteriores, como `LDAP injection`, `NoSQL Injection`, `HTTP Header Injection`, `XPath Injection`, `IMAP Injection`, `ORM Injection`, y otros. Siempre que se utilice la entrada del usuario dentro de una consulta sin estar debidamente sanitizada, puede ser posible escapar de los límites de la cadena de entrada del usuario a la consulta principal y manipularla para cambiar su propósito previsto. Es por eso que a medida que se introducen más tecnologías web en las aplicaciones web, veremos nuevos tipos de inyecciones introducidas en las aplicaciones web.

---

## OS Command Injections

Cuando se trata de OS Command Injections, la entrada del usuario que controlamos debe ir directa o indirectamente (o de alguna manera afectar) a una consulta web que ejecuta comandos del sistema. Todos los lenguajes de programación web tienen diferentes funciones que permiten al desarrollador ejecutar comandos del sistema operativo directamente en el servidor de back-end siempre que lo necesiten. Esto puede usarse para varios propósitos, como instalar plugins o ejecutar ciertas aplicaciones.

### PHP Example

Por ejemplo, una aplicación web escrita en `PHP` puede usar las funciones `exec`, `system`, `shell_exec`, `passthru` o `popen` para ejecutar comandos directamente en el servidor de back-end, cada una con un caso de uso ligeramente diferente. El siguiente código es un ejemplo de código PHP que es vulnerable a inyecciones de comandos:


```r
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

Tal vez una aplicación web particular tenga una funcionalidad que permite a los usuarios crear un nuevo documento `.pdf` que se crea en el directorio `/tmp` con un nombre de archivo proporcionado por el usuario y luego puede ser utilizado por la aplicación web para fines de procesamiento de documentos. Sin embargo, como la entrada del usuario desde el parámetro `filename` en la solicitud `GET` se usa directamente con el comando `touch` (sin estar sanitizada o escapada primero), la aplicación web se vuelve vulnerable a la inyección de comandos del sistema operativo. Este fallo puede ser explotado para ejecutar comandos arbitrarios del sistema en el servidor de back-end.

### NodeJS Example

Esto no es único de `PHP` solamente, sino que puede ocurrir en cualquier framework o lenguaje de desarrollo web. Por ejemplo, si una aplicación web está desarrollada en `NodeJS`, un desarrollador puede usar `child_process.exec` o `child_process.spawn` para el mismo propósito. El siguiente ejemplo realiza una funcionalidad similar a la que discutimos anteriormente:


```r
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
})
```

El código anterior también es vulnerable a una vulnerabilidad de inyección de comandos, ya que utiliza el parámetro `filename` de la solicitud `GET` como parte del comando sin sanearlo primero. Tanto las aplicaciones web en `PHP` como en `NodeJS` pueden ser explotadas usando los mismos métodos de inyección de comandos.

Asimismo, otros lenguajes de programación de desarrollo web tienen funciones similares utilizadas para los mismos propósitos y, si son vulnerables, pueden ser explotadas usando los mismos métodos de inyección de comandos. Además, las vulnerabilidades de Command Injection no son únicas de las aplicaciones web, sino que también pueden afectar a otros binarios y clientes gruesos si pasan la entrada del usuario sin sanear a una función que ejecuta comandos del sistema, lo que también puede ser explotado con los mismos métodos de inyección de comandos.

La siguiente sección discutirá diferentes métodos de detección y explotación de vulnerabilidades de inyección de comandos en aplicaciones web.