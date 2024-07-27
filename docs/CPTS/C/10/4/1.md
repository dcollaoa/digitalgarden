Las vulnerabilidades de `XML External Entity (XXE) Injection` ocurren cuando los datos XML se toman de una entrada controlada por el usuario sin desinfectarlos adecuadamente o analizarlos de manera segura, lo que puede permitirnos usar características de XML para realizar acciones maliciosas. Las vulnerabilidades XXE pueden causar daños considerables a una aplicación web y su servidor back-end, desde la divulgación de archivos sensibles hasta apagar el servidor back-end, por lo que se considera una de las [Top 10 Web Security Risks](https://owasp.org/www-project-top-ten/) por OWASP.

---

## XML

`Extensible Markup Language (XML)` es un lenguaje de marcado común (similar a HTML y SGML) diseñado para la transferencia flexible y el almacenamiento de datos y documentos en varios tipos de aplicaciones. XML no se centra en mostrar datos, sino principalmente en almacenar datos de documentos y representar estructuras de datos. Los documentos XML están formados por árboles de elementos, donde cada elemento se denota esencialmente por una `tag`, y el primer elemento se llama `root element`, mientras que otros elementos son `child elements`.

Aquí vemos un ejemplo básico de un documento XML que representa la estructura de un documento de correo electrónico:


```r
<?xml version="1.0" encoding="UTF-8"?>
<email>
  <date>01-01-2022</date>
  <time>10:00 am UTC</time>
  <sender>john@inlanefreight.com</sender>
  <recipients>
    <to>HR@inlanefreight.com</to>
    <cc>
        <to>billing@inlanefreight.com</to>
        <to>payslips@inlanefreight.com</to>
    </cc>
  </recipients>
  <body>
  Hello,
      Kindly share with me the invoice for the payment made on January 1, 2022.
  Regards,
  John
  </body> 
</email>
```

El ejemplo anterior muestra algunos de los elementos clave de un documento XML, como:

| Key        | Definition                                                                 | Example                                |
|------------|-----------------------------------------------------------------------------|----------------------------------------|
| `Tag`      | Las claves de un documento XML, generalmente envueltas con caracteres (`<`/`>`).  | `<date>`                               |
| `Entity`   | Variables XML, generalmente envueltas con caracteres (`&`/`;`).            | `&lt;`                                 |
| `Element`  | El `root element` o cualquiera de sus `child elements`, y su valor se almacena entre una `start-tag` y una `end-tag`. | `<date>01-01-2022</date>`              |
| `Attribute`| Especificaciones opcionales para cualquier elemento que se almacenan en las etiquetas, y que pueden ser utilizadas por el analizador XML. | `version="1.0"`/`encoding="UTF-8"`     |
| `Declaration`| Generalmente la primera línea de un documento XML, y define la versión y codificación de XML a utilizar al analizarlo. | `<?xml version="1.0" encoding="UTF-8"?>` |

Además, algunos caracteres se utilizan como parte de la estructura de un documento XML, como `<`, `>`, `&`, o `"`. Por lo tanto, si necesitamos usarlos en un documento XML, debemos reemplazarlos por sus referencias de entidad correspondientes (por ejemplo, `&lt;`, `&gt;`, `&amp;`, `&quot;`). Finalmente, podemos escribir comentarios en documentos XML entre `<!--` y `-->`, similar a los documentos HTML.

---

## XML DTD

`XML Document Type Definition (DTD)` permite la validación de un documento XML contra una estructura de documento predefinida. La estructura de documento predefinida se puede definir en el propio documento o en un archivo externo. El siguiente es un ejemplo de DTD para el documento XML que vimos anteriormente:


```r
<!DOCTYPE email [
  <!ELEMENT email (date, time, sender, recipients, body)>
  <!ELEMENT recipients (to, cc?)>
  <!ELEMENT cc (to*)>
  <!ELEMENT date (#PCDATA)>
  <!ELEMENT time (#PCDATA)>
  <!ELEMENT sender (#PCDATA)>
  <!ELEMENT to  (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
```

Como podemos ver, el DTD está declarando el `root element` `email` con la declaración de tipo `ELEMENT` y luego denotando sus `child elements`. Después de eso, cada uno de los `child elements` también se declara, donde algunos de ellos también tienen `child elements`, mientras que otros pueden contener solo datos sin procesar (como se denota por `PCDATA`).

El DTD anterior se puede colocar dentro del propio documento XML, justo después de la `XML Declaration` en la primera línea. De lo contrario, se puede almacenar en un archivo externo (por ejemplo, `email.dtd`), y luego referenciado dentro del documento XML con la palabra clave `SYSTEM`, como sigue:


```r
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "email.dtd">
```

También es posible referenciar un DTD a través de una URL, como sigue:


```r
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email SYSTEM "http://inlanefreight.com/email.dtd">
```

Esto es relativamente similar a cómo los documentos HTML definen y referencian scripts de JavaScript y CSS.

---

## XML Entities

También podemos definir entidades personalizadas (es decir, variables XML) en DTDs XML, para permitir la refactorización de variables y reducir datos repetitivos. Esto se puede hacer con el uso de la palabra clave `ENTITY`, que va seguida del nombre de la entidad y su valor, como sigue:


```r
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
```

Una vez que definimos una entidad, se puede referenciar en un documento XML entre un `&` y un `;` (por ejemplo, `&company;`). Siempre que se referencia una entidad, el analizador XML la reemplazará con su valor. Lo más interesante, sin embargo, es que podemos `referenciar External XML Entities` con la palabra clave `SYSTEM`, que va seguida de la ruta de la entidad externa, como sigue:


```r
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "http://localhost/company.txt">
  <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
]>
```

**Nota:** También podemos usar la palabra clave `PUBLIC` en lugar de `SYSTEM` para cargar recursos externos, que se usa con entidades y estándares declarados públicamente, como un código de idioma (`lang="en"`). En este módulo, usaremos `SYSTEM`, pero deberíamos poder usar cualquiera de los dos en la mayoría de los casos.

Esto funciona de manera similar a las entidades XML internas definidas dentro de los documentos. Cuando referenciamos una entidad externa (por ejemplo, `&signature;`), el analizador reemplazará la entidad con su valor almacenado en el archivo externo (por ejemplo, `signature.txt`). `When the XML file is parsed on the server-side, in cases like SOAP (XML) APIs or web forms, then an entity can reference a file stored on the back-end server, which may eventually be disclosed to us when we reference the entity`.

En la siguiente sección, veremos cómo podemos usar External XML Entities para leer archivos locales o incluso realizar acciones más maliciosas.