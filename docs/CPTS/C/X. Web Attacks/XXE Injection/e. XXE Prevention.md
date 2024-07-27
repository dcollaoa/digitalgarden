Hemos visto que las vulnerabilidades XXE ocurren principalmente cuando una entrada XML insegura hace referencia a una entidad externa, la cual es eventualmente explotada para leer archivos sensibles y realizar otras acciones. Prevenir las vulnerabilidades XXE es relativamente más fácil que prevenir otras vulnerabilidades web, ya que son causadas principalmente por bibliotecas XML desactualizadas.

## Avoiding Outdated Components

Mientras que otras vulnerabilidades de validación de entrada web generalmente se previenen mediante prácticas de codificación segura (por ejemplo, XSS, IDOR, SQLi, OS Injection), esto no es totalmente necesario para prevenir las vulnerabilidades XXE. Esto se debe a que la entrada XML generalmente no es manejada manualmente por los desarrolladores web, sino por las bibliotecas XML incorporadas. Por lo tanto, si una aplicación web es vulnerable a XXE, es muy probable que se deba a una biblioteca XML desactualizada que analiza los datos XML.

Por ejemplo, la función de PHP [libxml_disable_entity_loader](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php) está obsoleta ya que permite a un desarrollador habilitar entidades externas de manera insegura, lo que lleva a vulnerabilidades XXE. Si visitamos la documentación de PHP para esta función, vemos la siguiente advertencia:

**Warning**

Esta función ha sido _DEPRECATED_ a partir de PHP 8.0.0. Confiar en esta función es altamente desaconsejado.

Además, incluso los editores de código comunes (por ejemplo, VSCode) resaltarán que esta función específica está obsoleta y nos advertirán contra su uso: ![deprecated_warning](https://academy.hackthebox.com/storage/modules/134/web_attacks_xxe_deprecated_warning.jpg)

**Note:** Puede encontrar un informe detallado de todas las bibliotecas XML vulnerables, con recomendaciones sobre cómo actualizarlas y usar funciones seguras, en [OWASP's XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#php).

Además de actualizar las bibliotecas XML, también debemos actualizar cualquier componente que analice la entrada XML, como las bibliotecas de API como SOAP. Además, cualquier procesador de documentos o archivos que pueda realizar análisis XML, como los procesadores de imágenes SVG o los procesadores de documentos PDF, también pueden ser vulnerables a las vulnerabilidades XXE, y también debemos actualizarlos.

Estos problemas no son exclusivos de las bibliotecas XML solamente, ya que lo mismo se aplica a todos los demás componentes web (por ejemplo, `Node Modules` desactualizados). Además de los administradores de paquetes comunes (por ejemplo, `npm`), los editores de código comunes notificarán a los desarrolladores web sobre el uso de componentes desactualizados y sugerirán otras alternativas. Al final, `usar las últimas bibliotecas XML y componentes de desarrollo web puede ayudar en gran medida a reducir varias vulnerabilidades web`, incluidas las XXE.

---

## Using Safe XML Configurations

Además de usar las últimas bibliotecas XML, ciertas configuraciones XML para aplicaciones web pueden ayudar a reducir la posibilidad de explotación XXE. Estas incluyen:

- Deshabilitar la referencia a `Document Type Definitions (DTDs)` personalizadas
- Deshabilitar la referencia a `External XML Entities`
- Deshabilitar el procesamiento de `Parameter Entity`
- Deshabilitar el soporte para `XInclude`
- Prevenir `Entity Reference Loops`

Otra cosa que vimos fue la explotación XXE basada en errores. Por lo tanto, siempre debemos tener un manejo adecuado de excepciones en nuestras aplicaciones web y `siempre debemos deshabilitar la visualización de errores en tiempo de ejecución en los servidores web`.

Tales configuraciones deben ser otra capa de protección si no actualizamos algunas bibliotecas XML y también deben prevenir la explotación XXE. Sin embargo, aún podemos estar usando bibliotecas vulnerables en tales casos y solo aplicando soluciones alternativas contra la explotación, lo cual no es ideal.

Con los diversos problemas y vulnerabilidades introducidos por los datos XML, muchos también recomiendan `usar otros formatos, como JSON o YAML`. Esto también incluye evitar los estándares de API que dependen de XML (por ejemplo, SOAP) y usar APIs basadas en JSON en su lugar (por ejemplo, REST).

Finalmente, usar Web Application Firewalls (WAFs) es otra capa de protección contra la explotación XXE. Sin embargo, nunca debemos confiar completamente en los WAFs y dejar el back-end vulnerable, ya que los WAFs siempre pueden ser burlados.