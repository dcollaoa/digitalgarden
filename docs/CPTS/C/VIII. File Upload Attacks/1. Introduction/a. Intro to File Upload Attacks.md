Subir archivos de usuario se ha convertido en una característica clave para la mayoría de las aplicaciones web modernas, permitiendo la extensibilidad de las aplicaciones web con información del usuario. Un sitio web de redes sociales permite la subida de imágenes de perfil de usuario y otros medios sociales, mientras que un sitio web corporativo puede permitir a los usuarios subir PDFs y otros documentos para uso corporativo.

Sin embargo, a medida que los desarrolladores de aplicaciones web habilitan esta función, también corren el riesgo de permitir que los usuarios almacenen datos potencialmente maliciosos en el servidor back-end de la aplicación web. Si la entrada del usuario y los archivos subidos no se filtran y validan correctamente, los atacantes podrían explotar la función de subida de archivos para realizar actividades maliciosas, como ejecutar comandos arbitrarios en el servidor back-end para tomar control de él.

Las vulnerabilidades de subida de archivos están entre las más comunes encontradas en aplicaciones web y móviles, como podemos ver en los últimos [CVE Reports](https://www.cvedetails.com/vulnerability-list/cweid-434/vulnerabilities.html). También notaremos que la mayoría de estas vulnerabilidades están calificadas como `High` o `Critical`, mostrando el nivel de riesgo causado por subidas de archivos inseguras.

---

## Types of File Upload Attacks

La razón más común detrás de las vulnerabilidades de subida de archivos es la validación y verificación débil de los archivos, que pueden no estar bien aseguradas para prevenir tipos de archivos no deseados o podrían estar completamente ausentes. El peor tipo de vulnerabilidad de subida de archivos es una vulnerabilidad de `unauthenticated arbitrary file upload`. Con este tipo de vulnerabilidad, una aplicación web permite a cualquier usuario no autenticado subir cualquier tipo de archivo, quedando a un paso de permitir a cualquier usuario ejecutar código en el servidor back-end.

Muchos desarrolladores web emplean varios tipos de pruebas para validar la extensión o el contenido del archivo subido. Sin embargo, como veremos en este módulo, si estos filtros no son seguros, podríamos ser capaces de eludirlos y aún así lograr subidas de archivos arbitrarios para realizar nuestros ataques.

El ataque más común y crítico causado por subidas de archivos arbitrarios es `gaining remote command execution` sobre el servidor back-end subiendo un web shell o subiendo un script que envíe una reverse shell. Un web shell, como discutiremos en la siguiente sección, nos permite ejecutar cualquier comando que especifiquemos y puede convertirse en un shell interactivo para enumerar el sistema fácilmente y explotar aún más la red. También puede ser posible subir un script que envíe una reverse shell a un listener en nuestra máquina y luego interactuar con el servidor remoto de esa manera.

En algunos casos, puede que no tengamos subidas de archivos arbitrarios y solo podamos subir un tipo específico de archivo. Incluso en estos casos, hay varios ataques que podríamos realizar para explotar la funcionalidad de subida de archivos si ciertas protecciones de seguridad faltan en la aplicación web.

Ejemplos de estos ataques incluyen:

- Introducir otras vulnerabilidades como `XSS` o `XXE`.
- Causar un `Denial of Service (DoS)` en el servidor back-end.
- Sobrescribir archivos y configuraciones del sistema críticos.
- Y muchos otros.

Finalmente, una vulnerabilidad de subida de archivos no solo es causada por escribir funciones inseguras, sino que también a menudo es causada por el uso de bibliotecas desactualizadas que pueden ser vulnerables a estos ataques. Al final del módulo, repasaremos varios consejos y prácticas para asegurar nuestras aplicaciones web contra los tipos más comunes de ataques de subida de archivos, además de recomendaciones adicionales para prevenir vulnerabilidades de subida de archivos que podríamos pasar por alto.