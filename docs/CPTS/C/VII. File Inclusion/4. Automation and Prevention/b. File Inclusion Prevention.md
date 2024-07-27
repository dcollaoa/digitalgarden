Este módulo ha discutido varias formas de detectar y explotar vulnerabilidades de inclusión de archivos, junto con diferentes métodos de evasión de seguridad y técnicas de ejecución remota de código que podemos utilizar. Con esa comprensión de cómo identificar vulnerabilidades de inclusión de archivos a través de pruebas de penetración, ahora deberíamos aprender cómo parchear estas vulnerabilidades y reforzar nuestros sistemas para reducir las posibilidades de su aparición y minimizar el impacto si ocurren.

---

## File Inclusion Prevention

Lo más efectivo que podemos hacer para reducir las vulnerabilidades de inclusión de archivos es evitar pasar cualquier entrada controlada por el usuario a cualquier función o API de inclusión de archivos. La página debería poder cargar dinámicamente los recursos en el back-end, sin ninguna interacción del usuario. Además, en la primera sección de este módulo, discutimos diferentes funciones que pueden ser utilizadas para incluir otros archivos dentro de una página y mencionamos los privilegios que tiene cada función. Siempre que se utilice cualquiera de estas funciones, debemos asegurarnos de que ninguna entrada del usuario vaya directamente a ellas. Por supuesto, esta lista de funciones no es exhaustiva, por lo que generalmente debemos considerar cualquier función que pueda leer archivos.

En algunos casos, esto puede no ser factible, ya que puede requerir cambiar toda la arquitectura de una aplicación web existente. En tales casos, debemos utilizar una lista blanca limitada de entradas permitidas por el usuario y emparejar cada entrada con el archivo a cargar, teniendo un valor predeterminado para todas las demás entradas. Si estamos tratando con una aplicación web existente, podemos crear una lista blanca que contenga todas las rutas existentes utilizadas en el front-end y luego utilizar esta lista para emparejar la entrada del usuario. Tal lista blanca puede tener muchas formas, como una tabla de base de datos que empareje IDs con archivos, un script `case-match` que empareje nombres con archivos, o incluso un mapa estático en JSON con nombres y archivos que puedan ser emparejados.

Una vez implementado esto, la entrada del usuario no va a la función, sino que los archivos emparejados se utilizan en la función, lo que evita vulnerabilidades de inclusión de archivos.

---

## Preventing Directory Traversal

Si los atacantes pueden controlar el directorio, pueden escapar de la aplicación web y atacar algo con lo que estén más familiarizados o utilizar una `universal attack chain`. Como hemos discutido a lo largo del módulo, el recorrido de directorios podría permitir a los atacantes hacer cualquiera de las siguientes acciones:

- Leer `/etc/passwd` y potencialmente encontrar claves SSH o conocer nombres de usuarios válidos para un ataque de password spray.
- Encontrar otros servicios en la máquina como Tomcat y leer el archivo `tomcat-users.xml`.
- Descubrir cookies de sesión PHP válidas y realizar secuestro de sesión.
- Leer la configuración y el código fuente de la aplicación web actual.

La mejor manera de prevenir el recorrido de directorios es utilizar la herramienta incorporada de tu lenguaje de programación (o framework) para extraer solo el nombre del archivo. Por ejemplo, PHP tiene `basename()`, que leerá la ruta y solo devolverá la parte del nombre del archivo. Si solo se da un nombre de archivo, entonces devolverá solo el nombre del archivo. Si solo se da la ruta, tratará lo que esté después del último / como el nombre del archivo. La desventaja de este método es que si la aplicación necesita ingresar a algún directorio, no podrá hacerlo.

Si creas tu propia función para hacer este método, es posible que no estés considerando un caso límite extraño. Por ejemplo, en tu terminal bash, ve a tu directorio de inicio (cd ~) y ejecuta el comando `cat .?/.*/.?/etc/passwd`. Verás que Bash permite usar los comodines `?` y `*` como `.`. Ahora escribe `php -a` para entrar en el intérprete de línea de comandos de PHP y ejecuta `echo file_get_contents('.?/.*/.?/etc/passwd');`. Verás que PHP no tiene el mismo comportamiento con los comodines, si reemplazas `?` y `*` con `.`., el comando funcionará como se espera. Esto demuestra que hay un caso límite con nuestra función anterior, si hacemos que PHP ejecute bash con la función `system()`, el atacante podría eludir nuestra prevención de recorrido de directorios. Si utilizamos funciones nativas del framework en el que estamos, hay una posibilidad de que otros usuarios detecten casos límites como este y lo arreglen antes de que sea explotado en nuestra aplicación web.

Además, podemos sanitizar la entrada del usuario para eliminar recursivamente cualquier intento de recorrer directorios, de la siguiente manera:

```r
while(substr_count($input, '../', 0)) {
    $input = str_replace('../', '', $input);
};
```

Como podemos ver, este código elimina recursivamente subcadenas `../`, por lo que incluso si la cadena resultante contiene `../`, aún la eliminaría, lo que evitaría algunas de las evasiones que intentamos en este módulo.

---

## Web Server Configuration

Varias configuraciones también pueden ser utilizadas para reducir el impacto de las vulnerabilidades de inclusión de archivos en caso de que ocurran. Por ejemplo, deberíamos deshabilitar globalmente la inclusión de archivos remotos. En PHP, esto puede hacerse configurando `allow_url_fopen` y `allow_url_include` a Off.

También es posible bloquear aplicaciones web en su directorio raíz web, evitando que accedan a archivos no relacionados con la web. La forma más común de hacer esto hoy en día es ejecutando la aplicación dentro de `Docker`. Sin embargo, si eso no es una opción, muchos lenguajes a menudo tienen una forma de prevenir el acceso a archivos fuera del directorio web. En PHP, esto puede hacerse añadiendo `open_basedir = /var/www` en el archivo php.ini. Además, debes asegurarte de que ciertos módulos potencialmente peligrosos estén deshabilitados, como [PHP Expect](https://www.php.net/manual/en/wrappers.expect.php) y [mod_userdir](https://httpd.apache.org/docs/2.4/mod/mod_userdir.html).

Si se aplican estas configuraciones, debería evitarse el acceso a archivos fuera de la carpeta de la aplicación web, por lo que incluso si se identifica una vulnerabilidad LFI, su impacto sería reducido.

---

## Web Application Firewall (WAF)

La forma universal de reforzar aplicaciones es utilizar un Web Application Firewall (WAF), como `ModSecurity`. Al tratar con WAFs, lo más importante es evitar falsos positivos y bloquear solicitudes no maliciosas. ModSecurity minimiza los falsos positivos ofreciendo un modo `permissive`, que solo reportará las cosas que habría bloqueado. Esto permite a los defensores ajustar las reglas para asegurarse de que no se bloquee ninguna solicitud legítima. Incluso si la organización nunca quiere poner el WAF en "modo de bloqueo", solo tenerlo en modo permisivo puede ser una señal de advertencia temprana de que tu aplicación está siendo atacada.

Finalmente, es importante recordar que el propósito del hardening es darle a la aplicación una carcasa exterior más fuerte, para que cuando ocurra un ataque, los defensores tengan tiempo para defenderse. Según el [FireEye M-Trends Report de 2020](https://content.fireeye.com/m-trends/rpt-m-trends-2020), el tiempo promedio que tardó una empresa en detectar hackers fue de 30 días. Con un hardening adecuado, los atacantes dejarán muchos más signos, y la organización detectará estos eventos aún más rápido.

Es importante entender que el objetivo del hardening no es hacer que tu sistema sea imposible de hackear, lo que significa que no puedes descuidar la vigilancia de los registros sobre un sistema reforzado porque es "seguro". Los sistemas reforzados deben ser probados continuamente, especialmente después de que se lance un zero-day para una aplicación relacionada con tu sistema (por ejemplo, Apache Struts, RAILS, Django, etc.). En la mayoría de los casos, el zero-day funcionará, pero gracias al hardening, puede generar registros únicos, lo que permitirá confirmar si se utilizó el exploit contra el sistema o no.