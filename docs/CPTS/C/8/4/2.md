Además de los arbitrary file uploads y los limited file upload attacks, hay algunas otras técnicas y ataques que vale la pena mencionar, ya que pueden ser útiles en algunas web penetration tests o bug bounty tests. Vamos a discutir algunas de estas técnicas y cuándo podemos usarlas.

---

## Injections in File Name

Un ataque común de file upload utiliza una cadena maliciosa para el uploaded file name, que puede ejecutarse o procesarse si el uploaded file name se muestra (es decir, se refleja) en la página. Podemos intentar inyectar un comando en el file name, y si la web application usa el file name dentro de un OS command, puede llevar a un command injection attack.

Por ejemplo, si nombramos un archivo `file$(whoami).jpg` o ``file`whoami`.jpg`` o `file.jpg||whoami`, y luego la web application intenta mover el uploaded file con un OS command (e.g., `mv file /tmp`), entonces nuestro file name inyectaría el comando `whoami`, que se ejecutaría, llevando a remote code execution. Puedes consultar el módulo [Command Injections](https://academy.hackthebox.com/module/details/109) para más información.

De manera similar, podemos usar un XSS payload en el file name (e.g., `<script>alert(window.origin);</script>`), que se ejecutaría en la máquina del objetivo si se muestra el file name. También podemos inyectar una consulta SQL en el file name (e.g., `file';select+sleep(5);--.jpg`), que puede llevar a una SQL injection si el file name se usa de manera insegura en una SQL query.

---

## Upload Directory Disclosure

En algunos file upload forms, como un feedback form o un submission form, puede que no tengamos acceso al enlace de nuestro uploaded file y no conozcamos el uploads directory. En tales casos, podemos utilizar fuzzing para buscar el uploads directory o incluso usar otras vulnerabilidades (e.g., LFI/XXE) para encontrar dónde están los archivos cargados leyendo el código fuente de las web applications, como vimos en la sección anterior. Además, el módulo [Web Attacks/IDOR](https://academy.hackthebox.com/module/details/134) discute varios métodos para encontrar dónde pueden estar almacenados los archivos e identificar el file naming scheme.

Otro método que podemos usar para revelar el uploads directory es forzando mensajes de error, ya que a menudo revelan información útil para una mayor explotación. Un ataque que podemos usar para causar tales errores es cargar un archivo con un nombre que ya existe o enviar dos solicitudes idénticas simultáneamente. Esto puede llevar al web server a mostrar un error de que no pudo escribir el archivo, lo que puede revelar el uploads directory. También podemos intentar cargar un archivo con un nombre excesivamente largo (e.g., 5,000 caracteres). Si la web application no maneja esto correctamente, también puede mostrar un error y revelar el upload directory.

De manera similar, podemos intentar varias otras técnicas para hacer que el servidor muestre un error y revele el uploads directory, junto con información adicional útil.

---

## Windows-specific Attacks

También podemos usar algunas técnicas específicas de Windows en algunos de los ataques que discutimos en las secciones anteriores.

Uno de estos ataques es usar caracteres reservados, como (`|`, `<`, `>`, `*`, o `?`), que generalmente están reservados para usos especiales como wildcards. Si la web application no sanea adecuadamente estos nombres o los envuelve dentro de comillas, pueden referirse a otro archivo (que puede no existir) y causar un error que revela el upload directory. De manera similar, podemos usar nombres reservados de Windows para el uploaded file name, como (`CON`, `COM1`, `LPT1`, o `NUL`), que también pueden causar un error ya que la web application no permitirá escribir un archivo con este nombre.

Finalmente, podemos utilizar la [8.3 Filename Convention](https://en.wikipedia.org/wiki/8.3_filename) de Windows para sobrescribir archivos existentes o referirse a archivos que no existen. Las versiones antiguas de Windows estaban limitadas a una longitud corta para file names, por lo que usaban un carácter Tilde (`~`) para completar el file name, lo cual podemos usar a nuestro favor.

Por ejemplo, para referirnos a un archivo llamado (`hackthebox.txt`) podemos usar (`HAC~1.TXT`) o (`HAC~2.TXT`), donde el dígito representa el orden de los archivos coincidentes que comienzan con (`HAC`). Como Windows aún admite esta convención, podemos escribir un archivo llamado (e.g., `WEB~.CONF`) para sobrescribir el archivo `web.conf`. De manera similar, podemos escribir un archivo que reemplace archivos del sistema sensibles. Este ataque puede llevar a varios resultados, como causar información disclosure a través de errores, causar un DoS en el servidor de back-end, o incluso acceder a archivos privados.

---

## Advanced File Upload Attacks

Además de todos los ataques que hemos discutido en este módulo, hay ataques más avanzados que se pueden usar con file upload functionalities. Cualquier procesamiento automático que ocurra a un uploaded file, como encoding un video, compressing un archivo, o renaming un archivo, puede ser explotado si no está codificado de manera segura.

Algunas libraries comúnmente usadas pueden tener public exploits para tales vulnerabilidades, como la vulnerabilidad de AVI upload que lleva a XXE en `ffmpeg`. Sin embargo, cuando se trata de código personalizado y libraries personalizadas, detectar tales vulnerabilidades requiere más conocimiento y técnicas avanzadas, lo que puede llevar a descubrir una advanced file upload vulnerability en algunas web applications.

Hay muchas otras advanced file upload vulnerabilities que no discutimos en este módulo. Intenta leer algunos bug bounty reports para explorar más advanced file upload vulnerabilities.