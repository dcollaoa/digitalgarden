El tipo más básico de vulnerabilidad de carga de archivos ocurre cuando la aplicación web `no tiene ningún tipo de filtros de validación` en los archivos cargados, permitiendo la carga de cualquier tipo de archivo por defecto.

Con este tipo de aplicaciones web vulnerables, podemos cargar directamente nuestro web shell o script de reverse shell en la aplicación web, y luego, simplemente visitando el script cargado, podemos interactuar con nuestro web shell o enviar el reverse shell.

---

## Arbitrary File Upload

Comencemos el ejercicio al final de esta sección, y veremos una aplicación web `Employee File Manager`, que nos permite cargar archivos personales en la aplicación web:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_file_manager.jpg)

La aplicación web no menciona nada sobre qué tipos de archivos están permitidos, y podemos arrastrar y soltar cualquier archivo que queramos, y su nombre aparecerá en el formulario de carga, incluyendo archivos `.php`:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_file_selected_php_file.jpg)

Además, si hacemos clic en el formulario para seleccionar un archivo, el cuadro de diálogo del selector de archivos no especifica ningún tipo de archivo, ya que dice `All Files` para el tipo de archivo, lo que también puede sugerir que no se especifican restricciones o limitaciones para la aplicación web:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_file_selection_dialog.jpg)

Todo esto nos dice que el programa parece no tener restricciones de tipo de archivo en el front-end, y si no se especificaron restricciones en el back-end, podríamos cargar tipos de archivos arbitrarios en el servidor back-end para obtener control total sobre él.

---

## Identifying Web Framework

Necesitamos cargar un script malicioso para probar si podemos cargar cualquier tipo de archivo en el servidor back-end y probar si podemos usar esto para explotar el servidor back-end. Muchos tipos de scripts pueden ayudarnos a explotar aplicaciones web a través de la carga de archivos arbitrarios, comúnmente un `Web Shell` y un `Reverse Shell`.

Un Web Shell nos proporciona un método fácil para interactuar con el servidor back-end aceptando comandos shell e imprimiendo su salida de vuelta en el navegador web. Un web shell debe estar escrito en el mismo lenguaje de programación que ejecuta el servidor web, ya que ejecuta funciones y comandos específicos de la plataforma para ejecutar comandos del sistema en el servidor back-end, haciendo que los web shells no sean scripts multiplataforma. Entonces, el primer paso sería identificar qué lenguaje ejecuta la aplicación web.

Esto suele ser relativamente simple, ya que a menudo podemos ver la extensión de la página web en las URLs, lo que puede revelar el lenguaje de programación que ejecuta la aplicación web. Sin embargo, en ciertos frameworks web y lenguajes web, se utilizan `Web Routes` para mapear URLs a páginas web, en cuyo caso es posible que no se muestre la extensión de la página web. Además, la explotación de la carga de archivos también sería diferente, ya que nuestros archivos cargados pueden no ser directamente enrutables o accesibles.

Un método fácil para determinar qué lenguaje ejecuta la aplicación web es visitar la página `/index.ext`, donde sustituiríamos `ext` por varias extensiones web comunes, como `php`, `asp`, `aspx`, entre otras, para ver si alguna de ellas existe.

Por ejemplo, cuando visitamos nuestro ejercicio a continuación, vemos su URL como `http://SERVER_IP:PORT/`, ya que la página `index` suele estar oculta por defecto. Pero, si intentamos visitar `http://SERVER_IP:PORT/index.php`, obtendremos la misma página, lo que significa que esta es de hecho una aplicación web `PHP`. No necesitamos hacer esto manualmente, por supuesto, ya que podemos usar una herramienta como Burp Intruder para fuzzing de la extensión del archivo utilizando una [Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt) wordlist, como veremos en secciones posteriores. Sin embargo, este método puede no ser siempre preciso, ya que la aplicación web puede no utilizar páginas de índice o puede utilizar más de una extensión web.

Varias otras técnicas pueden ayudar a identificar las tecnologías que ejecutan la aplicación web, como usar la extensión [Wappalyzer](https://www.wappalyzer.com/), que está disponible para todos los navegadores principales. Una vez agregada a nuestro navegador, podemos hacer clic en su icono para ver todas las tecnologías que ejecutan la aplicación web:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_wappalyzer.jpg)

Como podemos ver, no solo la extensión nos dijo que la aplicación web se ejecuta en `PHP`, sino que también identificó el tipo y la versión del servidor web, el sistema operativo del back-end y otras tecnologías en uso. Estas extensiones son esenciales en el arsenal de un penetration tester web, aunque siempre es mejor conocer métodos manuales alternativos para identificar el framework web, como el método que discutimos anteriormente.

También podemos ejecutar escáneres web para identificar el framework web, como los escáneres de Burp/ZAP u otras herramientas de Web Vulnerability Assessment. Al final, una vez que identifiquemos el lenguaje que ejecuta la aplicación web, podemos cargar un script malicioso escrito en el mismo lenguaje para explotar la aplicación web y obtener control remoto sobre el servidor back-end.

---

## Vulnerability Identification

Ahora que hemos identificado el framework web que ejecuta la aplicación web y su lenguaje de programación, podemos probar si podemos cargar un archivo con la misma extensión. Como prueba inicial para identificar si podemos cargar archivos `PHP` arbitrarios, vamos a crear un script básico de `Hello World` para probar si podemos ejecutar código `PHP` con nuestro archivo cargado.

Para hacerlo, escribiremos `<?php echo "Hello HTB";?>` en `test.php`, y trataremos de cargarlo en la aplicación web:

`http://SERVER_IP:PORT/`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_upload_php.jpg)

El archivo parece haberse cargado correctamente, ya que recibimos un mensaje que dice `File successfully uploaded`, lo que significa que `la aplicación web no tiene ninguna validación de archivos en el back-end`. Ahora, podemos hacer clic en el botón `Download`, y la aplicación web nos llevará a nuestro archivo cargado:

`http://SERVER_IP:PORT/uploads/test.php`

![](https://academy.hackthebox.com/storage/modules/136/file_uploads_hello_htb.jpg)

Como podemos ver, la página imprime nuestro mensaje `Hello HTB`, lo que significa que la función `echo` se ejecutó para imprimir nuestra cadena, y ejecutamos con éxito código `PHP` en el servidor back-end. Si la página no pudiera ejecutar código PHP, veríamos nuestro código fuente impreso en la página.

En la siguiente sección, veremos cómo explotar esta vulnerabilidad para ejecutar código en el servidor back-end y tomar control sobre él.