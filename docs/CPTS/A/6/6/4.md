Hypertext Preprocessor o [PHP](https://www.php.net/) es un lenguaje de scripting de propósito general de código abierto que se utiliza típicamente como parte de una pila web que alimenta un sitio web. En el momento de escribir esto (octubre de 2021), PHP es el `server-side programming language` más popular. Según una [encuesta reciente](https://w3techs.com/technologies/details/pl-php) realizada por W3Techs, "PHP es utilizado por el `78.6%` de todos los sitios web cuyo lenguaje de programación del lado del servidor conocemos".

Consideremos un ejemplo práctico de completar los campos de cuenta de usuario y contraseña en un formulario web de inicio de sesión.

### PHP Login Page

![image](https://academy.hackthebox.com/storage/modules/115/rconfig.png)

¿Recuerdas el servidor rConfig de una sección anterior en este módulo? Usa PHP. Podemos ver un archivo `login.php`. Entonces, cuando seleccionamos el botón de inicio de sesión después de completar el campo de Nombre de Usuario y Contraseña, esa información se procesa del lado del servidor utilizando PHP. Saber que un servidor web está utilizando PHP nos da a los pentesters una pista de que podríamos obtener una web shell basada en PHP en este sistema. Vamos a trabajar este concepto de manera práctica.

---

## Hands-on With a PHP-Based Web Shell.

Dado que PHP procesa código y comandos del lado del servidor, podemos usar payloads preescritos para obtener una shell a través del navegador o iniciar una sesión de reverse shell con nuestra caja de ataque. En este caso, aprovecharemos la vulnerabilidad en rConfig 3.9.6 para subir manualmente una web shell PHP e interactuar con el host Linux subyacente. Además de toda la funcionalidad mencionada anteriormente, rConfig permite a los administradores agregar dispositivos de red y categorizarlos por proveedor. Inicia sesión en rConfig con las credenciales predeterminadas (admin:admin), luego navega a `Devices` > `Vendors` y haz clic en `Add Vendor`.

### Vendors Tab

![image](https://academy.hackthebox.com/storage/modules/115/vendors_tab.png)

Usaremos [WhiteWinterWolf's PHP Web Shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell). Podemos descargar esto o copiar y pegar el código fuente en un archivo `.php`. Ten en cuenta que el tipo de archivo es significativo, como pronto veremos. Nuestro objetivo es subir la web shell PHP a través del botón `browse` del logotipo del proveedor. Intentar hacer esto inicialmente fallará ya que rConfig está comprobando el tipo de archivo. Solo permitirá subir tipos de archivos de imagen (.png, .jpg, .gif, etc.). Sin embargo, podemos eludir esto utilizando `Burp Suite`.

Inicia Burp Suite, navega al menú de configuración de red del navegador y completa la configuración del proxy. `127.0.0.1` irá en el campo de dirección IP, y `8080` irá en el campo de puerto para asegurarnos de que todas las solicitudes pasen a través de Burp (recuerda que Burp actúa como el proxy web).

### Proxy Settings

![image](https://academy.hackthebox.com/storage/modules/115/proxy_settings.png)

Nuestro objetivo es cambiar el `content-type` para eludir la restricción de tipo de archivo en la carga de archivos para que se "presente" como el logotipo del proveedor y podamos navegar a ese archivo y tener nuestra web shell.

---

## Bypassing the File Type Restriction

Con Burp abierto y la configuración del proxy de nuestro navegador configurada correctamente, ahora podemos subir la web shell PHP. Haz clic en el botón de búsqueda, navega hasta donde esté almacenado nuestro archivo .php en nuestra caja de ataque, selecciona abrir y `Save` (es posible que debamos aceptar el certificado de PortSwigger). Parecerá que la página web se está colgando, pero eso es solo porque necesitamos decirle a Burp que reenvíe las solicitudes HTTP. Reenvía las solicitudes hasta que veas la solicitud POST que contiene nuestra carga de archivo. Se verá así:

### Post Request

![Burp](https://academy.hackthebox.com/storage/modules/115/burp.png)

Como se mencionó en una sección anterior, notarás que algunos payloads tienen comentarios del autor que explican el uso, proporcionan agradecimientos y enlaces a blogs personales. Esto puede delatarnos, por lo que no siempre es mejor dejar los comentarios en su lugar. Cambiaremos Content-type de `application/x-php` a `image/gif`. Esto "engañará" al servidor y nos permitirá subir el archivo .php, eludiendo la restricción de tipo de archivo. Una vez que hagamos esto, podemos seleccionar `Forward` dos veces, y el archivo se enviará. Podemos apagar el interceptor de Burp ahora y volver al navegador para ver los resultados.

### Vendor Added

![Burp](https://academy.hackthebox.com/storage/modules/115/added_vendor.png)

El mensaje: 'Added new vendor NetVen to Database' nos indica que nuestra carga de archivo fue exitosa. También podemos ver la entrada del proveedor NetVen con el logotipo que muestra un trozo de papel rasgado. Esto significa que rConfig no reconoció el tipo de archivo como una imagen, por lo que predeterminó esa imagen. Ahora podemos intentar usar nuestra web shell. Usando el navegador, navega a este directorio en el servidor rConfig:

`/images/vendor/connect.php`

Esto ejecuta el payload y nos proporciona una sesión shell no interactiva completamente en el navegador, permitiéndonos ejecutar comandos en el sistema operativo subyacente.

### Webshell Success

![image](https://academy.hackthebox.com/storage/modules/115/web_shell_now.png)

---

## Considerations when Dealing with Web Shells

Al utilizar web shells, considera los siguientes problemas potenciales que pueden surgir durante tu proceso de pruebas de penetración:

- Las aplicaciones web a veces eliminan automáticamente los archivos después de un período de tiempo predefinido
- Interactividad limitada con el sistema operativo en términos de navegación por el sistema de archivos, descarga y carga de archivos, encadenamiento de comandos juntos puede no funcionar (por ejemplo, `whoami && hostname`), ralentizando el progreso, especialmente al realizar enumeraciones
- Potencial inestabilidad a través de una web shell no interactiva
- Mayor probabilidad de dejar pruebas de que tuvimos éxito en nuestro ataque

Dependiendo del tipo de compromiso (por ejemplo, una evaluación evasiva de caja negra), es posible que necesitemos intentar pasar desapercibidos y `cover our tracks`. A menudo estamos ayudando a nuestros clientes a probar sus capacidades para detectar una amenaza en vivo, por lo que deberíamos emular tanto como sea posible los métodos que un atacante malicioso podría intentar, incluyendo intentar operar de manera sigilosa. Esto ayudará a nuestro cliente y nos salvará a largo plazo de que se descubran archivos después de que termine el período de compromiso. En la mayoría de los casos, al intentar obtener una sesión shell con un objetivo, sería prudente establecer una reverse shell y luego eliminar el payload ejecutado. También debemos documentar cada método que intentemos, lo que funcionó y lo que no funcionó, e incluso los nombres de los payloads y archivos que intentamos usar. Podríamos incluir un sha1sum o hash MD5 del nombre del archivo, ubicaciones de carga en nuestros informes como prueba, y proporcionar atribución.

`Now let's test our understanding with some challenge questions`.