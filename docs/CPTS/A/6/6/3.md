Antes de sumergirnos en los conceptos y ejercicios de aspx shell, debemos tomarnos el tiempo para cubrir un recurso de aprendizaje que puede ayudar a reforzar la mayoría de los conceptos cubiertos aquí en HTB Academy. Ocasionalmente puede ser un desafío visualizar un concepto utilizando solo un método de aprendizaje. Es bueno complementar la lectura con ver demostraciones y realizar prácticas, como hemos estado haciendo hasta ahora. Los tutoriales en video pueden ser una forma increíble de aprender conceptos, además de que se pueden consumir casualmente (comiendo, acostado en la cama, sentado en el sofá, etc.). Un gran recurso para usar en el aprendizaje es el sitio de blog de `IPPSEC` [ippsec.rocks](https://ippsec.rocks/?#). El sitio es una herramienta de aprendizaje poderosa. Tomemos, por ejemplo, el concepto de web shells. Podemos usar su sitio para escribir el concepto que queremos aprender, como aspx.

![IPPSEC Rocks](https://academy.hackthebox.com/storage/modules/115/ippsecrocks.png)

Su sitio rastrea las descripciones de cada uno de los videos que ha publicado en YouTube y recomienda una marca de tiempo asociada con esa palabra clave. Cuando hacemos clic en uno de los enlaces, nos llevará a esa sección del video donde se demuestra este concepto. Es como un motor de búsqueda para aprender habilidades de hacking. Para obtener una buena comprensión básica de lo que es una aspx web shell, veamos la breve parte de la demostración de IPPSEC de la caja retirada [Cereal](https://www.youtube.com/watch?v=04ZBIioD5pA&t=4677s). El enlace debería comenzar en la marca de 1 hora y 17 minutos. Observa desde la marca de 1 hora y 17 minutos hasta la marca de 1 hora y 20 minutos.

Notaremos que subió el archivo a través de FTP y luego navegó al archivo usando el navegador web. Esto le dio la capacidad de enviar comandos y recibir resultados del sistema operativo Windows subyacente.

`How does aspx work?`

---
## ASPX Explained

`Active Server Page Extended` (`ASPX`) es un tipo/extensión de archivo escrito para el [Microsoft's ASP.NET Framework](https://docs.microsoft.com/en-us/aspnet/overview). En un servidor web que ejecuta el framework ASP.NET, se pueden generar páginas de formularios web para que los usuarios ingresen datos. En el lado del servidor, la información se convertirá en HTML. Podemos aprovechar esto utilizando una web shell basada en ASPX para controlar el sistema operativo Windows subyacente. Vamos a presenciar esto de primera mano utilizando la Antak Webshell.

---
## Antak Webshell

Antak es una web shell construida en ASP.Net incluida en el [Nishang project](https://github.com/samratashok/nishang). Nishang es un conjunto de herramientas ofensivas de PowerShell que puede proporcionar opciones para cualquier parte de tu pentest. Como nos estamos enfocando en aplicaciones web por el momento, mantengamos nuestra atención en `Antak`. Antak utiliza PowerShell para interactuar con el host, lo que la hace ideal para adquirir una web shell en un servidor Windows. La interfaz de usuario incluso tiene un tema similar a PowerShell. Es hora de profundizar y experimentar con Antak.

---
## Working with Antak

Los archivos de Antak se pueden encontrar en el directorio `/usr/share/nishang/Antak-WebShell`.

```r
ls /usr/share/nishang/Antak-WebShell

antak.aspx  Readme.md
```

La web shell Antak funciona como una consola de PowerShell. Sin embargo, ejecutará cada comando como un nuevo proceso. También puede ejecutar scripts en memoria y codificar comandos que envíes. Como web shell, Antak es una herramienta bastante poderosa.

---

## Antak Demonstration

Ahora que entendemos qué es Antak y cómo funciona, pongámoslo a prueba contra la misma aplicación web de la sección de Laudanum. Si deseas seguir esta demostración, necesitarás agregar una entrada en tu archivo `/etc/hosts` en tu VM de ataque o dentro de Pwnbox para el host que estamos atacando. Esa entrada debería leer: `<target ip> status.inlanefreight.local`. Una vez hecho esto, siempre que estés en la VPN o usando Pwnbox, también puedes jugar y explorar esta demostración.

### Move a Copy for Modification

```r
cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx
```

Asegúrate de establecer credenciales para acceder a la web shell. Modifica la `line 14`, agregando un usuario (flecha verde) y contraseña (flecha naranja). Esto entra en juego cuando navegas a tu web shell, al igual que con Laudanum. Esto puede ayudar a hacer tus operaciones más seguras al asegurarte de que personas aleatorias no puedan simplemente tropezar y usar la shell. Puede ser prudente eliminar el arte ASCII y los comentarios del archivo. Estos elementos en un payload a menudo son firmados y pueden alertar a los defensores/AV sobre lo que estás haciendo.

### Modify the Shell for Use

![image](https://academy.hackthebox.com/storage/modules/115/antak-changes.png)

Para el propósito de demostrar la herramienta, la estamos subiendo al mismo portal de estado que usamos para Laudanum. Ese host era un host de Windows, por lo que nuestra shell debería funcionar bien con PowerShell. Sube el archivo y luego navega a la página para usarlo. Te dará un aviso de usuario y contraseña. Recuerda, con esta aplicación web, los archivos se almacenan en el directorio `\\files\`. Cuando navegues al archivo `upload.aspx`, deberías ver un aviso como el que tenemos a continuación.

### Shell Success

![image](https://academy.hackthebox.com/storage/modules/115/antak-creds-prompt.png)

Como se ve en la siguiente imagen, se nos otorgará acceso si nuestras credenciales se ingresan correctamente.

![image](https://academy.hackthebox.com/storage/modules/115/antak-success.png)

Ahora que tenemos acceso, podemos utilizar comandos de PowerShell para navegar y tomar acciones contra el host. Podemos emitir comandos básicos desde la ventana de la shell de Antak, subir y descargar archivos, codificar y ejecutar scripts, y mucho más (flecha verde a continuación). Esta es una excelente manera de utilizar una Webshell para entregarnos una devolución a nuestra plataforma de comando y control. Podríamos subir el payload a través de la función de carga o usar una línea de comando de PowerShell para descargar y ejecutar la shell por nosotros. Si te sientes inseguro sobre dónde comenzar, emite el comando `help` en la ventana del prompt (flecha naranja) a continuación.

### Issuing Commands

![image](https://academy.hackthebox.com/storage/modules/115/antak-commands.png)