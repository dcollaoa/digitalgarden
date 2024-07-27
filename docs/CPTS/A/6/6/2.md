Laudanum es un repositorio de archivos listos para usar que pueden ser inyectados en una víctima para recibir acceso a través de una reverse shell, ejecutar comandos en el host víctima directamente desde el navegador y más. El repositorio incluye archivos inyectables para muchos lenguajes de aplicaciones web diferentes, incluidos `asp, aspx, jsp, php` y más. Esto es un básico para cualquier pentest. Si estás usando tu propia VM, Laudanum está incorporado en Parrot OS y Kali por defecto. Para cualquier otra distribución, probablemente necesitarás descargar una copia para usar. Puedes obtenerla [aquí](https://github.com/jbarcia/Web-Shells/tree/master/laudanum). Vamos a examinar Laudanum y ver cómo funciona.

---

## Working with Laudanum

Los archivos de Laudanum se pueden encontrar en el directorio `/usr/share/laudanum`. Para la mayoría de los archivos dentro de Laudanum, puedes copiarlos tal cual y colocarlos donde los necesites en la víctima para ejecutarlos. Para archivos específicos como las shells, debes editar el archivo primero para insertar la dirección IP de tu host `attacking` para asegurarte de que puedas acceder a la web shell o recibir una devolución en caso de que uses una reverse shell. Antes de usar los diferentes archivos, asegúrate de leer el contenido y los comentarios para tomar las acciones adecuadas.

---

## Laudanum Demonstration

Ahora que entendemos qué es Laudanum y cómo funciona, veamos una aplicación web que hemos encontrado en nuestro entorno de laboratorio y veamos si podemos ejecutar una web shell. Si deseas seguir esta demostración, necesitarás agregar una entrada en tu archivo `/etc/hosts` en tu VM de ataque o dentro de Pwnbox para el host que estamos atacando. Esa entrada debería leer: `<target ip> status.inlanefreight.local`. Una vez hecho esto, puedes jugar y explorar esta demostración siempre que estés en la VPN o usando Pwnbox.

### Move a Copy for Modification

```r
cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
```

Agrega tu dirección IP a la variable `allowedIps` en la línea `59`. Haz cualquier otro cambio que desees. Puede ser prudente eliminar el arte ASCII y los comentarios del archivo. Estos elementos en un payload a menudo son firmados y pueden alertar a los defensores/AV sobre lo que estás haciendo.

### Modify the Shell for Use

![image](https://academy.hackthebox.com/storage/modules/115/modify-shell.png)

Estamos aprovechando la función de carga en la parte inferior de la página de estado (`Green Arrow`) para que esto funcione. Selecciona tu archivo shell y presiona cargar. Si tiene éxito, debería imprimir la ruta donde se guardó el archivo (`Yellow Arrow`). Usa la función de carga. El éxito imprime dónde fue el archivo, navega hasta él.

### Take Advantage of the Upload Function

![image](https://academy.hackthebox.com/storage/modules/115/laud-upload.png)

Una vez que la carga sea exitosa, necesitarás navegar a tu web shell para utilizar sus funciones. La imagen a continuación nos muestra cómo hacerlo. Como se ve en la última imagen, nuestra shell se subió al directorio `\\files\` y el nombre se mantuvo igual. Esto no siempre será el caso. Puedes encontrarte con algunas implementaciones que aleatorizan los nombres de archivo en la carga, que no tienen un directorio de archivos público o cualquier otra cantidad de posibles salvaguardias. Por ahora, tenemos suerte de que no sea el caso. Con esta aplicación web en particular, nuestro archivo fue a `status.inlanefreight.local\\files\demo.aspx` y requerirá que busquemos la carga usando ese \ en el camino en lugar de / como es normal. Una vez que hagas esto, tu navegador lo limpiará en tu ventana de URL para que aparezca como `status.inlanefreight.local//files/demo.aspx`.

### Navigate to Our Shell

![image](https://academy.hackthebox.com/storage/modules/115/laud-nav.png)

Ahora podemos utilizar la shell de Laudanum que subimos para emitir comandos al host. Podemos ver en el ejemplo que se ejecutó el comando `systeminfo`.

### Shell Success

![image](https://academy.hackthebox.com/storage/modules/115/laud-success.png)