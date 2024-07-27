Al discutir las últimas vulnerabilidades, centraremos esta sección y las siguientes en uno de los ataques previamente mostrados y lo presentaremos de la manera más simple posible sin entrar en demasiados detalles técnicos. Esto debería ayudarnos a facilitar el concepto del ataque a través de un ejemplo relacionado con un servicio específico para obtener una mejor comprensión.

En este caso, discutiremos la vulnerabilidad `CoreFTP antes de la versión 727` asignada a [CVE-2022-22836](https://nvd.nist.gov/vuln/detail/CVE-2022-22836). Esta vulnerabilidad es para un servicio FTP que no procesa correctamente la solicitud `HTTP PUT` y conduce a una vulnerabilidad de `directory traversal`/`path traversal` autenticada y `arbitrary file write`. Esta vulnerabilidad nos permite escribir archivos fuera del directorio al que el servicio tiene acceso.

---

## The Concept of the Attack

Este servicio FTP utiliza una solicitud HTTP `POST` para cargar archivos. Sin embargo, el servicio CoreFTP permite una solicitud HTTP `PUT`, que podemos usar para escribir contenido en archivos. Veamos el ataque basado en nuestro concepto. El [exploit](https://www.exploit-db.com/exploits/50652) para este ataque es relativamente sencillo, basado en un solo comando `cURL`.

### CoreFTP Exploitation

```r
curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

Creamos una solicitud HTTP `PUT` en bruto (`-X PUT`) con autenticación básica (`--basic -u <username>:<password>`), la ruta para el archivo (`--path-as-is https://<IP>/../../../../../whoops`), y su contenido (`--data-binary "PoC."`) con este comando. Además, especificamos el encabezado del host (`-H "Host: <IP>"`) con la dirección IP de nuestro sistema objetivo.

### The Concept of Attacks

![](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

En resumen, el proceso real malinterpreta la entrada del usuario de la ruta. Esto lleva a que se eluda el acceso a la carpeta restringida. Como resultado, los permisos de escritura en la solicitud HTTP `PUT` no están adecuadamente controlados, lo que nos permite crear los archivos que queremos fuera de las carpetas autorizadas. Sin embargo, omitiremos la explicación del proceso de `Basic Auth` y pasaremos directamente a la primera parte del exploit.

### Directory Traversal

|**Step**|**Directory Traversal**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|El usuario especifica el tipo de solicitud HTTP con el contenido del archivo, incluyendo caracteres de escape para salir del área restringida.|`Source`|
|`2.`|El tipo de solicitud HTTP cambiado, el contenido del archivo y la ruta ingresada por el usuario son tomados y procesados por el proceso.|`Process`|
|`3.`|La aplicación verifica si el usuario está autorizado para estar en la ruta especificada. Dado que las restricciones solo se aplican a una carpeta específica, todos los permisos otorgados a ella se eluden al salir de esa carpeta utilizando la `directory traversal`.|`Privileges`|
|`4.`|El destino es otro proceso que tiene la tarea de escribir el contenido especificado del usuario en el sistema local.|`Destination`|

Hasta este punto, hemos eludido las restricciones impuestas por la aplicación utilizando los caracteres de escape (`../../../../`) y llegamos a la segunda parte, donde el proceso escribe el contenido que especificamos en un archivo de nuestra elección. Es cuando el ciclo comienza de nuevo, pero esta vez para escribir contenido en el sistema objetivo.

### Arbitrary File Write

|**Step**|**Arbitrary File Write**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|La misma información que ingresó el usuario se usa como la fuente. En este caso, el nombre del archivo (`whoops`) y el contenido (`--data-binary "PoC."`).|`Source`|
|`6.`|El proceso toma la información especificada y procede a escribir el contenido deseado en el archivo especificado.|`Process`|
|`7.`|Dado que todas las restricciones se eludieron durante la vulnerabilidad de `directory traversal`, el servicio aprueba la escritura del contenido en el archivo especificado.|`Privileges`|
|`8.`|El nombre del archivo especificado por el usuario (`whoops`) con el contenido deseado (`"PoC."`) ahora sirve como el destino en el sistema local.|`Destination`|

Después de completar la tarea, podremos encontrar este archivo con el contenido correspondiente en el sistema objetivo.

### Target System

```r
C:\> type C:\whoops

PoC.
```