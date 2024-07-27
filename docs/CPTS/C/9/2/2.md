Hasta ahora, hemos encontrado que la aplicación web `Host Checker` es potencialmente vulnerable a inyecciones de comandos y hemos discutido varios métodos de inyección que podríamos utilizar para explotar la aplicación web. Así que, comencemos nuestros intentos de inyección de comandos con el operador de punto y coma (`;`).

---

## Injecting Our Command

Podemos agregar un punto y coma después de nuestra IP de entrada `127.0.0.1`, y luego anexar nuestro comando (por ejemplo, `whoami`), de manera que el payload final que usaremos es (`127.0.0.1; whoami`), y el comando final a ejecutar sería:


```r
ping -c 1 127.0.0.1; whoami
```

Primero, intentemos ejecutar el comando anterior en nuestra VM de Linux para asegurarnos de que se ejecute:



```r
21y4d@htb[/htb]$ ping -c 1 127.0.0.1; whoami

PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=1.03 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.034/1.034/1.034/0.000 ms
21y4d
```

Como podemos ver, el comando final se ejecuta con éxito, y obtenemos la salida de ambos comandos (como se mencionó en la tabla anterior para `;`). Ahora, podemos intentar usar nuestro payload anterior en la aplicación web `Host Checker`: ![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_injection.jpg)

Como podemos ver, la aplicación web rechazó nuestra entrada, ya que parece aceptar solo entradas en formato de IP. Sin embargo, por la apariencia del mensaje de error, parece originarse en el front-end y no en el back-end. Podemos verificar esto con las `Firefox Developer Tools` haciendo clic en `[CTRL + SHIFT + E]` para mostrar la pestaña de red y luego haciendo clic nuevamente en el botón `Check`:

![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_injection_network.jpg)

Como podemos ver, no se realizaron nuevas solicitudes de red cuando hicimos clic en el botón `Check`, pero recibimos un mensaje de error. Esto indica que la `validación de entrada del usuario está ocurriendo en el front-end`.

Esto parece ser un intento de evitar que enviemos payloads maliciosos al permitir solo entradas de usuario en formato de IP. Sin embargo, es muy común que los desarrolladores solo realicen validaciones de entrada en el front-end sin validar o sanitizar la entrada en el back-end. Esto ocurre por varias razones, como tener dos equipos diferentes trabajando en el front-end/back-end o confiar en la validación del front-end para prevenir payloads maliciosos.

Sin embargo, como veremos, las validaciones del front-end generalmente no son suficientes para prevenir inyecciones, ya que pueden ser muy fácilmente eludidas enviando solicitudes HTTP personalizadas directamente al back-end.

---

## Bypassing Front-End Validation

El método más sencillo para personalizar las solicitudes HTTP que se envían al servidor back-end es usar un proxy web que pueda interceptar las solicitudes HTTP enviadas por la aplicación. Para hacerlo, podemos iniciar `Burp Suite` o `ZAP` y configurar Firefox para que dirija el tráfico a través de ellos. Luego, podemos habilitar la función de interceptar del proxy, enviar una solicitud estándar desde la aplicación web con cualquier IP (por ejemplo, `127.0.0.1`), y enviar la solicitud HTTP interceptada a `repeater` haciendo clic en `[CTRL + R]`, y deberíamos tener la solicitud HTTP para personalización:

### Burp POST Request

![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_repeater_1.jpg)

Ahora podemos personalizar nuestra solicitud HTTP y enviarla para ver cómo la maneja la aplicación web. Comenzaremos usando el mismo payload anterior (`127.0.0.1; whoami`). También deberíamos URL-encodear nuestro payload para asegurarnos de que se envíe como pretendemos. Podemos hacerlo seleccionando el payload y luego haciendo clic en `[CTRL + U]`. Finalmente, podemos hacer clic en `Send` para enviar nuestra solicitud HTTP:

### Burp POST Request

![Basic Injection](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_repeater_2.jpg)

Como podemos ver, la respuesta que obtuvimos esta vez contiene la salida del comando `ping` y el resultado del comando `whoami`, lo que significa que `iniciamos exitosamente nuestro nuevo comando`.