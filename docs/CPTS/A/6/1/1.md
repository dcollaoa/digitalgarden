Una `shell` es un programa que proporciona al usuario de una computadora una interfaz para ingresar instrucciones en el sistema y ver la salida de texto (Bash, Zsh, cmd y PowerShell, por ejemplo). Como penetration testers y profesionales de la seguridad de la información, una shell es a menudo el resultado de explotar una vulnerabilidad o eludir medidas de seguridad para obtener acceso interactivo a un host. Es posible que hayamos oído o leído las siguientes frases utilizadas por personas que discuten una intervención o una sesión de práctica reciente:

- `"I caught a shell."`
- `"I popped a shell!"`
- `"I dropped into a shell!"`
- `"I'm in!"`

Típicamente, estas frases se traducen en la comprensión de que esta persona ha explotado con éxito una vulnerabilidad en un sistema y ha podido obtener control remoto de la shell en el sistema operativo de la computadora objetivo. Este es un objetivo común que un penetration tester tendrá al intentar acceder a una máquina vulnerable. Notaremos que la mayor parte de este módulo se centrará en lo que viene después de la enumeración e identificación de exploits prometedores.

---

## Why Get a Shell?

Recuerda que la shell nos da acceso directo al `OS`, `system commands` y `file system`. Entonces, si obtenemos acceso, podemos comenzar a enumerar el sistema en busca de vectores que nos permitan escalar privilegios, pivotar, transferir archivos y más. Si no establecemos una sesión de shell, estamos bastante limitados en cuanto a lo lejos que podemos llegar en una máquina objetivo.

Establecer una shell también nos permite mantener la persistencia en el sistema, dándonos más tiempo para trabajar. Puede hacer que sea más fácil usar nuestras `attack tools`, `exfiltrate data`, `gather`, `store` y `document` todos los detalles de nuestro ataque, como veremos en las demostraciones siguientes. Es importante notar que establecer una shell casi siempre significa que estamos accediendo a la CLI del OS, y esto puede hacernos más difíciles de notar que si estuviéramos accediendo remotamente a una shell gráfica a través de [VNC](https://en.wikipedia.org/wiki/Virtual_Network_Computing) o [RDP](https://www.cloudflare.com/learning/access-management/what-is-the-remote-desktop-protocol/). Otro beneficio significativo de ser hábiles con las interfaces de línea de comandos es que pueden ser `harder to detect than graphical shells`, `faster to navigate the OS` y `easier to automate our actions`. Vemos las shells a través de la lente de las siguientes perspectivas a lo largo de este módulo:

|**Perspective**|**Description**|
|---|---|
|`Computing`|El entorno de usuario basado en texto que se utiliza para administrar tareas y enviar instrucciones en una PC. Piensa en Bash, Zsh, cmd y PowerShell.|
|`Exploitation` `&` `Security`|Una shell es a menudo el resultado de explotar una vulnerabilidad o eludir medidas de seguridad para obtener acceso interactivo a un host. Un ejemplo sería desencadenar [EternalBlue](https://www.cisecurity.org/wp-content/uploads/2019/01/Security-Primer-EternalBlue.pdf) en un host de Windows para obtener acceso al cmd-prompt en un host de forma remota.|
|`Web`|Esto es un poco diferente. Una web shell es muy similar a una shell estándar, excepto que explota una vulnerabilidad (a menudo la capacidad de cargar un archivo o script) que proporciona al atacante una forma de emitir instrucciones, leer y acceder a archivos, y potencialmente realizar acciones destructivas en el host subyacente. El control de la web shell a menudo se realiza llamando al script dentro de una ventana del navegador.|

---

## Payloads Deliver us Shells

Dentro de la industria de IT en su conjunto, un `payload` se puede definir de varias maneras:

- `Networking`: La porción de datos encapsulada de un paquete que atraviesa redes informáticas modernas.
- `Basic Computing`: Un payload es la porción de un conjunto de instrucciones que define la acción a tomar. Información de encabezados y protocolos eliminada.
- `Programming`: La porción de datos referenciada o transportada por la instrucción del lenguaje de programación.
- `Exploitation & Security`: Un payload es `code` diseñado con la intención de explotar una vulnerabilidad en un sistema informático. El término payload puede describir varios tipos de malware, incluidos, entre otros, ransomware.

En este módulo, trabajaremos con muchos tipos diferentes de `payloads` y métodos de entrega en el contexto de otorgarnos acceso a un host y establecer sesiones de `remote shell` con sistemas vulnerables.