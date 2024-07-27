Para entender eficazmente los ataques a los diferentes servicios, debemos observar cómo se pueden atacar estos servicios. Un concepto es un plan delineado que se aplica a proyectos futuros. Como ejemplo, podemos pensar en el concepto de construir una casa. Muchas casas tienen un sótano, cuatro paredes y un techo. La mayoría de los hogares se construyen de esta manera, y es un concepto que se aplica en todo el mundo. Los detalles más finos, como el material utilizado o el tipo de diseño, son flexibles y se pueden adaptar a deseos y circunstancias individuales. Este ejemplo muestra que un concepto necesita una categorización general (piso, paredes, techo).

En nuestro caso, necesitamos crear un concepto para los ataques a todos los posibles servicios y dividirlo en categorías que resuman todos los servicios pero dejen los métodos de ataque individuales.

Para explicar más claramente de lo que estamos hablando aquí, podemos intentar agrupar los servicios SSH, FTP, SMB y HTTP nosotros mismos y averiguar qué tienen en común estos servicios. Luego, necesitamos crear una estructura que nos permita identificar los puntos de ataque de estos diferentes servicios utilizando un único patrón.

Analizar las similitudes y crear plantillas de patrones que se ajusten a todos los casos concebibles no es un producto terminado, sino un proceso que hace que estas plantillas de patrones crezcan cada vez más. Por lo tanto, hemos creado una plantilla de patrón para este tema para que puedas enseñar y explicar mejor y más eficientemente el concepto detrás de los ataques.

### The Concept of Attacks

![](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

El concepto se basa en cuatro categorías que ocurren para cada vulnerabilidad. Primero, tenemos una `Source` que realiza la solicitud específica a un `Process` donde se desencadena la vulnerabilidad. Cada proceso tiene un conjunto específico de `Privileges` con los que se ejecuta. Cada proceso tiene una tarea con un objetivo específico o `Destination` para computar nuevos datos o reenviarlos. Sin embargo, las especificaciones individuales y únicas bajo estas categorías pueden diferir de un servicio a otro.

Cada tarea e información sigue un patrón específico, un ciclo, que hemos hecho deliberadamente lineal. Esto se debe a que el `Destination` no siempre sirve como una `Source` y, por lo tanto, no se trata como una fuente de una nueva tarea.

Para que cualquier tarea exista, necesita una idea, información (`Source`), un proceso planeado para ello (`Processes`), y un objetivo específico (`Destination`) que debe lograrse. Por lo tanto, la categoría de `Privileges` es necesaria para controlar el procesamiento de la información de manera apropiada.

---

## Source

Podemos generalizar `Source` como una fuente de información utilizada para la tarea específica de un proceso. Hay muchas maneras diferentes de pasar información a un proceso. La gráfica muestra algunos de los ejemplos más comunes de cómo se pasa la información a los procesos.

|**Information Source**|**Description**|
|---|---|
|`Code`|Esto significa que los resultados del código del programa ya ejecutado se utilizan como fuente de información. Estos pueden provenir de diferentes funciones de un programa.|
|`Libraries`|Una biblioteca es una colección de recursos del programa, incluidos datos de configuración, documentación, datos de ayuda, plantillas de mensajes, código preconstruido y subrutinas, clases, valores o especificaciones de tipo.|
|`Config`|Las configuraciones suelen ser valores estáticos o prescritos que determinan cómo el proceso procesa la información.|
|`APIs`|La interfaz de programación de aplicaciones (API) se utiliza principalmente como la interfaz de los programas para recuperar o proporcionar información.|
|`User Input`|Si un programa tiene una función que permite al usuario ingresar valores específicos que se utilizan para procesar la información en consecuencia, esta es la entrada manual de información por una persona.|

La fuente es, por lo tanto, la fuente que se explota para las vulnerabilidades. No importa qué protocolo se use porque las inyecciones de encabezados HTTP se pueden manipular manualmente, al igual que los desbordamientos de búfer. La fuente para esto puede, por lo tanto, categorizarse como `Code`. Así que echemos un vistazo más de cerca a la plantilla de patrón basada en una de las últimas vulnerabilidades críticas de las que la mayoría de nosotros hemos oído hablar.

### Log4j

Un gran ejemplo es la vulnerabilidad crítica de Log4j ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228)) que se publicó a finales de 2021. Log4j es un marco o `Library` utilizado para registrar mensajes de aplicaciones en Java y otros lenguajes de programación. Esta biblioteca contiene clases y funciones que otros lenguajes de programación pueden integrar. Para este propósito, se documenta la información, similar a un libro de registro. Además, el alcance de la documentación se puede configurar ampliamente. Como resultado, se ha convertido en un estándar dentro de muchos productos de software de código abierto y comercial. En este ejemplo, un atacante puede manipular el encabezado del agente de usuario HTTP e insertar una búsqueda JNDI como un comando destinado a la `library` de Log4j. En consecuencia, no se procesa el encabezado real del agente de usuario, como Mozilla 5.0, sino la búsqueda JNDI.

---

## Processes

El `Process` trata sobre el procesamiento de la información reenviada desde la fuente. Estos se procesan de acuerdo con la tarea prevista determinada por el código del programa. Para cada tarea, el desarrollador especifica cómo se procesa la información. Esto puede ocurrir utilizando clases con diferentes funciones, cálculos y bucles. La variedad de posibilidades para esto es tan diversa como el número de desarrolladores en el mundo. En consecuencia, la mayoría de las vulnerabilidades se encuentran en el código del programa ejecutado por el proceso.

|**Process Components**|**Description**|
|---|---|
|`PID`|El Process-ID (PID) identifica el proceso que se está iniciando o ya está en ejecución. Los procesos en ejecución ya tienen privilegios asignados y se inician nuevos en consecuencia.|
|`Input`|Esto se refiere a la entrada de información que podría ser asignada por un usuario o como resultado de una función programada.|
|`Data processing`|Las funciones codificadas de un programa dictan cómo se procesa la información recibida.|
|`Variables`|Las variables se utilizan como marcadores de posición para la información que diferentes funciones pueden procesar durante la tarea.|
|`Logging`|Durante el registro, ciertos eventos se documentan y, en la mayoría de los casos, se almacenan en un registro o un archivo. Esto significa que cierta información permanece en el sistema.|

### Log4j

El proceso de Log4j es registrar el agente de usuario como una cadena utilizando una función y almacenarla en el lugar designado. La vulnerabilidad en este proceso es la mala interpretación de la cadena, lo que lleva a la ejecución de una solicitud en lugar de registrar los eventos. Sin embargo, antes de profundizar en esta función, necesitamos hablar de los privilegios.

---

## Privileges

`Privileges` están presentes en cualquier sistema que controle procesos. Estos sirven como un tipo de permiso que determina qué tareas y acciones se pueden realizar en el sistema. En términos simples, se puede comparar con un boleto de autobús. Si usamos un boleto destinado a una región en particular, podremos usar el autobús y, de lo contrario, no. Estos privilegios (o figurativamente hablando, nuestros boletos) también se pueden usar para diferentes medios de transporte, como aviones, trenes, barcos y otros. En los sistemas informáticos, estos privilegios sirven como control y segmentación de acciones para las que se necesitan diferentes permisos, controlados por el sistema. Por lo tanto, los derechos se verifican en función de esta categorización cuando un proceso necesita cumplir su tarea. Si el proceso cumple con estos privilegios y condiciones, el sistema aprueba la acción solicitada. Podemos dividir estos privilegios en las siguientes áreas:

|**Privileges**|**Description**|
|---|---|
|`System`|Estos privilegios son los más altos que se pueden obtener, lo que permite cualquier modificación del sistema. En Windows, este tipo de privilegio se llama `SYSTEM`, y en Linux, se llama `root`.|
|`User`|Los privilegios de usuario son permisos que se han asignado a un usuario específico. Por razones de seguridad, a menudo se configuran usuarios separados para servicios particulares durante la instalación de distribuciones de Linux.|
|`Groups`|Los grupos son una categorización de al menos un usuario que tiene ciertos permisos para realizar acciones específicas.|
|`Policies`|Las políticas determinan la ejecución de comandos específicos de la aplicación, que también pueden aplicarse a usuarios individuales o agrupados y sus acciones.|
|`Rules`|Las reglas son los permisos para realizar acciones manejadas desde dentro de las propias aplicaciones.|

### Log4j

Lo que hizo que la vulnerabilidad de Log4j fuera tan peligrosa fueron los `Privileges` que la implementación trajo. Los registros a menudo se consideran sensibles porque pueden contener datos sobre el servicio, el propio sistema o incluso clientes. Por lo tanto, los registros generalmente se almacenan en ubicaciones a las que ningún usuario regular debería poder acceder. En consecuencia, la mayoría de las aplicaciones con la implementación de Log4j se ejecutaron con los privilegios de un administrador. El proceso en sí explotó la biblioteca manipulando el agente de usuario para que el proceso malinterpretara la fuente y llevara a la ejecución de código proporcionado por el usuario.

---

## Destination

Cada tarea tiene al menos un propósito y un objetivo que debe cumplirse

. Lógicamente, si faltaran cambios en cualquier conjunto de datos o no se almacenaran o reenviaran en ninguna parte, la tarea sería generalmente innecesaria. El resultado de dicha tarea se almacena en algún lugar o se reenvía a otro punto de procesamiento. Por lo tanto, hablamos aquí del `Destination` donde se realizarán los cambios. Tales puntos de procesamiento pueden apuntar a un proceso local o remoto. Por lo tanto, a nivel local, los archivos locales o los registros pueden ser modificados por el proceso o ser reenviados a otros servicios locales para su uso posterior. Sin embargo, esto no excluye la posibilidad de que el mismo proceso pueda reutilizar los datos resultantes también. Si el proceso se completa con el almacenamiento de datos o su reenvío, el ciclo que lleva a la finalización de la tarea se cierra.

|**Destination**|**Description**|
|---|---|
|`Local`|El área local es el entorno del sistema en el que ocurrió el proceso. Por lo tanto, los resultados y resultados de una tarea son procesados ​​por un proceso que incluye cambios en los conjuntos de datos o almacenamiento de los datos.|
|`Network`|El área de red es principalmente una cuestión de reenviar los resultados de un proceso a una interfaz remota. Esto puede ser una dirección IP y sus servicios o incluso redes enteras. Los resultados de tales procesos también pueden influir en la ruta bajo ciertas circunstancias.|

### Log4j

La mala interpretación del agente de usuario conduce a una búsqueda JNDI que se ejecuta como un comando desde el sistema con privilegios de administrador y consulta un servidor remoto controlado por el atacante, que en nuestro caso es el `Destination` en nuestro concepto de ataques. Esta consulta solicita una clase Java creada por el atacante y manipulada para sus propios fines. El código Java consultado dentro de la clase Java manipulada se ejecuta en el mismo proceso, lo que lleva a una vulnerabilidad de ejecución remota de código (`RCE`).

GovCERT.ch ha creado una excelente representación gráfica de la vulnerabilidad de Log4j que vale la pena examinar en detalle.

![](https://academy.hackthebox.com/storage/modules/116/log4jattack.png) Source: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

Este gráfico desglosa el ataque JNDI de Log4j basado en el `Concept of Attacks`.

### Initiation of the Attack

|**Step**|**Log4j**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|El atacante manipula el agente de usuario con un comando de búsqueda JNDI.|`Source`|
|`2.`|El proceso malinterpreta el agente de usuario asignado, lo que lleva a la ejecución del comando.|`Process`|
|`3.`|El comando de búsqueda JNDI se ejecuta con privilegios de administrador debido a los permisos de registro.|`Privileges`|
|`4.`|Este comando de búsqueda JNDI apunta al servidor creado y preparado por el atacante, que contiene una clase Java maliciosa con comandos diseñados por el atacante.|`Destination`|

Es cuando el ciclo comienza de nuevo, pero esta vez para obtener acceso remoto al sistema objetivo.

### Trigger Remote Code Execution

|**Step**|**Log4j**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|Después de que se recupera la clase Java maliciosa del servidor del atacante, se utiliza como fuente para más acciones en el siguiente proceso.|`Source`|
|`6.`|Luego, se lee el código malicioso de la clase Java, que en muchos casos ha llevado al acceso remoto al sistema.|`Process`|
|`7.`|El código malicioso se ejecuta con privilegios de administrador debido a los permisos de registro.|`Privileges`|
|`8.`|El código conduce a través de la red de regreso al atacante con las funciones que permiten al atacante controlar el sistema de forma remota.|`Destination`|

Finalmente, vemos un patrón que podemos usar repetidamente para nuestros ataques. Esta plantilla de patrón se puede utilizar para analizar y entender exploits y depurar nuestros propios exploits durante el desarrollo y las pruebas. Además, esta plantilla de patrón también se puede aplicar al análisis de código fuente, lo que nos permite verificar ciertas funcionalidades y comandos en nuestro código paso a paso. Finalmente, también podemos pensar categóricamente sobre los peligros de cada tarea individualmente.