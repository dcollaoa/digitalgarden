Una reciente vulnerabilidad significativa que afectó al protocolo SMB fue llamada [SMBGhost](https://arista.my.site.com/AristaCommunity/s/article/SMBGhost-Wormable-Vulnerability-Analysis-CVE-2020-0796) con el [CVE-2020-0796](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796). La vulnerabilidad consistía en un mecanismo de compresión de la versión SMB v3.1.1, lo que hacía que las versiones de Windows 10 1903 y 1909 fueran vulnerables a un ataque por parte de un atacante no autenticado. La vulnerabilidad permitía al atacante obtener ejecución remota de código (`RCE`) y acceso completo al sistema objetivo remoto.

No discutiremos la vulnerabilidad en detalle en esta sección, ya que una explicación muy profunda requiere experiencia en ingeniería inversa y conocimientos avanzados de CPU, kernel y desarrollo de exploits. En su lugar, solo nos centraremos en el concepto del ataque porque, incluso con exploits y vulnerabilidades más complicadas, el concepto sigue siendo el mismo.

---

## The Concept of the Attack

En términos simples, esta es una vulnerabilidad de [integer overflow](https://en.wikipedia.org/wiki/Integer_overflow) en una función de un controlador SMB que permite sobrescribir comandos del sistema mientras se accede a la memoria. Un integer overflow resulta de una CPU que intenta generar un número mayor que el valor requerido para el espacio de memoria asignado. Las operaciones aritméticas siempre pueden devolver valores inesperados, lo que resulta en un error. Un ejemplo de integer overflow puede ocurrir cuando un programador no permite que ocurra un número negativo. En este caso, un integer overflow ocurre cuando una variable realiza una operación que resulta en un número negativo, y la variable se devuelve como un entero positivo. Esta vulnerabilidad ocurrió porque, en ese momento, la función carecía de comprobaciones de límites para manejar el tamaño de los datos enviados en el proceso de negociación de la sesión SMB.

Para aprender más sobre técnicas y vulnerabilidades de buffer overflow, revisa los módulos [Stack-Based Buffer Overflows on Linux x86](https://academy.hackthebox.com/course/preview/stack-based-buffer-overflows-on-linux-x86) y [Stack-Based Buffer Overflows on Windows x86](https://academy.hackthebox.com/course/preview/stack-based-buffer-overflows-on-windows-x86). Estos profundizan en los conceptos básicos de cómo el buffer puede ser sobrescrito y manejado por el atacante.

### The Concept of Attacks

![Concepto de Ataques](https://academy.hackthebox.com/storage/modules/116/attack_concept2.png)

La vulnerabilidad ocurre mientras se procesa un mensaje comprimido malformado después de las `Negotiate Protocol Responses`. Si el servidor SMB permite solicitudes (a través de TCP/445), la compresión generalmente es compatible, donde el servidor y el cliente establecen los términos de comunicación antes de que el cliente envíe más datos. Supongamos que los datos transmitidos exceden los límites de la variable entera debido a la cantidad excesiva de datos. En ese caso, estas partes se escriben en el buffer, lo que lleva a sobrescribir las instrucciones posteriores de la CPU e interrumpe la ejecución normal o planificada del proceso. Estos conjuntos de datos pueden estructurarse de manera que las instrucciones sobrescritas se reemplacen con las nuestras, y así forzamos a la CPU (y por lo tanto también al proceso) a realizar otras tareas e instrucciones.

### Initiation of the Attack

|**Step**|**SMBGhost**|**Concept of Attacks - Category**|
|---|---|---|
|`1.`|El cliente envía una solicitud manipulada por el atacante al servidor SMB.|`Source`|
|`2.`|Los paquetes comprimidos enviados se procesan según las respuestas del protocolo negociado.|`Process`|
|`3.`|Este proceso se realiza con los privilegios del sistema o al menos con los privilegios de un administrador.|`Privileges`|
|`4.`|El proceso local se usa como destino, el cual debe procesar estos paquetes comprimidos.|`Destination`|

Aquí es cuando el ciclo comienza de nuevo, pero esta vez para obtener acceso remoto al sistema objetivo.

### Trigger Remote Code Execution

|**Step**|**SMBGhost**|**Concept of Attacks - Category**|
|---|---|---|
|`5.`|Las fuentes utilizadas en el segundo ciclo son del proceso anterior.|`Source`|
|`6.`|En este proceso, ocurre el integer overflow al reemplazar el buffer sobrescrito con las instrucciones del atacante y forzando a la CPU a ejecutar esas instrucciones.|`Process`|
|`7.`|Se utilizan los mismos privilegios del servidor SMB.|`Privileges`|
|`8.`|El sistema del atacante remoto se utiliza como destino, en este caso, otorgando acceso al sistema local.|`Destination`|

Sin embargo, a pesar de la complejidad de la vulnerabilidad debido a la manipulación del buffer, que podemos ver en el [PoC](https://www.exploit-db.com/exploits/48537), el concepto del ataque se aplica aquí.