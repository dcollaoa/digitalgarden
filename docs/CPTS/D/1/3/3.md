Un restricted shell es un tipo de shell que limita la capacidad del usuario para ejecutar comandos. En un restricted shell, el usuario solo puede ejecutar un conjunto específico de comandos o solo puede ejecutar comandos en directorios específicos. Los restricted shells a menudo se usan para proporcionar un entorno seguro para usuarios que pueden dañar el sistema accidentalmente o intencionalmente o para proporcionar una forma en que los usuarios accedan solo a ciertas características del sistema. Algunos ejemplos comunes de restricted shells incluyen el shell `rbash` en Linux y el "Restricted-access Shell" en Windows.

### RBASH

[Restricted Bourne shell](https://www.gnu.org/software/bash/manual/html_node/The-Restricted-Shell.html) (`rbash`) es una versión restringida del Bourne shell, un intérprete de línea de comandos estándar en Linux, que limita la capacidad del usuario para usar ciertas características del Bourne shell, como cambiar de directorios, configurar o modificar variables de entorno y ejecutar comandos en otros directorios. A menudo se usa para proporcionar un entorno seguro y controlado para usuarios que pueden dañar el sistema accidentalmente o intencionalmente.

### RKSH

[Restricted Korn shell](https://www.ibm.com/docs/en/aix/7.2?topic=r-rksh-command) (`rksh`) es una versión restringida del Korn shell, otro intérprete de línea de comandos estándar. El shell `rksh` limita la capacidad del usuario para usar ciertas características del Korn shell, como ejecutar comandos en otros directorios, crear o modificar funciones del shell y modificar el entorno del shell.

### RZSH

[Restricted Z shell](https://manpages.debian.org/experimental/zsh/rzsh.1.en.html) (`rzsh`) es una versión restringida del Z shell y es el intérprete de línea de comandos más poderoso y flexible. El shell `rzsh` limita la capacidad del usuario para usar ciertas características del Z shell, como ejecutar scripts del shell, definir alias y modificar el entorno del shell.

Por ejemplo, los administradores a menudo usan restricted shells en redes empresariales para proporcionar un entorno seguro y controlado para usuarios que pueden dañar el sistema accidentalmente o intencionalmente. Al limitar la capacidad del usuario para ejecutar comandos específicos o acceder a ciertos directorios, los administradores pueden asegurarse de que los usuarios no realicen acciones que puedan dañar el sistema o comprometer la seguridad de la red. Además, los restricted shells pueden dar a los usuarios acceso solo a ciertas características del sistema, lo que permite a los administradores controlar qué recursos y funciones están disponibles para cada usuario.

Imagina una empresa con una red de servidores Linux que alojan aplicaciones y servicios críticos para el negocio. Muchos usuarios, incluidos empleados, contratistas y socios externos, acceden a la red. Para proteger la seguridad e integridad de la red, el equipo de IT de la organización decidió implementar restricted shells para todos los usuarios.

Para hacer esto, el equipo de IT configura varios shells `rbash`, `rksh` y `rzsh` en la red y asigna a cada usuario un shell específico. Por ejemplo, los socios externos que necesitan acceder solo a ciertas características de la red, como correo electrónico y compartir archivos, se asignan a shells `rbash`, lo que limita su capacidad para ejecutar comandos específicos y acceder a ciertos directorios. Los contratistas que necesitan acceder a características más avanzadas de la red, como servidores de bases de datos y servidores web, se asignan a shells `rksh`, que les brindan más flexibilidad pero aún limitan sus habilidades. Finalmente, los empleados que necesitan acceder a la red para propósitos específicos, como ejecutar aplicaciones o scripts específicos, se asignan a shells `rzsh`, que les brindan la mayor flexibilidad pero aún limitan su capacidad para ejecutar comandos específicos y acceder a ciertos directorios.

Se pueden usar varios métodos para escapar de un restricted shell. Algunos de estos métodos implican explotar vulnerabilidades en el shell en sí, mientras que otros implican usar técnicas creativas para sortear las restricciones impuestas por el shell. Aquí hay algunos ejemplos de métodos que se pueden usar para escapar de un restricted shell.

---

## Escaping

En algunos casos, puede ser posible escapar de un restricted shell inyectando comandos en la línea de comandos u otras entradas que acepta el shell. Por ejemplo, supongamos que el shell permite a los usuarios ejecutar comandos pasándolos como argumentos a un comando integrado. En ese caso, puede ser posible escapar del shell inyectando comandos adicionales en el argumento.

### Command Injection

Imagina que estamos en un restricted shell que nos permite ejecutar comandos pasándolos como argumentos al comando `ls`. Desafortunadamente, el shell solo nos permite ejecutar el comando `ls` con un conjunto específico de argumentos, como `ls -l` o `ls -a`, pero no nos permite ejecutar ningún otro comando. En esta situación, podemos usar la inyección de comandos (command injection) para escapar del shell inyectando comandos adicionales en el argumento del comando `ls`.

Por ejemplo, podríamos usar el siguiente comando para inyectar un comando `pwd` en el argumento del comando `ls`:

```r
ls -l `pwd`
```

Este comando haría que el comando `ls` se ejecute con el argumento `-l`, seguido de la salida del comando `pwd`. Dado que el comando `pwd` no está restringido por el shell, esto nos permitiría ejecutar el comando `pwd` y ver el directorio de trabajo actual, aunque el shell no nos permita ejecutar el comando `pwd` directamente.

### Command Substitution

Otro método para escapar de un restricted shell es usar la sustitución de comandos (command substitution). Esto implica usar la sintaxis de sustitución de comandos del shell para ejecutar un comando. Por ejemplo, imagina que el shell permite a los usuarios ejecutar comandos encerrándolos en backticks (`). En ese caso, puede ser posible escapar del shell ejecutando un comando en una sustitución de backtick que no esté restringido por el shell.

### Command Chaining

En algunos casos, puede ser posible escapar de un restricted shell usando encadenamiento de comandos (command chaining). Necesitaríamos usar múltiples comandos en una sola línea de comandos, separados por un metacarácter del shell, como un punto y coma (`;`) o una barra vertical (`|`), para ejecutar un comando. Por ejemplo, si el shell permite a los usuarios ejecutar comandos separados por puntos y comas, puede ser posible escapar del shell usando un punto y coma para separar dos comandos, uno de los cuales no está restringido por el shell.

### Environment Variables

Para escapar de un restricted shell usando variables de entorno (environment variables) implica modificar o crear variables de entorno que el shell usa para ejecutar comandos que no están restringidos por el shell. Por ejemplo, si el shell usa una variable de entorno para especificar el directorio en el que se ejecutan los comandos, puede ser posible escapar del shell modificando el valor de la variable de entorno para especificar un directorio diferente.

### Shell Functions

En algunos casos, puede ser posible escapar de un restricted shell usando funciones del shell (shell functions). Para esto, podemos definir y llamar a funciones del shell que ejecuten comandos que no están restringidos por el shell. Digamos que el shell permite a los usuarios definir y llamar a funciones del shell, puede ser posible escapar del shell definiendo una función del shell que ejecute un comando.