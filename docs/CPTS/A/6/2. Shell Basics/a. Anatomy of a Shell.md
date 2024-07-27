Cada sistema operativo tiene un shell, y para interactuar con él, debemos usar una aplicación conocida como `terminal emulator`. Aquí están algunos de los emuladores de terminal más comunes:

|**Terminal Emulator**|**Operating System**|
|:--|:--|
|[Windows Terminal](https://github.com/microsoft/terminal)|Windows|
|[cmder](https://cmder.app/)|Windows|
|[PuTTY](https://www.putty.org/)|Windows|
|[kitty](https://sw.kovidgoyal.net/kitty/)|Windows, Linux and MacOS|
|[Alacritty](https://github.com/alacritty/alacritty)|Windows, Linux and MacOS|
|[xterm](https://invisible-island.net/xterm/)|Linux|
|[GNOME Terminal](https://en.wikipedia.org/wiki/GNOME_Terminal)|Linux|
|[MATE Terminal](https://github.com/mate-desktop/mate-terminal)|Linux|
|[Konsole](https://konsole.kde.org/)|Linux|
|[Terminal](https://en.wikipedia.org/wiki/Terminal_(macOS))|MacOS|
|[iTerm2](https://iterm2.com/)|MacOS|

Esta lista no incluye todos los emuladores de terminal disponibles, pero sí algunos destacados. Además, dado que muchas de estas herramientas son de código abierto, podemos instalarlas en diferentes sistemas operativos de maneras que pueden diferir de las intenciones originales de los desarrolladores. Sin embargo, ese es un proyecto que va más allá del alcance de este módulo. La selección del emulador de terminal adecuado para el trabajo es principalmente una preferencia personal y de estilo basada en nuestros flujos de trabajo que se desarrollan a medida que nos familiarizamos con nuestro sistema operativo de elección. Así que no dejes que nadie te haga sentir mal por seleccionar una opción sobre otra. El emulador de terminal con el que interactuamos en los objetivos dependerá esencialmente de lo que exista en el sistema de manera nativa.

---
## Command Language Interpreters

Al igual que un intérprete de idiomas humanos traducirá el lenguaje hablado o de signos en tiempo real, un `command language interpreter` es un programa que trabaja para interpretar las instrucciones proporcionadas por el usuario y emitir las tareas al sistema operativo para su procesamiento. Así que cuando hablamos de interfaces de línea de comandos, sabemos que es una combinación del sistema operativo, la aplicación del emulador de terminal y el intérprete del lenguaje de comandos. Se pueden utilizar muchos intérpretes de lenguaje de comandos diferentes, algunos de los cuales también se llaman `shell scripting languages` o `Command and Scripting interpreters` según las técnicas de [Execution](https://attack.mitre.org/techniques/T1059/) de la `MITRE ATT&CK Matrix`. No necesitamos ser desarrolladores de software para entender estos conceptos, pero cuanto más sepamos, más éxito podemos tener al intentar explotar sistemas vulnerables para obtener una sesión de shell.

Entender el intérprete de lenguaje de comandos en uso en cualquier sistema dado también nos dará una idea de qué comandos y scripts debemos usar. Vamos a poner en práctica algunos de estos conceptos.

---
## Hands-on with Terminal Emulators and Shells

Vamos a usar nuestro `Parrot OS` Pwnbox para explorar más a fondo la anatomía de un shell. Haz clic en el icono de cuadrado `verde` en la parte superior de la pantalla para abrir el emulador de terminal `MATE` y luego escribe algo al azar y presiona enter.

### Terminal Example

![image](https://academy.hackthebox.com/storage/modules/115/green-square.png)

Tan pronto como seleccionamos el icono, se abrió la aplicación del emulador de terminal MATE, que ha sido preconfigurada para usar un intérprete de lenguaje de comandos. En este caso, estamos "informados" de qué intérprete de lenguaje está en uso al ver el signo `$`. Este signo $ se usa en Bash, Ksh, POSIX y muchos otros lenguajes de shell para marcar el inicio del `shell prompt` donde el usuario puede comenzar a escribir comandos y otras entradas. Cuando escribimos nuestro texto al azar y presionamos enter, se identificó nuestro intérprete de lenguaje de comandos. Eso es Bash diciéndonos que no reconoció el comando que escribimos. Así que aquí podemos ver que los intérpretes de lenguaje de comandos pueden tener su propio conjunto de comandos que reconocen. Otra forma en que podemos identificar el intérprete de lenguaje es viendo los procesos que se están ejecutando en la máquina. En Linux, podemos hacer esto usando el siguiente comando:

### Shell Validation From 'ps'

```r
ps

    PID TTY          TIME CMD
   4232 pts/1    00:00:00 bash
  11435 pts/1    00:00:00 ps
```

También podemos averiguar qué lenguaje de shell está en uso viendo las variables de entorno usando el comando `env`:

### Shell Validation Using 'env'

```r
env

SHELL=/bin/bash
```

Ahora seleccionemos el icono de cuadrado azul en la parte superior de la pantalla en Pwnbox.

### PowerShell vs. Bash

![image](https://academy.hackthebox.com/storage/modules/115/blue-box.png)

Seleccionar este icono también abre la aplicación de terminal MATE, pero usa un intérprete de lenguaje de comandos diferente esta vez. Compáralos mientras están colocados uno al lado del otro.

- `¿Qué diferencias podemos identificar?`
- `¿Por qué usaríamos uno sobre el otro en el mismo sistema?`

Hay innumerables diferencias y personalizaciones que podríamos descubrir. Intenta usar algunos comandos que conozcas en ambos y haz una nota mental de las diferencias en la salida y qué comandos son reconocidos. Uno de los puntos principales que podemos destacar es que un emulador de terminal no está vinculado a un lenguaje específico. De hecho, el lenguaje de shell se puede cambiar y personalizar para adaptarse a la preferencia personal, flujo de trabajo y necesidades técnicas del sysadmin, desarrollador o pentester.

`Ahora unas preguntas de desafío para probar nuestra comprensión. Todas las respuestas se pueden encontrar utilizando Pwnbox.`