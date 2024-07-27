El proceso de detectar vulnerabilidades básicas de OS Command Injection es el mismo proceso para explotarlas. Intentamos agregar nuestro comando a través de varios métodos de inyección. Si la salida del comando cambia del resultado habitual previsto, hemos explotado exitosamente la vulnerabilidad. Esto puede no ser cierto para vulnerabilidades de inyección de comandos más avanzadas porque podemos utilizar varios métodos de fuzzing o revisiones de código para identificar posibles vulnerabilidades de inyección de comandos. Luego, podemos construir gradualmente nuestro payload hasta lograr la inyección de comandos. Este módulo se centrará en inyecciones de comandos básicas, donde controlamos la entrada del usuario que se está utilizando directamente en una ejecución de comando del sistema sin ninguna sanitización.

Para demostrar esto, usaremos el ejercicio que se encuentra al final de esta sección.

---

## Command Injection Detection

Cuando visitamos la aplicación web en el ejercicio a continuación, vemos una utilidad `Host Checker` que parece pedirnos una IP para verificar si está activa o no:
![Basic Exercise](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_exercise_1.jpg)

Podemos intentar ingresar la IP de localhost `127.0.0.1` para verificar la funcionalidad, y como se esperaba, devuelve la salida del comando `ping` diciéndonos que el localhost está efectivamente activo:
![Basic Exercise](https://academy.hackthebox.com/storage/modules/109/cmdinj_basic_exercise_2.jpg)

Aunque no tenemos acceso al código fuente de la aplicación web, podemos adivinar con confianza que la IP que ingresamos está entrando en un comando `ping` ya que la salida que recibimos sugiere eso. Como el resultado muestra un solo paquete transmitido en el comando ping, el comando utilizado puede ser el siguiente:

```r
ping -c 1 OUR_INPUT
```

Si nuestra entrada no se sanitiza ni escapa antes de ser utilizada con el comando `ping`, podríamos inyectar otro comando arbitrario. Entonces, vamos a intentar ver si la aplicación web es vulnerable a la inyección de comandos del sistema operativo.

---

## Command Injection Methods

Para inyectar un comando adicional al previsto, podemos usar cualquiera de los siguientes operadores:

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| --- | --- | --- | --- |
| Semicolon | `;` | `%3b` | Ambos |
| New Line | `\n` | `%0a` | Ambos |
| Background | `&` | `%26` | Ambos (generalmente se muestra primero la segunda salida) |
| Pipe | `\|` | `%7c` | Ambos (solo se muestra la segunda salida) |
| AND | `&&` | `%26%26` | Ambos (solo si el primero tiene éxito) |
| OR | `\|` | `%7c%7c` | Segundo (solo si el primero falla) |
| Sub-Shell | ` `` ` | `%60%60` | Ambos (solo Linux) |
| Sub-Shell | `$()` | `%24%28%29` | Ambos (solo Linux) |

Podemos usar cualquiera de estos operadores para inyectar otro comando de modo que `ambos` o `alguno` de los comandos se ejecuten. `Escribiríamos nuestra entrada esperada (por ejemplo, una IP), luego usaríamos cualquiera de los operadores anteriores y luego escribiríamos nuestro nuevo comando.`

Tip: Además de lo anterior, hay algunos operadores solo para Unix, que funcionarían en Linux y macOS, pero no funcionarían en Windows, como envolver nuestro comando inyectado con dobles backticks (` `` `) o con un operador de sub-shell (`$()`).

En general, para la inyección de comandos básica, todos estos operadores pueden usarse para inyecciones de comandos `sin importar el lenguaje de la aplicación web, el framework o el servidor de back-end`. Por lo tanto, si estamos inyectando en una aplicación web `PHP` que se ejecuta en un servidor `Linux`, o una aplicación web `.Net` que se ejecuta en un servidor de back-end `Windows`, o una aplicación web `NodeJS` que se ejecuta en un servidor de back-end `macOS`, nuestras inyecciones deberían funcionar independientemente.

Nota: La única excepción puede ser el punto y coma `;`, que no funcionará si el comando se estaba ejecutando con `Windows Command Line (CMD)`, pero aún funcionaría si se estaba ejecutando con `Windows PowerShell`.

En la siguiente sección, intentaremos usar uno de los operadores de inyección anteriores para explotar el ejercicio `Host Checker`.