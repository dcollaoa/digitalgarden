

Al final de la sección anterior, la salida de sqlmap nos mostró mucha información durante su escaneo. Estos datos suelen ser cruciales para entender el proceso automatizado de inyección SQL, ya que nos guía y nos muestra exactamente qué tipo de vulnerabilidades está explotando SQLMap. Esto nos ayuda a informar sobre el tipo de inyección que tiene la aplicación web y puede ser útil si queremos explotar manualmente la aplicación web una vez que SQLMap determine el tipo de inyección y el parámetro vulnerable.

---

## Descripción de los Mensajes de Registro

A continuación se muestran algunos de los mensajes más comunes que se suelen encontrar durante un escaneo de SQLMap, junto con un ejemplo de cada uno del ejercicio anterior y su descripción.

### URL content is stable

`Log Message:`

- "target URL content is stable"

Esto significa que no hay cambios importantes entre las respuestas en caso de solicitudes idénticas continuas. Esto es importante desde el punto de vista de la automatización, ya que en caso de respuestas estables, es más fácil detectar diferencias causadas por los posibles intentos de SQLi. Aunque la estabilidad es importante, SQLMap tiene mecanismos avanzados para eliminar automáticamente el posible "ruido" que podría provenir de objetivos potencialmente inestables.

### Parameter appears to be dynamic

`Log Message:`

- "GET parameter 'id' appears to be dynamic"

Siempre se desea que el parámetro probado sea "dinámico", ya que es una señal de que cualquier cambio realizado en su valor resultaría en un cambio en la respuesta; por lo tanto, el parámetro puede estar vinculado a una base de datos. En caso de que la salida sea "estática" y no cambie, podría ser un indicador de que el valor del parámetro probado no es procesado por el objetivo, al menos en el contexto actual.

### Parameter might be injectable

`Log Message:` "heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"

Como se discutió anteriormente, los errores de DBMS son una buena indicación de la posible SQLi. En este caso, hubo un error de MySQL cuando SQLMap envió un valor intencionalmente inválido (por ejemplo, `?id=1",)..).))'`), lo que indica que el parámetro probado podría ser inyectable por SQLi y que el objetivo podría ser MySQL. Cabe señalar que esto no es una prueba de SQLi, sino solo una indicación de que el mecanismo de detección debe ser probado en la ejecución posterior.

### Parameter might be vulnerable to XSS attacks

`Log Message:`

- "heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"

Aunque no es su propósito principal, SQLMap también realiza una prueba heurística rápida para la presencia de una vulnerabilidad de XSS. En pruebas a gran escala, donde se están probando muchos parámetros con SQLMap, es bueno tener este tipo de comprobaciones heurísticas rápidas, especialmente si no se encuentran vulnerabilidades de SQLi.

### Back-end DBMS is '...'

`Log Message:`

- "it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"

En una ejecución normal, SQLMap prueba todos los DBMS soportados. En caso de que haya una indicación clara de que el objetivo está utilizando un DBMS específico, podemos reducir los payloads solo a ese DBMS específico.

### Level/risk values

`Log Message:`

- "for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"

Si hay una indicación clara de que el objetivo utiliza un DBMS específico, también es posible extender las pruebas para ese mismo DBMS específico más allá de las pruebas regulares.  
Esto básicamente significa ejecutar todos los payloads de inyección SQL para ese DBMS específico, mientras que si no se detecta ningún DBMS, solo se probarían los payloads principales.

### Reflective values found

`Log Message:`

- "reflective value(s) found and filtering out"

Solo una advertencia de que partes de los payloads utilizados se encuentran en la respuesta. Este comportamiento podría causar problemas a las herramientas de automatización, ya que representa basura. Sin embargo, SQLMap tiene mecanismos de filtrado para eliminar dicha basura antes de comparar el contenido de la página original.

### Parameter appears to be injectable

`Log Message:`

- "GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="luther")"

Este mensaje indica que el parámetro parece ser inyectable, aunque todavía existe la posibilidad de que sea un hallazgo falso positivo. En el caso de los tipos de SQLi basados en booleanos y similares (por ejemplo, basados en tiempo), donde hay una alta probabilidad de falsos positivos, al final de la ejecución, SQLMap realiza pruebas extensas que consisten en comprobaciones lógicas simples para eliminar hallazgos falsos positivos.

Además, `with --string="luther"` indica que SQLMap reconoció y utilizó la aparición del valor constante `luther` en la respuesta para distinguir entre las respuestas `TRUE` y `FALSE`. Este es un hallazgo importante porque en tales casos, no es necesario el uso de mecanismos internos avanzados, como la eliminación de dinamismo/reflejo o la comparación difusa de respuestas, que no pueden considerarse como falsos positivos.

### Time-based comparison statistical model

`Log Message:`

- "time-based comparison requires a larger statistical model, please wait........... (done)"

SQLMap utiliza un modelo estadístico para el reconocimiento de respuestas regulares y respuestas (deliberadamente) retrasadas del objetivo. Para que este modelo funcione, es necesario recopilar un número suficiente de tiempos de respuesta regulares. De esta manera, SQLMap puede distinguir estadísticamente entre el retraso deliberado incluso en entornos de red de alta latencia.

### Extending UNION query injection technique tests

`Log Message:`

- "automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"

Las comprobaciones de SQLi con consultas UNION requieren considerablemente más solicitudes para el reconocimiento exitoso de payloads utilizables que otros tipos de SQLi. Para reducir el tiempo de prueba por parámetro, especialmente si el objetivo no parece ser inyectable, el número de solicitudes se limita a un valor constante (es decir, 10) para este tipo de comprobación. Sin embargo, si hay una buena posibilidad de que el objetivo sea vulnerable, especialmente si se encuentra otra técnica SQLi (potencial), SQLMap extiende el número predeterminado de solicitudes para SQLi de consulta UNION, debido a una mayor expectativa de éxito.

### Technique appears to be usable

`Log Message:`

- "ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"

Como una comprobación heurística para el tipo de SQLi de consulta UNION, antes de que se envíen los payloads `UNION`, se comprueba la técnica conocida como `ORDER BY` para su usabilidad. En caso de que sea usable, SQLMap puede reconocer rápidamente el número correcto de columnas de `UNION` requeridas mediante el enfoque de búsqueda binaria.

Tenga en cuenta que esto depende de la tabla afectada en la consulta vulnerable.

### Parameter is vulnerable

`Log Message:`

- "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"

Este es uno de los mensajes más importantes de SQLMap, ya que significa que se encontró que el parámetro es vulnerable a las inyecciones SQL. En los casos regulares, el usuario solo puede querer encontrar al menos un punto de inyección (es decir, parámetro) utilizable contra el objetivo. Sin embargo, si estamos realizando una prueba exhaustiva en la aplicación web y queremos informar todas las posibles vulnerabilidades, podemos seguir buscando todos los parámetros vulnerables.

### Sqlmap identified injection points

`Log Message:`

- "sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"

Después de esto, se presenta una lista de todos los puntos de inyección con tipo, título y payloads, lo que representa la prueba final de la detección y explotación exitosa de las vulnerabilidades de SQLi encontradas. Cabe señalar que SQLMap solo enumera aquellos hallazgos que son explotables (es decir, utilizables).

### Data logged to text files

`Log Message:`

- "fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"

Esto indica la ubicación del sistema de archivos local utilizado para almacenar todos los registros, sesiones y datos de salida para un objetivo específico - en este caso, `www.example.com`. Después de una ejecución inicial como esta, donde se detecta con éxito el punto de inyección, todos los detalles para futuras ejecuciones se almacenan en los archivos de sesión del mismo directorio. Esto significa que SQLMap intenta reducir las solicitudes necesarias al objetivo tanto como sea posible, dependiendo de los datos de los archivos de sesión.