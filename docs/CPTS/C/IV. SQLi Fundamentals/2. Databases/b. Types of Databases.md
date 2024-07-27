Las bases de datos, en general, se dividen en `Relational Databases` y `Non-Relational Databases`. Solo las bases de datos relacionales utilizan SQL, mientras que las bases de datos no relacionales utilizan una variedad de métodos para las comunicaciones.

---

## Relational Databases

Una base de datos relacional es el tipo más común de base de datos. Utiliza un esquema, una plantilla, para dictar la estructura de datos almacenados en la base de datos. Por ejemplo, podemos imaginar una empresa que vende productos a sus clientes teniendo alguna forma de conocimiento almacenado sobre a dónde van esos productos, a quién y en qué cantidad. Sin embargo, esto a menudo se hace en el back-end y sin informar de manera obvia en el front-end. Se pueden utilizar diferentes tipos de bases de datos relacionales para cada enfoque. Por ejemplo, la primera tabla puede almacenar y mostrar información básica del cliente, la segunda el número de productos vendidos y su costo, y la tercera tabla para enumerar quién compró esos productos y con qué datos de pago.

Las tablas en una base de datos relacional están asociadas con claves que proporcionan un resumen rápido de la base de datos o acceso a la fila o columna específica cuando se necesita revisar datos específicos. Estas tablas, también llamadas entidades, están todas relacionadas entre sí. Por ejemplo, la tabla de información del cliente puede proporcionar a cada cliente una ID específica que puede indicar todo lo que necesitamos saber sobre ese cliente, como dirección, nombre e información de contacto. Además, la tabla de descripción del producto puede asignar una ID específica a cada producto. La tabla que almacena todos los pedidos solo necesitaría registrar estas IDs y su cantidad. Cualquier cambio en estas tablas afectará a todas ellas, pero de manera predecible y sistemática.

Sin embargo, al procesar una base de datos integrada, se requiere un concepto para vincular una tabla a otra usando su clave, llamado `relational database management system` (`RDBMS`). Muchas empresas que inicialmente utilizan conceptos diferentes están cambiando al concepto de RDBMS porque este concepto es fácil de aprender, usar y entender. Inicialmente, este concepto solo era utilizado por grandes empresas. Sin embargo, muchos tipos de bases de datos ahora implementan el concepto RDBMS, como Microsoft Access, MySQL, SQL Server, Oracle, PostgreSQL, y muchos otros.

Por ejemplo, podemos tener una tabla `users` en una base de datos relacional que contenga columnas como `id`, `username`, `first_name`, `last_name` y otros. El `id` puede usarse como la clave de la tabla. Otra tabla, `posts`, puede contener publicaciones hechas por todos los usuarios, con columnas como `id`, `user_id`, `date`, `content`, y así sucesivamente.

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_relational_db.jpg)

Podemos vincular el `id` de la tabla `users` con el `user_id` en la tabla `posts` para recuperar los detalles del usuario para cada publicación sin almacenar todos los detalles del usuario con cada publicación. Una tabla puede tener más de una clave, ya que otra columna puede usarse como clave para vincular con otra tabla. Entonces, por ejemplo, la columna `id` puede usarse como clave para vincular la tabla `posts` con otra tabla que contiene comentarios, cada uno de los cuales pertenece a una publicación particular, y así sucesivamente.

La relación entre tablas dentro de una base de datos se llama un Esquema.

De esta manera, al usar bases de datos relacionales, se vuelve rápido y fácil recuperar todos los datos sobre un elemento particular de todas las bases de datos. Entonces, por ejemplo, podemos recuperar todos los detalles vinculados a un usuario específico de todas las tablas con una sola consulta. Esto hace que las bases de datos relacionales sean muy rápidas y confiables para conjuntos de datos grandes con una estructura y diseño claros y una gestión de datos eficiente. El ejemplo más común de bases de datos relacionales es `MySQL`, que cubriremos en este módulo.

---

## Non-relational Databases

Una base de datos no relacional (también llamada `NoSQL` database) no usa tablas, filas, y columnas, ni claves primarias, relaciones, ni esquemas. En cambio, una base de datos NoSQL almacena datos utilizando varios modelos de almacenamiento, dependiendo del tipo de datos almacenados. Debido a la falta de una estructura definida para la base de datos, las bases de datos NoSQL son muy escalables y flexibles. Por lo tanto, al tratar con conjuntos de datos que no están muy bien definidos y estructurados, una base de datos NoSQL sería la mejor opción para almacenar dichos datos. Hay cuatro modelos de almacenamiento comunes para bases de datos NoSQL:

- Key-Value
- Document-Based
- Wide-Column
- Graph

Cada uno de los modelos anteriores tiene una forma diferente de almacenar datos. Por ejemplo, el modelo `Key-Value` generalmente almacena datos en JSON o XML, y tiene una clave para cada par, y almacena todos sus datos como su valor:

![HTML Example](https://academy.hackthebox.com/storage/modules/75/web_apps_non-relational_db.jpg)

El ejemplo anterior puede representarse usando JSON como:

```r
{
  "100001": {
    "date": "01-01-2021",
    "content": "Welcome to this web application."
  },
  "100002": {
    "date": "02-01-2021",
    "content": "This is the first post on this web app."
  },
  "100003": {
    "date": "02-01-2021",
    "content": "Reminder: Tomorrow is the ..."
  }
}
```

Se parece a un elemento de diccionario en lenguajes como `Python` o `PHP` (es decir, `{'key':'value'}`), donde la `key` generalmente es una cadena y el `value` puede ser una cadena, diccionario o cualquier objeto de clase.

El ejemplo más común de una base de datos NoSQL es `MongoDB`.

Las bases de datos NoSQL tienen un método diferente para la inyección, conocido como NoSQL injections. Las SQL injections son completamente diferentes a las NoSQL injections. Las NoSQL injections se cubrirán en un módulo posterior.