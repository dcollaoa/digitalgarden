La mayoría de las aplicaciones web modernas utilizan una estructura de base de datos en el back-end. Estas bases de datos se utilizan para almacenar y recuperar datos relacionados con la aplicación web, desde contenido web real hasta información de usuarios y contenido, entre otros. Para que las aplicaciones web sean dinámicas, la aplicación web debe interactuar con la base de datos en tiempo real. A medida que llegan solicitudes HTTP(S) del usuario, el back-end de la aplicación web emitirá consultas a la base de datos para construir la respuesta. Estas consultas pueden incluir información de la solicitud HTTP(S) u otra información relevante.

![dbms_architecture](https://academy.hackthebox.com/storage/modules/33/db_request_3.png)

Cuando se utiliza información proporcionada por el usuario para construir la consulta a la base de datos, los usuarios malintencionados pueden engañar a la consulta para que se utilice con fines distintos a los previstos por el programador original, proporcionando al usuario acceso para consultar la base de datos mediante un ataque conocido como SQL injection (SQLi).

SQL injection se refiere a ataques contra bases de datos relacionales como `MySQL` (mientras que las inyecciones contra bases de datos no relacionales, como MongoDB, son NoSQL injection). Este módulo se centrará en `MySQL` para introducir conceptos de SQL Injection.

---

## SQL Injection (SQLi)

Muchos tipos de vulnerabilidades de inyección son posibles dentro de las aplicaciones web, como HTTP injection, code injection y command injection. Sin embargo, el ejemplo más común es SQL injection. Una SQL injection ocurre cuando un usuario malintencionado intenta pasar una entrada que cambia la consulta SQL final enviada por la aplicación web a la base de datos, lo que permite al usuario realizar otras consultas SQL no previstas directamente contra la base de datos.

Hay muchas formas de lograr esto. Para que una SQL injection funcione, el atacante primero debe inyectar código SQL y luego subvertir la lógica de la aplicación web cambiando la consulta original o ejecutando una completamente nueva. Primero, el atacante tiene que inyectar código fuera de los límites de entrada esperados del usuario, para que no se ejecute como una simple entrada de usuario. En el caso más básico, esto se hace inyectando una comilla simple (`'`) o una comilla doble (`"`) para escapar de los límites de entrada del usuario e inyectar datos directamente en la consulta SQL.

Una vez que un atacante puede inyectar, debe buscar una forma de ejecutar una consulta SQL diferente. Esto se puede hacer utilizando código SQL para crear una consulta funcional que ejecute tanto las consultas SQL previstas como las nuevas. Hay muchas formas de lograr esto, como utilizando consultas [stacked](https://www.sqlinjection.net/stacked-queries/) o consultas [Union](https://www.mysqltutorial.org/sql-union-mysql.aspx/). Finalmente, para recuperar la salida de nuestra nueva consulta, debemos interpretarla o capturarla en el front-end de la aplicación web.

---

## Use Cases and Impact

Una SQL injection puede tener un impacto tremendo, especialmente si los privilegios en el servidor back-end y la base de datos son muy laxos.

Primero, podemos recuperar información secreta/sensible que no debería ser visible para nosotros, como inicios de sesión y contraseñas de usuarios o información de tarjetas de crédito, que luego se puede usar para otros fines maliciosos. Las inyecciones SQL causan muchas filtraciones de contraseñas y datos contra sitios web, que luego se reutilizan para robar cuentas de usuarios, acceder a otros servicios o realizar otras acciones nefastas.

Otro caso de uso de SQL injection es subvertir la lógica prevista de la aplicación web. El ejemplo más común de esto es eludir el inicio de sesión sin pasar un par válido de credenciales de nombre de usuario y contraseña. Otro ejemplo es acceder a funciones que están bloqueadas para usuarios específicos, como paneles de administración. Los atacantes también pueden leer y escribir archivos directamente en el servidor back-end, lo que puede llevar a colocar puertas traseras en el servidor back-end, ganar control directo sobre él y, eventualmente, tomar control de todo el sitio web.

---

## Prevention

Las inyecciones SQL suelen ser causadas por aplicaciones web mal codificadas o privilegios de servidor y bases de datos back-end mal asegurados. Más adelante, discutiremos formas de reducir las posibilidades de ser vulnerables a las inyecciones SQL mediante métodos de codificación seguros como la sanitización y validación de entradas de usuario y privilegios y control adecuados de usuarios en el back-end.