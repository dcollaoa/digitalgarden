Antes de aprender sobre SQL injections, necesitamos saber más sobre las bases de datos y el Structured Query Language (SQL), que las bases de datos usarán para realizar las consultas necesarias. Las aplicaciones web utilizan bases de datos en el back-end para almacenar varios contenidos e información relacionada con la aplicación web. Esto puede ser activos principales de la aplicación web como imágenes y archivos, contenido como publicaciones y actualizaciones, o datos de usuarios como nombres de usuario y contraseñas.

Hay muchos tipos diferentes de bases de datos, cada una de las cuales se adapta a un tipo particular de uso. Tradicionalmente, una aplicación utilizaba bases de datos basadas en archivos, lo cual era muy lento con el aumento de tamaño. Esto llevó a la adopción de `Database Management Systems` (`DBMS`).

---

## Database Management Systems

Un Database Management System (DBMS) ayuda a crear, definir, alojar y gestionar bases de datos. Se diseñaron varios tipos de DBMS a lo largo del tiempo, como basados en archivos, Relational DBMS (RDBMS), NoSQL, basados en gráficos y almacenes de clave/valor.

Hay múltiples formas de interactuar con un DBMS, como herramientas de línea de comandos, interfaces gráficas o incluso APIs (Application Programming Interfaces). Los DBMS se utilizan en varios sectores como banca, finanzas y educación para registrar grandes cantidades de datos. Algunas de las características esenciales de un DBMS incluyen:

|**Feature**|**Description**|
|---|---|
|`Concurrency`|Una aplicación del mundo real podría tener múltiples usuarios interactuando con ella simultáneamente. Un DBMS asegura que estas interacciones concurrentes tengan éxito sin corromper o perder ningún dato.|
|`Consistency`|Con tantas interacciones concurrentes, el DBMS necesita asegurar que los datos permanezcan consistentes y válidos en toda la base de datos.|
|`Security`|El DBMS proporciona controles de seguridad granulares mediante autenticación de usuarios y permisos. Esto evitará la visualización o edición no autorizada de datos sensibles.|
|`Reliability`|Es fácil hacer copias de seguridad de las bases de datos y retrocederlas a un estado anterior en caso de pérdida de datos o una brecha.|
|`Structured Query Language`|SQL simplifica la interacción del usuario con la base de datos con una sintaxis intuitiva que admite varias operaciones.|

---

## Architecture

El siguiente diagrama detalla una arquitectura de dos niveles.

![dbms_architecture](https://academy.hackthebox.com/storage/modules/33/db_2.png)

`Tier I` generalmente consiste en aplicaciones del lado del cliente como sitios web o programas GUI. Estas aplicaciones consisten en interacciones de alto nivel, como inicio de sesión de usuario o comentarios. Los datos de estas interacciones se pasan a `Tier II` a través de llamadas API u otras solicitudes.

El segundo nivel es el middleware, que interpreta estos eventos y los pone en una forma requerida por el DBMS. Finalmente, la capa de aplicación utiliza bibliotecas y controladores específicos según el tipo de DBMS para interactuar con ellos. El DBMS recibe consultas del segundo nivel y realiza las operaciones solicitadas. Estas operaciones podrían incluir inserción, recuperación, eliminación o actualización de datos. Después del procesamiento, el DBMS devuelve cualquier dato solicitado o códigos de error en caso de consultas inválidas.

Es posible alojar el servidor de aplicaciones así como el DBMS en el mismo host. Sin embargo, las bases de datos con grandes cantidades de datos que admiten a muchos usuarios suelen alojarse por separado para mejorar el rendimiento y la escalabilidad.