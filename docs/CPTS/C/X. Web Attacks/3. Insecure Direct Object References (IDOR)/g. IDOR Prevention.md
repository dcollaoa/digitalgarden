Aprendimos varias formas de identificar y explotar vulnerabilidades de IDOR en páginas web, funciones web y llamadas API. A estas alturas, deberíamos haber entendido que las vulnerabilidades de IDOR son causadas principalmente por un control de acceso inadecuado en los servidores back-end. Para prevenir tales vulnerabilidades, primero debemos construir un sistema de control de acceso a nivel de objeto y luego usar referencias seguras para nuestros objetos al almacenarlos y llamarlos.

---

## Object-Level Access Control

Un sistema de Access Control debe estar en el núcleo de cualquier aplicación web, ya que puede afectar todo su diseño y estructura. Para controlar adecuadamente cada área de la aplicación web, su diseño debe soportar la segmentación de roles y permisos de manera centralizada. Sin embargo, Access Control es un tema vasto, por lo que solo nos enfocaremos en su papel en las vulnerabilidades de IDOR, representado en mecanismos de control de acceso a nivel de objeto.

Los roles y permisos de usuario son una parte vital de cualquier sistema de control de acceso, que se realiza completamente en un sistema Role-Based Access Control (RBAC). Para evitar explotar vulnerabilidades de IDOR, debemos mapear el RBAC a todos los objetos y recursos. El servidor back-end puede permitir o denegar cada solicitud, dependiendo de si el rol del solicitante tiene suficientes privilegios para acceder al objeto o recurso.

Una vez implementado un RBAC, a cada usuario se le asignaría un rol que tiene ciertos privilegios. Ante cada solicitud que el usuario haga, sus roles y privilegios se probarían para ver si tienen acceso al objeto que están solicitando. Solo se les permitiría acceder si tienen el derecho de hacerlo.

Hay muchas formas de implementar un sistema RBAC y mapearlo a los objetos y recursos de la aplicación web, y diseñarlo en el núcleo de la estructura de la aplicación web es un arte que perfeccionar. El siguiente es un código de muestra de cómo una aplicación web puede comparar roles de usuario con objetos para permitir o denegar el control de acceso:

```r
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

El ejemplo anterior usa el token `user`, que puede ser `mapeado desde la solicitud HTTP realizada al RBAC` para recuperar los diversos roles y privilegios del usuario. Luego, solo permite acceso de lectura/escritura si el `uid` del usuario en el sistema RBAC coincide con el `uid` en el endpoint de la API que están solicitando. Además, si un usuario tiene `admin` como su rol en el back-end RBAC, se le permite acceso de lectura/escritura.

En nuestros ataques anteriores, vimos ejemplos de que el rol del usuario se almacenaba en los detalles del usuario o en su cookie, ambos bajo el control del usuario y que pueden ser manipulados para escalar sus privilegios de acceso. El ejemplo anterior demuestra un enfoque más seguro para mapear roles de usuario, ya que los privilegios del usuario `no se pasaron a través de la solicitud HTTP`, sino que se mapearon directamente desde el RBAC en el back-end utilizando el token de sesión del usuario autenticado como mecanismo de autenticación.

Hay mucho más en los sistemas de control de acceso y RBACs, ya que pueden ser algunos de los sistemas más desafiantes de diseñar. Esto, sin embargo, debería darnos una idea de cómo debemos controlar el acceso de usuarios sobre los objetos y recursos de las aplicaciones web.

---

## Object Referencing

Aunque el problema central con IDOR radica en el control de acceso roto (`Insecure`), tener acceso a referencias directas a objetos (`Direct Object Referencing`) hace posible enumerar y explotar estas vulnerabilidades de control de acceso. Aún podemos usar referencias directas, pero solo si tenemos un sistema de control de acceso sólido implementado.

Incluso después de construir un sistema de control de acceso sólido, nunca debemos usar referencias de objetos en texto claro o patrones simples (e.g. `uid=1`). Siempre debemos usar referencias fuertes y únicas, como hashes salteados o `UUID`s. Por ejemplo, podemos usar `UUID V4` para generar un ID fuertemente aleatorio para cualquier elemento, que se ve algo así como (`89c9b29b-d19f-4515-b2dd-abb6e693eb20`). Luego, podemos mapear este `UUID` al objeto que está referenciando en la base de datos back-end, y cada vez que se llame a este `UUID`, la base de datos back-end sabría qué objeto devolver. El siguiente código PHP de ejemplo nos muestra cómo esto puede funcionar:

```r
$uid = intval($_REQUEST['uid']);
$query = "SELECT url FROM documents where uid=" . $uid;
$result = mysqli_query($conn, $query);
$row = mysqli_fetch_array($result));
echo "<a href='" . $row['url'] . "' target='_blank'></a>";
```

Además, como vimos anteriormente en el módulo, nunca debemos calcular hashes en el front-end. Debemos generarlos cuando se crea un objeto y almacenarlos en la base de datos back-end. Luego, debemos crear mapas de base de datos para permitir referencias cruzadas rápidas de objetos y referencias.

Finalmente, debemos notar que usar `UUID`s puede dejar las vulnerabilidades de IDOR sin detectar, ya que hace más difícil probar las vulnerabilidades de IDOR. Es por esto que una referencia fuerte de objetos siempre es el segundo paso después de implementar un sistema de control de acceso fuerte. Además, algunas de las técnicas que aprendimos en este módulo funcionarían incluso con referencias únicas si el sistema de control de acceso está roto, como repetir la solicitud de un usuario con la sesión de otro usuario, como vimos anteriormente.

Si implementamos ambos mecanismos de seguridad, deberíamos estar relativamente seguros contra las vulnerabilidades de IDOR.