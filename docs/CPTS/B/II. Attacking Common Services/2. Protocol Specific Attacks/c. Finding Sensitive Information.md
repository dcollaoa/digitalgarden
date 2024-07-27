Cuando atacamos un servicio, usualmente jugamos el papel de detective, y necesitamos recolectar la mayor cantidad de información posible y observar cuidadosamente los detalles. Por lo tanto, cada fragmento de información es esencial.

Imaginemos que estamos en un compromiso con un cliente, estamos apuntando a email, FTP, bases de datos y almacenamiento, y nuestro objetivo es obtener Remote Code Execution (RCE) en cualquiera de estos servicios. Comenzamos la enumeración e intentamos el acceso anónimo a todos los servicios, y solo FTP tiene acceso anónimo. Encontramos un archivo vacío dentro del servicio FTP, pero con el nombre `johnsmith`, intentamos `johnsmith` como usuario y contraseña de FTP, pero no funcionó. Probamos lo mismo contra el servicio de email, y logramos iniciar sesión exitosamente. Con acceso al email, comenzamos a buscar correos electrónicos que contengan la palabra `password`, encontramos muchos, pero uno de ellos contiene las credenciales de John para la base de datos MSSQL. Accedemos a la base de datos y usamos la funcionalidad incorporada para ejecutar comandos y obtener exitosamente RCE en el servidor de la base de datos. Logramos cumplir nuestro objetivo.

Un servicio mal configurado nos permitió acceder a un fragmento de información que inicialmente puede parecer insignificante, `johnsmith`, pero esa información nos abrió las puertas para descubrir más información y finalmente obtener ejecución remota de código en el servidor de la base de datos. Esta es la importancia de prestar atención a cada fragmento de información, cada detalle, mientras enumeramos y atacamos servicios comunes.

La información sensible puede incluir, pero no se limita a:

- Usernames.
- Email Addresses.
- Passwords.
- DNS records.
- IP Addresses.
- Source code.
- Configuration files.
- PII.

Este módulo cubrirá algunos servicios comunes donde podemos encontrar información interesante y descubrir diferentes métodos y herramientas que podemos usar para automatizar nuestro proceso de descubrimiento. Estos servicios incluyen:

- File Shares.
- Email.
- Databases.

---

### Understanding of What We Have to Look for

Cada objetivo es único, y necesitamos familiarizarnos con nuestro objetivo, sus procesos, procedimientos, modelo de negocio y propósito. Una vez que entendamos nuestro objetivo, podemos pensar en qué información es esencial para ellos y qué tipo de información es útil para nuestro ataque.

Hay dos elementos clave para encontrar información sensible:

1. Necesitamos entender el servicio y cómo funciona.
2. Necesitamos saber qué estamos buscando.