[GitLab](https://about.gitlab.com/) es una herramienta de alojamiento de repositorios Git basada en web que proporciona capacidades de wiki, seguimiento de issues, y funcionalidad de pipeline de integración y despliegue continuo. Es de código abierto y fue originalmente escrito en Ruby, pero la pila tecnológica actual incluye Go, Ruby on Rails, y Vue.js. GitLab se lanzó por primera vez en 2014 y, a lo largo de los años, ha crecido hasta convertirse en una empresa de 1,400 personas con $150 millones de ingresos en 2020. Aunque la aplicación es gratuita y de código abierto, también ofrecen una versión empresarial de pago. Aquí hay algunas estadísticas rápidas sobre GitLab:

- En el momento de escribir esto, la empresa tiene 1,466 empleados.
- GitLab tiene más de 30 millones de usuarios registrados ubicados en 66 países.
- La empresa publica la mayoría de sus procedimientos internos y OKRs públicamente en su sitio web.
- Algunas empresas que usan GitLab incluyen Drupal, Goldman Sachs, Hackerone, Ticketmaster, Nvidia, Siemens, y [más](https://about.gitlab.com/customers/).

GitLab es similar a GitHub y BitBucket, que también son herramientas de repositorio Git basadas en web. Una comparación entre los tres puede verse [aquí](https://stackshare.io/stackups/bitbucket-vs-github-vs-gitlab).

Durante pruebas de penetración internas y externas, es común encontrar datos interesantes en el repositorio GitHub de una empresa o en una instancia autoalojada de GitLab o BitBucket. Estos repositorios Git pueden contener código públicamente disponible como scripts para interactuar con una API. Sin embargo, también podemos encontrar scripts o archivos de configuración que fueron accidentalmente comprometidos y contienen secretos en texto claro, como contraseñas que podemos usar a nuestro favor. También podemos encontrar claves privadas SSH. Podemos intentar usar la función de búsqueda para buscar usuarios, contraseñas, etc. Aplicaciones como GitLab permiten repositorios públicos (que no requieren autenticación), repositorios internos (disponibles para usuarios autenticados), y repositorios privados (restringidos a usuarios específicos). También vale la pena revisar cualquier repositorio público en busca de datos sensibles y, si la aplicación lo permite, registrar una cuenta y ver si hay repositorios internos interesantes accesibles. La mayoría de las empresas solo permiten registrar a un usuario con una dirección de correo electrónico de la empresa y requieren que un administrador autorice la cuenta, pero como veremos más adelante, una instancia de GitLab puede configurarse para permitir que cualquier persona se registre y luego inicie sesión.

`http://gitlab.inlanefreight.local:8081/admin/application_settings/general`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_signup_res.png)

Si podemos obtener credenciales de usuario a partir de nuestro OSINT, es posible que podamos iniciar sesión en una instancia de GitLab. La autenticación de dos factores está deshabilitada de manera predeterminada.

`http://gitlab.inlanefreight.local:8081/admin/application_settings/general`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_2fa.png)

---

## Footprinting & Discovery

Podemos determinar rápidamente que GitLab está en uso en un entorno simplemente navegando a la URL de GitLab, y seremos dirigidos a la página de inicio de sesión, que muestra el logo de GitLab.

`http://gitlab.inlanefreight.local:8081/users/sign_in`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_login.png)

La única forma de rastrear el número de versión de GitLab en uso es navegando a la página ` /help` cuando estamos conectados. Si la instancia de GitLab nos permite registrar una cuenta, podemos iniciar sesión y navegar a esta página para confirmar la versión. Si no podemos registrar una cuenta, es posible que tengamos que intentar un exploit de bajo riesgo como [este](https://www.exploit-db.com/exploits/49821). No recomendamos lanzar varios exploits a una aplicación, por lo que si no tenemos forma de enumerar el número de versión (como una fecha en la página, el primer commit público, o registrando un usuario), entonces deberíamos limitarnos a buscar secretos y no intentar múltiples exploits contra ella a ciegas. Ha habido algunos exploits serios contra GitLab [12.9.0](https://www.exploit-db.com/exploits/48431) y GitLab [11.4.7](https://www.exploit-db.com/exploits/49257) en los últimos años, así como GitLab Community Edition [13.10.3](https://www.exploit-db.com/exploits/49821), [13.9.3](https://www.exploit-db.com/exploits/49944), y [13.10.2](https://www.exploit-db.com/exploits/49951).

---

## Enumeration

No hay mucho que podamos hacer contra GitLab sin conocer el número de versión o sin estar conectados. Lo primero que deberíamos intentar es navegar a `/explore` y ver si hay algún proyecto público que pueda contener algo interesante. Navegando a esta página, vemos un proyecto llamado `Inlanefreight dev`. Los proyectos públicos pueden ser interesantes porque podemos usarlos para averiguar más sobre la infraestructura de la empresa, encontrar código de producción en el que podamos encontrar un bug después de una revisión de código, credenciales codificadas, un script o archivo de configuración que contenga credenciales u otros secretos como una clave privada SSH o una clave API.

`http://gitlab.inlanefreight.local:8081/explore`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_explore.png)

Al navegar al proyecto, parece ser un proyecto de ejemplo y puede que no contenga nada útil, aunque siempre vale la pena investigar.

`http://gitlab.inlanefreight.local:8081/root/inlanefreight-dev`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_example.png)

Desde aquí, podemos explorar cada una de las páginas vinculadas en la esquina superior izquierda: `groups`, `snippets`, y `help`. También podemos usar la funcionalidad de búsqueda y ver si podemos descubrir otros proyectos. Una vez que hayamos terminado de investigar lo que está disponible externamente, deberíamos verificar si podemos registrar una cuenta y acceder a proyectos adicionales. Supongamos que la organización no configuró GitLab para permitir solo correos electrónicos de la empresa para registrarse o requerir que un administrador apruebe una nueva cuenta. En ese caso, es posible que podamos acceder a datos adicionales.

`http://gitlab.inlanefreight.local:8081/users/sign_up`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_signup.png)

También podemos usar el formulario de registro para enumerar usuarios válidos (más sobre esto en la siguiente sección). Si podemos hacer una lista de usuarios válidos, podríamos intentar adivinar contraseñas débiles o posiblemente reutilizar credenciales que encontramos en un volcado de contraseñas usando una herramienta como `Dehashed` como se vio en la sección de osTicket. Aquí podemos ver que el usuario `root` está tomado. Veremos otro ejemplo de enumeración de nombres de usuario en la siguiente sección. En esta instancia particular de GitLab (y probablemente en otras), también podemos enumerar correos electrónicos. Si intentamos registrarnos con un correo electrónico que ya ha sido tomado, obtendremos el error `1 error prohibited this user from being saved: Email has already been taken`. En el momento de escribir esto, esta técnica de enumeración de nombres de usuario funciona con la última versión de GitLab. Incluso si la casilla `Sign-up enabled` está desactivada en la página de configuración bajo `Sign-up restrictions`, aún podemos navegar a la página `/users/sign_up` y enumerar usuarios pero no podremos registrar un usuario.

Se pueden implementar algunas mitigaciones para esto, como hacer cumplir 2FA en todas las cuentas de usuario, usar `Fail2Ban` para bloquear intentos de inicio de sesión fallidos que son indicativos de ataques de fuerza bruta, e incluso restringir qué direcciones IP pueden acceder a una instancia de GitLab si debe ser accesible fuera de la red corporativa interna.

`http://gitlab.inlanefreight.local:8081/users/sign_up`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_taken2.png)

Vamos a registrarnos con las credenciales `hacker:Welcome` e iniciar sesión para investigar. Tan pronto como completamos el registro, iniciamos sesión y nos dirigimos a la página del dashboard de proyectos. Si vamos a la página `/explore` ahora, notamos que ahora hay un proyecto interno `Inlanefreight website` disponible para nosotros. Investigando un poco, esto parece ser solo un sitio web estático para la empresa. Si esto fuera algún otro tipo de aplicación (como PHP), posiblemente podríamos descargar el código fuente y revisarlo en busca de vulnerabilidades o funcionalidad oculta, o encontrar credenciales u otros datos sensibles.

`http://gitlab.inlanefreight.local:8081/users/sign_up`

![](https://academy.hackthebox.com/storage/modules/113/gitlab_internal.png)

En un escenario del mundo real, es posible que podamos encontrar una cantidad considerable de datos sensibles si podemos registrarnos y obtener acceso a cualquiera de sus repositorios. Como explica este [blog post](https://tillsongalloway.com/finding-sensitive-information-on-github/index.html), hay una cantidad considerable de datos que podríamos descubrir en GitLab, GitHub, etc.

---

## Onwards

Esta sección nos muestra la importancia (y el poder) de la enumeración y que no todas las aplicaciones que descubrimos tienen que ser directamente explotables para seguir siendo muy interesantes y útiles para nosotros durante un engagement. Esto es especialmente cierto en pruebas de penetración externas, donde la superficie de ataque suele ser considerablemente más pequeña que en una evaluación interna. Es posible que necesitemos recopilar datos de dos o más fuentes para montar un ataque exitoso.