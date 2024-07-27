[Jenkins](https://www.jenkins.io/) es un servidor de automatización de código abierto escrito en Java que ayuda a los desarrolladores a construir y probar continuamente sus proyectos de software. Es un sistema basado en servidor que se ejecuta en contenedores de servlets como Tomcat. A lo largo de los años, los investigadores han descubierto varias vulnerabilidades en Jenkins, incluidas algunas que permiten la ejecución remota de código sin requerir autenticación. Jenkins es un servidor de [continuous integration](https://en.wikipedia.org/wiki/Continuous_integration). Aquí hay algunos puntos interesantes sobre Jenkins:

- Jenkins fue originalmente llamado Hudson (lanzado en 2005) y se renombró en 2011 después de una disputa con Oracle.
- [Data](https://discovery.hgdata.com/product/jenkins) muestra que más de 86,000 empresas usan Jenkins.
- Jenkins es utilizado por empresas conocidas como Facebook, Netflix, Udemy, Robinhood y LinkedIn.
- Tiene más de 300 plugins para apoyar la construcción y prueba de proyectos.

---

## Discovery/Footprinting

Supongamos que estamos trabajando en una prueba de penetración interna y hemos completado nuestros escaneos de descubrimiento web. Notamos lo que creemos es una instancia de Jenkins y sabemos que a menudo se instala en servidores Windows que se ejecutan como la cuenta SYSTEM todopoderosa. Si podemos acceder a través de Jenkins y obtener ejecución remota de código como la cuenta SYSTEM, tendríamos un punto de apoyo en Active Directory para comenzar la enumeración del entorno del dominio.

Jenkins se ejecuta en el puerto 8080 de Tomcat por defecto. También utiliza el puerto 5000 para adjuntar servidores esclavos. Este puerto se usa para comunicar entre maestros y esclavos. Jenkins puede usar una base de datos local, LDAP, base de datos de usuarios de Unix, delegar la seguridad a un contenedor de servlets, o no usar autenticación en absoluto. Los administradores también pueden permitir o prohibir a los usuarios crear cuentas.

---

## Enumeration

`http://jenkins.inlanefreight.local:8000/configureSecurity/`

![](https://academy.hackthebox.com/storage/modules/113/jenkins_global_security.png)

La instalación por defecto típicamente usa la base de datos de Jenkins para almacenar credenciales y no permite a los usuarios registrar una cuenta. Podemos identificar rápidamente Jenkins por la página de inicio de sesión característica.

`http://jenkins.inlanefreight.local:8000/login?from=%2F`

![](https://academy.hackthebox.com/storage/modules/113/jenkins_login.png)

Podemos encontrar una instancia de Jenkins que use credenciales débiles o predeterminadas como `admin:admin` o que no tenga ningún tipo de autenticación habilitada. No es raro encontrar instancias de Jenkins que no requieren ninguna autenticación durante una prueba de penetración interna. Aunque raro, nos hemos encontrado con Jenkins durante pruebas de penetración externas que pudimos atacar.