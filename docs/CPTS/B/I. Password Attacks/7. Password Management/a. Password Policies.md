Ahora que hemos trabajado a través de numerosas formas de capturar credenciales y contraseñas, cubramos algunas mejores prácticas relacionadas con las contraseñas y la protección de identidad. Los límites de velocidad y las leyes de tránsito existen para que conduzcamos de manera segura. Sin ellas, conducir sería un caos. Lo mismo ocurre cuando una empresa no tiene políticas adecuadas en su lugar; todos podrían hacer lo que quisieran sin consecuencias. Es por eso que los proveedores de servicios y los administradores utilizan diferentes políticas y aplican métodos para hacerlas cumplir, logrando así una mejor seguridad.

Conozcamos a Mark, un nuevo empleado de Inlanefreight Corp. Mark no trabaja en TI, y no es consciente del riesgo de una contraseña débil. Necesita establecer su contraseña para su correo electrónico empresarial. Elige la contraseña `password123`. Sin embargo, recibe un error que dice que la contraseña no cumple con la política de contraseñas de la empresa y un mensaje que le informa los requisitos mínimos para que la contraseña sea más segura.

En este ejemplo, tenemos dos piezas esenciales, una definición de la política de contraseñas y la aplicación de la misma. La definición es una guía, y la aplicación es la tecnología utilizada para hacer que los usuarios cumplan con la política. Ambos aspectos de la implementación de la política de contraseñas son esenciales. Durante esta lección, exploraremos ambos y entenderemos cómo podemos crear una política de contraseñas efectiva y su implementación.

---

## Password Policy

Una [password policy](https://en.wikipedia.org/wiki/Password_policy) es un conjunto de reglas diseñadas para mejorar la seguridad informática alentando a los usuarios a emplear contraseñas fuertes y usarlas adecuadamente según la definición de la empresa. El alcance de una política de contraseñas no se limita a los requisitos mínimos de la contraseña, sino a todo el ciclo de vida de una contraseña (como la manipulación, el almacenamiento y la transmisión).

---

## Password Policy Standards

Debido al cumplimiento y las mejores prácticas, muchas empresas utilizan [IT security standards](https://en.wikipedia.org/wiki/IT_security_standards). Aunque cumplir con un estándar no significa que estemos 100% seguros, es una práctica común dentro de la industria que define una base de controles de seguridad para las organizaciones. Esto no debería ser la única forma de medir la efectividad de los controles de seguridad organizacionales.

Algunos estándares de seguridad incluyen una sección para políticas de contraseñas o directrices de contraseñas. Aquí hay una lista de los más comunes:

1. [NIST SP800-63B](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63b.pdf)
    
2. [CIS Password Policy Guide](https://www.cisecurity.org/insights/white-papers/cis-password-policy-guide)
    
3. [PCI DSS](https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss)
    

Podemos utilizar esos estándares para entender diferentes perspectivas de las políticas de contraseñas. Después de eso, podemos usar esta información para crear nuestra política de contraseñas. Tomemos un caso de uso donde diferentes estándares usan un enfoque diferente, `password expiration`.

`Change your password periodically (e.g., 90 days) to be more secure` puede ser una frase que hayamos escuchado un par de veces, pero la verdad es que no todas las empresas están utilizando esta política. Algunas empresas solo requieren que sus usuarios cambien la contraseña cuando hay evidencia de compromiso. Si miramos algunos de los estándares anteriores, algunos requieren que los usuarios cambien la contraseña periódicamente y otros no. Debemos detenernos y pensar, desafiar los estándares y definir lo que es mejor para nuestras necesidades.

---

## Password Policy Recommendations

Creamos una política de contraseñas de muestra para ilustrar algunas cosas importantes a tener en cuenta al crear una política de contraseñas. Nuestra política de contraseñas de muestra indica que todas las contraseñas deben:

- Tener un mínimo de 8 caracteres.
- Incluir letras mayúsculas y minúsculas.
- Incluir al menos un número.
- Incluir al menos un carácter especial.
- No debe ser el nombre de usuario.
- Debe cambiarse cada 60 días.

Nuestro nuevo empleado, Mark, que recibió un error al crear el correo electrónico con la contraseña `password123`, ahora elige la siguiente contraseña `Inlanefreight01!` y registra su cuenta con éxito. Aunque esta contraseña cumple con las políticas de la empresa, no es segura y es fácilmente adivinable porque usa el nombre de la empresa como parte de la contraseña. Aprendimos en la sección "Password Mutations" que esta es una práctica común de los empleados y los atacantes son conscientes de esto.

Una vez que esta contraseña alcance el tiempo de expiración, Mark puede cambiar 01 a 02, y su contraseña cumple con la política de contraseñas de la empresa, pero la contraseña es casi la misma. Debido a esto, los profesionales de la seguridad tienen una discusión abierta sobre la expiración de contraseñas y cuándo se debe exigir a un usuario que cambie su contraseña.

Basándonos en este ejemplo, debemos incluir, como parte de nuestras políticas de contraseñas, algunas palabras en la lista negra, que incluyen, pero no se limitan a:

- El nombre de la empresa
- Palabras comunes asociadas con la empresa
- Nombres de meses
- Nombres de estaciones del año
- Variaciones de la palabra bienvenida y contraseña
- Palabras comunes y adivinables como password, 123456 y abcde

---

## Enforcing Password Policy

Una política de contraseñas es una guía que define cómo debemos crear, manipular y almacenar contraseñas en la organización. Para aplicar esta guía, necesitamos hacerla cumplir, utilizando la tecnología a nuestra disposición o adquiriendo lo necesario para que esto funcione. La mayoría de las aplicaciones y administradores de identidades proporcionan métodos para aplicar nuestra política de contraseñas.

Por ejemplo, si usamos Active Directory para la autenticación, necesitamos configurar un [Active Directory Password Policy GPO](https://activedirectorypro.com/how-to-configure-a-domain-password-policy/), para obligar a nuestros usuarios a cumplir con nuestra política de contraseñas.

Una vez que el aspecto técnico esté cubierto, necesitamos comunicar la política a la empresa y crear procesos y procedimientos para garantizar que nuestra política de contraseñas se aplique en todas partes.

---

## Creating a Good password

Crear una buena contraseña puede ser fácil. Usemos [PasswordMonster](https://www.passwordmonster.com/), un sitio web que nos ayuda a probar qué tan fuertes son nuestras contraseñas, y [1Password Password Generator](https://1password.com/password-generator/), otro sitio web para generar contraseñas seguras.

![Strong Password Generated by the tool](https://academy.hackthebox.com/storage/modules/147/strong_password_1.png)

`CjDC2x[U` fue la contraseña generada por la herramienta, y es una buena contraseña. Tomaría mucho tiempo descifrarla y probablemente no sería adivinada u obtenida en un ataque de rociado de contraseñas, pero es difícil de recordar.

Podemos crear buenas contraseñas con palabras comunes, frases e incluso canciones que nos gusten. Aquí hay un ejemplo de una buena contraseña `This is my secure password` o `The name of my dog is Poppy`. Podemos combinar esas contraseñas con caracteres especiales para hacerlas más complejas, como `()The name of my dog is Poppy!`. Aunque es difícil de adivinar, debemos tener en cuenta que los atacantes pueden usar OSINT para aprender sobre nosotros, y debemos tener esto en cuenta al crear contraseñas.

![Strong Password with a Phrase](https://academy.hackthebox.com/storage/modules/147/strong_password_phrase.png)

Con este método, podemos crear y memorizar 3, 4 o más contraseñas, pero a medida que la lista aumenta, será difícil recordar todas nuestras contraseñas. En la siguiente sección, discutiremos el uso de un Administrador de Contraseñas para ayudarnos a crear y mantener la gran cantidad de contraseñas que tenemos.