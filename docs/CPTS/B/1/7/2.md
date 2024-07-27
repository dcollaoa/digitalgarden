Parece que todo requiere una contraseña hoy en día. Usamos contraseñas para nuestro Wi-Fi de casa, redes sociales, cuentas bancarias, correos electrónicos de negocios e incluso nuestras aplicaciones y sitios web favoritos. Según este [estudio de NordPass](https://www.techradar.com/news/most-people-have-25-more-passwords-than-at-the-start-of-the-pandemic), la persona promedio tiene 100 contraseñas, lo cual es una de las razones por las que la mayoría de las personas reutilizan contraseñas o crean contraseñas simples.

Con todo esto en mente, necesitamos contraseñas diferentes y seguras, pero no todos pueden memorizar cientos de contraseñas que cumplan con la complejidad requerida para ser seguras. Necesitamos algo que nos ayude a organizar nuestras contraseñas de manera segura. Un [password manager](https://en.wikipedia.org/wiki/Password_manager) es una aplicación que permite a los usuarios almacenar sus contraseñas y secretos en una base de datos encriptada. Además de mantener nuestras contraseñas y datos sensibles seguros, también tienen características para generar y gestionar contraseñas robustas y únicas, 2FA, llenar formularios web, integración con navegadores, sincronización entre múltiples dispositivos, alertas de seguridad, entre otras características.

## How Does a Password Manager Work?

La implementación de los password managers varía según el fabricante, pero la mayoría funciona con una master password para encriptar la base de datos.

La encriptación y autenticación funcionan utilizando diferentes [Cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) y [key derivations functions](https://en.wikipedia.org/wiki/Key_derivation_function), para prevenir el acceso no autorizado a nuestra base de datos de contraseñas encriptadas y su contenido. La forma en que esto funciona depende del fabricante y si el password manager es offline o online.

Desglosemos los password managers comunes y cómo funcionan.

## Online Password Managers

Uno de los elementos clave al decidir sobre un password manager es la conveniencia. Una persona típica tiene 3 o 4 dispositivos y los usa para iniciar sesión en diferentes sitios web, aplicaciones, etc. Un online password manager permite al usuario sincronizar su base de datos de contraseñas encriptada entre múltiples dispositivos, la mayoría de ellos proporcionan:

- Una aplicación móvil.
- Un complemento para el navegador.
- Algunas otras características que discutiremos más adelante en esta sección.

Todos los proveedores de password managers tienen su manera de gestionar la implementación de seguridad y generalmente proporcionan un documento técnico que describe cómo funciona. Puedes consultar la documentación de [Bitwarden](https://bitwarden.com/images/resources/security-white-paper-download.pdf), [1Password](https://1passwordstatic.com/files/security/1password-white-paper.pdf) y [LastPass](https://assets.cdngetgo.com/da/ce/d211c1074dea84e06cad6f2c8b8e/lastpass-technical-whitepaper.pdf) como referencia, pero hay muchos otros. Hablemos de cómo funciona esto en general.

Una implementación común para los online password managers es derivar claves basadas en la master password. Su propósito es proporcionar una [Zero Knowledge Encryption](https://blog.cubbit.io/blog-posts/what-is-zero-knowledge-encryption), lo que significa que nadie, excepto tú (ni siquiera el proveedor de servicios), puede acceder a tus datos asegurados. Para lograr esto, comúnmente derivan la master password. Utilicemos la implementación técnica de Bitwarden para la derivación de contraseñas para explicar cómo funciona:

1. Master Key: creada por alguna función para convertir la master password en un hash.
2. Master Password Hash: creada por alguna función para convertir la master password con una combinación de la master key en un hash para autenticarse en la nube.
3. Decryption Key: creada por alguna función utilizando la master key para formar una Symmetric Key para desencriptar elementos del Vault.

![Bitwarden Diagram](https://academy.hackthebox.com/storage/modules/147/bitwarden_diagram.png)

Esta es una forma simple de ilustrar cómo funcionan los password managers, pero la implementación común es más compleja. Puedes consultar los documentos técnicos mencionados arriba o ver el video [How Password Managers Work - Computerphile](https://www.youtube.com/watch?v=w68BBPDAWr8).

Los online password managers más populares son:

1. [1Password](https://1password.com/)
2. [Bitwarden](https://bitwarden.com/)
3. [Dashlane](https://www.dashlane.com/)
4. [Keeper](https://www.keepersecurity.com/)
5. [Lastpass](https://www.lastpass.com/)
6. [NordPass](https://nordpass.com/)
7. [RoboForm](https://www.roboform.com/)

## Local Password Managers

Algunas compañías e individuos prefieren gestionar su seguridad por diferentes razones y no depender de los servicios proporcionados por terceros. Los local password managers ofrecen esta opción al almacenar la base de datos localmente y poner la responsabilidad en el usuario para proteger su contenido y la ubicación donde se almacena. [Dashlane](https://www.dashlane.com/) escribió un blog post [Password Manager Storage: Cloud vs. Local](https://blog.dashlane.com/password-storage-cloud-versus-local/) que puede ayudarte a descubrir los pros y contras de cada almacenamiento. El blog post afirma: "Al principio, puede parecer que esto hace que el almacenamiento local sea más seguro que el almacenamiento en la nube, pero la ciberseguridad no es una disciplina simple". Puedes usar este blog para comenzar tu investigación y entender qué método serviría mejor en los diferentes escenarios donde necesitas gestionar contraseñas.

Los local password managers encriptan el archivo de la base de datos utilizando una master key. La master key puede consistir en uno o múltiples componentes: una master password, un key file, un username, password, etc. Generalmente, todas las partes de la master key son necesarias para acceder a la base de datos.

La encriptación de los local password managers es similar a las implementaciones en la nube. La diferencia más notable es la transmisión de datos y la autenticación. Para encriptar la base de datos, los local password managers se centran en asegurar la base de datos local utilizando diferentes cryptographic hash functions (dependiendo del fabricante). También utilizan la key derivation function (random salt) para evitar precomputar claves y dificultar los ataques de diccionario y de adivinanza. Algunos ofrecen protección de memoria y protección contra keyloggers utilizando un escritorio seguro, similar al User Account Control (UAC) de Windows.

Los local password managers más populares son:

1. [KeePass](https://keepass.info/)
2. [KWalletManager](https://apps.kde.org/kwalletmanager5/)
3. [Pleasant Password Server](https://pleasantpasswords.com/)
4. [Password Safe](https://pwsafe.org/)

## Features

Imaginemos que usamos Linux, Android y Chrome OS. Accedemos a todas nuestras aplicaciones y sitios web desde cualquier dispositivo. Queremos sincronizar todas las contraseñas y notas seguras en todos los dispositivos. Necesitamos protección extra con 2FA, y nuestro presupuesto es de 1USD mensual. Esa información puede ayudarnos a identificar el password manager correcto para nosotros.

Al decidir sobre un cloud o local password manager, necesitamos entender sus características, [Wikipedia](https://en.wikipedia.org/wiki/List_of_password_managers) tiene una lista de password managers (online y local) así como algunas de sus características. Aquí hay una lista de las características más comunes para los password managers:

1. [2FA](https://authy.com/what-is-2fa/) support.
2. Multi-platform (Android, iOS, Windows, Linux, Mac, etc.).
3. Browser Extension.
4. Login Autocomplete.
5. Import and export capabilities.
6. Password generation.

## Alternatives

Las contraseñas son la forma más común de autenticación pero no la única. Como aprendimos en este módulo, hay múltiples formas de comprometer una contraseña, cracking, guessing, shoulder surfing, etc., pero ¿qué pasaría si no necesitamos una contraseña para iniciar sesión? ¿Es posible algo así?

Por defecto, la mayoría de los sistemas operativos y aplicaciones no admiten ninguna alternativa a una contraseña. Aún así, los administradores pueden usar proveedores de identidad de terceros o aplicaciones para configurar o mejorar la protección de identidad en sus organizaciones. Algunas de las formas más comunes de asegurar identidades más allá de las contraseñas son:

1. [Multi-factor Authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication).
2. [FIDO2](https://fidoalliance.org/fido2/) open authentication standard, que permite a los usuarios aprovechar dispositivos comunes como [Yubikey](https://www.yubico.com/), para autenticarse fácilmente. Para una lista de dispositivos más amplia, puedes ver [Microsoft FIDO2 security key providers](https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-passwordless#fido2-security-key-providers).
3. [One-Time Password (OTP)](https://en.wikipedia.org/wiki/One-time_password).
4. [Time-based one-time password (TOTP)](https://en.wikipedia.org/wiki/Time-based_one-time_password).
5. [IP restriction](https://news.gandi.net/en/2019/05/using-ip-restriction-to-help-secure-your-account/).
6. Device Compliance. Ejemplos: [Endpoint Manager](https://www.petervanderwoude.nl/post/tag/device-compliance/) o [Workspace ONE](https://www.loginconsultants.com/enabling-the-device-compliance-with-workspace-one-uem-authentication-policy-in-workspace-one-access)

## Passwordless

Múltiples compañías como [Microsoft](https://www.microsoft.com/en-us), [Auth0](https://auth0.com/), [Okta](https://www.okta.com/), [Ping Identity](https://www.pingidentity.com/en.html), etc., están tratando de promover la estrategia de [Passwordless](https://en.wikipedia.org/wiki/Passwordless_authentication), para eliminar la contraseña como forma de autenticación.

[Passwordless](https://www.pingidentity.com/en/resources/blog/posts/2021/what-does-passwordless-really-mean.html) authentication se logra cuando se utiliza un factor de autenticación distinto a una contraseña. Una contraseña es un factor de conocimiento, lo que significa que es algo que un usuario sabe. El problema de depender únicamente de un factor de conocimiento es que es vulnerable al robo, al compartirlo, al uso repetido, al mal uso y a otros riesgos. La autenticación sin contraseña significa en última instancia que ya no hay más contraseñas. En su lugar, se basa en un factor de posesión, algo que el usuario tiene, o un factor inherente, que es el usuario, para verificar la identidad del usuario con mayor certeza.

A medida que la nueva tecnología y los estándares evolucionan, necesitamos investigar y comprender los detalles de su implementación para entender si esas alternativas proporcionarán o no la seguridad que necesitamos para el proceso de autenticación. Puedes leer más sobre la autenticación sin contraseña y las estrategias de diferentes proveedores:

1. [Microsoft Passwordless](https://www.microsoft.com/en-us/security/business/identity-access-management/passwordless-authentication)
2. [Auth0 Passwordless](https://auth0.com/passwordless)
3. [Okta Passwordless](https://www.okta.com/passwordless-authentication/)
4. [PingIdentity](https://www.pingidentity.com/en/resources/blog/posts/2021/what-does-passwordless-really-mean.html)

Hay muchas opciones cuando se trata de proteger contraseñas. Elegir la correcta dependerá de los requisitos individuales o de la compañía. Es común que las personas y las compañías utilicen diferentes métodos de protección de contraseñas para diversos propósitos.