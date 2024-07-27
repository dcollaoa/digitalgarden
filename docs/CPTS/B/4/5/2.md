Desde un punto de apoyo en un host Windows unido a un dominio, la herramienta [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) es altamente efectiva. Si estamos autenticados en el dominio, la herramienta generará automáticamente una lista de usuarios desde Active Directory, consultará la política de contraseñas del dominio y excluirá las cuentas de usuario que estén a un intento de bloquearse. Al igual que ejecutamos el ataque de spraying desde nuestro host Linux, también podemos proporcionar una lista de usuarios a la herramienta si estamos en un host Windows pero no autenticados en el dominio. Podríamos encontrarnos en una situación en la que el cliente quiera que realicemos pruebas desde un dispositivo Windows gestionado en su red al que podamos cargar herramientas. Podríamos estar físicamente en sus oficinas y desear probar desde una VM de Windows, o podríamos obtener un punto de apoyo inicial a través de otro ataque, autenticarnos en un host en el dominio y realizar password spraying en un intento de obtener credenciales para una cuenta que tenga más derechos en el dominio.

Hay varias opciones disponibles para nosotros con la herramienta. Dado que el host está unido a un dominio, omitiremos la flag `-UserList` y dejaremos que la herramienta genere una lista para nosotros. Proporcionaremos la flag `Password` y una sola contraseña, y luego usaremos la flag `-OutFile` para escribir nuestra salida en un archivo para su uso posterior.

### Using DomainPasswordSpray.ps1

```r
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] The smallest lockout threshold discovered in the domain is 5 login attempts.
[*] Removing disabled users from list.
[*] There are 2923 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 2923 users gathered from the current user's domain
[*] The domain password policy observation window is set to  minutes.
[*] Setting a  minute wait in between sprays.

Confirm Password Spray
Are you sure you want to perform a password spray against 2923 accounts?
[Y] Yes  [N] No  [?] Help (default is "Y"): Y

[*] Password spraying has begun with  1  passwords
[*] This might take a while depending on the total number of users
[*] Now trying password Welcome1 against 2923 users. Current time is 2:57 PM
[*] Writing successes to spray_success
[*] SUCCESS! User:sgage Password:Welcome1
[*] SUCCESS! User:tjohnson Password:Welcome1

[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to spray_success
```

También podríamos utilizar Kerbrute para realizar los mismos pasos de enumeración y spraying de usuarios mostrados en la sección anterior. La herramienta está presente en el directorio `C:\Tools` si deseas trabajar con los mismos ejemplos desde el host Windows proporcionado.

---

## Mitigations

Se pueden tomar varios pasos para mitigar el riesgo de ataques de password spraying. Aunque ninguna solución única prevendrá completamente el ataque, un enfoque de defensa en profundidad hará que los ataques de password spraying sean extremadamente difíciles.

| Técnica | Descripción |
|---|---|
| `Multi-factor Authentication` | La autenticación multifactor puede reducir en gran medida el riesgo de ataques de password spraying. Existen muchos tipos de autenticación multifactor, como notificaciones push a un dispositivo móvil, una contraseña de un solo uso (OTP) rotatoria como Google Authenticator, clave RSA o confirmaciones por mensaje de texto. Aunque esto puede evitar que un atacante obtenga acceso a una cuenta, ciertas implementaciones de multifactor aún revelan si la combinación de nombre de usuario/contraseña es válida. Es posible que se pueda reutilizar esta credencial contra otros servicios o aplicaciones expuestas. Es importante implementar soluciones multifactor en todos los portales externos. |
| `Restricting Access` | A menudo es posible iniciar sesión en aplicaciones con cualquier cuenta de usuario del dominio, incluso si el usuario no necesita acceder a ella como parte de su rol. En línea con el principio de privilegio mínimo, el acceso a la aplicación debe restringirse a aquellos que lo requieran. |
| `Reducing Impact of Successful Exploitation` | Un éxito rápido es asegurar que los usuarios privilegiados tengan una cuenta separada para cualquier actividad administrativa. También se deben implementar niveles de permiso específicos de la aplicación si es posible. También se recomienda la segmentación de la red, porque si un atacante está aislado a un subred comprometida, esto puede ralentizar o detener por completo el movimiento lateral y el compromiso adicional. |
| `Password Hygiene` | Educar a los usuarios sobre la selección de contraseñas difíciles de adivinar, como frases de contraseña, puede reducir significativamente la eficacia de un ataque de password spraying. Además, usar un filtro de contraseñas para restringir palabras comunes del diccionario, nombres de meses y estaciones, y variaciones del nombre de la empresa hará que sea bastante difícil para un atacante elegir una contraseña válida para intentos de spraying. |

---

## Other Considerations

Es vital asegurarse de que la política de bloqueo de contraseñas del dominio no aumente el riesgo de ataques de denegación de servicio. Si es muy restrictiva y requiere una intervención administrativa para desbloquear cuentas manualmente, un password spray descuidado puede bloquear muchas cuentas en un corto período.

---

## Detection

Algunos indicadores de ataques de password spraying externos incluyen muchos bloqueos de cuentas en un corto período, registros de servidores o aplicaciones que muestran muchos intentos de inicio de sesión con usuarios válidos o inexistentes, o muchas solicitudes en un corto período a una aplicación o URL específica.

En el registro de seguridad del Domain Controller, muchas instancias del ID de evento [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625) en un corto período pueden indicar un ataque de password spraying. Las organizaciones deben tener reglas para correlacionar muchos fallos de inicio de sesión dentro de un intervalo de tiempo establecido para activar una alerta. Un atacante más astuto puede evitar el password spraying de SMB y en su lugar apuntar a LDAP. Las organizaciones también deben monitorear el ID de evento [4771: Kerberos pre-authentication failed](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4771), que puede indicar un intento de password spraying de LDAP. Para hacerlo, necesitarán habilitar el registro de Kerberos. Este [post](https://www.hub.trimarcsecurity.com/post/trimarc-research-detecting-password-spraying-with-security-event-auditing) detalla la investigación sobre la detección de password spraying utilizando el registro de eventos de seguridad de Windows.

Con estas mitigaciones finamente ajustadas y con el registro habilitado, una organización estará bien posicionada para detectar y defenderse de los ataques de password spraying internos y externos.

---

## External Password Spraying

Aunque fuera del alcance de este módulo, el password spraying es también una forma común en la que los atacantes intentan obtener un punto de apoyo en internet. Hemos tenido mucho éxito con este método durante las pruebas de penetración para obtener acceso a datos sensibles a través de bandejas de correo electrónico o aplicaciones web como sitios de intranet que enfrentan el exterior. Algunos objetivos comunes incluyen:

- Microsoft 0365
- Outlook Web Exchange
- Exchange Web Access
- Skype for Business
- Lync Server
- Microsoft Remote Desktop Services (RDS) Portals
- Citrix portals using AD authentication
- VDI implementations using AD authentication such as VMware Horizon
- VPN portals (Citrix, SonicWall, OpenVPN, Fortinet, etc. that use AD authentication)
- Custom web applications that use AD authentication

---

## Moving Deeper

Ahora que tenemos varios conjuntos de credenciales válidas, podemos comenzar a profundizar en el dominio realizando una enumeración con credenciales con varias herramientas. Recorreremos varias herramientas que se complementan entre sí para darnos la imagen más completa y precisa de un entorno de dominio. Con esta información, buscaremos movernos lateral y verticalmente en el dominio para eventualmente alcanzar el objetivo final de nuestra evaluación.