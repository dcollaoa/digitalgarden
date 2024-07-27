El primer paso para cualquier organización debe ser crear un inventario de aplicaciones detallado (y preciso) tanto de aplicaciones internas como externas. Esto se puede lograr de muchas maneras, y los blue teams con un presupuesto limitado podrían beneficiarse de herramientas de pentesting como Nmap y EyeWitness para ayudar en el proceso. Se pueden usar varias herramientas open-source y de pago para crear y mantener este inventario. ¡Sin saber qué existe en el entorno, no sabremos qué proteger! Crear este inventario puede exponer instancias de "shadow IT" (o instalaciones no autorizadas), aplicaciones obsoletas que ya no se necesitan, o incluso problemas como una versión de prueba de una herramienta que se convierte automáticamente en una versión gratuita (como Splunk cuando ya no requiere autenticación).

---

## General Hardening Tips

Las aplicaciones discutidas en esta sección deben ser endurecidas para prevenir compromisos utilizando estas técnicas y otras. A continuación se presentan algunas medidas importantes que pueden ayudar a asegurar implementaciones de WordPress, Drupal, Joomla, Tomcat, Jenkins, osTicket, GitLab, PRTG Network Monitor, y Splunk en cualquier entorno.

- **Secure authentication**: Las aplicaciones deben exigir contraseñas fuertes durante el registro y la configuración, y las contraseñas de las cuentas administrativas por defecto deben ser cambiadas. Si es posible, las cuentas administrativas por defecto deben ser deshabilitadas, creando nuevas cuentas administrativas personalizadas. Algunas aplicaciones admiten inherentemente la autenticación 2FA, que debe ser obligatoria al menos para los usuarios a nivel de administrador.
    
- **Access controls**: Deben implementarse mecanismos de control de acceso adecuados por aplicación. Por ejemplo, las páginas de inicio de sesión no deben ser accesibles desde la red externa a menos que haya una razón comercial válida para este acceso. Del mismo modo, se pueden configurar permisos de archivos y carpetas para denegar cargas o implementaciones de aplicaciones.
    
- **Disable unsafe features**: Características como la edición de código PHP en WordPress pueden deshabilitarse para prevenir la ejecución de código si el servidor es comprometido.
    
- **Regular updates**: Las aplicaciones deben actualizarse regularmente, y los parches suministrados por los proveedores deben aplicarse lo antes posible.
    
- **Backups**: Los administradores de sistemas deben configurar siempre copias de seguridad del sitio web y la base de datos, permitiendo que la aplicación sea restaurada rápidamente en caso de compromiso.
    
- **Security monitoring**: Hay varias herramientas y plugins que se pueden usar para monitorear el estado y varios problemas relacionados con la seguridad de nuestras aplicaciones. Otra opción es un Web Application Firewall (WAF). Aunque no es una bala de plata, un WAF puede ayudar a añadir una capa extra de protección siempre que se hayan tomado todas las medidas anteriores.
    
- **LDAP integration with Active Directory**: Integrar aplicaciones con Active Directory single sign-on puede aumentar la facilidad de acceso, proporcionar más funcionalidad de auditoría (especialmente si está sincronizado con Azure), y hacer que la gestión de credenciales y cuentas de servicio sea más eficiente. También disminuye el número de cuentas y contraseñas que un usuario tendrá que recordar y ofrece un control granular sobre la política de contraseñas.

Cada aplicación que discutimos en este módulo (y más allá) debe seguir pautas clave de hardening, como habilitar la autenticación multifactor para administradores y usuarios siempre que sea posible, cambiar los nombres de cuenta de administrador predeterminados, limitar el número de administradores y cómo los administradores pueden acceder al sitio (por ejemplo, no desde internet abierta), aplicar el principio de privilegio mínimo en toda la aplicación, realizar actualizaciones regulares para abordar vulnerabilidades de seguridad, tomar copias de seguridad regulares en una ubicación secundaria para poder recuperarse rápidamente en caso de un ataque e implementar herramientas de monitoreo de seguridad que puedan detectar y bloquear actividades maliciosas y ataques de fuerza bruta a cuentas, entre otros.

Finalmente, debemos tener cuidado con lo que exponemos a internet. ¿Realmente necesita ser público ese repositorio de GitLab? ¿Nuestro sistema de tickets necesita ser accesible fuera de la red interna? Con estos controles en su lugar, tendremos una base sólida para aplicar a todas las aplicaciones independientemente de su función.

También debemos realizar verificaciones y actualizaciones regulares de nuestro inventario de aplicaciones para asegurarnos de que no estamos exponiendo aplicaciones en la red interna o externa que ya no se necesitan o tienen fallas de seguridad graves. Finalmente, realizar evaluaciones regulares para buscar vulnerabilidades de seguridad y configuraciones incorrectas, así como la exposición de datos sensibles. Siga las recomendaciones de remediación incluidas en los informes de penetration testing y verifique periódicamente los mismos tipos de fallas descubiertas por sus penetration testers. Algunas podrían estar relacionadas con procesos, requiriendo un cambio de mentalidad para que la organización sea más consciente de la seguridad.

---

## Application-Specific Hardening Tips

Aunque los conceptos generales para hardening de aplicaciones se aplican a todas las aplicaciones que discutimos en este módulo y encontraremos en el mundo real, podemos tomar algunas medidas más específicas. Aquí hay algunas:

| Application | Hardening Category | Discussion |
|---|---|---|
| [WordPress](https://wordpress.org/support/article/hardening-wordpress/) | Security monitoring | Use un plugin de seguridad como [WordFence](https://www.wordfence.com/) que incluye monitoreo de seguridad, bloqueo de actividad sospechosa, bloqueo de país, autenticación de dos factores, y más |
| [Joomla](https://docs.joomla.org/Security_Checklist/Joomla!_Setup) | Access controls | Un plugin como [AdminExile](https://extensions.joomla.org/extension/adminexile/) se puede usar para requerir una clave secreta para iniciar sesión en la página de administración de Joomla como `http://joomla.inlanefreight.local/administrator?thisismysecretkey` |
| [Drupal](https://www.drupal.org/docs/security-in-drupal) | Access controls | Deshabilite, oculte, o mueva la [admin login page](https://www.drupal.org/docs/7/managing-users/hide-user-login) |
| [Tomcat](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html) | Access controls | Limite el acceso a las aplicaciones Tomcat Manager y Host-Manager solo a localhost. Si deben ser expuestas externamente, aplique whitelisting de IPs y establezca una contraseña muy fuerte y un nombre de usuario no estándar. |
| [Jenkins](https://www.jenkins.io/doc/book/security/securing-jenkins/) | Access controls | Configure permisos utilizando el [Matrix Authorization Strategy plugin](https://plugins.jenkins.io/matrix-auth) |
| [Splunk](https://docs.splunk.com/Documentation/Splunk/8.2.2/Security/Hardeningstandards) | Regular updates | Asegúrese de cambiar la contraseña por defecto y garantice que Splunk esté correctamente licenciado para forzar la autenticación |
| [PRTG Network Monitor](https://kb.paessler.com/en/topic/61108-what-security-features-does-prtg-include) | Secure authentication | Asegúrese de mantenerse actualizado y cambiar la contraseña predeterminada de PRTG |
| osTicket | Access controls | Limite el acceso desde internet si es posible |
| [GitLab](https://about.gitlab.com/blog/2020/05/20/gitlab-instance-security-best-practices/) | Secure authentication | Haga cumplir las restricciones de registro como requerir aprobación de administrador para nuevos registros, configurar dominios permitidos y denegados |

---

## Conclusion

En este módulo, cubrimos un área crítica del penetration testing: aplicaciones comunes. Las aplicaciones web presentan una enorme superficie de ataque y a menudo pasan desapercibidas. Durante un penetration test externo, a menudo, la mayoría de nuestros objetivos son aplicaciones. Debemos entender cómo descubrir aplicaciones (y organizar nuestros datos de escaneo para procesarlos eficientemente), identificar versiones, descubrir vulnerabilidades conocidas y aprovechar la funcionalidad incorporada. Muchas organizaciones se desempeñan bien con el patching y la gestión de vulnerabilidades, pero a menudo pasan por alto problemas como credenciales débiles para acceder a Tomcat Manager o una impresora con credenciales por defecto para la aplicación de gestión web donde podemos obtener credenciales LDAP para usar como punto de entrada a la red interna. Las tres evaluaciones de habilidades que siguen están destinadas a poner a prueba el proceso de descubrimiento y enumeración de aplicaciones.