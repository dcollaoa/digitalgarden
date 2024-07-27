Una vez que accedimos a la página bajo `/blog`, recibimos un mensaje diciendo `Admin panel moved to academy.htb`. Si visitamos el sitio web en nuestro navegador, obtenemos `can’t connect to the server at www.academy.htb`:

![[Pasted image 20240716004806.png]]

Esto se debe a que los ejercicios que hacemos no son sitios web públicos que pueden ser accedidos por cualquier persona, sino sitios web locales dentro de HTB. Los navegadores solo saben cómo ir a IPs, y si les proporcionamos una URL, intentan mapear la URL a una IP buscando en el archivo local `/etc/hosts` y en el DNS público `Domain Name System`. Si la URL no está en ninguno de los dos, no sabría cómo conectarse a ella.

Si visitamos la IP directamente, el navegador va a esa IP directamente y sabe cómo conectarse. Pero en este caso, le decimos que vaya a `academy.htb`, por lo que busca en el archivo local `/etc/hosts` y no encuentra ninguna mención de él. Pregunta al DNS público sobre ello (como el DNS de Google `8.8.8.8`) y no encuentra ninguna mención, ya que no es un sitio web público, y finalmente falla en conectarse. Entonces, para conectarnos a `academy.htb`, tendríamos que agregarlo a nuestro archivo `/etc/hosts`. Podemos lograrlo con el siguiente comando:

```r
sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'
```

Ahora podemos visitar el sitio web (no olvides agregar el PORT en la URL) y ver que podemos alcanzar el sitio web:

![[Pasted image 20240716004841.png]]

Sin embargo, obtenemos el mismo sitio web que obtuvimos cuando visitamos la IP directamente, por lo que `academy.htb` es el mismo dominio que hemos estado probando hasta ahora. Podemos verificarlo visitando `/blog/index.php` y ver que podemos acceder a la página.

Cuando ejecutamos nuestras pruebas en esta IP, no encontramos nada sobre `admin` o panels, incluso cuando hicimos un escaneo `recursive` completo en nuestro objetivo. Así que, en este caso, comenzamos a buscar sub-dominios bajo `*.academy.htb` y ver si encontramos algo, lo cual es lo que intentaremos en la próxima sección.