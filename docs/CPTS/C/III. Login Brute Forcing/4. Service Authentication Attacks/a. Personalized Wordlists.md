Para crear una wordlist personalizada para el usuario, necesitaremos recopilar algo de información sobre ellos. Como nuestro ejemplo aquí es una figura pública conocida, podemos revisar su [Wikipedia page](https://en.wikipedia.org/wiki/Bill_Gates) o hacer una búsqueda básica en Google para recopilar la información necesaria. Incluso si no fuera una figura conocida, aún podríamos llevar a cabo el mismo ataque y crear una wordlist personalizada para ellos. Todo lo que necesitamos hacer es recopilar información sobre ellos, lo cual se discute en detalle en el módulo de [Hashcat](https://academy.hackthebox.com/module/details/20), así que siéntete libre de revisarlo.

---

## CUPP

Muchas herramientas pueden crear una wordlist de contraseñas personalizada basada en cierta información. La herramienta que usaremos es `cupp`, que está preinstalada en tu PwnBox. Si estamos haciendo el ejercicio desde nuestra propia VM, podemos instalarla con `sudo apt install cupp` o clonarla desde el [repositorio de Github](https://github.com/Mebus/cupp). `Cupp` es muy fácil de usar. La ejecutamos en modo interactivo especificando el argumento `-i` y respondemos las preguntas, como sigue:

```r
cupp -i

___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]

[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: William
> Surname: Gates
> Nickname: Bill
> Birthdate (DDMMYYYY): 28101955

> Partners) name: Melinda
> Partners) nickname: Ann
> Partners) birthdate (DDMMYYYY): 15081964

> Child's name: Jennifer
> Child's nickname: Jenn
> Child's birthdate (DDMMYYYY): 26041996

> Pet's name: Nila
> Company name: Microsoft

> Do you want to add some key words about the victim? Y/[N]: Phoebe,Rory
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:y
> Leet mode? (i.e. leet = 1337) Y/[N]: y

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to william.txt, counting 43368 words.
[+] Now load your pistolero with william.txt and shoot! Good luck!
```

Y como resultado, obtenemos nuestra wordlist de contraseñas personalizada guardada como `william.txt`.

---

## Password Policy

La wordlist de contraseñas personalizada que generamos tiene unas 43,000 líneas. Dado que vimos la política de contraseñas cuando iniciamos sesión, sabemos que la contraseña debe cumplir con las siguientes condiciones:

1. 8 caracteres o más
2. contiene caracteres especiales
3. contiene números

Así que podemos eliminar cualquier contraseña que no cumpla con estas condiciones de nuestra wordlist. Algunas herramientas convertirían las políticas de contraseñas a reglas de `Hashcat` o `John`, pero `hydra` no admite reglas para filtrar contraseñas. Así que simplemente usaremos los siguientes comandos para hacer eso por nosotros:

```r
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

Vemos que estos comandos acortaron la wordlist de 43k contraseñas a alrededor de 13k contraseñas, aproximadamente un 70% más corta.

---

## Mangling

Todavía es posible crear muchas permutaciones de cada palabra en esa lista. Nunca sabemos cómo piensa nuestro objetivo al crear su contraseña, por lo que nuestra opción más segura es agregar tantas alteraciones y permutaciones como sea posible, notando que esto, por supuesto, tomará mucho más tiempo para brute force.

Muchas herramientas excelentes realizan el mangling de palabras y la permutación de mayúsculas/minúsculas de manera rápida y fácil, como [rsmangler](https://github.com/digininja/RSMangler) o [The Mentalist](https://github.com/sc0tfree/mentalist.git). Estas herramientas tienen muchas otras opciones, que pueden hacer que cualquier wordlist pequeña alcance millones de líneas. Debemos tener en cuenta estas herramientas porque podríamos necesitarlas en otros módulos y situaciones.

Como punto de partida, nos ceñiremos a la wordlist que hemos generado hasta ahora y no realizaremos ningún mangling en ella. En caso de que nuestra wordlist no logre un inicio de sesión exitoso, volveremos a estas herramientas y realizaremos algún mangling para aumentar nuestras posibilidades de adivinar la contraseña.

Tip: Cuanto más mangled esté una wordlist, más probabilidades tendrás de acertar una contraseña correcta, pero tomará más tiempo realizar el brute force. Así que siempre trata de ser eficiente y personaliza adecuadamente tu wordlist usando la inteligencia que recopilaste.

---

## Custom Username Wordlist

También deberíamos considerar crear una wordlist personalizada de nombres de usuario basada en los detalles disponibles de la persona. Por ejemplo, el nombre de usuario de la persona podría ser `b.gates` o `gates` o `bill`, y muchas otras variaciones potenciales. Hay varios métodos para crear la lista de nombres de usuario potenciales, el más básico de los cuales es simplemente escribirlo manualmente.

Una herramienta que podemos usar es [Username Anarchy](https://github.com/urbanadventurer/username-anarchy), que podemos clonar desde GitHub, como sigue:

```r
git clone https://github.com/urbanadventurer/username-anarchy.git

Cloning into 'username-anarchy'...
remote: Enumerating objects: 386, done.
remote: Total 386 (delta 0), reused 0 (delta 0), pack-reused 386
Receiving objects: 100% (386/386), 16.76 MiB | 5.38 MiB/s, done.
Resolving deltas: 100% (127/127), done.
```

Esta herramienta tiene muchos casos de uso de los que podemos aprovechar para crear listas avanzadas de nombres de usuario potenciales. Sin embargo, para nuestro caso simple, podemos simplemente ejecutarlo y proporcionar los nombres de pila/apellidos como argumentos, y redirigir la salida a un archivo, como sigue:

```r
./username-anarchy Bill Gates > bill.txt
```

Finalmente, deberíamos tener nuestras wordlists de nombres de usuario y contraseñas listas y podríamos atacar el servidor SSH.