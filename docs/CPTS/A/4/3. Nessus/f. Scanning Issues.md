Nessus es una plataforma de escaneo de vulnerabilidades bien conocida y ampliamente utilizada. Sin embargo, se deben tener en cuenta algunas mejores prácticas antes de comenzar un escaneo. Los escaneos pueden causar problemas en redes sensibles y proporcionar falsos positivos, no dar resultados o tener un impacto desfavorable en la red. Siempre es mejor comunicarse con tu cliente (o con las partes interesadas internas si se está ejecutando un escaneo en tu propia red) para determinar si se deben excluir del escaneo algunos hosts sensibles/legados o si se deben escanear por separado hosts de alta prioridad/alta disponibilidad, fuera del horario laboral habitual, o con diferentes configuraciones de escaneo para evitar posibles problemas.

También hay momentos en que un escaneo puede devolver resultados inesperados y necesitar ajustes.

---

## Mitigating Issues

Algunos firewalls pueden hacer que recibamos resultados de escaneo que muestran todos los puertos abiertos o ningún puerto abierto. Si esto sucede, una solución rápida suele ser configurar un Advanced Scan y desactivar la opción `Ping the remote host`. Esto evitará que el escaneo use ICMP para verificar que el host está "vivo" y en su lugar procederá con el escaneo. Algunos firewalls pueden devolver un mensaje de "ICMP Unreachable" que Nessus interpretará como un host en vivo y proporcionará muchos hallazgos informativos falsos positivos.

En redes sensibles, podemos usar limitación de tasa para minimizar el impacto. Por ejemplo, podemos ajustar las `Performance Options` y modificar `Max Concurrent Checks Per Host` si el host de destino está frecuentemente bajo una carga pesada, como una aplicación web ampliamente utilizada. Esto limitará el número de plugins utilizados simultáneamente contra el host.

Podemos evitar escanear sistemas heredados y elegir la opción de no escanear impresoras, como mostramos en una sección anterior. Si un host es de particular preocupación, debería quedar fuera del alcance del objetivo o podemos usar el archivo `nessusd.rules` para configurar los escaneos de Nessus. Más información sobre esto se puede encontrar [aquí](https://community.tenable.com/s/article/What-is-the-Nessus-rules-file?language=en_US).

Finalmente, a menos que se solicite específicamente, nunca debemos realizar [Denial of Service checks](https://www.tenable.com/plugins/nessus/families/Denial%20of%20Service). Podemos asegurarnos de que este tipo de plugins no se utilicen habilitando siempre la opción ["safe checks"](https://www.tenable.com/blog/understanding-the-nessus-safe-checks-option) al realizar escaneos para evitar cualquier plugin de red que pueda tener un impacto negativo en un objetivo, como bloquear un daemon de red. Habilitar la opción de "safe checks" no garantiza que un escaneo de vulnerabilidades de Nessus no tendrá ningún impacto adverso, pero minimizará significativamente el impacto potencial y disminuirá el tiempo de escaneo.

Siempre es mejor comunicarse con nuestros clientes o partes interesadas internas y alertar al personal necesario antes de comenzar un escaneo. Cuando el escaneo se complete, debemos mantener registros detallados de la actividad de escaneo en caso de que ocurra un incidente que deba ser investigado.

---

## Network Impact

También es esencial tener en cuenta el impacto potencial de los escaneos de vulnerabilidades en una red, especialmente en enlaces de baja capacidad o congestionados. Esto se puede medir utilizando [vnstat](https://humdi.net/vnstat/):

```r
sudo apt install vnstat
```

Vamos a monitorear el adaptador de red `eth0` antes de ejecutar un escaneo de Nessus:

```r
sudo vnstat -l -i eth0

Monitoring eth0...    (press CTRL-C to stop)

   rx:       332 bit/s     0 p/s          tx:       332 bit/s     0 p/s

   rx:         0 bit/s     0 p/s          tx:         0 bit/s     0 p/s
   rx:         0 bit/s     0 p/s          tx:         0 bit/s     0 p/s^C

 eth0  /  traffic statistics

                           rx         |       tx
--------------------------------------+------------------
  bytes                        572 B  |           392 B
--------------------------------------+------------------
          max              480 bit/s  |       332 bit/s
      average              114 bit/s  |        78 bit/s
          min                0 bit/s  |         0 bit/s
--------------------------------------+------------------
  packets                          8  |               5
--------------------------------------+------------------
          max                  1 p/s  |           0 p/s
      average                  0 p/s  |           0 p/s
          min                  0 p/s  |           0 p/s
--------------------------------------+------------------
  time                    40 seconds
```

Podemos comparar este resultado con el resultado que obtenemos al monitorear la misma interfaz durante un escaneo de Nessus contra un solo host:

```r
sudo vnstat -l -i eth0

Monitoring eth0...    (press CTRL-C to stop)

   rx:   307.92 kbit/s   641 p/s          tx:   380.41 kbit/s   767 p/s^C

 eth0  /  traffic statistics

                           rx         |       tx
--------------------------------------+------------------
  bytes                     1.04 MiB  |        1.34 MiB
--------------------------------------+------------------
          max          414.81 kbit/s  |   480.59 kbit/s
      average          230.57 kbit/s  |   296.72 kbit/s
          min                0 bit/s  |         0 bit/s
--------------------------------------+------------------
  packets                      18252  |           22733
--------------------------------------+------------------
          max                864 p/s  |         969 p/s
      average                480 p/s  |         598 p/s
          min                  0 p/s  |           0 p/s
--------------------------------------+------------------
  time                    38 seconds


real  0m38.588s
user  0m0.002s
sys 0m0.016s
```

Al comparar los resultados, podemos ver que la cantidad de bytes y paquetes transferidos durante un escaneo de vulnerabilidades es bastante significativa y puede afectar gravemente a una red si no se ajusta correctamente o se realiza contra dispositivos frágiles/sensibles.