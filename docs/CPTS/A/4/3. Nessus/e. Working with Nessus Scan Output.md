Nessus nos da la opción de exportar los resultados de los escaneos en una variedad de formatos de informe, así como la opción de exportar los resultados crudos de los escaneos de Nessus para ser importados en otras herramientas, archivados o pasados a herramientas como [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness), que puede ser utilizada para tomar capturas de pantalla de todas las aplicaciones web identificadas por Nessus y ayudarnos en gran medida a trabajar con los resultados y encontrarles más valor.

---

## Nessus Reports

Una vez que un escaneo se completa, podemos elegir exportar un informe en formatos `.pdf`, `.html` o `.csv`. Los informes en .pdf y .html dan la opción de un Resumen Ejecutivo o un informe personalizado. El informe de Resumen Ejecutivo proporciona una lista de hosts, un número total de vulnerabilidades descubiertas por host, y una opción `Show Details` para ver la severidad, el puntaje CVSS, el número del plugin y el nombre de cada problema descubierto. El número del plugin contiene un enlace al informe completo del plugin en la base de datos de plugins de Tenable. La opción PDF proporciona los resultados del escaneo en un formato más fácil de compartir. La opción de informe CSV nos permite seleccionar qué columnas nos gustaría exportar. Esto es particularmente útil si se importan los resultados del escaneo en otra herramienta como Splunk, si se necesita compartir un documento con muchos stakeholders internos responsables de la remediación de los diversos activos escaneados o para realizar análisis sobre los datos del escaneo.

![image](https://academy.hackthebox.com/storage/modules/108/nessus/exportreport.png)

**Nota:** Estos informes de escaneo solo deben compartirse como un apéndice o datos suplementarios a un informe personalizado de prueba de penetración/evaluación de vulnerabilidades. No deben entregarse a un cliente como el producto final de cualquier tipo de evaluación.

A continuación se muestra un ejemplo del informe HTML:

![image](https://academy.hackthebox.com/storage/modules/108/nessus/htmlreport.png)

Es mejor asegurarse siempre de que las vulnerabilidades estén agrupadas para una comprensión clara de cada problema y los activos afectados.

---

## Exporting Nessus Scans

Nessus también da la opción de exportar escaneos en dos formatos: `Nessus (scan.nessus)` o `Nessus DB (scan.db)`. El archivo `.nessus` es un archivo `.xml` e incluye una copia de la configuración del escaneo y las salidas de los plugins. El archivo `.db` contiene el archivo `.nessus` y el KB del escaneo, el Audit Trail del plugin y cualquier adjunto del escaneo. Más información sobre el `KB` y el `Audit Trail` puede encontrarse [aquí](https://community.tenable.com/s/article/What-is-included-in-a-nessus-db-file).

Scripts como el [nessus-report-downloader](https://raw.githubusercontent.com/eelsivart/nessus-report-downloader/master/nessus6-report-downloader.rb) pueden ser usados para descargar rápidamente los resultados del escaneo en todos los formatos disponibles desde la CLI usando la REST API de Nessus:

```r
./nessus_downloader.rb 

Nessus 6 Report Downloader 1.0

Enter the Nessus Server IP: 127.0.0.1
Enter the Nessus Server Port [8834]: 8834
Enter your Nessus Username: admin
Enter your Nessus Password (will not echo): 

Getting report list...
Scan ID Name                                               Last Modified                  Status         
------- ----                                               -------------                  ------         
1     Windows_basic                                Aug 22, 2020 22:07 +00:00      completed      
         
Enter the report(s) your want to download (comma separate list) or 'all': 1

Choose File Type(s) to Download: 
[0] Nessus (No chapter selection)
[1] HTML
[2] PDF
[3] CSV (No chapter selection)
[4] DB (No chapter selection)
Enter the file type(s) you want to download (comma separate list) or 'all': 3

Path to save reports to (without trailing slash): /assessment_data/inlanefreight/scans/nessus

Downloading report(s). Please wait...

[+] Exporting scan report, scan id: 1, type: csv
[+] Checking export status...
[+] Report ready for download...
[+] Downloading report to: /assessment_data/inlanefreight/scans/nessus/inlanefreight_basic_5y3hxp.csv

Report Download Completed!
```

También podemos escribir nuestros propios scripts para automatizar muchas características de Nessus.
