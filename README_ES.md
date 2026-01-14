<h1 align="center">NearPath</h1>
<p align="center">
  🇺🇸 <a href="README.md"><b>English</b></a> |
  🇪🇸 <a href="README_ES.md">Español</a>
</p>
<h2 align="center">Fuzzer de Superficie Guiado & Motor de Descubrimiento de Contenido</h2>

<h3 align="center">
NearPath es una herramienta ligera de fuzzing guiado diseñada para descubrir endpoints ocultos en aplicaciones web combinando crawling superficial, análisis de JavaScript y mutación heurística de rutas.
No hace fuerza bruta con grandes wordlists. En su lugar, expande lo que la aplicación ya revela y sondea inteligentemente lo que probablemente exista.
</h3>

---

Esto hace que NearPath sea ideal para:

* Mapeo de superficie de APIs
* Descubrimiento de rutas ocultas
* Análisis de exposición de endpoints internos
* Detección de rutas olvidadas o legacy

---

## Filosofía

NearPath no es un spider.
NearPath no es un fuzzer de fuerza bruta.

NearPath responde a una sola pregunta específica:

> **“¿Qué probablemente existe aquí que el sitio no enlaza?”**

Lo hace mediante:

1. Observación de rutas reales desde HTML y JavaScript
2. Extracción de pistas estructurales
3. Generación de mutaciones inteligentes
4. Validación mediante fingerprinting de respuestas

Esto permite que NearPath encuentre endpoints que los crawlers normales y los fuzzers de directorios pasan por alto.

---

## Características Principales

### Descubrimiento de Rutas Guiado

NearPath extrae URLs desde:

* HTML (`href`, `src`, `action`)
* JavaScript (`fetch`, `import`, `require`, rutas entre comillas)

Estas rutas reales se convierten en **semillas** para una expansión posterior.

---

### Motor de Mutación Heurística

Las rutas descubiertas se mutan usando reglas estructurales:

* `_old`, `_bak`, `_dev`, `_test`
* `.json`, `.php`, `.xml`, `.txt`
* `/v1`, `/v2`, `/internal`, `/private`
* pluralización y truncado
* pivotado de versiones de API

Esto genera conjeturas de alta calidad en lugar de fuerza bruta ruidosa. **MUCHO más rápido**

---

### Detección de Fake-404

Las aplicaciones modernas suelen devolver HTTP 200 para páginas inexistentes (rutas fallback de SPA).

NearPath genera fingerprints de:

* Código de estado
* Longitud de la respuesta
* Headers

Esto le permite distinguir:

```
Endpoints reales vs Páginas falsas
```

Incluso cuando todo devuelve 200. **Adiós a los falsos positivos**

---

### Descubrimiento Impulsado por JavaScript

NearPath analiza archivos JavaScript y extrae:

* Llamadas `fetch`
* Imports
* Rutas de API entre comillas

Esto revela rutas backend que nunca aparecen en el HTML.

---

### Escaneo Basado en Prioridades

Las rutas se puntúan según cómo fueron descubiertas:

* Enlaces directos = alta prioridad
* Referencias en JS = prioridad aún mayor
* Mutaciones = menor prioridad

Esto asegura que:

* Las superficies reales se escanean primero
* El ruido se limite de forma natural

---

### Multi-Hilo y Seguro ante Interrupciones

NearPath soporta:

* Workers concurrentes
* Apagado seguro con Ctrl+C
* Detención elegante con persistencia completa de resultados

---

### Salida Estructurada

Cada objetivo obtiene su propia carpeta:

```
nearpath_results/
└── example.com/
    ├── discovered.txt
    ├── target.json
    ├── responses.db
    └── js_sources.txt
```

---

## Instalación

Clona el repositorio y entra en su directorio:

```bash
git clone https://github.com/URDev4ever/NearPath.git
cd NearPath/
```

```bash
pip install requests
```

Se requiere Python 3.8+.

---

## Uso

```bash
python nearpath.py
```

NearPath se ejecuta en modo interactivo:

```
URL objetivo:
Profundidad máxima (por defecto 2):
Timeout por request (por defecto 6):
¿Seguir imports de JS? (Y/n):
Máx. mutaciones por ruta (por defecto 12):
```

No se requieren flags.
Todo se configura mediante prompts. (pd: podés simplemente apretar *enter* para usar los valores por defecto)

---

## Cómo Funciona NearPath

```
URL objetivo
   ↓
Crawl de HTML
   ↓
Extracción de JS
   ↓
Recolección de rutas
   ↓
Motor de mutación
   ↓
Filtrado Fake-404
   ↓
Cola de prioridades
   ↓
Endpoints validados
   ↓
Base de datos + reportes
```

NearPath no intenta todo.
Intenta **lo que tiene sentido**, por eso es **10x más rápido** que un fuzzer común.

---

## Archivos de Salida

### `discovered.txt`

Lista legible de endpoints:

```
https://site/api/users - 200 - 1345b
https://site/api/internal - 403 - 421b
```

---

### `target.json`

Datos estructurados del escaneo agrupados por ruta base:

```json
{
  "/api/users": {
    "https://site/api/users": {
      "status": 200,
      "length": 1345,
      "type": "application/json",
      "priority": 7
    }
  }
}
```

---

### `responses.db`

Base de datos SQLite que contiene:

* URL
* Ruta
* Estado
* Longitud
* Headers
* Timestamp

Esto permite análisis posterior, filtrado y correlación.

---

### `js_sources.txt`

Fragmentos de JavaScript capturados que fueron minados para endpoints.

Útil para:

* Revisión manual
* Ingeniería inversa de APIs
* Comparación entre versiones

---

## Qué No Es NearPath

NearPath **no**:

* Ejecuta payloads
* Inyecta datos
* Testea vulnerabilidades
* Adivina grandes wordlists
* Realiza ataques de autenticación

Se limita estrictamente a mapear y validar la **superficie de ataque**.

---

## Cuándo Usar NearPath

Usá NearPath cuando:

* Querés entender la API real de una aplicación web
* Querés encontrar endpoints no documentados
* Querés descubrir rutas olvidadas o legacy
* Querés mapear qué existe antes de pruebas más profundas

---

## Perfil de Rendimiento

NearPath es intencionalmente *“fuzzing chill”*:

* Bajo ruido
* Bajo consumo de ancho de banda
* Alta señal

Escala según:

* Profundidad
* Cantidad de mutaciones
* Número de hilos

---

## Advertencia

NearPath se proporciona tal cual para investigación, auditoría y análisis defensivo.

Usalo solo contra sistemas que poseas o para los cuales tengas autorización.

---

Hecho con <3 por URDev.
