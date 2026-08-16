# Fase 0 — Hechos verificados (2026-08-14/15)

Todo lo de aquí está comprobado con peticiones reales. No son suposiciones.
Ningún agente debe volver a verificarlo; construid sobre esto.

## Fuentes de datos

### 1. CISA KEV — feed JSON
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

- HTTP 200, ~1,5 MB, **1665 vulnerabilidades**, `dateReleased: 2026-08-14`.
- Claves raíz: `title, catalogVersion, dateReleased, count, vulnerabilities`.
- Campos por vulnerabilidad: `cveID, vendorProject, product, vulnerabilityName,
  dateAdded, shortDescription, requiredAction, dueDate,
  knownRansomwareCampaignUse, notes, cwes`.
- Barato: una petición, sin autenticación, sin límite conocido.

### 2. EPSS — volcado completo (FIRST)
`https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`

- **302 → hay que seguir la redirección** (`curl -L` / `allow_redirects=True`).
- 2,5 MB gz, **359.229 CVEs**.
- **Línea 1 es un comentario**: `#model_version:v2026.06.15,score_date:2026-08-14T12:00:27Z`.
  La cabecera real (`cve,epss,percentile`) está en la **línea 2** → `skiprows=1` en pandas.
- La API puntual `https://api.first.org/data/v1/epss?cve=A,B` también funciona
  (`data[]` con `cve, epss, percentile, date`) pero **devuelve los números como string**.

### 3. NVD — la API oficial NO sirve para el universo completo
`https://services.nvd.nist.gov/rest/json/cves/2.0`

- **`?hasKev&resultsPerPage=2000` devuelve los 1665 CVEs del KEV en UNA petición, <1 s.**
  Esto sí es viable y es la vía correcta para el subconjunto KEV.
- **El universo completo NO es viable por la API.** Medido: `totalResults = 377.370`,
  189 páginas de 2000. Se intentó y **se abandonó**:
  - ritmo real **255 s/página** (no los ~15 s del primer sondeo) → **~12 horas**.
  - la conexión se **cuelga**: el servidor gotea bytes, así que `timeout=180` de
    `urlopen` no salta nunca. Se quedó 105 min parado en la página 20.
  - sin API key el límite es 5 peticiones / 30 s.
- Conclusión: usar la API **solo** para el subconjunto KEV y para validar el mirror.

### 4. NVD universo completo — mirror fkie-cad (LA VÍA BUENA)
`https://github.com/fkie-cad/nvd-json-data-feeds`

- Reconstrucción comunitaria de los feeds JSON legacy del NVD. 244 estrellas.
  Se regenera **a diario** (release visto: `v2026.08.15-000015`).
- **Aviso de licencia que hay que citar**: *"uses and redistributes data from the
  NVD API but is neither endorsed nor certified by the NVD"*. Hay que decirlo en el README.
- Assets: 31 ficheros `.xz`, **207 MB comprimidos en total**:
  - `CVE-all.json.xz` → **96 MB, descarga en 12 s**, **3,00 GB descomprimido**,
    `cve_count: 377.359`.
  - anuales `CVE-1999.json.xz` … `CVE-2026.json.xz` (el mayor, 12 MB).
- **URL estable, independiente del tag diario** (verificada, HTTP 200):
  `https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-2021.json.xz`
- Estructura: `{timestamp, cve_count, feed_name, source, cve_items: [...]}`.
  Cada elemento de `cve_items` es un objeto CVE **idéntico al de la API 2.0**.
- **Fidelidad verificada sobre CVE-2021-44228 (Log4Shell)**: conserva
  `cisaExploitAdd: 2021-12-10`, `cisaActionDue: 2021-12-24`, `cisaRequiredAction`,
  `cisaVulnerabilityName`, `metrics.cvssMetricV31` (base 10.0, CRITICAL,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`), `metrics.cvssMetricV2` (9.3),
  `metrics.ssvcV203`, y `weaknesses` (CWE-20, CWE-917).
- Rendimiento medido en el año 2021: `json.load` de un fichero anual = **1,5 s**,
  23.445 CVEs, de los cuales 214 con KEV, 22.424 con CVSS v3.1, 5.178 con SSVC.
- **3 GB no caben cómodos en memoria** → procesar **año por año** (pico ~1 año) o
  en streaming, extrayendo solo las columnas necesarias.

### Nota sobre SSVC
`metrics.ssvcV203` NO tiene `cvssData`; su forma es
`{source, ssvcData: {timestamp, id, options: [{exploitation}, {automatable}, {technicalImpact}], role, version}}`.
Es la decisión propia de CISA. Solo la tiene un subconjunto (5.178 de 23.445 en 2021).

## Entorno

- macOS, Apple Silicon. `python3` del sistema = **3.9.6** (no usar).
- **`uv 0.12.0`** en `/opt/homebrew/bin/uv`. Ojo: **`uv pip index` NO existe** en esta versión.
  Para consultar versiones: `curl -s https://pypi.org/pypi/<pkg>/json | python3 -c "import json,sys; print(json.load(sys.stdin)['info']['version'])"`.
- `gh` autenticado como **Yoyagm**. Git global sin `user.name`/`user.email`
  (ya fijados localmente en este repo: Johan Rodriguez / johan.rc2020@gmail.com).
- Repo destino: `/Users/johanrodriguez/vuln-prioritization-dashboard`, ya con `git init`.

## Versiones reales en PyPI a 2026-08-14 (verificadas)

```
streamlit   1.61.1   requires_python >=3.10
pandas      3.0.5    requires_python >=3.11
requests    2.34.2   requires_python >=3.10
plotly      6.9.0    requires_python >=3.8
altair      6.2.2    requires_python >=3.10
pyarrow     25.0.1   requires_python >=3.10
pytest      9.1.1    requires_python >=3.10
httpx       0.28.1   requires_python >=3.8
numpy       2.5.2    requires_python >=3.12
```

**CORRECCIÓN (2026-08-15): esa lista NO es un conjunto instalable.** Son las últimas versiones de
cada paquete por separado, que es otra cosa. Al instalarlas juntas, `uv` falla:

```
Because streamlit>=1.61.1 depends on pyarrow>=7.0,<25 and you require pyarrow==25.0.1,
we can conclude that your requirements are unsatisfiable.
```

**Conjunto resuelto y verificado que sí instala** (Python 3.12.13, macOS arm64,
`uv venv --python 3.12`):

```
streamlit 1.61.1   pandas 3.0.5   pyarrow 24.0.0   plotly 6.9.0
numpy 2.5.2        requests 2.34.2   pytest 9.1.1
```

`pyarrow` baja a **24.0.0**, no 25.0.1. El `requirements.txt` se genera con
`uv pip freeze`, nunca a mano desde esta lista.

## Despliegue

- **Streamlit Community Cloud admite Python 3.10–3.14 y usa 3.12 por defecto.**
  Se fija con `runtime.txt` en la raíz. Dependencias desde `requirements.txt` en la raíz.
- La app **no puede** hacer ingesta pesada en el arranque → ingesta offline que
  produce artefactos pequeños **commiteados**, y la app los lee.
- Causa nº1 de "va en local, falla en Cloud": `requirements.txt` sin versiones fijadas.

## Datos ya descargados en disco

`/Users/johanrodriguez/vuln-prioritization-dashboard/data/raw/`
- `CVE-all.json.xz` — 96 MB, el universo entero (del release `v2026.08.15-000015`).
- `CVE-2021.json.xz` — 6,7 MB, usado para verificar el esquema.
- `nvd/page_*.json.gz` — 19 páginas del intento fallido por la API. **Basura, borrar.**
