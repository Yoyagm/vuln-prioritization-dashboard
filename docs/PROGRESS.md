# Progreso

## Estado actual

Spec escrita y commiteada (`docs/specs/vuln-prioritization-dashboard.md`), con los siete hitos, los
contratos de datos y — lo importante — el hallazgo ya **medido**, no supuesto: los tanteos de la
fase 0 reprodujeron la comparación CVSS vs EPSS en cinco fechas de corte congeladas.

Siguiente paso: M1–M3 (ingesta reproducible, join y métricas) en `src/`, portando la lógica ya
verificada de los scripts de tanteo a código de producción con tests.

Bloqueos: ninguno.

## Registro

### 2026-08-15 (tarde)

- **Hallazgo, y es el eje del proyecto:** la ventaja de EPSS sobre el CVSS es real en la cabeza de
  la cola y **artefacto de medición** en el resto. Retrospectivamente, cubrir el 80 % del KEV cuesta
  137.952 CVEs por CVSS y 22.736 por EPSS — **6,1×**. Pero congelando EPSS en una fecha pasada (FIRST
  publica archivos diarios) y puntuando solo contra los CVEs que CISA añadió al KEV **después**, la
  ventaja se invierte en la cola: EPSS necesita **más** trabajo que el CVSS para llegar al 80 %
  (ratio 0,5–0,7×), aunque sigue ganando a igual presupuesto (1,4–1,8× de explotados capturados).
  Estable en las cinco fechas probadas (2023-08-15 … 2025-08-15), con bootstrap sobre los positivos.
  La conclusión operativa que implementa el dashboard es la híbrida: KEV primero, EPSS para la
  cabeza de la cola, CVSS como guardia de la cola larga.

- **Decisión:** los empates no se rompen, se promedian. Decenas de miles de CVEs comparten un CVSS de
  9,8; cualquier implementación que deje que `sort` resuelva ese empate está midiendo el orden
  alfabético del identificador, no la métrica. La curva se evalúa por bloques de puntuación distinta
  y se lee linealmente entre ellos, que es el valor esperado bajo orden aleatorio dentro del bloque.

- **Decisión:** el repo se publica en GitHub al terminar, no ahora.

- **Hecho:** medido que la extracción del NVD entero, año a año, tarda **20 s** y produce un parquet
  de **5,5 MB** — el presupuesto de artefacto commiteado se cumple con holgura.

- **Corregido:** la lista de versiones de la fase 0 **no era instalable**. `streamlit 1.61.1` exige
  `pyarrow < 25`, así que la versión buena es **24.0.0** y no 25.0.1. El `requirements.txt` se
  genera con `uv pip freeze`, nunca a mano — que es justo la causa nº 1 de "va en local y falla en
  Streamlit Cloud" que ya teníamos anotada.

### 2026-08-15

- **Hecho:** Fase 0. Verificadas las tres fuentes con peticiones reales: CISA KEV (1.665 CVEs,
  catálogo 2026-08-14, 349 con uso conocido en campañas de ransomware), EPSS (360.142 CVEs,
  `score_date` 2026-08-15) y NVD (377.359 CVEs). Descargados a `data/raw/`, que va ignorado.

- **Decisión:** el universo completo del NVD se toma del mirror `fkie-cad/nvd-json-data-feeds`, no de
  la API oficial. La API se intentó y se abandonó: sin clave son 189 páginas a 255 s de ritmo real
  (~12 h) y la conexión se cuelga goteando bytes, así que el timeout de `urlopen` no salta nunca —
  se quedó 105 minutos parado en la página 20. El mirror sirve el NVD entero en un `.xz` de 96 MB
  que se descarga en **12 segundos**, con esquema idéntico al de la API 2.0 y conservando
  `cisaExploitAdd`, `cisaActionDue`, `cvssMetricV31/V2`, `ssvcV203` y `weaknesses` (verificado sobre
  CVE-2021-44228). La API del NVD se queda solo para el subconjunto KEV, donde `?hasKev` devuelve
  los 1.665 en una sola petición. Contrapartida asumida: hay que citar en el README el aviso de que
  el mirror redistribuye datos del NVD sin estar avalado por él.

- **Decisión:** el NVD se procesa año a año. Los 3 GB descomprimidos no caben cómodos en memoria y
  un fichero anual carga en 1,5 s.

- **Bloqueo resuelto:** Streamlit Community Cloud admite Python 3.10–3.14 y usa 3.12 por defecto,
  fijable con `runtime.txt`. No hacía falta plan B de despliegue.
