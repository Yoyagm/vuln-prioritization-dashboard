# Progreso

## Estado actual

Fase 0 (entender y verificar las fuentes) **cerrada**. Los tres feeds están descargados y validados
en `data/raw/`, y todo lo comprobado con peticiones reales está en `docs/PHASE0-FINDINGS.md`.

Siguiente paso: la especificación (`docs/specs/vuln-prioritization-dashboard.md`), que define los
hitos, los contratos de datos y la métrica del hallazgo — "¿predice el CVSS la explotación real?".

Bloqueos: ninguno.

## Registro

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
