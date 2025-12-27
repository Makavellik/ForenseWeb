
# 🧬 FORENSEWEB.PY

## Documentación Oficial

**Post‑Human Web Forensics & Decision Engine**
*ByMakaveli*

---

## 1. Visión General

**ForenseWeb** es un motor forense web de análisis lógico‑decisional diseñado para entornos SOC, Blue Team, Bug Bounty y análisis post‑request. Su objetivo no es interceptar tráfico de red, sino **comprender, correlacionar y decidir** a partir de señales web observables.

> "La seguridad moderna no bloquea más, **entiende mejor**."

---

## 2. Qué es y qué NO es

### ✔️ Es

* Motor forense web
* IDS heurístico de payloads
* Fingerprinting comportamental
* Clasificador de atribución
* WAF **lógico / decisional**
* Fuente explicable para SIEM / SOAR

### ❌ No es

* Un WAF perimetral
* Un IDS de red
* Un sniffer TLS
* Un sistema de alto throughput

---

## 3. Arquitectura General

```
URL → URLAnalyzer → Domain Model → Fingerprint → IDS → Attribution → WAF Decision → JSON
```

Cada request es evaluado **de forma aislada**, pero los modelos **aprenden con el tiempo**.

---

## 4. Componentes del Sistema

### 4.1 URLAnalyzer

Responsable de extraer características estructurales de la URL.

**Señales principales:**

* Profundidad del path
* Entropía por segmento
* Ratios alfanuméricos
* Extensiones
* Entropía de query

**Objetivo:** detectar rutas generadas, evasión y APIs no documentadas.

---

### 4.2 DomainMethodModel

Modelo estadístico por `(dominio, método HTTP)`.

**Funciones clave:**

* Aprendizaje incremental
* Decay temporal
* Z‑Score de anomalía
* Similaridad estructural de paths

**Objetivo:** identificar desviaciones de comportamiento histórico.

---

### 4.3 FingerprintEngine

Genera un fingerprint lógico a partir de headers y latencia.

**Detecta:**

* Drift de identidad
* Automatización
* Rotación de clientes

---

### 4.4 PayloadIDS

IDS heurístico para análisis de payloads.

**Señales:**

* Entropía
* Longitud
* Patrones XSS / SQLi / traversal

**Salida:** score normalizado (0–5) + señales explicables.

---

### 4.5 AttributionEngine

Clasifica el tipo de actor observado:

* `human_like`
* `scanner_like`
* `automation_like`
* `unknown`

Basado en correlación de payload, latencia, drift y método.

---

### 4.6 WAFEngine (Decisional)

Motor de decisión lógica.

**Acciones posibles:**

* `ALLOW`
* `MONITOR`
* `BLOCK`

⚠️ No bloquea tráfico real. **Sugiere decisiones.**

Incluye:

* Umbrales configurables
* Explainability
* Severidad y confianza

---

## 5. Flujo de Análisis

1. Extracción de features
2. Evaluación estadística
3. Fingerprint y drift
4. IDS de payload
5. Cálculo de riesgo
6. Atribución
7. Decisión WAF
8. Output explicable

---

## 6. Output del Sistema

### 6.1 Métricas principales

* `risk_score`
* `severity`
* `confidence`
* `verdict`

### 6.2 WAF Decision

* Acción
* Severidad
* Razones

### 6.3 Attribution

* Label
* Confidence
* Reasons

### 6.4 RAW JSON

Diseñado para ingestión directa en:

* SIEM
* Dashboards
* Alerting
* ML downstream

---

## 7. Uso desde CLI

El modo CLI permite:

* Análisis interactivo
* Aprendizaje progresivo
* Visualización SOC‑like

Ideal para:

* Investigación
* Bug bounty
* Formación
* Pruebas controladas

---

## 8. Limitaciones Conocidas

* No inspecciona TLS
* No ve tráfico completo
* No aplica rate‑limit real

Estas limitaciones son **intencionales**.

---

## 9. Casos de Uso

* Análisis forense web
* Detección de scanners
* Evaluación de comportamiento
* Soporte a decisiones humanas
* Investigación avanzada

---

## 10. Filosofía

> Observar sin apego.
> Detectar sin emoción.
> Decidir sin duda.

ForenseWeb no reacciona: **comprende**.

---

## 11. Firma

```
FORENSEWEB.PY
Post‑Human Defensive Consciousness
ByMakaveli
```
