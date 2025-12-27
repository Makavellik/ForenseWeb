import math, time, hashlib, statistics, json, sqlite3
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from difflib import SequenceMatcher
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

console = Console()

# =========================================================
# UTILS
# =========================================================

def entropy(s: str) -> float:
    if not s: return 0.0
    probs = [s.count(c)/len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def stable_hash(data: str) -> str:
    return hashlib.sha256(data.encode(errors="ignore")).hexdigest()[:16]

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def decay_weight(age_s: float, T: float = 3600) -> float:
    return math.exp(-age_s / T)

# =========================================================
# PERSISTENCE (SQLITE)
# =========================================================

class Persistence:
    def __init__(self, db="forenseweb.db"):
        self.conn = sqlite3.connect(db)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY,
                v REAL
            )
        """)

    def save(self, k, v):
        self.conn.execute("REPLACE INTO kv (k,v) VALUES (?,?)", (k, v))
        self.conn.commit()

    def load(self, k):
        cur = self.conn.execute("SELECT v FROM kv WHERE k=?", (k,))
        row = cur.fetchone()
        return row[0] if row else None

# =========================================================
# URL ANALYZER (SEGMENT ENTROPY) — ADVANCED EXTENSION
# =========================================================

class URLAnalyzer:
    def extract(self, url: str) -> dict:
        try:
            # =========================
            # URL NORMALIZATION (CRITICAL)
            # =========================
            if "://" not in url:
                url = "http://" + url

            p = urlparse(url)
            segments = [s for s in p.path.split("/") if s]

            # =========================
            # BASE METRICS (ORIGINAL)
            # =========================
            seg_ents = [entropy(s) for s in segments]
            seg_lengths = [len(s) for s in segments]

            # =========================
            # ADVANCED SEGMENT ANALYSIS
            # =========================
            digit_ratios = [
                sum(c.isdigit() for c in s) / max(len(s), 1)
                for s in segments
            ]

            alpha_ratios = [
                sum(c.isalpha() for c in s) / max(len(s), 1)
                for s in segments
            ]

            # Length-aware entropy normalization
            norm_seg_entropy = [
                (entropy(s) / math.log2(len(s)))
                if len(s) > 1 else 0
                for s in segments
            ]

            # =========================
            # EXTENSION AWARENESS
            # =========================
            last_segment = segments[-1] if segments else ""
            has_extension = "." in last_segment
            extension = (
                last_segment.rsplit(".", 1)[-1].lower()
                if has_extension else None
            )

            # =========================
            # RETURN STRUCTURE
            # =========================
            return {
                # ===== ORIGINAL KEYS (UNTOUCHED) =====
                "length": len(url),
                "segments": segments,
                "seg_ent_avg": (sum(seg_ents) / len(seg_ents)) if seg_ents else 0,
                "seg_ent_max": max(seg_ents) if seg_ents else 0,
                "query_entropy": entropy(p.query),
                "param_count": len(parse_qs(p.query)),

                # ===== ADVANCED EXTENSIONS (SAFE) =====
                "path_depth": len(segments),
                "seg_length_avg": (
                    sum(seg_lengths) / len(seg_lengths)
                ) if seg_lengths else 0,

                "digit_ratio_avg": (
                    sum(digit_ratios) / len(digit_ratios)
                ) if digit_ratios else 0,

                "alpha_ratio_avg": (
                    sum(alpha_ratios) / len(alpha_ratios)
                ) if alpha_ratios else 0,

                "seg_entropy_norm_avg": (
                    sum(norm_seg_entropy) / len(norm_seg_entropy)
                ) if norm_seg_entropy else 0,

                "has_extension": has_extension,
                "extension": extension,
            }

        except Exception:
            # =========================
            # FAIL-SAFE FORENSIC MODE
            # =========================
            return {
                "length": len(url),
                "segments": [],
                "seg_ent_avg": 0,
                "seg_ent_max": 0,
                "query_entropy": 0,
                "param_count": 0,
                "path_depth": 0,
                "seg_length_avg": 0,
                "digit_ratio_avg": 0,
                "alpha_ratio_avg": 0,
                "seg_entropy_norm_avg": 0,
                "has_extension": False,
                "extension": None,
            }



# =========================================================
# DOMAIN+METHOD MODEL (DECAY + CAP) — ADVANCED HARDENED
# =========================================================

class DomainMethodModel:
    def __init__(self, cap=1000, min_samples=12, z_threshold=3.0):
        self.samples = defaultdict(list)   # feature -> [(value, ts)]
        self.paths = []
        self.cap = int(cap)
        self.min_samples = int(min_samples)
        self.z_threshold = float(z_threshold)

    # -----------------------------------------------------
    # LEARNING PHASE
    # -----------------------------------------------------
    def learn(self, features: dict):
        if not isinstance(features, dict):
            return

        now = time.time()

        for k, v in features.items():
            if isinstance(v, (int, float)) and math.isfinite(v):
                bucket = self.samples[k]
                bucket.append((float(v), now))

                # Cap enforcement
                if len(bucket) > self.cap:
                    del bucket[0]

        # Path memory (structural baseline)
        segments = features.get("segments")
        if isinstance(segments, list):
            self.paths.append(list(segments))
            if len(self.paths) > self.cap:
                del self.paths[0]

    # -----------------------------------------------------
    # ANOMALY SCORING
    # -----------------------------------------------------
    def anomaly_score(self, features: dict) -> (int, list):
        if not isinstance(features, dict):
            return 0, []

        now = time.time()
        score = 0
        explain = []

        for k, recs in self.samples.items():
            if k not in features:
                continue
            if len(recs) < self.min_samples:
                continue

            x = features[k]
            if not isinstance(x, (int, float)) or not math.isfinite(x):
                continue

            # ---- weighted stats (decay-aware) ----
            weights = []
            values = []

            for v, ts in recs:
                w = decay_weight(max(now - ts, 0))
                if w > 0 and math.isfinite(w):
                    weights.append(w)
                    values.append(v)

            sw = sum(weights)
            if sw <= 1e-9:
                continue

            mean = sum(v * w for v, w in zip(values, weights)) / sw

            # true weighted variance
            var = sum(
                w * (v - mean) ** 2
                for v, w in zip(values, weights)
            ) / sw

            st = math.sqrt(var) if var > 1e-9 else 1.0
            z = abs(x - mean) / st

            if z > self.z_threshold:
                score += 1
                explain.append({
                    "feature": k,
                    "value": round(x, 5),
                    "baseline": round(mean, 5),
                    "std": round(st, 5),
                    "z": round(z, 3),
                    "impact": f"z>{self.z_threshold}",
                    "samples": len(recs)
                })

        return score, explain

    # -----------------------------------------------------
    # PATH SIMILARITY (STRUCTURAL MEMORY)
    # -----------------------------------------------------
    def path_similarity(self, segments: list) -> float:
        if not segments or not self.paths:
            return 1.0

        try:
            j = lambda x: "/".join(x)
            base = j(segments)

            sims = [
                similarity(base, j(p))
                for p in self.paths
                if p
            ]

            return max(sims) if sims else 0.0

        except Exception:
            # forensic-safe fallback
            return 0.0


# =========================================================
# FINGERPRINT ENGINE — ADVANCED HARDENED
# =========================================================

class FingerprintEngine:
    def __init__(self, cap=1000, min_samples=6, z_threshold=3.0):
        self.history = defaultdict(list)
        self.cap = int(cap)
        self.min_samples = int(min_samples)
        self.z_threshold = float(z_threshold)

    # -----------------------------------------------------
    # FEATURE EXTRACTION
    # -----------------------------------------------------
    def extract(self, headers: dict, latency: float) -> dict:
        headers = headers or {}

        raw = "|".join([
            headers.get("User-Agent", ""),
            headers.get("Accept-Language", ""),
            headers.get("Accept-Encoding", ""),
            headers.get("Time-Zone", "NA")
        ])

        return {
            "fp_id": stable_hash(raw),
            "ua_entropy": entropy(headers.get("User-Agent", "")),
            "latency": float(latency) if latency is not None else 0.0,
            "ts": time.time()
        }

    # -----------------------------------------------------
    # DRIFT DETECTION
    # -----------------------------------------------------
    def drift_score(self, fp: dict) -> (int, list):
        if not fp or "fp_id" not in fp:
            return 0, []

        hist = self.history.get(fp["fp_id"], [])
        if len(hist) < self.min_samples:
            return 0, []

        score = 0
        explain = []

        # ---- LATENCY DRIFT ----
        lats = [h["latency"] for h in hist if isinstance(h.get("latency"), (int, float))]
        if len(lats) >= self.min_samples:
            mean = statistics.mean(lats)
            st = statistics.pstdev(lats) or 1.0
            z = abs(fp["latency"] - mean) / st

            if z > self.z_threshold:
                score += 1
                explain.append({
                    "feature": "latency",
                    "value": round(fp["latency"], 4),
                    "baseline": round(mean, 4),
                    "std": round(st, 4),
                    "z": round(z, 3),
                    "impact": "latency-drift",
                    "samples": len(lats)
                })
            elif z > self.z_threshold * 0.6:
                explain.append({
                    "feature": "latency",
                    "value": round(fp["latency"], 4),
                    "baseline": round(mean, 4),
                    "z": round(z, 3),
                    "impact": "weak-drift"
                })

        # ---- USER-AGENT ENTROPY ----
        ue = fp.get("ua_entropy", 0)
        if isinstance(ue, (int, float)):
            if ue < 2.2:
                score += 1
                explain.append({
                    "feature": "ua_entropy",
                    "value": round(ue, 3),
                    "baseline": ">= 2.2",
                    "impact": "low-entropy-UA"
                })

        return score, explain

    # -----------------------------------------------------
    # LEARNING PHASE
    # -----------------------------------------------------
    def learn(self, fp: dict):
        if not fp or "fp_id" not in fp:
            return

        bucket = self.history[fp["fp_id"]]
        bucket.append(fp)

        if len(bucket) > self.cap:
            del bucket[0]


# =========================================================
# IDS PAYLOAD — ADVANCED FORENSIC
# =========================================================

class PayloadIDS:
    GENERIC = [
        "<script", "javascript:", "onerror=", "onload=",
        "' or '1'='1", "\" or \"1\"=\"1",
        "../", "%00", "%2e%2e", "%3cscript"
    ]

    def analyze(self, payload: str) -> dict:
        if not payload or not isinstance(payload, str):
            return {
                "score": 0,
                "severity": "NONE",
                "confidence": 0.0,
                "signals": []
            }

        score = 0
        signals = []

        raw = payload
        pl = payload.lower()

        # -------------------------------------------------
        # 1. ENTROPY (OBFUSCATION / ENCODING)
        # -------------------------------------------------
        e = entropy(raw)
        if e > 4.5:
            score += 1
            signals.append({
                "type": "entropy",
                "value": round(e, 3),
                "impact": "high-entropy"
            })

        # -------------------------------------------------
        # 2. LENGTH ANOMALY
        # -------------------------------------------------
        ln = len(raw)
        if ln > 2000:
            score += 1
            signals.append({
                "type": "length",
                "value": ln,
                "impact": "oversized-payload"
            })

        # -------------------------------------------------
        # 3. PATTERN MATCHING (MULTI-HIT)
        # -------------------------------------------------
        hits = 0
        for p in self.GENERIC:
            if p in pl:
                hits += 1
                signals.append({
                    "type": "pattern",
                    "value": p,
                    "impact": "known-attack-signal"
                })

        if hits:
            score += min(hits, 2)  # evita inflar score
       
        # -------------------------------------------------
        # 4. ENCODING / OBFUSCATION HEURISTICS
        # -------------------------------------------------
        if "%" in raw and any(c.isalpha() for c in raw):
            score += 1
            signals.append({
                "type": "encoding",
                "value": "percent-encoding",
                "impact": "possible-evasion"
            })

        # -------------------------------------------------
        # 5. SCORE NORMALIZATION
        # -------------------------------------------------
        score = min(score, 5)

        severity = (
            "LOW" if score == 1 else
            "MEDIUM" if score in (2, 3) else
            "HIGH" if score >= 4 else
            "NONE"
        )

        confidence = round(score / 5.0, 2)

        return {
            "score": score,
            "severity": severity,
            "confidence": confidence,
            "signals": signals
        }


# =========================================================
# ATTRIBUTION ENGINE — ADVANCED FORENSIC
# =========================================================

class AttributionEngine:
    def classify(self, fp_drift, latency, method, payload_score):
        reasons = []
        score = 0

        # -------------------------------------------------
        # PAYLOAD-DRIVEN BEHAVIOR
        # -------------------------------------------------
        if payload_score >= 3:
            score += 2
            reasons.append("payload_score>=3")

        # -------------------------------------------------
        # FINGERPRINT DRIFT
        # -------------------------------------------------
        if fp_drift:
            score += 1
            reasons.append("fingerprint_drift")

        # -------------------------------------------------
        # AUTOMATION HEURISTICS
        # -------------------------------------------------
        if latency is not None and latency < 80:
            if method and method.upper() != "GET":
                score += 1
                reasons.append("low_latency+non_GET")

        # -------------------------------------------------
        # HUMAN-LIKE BEHAVIOR
        # -------------------------------------------------
        if payload_score == 0 and not fp_drift and latency and latency > 200:
            reasons.append("clean_payload+stable_fp+human_latency")
            return {
                "label": "human_like",
                "confidence": 0.85,
                "reasons": reasons
            }

        # -------------------------------------------------
        # FINAL CLASSIFICATION
        # -------------------------------------------------
        if payload_score >= 3 and fp_drift:
            label = "scanner_like"
            confidence = min(0.6 + score * 0.1, 0.95)

        elif latency and latency < 80 and method and method.upper() != "GET":
            label = "automation_like"
            confidence = min(0.55 + score * 0.1, 0.9)

        else:
            label = "unknown"
            confidence = 0.4 + min(score * 0.1, 0.3)

        return {
            "label": label,
            "confidence": round(confidence, 2),
            "reasons": reasons
        }


# =========================================================
# WAF LOGIC — DECISIONAL / FORENSIC (EXPERT MODE)
# =========================================================
class WAFEngine:
    POLICY_VERSION = "2025.1-decisional"

    def __init__(
        self,
        block_risk=6,
        monitor_risk=4,
        min_block_confidence=0.7,
        dry_run=False
    ):
        self.block_risk = block_risk
        self.monitor_risk = monitor_risk
        self.min_block_confidence = min_block_confidence
        self.dry_run = dry_run  # SOC simulation mode

    def decide(self, risk, payload_score, confidence):
        # -------------------------------
        # Input normalization (fail-safe)
        # -------------------------------
        risk = int(risk or 0)
        payload_score = int(payload_score or 0)
        confidence = float(confidence or 0.0)

        reasons = []
        decision_trace = []

        # -------------------------------
        # HARD BLOCK EVALUATION
        # -------------------------------
        if risk >= self.block_risk:
            decision_trace.append(f"risk >= {self.block_risk}")

        if payload_score >= 3:
            decision_trace.append("payload_score >= 3")

        if confidence >= self.min_block_confidence:
            decision_trace.append(f"confidence >= {self.min_block_confidence}")

        hard_block = (
            risk >= self.block_risk
            and payload_score >= 3
            and confidence >= self.min_block_confidence
        )

        if hard_block:
            action = "BLOCK"
            severity = "HIGH"
            reasons = decision_trace.copy()

        # -------------------------------
        # MONITOR / CHALLENGE EVALUATION
        # -------------------------------
        elif risk >= self.monitor_risk or payload_score >= 2:
            action = "MONITOR"
            severity = "MEDIUM"

            if risk >= self.monitor_risk:
                reasons.append(f"risk >= {self.monitor_risk}")

            if payload_score >= 2:
                reasons.append("payload_score >= 2")

        # -------------------------------
        # ALLOW (LOW RISK)
        # -------------------------------
        else:
            action = "ALLOW"
            severity = "LOW"
            reasons = ["below_thresholds"]

        # -------------------------------
        # DRY-RUN SAFETY (SOC MODE)
        # -------------------------------
        if self.dry_run and action == "BLOCK":
            action = "MONITOR"
            reasons.append("dry_run_override")

        # -------------------------------
        # Structured SOC Output
        # -------------------------------
        return {
            "engine": "WAF_DECISIONAL",
            "policy_version": self.POLICY_VERSION,
            "action": action,
            "severity": severity,
            "confidence": round(confidence, 2),
            "risk_score": risk,
            "payload_score": payload_score,
            "reasons": reasons,
            "explainability": {
                "decision_trace": decision_trace,
                "block_threshold": self.block_risk,
                "monitor_threshold": self.monitor_risk,
                "min_block_confidence": self.min_block_confidence,
                "dry_run": self.dry_run
            }
        }



class ForenseWeb:
    def __init__(self):
        self.url = URLAnalyzer()

        # Control explícito del modelo por dominio+método
        self.domains = defaultdict(lambda: DomainMethodModel(cap=1000))

        self.fp = FingerprintEngine()
        self.ids = PayloadIDS()
        self.attr = AttributionEngine()
        self.waf = WAFEngine()
        self.db = Persistence()  # asumido externo

    def analyze(self, url, method, headers, latency, payload=""):
        p = urlparse(url)
        method = method.upper()
        key = (p.netloc, method)

        # ----------------------------
        # URL / STRUCTURAL FEATURES
        # ----------------------------
        feats = self.url.extract(url)
        model = self.domains[key]

        z, exp_z = model.anomaly_score(feats)
        ps = model.path_similarity(feats["segments"])

        # ----------------------------
        # FINGERPRINT (ORDER FIXED)
        # ----------------------------
        fp = self.fp.extract(headers, latency)
        self.fp.learn(fp)                  # ✅ learn first
        d, exp_d = self.fp.drift_score(fp)

        # ----------------------------
        # PAYLOAD IDS
        # ----------------------------
        pid = self.ids.analyze(payload)

        # ----------------------------
        # RISK FUSION
        # ----------------------------
        risk = 0
        reasons = []
        explain = []

        explain.extend(exp_z)
        explain.extend(exp_d)

        if z >= 2:
            risk += 2
            reasons.append("stat_deviation")

        if ps < 0.45:
            risk += 2
            reasons.append("path_inconsistent")

        if feats["seg_ent_max"] > 4.2:
            risk += 1
            reasons.append("high_segment_entropy")

        if feats["query_entropy"] > 4:
            risk += 1
            reasons.append("query_anomaly")

        if d:
            risk += 1
            reasons.append("fp_drift")

        if pid["score"] >= 2:
            risk += 1
            reasons.append("payload_signals")

        # ----------------------------
        # LEARNING (URL MODEL)
        # ----------------------------
        model.learn(feats)

        # ----------------------------
        # SEVERITY & CONFIDENCE
        # ----------------------------
        if risk >= 5:
            severity = "HIGH"
        elif risk >= 3:
            severity = "MED"
        else:
            severity = "LOW"

        confidence = round(min(0.95, 0.4 + risk * 0.1), 2)

        # ----------------------------
        # ATTRIBUTION & WAF
        # ----------------------------
        attribution = self.attr.classify(
            d, latency, method, pid["score"]
        )

        waf_action = self.waf.decide(
            risk, pid["score"], confidence
        )

        # ----------------------------
        # FINAL RESULT
        # ----------------------------
        result = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "domain": p.netloc,
            "method": method,
            "risk_score": risk,
            "severity": severity,
            "confidence": confidence,
            "verdict": "FORENSIC_ANOMALY" if risk >= 4 else "CONSISTENT",
            "waf": waf_action,
            "attribution": attribution,
            "fingerprint_id": fp["fp_id"],
            "payload_score": pid["score"],
            "payload_signals": pid["signals"],
            "reasons": reasons,
            "explainability": explain
        }

        return result


def type_line(text, style="", delay=0.04):
    words = text.split(" ")
    for w in words:
        console.print(f"[{style}]{w}[/]", end=" ")
        time.sleep(delay)
    console.print()

def banner():
    console.clear()

    # ── Intro filosófica ─────────────────────────────
    type_line("ByMakaveli, el futuro es hoy.", "bold bright_cyan", 0.06)
    type_line("el momento se vive en la terminal.", "bold bright_cyan", 0.06)
    time.sleep(0.6)

    console.print()

    # ── Core identity ───────────────────────────────
    type_line("╭─▸ FORENSEWEB.PY", "bold magenta", 0.05)
    type_line("│  Fusion Engine • Cyber Forensics • Alien Intelligence", "cyan", 0.03)
    type_line("│  IDS ▸ WAF ▸ Attribution ▸ Behavioral Analysis", "cyan", 0.03)
    type_line("│  Zero Trust • Post-Human SOC • Temporal Awareness", "cyan", 0.03)
    type_line("│", "cyan", 0.02)

    console.print()

    # ── Manifiesto ──────────────────────────────────
    type_line("│  “Observe without attachment.", "green", 0.05)
    type_line("│   Detect without emotion.", "green", 0.05)
    type_line("│   Decide without hesitation.”", "green", 0.05)
    type_line("│        — Ninja Protocol, Beyond Time", "green", 0.04)

    console.print()

    # ── Status ──────────────────────────────────────
    type_line("╰─▸ STATUS:", "bold bright_magenta", 0.04)
    type_line("ONLINE ⚡ MODE: LEGENDARY", "bold bright_cyan", 0.06)

    time.sleep(0.4)

    # ── Final panel pulse ───────────────────────────
    console.print(
        Panel.fit(
            "[bold bright_magenta]FORENSEWEB ONLINE[/bold bright_magenta]\n"
            "[cyan]Post-Human Defensive Consciousness Initialized[/cyan]",
            border_style="bright_magenta",
            padding=(1, 4)
        )
    )


def cli():
    fw = ForenseWeb()
    banner()

    while True:
        try:
            url = Prompt.ask("\n[cyan]Target URL[/cyan] (exit)")
            if url.lower() == "exit":
                break

            method = Prompt.ask("HTTP Method", default="GET")
            latency = float(Prompt.ask("Latency (ms)", default="120"))
            payload = Prompt.ask("Payload (optional)", default="")

            headers = {
                "User-Agent": Prompt.ask("User-Agent", default="Mozilla/5.0"),
                "Accept-Language": Prompt.ask("Accept-Language", default="en-US"),
                "Accept-Encoding": Prompt.ask("Accept-Encoding", default="gzip"),
                "Time-Zone": Prompt.ask("Time-Zone", default="UTC"),
            }

            res = fw.analyze(url, method, headers, latency, payload)

            # =========================
            # CORE METRICS
            # =========================
            metrics = Table(title="🧬 Core Metrics", style="bright_cyan")
            metrics.add_column("Metric", style="magenta")
            metrics.add_column("Value", style="green")

            for k in ["domain", "method", "risk_score", "severity", "confidence", "verdict"]:
                metrics.add_row(k.replace("_", " ").title(), str(res.get(k)))

            console.print(metrics)

            # =========================
            # WAF
            # =========================
            waf = res.get("waf", {})
            waf_t = Table(title="🛡 WAF Decision", style="bright_magenta")
            waf_t.add_column("Field")
            waf_t.add_column("Value")

            for k, v in waf.items():
                waf_t.add_row(k, json.dumps(v))

            console.print(waf_t)

            # =========================
            # ATTRIBUTION
            # =========================
            attr = res.get("attribution", {})
            attr_t = Table(title="🧬 Attribution", style="cyan")
            attr_t.add_column("Field")
            attr_t.add_column("Value")

            for k, v in attr.items():
                attr_t.add_row(k, json.dumps(v))

            console.print(attr_t)

            # =========================
            # FORENSIC SIGNALS
            # =========================
            sig = Table(title="🧠 Forensic Signals", style="green")
            sig.add_column("Type")
            sig.add_column("Details")

            if res["payload_signals"]:
                for s in res["payload_signals"]:
                    sig.add_row("Payload", s)

            if res["reasons"]:
                for r in res["reasons"]:
                    sig.add_row("Risk Reason", r)

            if res["explainability"]:
                for e in res["explainability"]:
                    sig.add_row("Explain", e)

            if sig.row_count == 0:
                sig.add_row("—", "No anomalies detected")

            console.print(sig)

            # =========================
            # RAW JSON
            # =========================
            console.print("\n[bold yellow]📦 RAW JSON (for SIEM / export):[/bold yellow]")
            console.print(json.dumps(res, indent=2))

        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[bold red]Controlled error:[/bold red] {e}")



if __name__ == "__main__":
    cli()
