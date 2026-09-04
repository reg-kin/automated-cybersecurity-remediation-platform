#!/usr/bin/env python3
# Canonical Ollama enrichment worker. Ollama enriches risk only; routing is deterministic DB/n8n.
import json, logging, os, sys, urllib.request
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

from jsonschema import Draft7Validator, FormatChecker
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import Json

CONFIG_PATH=os.getenv('ENRICHER_CONFIG','/opt/automated-remediation/config.json')
DEFAULT={'ollama_url':'http://127.0.0.1:11434/api/chat','ollama_model':'phi3:latest','ollama_timeout':120,'pg_host':'127.0.0.1','pg_port':5432,'pg_dbname':'security_portal','pg_user':'telemetry_admin','pg_password':'','pg_minconn':1,'pg_maxconn':5,'log_dir':'/var/log/automated-remediation','recurrence_grace_seconds':300}
CATEGORIES={'vulnerability','compliance_drift','integrity_drift','rootkit'}
SEVERITIES={'CRITICAL','HIGH','MEDIUM','LOW'}
LIFECYCLE={'OPEN','IN_REMEDIATION','RESOLVED','FALSE_POSITIVE'}
COMPLIANCE={'PASS','FAIL','NOT_APPLICABLE'}
SYSTEM_PROMPT=("You are the risk-enrichment component of an automated cybersecurity remediation platform. Your ONLY job is to enrich the supplied security finding with concise risk context. Do NOT select or recommend an Ansible role, playbook, remediation action, automation tier, approval requirement, remediation capability, or execution parameters. Those decisions are made deterministically by PostgreSQL remediation_rules and n8n. Do not invent technical facts. Return JSON only with exactly: risk_summary, business_context_impact, confidence_score. confidence_score must be between 0 and 1.")
FALLBACK={'risk_summary':'Security finding requires deterministic remediation-rule evaluation.','business_context_impact':'Potential security exposure or control weakness on the target asset.','confidence_score':0.0}
logger=logging.getLogger('automated_remediation.enricher'); pool=None

REFRESH_EVENT_TYPE='scanner_refresh_complete'
REFRESH_STATUSES={'SUCCESS','FAILED'}
WAZUH_ASYNC_ENGINES={'wazuh_vulnerability','wazuh_sca'}

UNIFIED_FINDING_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / 'schema'
    / 'unified_security_finding.schema.json'
)

with UNIFIED_FINDING_SCHEMA_PATH.open(encoding='utf-8') as schema_file:
    UNIFIED_FINDING_SCHEMA = json.load(schema_file)

Draft7Validator.check_schema(UNIFIED_FINDING_SCHEMA)

UNIFIED_FINDING_VALIDATOR = Draft7Validator(
    UNIFIED_FINDING_SCHEMA,
    format_checker=FormatChecker(),
)

def config():
    c=DEFAULT.copy()
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH,encoding='utf-8') as f: c.update(json.load(f))
    if not c.get('pg_password'): c['pg_password']=os.getenv('PGPASSWORD','')
    return c

def setup(c):
    os.makedirs(c['log_dir'],exist_ok=True); logger.setLevel(logging.INFO); logger.handlers.clear()
    fmt=logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh=RotatingFileHandler(os.path.join(c['log_dir'],'enrichment_worker.log'),maxBytes=10*1024*1024,backupCount=5); fh.setFormatter(fmt); logger.addHandler(fh)
    sh=logging.StreamHandler(sys.stdout); sh.setFormatter(fmt); logger.addHandler(sh)

def now(): return datetime.now(timezone.utc).isoformat()

def parse_timestamp(v):
    if not v: return datetime.now(timezone.utc)
    if isinstance(v,datetime): dt=v
    else:
        s=str(v).strip(); s=s[:-1]+'+00:00' if s.endswith('Z') else s; dt=datetime.fromisoformat(s)
    if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def is_nullish(value):
    """
    Return True for values that represent an absent optional value.

    Scanner payloads should ideally use JSON null, which becomes Python None,
    but this also safely handles common string representations.
    """
    if value is None:
        return True

    if isinstance(value, str):
        return value.strip().lower() in {
            "",
            "null",
            "none",
            "nil",
        }

    return False


def parse_optional_timestamp(value):
    """
    Parse an optional timestamp and return an aware UTC datetime.

    Nullish values become None so psycopg2 sends SQL NULL rather than the
    literal string 'null'.
    """
    if is_nullish(value):
        return None

    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(
                f"Invalid timestamp value: {value!r}"
            ) from exc

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)

def validate_unified_finding_schema(payload):
    """
    Validate the scanner-ingress Unified Security Finding contract.

    Scanner refresh control events use a separate contract and are handled
    before this validator is called.
    """
    errors = sorted(
        UNIFIED_FINDING_VALIDATOR.iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )

    if not errors:
        return

    error = errors[0]

    location = "$"

    if error.absolute_path:
        location += "".join(
            f"[{part!r}]"
            if isinstance(part, int)
            else f".{part}"
            for part in error.absolute_path
        )

    raise ValueError(
        "Unified Security Finding schema validation failed "
        f"at {location}: {error.message}"
    )


def parse_detected_timestamp(value):
    """
    Parse the scanner observation timestamp.

    detected_at is mandatory because it represents the time of the scanner
    observation and participates in recurrence and lifecycle decisions.
    Ingestion must never manufacture this evidence.
    """
    parsed = parse_optional_timestamp(value)

    if parsed is None:
        raise ValueError(
            "detected_at is required for a Unified Security Finding"
        )

    return parsed

def is_refresh_control_event(payload):
    return isinstance(payload,dict) and str(payload.get('event_type') or '').strip().lower()==REFRESH_EVENT_TYPE

def normalise_refresh_event(payload):
    required=['engine_source','scanner_subject_type','scanner_subject_id','refresh_id','refresh_started_at','refresh_completed_at','refresh_status','expected_findings']
    missing=[x for x in required if is_nullish(payload.get(x))]
    if missing: raise ValueError('Missing refresh-control fields: '+', '.join(missing))
    engine_source=str(payload['engine_source']).strip().lower()
    if engine_source not in WAZUH_ASYNC_ENGINES: raise ValueError(f'Unsupported asynchronous refresh engine_source: {engine_source}')
    status=str(payload['refresh_status']).strip().upper()
    if status not in REFRESH_STATUSES: raise ValueError(f'Invalid refresh_status: {status}')
    try: expected=int(payload['expected_findings'])
    except (TypeError,ValueError) as exc: raise ValueError('expected_findings must be an integer') from exc
    if expected<0: raise ValueError('expected_findings cannot be negative')
    started=parse_optional_timestamp(payload['refresh_started_at']); completed=parse_optional_timestamp(payload['refresh_completed_at'])
    if started is None or completed is None: raise ValueError('refresh timestamps are required')
    if completed<started: raise ValueError('refresh_completed_at cannot precede refresh_started_at')
    tenant=payload.get('tenant_code'); tenant=None if is_nullish(tenant) else str(tenant).strip()
    excluded={'event_type','engine_source','scanner_subject_type','scanner_subject_id','refresh_id','refresh_started_at','refresh_completed_at','refresh_status','expected_findings'}
    return {'engine_source':engine_source,'scanner_subject_type':str(payload['scanner_subject_type']).strip().lower(),'scanner_subject_id':str(payload['scanner_subject_id']).strip(),'refresh_id':str(payload['refresh_id']).strip(),'refresh_started_at':started,'refresh_completed_at':completed,'refresh_status':status,'expected_findings':expected,'tenant_code':tenant,'metadata':{k:v for k,v in payload.items() if k not in excluded}}

def store_refresh_completion(conn,e):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO scanner_refresh_completions(engine_source,scanner_subject_type,scanner_subject_id,refresh_id,refresh_started_at,refresh_completed_at,refresh_status,expected_findings,tenant_code,metadata)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(engine_source,scanner_subject_type,scanner_subject_id,refresh_id) DO UPDATE SET
        refresh_started_at=EXCLUDED.refresh_started_at,refresh_completed_at=EXCLUDED.refresh_completed_at,refresh_status=EXCLUDED.refresh_status,expected_findings=EXCLUDED.expected_findings,tenant_code=EXCLUDED.tenant_code,metadata=EXCLUDED.metadata,updated_at=now()
        RETURNING completion_id""",(e['engine_source'],e['scanner_subject_type'],e['scanner_subject_id'],e['refresh_id'],e['refresh_started_at'],e['refresh_completed_at'],e['refresh_status'],e['expected_findings'],e['tenant_code'],Json(e['metadata'])))
        return cur.fetchone()[0]

def get_refresh_completion(conn,engine_source,subject_type,refresh_id,subject_id):
    with conn.cursor() as cur:
        cur.execute("""SELECT completion_id,engine_source,scanner_subject_type,scanner_subject_id,refresh_id,refresh_started_at,refresh_completed_at,refresh_status,expected_findings,tenant_code,metadata,promoted_at
        FROM scanner_refresh_completions
        WHERE engine_source=%s
          AND scanner_subject_type=%s
          AND refresh_id=%s
          AND scanner_subject_id=%s
        FOR UPDATE""",(engine_source,subject_type,refresh_id,subject_id))
        r=cur.fetchone()
    if not r: return None
    return {'completion_id':r[0],'engine_source':r[1],'scanner_subject_type':r[2],'scanner_subject_id':r[3],'refresh_id':r[4],'refresh_started_at':r[5],'refresh_completed_at':r[6],'refresh_status':r[7],'expected_findings':r[8],'tenant_code':r[9],'metadata':r[10] or {},'promoted_at':r[11]}

def record_refresh_finding_receipt(
    conn,
    engine_source,
    scanner_subject_type,
    scanner_subject_id,
    refresh_id,
    tenant_code,
    finding_key,
    finding_id
):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO scanner_refresh_finding_receipts(
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                refresh_id,
                tenant_code,
                finding_key,
                finding_id
            )
            VALUES(%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(
                engine_source,
                scanner_subject_type,
                scanner_subject_id,
                refresh_id,
                finding_key
            )
            DO NOTHING
        """,(
            engine_source,
            scanner_subject_type,
            scanner_subject_id,
            refresh_id,
            tenant_code,
            finding_key,
            finding_id
        ))

def count_refresh_receipts(conn,c):
    clauses=[
        "engine_source=%s",
        "scanner_subject_type=%s",
        "scanner_subject_id=%s",
        "refresh_id=%s"
    ]
    params=[
        c['engine_source'],
        c['scanner_subject_type'],
        c['scanner_subject_id'],
        c['refresh_id']
    ]

    if c.get('tenant_code'):
        clauses.append("tenant_code=%s")
        params.append(c['tenant_code'])

    with conn.cursor() as cur:
        cur.execute(
            'SELECT COUNT(*) FROM scanner_refresh_finding_receipts WHERE '
            + ' AND '.join(clauses),
            tuple(params)
        )
        return int(cur.fetchone()[0])

def write_refresh_watermark(conn,c):
    metadata={**(c.get('metadata') or {}),'expected_findings':c['expected_findings'],'tenant_code':c.get('tenant_code'),'completion_id':c['completion_id']}
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO scanner_refresh_watermarks(engine_source,scanner_subject_type,scanner_subject_id,refresh_id,refresh_started_at,refresh_completed_at,refresh_status,metadata)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(engine_source,scanner_subject_type,scanner_subject_id,refresh_id) DO UPDATE SET
        refresh_started_at=EXCLUDED.refresh_started_at,refresh_completed_at=EXCLUDED.refresh_completed_at,refresh_status=EXCLUDED.refresh_status,metadata=EXCLUDED.metadata
        RETURNING watermark_id""",(c['engine_source'],c['scanner_subject_type'],c['scanner_subject_id'],c['refresh_id'],c['refresh_started_at'],c['refresh_completed_at'],c['refresh_status'],Json(metadata)))
        wid=cur.fetchone()[0]
        cur.execute("UPDATE scanner_refresh_completions SET promoted_at=COALESCE(promoted_at,now()),updated_at=now() WHERE completion_id=%s",(c['completion_id'],))
    return wid

def try_promote_refresh(conn,engine_source,subject_type,refresh_id,subject_id):
    c=get_refresh_completion(
        conn,
        engine_source,
        subject_type,
        refresh_id,
        subject_id
    )
    if not c:
        return {
            'promoted':False,
            'reason':'completion_event_not_received'
        }

    if c['promoted_at'] is not None:
        return {
            'promoted':True,
            'reason':'already_promoted'
        }

    if c['refresh_status']=='FAILED':
        return {
            'promoted':True,
            'watermark_id':write_refresh_watermark(conn,c),
            'refresh_status':'FAILED',
            'expected_findings':c['expected_findings']
        }

    ingested=count_refresh_receipts(conn,c)
    expected=c['expected_findings']

    if ingested<expected:
        return {
            'promoted':False,
            'reason':'awaiting_findings',
            'ingested_findings':ingested,
            'expected_findings':expected
        }

    return {
        'promoted':True,
        'watermark_id':write_refresh_watermark(conn,c),
        'refresh_status':'SUCCESS',
        'ingested_findings':ingested,
        'expected_findings':expected
    }

def process_refresh_control_event(c,payload):
    global pool
    e=normalise_refresh_event(payload)
    if pool is None: pool=SimpleConnectionPool(int(c['pg_minconn']),int(c['pg_maxconn']),host=c['pg_host'],port=c['pg_port'],dbname=c['pg_dbname'],user=c['pg_user'],password=c['pg_password'],connect_timeout=5)
    conn=pool.getconn()
    try:
        with conn:
            cid=store_refresh_completion(conn,e)
            result=try_promote_refresh(
                conn,
                e['engine_source'],
                e['scanner_subject_type'],
                e['refresh_id'],
                e['scanner_subject_id']
            )
        logger.info('Refresh control stored completion_id=%s engine=%s subject=%s refresh_id=%s status=%s promoted=%s',cid,e['engine_source'],e['scanner_subject_id'],e['refresh_id'],e['refresh_status'],result.get('promoted'))
        return {'event_type':REFRESH_EVENT_TYPE,'completion_id':cid,**result}
    finally: pool.putconn(conn)

def normalise(p):
    if not isinstance(p, dict):
        raise ValueError(
            "Scanner payload must be a JSON object"
        )

    required = [
        "tenant_code",
        "tenant_service_tier",
        "target_host",
        "engine_source",
        "finding_category",
        "finding_class",
        "finding_key",
        "finding_title",
        "lifecycle_status",
    ]

    missing = [
        field
        for field in required
        if is_nullish(
            p.get(field)
        )
    ]

    if missing:
        raise ValueError(
            "Missing scanner fields: "
            + ", ".join(missing)
        )

    category = str(
        p["finding_category"]
    ).lower().strip()

    if category not in CATEGORIES:
        raise ValueError(
            f"Invalid finding_category: {category}"
        )

    lifecycle_status = str(
        p["lifecycle_status"]
    ).upper().strip()

    if lifecycle_status not in LIFECYCLE:
        raise ValueError(
            "Invalid lifecycle_status: "
            f"{lifecycle_status}"
        )

    severity_level = p.get(
        "severity_level"
    )

    if is_nullish(
        severity_level
    ):
        severity_level = None

    else:
        severity_level = str(
            severity_level
        ).upper().strip()

        if severity_level not in SEVERITIES:
            raise ValueError(
                "Invalid severity_level: "
                f"{severity_level}"
            )

    severity_score = p.get(
        "severity_score"
    )

    if is_nullish(
        severity_score
    ):
        severity_score = None

    else:
        try:
            severity_score = float(
                severity_score
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                "Invalid severity_score: "
                f"{severity_score!r}"
            ) from exc

        if not 0 <= severity_score <= 10:
            raise ValueError(
                "severity_score must be between 0 and 10"
            )

    compliance_result = p.get(
        "compliance_result"
    )

    if is_nullish(
        compliance_result
    ):
        compliance_result = None

    else:
        compliance_result = str(
            compliance_result
        ).upper().strip()

        if compliance_result not in COMPLIANCE:
            raise ValueError(
                "Invalid compliance_result: "
                f"{compliance_result}"
            )

    engine_metadata = (
        p.get("engine_metadata")
        or {}
    )

    if not isinstance(
        engine_metadata,
        dict
    ):
        raise ValueError(
            "engine_metadata must be a JSON object"
        )

    return {
        **p,

        "tenant_code":
            str(
                p["tenant_code"]
            ).strip(),

        "tenant_service_tier":
            str(
                p["tenant_service_tier"]
            ).strip().upper(),

        "target_host":
            str(
                p["target_host"]
            ).strip(),

        "engine_source":
            str(
                p["engine_source"]
            ).strip().lower(),

        "finding_category":
            category,

        "finding_class":
            str(
                p["finding_class"]
            ).strip(),

        "finding_key":
            str(
                p["finding_key"]
            ).strip(),

        "finding_title":
            str(
                p["finding_title"]
            ).strip(),

        "lifecycle_status":
            lifecycle_status,

        "detected_at":
            parse_detected_timestamp(
                p.get("detected_at")
            ),

        "remediated_at":
            parse_optional_timestamp(
                p.get("remediated_at")
            ),

        "last_verified_at":
            parse_optional_timestamp(
                p.get("last_verified_at")
            ),

        "compliance_result":
            compliance_result,

        "severity_level":
            severity_level,

        "severity_score":
            severity_score,

        "engine_metadata":
            engine_metadata,
    }

def enrich(c,f):
    user={k:f.get(k) for k in ['tenant_service_tier','target_host','engine_source','finding_category','finding_class','finding_key','finding_title','severity_level','severity_score','engine_metadata']}
    body={'model':c['ollama_model'],'messages':[{'role':'system','content':SYSTEM_PROMPT},{'role':'user','content':json.dumps(user,ensure_ascii=False)}],'stream':False,'format':'json','options':{'temperature':0.1,'num_predict':250,'num_ctx':4096}}
    try:
        req=urllib.request.Request(c['ollama_url'],data=json.dumps(body).encode(),headers={'Content-Type':'application/json'},method='POST')
        with urllib.request.urlopen(req,timeout=float(c['ollama_timeout'])) as r: raw=json.loads(r.read().decode())
        d=json.loads(raw.get('message',{}).get('content','{}'))
        rs=str(d.get('risk_summary','')).strip() or FALLBACK['risk_summary']; bi=str(d.get('business_context_impact','')).strip() or FALLBACK['business_context_impact']
        try: cs=max(0.0,min(1.0,float(d.get('confidence_score',0.0))))
        except Exception: cs=0.0
        return {'risk_summary':rs,'business_context_impact':bi,'confidence_score':cs,'analyzed_at':now()}
    except Exception:
        logger.exception('Ollama enrichment failed; using fallback'); return {**FALLBACK,'analyzed_at':now()}

def process_ai_enrichment(payload):
    global pool
    c=config(); setup(c)
    if is_refresh_control_event(payload): return process_refresh_control_event(c,payload)

    validate_unified_finding_schema(payload)

    f=normalise(payload)
    grace=int(c.get('recurrence_grace_seconds',300))
    if pool is None: pool=SimpleConnectionPool(int(c['pg_minconn']),int(c['pg_maxconn']),host=c['pg_host'],port=c['pg_port'],dbname=c['pg_dbname'],user=c['pg_user'],password=c['pg_password'],connect_timeout=5)
    conn=pool.getconn()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT 1 FROM finding_class_catalogue WHERE finding_class=%s AND finding_category=%s AND enabled=TRUE',(f['finding_class'],f['finding_category']))
            if not cur.fetchone(): raise ValueError(f"Unknown/disabled/category-mismatched finding_class: {f['finding_class']}")
        ai=enrich(c,f)
        sql='''INSERT INTO unified_security_findings(tenant_code,tenant_service_tier,target_host,engine_source,finding_category,finding_class,finding_key,finding_title,lifecycle_status,detected_at,last_seen_at,remediated_at,last_verified_at,compliance_result,severity_level,severity_score,engine_metadata,ai_analysis)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT(tenant_code,target_host,engine_source,finding_key) DO UPDATE SET
          tenant_service_tier=EXCLUDED.tenant_service_tier,finding_category=EXCLUDED.finding_category,finding_class=EXCLUDED.finding_class,finding_title=EXCLUDED.finding_title,
          compliance_result=EXCLUDED.compliance_result,severity_level=EXCLUDED.severity_level,severity_score=EXCLUDED.severity_score,engine_metadata=EXCLUDED.engine_metadata,ai_analysis=EXCLUDED.ai_analysis,
          last_seen_at=GREATEST(unified_security_findings.last_seen_at,EXCLUDED.detected_at),
          lifecycle_status=CASE WHEN unified_security_findings.lifecycle_status='RESOLVED' AND unified_security_findings.remediated_at IS NOT NULL AND EXCLUDED.detected_at > unified_security_findings.remediated_at+(%s*INTERVAL '1 second') THEN 'OPEN' ELSE unified_security_findings.lifecycle_status END,
          recurrence_count=CASE WHEN unified_security_findings.lifecycle_status='RESOLVED' AND unified_security_findings.remediated_at IS NOT NULL AND EXCLUDED.detected_at > unified_security_findings.remediated_at+(%s*INTERVAL '1 second') THEN unified_security_findings.recurrence_count+1 ELSE unified_security_findings.recurrence_count END,
          last_reopened_at=CASE WHEN unified_security_findings.lifecycle_status='RESOLVED' AND unified_security_findings.remediated_at IS NOT NULL AND EXCLUDED.detected_at > unified_security_findings.remediated_at+(%s*INTERVAL '1 second') THEN now() ELSE unified_security_findings.last_reopened_at END,
          remediated_at=CASE WHEN unified_security_findings.lifecycle_status='RESOLVED' AND unified_security_findings.remediated_at IS NOT NULL AND EXCLUDED.detected_at > unified_security_findings.remediated_at+(%s*INTERVAL '1 second') THEN NULL ELSE unified_security_findings.remediated_at END,
          last_error=CASE WHEN unified_security_findings.lifecycle_status='RESOLVED' AND unified_security_findings.remediated_at IS NOT NULL AND EXCLUDED.detected_at > unified_security_findings.remediated_at+(%s*INTERVAL '1 second') THEN 'Previously resolved finding detected again by scanner' ELSE unified_security_findings.last_error END,
          updated_at=now()
        RETURNING finding_id,lifecycle_status,recurrence_count,last_reopened_at'''
        vals=(f['tenant_code'],f['tenant_service_tier'],f['target_host'],f['engine_source'],f['finding_category'],f['finding_class'],f['finding_key'],f['finding_title'],f['lifecycle_status'],f['detected_at'],f['detected_at'],f.get('remediated_at'),f.get('last_verified_at'),f.get('compliance_result'),f['severity_level'],f['severity_score'],Json(f['engine_metadata']),Json(ai),grace,grace,grace,grace,grace)
        with conn:
            with conn.cursor() as cur: cur.execute(sql,vals); row=cur.fetchone()
            metadata=f.get('engine_metadata') or {}
            refresh_id=metadata.get('refresh_id')
            agent_id=metadata.get('agent_id')

            if f['engine_source'] in WAZUH_ASYNC_ENGINES and refresh_id and agent_id:
                scanner_subject_type='wazuh_agent'

                record_refresh_finding_receipt(
                    conn,
                    f['engine_source'],
                    scanner_subject_type,
                    str(agent_id),
                    str(refresh_id),
                    f['tenant_code'],
                    f['finding_key'],
                    row[0]
                )

                try_promote_refresh(
                    conn,
                    f['engine_source'],
                    scanner_subject_type,
                    str(refresh_id),
                    str(agent_id)
                )
        logger.info('Finding stored finding_id=%s lifecycle=%s recurrence_count=%s',row[0],row[1],row[2])
        return {'finding_id':row[0],'lifecycle_status':row[1],'recurrence_count':row[2],'last_reopened_at':row[3].isoformat() if row[3] else None,'ai_analysis':ai}
    finally: pool.putconn(conn)

process=process_ai_enrichment
if __name__=='__main__':
    if len(sys.argv)!=2: raise SystemExit('Usage: enricher_worker.py payload.json')
    with open(sys.argv[1],encoding='utf-8') as f: payload=json.load(f)
    print(json.dumps(process_ai_enrichment(payload),default=str))
