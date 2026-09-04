#!/usr/bin/env python3
import json,os,subprocess,sys
ORCHESTRATORS={
'openvas':os.getenv('OPENVAS_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/openvas_orchestrator.py'),
'nmap_nse':os.getenv('NMAP_NSE_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/nmap_orchestrator.py'),
'wazuh_vulnerability':os.getenv('WAZUH_VULN_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/wazuh_vuln_orchestrator.py'),
'wazuh_sca':os.getenv('WAZUH_SCA_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/wazuh_sca_orchestrator.py'),
'lynis':os.getenv('LYNIS_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/lynis_orchestrator.py'),
'nuclei':os.getenv('NUCLEI_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/nuclei_orchestrator.py'),
'trivy':os.getenv('TRIVY_ORCHESTRATOR','/opt/automated-remediation/scanner_orchestrators/trivy_orchestrator.py'),
}

def dispatch(p):
    req=['finding_id','execution_id','target_host','engine_source','finding_class','finding_key']; missing=[x for x in req if p.get(x) in (None,'')]
    if missing: raise ValueError('Missing verification fields: '+', '.join(missing))
    src=str(p['engine_source']).lower(); orch=ORCHESTRATORS.get(src)
    if not orch: raise ValueError(f'No verification orchestrator configured for engine_source={src}')
    if not os.path.isfile(orch): raise FileNotFoundError(f'Orchestrator does not exist: {orch}')
    meta=p.get('engine_metadata') if isinstance(p.get('engine_metadata'),dict) else {}
    cmd=[sys.executable,orch,'--mode','verify','--target-host',str(p['target_host']),'--finding-key',str(p['finding_key']),'--finding-class',str(p['finding_class']),'--engine-metadata-json',json.dumps(meta,separators=(',',':')),'--json']
    r=subprocess.run(cmd,capture_output=True,text=True,timeout=int(os.getenv('SCANNER_VERIFY_TIMEOUT','1800')))
    if r.returncode!=0:
        return {'finding_id':p['finding_id'],'execution_id':p['execution_id'],'engine_source':src,'finding_class':p['finding_class'],'finding_key':p['finding_key'],'target_host':p['target_host'],'present':True,'verification_status':'FAILED','verification_error':f'Scanner orchestrator exited with return code {r.returncode}','scanner_result':{'present':True,'scanner':src,'target_host':p['target_host'],'finding_key':p['finding_key'],'finding_class':p['finding_class'],'evidence':{},'verification_error':r.stderr.strip(),'return_code':r.returncode}}
    try: result=json.loads(r.stdout.strip())
    except Exception as exc: raise RuntimeError(f'{src} returned invalid JSON: {r.stdout[:500]}') from exc
    present=result.get('present')
    if not isinstance(present,bool): raise RuntimeError(f'{src} verification result missing boolean present')
    return {'finding_id':p['finding_id'],'execution_id':p['execution_id'],'engine_source':src,'finding_class':p['finding_class'],'finding_key':p['finding_key'],'target_host':p['target_host'],'present':present,'verification_status':'FAILED' if present else 'PASSED','verified_at':result.get('verified_at'),'scanner_result':result}
