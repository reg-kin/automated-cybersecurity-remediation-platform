import os

def env(name,default=None): return os.getenv(name,default)
PG={'host':env('REGIS_PG_HOST','127.0.0.1'),'port':int(env('REGIS_PG_PORT','5432')),'dbname':env('REGIS_PG_DBNAME','security_portal'),'user':env('REGIS_PG_USER','telemetry_admin'),'password':env('REGIS_PG_PASSWORD','')}
CONTROLLER_TOKEN=env('CONTROLLER_TOKEN','')
ANSIBLE_RUNNER_URL=env('ANSIBLE_RUNNER_URL','http://127.0.0.1:8081/run')
ANSIBLE_RUNNER_TOKEN=env('ANSIBLE_RUNNER_TOKEN','')
ANSIBLE_RUNNER_TIMEOUT=int(env('ANSIBLE_RUNNER_TIMEOUT','600'))
VERIFICATION_URL=env('VERIFICATION_URL','')
VERIFICATION_TOKEN=env('VERIFICATION_TOKEN','')
VERIFICATION_TIMEOUT=int(env('VERIFICATION_TIMEOUT','1800'))
SKIP_STAGE2=env('REGIS_TEST_SKIP_STAGE2','false').lower() in ('1','true','yes')
