import requests
from .config import ANSIBLE_RUNNER_URL,ANSIBLE_RUNNER_TOKEN,ANSIBLE_RUNNER_TIMEOUT

def run(playbook,target_host,extra_vars):
    if not ANSIBLE_RUNNER_URL: raise RuntimeError('ANSIBLE_RUNNER_URL is not configured')
    h={'Content-Type':'application/json'}
    if ANSIBLE_RUNNER_TOKEN: h['Authorization']='Bearer '+ANSIBLE_RUNNER_TOKEN
    r=requests.post(ANSIBLE_RUNNER_URL,json={'playbook':playbook,'target_host':target_host,'extra_vars':extra_vars},headers=h,timeout=ANSIBLE_RUNNER_TIMEOUT)
    r.raise_for_status(); return r.json()
