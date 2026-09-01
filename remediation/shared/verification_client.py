import requests
from .config import VERIFICATION_URL,VERIFICATION_TOKEN,VERIFICATION_TIMEOUT

def verify(payload):
    if not VERIFICATION_URL: raise RuntimeError('REGIS_VERIFICATION_URL is not configured')
    h={'Content-Type':'application/json'}
    if VERIFICATION_TOKEN: h['Authorization']='Bearer '+VERIFICATION_TOKEN
    r=requests.post(VERIFICATION_URL,json=payload,headers=h,timeout=VERIFICATION_TIMEOUT)
    r.raise_for_status(); return r.json()
