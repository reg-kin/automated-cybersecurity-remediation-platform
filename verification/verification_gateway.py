#!/usr/bin/env python3
import os
from flask import Flask,jsonify,request
from verification_dispatcher import dispatch
TOKEN=os.getenv('REGIS_VERIFICATION_TOKEN',''); app=Flask(__name__)
def authorised(): return (not TOKEN) or request.headers.get('Authorization')=='Bearer '+TOKEN
@app.get('/health')
def health(): return jsonify({'status':'ok','service':'regis-verification-gateway'})
@app.post('/verify')
def verify():
    if not authorised(): return jsonify({'error':'unauthorised'}),401
    try: return jsonify(dispatch(request.get_json(force=True) or {})),200
    except Exception as exc:
        app.logger.exception('Verification failed closed')
        return jsonify({'verification_status':'FAILED','present':True,'verification_error':str(exc)}),500
if __name__=='__main__': app.run(host=os.getenv('REGIS_VERIFICATION_HOST','0.0.0.0'),port=int(os.getenv('REGIS_VERIFICATION_PORT','8090')))
