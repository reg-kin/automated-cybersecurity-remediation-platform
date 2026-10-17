# Controlled Nmap NSE Stage 2 integration test

Prepared 2026-10-17. Repository inspection and offline tests only. No candidate or laptop connection, database connection, scanner invocation, remediation, service/credential change, migration, commit or push was performed. Candidate runtime details below are supplied context, not independently verified. Existing unrelated working-tree files were left alone.

## A. Current architecture

- `remediation/controllers/base.py:989` constructs the immediate Stage 2 request after Stage 1. It uses `scanner_target_host` as `target_host` and carries the original finding key, class and metadata. `remediation/shared/workflow_payload.py` deep-copies queue metadata. The controller normally persists verification results; bypass it for this isolated test.
- `remediation/shared/verification_client.py` sends authenticated JSON to the configured verification URL. Candidate controller is `127.0.0.1:9001`; do not invoke it in this test.
- `verification/verification_gateway.py` exposes `POST /verify`, exact `Authorization: Bearer <configured token>`, then delegates to the dispatcher. `/health` proves neither scanner readiness nor target reachability.
- `verification/verification_dispatcher.py` selects `nmap_nse` from its fixed orchestrator mapping and invokes its Python interpreter with `--mode verify --verification-request-stdin --json`. Only target, key, class and metadata go to stdin. Finding/execution IDs remain response correlation fields. No database access exists in this gateway/dispatcher path.
- `scanner_orchestrators/nmap_orchestrator.py:1511` requires original `script_id` (legacy fallback `requested_script`) and runs only that selection. Normalization stores `script_id`, original port/protocol, scanned port, service details and requested script in metadata. Keys prefer extracted CVEs; otherwise `NMAP-NSE:<script>:<port>/<protocol>` or `...:host`. Classes remain deterministic. Finding key is the verification identity; class drift is retained as evidence rather than hiding a match.
- Nmap arguments are `/usr/bin/nmap -sV -T4 -Pn --script=ftp-anon -p 2121 -oX - <confirmed-laptop-IP>` for the proposed case. Service detection adds probes on that one port. FTP verification also makes a separate `ftplib` anonymous authentication attempt (15-second timeout).
- Generic NSE negative/missing/error evidence cannot establish absence. Missing host, wrong host, host not up, missing script evidence and negative-only vulnerability output fail closed. FTP uniquely requires the exact FTP key/class and an open original TCP port, then accepts only `230` login success as present or explicit `530` rejection as absent. Closed port is a failure, never a pass.
- Dispatcher maps `present:true` to `FAILED`, `present:false` to `PASSED`. Nonzero scanner exit yields HTTP 200 with FAILED and diagnostic details; dispatcher exceptions yield gateway HTTP 500 with FAILED/present:true. HTTP 200 alone is not success. Controller acceptance additionally requires PASSED and literal false.

## B. Exact payload

For direct gateway testing, use synthetic correlation IDs; these are not database references in this path:

```json
{
  "finding_id": "stage2-laptop-synthetic-finding",
  "execution_id": "stage2-laptop-synthetic-execution",
  "target_host": "<confirmed-current-laptop-IPv4>",
  "engine_source": "nmap_nse",
  "finding_class": "service_misconfiguration",
  "finding_key": "NMAP-NSE:ftp-anon:2121/tcp",
  "engine_metadata": {
    "script_id": "ftp-anon",
    "port": "2121",
    "protocol": "tcp"
  },
  "verification_type": "SCANNER_RESCAN"
}
```

All top-level fields above except `verification_type` are required for this test. Dispatcher requires nonempty finding/execution IDs but does not type-check them. Target, engine source, class and key must be nonempty strings without NUL/CR/LF. Limits: target 2048, engine source 64, class 128, key 4096 characters; metadata object serialized limit 65536. Stdin total limit is 73728 characters. `verification_type` is controller convention, ignored by dispatcher. Metadata is optional in the generic transport but the script ID is mandatory for Nmap; explicit single port and TCP protocol are mandatory for this controlled scope. FTP protocol defaults to TCP if absent, but supply it explicitly. FTP key matching is exact and case-sensitive.

For orchestrator-only stdin, remove IDs, engine_source and verification_type, leaving target_host, finding_key, finding_class and engine_metadata. Do not use a scan-mode ingestion route or invent a database finding. Synthetic original-finding metadata is sufficient to test transport and verification; it does not prove database lifecycle integration.

## C. Recommended Ubuntu scenario

Use a temporary, unprivileged, authentication-only FTP protocol stub on TCP 2121, bound to the confirmed laptop LAN address and restricted to the VM's observed source address. It exposes no files, data connections, commands, uploads, shell or real accounts. Default mode rejects anonymous login with 530, giving a decisive PASSED. A second mode returns a simulated 230 then refuses all data operations, giving FAILED without introducing a vulnerable FTP installation. This is a synthetic integration fixture, not a real detected vulnerability and not remediation.

Avoid SMB vulnerability scripts on Ubuntu, actual vulnerable services, and information scripts such as http-title as negative verification proofs. Do not replace the existing FTP service or install packages. A stub may produce an NSE directory-listing error after 230; the existing FTP branch deliberately uses independent authentication for its decision. Confirm actual behavior with the supplied Nmap 7.94SVN only in a separately authorized live window.

## D. Networking prerequisites (not established)

172.16.95.134 and historical 192.168.0.198 are on different apparent networks; actual masks, routes, VMware mode and laptop address are unknown. Neither reachability nor lack of reachability can be inferred. Do not use 192.168.0.198 until the laptop owner confirms its current assignment and identity.

During a later authorized window, inspect locally on each console (no SSH):

```sh
ip -4 -br address
ip -4 route show
# VM, with confirmed address substituted; route lookup sends no probe:
ip -4 route get <confirmed-laptop-IP>
# Laptop, using the source address observed/expected for the VM:
ip -4 route get <VM-source-IP>
ss -ltn 'sport = :2121'
```

Require a forward route and return path, correct source selection, no VPN overlapping routes, no Wi-Fi client isolation, and laptop firewall permission only for the VM source to TCP 2121. NAT may permit outbound VM-to-LAN connections but change the source address; bridged mode may put the VM directly on the LAN. Host-only networking typically needs an explicitly routed path. Do not change adapters/routes/firewalls during preparation. If rules are necessary, record exact pre-state and seek a separate authorized change window. Gateway 127.0.0.1:18091 is VM-local, not this workspace's or the laptop's loopback; leave it bound to loopback. No inbound exposure of gateway/controller is needed.

## E. Later execution plan — commands below are NOT executed

1. Obtain authorization for the live window and temporary laptop listener. Confirm laptop IP with its owner/local console, routes, source IP, existing source restriction, free port 2121, and candidate process identity/configuration. Stop if any are uncertain. Verify gateway resolves `NMAP_NSE_ORCHESTRATOR` to `/opt/automated-remediation-candidate-47889b1d/application/scanner_orchestrators/nmap_orchestrator.py`, uses the intended Python environment, and NMAP_BINARY is `/usr/bin/nmap`. Do not print credential files. Candidate installed source parity has not been checked here.
2. On laptop console create the following temporary `ftp-auth-stub.py` in a private test directory. It supports only authentication responses and no data access:

```python
import socketserver, sys
bind_ip, allowed_source, mode = sys.argv[1:]
assert mode in ('reject', 'accept')
class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        if self.client_address[0] != allowed_source:
            return
        self.connection.settimeout(10)
        self.wfile.write(b'220 Stage2 FTP test fixture\r\n')
        for _ in range(32):
            line = self.rfile.readline(1025)
            if not line or len(line) > 1024:
                return
            verb = line.split(None, 1)[0].upper() if line.strip() else b''
            if verb == b'QUIT':
                self.wfile.write(b'221 Goodbye\r\n')
                return
            response = {
                b'USER': b'331 Password required\r\n',
                b'PASS': (b'530 Anonymous login disabled\r\n' if mode == 'reject'
                          else b'230 Simulated login accepted\r\n'),
                b'SYST': b'215 UNIX Type: L8\r\n',
                b'FEAT': b'211 No extensions\r\n',
            }.get(verb, b'502 Unsupported by test fixture\r\n')
            self.wfile.write(response)
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
with Server((bind_ip, 2121), Handler) as server:
    server.serve_forever()
```

Run in foreground, initially reject mode:

```sh
python3 ftp-auth-stub.py <confirmed-laptop-IP> <observed-VM-source-IP> reject
```

The source check is defense in depth; require existing scoped firewall permission before binding. No data channel ports are needed. Inspect `ss -ltn 'sport = :2121'` locally. No active connectivity probe was performed in preparation. The authorized single-target verification below will establish endpoint connectivity; a timeout means stop and investigate, never declare PASSED.

3. On VM console create private evidence workspace and `request.json` with the exact payload above, substituting only the confirmed target. Use the existing authorized gateway credential without displaying or altering it. The following assumes it is already available as VERIFICATION_TOKEN in the operator's approved environment; do not source an arbitrary credential file or enable shell tracing.

```sh
umask 077
TEST_DIR=$(mktemp -d /tmp/nmap-stage2.XXXXXX)
# Save the reviewed JSON as "$TEST_DIR/request.json" before continuing.
# Supply token through stdin config, avoiding a token in curl argv:
printf 'header = "Authorization: Bearer %s"\n' "$VERIFICATION_TOKEN" |
  curl --config - --silent --show-error --max-time 1900 \
    --header 'Content-Type: application/json' \
    --data-binary @"$TEST_DIR/request.json" \
    --output "$TEST_DIR/reject.json" --write-out '%{http_code}\n' \
    http://127.0.0.1:18091/verify
```

Do not call controller `/remediate`, ingestion, queue or any database endpoint. Direct gateway execution writes scanner diagnostic logs but has no database persistence. Neither production nor `remediation_candidate_47889b1d` needs a connection. Preserve evidence outside any watched ingestion log directory.

Expected HTTP 200; `verification_status=PASSED`, `present=false`; `scanner_result.evidence.authentication_result=anonymous_login_rejected_530`, method ftp_anonymous_authentication, port 2121, protocol tcp, original key/class/IDs/target preserved. Validate strictly:

```sh
python3 - "$TEST_DIR/reject.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assert r['verification_status'] == 'PASSED' and r['present'] is False
assert r['finding_key'] == 'NMAP-NSE:ftp-anon:2121/tcp'
assert r['scanner_result']['evidence']['authentication_result'] == 'anonymous_login_rejected_530'
PY
```

4. Stop only the foreground stub with Ctrl-C, restart with identical bind/source and `accept` in place of `reject`. Repeat the exact gateway call, changing output to `accept.json`. Expect HTTP 200, FAILED/present:true, authentication_result anonymous_login_accepted. Assert those values and preserved identity. This proves a positive finding remains; it is not an infrastructure failure.
5. Stop the stub and, only if an additional authorized invocation is desired, repeat to `closed.json`. Expect FAILED/present:true and a diagnostic nonzero scanner return (or gateway 500 on timeout); never PASSED. Keep this operational failure distinct from the decisive positive result. Existing offline tests already cover this case, so live repetition is optional.
6. Record candidate source version, runtime configuration identity without secrets, UTC timestamps, actual target/source IP, HTTP status and JSON evidence. Do not claim controller lifecycle closure or production remediation from a direct gateway test.
7. Rollback: stop only the test stub via Ctrl-C; confirm listener removed locally with ss. Delete the temporary stub/private directory and VM evidence directory after retaining approved sanitized results. If any separately authorized firewall rule was added, remove that exact rule and verify restored pre-state. No service restart, credential rollback, migration, database restoration or application rollback is required. Do not restore an entire database snapshot or remove unrelated logs/files.

## F. Gaps and blockers

- Live connectivity, laptop current address/source restriction, installed source parity and actual Nmap 7.94SVN interaction remain unverified by design. They block a live-test claim.
- Generic verify mode permits missing ports (Nmap default port set) and accepts category-shaped script selectors under the name validator. Original protocol is stored but not translated to UDP scanning or checked in generic requested-results filtering. FTP's exact scope validation occurs after run_nmap, so malformed FTP scope can launch a scan before rejection. These are pre-existing scope-hardening gaps; this plan avoids them with a reviewed, exact ftp-anon single TCP port request. Do not generalize this plan to UDP, ranges, categories or absent metadata.
- Generic CVE matching considers all returned script results; CVE keys alone do not encode endpoint identity. FTP synthetic keys explicitly include port/protocol. General endpoint-isolation hardening merits a separate focused change/test task; no application changes are necessary for this exact valid FTP test.
- Only FTP has an implemented decisive negative path here; arbitrary NSE negative evidence must continue failing closed. Do not weaken semantics to force PASSED.
- The temporary stub is a proposed live fixture and was not started/tested over sockets. No real finding ID was read or created. Full controller/database workflow is outside this test.

## G. Offline evidence

Reviewed and ran all zero-argument test functions via runpy using `.venv/bin/python`, plus the gateway security module's import-time assertions. Scanner subprocesses and FTP network operations in these tests are mocked; gateway security subprocesses run local Python only, with Flask test_client in memory.

| Existing test file | Result |
|---|---|
| tests/test_nmap_stage2_verification.py | 12 passed |
| tests/test_nmap_normalization.py | 2 passed |
| tests/test_nmap_hardening.py | 5 passed |
| tests/test_verification_stdin_transport.py | 6 passed |
| tests/test_verification_command_safety.py | 10 passed |
| tests/test_verification_gateway_security.py | module assertions passed |

Total: 35 functions passed plus gateway security assertions. `python` was unavailable; system python3 and virtualenv Python have no pytest installed. No dependencies were installed. Direct runner executed functions rather than reporting a pytest run. Reusable XML fixture: `tests/fixtures/nmap/ms17_010.xml`; FTP XML/metadata fixtures are inline in Stage 2 tests; normalization also supplies inline ftp-anon positive output. Tests cover explicit 230/530, closed port, ambiguous errors/timeouts, wrong key/range, missing host/script evidence, command injection, stdin preservation, deterministic normalization and gateway authentication.

Reproduce without pytest:

```sh
.venv/bin/python - <<'PY'
import runpy
for name in ('nmap_stage2_verification', 'nmap_normalization', 'nmap_hardening',
             'verification_stdin_transport', 'verification_command_safety',
             'verification_gateway_security'):
    ns = runpy.run_path('tests/test_' + name + '.py')
    for key, fn in ns.items():
        if key.startswith('test_') and callable(fn):
            fn()
    print('PASS:', name)
PY
```

## H. Execution results — 2026-10-17

The controlled integration test was performed on 2026-10-17 through the direct verification gateway. This section records the supplied execution results; the preparation-time statements and test plan above are preserved as historical context.

| Test component | Executed configuration |
|---|---|
| Candidate VM | `172.16.95.134` |
| Ubuntu laptop target | `172.16.95.1:2121/tcp` |
| Gateway | `127.0.0.1:18091` |
| Scanner | Nmap NSE `ftp-anon` |

| FTP stub mode | HTTP status | `verification_status` | `present` | `authentication_result` |
|---|---|---|---|---|
| Rejection | 200 | `PASSED` | `false` | `anonymous_login_rejected_530` |
| Acceptance | 200 | `FAILED` | `true` | `anonymous_login_accepted` |

Two infrastructure failures were encountered:

- Initial logging failed because the candidate lacked write access to `/var/log/automated-remediation`. This was resolved with the candidate-specific `LOG_DIR=/var/log/automated-remediation-candidate-47889b1d`.
- The temporary firewall exception expired, causing Nmap to report the target port as filtered.

Both infrastructure failures produced fail-closed verification results; neither established absence of the finding.

Cleanup completed: the FTP stub was stopped, the temporary firewall exception was removed, and the temporary FTP script was removed from the laptop.

Controller lifecycle and database persistence were **NOT tested**. These results establish the controlled direct-gateway verification behavior only.
