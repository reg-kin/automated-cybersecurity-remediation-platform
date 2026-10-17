"""Connection guard shared by the mutating release-smoke regressions."""
import os
import re


# These can redirect connections or change session/authentication semantics.
# PGPASSFILE, PGPASSWORD, PGSSLMODE and channel binding remain supported.
UNSAFE_ENV = (
    'PGSERVICE', 'PGSERVICEFILE', 'PGHOSTADDR', 'PGOPTIONS',
    'PGREQUIRESSL', 'PGREQUIREPEER', 'PGGSSENCMODE', 'PGKRBSRVNAME',
    'PGGSSLIB', 'PGREALM', 'PGREQUIREAUTH', 'PGLOADBALANCEHOSTS',
    'PGTARGETSESSIONATTRS', 'PGSSLNEGOTIATION',
)


def connect(**kwargs):
    import psycopg2

    options = {key: os.environ.get(env) for key, env in (
        ('host', 'PG_HOST'), ('port', 'PG_PORT'), ('user', 'PG_USER'),
        ('password', 'PG_PASSWORD'), ('dbname', 'PG_DBNAME'))
        if os.environ.get(env) is not None}
    # Only explicit keyword connection arguments are supported. In particular,
    # libpq expands connection strings supplied as dbname/database or dsn.
    if set(kwargs) - {'host', 'port', 'user', 'password', 'dbname', 'database', 'connect_timeout'}:
        raise RuntimeError('Unsafe PostgreSQL connection arguments')
    if 'database' in kwargs:
        if 'dbname' in kwargs and kwargs['dbname'] != kwargs['database']:
            raise RuntimeError('Conflicting database overrides')
        kwargs['dbname'] = kwargs.pop('database')
    for key, value in kwargs.items():
        if key in options and str(value) != str(options[key]):
            raise RuntimeError('Conflicting PostgreSQL connection override: ' + key)
    options.update(kwargs)
    database = options.get('dbname', '')
    confirmed = os.environ.get('SMOKE_DISPOSABLE_DATABASE', '')
    if (not isinstance(database, str) or database != confirmed or
            len(database.encode()) > 63 or not re.fullmatch(
                r'automated_remediation_release_smoke_test_[a-z0-9_]+', database)):
        raise RuntimeError('Explicit disposable smoke database confirmation required')
    host, port = options.get('host', ''), str(options.get('port', ''))
    if (not isinstance(host, str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]+', host)
            or not re.fullmatch(r'[0-9]{1,5}', port) or not 0 < int(port) <= 65535):
        raise RuntimeError('Invalid PostgreSQL host or port')
    for key, value in (('PGHOST', host), ('PGPORT', port)):
        if os.environ.get(key) and os.environ[key] != value:
            raise RuntimeError('Conflicting inherited PostgreSQL endpoint: ' + key)
    if any(os.environ.get(key) for key in UNSAFE_ENV):
        raise RuntimeError('Unsafe inherited libpq configuration')
    expected = os.environ.get('SMOKE_EXPECTED_ENDPOINT', '')
    # IPv6 addresses contain colons; split the fixed trailing fields only.
    fields = expected.rsplit(':', 3)
    if (len(fields) != 4 or not fields[0] or not fields[1].isdigit()
            or not fields[2].isdigit() or not re.fullmatch(r'[a-f0-9]{20}', fields[3])):
        raise RuntimeError('Expected PostgreSQL endpoint is required and must be unambiguous')
    options['connect_timeout'] = 5
    connection = psycopg2.connect(**options)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT inet_server_addr()::text || ':' || inet_server_port() || ':' || oid || ':' || shobj_description(oid, 'pg_database') "
                           "FROM pg_database WHERE datname=current_database()")
            rows = cursor.fetchall()
        connection.rollback()
        actual = rows[0][0] if len(rows) == 1 else None
        # Docker NAT can change the server address/port observed by a client.
        # The fresh random marker plus database OID proves the same database;
        # never infer equivalence from container loopback or published ports.
        mode = os.environ.get('SMOKE_PG_MODE', 'native')
        matches = actual == expected
        if mode == 'docker' and isinstance(actual, str):
            observed = actual.rsplit(':', 3)
            matches = (len(observed) == 4 and bool(observed[0]) and
                       observed[1].isdigit() and observed[2:] == fields[2:])
        if mode not in ('native', 'docker') or not matches:
            raise RuntimeError('PostgreSQL endpoint mismatch; refusing database mutation')
        return connection
    except BaseException:
        connection.close()
        raise
