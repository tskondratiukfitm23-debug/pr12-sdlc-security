#!/usr/bin/env python3
"""OWASP pytm model of pr12-sdlc-security (threat modeling as code).

Usage:
  python threatmodel/tm.py --dfd | dot -Tpng -o docs/dfd.png   # data-flow diagram
  python threatmodel/tm.py --seq | java -jar plantuml.jar -p    # sequence diagram (optional)
  python threatmodel/tm.py --json reports/pytm/tm.json          # findings for the report
"""
from pytm import TM, Actor, Boundary, Classification, Data, Dataflow, Datastore, Lambda, Process, Server

tm = TM("pr12-sdlc-security: Flask demo app")
tm.description = "Flask web app with search, echo, login and profile pages; SQLite storage; GitHub Actions CI/CD."
tm.isOrdered = True
tm.mergeResponses = True
tm.assumptions = [
    "Production runs behind a TLS-terminating reverse proxy (nginx).",
    "SECRET_KEY is injected at runtime from a secret store, never committed.",
    "GitHub account of the owner is protected with 2FA.",
]

internet = Boundary("TB1 Internet")
app_zone = Boundary("TB2 App container")
data_zone = Boundary("TB3 Data")
cicd = Boundary("TB4 CI/CD (GitHub)")

user = Actor("Browser (user / attacker)")
user.inBoundary = internet

web = Server("Flask app :5000")
web.inBoundary = app_zone
web.OS = "Debian slim (python:3.11)"
web.isHardened = True
web.sanitizesInput = True          # length limits, parameterized SQL
web.encodesOutput = True           # Jinja autoescape + markupsafe.escape
web.validatesInput = True
web.implementsCSRFToken = True     # PR #12
web.implementsAuthenticationScheme = True
web.authorizesSource = True
web.hasAccessControl = True
web.usesSessionTokens = True
web.handlesResources = False
web.implementsNonce = True
web.checksInputBounds = True
web.usesEnvironmentVariables = True
web.protocol = "HTTP"              # TLS is terminated at the reverse proxy (assumption)
web.port = 5000
web.controls.isHardened = True
web.controls.sanitizesInput = True
web.controls.encodesOutput = True
web.controls.validatesInput = True
web.controls.implementsCSRFToken = True
web.controls.implementsAuthenticationScheme = True
web.controls.authorizesSource = True
web.controls.hasAccessControl = True
web.controls.checksInputBounds = True

db = Datastore("SQLite DB (users, posts)")
db.inBoundary = data_zone
db.isSQL = True
db.isEncryptedAtRest = False       # residual risk: file-level encryption not used
db.hasWriteAccess = True
db.storesPII = True
db.storesCredentials = True        # scrypt hashes only
db.controls.isHardened = True
db.controls.isEncryptedAtRest = False

secrets_store = Datastore("Config / Secrets (env)")
secrets_store.inBoundary = app_zone
secrets_store.storesSensitiveData = True
secrets_store.controls.isEncryptedAtRest = False

ci = Process("GitHub Actions (SAST/DAST)")
ci.inBoundary = cicd
ci.controls.authenticatesSource = True
ci.controls.hasAccessControl = True

audit_log = Lambda("Audit logger")
audit_log.inBoundary = app_zone

creds = Data("Login credentials", classification=Classification.SECRET, isCredentials=True)
query = Data("Search query", classification=Classification.PUBLIC)
cookie = Data("Session cookie", classification=Classification.SENSITIVE, isCredentials=True)
html = Data("HTML page", classification=Classification.PUBLIC)
sql = Data("SQL statement", classification=Classification.RESTRICTED)
key = Data("SECRET_KEY", classification=Classification.TOP_SECRET, isCredentials=True)
event = Data("Security event", classification=Classification.SENSITIVE)

f1 = Dataflow(user, web, "POST /login (username, password, csrf_token)")
f1.protocol = "HTTP"
f1.dstPort = 5000
f1.data = creds
f1.controls.isEncrypted = False    # TLS at proxy, not in the app itself

f2 = Dataflow(user, web, "GET /search?q= , /echo?msg=")
f2.protocol = "HTTP"
f2.data = query

f3 = Dataflow(web, db, "Parameterized SQL")
f3.protocol = "SQLite"
f3.data = sql
f3.controls.usesParameterizedInput = True

f4 = Dataflow(db, web, "Rows (posts, password_hash)")
f4.protocol = "SQLite"
f4.data = sql
f4.responseTo = f3

f5 = Dataflow(web, user, "HTML + Set-Cookie (HttpOnly, SameSite=Lax) + security headers")
f5.protocol = "HTTP"
f5.data = [html, cookie]
f5.responseTo = f1

f6 = Dataflow(secrets_store, web, "Read SECRET_KEY / DB_PATH")
f6.protocol = "env"
f6.data = key

f7 = Dataflow(web, audit_log, "login_success / login_failed / csrf_rejected")
f7.protocol = "logging"
f7.data = event

f8 = Dataflow(ci, web, "Build image, ZAP baseline scan")
f8.protocol = "HTTPS"
f8.controls.isEncrypted = True

if __name__ == "__main__":
    tm.process()
