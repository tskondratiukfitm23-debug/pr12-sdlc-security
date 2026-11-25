# DAST: процес тестування (OWASP ZAP baseline)

## 1. Запуск

**CI** (`.github/workflows/dast.yml`): на кожен push у `main` і вручну. Застосунок стартує з
ефемерним `SECRET_KEY`, після готовності (`curl` до 20 с) виконується `zaproxy/action-baseline@v0.14.0`
(`-a -j`: альфа-правила + AJAX spider). Звіти — артефакт `zap-report`, підсумок — Issue «ZAP Scan Baseline Report».

**Локально (ВМ Ubuntu):**
```
SECRET_KEY=$(openssl rand -hex 32) flask --app src/app.py run --host=127.0.0.1 --port=5000 &
docker run --rm --network host -v $(pwd)/reports/zap-after:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://127.0.0.1:5000 -r zap.html -J zap.json -w zap.md -a -j -I
```

Baseline — пасивне сканування (без атакувальних запитів), безпечне для спільних середовищ (NFR-6).

## 2. Результати до виправлень (baseline, коміт b813dca)

Підсумок: FAIL 0 · WARN 13 · PASS 58.

| Ризик ZAP | ID | Знахідка | Issue |
|---|---|---|---|
| Medium | 10038 | Content Security Policy не встановлено | #9 |
| Medium | 10020 | Немає захисту від clickjacking (X-Frame-Options) | #9 |
| Medium | 10202 | Відсутні Anti-CSRF токени | #8 |
| Medium | 10099 | Розкриття вихідного коду — SQL | #10 |
| Low | 10021 | Немає X-Content-Type-Options | #9 |
| Low | 10063 | Немає Permissions-Policy | #9 |
| Low | 90004 | Немає COEP / COOP / CORP | #9 |
| Low | 10036 | Заголовок `Server` розкриває версію | RR1 |
| Info | 10031, 10049, 10109, 10111, 90005 | атрибут під контролем користувача, кешування, Sec-Fetch-* тощо | — |

## 3. Результати після виправлень (коміт 80682c0 / 9a77d9f)

Підсумок: FAIL 0 · **WARN 7** · **PASS 64**. Medium: 4 → **0**, Low: 6 → **1**.

| Ризик | ID | Знахідка | Рішення |
|---|---|---|---|
| Low | 10036 | `Server: Werkzeug/3.1.9 Python/…` | залишковий ризик RR1: dev-сервер; у production gunicorn за nginx (`server_tokens off`) |
| Info | 10031 | User Controllable HTML Attribute (`q` у value) | false positive — Jinja autoescape |
| Info | 10094, 10112, 10111 | Base64 у cookie сесії, Session Management, Authentication Request | інформаційні, очікувана поведінка |
| Info | 10049, 90005 | Non-Storable Content (`no-store` — навмисно), Sec-Fetch-* (заголовок браузера) | прийнято |

## 4. План усунення (формалізований)

| № | Знахідка | Дія | Відповідальний | Термін | Критерій перевірки |
|---|---|---|---|---|---|
| D1 | CSP/XFO/XCTO/Permissions-Policy | `after_request` із заголовками (PR #12) | Dev | ✅ виконано | ZAP 10038/10020/10021/10063 = PASS |
| D2 | Anti-CSRF | токен у формі + перевірка (PR #12) | Dev | ✅ | ZAP 10202 = PASS |
| D3 | SQL disclosure | прибрати SQL із шаблону (PR #11) | Dev | ✅ | ZAP 10099 = PASS |
| D4 | Server version | gunicorn + nginx `server_tokens off` | DevOps | наступний реліз | ZAP 10036 = PASS |
| D5 | Глибше покриття | ZAP full scan / автентифікований контекст у nightly | QA | +1 ітерація | звіт full scan без High |
