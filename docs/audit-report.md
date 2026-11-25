# Підсумковий аудит безпеки

Дата: 25.11.2026 · Аудитор: Кондратюк Т.С. (гр. 22340) · Об'єкт: `pr12-sdlc-security` (Flask 3.1.3, SQLite, Docker)
Джерела доказів: CI-артефакти `sast-reports_*`, `zap-report_*`, GitHub Code scanning, Issues #1–#10, PR #11, PR #12, `reports/pytm/tm.json`.

## 1. Виконання початкових вимог

| ID | Вимога | Стан | Доказ |
|----|--------|------|-------|
| AUTH-1 | `/profile` тільки для автентифікованих | ✅ Виконано | без сесії → 302 `/login` |
| AUTH-2 | Блокування після 5 спроб на 15 хв (username + IP) | ⚠️ Частково | реалізовано per-username (429), прив'язки до IP немає |
| AUTH-3 | Однакове повідомлення про помилку входу | ✅ Виконано | «Invalid credentials» в обох випадках |
| AUTH-4 | Регенерація сесії, `/logout` | ⚠️ Частково | `session.clear()` перед входом є, маршруту `/logout` немає |
| STOR-1 | Стійкий сольований хеш паролів | ✅ Виконано | scrypt (`werkzeug.security`), PR #12 |
| INP-1 | Параметризовані SQL-запити | ✅ Виконано | Bandit B608 = 0, Semgrep tainted-sql = 0 (PR #11) |
| INP-2 | Екранування виводу | ✅ Виконано | `escape()` + Jinja2 autoescape, ZAP XSS = 0 |
| INP-3 | Обмеження довжини параметрів ≤ 200 | ⚠️ Частково | параметри обрізаються до 100 символів (у межах ліміту), але відповідь 400 не повертається |
| CSRF-1 | CSRF-токен у формах | ✅ Виконано | POST без токена → 400 (PR #12) |
| SESS-1 | Прапорці cookie | ✅ Виконано | HttpOnly, SameSite=Lax; Secure — через змінну оточення |
| HDR-1 | Заголовки безпеки | ✅ Виконано | CSP, XFO, XCTO, Referrer-Policy; ZAP Medium 4 → 0 |
| LOG-1 | Аудитні події входу (JSON) | ⚠️ Частково | події пишуться в stdout у текстовому форматі, не JSON |
| ERR-1 | Debug вимкнено | ✅ Виконано | Bandit B201 = 0 (PR #11) |
| CONF-1 | Секрети лише в оточенні | ✅ Виконано | без `SECRET_KEY` → RuntimeError; ключ прибрано з Dockerfile/compose (9a77d9f) |
| DEP-1 | Залежності без вразливостей | ✅ Виконано | pip-audit = 0 (flask 3.1.3) |
| NFR-3 | Злиття тільки через PR з гейтом | ✅ Виконано | branch protection, check `semgrep-bandit-audit` |
| NFR-8 | Контейнер від непривілейованого користувача | ✅ Виконано | `whoami` = appuser |

Разом: **13 із 17 виконано повністю, 4 частково** (AUTH-2, AUTH-4, INP-3, LOG-1 — включені в план REC-6…REC-8).

## 2. Перегляд змін у коді

| Зміна | Комміт / PR | Що зроблено |
|-------|-------------|-------------|
| SQLi, XSS, debug, розкриття SQL | PR #11 (bbb6a57, e17e2ac) | параметризовані запити, `escape()`, `debug=False`, загальні тексти помилок |
| Хешування, lockout, секрет, залежності, CSRF, заголовки, аудит-лог | PR #12 (80682c0) | scrypt, блокування 5/15 хв, `SECRET_KEY` з env, flask 3.1.3, CSRF-токен, `after_request` із заголовками |
| Конфігурація контейнера | 9a77d9f | секрет прибрано з Dockerfile/compose, `USER appuser` |
| Модель загроз як код | 48566f4, cda7abd | OWASP pytm 1.4.1, DFD, 125 знахідок у `tm.json` |

Кожна зміна з PR пройшла гейт SAST (Semgrep + Bandit + pip-audit) і DAST (ZAP baseline) у CI.

## 3. Закриті вразливості

| Ризик | Вразливість | Severity (CVSS) | Issue | Закрито в | Перевірка |
|-------|-------------|-----------------|-------|-----------|-----------|
| R1 | SQL injection у `/search` (CWE-89) | Critical (9.8) | #2 | PR #11 | Bandit B608 / Semgrep = 0 |
| R2 | Reflected XSS у `/echo` (CWE-79) | High (6.1) | #3 | PR #11 | Semgrep = 0, ZAP |
| R3 | Паролі у відкритому вигляді, немає lockout (CWE-256/307) | Critical (8.1) | #5 | PR #12 | scrypt у БД, 6-та спроба → 429 |
| R4 | Вразлива залежність flask 3.0.3 | High (7.5) | #7 | PR #12 | pip-audit = 0 |
| R5 | Werkzeug debugger, `debug=True` (CWE-94/489) | Critical (9.8) | #4 | PR #11 | Bandit B201 = 0 |
| R6 | Захардкоджений `SECRET_KEY` (CWE-798) | High (7.4) | #6 | PR #12, 9a77d9f | RuntimeError без ключа |
| R7 | Немає CSRF, прапорців cookie, заголовків (CWE-352/693) | Medium (5.4) | #8, #9 | PR #12 | ZAP Medium = 0 |
| R8 | Немає аудиту входів (CWE-778) | Medium (4.3) | — | PR #12 | події `login_success/failed/locked`, `csrf_rejected` |
| R9 | Показ тексту SQL на сторінці (CWE-209) | Medium (5.3) | #10 | PR #11 | ZAP 10099 = PASS |
| R10 | Bind на 0.0.0.0 у dev (CWE-1327) | Low (3.1) | — | PR #11 | host з env, 127.0.0.1 |

Підсумок: Code scanning — 19 fixed, 1 dismissed (false positive `django-no-csrf-token`), 0 open. ZAP: FAIL 0, WARN 13 → 7, PASS 58 → 64.
Залишковий ризик **RR1** (Low): заголовок `Server: Werkzeug/x.y` розкриває версію — прийнято до переходу на gunicorn (REC-2), Issue #1 відкрите.

## 4. Ролі та відповідальність (RACI)

| Активність | Owner | Security Champion | Dev | QA | DevOps |
|------------|-------|-------------------|-----|----|--------|
| Вимоги безпеки | A | R | C | C | I |
| Модель загроз | A | R | C | I | C |
| Написання коду / виправлення | I | C | R | I | I |
| Code review PR | A | R | I | I | I |
| SAST/SCA у CI | I | A | I | I | R |
| DAST (ZAP) | I | A | I | R | C |
| Тріаж і false positive | I | R/A | C | C | I |
| Злиття в `main` | A | R | I | I | I |
| Секрети, branch protection | A | C | I | I | R |

**Розподіл обов'язків (segregation of duties):** автор PR не може самостійно обійти гейт — злиття в `main` можливе лише через PR з успішним check `semgrep-bandit-audit`; рішення про dismiss/false positive приймає Security Champion, а не автор коду; секрети керуються DevOps через GitHub Secrets і не доступні в коді; файл `CODEOWNERS` призначає відповідального рецензента за критичні шляхи (`src/`, `.github/workflows/`, `Dockerfile`).
**Обмеження:** у навчальному проєкті всі ролі виконує одна особа, тому кількість обов'язкових схвалень = 0. У реальній команді: ≥ 1 approval від CODEOWNER, заборона self-approve, «Require review from Code Owners».

## 5. Рекомендації та план усунення

| ID | Рекомендація | Пріоритет | Відповідальний | Строк |
|----|--------------|-----------|----------------|-------|
| REC-1 | TLS на reverse proxy, HSTS, `SESSION_COOKIE_SECURE=1` | High | DevOps | 3 дні |
| REC-2 | Production WSGI (gunicorn) замість Werkzeug — закриває RR1 | Medium | DevOps | 14 днів |
| REC-3 | Секрети у Vault / GitHub Environments з ротацією | Medium | DevOps | 14 днів |
| REC-4 | Додати CodeQL і сканування образу (Trivy) та IaC (Checkov) у CI | Medium | Security Champion | 14 днів |
| REC-5 | ZAP full/API scan з автентифікацією за розкладом | Medium | QA | 14 днів |
| REC-6 | Lockout за username + IP, rate limiting (Flask-Limiter) | Medium | Dev | 14 днів |
| REC-7 | Маршрут `/logout`, 400 для задовгих параметрів | Low | Dev | наступний спринт |
| REC-8 | Структуровані JSON-логи, централізація (SIEM) | Low | DevOps | наступний спринт |
| REC-9 | Обов'язковий review ≥ 1 CODEOWNER, підписані коміти | Low | Owner | наступний спринт |
| REC-10 | Шифрування БД at rest (зашифрований том / SQLCipher) — залишковий ризик pytm DR01 | Medium | DevOps | 14 днів |

## 6. Висновок аудиту

Усі 10 ризиків початкового реєстру (3 Critical, 3 High, 3 Medium, 1 Low) закриті та підтверджені повторними SAST/DAST-скануваннями. Гейт безпеки блокує злиття при High/Critical. Залишається один прийнятий Low-ризик (RR1) і 4 частково виконані вимоги, для яких є план REC-1…REC-10 зі строками згідно з SLA (NFR-4).
