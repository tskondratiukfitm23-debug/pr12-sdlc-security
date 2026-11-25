# Модель загроз (STRIDE + DFD)

Методика: Microsoft STRIDE per element, DFD з межами довіри; інструментальна перевірка архітектури —
**OWASP pytm** (threat modeling as code). Оцінка ризику: Likelihood × Impact (1–5) та CVSS 3.1
(див. `risk-register.csv`).

## 1. Контекст і межі довіри

```
            TB1: Internet → застосунок                     TB2: застосунок → дані
 ┌──────────┐  HTTP GET/POST   ┌────────────────────┐  SQL (sqlite3)  ┌──────────────┐
 │ Browser  │ ───────────────▶ │  Flask app (:5000) │ ──────────────▶ │ SQLite DB    │
 │ (user /  │ ◀─────────────── │  /search /echo     │ ◀────────────── │ users, posts │
 │ attacker)│  HTML + cookie   │  /login /profile   │                 └──────────────┘
 └──────────┘                  └─────────┬──────────┘
                                         │ env (SECRET_KEY, DB_PATH)        TB3: CI/CD → runtime
                                         ▼
                                ┌────────────────────┐        ┌────────────────────────────┐
                                │ Config / Secrets   │ ◀───── │ GitHub Actions (SAST/DAST) │
                                └────────────────────┘        └────────────────────────────┘
```

| Елемент | Тип DFD | Категорії STRIDE |
|---------|---------|------------------|
| Browser (користувач / зловмисник) | External entity | S, R |
| Flask app | Process | S, T, R, I, D, E |
| SQLite DB | Data store | T, I, D |
| Config / Secrets | Data store | T, I |
| HTTP-запит/відповідь (TB1) | Data flow | T, I, D |
| SQL-запит (TB2) | Data flow | T, I |
| GitHub Actions | External process | S, T, E |

## 2. STRIDE-матриця

| ID | STRIDE | Елемент | Загроза | Контроль у baseline | Ризик |
|----|--------|---------|---------|---------------------|-------|
| T-S-1 | Spoofing | /login | Перебір / credential stuffing | немає | R3 |
| T-S-2 | Spoofing | cookie | Викрадення / фіксація сесії | лише підпис cookie | R7 |
| T-T-1 | Tampering | SQL flow | SQL-ін'єкція через `q` | немає | R1 |
| T-T-2 | Tampering | /login | Login CSRF | немає | R7 |
| T-T-3 | Tampering | ланцюг постачання | Вразливі залежності | немає | R4 |
| T-R-1 | Repudiation | Flask app | Немає аудиту входів | немає | R8 |
| T-I-1 | Info disclosure | /echo | Відбитий XSS | немає | R2 |
| T-I-2 | Info disclosure | DB | Паролі у відкритому вигляді | немає | R3 |
| T-I-3 | Info disclosure | /search | Показ тексту SQL-запиту | — | R9 |
| T-I-4 | Info disclosure | Config | Жорстко заданий `SECRET_KEY` → підробка сесії | env var з fallback | R6 |
| T-D-1 | DoS | /search | Довгі / важкі `LIKE`-запити | немає | R1/R9 |
| T-EoP-1 | Elevation | /profile | Доступ без автентифікації | перевірка сесії | — |
| T-EoP-2 | Elevation | Flask app | RCE через Werkzeug debugger | немає | R5 |

## 3. Сценарії атак і способи виявлення

### Сценарій 1 — SQL-ін'єкція у `/search` (R1, CWE-89)
- **Кроки:** `GET /search?q=' UNION SELECT id, username, password FROM users--` → на сторінці логіни й паролі.
- **Вплив:** розкриття таблиці `users` (у поєднанні з R3 — паролі у відкритому вигляді).
- **Виявлення:** Bandit B608, Semgrep `tainted-sql-string`; ZAP; регресійний тест; моніторинг `UNION`/`'` у логах.
- **Пом'якшення:** параметризований запит, обмеження довжини, прибрати показ SQL.

### Сценарій 2 — Відбитий XSS у `/echo` (R2, CWE-79)
- **Кроки:** жертва відкриває `/echo?msg=<script>...</script>` → JS виконується в контексті сайту.
- **Виявлення:** Semgrep `raw-html-format`, `directly-returned-format-string`; ZAP; тест екранування.
- **Пом'якшення:** `markupsafe.escape`, CSP, HttpOnly-cookie.

### Сценарій 3 — Перебір паролів (R3, CWE-307/256)
- **Кроки:** скрипт перебирає словник для `alice` на `POST /login` без обмежень.
- **Виявлення:** аудит-лог (серія `login_failed` з одного IP), тест lockout, огляд коду.
- **Пом'якшення:** scrypt-хеші, lockout 5 спроб / 15 хв, однакові повідомлення.

### Сценарій 4 — RCE через Werkzeug debugger (R5, CWE-94)
- **Кроки:** при `debug=True` помилка відкриває інтерактивну консоль Python.
- **Виявлення:** Bandit B201, Semgrep `debug-enabled`.
- **Пом'якшення:** `debug` лише зі змінної оточення, за замовчуванням вимкнено.

### Сценарій 5 — Підробка сесії через відомий `SECRET_KEY` (R6, CWE-798)
- **Кроки:** ключ `hardcoded-dev-secret` у публічному коді → підписати cookie `{'user_id': 1}` → вхід як alice.
- **Виявлення:** кастомне Semgrep-правило, GitHub secret scanning, огляд PR.
- **Пом'якшення:** обов'язковий `SECRET_KEY` з оточення / GitHub Secrets.

## 4. Інструментальний аналіз архітектури (OWASP pytm)

Модель описана кодом у `threatmodel/tm.py`; результати й висновки буде додано після запуску.

## 5. Виявлені ризики / знахідки

Заповнюється за результатами pytm, SAST та DAST.
