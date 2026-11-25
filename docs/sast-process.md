# SAST: процес керування звітами і вразливостями

## 1. Інструменти та правила

| Інструмент | Що перевіряє | Набір правил |
|---|---|---|
| Semgrep OSS | код Python, шаблони Jinja | `--config auto` (реєстр Semgrep: python, flask, django, sqlalchemy) + 6 власних правил `.semgrep/rules.yml` |
| Bandit | типові помилки безпеки Python | усі плагіни (B1xx–B7xx) |
| pip-audit (SCA) | вразливі залежності `requirements.txt` | база PyPA Advisory / OSV |

Власні правила (`.semgrep/rules.yml`): `sqli-fstring`, `flask-raw-html-from-request`,
`plaintext-password-compare`, `hardcoded-secret-key-fallback`, `flask-debug-true`, `sql-shown-to-user`.

## 2. Конвеєр (`.github/workflows/sast.yml`)

1. Тригери: кожен `push`, кожен `pull_request`, ручний запуск.
2. Semgrep, Bandit, pip-audit формують JSON і SARIF.
3. SARIF завантажується у **GitHub Code scanning** (анотації в PR, історія сповіщень).
4. Усі звіти зберігаються як артефакт `sast-reports` (90 днів).
5. `scripts/sast_summary.py` пише зведену таблицю у Job Summary.
6. **Security gate** (`--gate`) падає, якщо є хоча б одна блокуюча знахідка:
   Semgrep `ERROR`, Bandit `HIGH`, будь-яка вразлива залежність. Червоний гейт блокує злиття PR
   (правило захисту гілки `main`).

## 3. Тріаж і пріоритезація

| Рівень | Критерії | SLA | Хто вирішує |
|---|---|---|---|
| Critical | RCE, SQLi, обхід автентифікації; CVSS ≥ 9.0 | 24 год | Security Champion + Owner |
| High | XSS, витік секретів, слабке зберігання паролів, вразлива залежність з High CVE; CVSS 7.0–8.9 | 3 дні | Security Champion |
| Medium | CSRF, відсутні заголовки, CVSS 4.0–6.9 | 14 днів | Dev lead |
| Low / Info | розкриття версій, інформаційні | наступний реліз | Dev |

Пріоритет = CVSS 3.1 × експлуатованість (чи досяжно з Internet) × цінність активу (`risk-register.csv`).

Рішення по кожній знахідці: **Fix** (Issue + PR) · **False positive** (Dismiss у Code scanning з коментарем) ·
**Accept risk** (лише Owner, з датою перегляду) · **Duplicate** (посилання на існуючий Issue).

## 4. Задачі у трекері (GitHub Issues)

- Заголовок: `[SAST|DAST|SCA][Severity] Опис (CWE-xxx, Rn)`.
- Мітки: `security`, `sast`/`dast`/`sca`, `severity:critical|high|medium|low`.
- Тіло: файл і рядок, правило сканера, CWE/CVSS, сценарій експлуатації, план виправлення, SLA, критерій закриття.
- Виправлення — окрема гілка `fix/...` і PR з `Closes #N`; після злиття Issue закривається автоматично,
  сповіщення Code scanning переходить у `Fixed` при наступному скануванні `main`.

## 5. Результати в проєкті

| Етап | Знахідок | Blocking | Code scanning |
|---|---|---|---|
| Baseline (b813dca) | 20 | 9 | 19 open |
| PR #11 (SQLi, XSS, debug, SQL disclosure) | 4 | 3 | — |
| PR #12 (auth, secrets, CSRF, headers, flask 3.1.3) | 1 | **0** | 19 fixed, #20 dismissed (FP) |

False positive: `python.django.security.django-no-csrf-token` у `login.html` — правило для Django,
у Flask токен формується `csrf_token()` і перевіряється в `before_request`.
