# АРМ пен-тестера

Локальный учебный стенд для мониторинга устойчивости персонала к фишингу.
Клонирование, разведка и рассылка работают с любыми http/https URL; SMTP/IMAP —
с любыми хостами. Lookalike-механизмы не используются.

## Возможности

- Dashboard, campaigns, recon, contacts, landings, mail templates, settings, tracking.
- Защищённая панель с первой настройкой учётной записи; пароль хранится как PBKDF2-хеш.
- SMTP-подключение и тест, затем статус отправки для каждого получателя.
- IMAP-проверка расположения письма: `INBOX`, `JUNK` или `not_found`.
- Пароли SMTP/IMAP вводятся только для операции и не сохраняются.
- PBKDF2-SHA256-хеш учебных тестовых паролей и метаданные: открытый пароль не сохраняется.
- CSV-отчёт кампании.
- CSV- и минимальный PDF-отчёт кампании.
- Клонирование и архивирование выполняются библиотекой `website-downloader`
  (MIT, PyPI): страницы и ассеты сохраняются в каталог зеркала, внутренние ссылки
  переписываются на относительные — переходы внутри копии не уходят на оригинал.
- Для SPA доступен режим JS-рендера через Playwright/Chromium (extra `[render]`),
  лимиты глубины/страниц/размера/таймаута. Chromium устанавливается командой
  `.venv\Scripts\python -m playwright install chromium`.
- Разведка запускает реальный upstream CLI `atesahmet0/email-crawler`:
  `node.exe dist/index.js --url <stand-url> --output <csv> --depth <n> --max-pages <n>`.
  Исходник и сборка находятся в `data/tools/email-crawler`; резульаты — `data/recon`.
- Клонирование, разведка и рассылка работают с любыми http/https URL; SMTP/IMAP — с любыми хостами.

## Внешние инструменты

| Инструмент | Назначение | Где лежит / установка | Лицензия |
|---|---|---|---|
| website-downloader (PKHarsimran) | Зеркалирование сайта: страницы + ассеты, переписывание ссылок на относительные | `pip install website-downloader` (PyPI, [github.com/PKHarsimran/website-downloader](https://github.com/PKHarsimran/website-downloader)) | MIT |
| Playwright + Chromium | JS-рендер SPA для режима «JS-рендер» (extra `[render]`) | `.venv\Scripts\python -m playwright install chromium` | Apache-2.0 |
| atesahmet0/email-crawler | Краулинг сайта и извлечение e-mail в CSV | `data/tools/email-crawler/` (сборка `dist/index.js`) | MIT |

email-crawler содержит локальный патч `src/client/http-client.ts`
(`maxRedirects: 0`, `proxy: false`) — защита от зацикливания редиректов и прокси.

## Запуск

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python run.py
```

Откройте `http://127.0.0.1:8000`. При первом входе создайте имя пользователя и пароль
панели (минимум 12 символов). Для постоянного session-secret задайте переменную
`ARM_SESSION_SECRET`.

Запуск на другом свободном порту:

```powershell
.\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8765
```

## Настройка учебного SMTP/IMAP

В разделе **Настройки** укажите хосты SMTP-сервера атакующего и IMAP-сервера жертвы.
Пароли в форму вводятся отдельно для теста и не сохраняются в SQLite. Тест IMAP
требует доступный IMAP-сервер.

## Тесты

```powershell
.\.venv\Scripts\python -m pip install pytest httpx
.\.venv\Scripts\python -m pytest -q
```

Тесты используют заглушки `smtplib.SMTP` и `imaplib.IMAP4`, реального почтового трафика нет.

## Запуск в Docker

Для запуска нужны Docker и Docker Compose. Собранный образ содержит Python/FastAPI,
Node.js и Chromium для режима JS-рендеринга. Зависимости `website-downloader` и
Playwright устанавливаются из `requirements.txt`.

```powershell
docker compose build
docker compose up --build -d
```

Откройте `http://127.0.0.1:8000`. Порт приложения внутри и снаружи контейнера — `8000`.

Для постоянного ключа сессий задайте переменную перед запуском:

```powershell
$env:ARM_SESSION_SECRET = "<длинный случайный секрет>"
docker compose up --build -d
```

Либо создайте файл `.env` в корне проекта:

```dotenv
ARM_SESSION_SECRET=<длинный случайный секрет>
```

После запуска состояние сохраняется в Docker volume
`phishpanel_phishpanel-data`. Он содержит SQLite-базу `data/app.db`, результаты
разведки `data/recon`, зеркала `data/clones` и архивы `data/archives`.

```powershell
docker volume inspect phishpanel_phishpanel-data
docker compose logs -f phishpanel
```

Остановка и обновление:

```powershell
docker compose stop
docker compose start

# Пересборка и запуск после обновления файлов проекта
docker compose up --build -d

# Полная остановка с удалением контейнера и сети
docker compose down
```

Команда `docker compose down` не удаляет named volume, поэтому база и сгенерированные
данные сохраняются. Для полного удаления данных используйте
`docker compose down -v` только если это намеренное и необратимое действие.
