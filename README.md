# Auto Updater - backend

Бот зеркалирует каталог модов из Steam Workshop в Open Workshop и поддерживает их в актуальном состоянии.

Что делает:
- авторизуется по паролю и использует сессионные cookies
- находит игру по Steam App ID (или создаёт в OW, если отсутствует)
- обходит каталог Workshop и создаёт/обновляет моды в OW
- синхронизирует описание, теги, зависимости, скриншоты
- скачивает моды через `steamcmd` (анонимный режим) и публикует актуальный архив

## Переменные окружения
Обязательные:
- `OW_LOGIN` — логин пользователя
- `OW_PASSWORD` — пароль пользователя
- `OW_STEAM_APP_ID` — Steam App ID игры (или `STEAM_APP_ID`)

Опционально:
- `OW_GAME_ID` — ID игры в Open Workshop (если не задан, будет найден/создан по Steam App ID)
- `OW_API_BASE` — базовый URL API, по умолчанию `https://api.openworkshop.miskler.ru`
- `OW_MIRROR_DIR` — корень зеркала, по умолчанию `/data/mirror`
- `STEAM_ROOT` — корень данных steamcmd, по умолчанию `${OW_MIRROR_DIR}/steam`
- `OW_PAGE_SIZE` — размер страницы API, по умолчанию `50`
- `OW_POLL_INTERVAL` — интервал синхронизации в секундах, по умолчанию `600`
- `OW_HTTP_TIMEOUT` — таймаут запросов, по умолчанию `60`
- `OW_HTTP_RETRIES` — количество ретраев HTTP запросов, по умолчанию `3`
- `OW_HTTP_RETRY_BACKOFF` — базовая задержка для экспоненциального backoff, по умолчанию `1.0`
- `OW_RUN_ONCE` — выполнить одну синхронизацию и завершить (`true/false`)
- `OW_LOG_LEVEL` — уровень логирования (`INFO`, `DEBUG`), по умолчанию `INFO`
- `OW_LOG_STEAM_REQUESTS` — логировать каждый запрос к Steam (`true/false`)
- `OW_STEAM_HTTP_RETRIES` — ретраи для запросов к Steam и загрузки изображений, по умолчанию `2`
- `OW_STEAM_HTTP_BACKOFF` — базовая задержка backoff для Steam и загрузки изображений, по умолчанию `1.0`
- `OW_STEAM_REQUEST_DELAY` — минимальная задержка между запросами к Steam (сек), по умолчанию `0.0`
- `OW_STEAM_PROXY_POOL` — список прокси для Steam (через запятую или пробел), например `http://user:pass@host:port,socks5://host:1080`
- `OW_STEAM_PROXY_SCOPE` — область применения прокси: `all` (все запросы к Steam), `mod_pages` (только страницы модов), `none` (выключить прокси), по умолчанию `all`

OpenTelemetry / Uptrace:
- `UPTRACE_DSN` — DSN Uptrace. Если не задан, telemetry отключена.
- `OTEL_SERVICE_NAME` — имя сервиса в трассировке, по умолчанию `auto-updater-backend`
- `OTEL_SERVICE_VERSION` — версия сервиса (опционально)
- `OTEL_DEPLOYMENT_ENVIRONMENT` — окружение (`prod`, `staging` и т.п., опционально)
- `UPTRACE_DISABLED` — принудительно отключить экспорт (`True`)

Steam / Workshop:
- `OW_STEAM_MAX_PAGES` — максимум страниц Workshop при HTML‑обходе, по умолчанию `50` (0 = без лимита)
- `OW_STEAM_START_PAGE` — стартовая страница Workshop, по умолчанию `1`
- `OW_STEAM_MAX_ITEMS` — максимум модов в одном проходе, по умолчанию `0` (без лимита)
- `OW_STEAM_DELAY` — задержка между страницами Workshop, по умолчанию `1.0`
- `OW_MAX_SCREENSHOTS` — максимум скриншотов, по умолчанию `8`
- `STEAM_LANGUAGE` — язык Steam страниц и описаний, по умолчанию `english`
- `STEAMCMD_PATH` — путь к `steamcmd.sh`, по умолчанию `/opt/steamcmd/steamcmd.sh`

Поведение синхронизации:
- `OW_MOD_PUBLIC` — публичность мода: `0` публичный, `1` по ссылке, `2` скрытый
- `OW_WITHOUT_AUTHOR` — не указывать авторство (нужно админ‑право), по умолчанию `false`
- `OW_SYNC_TAGS` / `OW_PRUNE_TAGS` — синхронизировать/удалять теги
- `OW_SYNC_DEPENDENCIES` / `OW_PRUNE_DEPENDENCIES` — синхронизировать/удалять зависимости
- `OW_SYNC_RESOURCES` / `OW_PRUNE_RESOURCES` — синхронизировать/удалять ресурсы (скриншоты)
- `OW_RESOURCE_UPLOAD_FILES` — загружать скриншоты файлом вместо URL, по умолчанию `true`
- `OW_SCRAPE_PREVIEW_IMAGES` — пытаться вытянуть дополнительные скриншоты со страницы Steam, по умолчанию `true`
- `OW_SCRAPE_REQUIRED_ITEMS` — вытягивать зависимости из HTML, по умолчанию `true`

Структура зеркала по умолчанию:
- `OW_MIRROR_DIR/steam/steamapps/workshop/content/<app_id>/<workshop_id>/...` — Steam‑моды
- `OW_MIRROR_DIR/steam_archives/<workshop_id>.zip` — архивы для публикации в OW
- `OW_MIRROR_DIR/resources/<workshop_id>/...` — кеш загруженных изображений

## Установка steamcmd (Ubuntu)
Если запускаете бота не в Docker, `steamcmd` нужно установить отдельно и указать `STEAMCMD_PATH`.

Установка в домашнюю директорию пользователя:
```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install -y curl ca-certificates lib32gcc-s1 lib32stdc++6 lib32z1

mkdir -p ~/.local/steamcmd
curl -sSL https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz \
  | tar -xz -C ~/.local/steamcmd

~/.local/steamcmd/steamcmd.sh +quit
```

После установки выставьте путь:
```bash
export STEAMCMD_PATH="$HOME/.local/steamcmd/steamcmd.sh"
```

Для `systemd`/`.env`:
```bash
STEAMCMD_PATH=/home/<user>/.local/steamcmd/steamcmd.sh
```

## Docker
Сборка:
```bash
docker build -t ow-mirror .
```

Запуск:
```bash
docker run --rm \
  -e OW_LOGIN=your_login \
  -e OW_PASSWORD=your_password \
  -e OW_STEAM_APP_ID=294100 \
  -v /path/to/mirror:/data/mirror \
  ow-mirror
```

Однократная синхронизация:
```bash
docker run --rm \
  -e OW_LOGIN=your_login \
  -e OW_PASSWORD=your_password \
  -e OW_STEAM_APP_ID=294100 \
  -e OW_RUN_ONCE=true \
  -v /path/to/mirror:/data/mirror \
  ow-mirror
```
