# Auto Updater - backend

Бот зеркалирует каталог модов из Steam Workshop в Open Workshop и поддерживает их в актуальном состоянии.

Что делает:
- авторизуется по паролю и использует сессионные cookies
- находит игру по Steam App ID (или создаёт в OW, если отсутствует)
- обходит каталог Workshop и создаёт/обновляет моды в OW
- синхронизирует описание, теги, зависимости (при наличии Steam API key), скриншоты
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
- `OW_STATE_FILE` — путь к файлу состояния, по умолчанию `${OW_MIRROR_DIR}/state.json`
- `OW_PAGE_SIZE` — размер страницы API, по умолчанию `50`
- `OW_POLL_INTERVAL` — интервал синхронизации в секундах, по умолчанию `600`
- `OW_HTTP_TIMEOUT` — таймаут запросов, по умолчанию `60`
- `OW_RUN_ONCE` — выполнить одну синхронизацию и завершить (`true/false`)

Steam / Workshop:
- `STEAM_WEB_API_KEY` — ключ Steam Web API (нужен для зависимостей и более точного списка)
- `OW_STEAM_MAX_PAGES` — максимум страниц Workshop при HTML‑обходе, по умолчанию `50` (0 = без лимита)
- `OW_STEAM_MAX_ITEMS` — максимум модов в одном проходе, по умолчанию `0` (без лимита)
- `OW_STEAM_DELAY` — задержка между страницами Workshop, по умолчанию `1.0`
- `OW_MAX_SCREENSHOTS` — максимум скриншотов, по умолчанию `8`
- `STEAM_LANGUAGE` — язык Steam страниц и описаний, по умолчанию `english`

Поведение синхронизации:
- `OW_MOD_PUBLIC` — публичность мода: `0` публичный, `1` по ссылке, `2` скрытый
- `OW_WITHOUT_AUTHOR` — не указывать авторство (нужно админ‑право), по умолчанию `true`
- `OW_SYNC_TAGS` / `OW_PRUNE_TAGS` — синхронизировать/удалять теги
- `OW_SYNC_DEPENDENCIES` / `OW_PRUNE_DEPENDENCIES` — синхронизировать/удалять зависимости
- `OW_SYNC_RESOURCES` / `OW_PRUNE_RESOURCES` — синхронизировать/удалять ресурсы (скриншоты)

Структура зеркала по умолчанию:
- `OW_MIRROR_DIR/steam/steamapps/workshop/content/<app_id>/<workshop_id>/...` — Steam‑моды
- `OW_MIRROR_DIR/steam_archives/<workshop_id>.zip` — архивы для публикации в OW

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
