# Auto Updater Backend

Сервис зеркалирует моды из Steam Workshop в Open Workshop. Репозиторий теперь поддерживает не только одиночный запуск parser, но и kubernetes-native control plane: `MirrorInstance` CRD, оператор, web UI и раздельные workload'ы для parser и `steamcmd-runner`.

## Архитектура

На каждый экземпляр создаются два отдельных `StatefulSet`:

- `parser` — синхронизация каталога, работа с Open Workshop, HTML/API обход Steam и публикация ресурсов.
- `steamcmd-runner` — отдельный pod со своим локальным `steamcmd` и sidecar на `sing-box`, который уводит egress через TUN и upstream proxy.

Ключевые свойства:

- управление идёт через `MirrorInstance`, а не через ручные Deployment'ы;
- OW credentials, parser proxy pool и steamcmd upstream proxy хранятся в отдельных `Secret`;
- parser использует свой proxy pool на application level;
- `steamcmd-runner` использует один активный upstream proxy через TUN внутри pod;
- UI работает через Kubernetes API: создаёт и редактирует `MirrorInstance` и связанные `Secret`, показывает статусы, ресурсы и pod logs.

## Режимы запуска

Образ поддерживает четыре режима:

- `parser`
- `runner`
- `operator`
- `ui`

Режим определяется аргументом контейнера или `OW_MODE`.

Примеры:

```bash
python3 main.py parser
python3 main.py runner
python3 main.py operator
python3 main.py ui
```

## Kubernetes Install

Helm chart лежит в `charts/auto-updater`.

Сборка образа:

```bash
docker build -t ghcr.io/your-org/auto-updater-backend:latest .
```

Установка chart:

```bash
helm upgrade --install auto-updater ./charts/auto-updater \
  --namespace auto-updater \
  --create-namespace \
  --set image.repository=ghcr.io/your-org/auto-updater-backend \
  --set image.tag=latest
```

## Production Release Flow

Для k3s/buildah есть готовый release-скрипт: `scripts/release_k3s_buildah.sh`.

Что он делает:

- прогоняет `py_compile` по Python-модулям;
- собирает образ через `buildah bud --layers`;
- упаковывает образ в `docker-archive` и импортирует в `containerd`;
- обновляет `image.tag` в values-файле;
- делает `helm upgrade` и дожидается rollout.

Пример для нашего k3s-сценария:

```bash
scripts/release_k3s_buildah.sh \
  --tag prod-20260326-9 \
  --values /root/auto-updater-values.yaml \
  --kube-cli "k3s kubectl"
```

Если нужно только проверить build cache без деплоя:

```bash
scripts/release_k3s_buildah.sh \
  --tag cache-smoke \
  --values /root/auto-updater-values.yaml \
  --skip-import \
  --skip-deploy
```

`--layers` включён по умолчанию. Для образа также добавлен `.dockerignore`, чтобы не тащить в build context тесты, chart и служебные файлы.

Chart ставит:

- `MirrorInstance` CRD;
- `Deployment` оператора;
- `Deployment` web UI;
- `ServiceAccount`, `Role`, `RoleBinding`;
- опциональный ingress для UI.

## MirrorInstance

Базовый объект:

```yaml
apiVersion: auto-updater.miskler.ru/v1alpha1
kind: MirrorInstance
metadata:
  name: rimworld-main
  namespace: auto-updater
spec:
  enabled: true
  source:
    steamAppId: 294100
    owGameId: 0
    language: english
  sync:
    pollIntervalSeconds: 600
    pageSize: 50
    timeoutSeconds: 60
    httpRetries: 3
    httpRetryBackoff: 5.0
    logLevel: INFO
    steamHttpRetries: 2
    steamHttpBackoff: 2.0
    steamRequestDelay: 1.0
    steamMaxPages: 1000
    steamStartPage: 1
    steamMaxItems: 0
    steamDelay: 1.0
    maxScreenshots: 20
    uploadResourceFiles: true
    scrapePreviewImages: true
    scrapeRequiredItems: true
    publicMode: 0
    withoutAuthor: false
    syncTags: true
    pruneTags: true
    syncDependencies: true
    pruneDependencies: true
    syncResources: true
    pruneResources: true
  credentials:
    secretRef: rimworld-main-ow-credentials
  parser:
    proxyPoolSecretRef: rimworld-main-parser-proxies
  steamcmd:
    proxy:
      type: socks5
      secretRef: rimworld-main-steamcmd-proxy
  storage:
    parser:
      size: 20Gi
      storageClassName: local-path
    runner:
      size: 10Gi
      storageClassName: local-path
```

Связанные секреты:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: rimworld-main-ow-credentials
  namespace: auto-updater
type: Opaque
stringData:
  login: your-login
  password: your-password
---
apiVersion: v1
kind: Secret
metadata:
  name: rimworld-main-parser-proxies
  namespace: auto-updater
type: Opaque
stringData:
  proxyPool: |
    socks5://user:pass@host-1:3001
    http://user:pass@host-2:3000
---
apiVersion: v1
kind: Secret
metadata:
  name: rimworld-main-steamcmd-proxy
  namespace: auto-updater
type: Opaque
stringData:
  proxyUrl: socks5://user:pass@host:3001
```

## Web UI

UI поднимается в режиме `ui` и работает прямо с Kubernetes API.

Что умеет:

- создавать и редактировать `MirrorInstance`;
- управлять связанными `Secret`;
- `pause` / `resume`;
- `Sync now` через parser admin endpoint;
- показывать `phase`, `conditions`, `lastSync*`, `lastError`;
- открывать связанные ресурсы;
- читать `parser`, `runner` и `tun-proxy` pod logs без отдельной БД.

## Parser / Runner API

Внутренние HTTP интерфейсы:

- parser:
  - `GET /healthz`
  - `GET /api/v1/status`
  - `POST /api/v1/sync`
- runner:
  - `GET /healthz`
  - `POST /api/v1/archive`

`POST /api/v1/archive` принимает JSON:

```json
{"appId": 294100, "workshopId": 1234567890}
```

Успешный ответ — ZIP stream. Ошибка — JSON:

```json
{
  "reason": "steamcmd exit code 8",
  "retryable": true,
  "diagnostics": "..."
}
```

## Локальный / Legacy запуск

Старый single-process сценарий сохранён. Если вы запускаете только parser, используются те же env-переменные:

- `OW_LOGIN`
- `OW_PASSWORD`
- `OW_STEAM_APP_ID` или `STEAM_APP_ID`

Дополнительные env:

- `OW_STEAMCMD_RUNNER_URL` — вынести `steamcmd` в отдельный runner service;
- `OW_ADMIN_HOST`, `OW_ADMIN_PORT` — поднять parser admin HTTP endpoint;
- `OW_INSTANCE_NAME`, `OW_INSTANCE_NAMESPACE` — писать runtime status обратно в `MirrorInstance`.

Пример локального однократного запуска:

```bash
docker run --rm \
  -e OW_LOGIN=your_login \
  -e OW_PASSWORD=your_password \
  -e OW_STEAM_APP_ID=294100 \
  -e OW_RUN_ONCE=true \
  -v /path/to/runtime:/data \
  ghcr.io/your-org/auto-updater-backend:latest parser
```

## Переменные окружения Parser

Обязательные:

- `OW_LOGIN`
- `OW_PASSWORD`
- `OW_STEAM_APP_ID` или `STEAM_APP_ID`

Основные опциональные:

- `OW_GAME_ID`
- `OW_API_BASE`
- `OW_MIRROR_DIR`
- `STEAM_ROOT`
- `OW_PAGE_SIZE`
- `OW_POLL_INTERVAL`
- `OW_HTTP_TIMEOUT`
- `OW_HTTP_RETRIES`
- `OW_HTTP_RETRY_BACKOFF`
- `OW_RUN_ONCE`
- `OW_LOG_LEVEL`
- `OW_LOG_STEAM_REQUESTS`
- `OW_STEAM_HTTP_RETRIES`
- `OW_STEAM_HTTP_BACKOFF`
- `OW_STEAM_REQUEST_DELAY`
- `OW_STEAM_PROXY_POOL`
- `OW_STEAM_PROXY_SCOPE`
- `OW_STEAM_MAX_PAGES`
- `OW_STEAM_START_PAGE`
- `OW_STEAM_MAX_ITEMS`
- `OW_STEAM_DELAY`
- `OW_MAX_SCREENSHOTS`
- `STEAM_LANGUAGE`
- `STEAMCMD_PATH`
- `OW_RESOURCE_UPLOAD_FILES`
- `OW_SCRAPE_PREVIEW_IMAGES`
- `OW_SCRAPE_REQUIRED_ITEMS`
- `OW_FORCE_REQUIRED_ITEM_ID`
- `OW_MOD_PUBLIC`
- `OW_WITHOUT_AUTHOR`
- `OW_SYNC_TAGS`
- `OW_PRUNE_TAGS`
- `OW_SYNC_DEPENDENCIES`
- `OW_PRUNE_DEPENDENCIES`
- `OW_SYNC_RESOURCES`
- `OW_PRUNE_RESOURCES`

## Прокси

Parser proxy pool поддерживает:

- `http://`
- `https://`
- `socks5://`
- `socks5h://`

`steamcmd-runner` принимает один upstream proxy URL и валидирует его тип относительно `spec.steamcmd.proxy.type`.

## Проверка

Быстрые проверки:

```bash
python3 -m compileall .
python3 -m unittest discover -s tests -v
```
