# Production Release Pipeline

Этот документ описывает фактический пайплайн, которым обновления выкатывались на production-сервер для `auto-updater-backend`.

Секреты и чувствительные данные в примерах замазаны:

- `<REDACTED_SERVER_IP>`
- `<REDACTED_DOMAIN>`
- `<REDACTED_UI_USERNAME>`
- `<REDACTED_UI_PASSWORD>`
- `<REDACTED_BASIC_AUTH>`
- `<REDACTED_K8S_TOKEN>`
- `<REDACTED_OW_LOGIN>`
- `<REDACTED_OW_PASSWORD>`
- `<REDACTED_PROXY_URL>`

## 1. Что есть на production

На production уже подготовлены:

- single-node `k3s`
- namespace `auto-updater`
- Helm release `auto-updater`
- локальный checkout репозитория на сервере: `/root/auto-updater-backend`
- values-файл окружения: `/root/auto-updater-values.yaml`
- ingress на UI
- локальный container runtime `containerd` от `k3s`

Важная особенность пайплайна: образ не обязан пушиться во внешний registry. Он собирается прямо на сервере и импортируется в локальный `containerd`.

## 2. Общая схема релиза

Пайплайн выглядит так:

1. Изменения вносятся в репозиторий.
2. Код на сервере обновляется до нужного состояния.
3. На сервере запускается release-скрипт `scripts/release_k3s_buildah.sh`.
4. Скрипт проверяет Python-код.
5. Скрипт собирает Docker-образ через `buildah bud --layers`.
6. Собранный образ экспортируется в `docker-archive`.
7. Архив импортируется в `containerd` k3s через `ctr`.
8. В `/root/auto-updater-values.yaml` обновляется `image.tag`.
9. Явно применяется `MirrorInstance` CRD через `kubectl apply`, потому что Helm не обновляет CRD из каталога `crds/` автоматически.
10. Выполняется `helm upgrade`.
11. Скрипт ждёт rollout `operator` и `ui`.
12. Затем скрипт ждёт rollout managed `StatefulSet` для parser/runner инстансов.
13. После rollout выполняется миграция существующих `MirrorInstance` в канонический `parser.*`-формат.
14. После этого проверяются pod'ы, statefulset'ы и UI.

## 3. Подготовка изменений

Локально работа обычно идёт в git-репозитории:

```bash
cd /home/admin1/Documents/GitHub/auto-updater-backend
```

После завершения изменений нужно, чтобы рабочее дерево на сервере в `/root/auto-updater-backend` содержало ту версию кода, которую нужно выкатывать.

Если серверный каталог является git checkout, его можно обновить так:

```bash
ssh root@<REDACTED_SERVER_IP>
cd /root/auto-updater-backend
git fetch origin
git checkout <branch-or-tag>
git pull --ff-only
```

Если используется не `git pull`, а другой способ синхронизации рабочего дерева, это тоже штатный вариант. На практике релиз уже выполнялся через синхронизацию дерева на сервер и последующий локальный build/release. Важно только сохранить ту же структуру репозитория и актуальный `Dockerfile`.

## 4. Release-скрипт

Текущий основной скрипт релиза:

- [scripts/release_k3s_buildah.sh](/home/admin1/Documents/GitHub/auto-updater-backend/scripts/release_k3s_buildah.sh)

Пример запуска:

```bash
cd /root/auto-updater-backend

scripts/release_k3s_buildah.sh \
  --tag prod-20260327-1 \
  --values /root/auto-updater-values.yaml \
  --kube-cli "k3s kubectl"
```

Где:

- `--tag` это новый image tag
- `--values` это production values-файл
- `--kube-cli "k3s kubectl"` нужен, потому что кластер обслуживается через `k3s`

## 5. Что делает release-скрипт по шагам

### 5.1 Syntax check

Сначала выполняется проверка Python-кода:

```bash
python3 -m compileall \
  /root/auto-updater-backend/main.py \
  /root/auto-updater-backend/core \
  /root/auto-updater-backend/kube \
  /root/auto-updater-backend/ow \
  /root/auto-updater-backend/services \
  /root/auto-updater-backend/steam \
  /root/auto-updater-backend/sync \
  /root/auto-updater-backend/ui
```

Если на этом шаге есть ошибка, релиз останавливается до сборки образа.

### 5.2 Сборка образа

Дальше запускается `buildah`:

```bash
buildah bud --layers -t localhost/auto-updater-backend:prod-20260327-1 /root/auto-updater-backend
```

Почему используется именно `buildah --layers`:

- повторно используются слои `apt`
- повторно используются слои `pip install`
- повторно используются слои с `steamcmd`
- релизы становятся заметно быстрее при неизменных зависимостях

### 5.3 Тегирование

После сборки локальный образ получает production-имя:

```bash
buildah tag \
  localhost/auto-updater-backend:prod-20260327-1 \
  docker.io/library/auto-updater-backend:prod-20260327-1
```

Это нужно для согласованности с тем, что ожидает Helm values.

### 5.4 Экспорт образа в archive

Потом образ упаковывается в tar-архив. По умолчанию архив складывается вне репозитория, чтобы не попадать в следующий build context:

```bash
buildah push \
  docker.io/library/auto-updater-backend:prod-20260327-1 \
  docker-archive:/tmp/auto-updater-backend-prod-20260327-1.tar:docker.io/library/auto-updater-backend:prod-20260327-1
```

### 5.5 Импорт образа в k3s/containerd

Далее архив импортируется в runtime кластера:

```bash
ctr -n k8s.io images import /tmp/auto-updater-backend-prod-20260327-1.tar
```

Это ключевой шаг. Именно он делает образ доступным для pod'ов в локальном `k3s` без внешнего registry push.

### 5.6 Обновление Helm values

После этого скрипт меняет `image.tag` в production values:

```bash
python3 - /root/auto-updater-values.yaml prod-20260327-1 <<'PY'
import pathlib
import re
import sys

values_path = pathlib.Path(sys.argv[1])
tag = sys.argv[2]
text = values_path.read_text()
updated, count = re.subn(r"(?m)^(\s*tag:\s*).*$", rf"\1{tag}", text, count=1)
if count != 1:
    raise SystemExit("could not find image.tag line in values file")
values_path.write_text(updated)
PY
```

То есть production values-файл хранит текущее значение тега, и релиз обновляет его автоматически.

### 5.7 Helm upgrade

Дальше выполняется релиз в Kubernetes:

```bash
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

helm upgrade auto-updater /root/auto-updater-backend/charts/auto-updater \
  -n auto-updater \
  -f /root/auto-updater-values.yaml
```

На этом шаге Kubernetes получает новую версию `operator` и `ui`, а также актуальные значения chart'а.

### 5.8 Ожидание rollout

Скрипт сначала ждёт, пока ключевые deployment'ы станут готовы:

```bash
k3s kubectl -n auto-updater rollout status deployment/auto-updater-operator --timeout=240s
k3s kubectl -n auto-updater rollout status deployment/auto-updater-ui --timeout=240s
```

После этого он отдельно дожидается rollout управляемых `StatefulSet`, которые используют тот же application image:

```bash
for sts in $(k3s kubectl -n auto-updater get statefulset -l app.kubernetes.io/part-of=auto-updater -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'); do
  k3s kubectl -n auto-updater rollout status statefulset/"$sts" --timeout=240s
done
```

### 5.9 Финальный статус ресурсов

В конце выводится сводка:

```bash
k3s kubectl -n auto-updater get deploy,sts,pod -o wide
```

## 6. Что находится в values-файле

Production values-файл расположен на сервере:

```text
/root/auto-updater-values.yaml
```

Там находятся environment-specific параметры, например:

- `image.repository`
- `image.tag`
- ingress settings
- host/base path для UI
- настройки chart'а, специфичные для production

Секреты не должны коммититься в репозиторий. Если где-то есть чувствительные значения, в документации и примерах нужно использовать placeholders.

Пример замазанного фрагмента:

```yaml
ui:
  env:
    OW_UI_BASE_PATH: /auto-updater
    OW_UI_USERNAME: <REDACTED_UI_USERNAME>
    OW_UI_PASSWORD: <REDACTED_UI_PASSWORD>

ingress:
  enabled: true
  hosts:
    - host: <REDACTED_DOMAIN>
      paths:
        - path: /auto-updater
          pathType: Prefix
```

## 7. Что не хранится в репозитории

В репозиторий не должны попадать:

- root password сервера
- basic auth UI
- kube tokens
- Open Workshop credentials
- proxy credentials
- любые реальные bearer tokens
- production-only values с секретами

Вместо них используются:

- Kubernetes `Secret`
- values-файл на сервере
- manual input через UI
- placeholders в документации

## 8. Проверка после релиза

После успешного `helm upgrade` обычно проверяются:

### 8.1 Kubernetes ресурсы

```bash
k3s kubectl -n auto-updater get deploy,sts,pod
k3s kubectl -n auto-updater get mirrorinstances.auto-updater.miskler.ru
```

### 8.2 Логи

```bash
k3s kubectl -n auto-updater logs deploy/auto-updater-ui --tail=200
k3s kubectl -n auto-updater logs deploy/auto-updater-operator --tail=200
```

Для конкретного инстанса:

```bash
k3s kubectl -n auto-updater logs barotrauma-parser-0 --tail=200
k3s kubectl -n auto-updater logs barotrauma-steamcmd-0 -c runner --tail=200
k3s kubectl -n auto-updater logs barotrauma-steamcmd-0 -c tun-proxy --tail=200
```

### 8.3 UI

Проверяются:

- dashboard открывается
- `GET /api/instances` отвечает
- detail/logs/resources страницы работают
- `Sync now`, `Pause/Resume`, delete и edit не ломаются
- для live logs отдаются JSON-эндпоинты

Пример с замазанным auth:

```bash
curl -i \
  -u <REDACTED_BASIC_AUTH> \
  https://<REDACTED_DOMAIN>/auto-updater/api/instances
```

## 9. Быстрый build-cache smoke

Если нужно проверить только скорость сборки и кэш, но не деплоить:

```bash
cd /root/auto-updater-backend

scripts/release_k3s_buildah.sh \
  --tag cache-smoke \
  --values /root/auto-updater-values.yaml \
  --skip-import \
  --skip-deploy
```

Этот режим:

- делает syntax check
- собирает образ через `buildah --layers`
- не импортирует образ в `containerd`
- не делает `helm upgrade`

## 10. Rollback

Если после релиза что-то пошло не так:

```bash
helm history auto-updater -n auto-updater
helm rollback auto-updater <REVISION> -n auto-updater
```

Потом снова проверить rollout:

```bash
k3s kubectl -n auto-updater rollout status deployment/auto-updater-operator --timeout=240s
k3s kubectl -n auto-updater rollout status deployment/auto-updater-ui --timeout=240s
```

## 11. Краткая памятка

Минимальный боевой сценарий:

```bash
ssh root@<REDACTED_SERVER_IP>
cd /root/auto-updater-backend
git fetch origin
git checkout <branch-or-tag>
git pull --ff-only

scripts/release_k3s_buildah.sh \
  --tag prod-YYYYMMDD-N \
  --values /root/auto-updater-values.yaml \
  --kube-cli "k3s kubectl"

k3s kubectl -n auto-updater get deploy,sts,pod -o wide
```

Если нужен максимально короткий ответ на вопрос "как обновления попадали на сервер?":

- код приводился к нужному состоянию в checkout на сервере
- на сервере собирался новый образ через `buildah --layers`
- образ импортировался в `k3s/containerd`
- Helm обновлял release на новый `image.tag`
- rollout проверялся через `k3s kubectl`
