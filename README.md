# rdcli — headless RustDesk client CLI (C++)

Кроссплатформенный (Windows / macOS / Linux) CLI, говорящий напрямую по
wire-протоколу RustDesk — без GUI и официального бинарника. Подключается к
любой машине RustDesk по ID/имени/тегу и умеет: удалённую передачу файлов,
TCP-туннели и удалённые оболочки. Вывод рассчитан и на людей, и на
AI-агентов (выровненные таблицы + строгий JSON).

Порт оригинального Go-проекта на C++20.

---

## Сборка

Зависимости: CMake ≥ 3.20, компилятор C++20, protobuf (библиотека и `protoc`
из одной установки), libsodium, libzstd, libcurl.

C++-код протокола генерируется из `proto/*.proto` во время сборки, поэтому
подходит любая версия protobuf — сгенерированные файлы в репозитории не хранятся.

### Windows (рекомендуется vcpkg)

Даёт один статический `rdcli.exe` без внешних DLL.

```powershell
# 1. Установите vcpkg (https://github.com/microsoft/vcpkg), переменная
#    окружения VCPKG_INSTALLATION_ROOT должна указывать на каталог vcpkg.

# 2. Автоматическая сборка (скрипт):
.\build.ps1

# …или вручную:
vcpkg install --triplet x64-windows-static-md protobuf libsodium zstd curl
cmake -S . -B build -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static-md -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
# результат: build\Release\rdcli.exe
```

### macOS

```sh
brew install cmake protobuf libsodium zstd curl
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/rdcli version
```

### Linux (Debian/Ubuntu)

```sh
sudo apt-get install -y cmake g++ pkg-config \
  libsodium-dev libzstd-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/rdcli version
```

### Установка в PATH

```sh
# macOS / Linux
install -m 0755 build/rdcli ~/.local/bin/rdcli

# Windows — положите build\Release\rdcli.exe в каталог из %PATH%
```

---

## Настройка

### Файл конфигурации

`~/.config/rdcli/config.toml` (путь можно переопределить переменной
`RDC_CONFIG`):

```toml
server = ""              # пусто = публичные серверы rustdesk.com
key = ""                 # лицензионный ключ self-hosted сервера
access_token = ""        # токен логина (см. auth)
api_server = ""          # self-hosted Pro API (адресная книга)
api_username = ""
api_password = ""

[peers."123456789"]
password = "..."         # пароль машины
name = "home-pc"         # человекочитаемое имя

[tags]
"123456789" = ["work", "prod"]
```

Файл пишется с правами `0600` (только владелец).

### Переменные окружения

| Переменная    | Назначение                                  |
|---------------|---------------------------------------------|
| `RDC_PASSWORD`| пароль машины                               |
| `RDC_SERVER`  | rendezvous-сервер (напр. `hbbs:21116`)      |
| `RDC_KEY`     | лицензионный ключ self-hosted               |
| `RDC_TOKEN`   | токен логина (публичный сервер)             |
| `RDC_CONFIG`  | путь к файлу конфигурации                   |

### Логин (публичный сервер требует токен)

```sh
rdcli import-gui            # подтянуть токен из десктоп-приложения RustDesk
rdcli auth set <token>      # задать токен вручную
rdcli auth status           # проверить статус
rdcli auth logout           # очистить токен
```

### Запомнить пароль машины

```sh
rdcli connect home-pc -p "your-password"
rdcli disconnect home-pc
```

`connect` принимает ID, имя или тег.

---

## Использование

```sh
# список машин
rdcli devices
rdcli devices --online
rdcli devices --tag work
rdcli devices search jane --json

# теги
rdcli tag add <id> <tag>
rdcli tag rm  <id> <tag>
rdcli tag ls
rdcli tag ls <id>

# онлайн-проверка
rdcli ping <id>

# удалённый листинг каталога
rdcli -c home-pc ls C:/Users/jane

# копирование файлов (обе стороны; -r рекурсивно)
rdcli -c home-pc cp ./backup.tar.gz C:/Users/jane/Desktop/   # up
rdcli -c home-pc cp C:/log.txt ./log.txt                     # down (по умолчанию)
rdcli -c home-pc cp ./dir C:/dst -r

# удалённая команда
rdcli -c home-pc sh "ipconfig"

# интерактивная оболочка
rdcli -c home-pc sh

# TCP-туннель: RDP-переход
rdcli -c home-pc tunnel -L 3389:localhost:3389
# single-stream режим (ssh ProxyCommand-стиль, stdin/stdout)
rdcli -c home-pc tunnel --once -L 1234:localhost:22
```

### Общие флаги (для всех команд)

```
--password <pw> / -p   пароль машины (или RDC_PASSWORD / config)
--server <host:port>   rendezvous-сервер (или RDC_SERVER / config)
--key <key>            лицензионный ключ self-hosted (или RDC_KEY)
--token <tok>          токен логина (или RDC_TOKEN / config / import-gui)
-c <ref>               машина (id/имя/тег) — вместо позиционного аргумента
--relay                принудительный relay (без hole punching)
--yes                  принять незащищённое прямое IP-соединение
--json                 машинно-читаемый вывод
--timeout <s>          таймаут соединения (по умолчанию 10)
```

### Семантика `cp`

`rdcli cp [ref] <src> <dst>`: если `dst` похож на удалённый путь (начинается с
`/` или `X:`), идёт передача local→remote; иначе remote→local. Явное
направление — флагом `-d up|down` (`to-remote` / `to-local`).

### Вывод и коды возврата

- Человеческий вывод — выровненная таблица, детерминированный порядок.
- `--json` — один JSON-объект на stdout.
- Ошибки — всегда на stderr; данные — всегда на stdout.
- Коды возврата: `0` — успех, `1` — runtime/auth/сеть, `2` — ошибка
  использования.

---

## Ограничения

- Нет демонстрации экрана, буфера обмена, аудио.
- UDP NAT-тест не реализован — direct hole punching только по TCP (симметричный
  NAT может уйти в relay; relay работает всегда).
- Терминал требует версию пира ≥ 1.4.1.
- Публичный сервер требует токен логина.

## Лицензия

AGPL-3.0 — портирует детали wire-протокола из AGPL-исходников RustDesk.
