# 📂 Samba Web Management Panel

[![Stack](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Flask-3.0%2B-lightgrey.svg?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/SQLite-3-blue.svg?style=for-the-badge&logo=sqlite)](https://www.sqlite.org/)

Легковесная веб-панель управления пользователями Samba и разграничения прав доступа к сетевым ресурсам на основе системных групп Linux (нода). Авторизация администраторов полностью делегирована Центральному серверу авторизации (`centralized-auth`) по схеме SSO.

<img width="1372" height="676" alt="image" src="https://github.com/user-attachments/assets/3fe874f3-baaa-4e69-9b98-aabc04ed200d" />

---

## ⚡ Основные возможности

* **Матрица прав в реальном времени:** Отображение и изменение прав доступа сотрудников на общие папки в один клик: **RW** (чтение/запись), **RO** (только чтение), **—** (нет доступа). Изменения мгновенно применяются на уровне групп ОС Linux.
* **Управление пользователями Samba:** Синхронизированное создание локальных системных пользователей и учетных записей Samba (`smbpasswd`), смена паролей, блокировка и разблокировка доступа.
* **Строгая валидация и санитарная обработка:** Защита от инъекций команд и спецсимволов: строгая фильтрация логинов (буквы, цифры, `_`, `-`) и ФИО с запретом переносов строк.
* **Гибкие режимы авторизации (`AUTH_MODE`):** Поддержка как централизованной SSO-авторизации (`central`), так и автономного режима (`standalone`) с локальным администратором без привязки к `centralized-auth`.
* **Экспорт матрицы в Excel:** Выгрузка всей текущей сетки прав доступа в красивую таблицу `.xlsx` с автоматической цветовой разметкой.
* **Временные ссылки для клиентов:** Генерация уникальных временных ссылок (на 1, 3, 7, 30 дней) для демонстрации прав руководству или внешним аудиторам в режиме Read-Only.
* **Отказоустойчивый Rate Limiter и SQLite WAL:** Конкурентный ограничитель запросов на базе SQLite в режиме WAL с `busy_timeout=5000` для многопоточного Gunicorn.
* **Современный интерфейс:** Переработанный дизайн Enterprise SaaS Dark (Slate `#0b1120`, Indigo/Royal Blue `#3b82f6`).

---

## 📂 Структура проекта

```text
/opt/samba-web/
├── app.py                  # Главный исполняемый файл приложения Flask
├── samba_utils.py          # Модуль системного взаимодействия с Samba и ОС Linux
├── samba-web.service       # Файл службы systemd для автозапуска
├── .env.example            # Пример файла конфигурации окружения
├── templates/              # HTML-шаблоны веб-интерфейса
│   ├── login.html          # Форма авторизации (Standalone / Central SSO)
│   └── shared_matrix.html  # Шаблон матрицы прав для временных ссылок
└── static/                 # Статические файлы стилей и скриптов
    └── css/style.css       # Таблица стилей Enterprise SaaS Dark
```

---

## ⚙️ Конфигурация окружения (`.env`)

Создайте файл `.env` на основе шаблона `.env.example`:

| Переменная | Описание | Значение по умолчанию |
| :--- | :--- | :---: |
| `BIND_PORT` | Порт для запуска веб-панели | `5003` |
| `BIND_HOST` | Интерфейс прослушивания | `0.0.0.0` |
| `SECRET_KEY` | Секретный ключ сессий Flask этой ноды (`openssl rand -hex 16`) | *Автогенерация* |
| `AUTH_MODE` | Режим авторизации: `central` (SSO через Auth-сервер) или `standalone` (автономно) | `central` |
| `STANDALONE_ADMIN_USER` | Логин администратора в режиме `standalone` | `admin` |
| `STANDALONE_ADMIN_PASSWORD` | Пароль администратора в режиме `standalone` | `admin` |
| `CENTRAL_AUTH_URL` | Базовый URL-адрес сервера авторизации `centralized-auth` (при `AUTH_MODE=central`) | `http://host.docker.internal:5001` |
| `NODE_API_TOKEN` | Токен авторизации (должен совпадать с указанным на Auth-сервере) | *Обязательный* |
| `VERIFY_SSL` | Проверять SSL сертификат сервера авторизации (`true` / `false`) | `false` |
| `SMB_CONF_PATH` | Путь к файлу конфигурации Samba | `/etc/samba/smb.conf` |

---

## 🚀 Варианты развертывания

### Вариант 1. Запуск через Docker со стерильным Хост-Агентом (Рекомендуемый для продакшна)

Контейнер работает **полностью без привилегий хоста** (`privileged: false`, нет `pid: host`, нет `nsenter`). Взаимодействие с Samba и POSIX ACL хоста осуществляется через изолированный локальный Unix Domain Socket (`/run/samba-agent/samba-agent.sock`), обслуживаемый легковесным zero-dependency агентом на хосте.

1. **Клонирование проекта:**
   ```bash
   git clone https://github.com/Ttolyanich/samba-web.git /opt/samba-web
   cd /opt/samba-web
   ```

2. **Установка Хост-Агента на сервере (выполняется один раз):**
   ```bash
   sudo bash agent/install-agent.sh
   ```
   *Скрипт регистрирует службу `samba-agent.service` в systemd, запускает локальный сокет `/run/samba-agent/samba-agent.sock` с жёстким белым списком разрешённых команд (`pdbedit`, `smbpasswd`, `getfacl`, `smbstatus`, безопасный `kill` только для процессов `smbd`).*

3. **Настройка окружения панели:**
   ```bash
   cp .env.example .env
   nano .env # Задайте SECRET_KEY, CENTRAL_AUTH_URL и NODE_API_TOKEN
   ```

4. **Запуск изолированного контейнера:**
   ```bash
   docker compose up -d
   ```

---

### Вариант 2. Нативный запуск (через Systemd)
1. Установите зависимости:
   ```bash
   pip3 install -r requirements.txt
   ```
2. **Настройка прав и пользователя:**
   Создайте системного пользователя `samba-web` (если он еще не создан) и сделайте его владельцем папки проекта, чтобы он мог записывать локальную базу данных SQLite:
   ```bash
   sudo useradd -r -s /bin/false samba-web || true
   sudo chown -R samba-web:samba-web /opt/samba-web
   ```

   Настройте права `sudo` в файле `/etc/sudoers.d/samba-web` для пользователя `samba-web`:
   ```text
   samba-web ALL=(ALL) NOPASSWD: /usr/bin/pdbedit, /usr/sbin/useradd, /usr/sbin/usermod, /usr/bin/passwd, /usr/bin/smbpasswd, /usr/bin/gpasswd, /usr/bin/getfacl, /usr/bin/find, /usr/bin/smbstatus, /usr/bin/kill
   ```

3. **Настройте службу:**
   ```bash
   sudo cp samba-web.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now samba-web
   ```

