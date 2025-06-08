## Инструкция по установке

Программа совместима с дистрибутивом Anaconda.

Для корректной работы необходимо устанавливать зависимости через pip, а не через conda.

```shell
python -m pip install -r requirements.txt
```

## Запуск программы

Запускать программу следует от имени администратора. 
Брандмауэр не должен запрещать открывать порты и биндить на них сокеты.

Для запуска достаточно запустить файл `main.py`

```shell
python main.py
```

## Структура проекта
```
deanon_python_hse/
├── app/
│   ├── api/
│   │   └── routers/
│   │       ├── analyze.py
│   │       ├── analyze_quick.py
│   │       ├── dnsleak.py
│   │       ├── root.py
│   │       └── __init__.py
│   ├── core/
│   │   └── config.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── analysis.py
│   │   ├── anonymization.py
│   │   ├── dns_info.py
│   │   ├── ip_info.py
│   │   ├── os_info.py
│   │   ├── port_scan_info.py
│   │   ├── security.py
│   │   └── tunnel_ping.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── anonymization_service.py
│   │   ├── dns_service.py
│   │   ├── ip_service.py
│   │   ├── os_service.py
│   │   ├── port_scan_service.py
│   │   ├── security_service.py
│   │   └── tunnel_service.py
├── static/
│   ├── css/
│   │   └── analyze.css
│   └── js/
│       └── analyze.js
├── templates/
│   └── analyze.html
├── utils/
│   ├── __init__.py
│   ├── bst_ip.py
│   ├── cache.py
│   ├── dns_client.py
│   ├── http_client.py
│   ├── ip_database.txt
│   ├── ip_parser.py
│   ├── tor_exit_nodes.py
│   └── tor_exits.txt
├── __init__.py
├── dependencies.py
├── exceptions.py
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
```
