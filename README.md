# Happ VLESS subscription mirror

Автоматическая подписка для Happ на основе:
https://github.com/kenkaral45/happ-subscription

GitHub Actions каждые 6 часов скачивает `whitelist_configs_combined.json` и извлекает до 50 уникальных VLESS-конфигураций.

## Ссылка для Happ

Обычная подписка:
`https://raw.githubusercontent.com/dfantomasd/VPN/main/vless.txt`

Base64-вариант:
`https://raw.githubusercontent.com/dfantomasd/VPN/main/vless_base64.txt`

Обновление можно запустить вручную: Actions → Update VLESS subscription → Run workflow.
