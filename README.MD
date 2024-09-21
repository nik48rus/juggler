# Juggler

<img src="logo.png" alt="logo" style="width:256px;"/>

## Управление
настройка
| Переменная | Описание |
| --- | --- |
| JUGGLER_DB_PATH | Путь к базе данных |
| JUGGLER_PASSWORD | Пароль для шифрования данных |

создание ключа
```bash
./juggler set key value
```

получение значения по ключу
```bash
./juggler get key
```

## Фунции
#### CLI
- [x] Сохранение ключа
- [x] Получение значения по ключу
- [x] Удаление ключа
#### Фичи
- [x] Шифрование данных

## Сборка
```bash
go build -o juggler main.go
```
