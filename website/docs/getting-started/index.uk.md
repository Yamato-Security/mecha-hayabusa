# Використання

## Як запустити（HTTP）

```bash
uv sync
uv run server.py --transport http --port 9999
```

Кінцева точка:

```text
http://127.0.0.1:9999/mcp
```

## Як додати до Claude

```bash
claude mcp add --transport http hayabusa http://127.0.0.1:9999/mcp
```

Підтвердження:

```bash
claude mcp list
```

## Приклад запиту:

### Використання навички investigate
```
Use Mecha Hayabusa to read hayabusa-results.csv and build an intrusion timeline and report.
```

<img width="1073" height="895" alt="Image" src="https://github.com/user-attachments/assets/8c972743-9f22-4278-a468-bd97376f1329" />

Результати

<img width="1073" height="795" alt="Image" src="https://github.com/user-attachments/assets/4077c74f-fc85-4d07-9597-370a1e20582e" />

Буде згенеровано звіт у форматі HTML. Приклад дивіться в папці "samples".

<img width="1073" height="743" alt="Image" src="https://github.com/user-attachments/assets/2c5414f7-fc02-4db7-b85b-b62f4a03b9a4" />

<img width="1073" height="992" alt="Image" src="https://github.com/user-attachments/assets/4ba38a9b-1618-4c2c-86a2-7b621d205774" />

<img width="1073" height="682" alt="Image" src="https://github.com/user-attachments/assets/47919ec4-67e9-40bc-a503-26bef27cddcf" />

### Запит на додаткове розслідування та пояснення

```
What happened in ACC-09?
```

<img width="1073" height="892" alt="Image" src="https://github.com/user-attachments/assets/bac54fd4-9e7c-401a-8fda-e6160dec0409" />
