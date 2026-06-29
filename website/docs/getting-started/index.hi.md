# उपयोग

## निष्पादन कैसे करें（HTTP）

```bash
uv sync
uv run server.py --transport http --port 9999
```

Endpoint:

```text
http://127.0.0.1:9999/mcp
```

## Claude में कैसे जोड़ें

```bash
claude mcp add --transport http hayabusa http://127.0.0.1:9999/mcp
```

पुष्टि:

```bash
claude mcp list
```

## प्रॉम्प्ट उदाहरण:

### investigate Skill का उपयोग करें
```
Use Mecha Hayabusa to read hayabusa-results.csv and build an intrusion timeline and report.
```

<img width="1073" height="895" alt="Image" src="https://github.com/user-attachments/assets/8c972743-9f22-4278-a468-bd97376f1329" />

परिणाम

<img width="1073" height="795" alt="Image" src="https://github.com/user-attachments/assets/4077c74f-fc85-4d07-9597-370a1e20582e" />

एक HTML रिपोर्ट तैयार की जाएगी। उदाहरण के लिए "samples" फ़ोल्डर देखें।

<img width="1073" height="743" alt="Image" src="https://github.com/user-attachments/assets/2c5414f7-fc02-4db7-b85b-b62f4a03b9a4" />

<img width="1073" height="992" alt="Image" src="https://github.com/user-attachments/assets/4ba38a9b-1618-4c2c-86a2-7b621d205774" />

<img width="1073" height="682" alt="Image" src="https://github.com/user-attachments/assets/47919ec4-67e9-40bc-a503-26bef27cddcf" />

### अतिरिक्त जाँच और स्पष्टीकरण माँगें

```
What happened in ACC-09?
```

<img width="1073" height="892" alt="Image" src="https://github.com/user-attachments/assets/bac54fd4-9e7c-401a-8fda-e6160dec0409" />
