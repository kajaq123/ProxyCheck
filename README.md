### Format pliku wejściowego
Program akceptuje proxy w jednej z form:
- `IP:PORT`
- `IP:PORT:USER:PASS`
- `protokół://użytkownik:hasło@IP:PORT`

### Lista flag

| Flaga (Krótka) | Flaga (Długa) | Opis | Domyślnie |
| :--- | :--- | :--- | :--- |
| `-i` | `--input` | Plik wejściowy z listą proxy | `data.csv` |
| `-o` | `--output` | Plik wyjściowy (zapisuje tylko działające) | `proxy_details.csv` |
| `-t` | `--threads` | Liczba jednoczesnych wątków | `500` |
| `-p` | `--protocol`| Rodzaj proxy: `socks5`, `http`, `https` | `socks5` |
| N/A | `--target` | Adres URL do testowania proxy | `https://ip.decodo.com/json` |
| `-h` | `--help` | Wyświetla pomoc | `false` |

## Instrukcja dla Linux / Bash

Wymagane zainstalowane środowisko Go.

### 1. Pobieranie zależności
Ten projekt używa zewnętrznej biblioteki do obsługi SOCKS5. Przed kompilacją musisz ją pobrać.

Jeśli nie masz zainicjowanego modułu:
```bash
go mod init proxyCheck
```

Pobierz wymagany pakiet:
```bash
go get golang.org/x/net/proxy
```

### 2. Kompilacja
Kompilacja do pliku wykonywalnego `proxyCheck`:

```bash
go build -o proxyCheck proxyCheck.go
```

### 3. Użycie (Bash)
Nadaj uprawnienia wykonywalne i uruchom:

```bash
chmod +x proxyCheck
./proxyCheck --help
```

Przykłady:
```bash
# SOCKS5 (domyślnie)
./proxyCheck -i socks5.txt

# HTTP
./proxyCheck -i http.txt -p http

# HTTPS z zapisem do pliku
./proxyCheck -i https.txt -p https -o alive.txt
```
