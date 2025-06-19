# Simple C HTTP/HTTPS Server

This project is a basic HTTP and HTTPS server written in C, using:

- `OpenSSL` for TLS support
- `libyaml` for configuration
- `pthreads` for handling multiple connections

---

## 🔧 Build Instructions

### 1. Install dependencies

#### On Arch Linux:
```bash
sudo pacman -S gcc make openssl libyaml
````

#### On Debian/Ubuntu:

```bash
sudo apt install build-essential libssl-dev libyaml-dev
```

---

### 2. Build the server

```bash
make
```

---

### 3. Generate a self-signed certificate

```bash
make keygen
```

This creates `cert.pem` and `key.pem`.

---

### 4. Run the server

```bash
make run
```

---

## ⚙️ Configuration

Create a file named `config.yaml` in the root directory:

```yaml
port: 8080

https:
  force: true
  port: 8443
  cert: cert.pem
  key: key.pem

index_file: index.html
allow_list_content: true
```

* `https.force: true` enables HTTPS-only mode with redirect.
* `allow_list_content: true` enables directory listing.

---

## 🌐 Access

* HTTP: `http://localhost:8080`
* HTTPS: `https://localhost:8443`

---

## 🧹 Cleaning

```bash
make clean       # Remove object files and binary
make clean-all   # Also remove cert.pem and key.pem
```

---

## 🔐 Notes

* This is a development/test server. Do not use in production without review.
* Self-signed certificates will show browser warnings.
