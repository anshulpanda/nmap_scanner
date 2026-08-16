# NMAP Port Scanner

Scans a host for open TCP ports, stores results in MySQL, and shows what changed
since the last scan.

Assumes MySQL is already installed and running.

## 1. Create the database

```sql
CREATE DATABASE nmap_scanner CHARACTER SET utf8mb4;
CREATE USER 'nmap_app'@'localhost' IDENTIFIED BY 'your_password_here';
GRANT ALL PRIVILEGES ON nmap_scanner.* TO 'nmap_app'@'localhost';
FLUSH PRIVILEGES;
```

Tables are created automatically on first run — no migration step needed.

## 2. Configure

```bash
cp .env.example .env
```

Edit `.env` with your MySQL credentials:

```ini
DB_HOST=localhost
DB_PORT=3306
DB_USER=nmap_app
DB_PASSWORD=your_password_here
DB_NAME=nmap_scanner
```

## 3. Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Also requires `nmap` on your `PATH` (`brew install nmap` / `apt install nmap`).

- Web UI: <http://localhost:8000>
- API docs: <http://localhost:8000/docs>

## 4. Run unit tests (optional)

```bash
pytest
```
