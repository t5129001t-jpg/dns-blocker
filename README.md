# 🛡️ Local DNS Blocker

Лёгкий локальный DNS-блокировщик рекламы и трекеров с веб-дашбордом. Блокирует более 80 000 доменов из списка StevenBlack.

## ✨ Возможности

- 🔒 Блокировка рекламы, аналитики и fingerprinting-доменов
- 📊 Веб-дашборд со статистикой в реальном времени
- 📈 Графики активности по часам
- ➕ Добавление доменов в чёрный список через интерфейс
- 📝 Логирование всех запросов в SQLite
- ⚡ Асинхронная работа (FastAPI + asyncio)

## 🚀 Быстрый старт

### Требования
- Python 3.10+
- macOS / Linux

### Установка

```bash
git clone https://github.com/t5129001t-jpg/dns-blocker.git
cd dns-blocker

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Загружаем списки блокировки
curl -L "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" -o lists/blocklist.txt

# Запускаем сервер
python main.py
