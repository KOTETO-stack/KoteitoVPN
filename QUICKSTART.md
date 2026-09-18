# QUICKSTART — запуск за 5 минут

1. Создай публичный репозиторий на GitHub.
2. Залей файлы в него ровно по тем путям, что указаны в названии каждого файла.
3. Settings → Actions → General → Workflow permissions →
   **Read and write permissions** → Save.
4. (Необязательно) Settings → Secrets and variables → Actions → New repository secret:
   - `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` — для уведомлений при падении.
5. Вкладка **Actions** → `Collect and Test VPN Sources` → **Run workflow** →
   подожди 1-3 минуты → появится `output/raw_servers.txt`.
6. Сразу после — запусти `Build Final Subscription` тем же способом →
   появится `output/subscription.txt`.
7. Ссылка для Karing/Hiddyfi:
