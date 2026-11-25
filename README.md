# NetGuard — Программный фаервол на C# (ASP.NET Core)

Программный межсетевой экран с разбором IPv4-заголовков (`TCP`, `UDP`, `ICMP`), приоритетными ACL-правилами, stateful-инспекцией соединений, защитой от `SYN-flood` / `Ping-flood`, горячей перезагрузкой конфигурации `rules.json` и веб-интерфейсом управления.

## Возможности

- **Перехват пакетов**: выбор сетевого интерфейса, Live Raw Socket (`IOControlCode.ReceiveAll` при запуске от Администратора) и встроенный генератор сырых IPv4-пакетов для тестирования и демонстрации без Npcap.
- **Анализ заголовков**: бинарный парсер `PacketParser` (IPv4 IHL, протокол, src/dst IP, TCP-порты и флаги `SYN/ACK/FIN/RST`, UDP-порты, ICMP Type/Code).
- **Фильтрация (ACL)**: правила с приоритетами (`Allow`/`Deny`), поддержка CIDR-подсетей (`10.99.0.0/16`), диапазонов портов (`8000-8080`), wildcard `*` и настраиваемой политики по умолчанию.
- **Продвинутые функции**:
  - Stateful-инспекция установленных TCP-сессий.
  - Защита от `SYN-flood` и `Ping-flood` с ограничением частоты запросов (rate limiting).
  - Горячая перезагрузка правил (`FileSystemWatcher` + `/api/rules/reload`).
  - Логирование событий в файл `firewall.log` и веб-панель статистики в реальном времени.

## Сборка, тесты и запуск

```powershell
dotnet build FirewallApp.csproj
dotnet test FirewallApp.Tests\FirewallApp.Tests.csproj
dotnet run --project FirewallApp.csproj --urls "http://localhost:5055"
```

После запуска откройте веб-интерфейс: `http://localhost:5055`.
