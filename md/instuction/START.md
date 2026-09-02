Запустить можно, но есть важное ограничение: rAPB для `1.19.4.775380` реализует логин, персонажей и выбор мира, однако полноценный вход в district отсутствует. Это прямо указано в [README проекта](https://github.com/ivan-draga/rAPB).

## Что понадобится

- Точный клиент APB `1.19.4.775380`. Клиент `1.13.1` с этим состоянием эмулятора несовместим без изменения opcodes и структур пакетов.
- Windows.
- Visual Studio 2015 либо более новая Visual Studio с:
    - .NET Framework Desktop Development;
    - targeting pack .NET Framework 4.5;
    - для необязательного DistrictServer — toolset `v140` и Windows SDK 8.1.
- MySQL 5.7 или совместимая MariaDB.
- Исходники [ivan-draga/rAPB](https://github.com/ivan-draga/rAPB).

DistrictServer можно пока вообще не собирать.

## 1. Подготовить базу данных

Создай пустую базу:

```sql
CREATE DATABASE rapb CHARACTER SET latin1;
```

Таблицы `accounts`, `characters`, `friends` и `ignores` сервер создаёт автоматически.

Отредактируй:

```text
Emulator\APB SERVER\Configs\Database.xml
```

Например:

```xml
<Database>
    <IP>127.0.0.1</IP>
    <Port>3306</Port>
    <Username>root</Username>
    <Password>твой_пароль</Password>
    <Database>rapb</Database>
</Database>
```

Из-за старого `MySql.Data.dll` безопаснее использовать MySQL 5.7 и обычную парольную аутентификацию. MySQL 8 с новым методом аутентификации может не подключиться.

## 2. Собрать сервер

Открой:

```text
Emulator\ApbEmu.sln
```

Проекты рассчитаны на .NET Framework 4.5. Если современная Visual Studio отказывается его устанавливать, можно перевести три C#-проекта на .NET Framework 4.8:

- `MyDB`
- `LoginServer`
- `WorldServer`

Сборка в репозитории устроена не очень аккуратно, поэтому порядок такой:

1. Собрать `MyDB`.
2. Скопировать:

```text
Emulator\MyDB\bin\Release\MyDB.dll
```

в:

```text
Emulator\APB SERVER\
```

3. Собрать `LoginServer` и `WorldServer`.
4. Скопировать получившиеся файлы из:

```text
Emulator\bin\Release\
```

в:

```text
Emulator\APB SERVER\
```

В итоговой папке должны находиться как минимум:

```text
LobbyServer.exe
LobbyServer.exe.config
WorldServer.exe
WorldServer.exe.config
MyDB.dll
FrameWork.dll
MySql.Data.dll
libmysql.dll
Configs\
```

## 3. Проверить конфигурацию

Локальная конфигурация уже почти готова:

| Назначение | Порт |
|---|---:|
| Клиент → LobbyServer | TCP 2106 |
| WorldServer → LobbyServer | TCP 2101 |
| Клиент → WorldServer | TCP 2121 |
| Создание аккаунтов | HTTP 8880 |
| DistrictServer → WorldServer | TCP 2108 |
| Клиент → District | UDP 6969, фактически не реализован |

Для полностью локального запуска оставь адреса `127.0.0.1`.

## 4. Запустить серверы

Запускать нужно именно из папки `Emulator\APB SERVER`, потому что пути к конфигам относительные.

Сначала:

```powershell
.\LobbyServer.exe
```

Затем во втором окне:

```powershell
.\WorldServer.exe
```

`LobbyServer.exe` желательно запускать от администратора: HTTP-сервер слушает `http://*:8880/`. Без прав администратора основной login server продолжит работать, но создание аккаунта через HTTP может не запуститься.

В логах должно появиться примерно:

```text
Server initialisation complete
HTTP server started
Expecting worlds to connect at 127.0.0.1:2101
```

А WorldServer должен сообщить, что зарегистрировался в LobbyServer с ID 1.

## 5. Создать аккаунт

У HTTP-обработчика необычный формат URL. Открой в браузере:

```text
http://127.0.0.1:8880/createAccount&username=test&password=test
```

Или PowerShell:

```powershell
Invoke-WebRequest "http://127.0.0.1:8880/createAccount&username=test&password=test"
```

Допустимы только латинские буквы и цифры в имени.

Пароль сохраняется в базе открытым текстом, поэтому сервер следует держать только в локальной сети.

## 6. Перенаправить клиент

В клиенте `1.19.4.775380` открой:

```text
APBGame\Config\EnvironmentGame.ini
```

Установи:

```ini
[APBGame.cHostingGC2LS]
m_sLS1=127.0.0.1:2106
```

Если такой раздел присутствует также в `APBGame\Config\APBGame.ini`, поменяй адрес и там.

Запускай клиент напрямую через:

```text
Binaries\APB.exe
```

Не через официальный launcher, иначе он может обновить клиент или восстановить конфиги.

## Важное про `dinput8.dll`

В архиве репозитория есть:

```text
Other\ClientServer + Client DLL + Files.rar
```

Не копируй находящийся там `dinput8.dll` в клиент `1.19.4`. Я проверил его исходники: hook содержит жёстко заданные адреса для `1.4.1.555239`, поэтому с `1.19.4` он потенциально приведёт к вылету или повреждению памяти.

Для `1.19.4` достаточно перенаправить `m_sLS1` на `127.0.0.1:2106`.

## Что в итоге должно работать

- подключение к LobbyServer;
- SRP-логин;
- создание и выбор персонажа;
- список миров;
- подключение к WorldServer;
- часть списков друзей, ignore и district list.

Не будет работать полноценная загрузка Social/Financial/Waterfront: DistrictServer в этом репозитории только регистрируется и принимает UDP-пакеты, но не реализует игровой UE3 replication. Точная версия клиента жёстко записана в [`LOGIN_PUZZLE.cs`](https://github.com/ivan-draga/rAPB/blob/master/Emulator/LobbyServer/TCP/Packets/LOGIN_PUZZLE.cs).