# Отчёт по reverse engineering APB Reloaded 1.13.1 (2013)
## UE3 PackageMap / NetIndex / District Server handshake

### 1. Цель работы

Цель — восстановить сетевую часть клиента **APB Reloaded 1.13.1 (2013)** настолько, чтобы собственный сервер мог корректно провести клиента через подключение к District Server и далее перейти к UE3 replication.

Исходно предполагалось, что главный блокер — неправильный **NetIndexMap / PackageMap**, то есть необходимо определить:

- точный порядок сетевых UE3-пакетов;
- GUID каждого пакета;
- Generation;
- NetObjectCount / ObjectCount;
- ObjectBase / BaseIndex;
- итоговый NetIndex каждого реплицируемого UObject.

Клиент находится здесь:

```text
E:\APBClients\APB_1.13.1(2013)
```

Проекты:

```text
Package dumper:
E:\ProgrammingProjects\C#\dumper_1.13.1\ConsoleApp1\ConsoleApp1

NetIndexBuilder:
E:\ProgrammingProjects\C#\NetIndexBuilder\NetIndexBuilder\NetIndexBuilder
```

---

# 2. Исследование UE3 package-файлов

Был написан C# dumper для чтения метаданных пакетов:

```text
.u
.upk
.apb
```

Сначала использовался `Eliot.UELib`.

Для старого пакета:

```text
EngineFonts.upk
Version = 547
LicenseeVersion = 31
```

UELib корректно распознал APB и выдал:

```text
GUID = CAA646224F6BC4EFD6C7A292C4D8D4A1
GenerationCount = 1
ExportCount = 11
Gen1:
    Exports = 11
    Names = 30
    NetObjects = 11
```

Но для:

```text
Core.u
Engine.u
EngineResources.upk
```

версия была:

```text
564 / 32
```

и UELib определял build как `Unknown`.

Даже принудительный `BuildName.APB` не исправлял всё полностью: GUID и Generation начинали читаться со смещением.

Поэтому был написан собственный raw UE3 package summary parser.

---

# 3. Восстановленный APB package header layout

UE3 signature:

```text
C1 83 2A 9E
```

то есть little-endian:

```text
0x9E2A83C1
```

Для APB были выявлены дополнительные поля.

Для LicenseeVersion >= 29:

```text
+4 bytes
```

Для LicenseeVersion >= 28:

```text
+20 bytes
```

Для APB `564/32`, после `DependsOffset`, присутствует ещё 16 байт:

```text
ImportExportGuidsOffset
ImportGuidsCount
ExportGuidsCount
ThumbnailTableOffset
```

После них расположен обычный package GUID.

Для LicenseeVersion >= 32 после `GenerationCount` также присутствует второй GUID:

```text
GUID2
```

В исследованных пакетах:

```text
GUID2 = 00000000000000000000000000000000
```

GenerationInfo читается как:

```text
ExportCount
NameCount
NetObjectCount
```

Эта структура была проверена на `EngineFonts 547/31` и дала те же значения, что UELib.

---

# 4. Проверенные package metadata

## Core

```text
Version = 564
LicenseeVersion = 32
HeaderSize = 686

GUID:
0FE825BC4970D0BCE10969A84C498AF9

GenerationCount = 1

Gen1:
ExportCount = 3
NameCount = 9
NetObjectCount = 3
```

## Engine

```text
Version = 564
LicenseeVersion = 32
HeaderSize = 688

GUID:
8CC8C3484498F5A30556718879EC40E0

GenerationCount = 1

Gen1:
ExportCount = 3
NameCount = 9
NetObjectCount = 3
```

## EngineResources

```text
Version = 564
LicenseeVersion = 32
HeaderSize = 22902

GUID:
44A17FB24FA4F77ECE54BB861C6EDB43

GenerationCount = 1

Gen1:
ExportCount = 194
NameCount = 239
NetObjectCount = 194
```

## EngineFonts

```text
Version = 547
LicenseeVersion = 31
HeaderSize = 1822

GUID:
CAA646224F6BC4EFD6C7A292C4D8D4A1

GenerationCount = 1

Gen1:
ExportCount = 11
NameCount = 30
NetObjectCount = 11
```

---

# 5. Важное открытие по `HeaderSize > FileSize`

Изначально `Core.u` и `Engine.u` выглядели подозрительно маленькими:

```text
Core.u
FileSize = 526
HeaderSize = 686

Engine.u
FileSize = 528
HeaderSize = 688
```

Была гипотеза, что это какие-то stub-пакеты.

Эта гипотеза оказалась неправильной.

Парсер был расширен чтением:

```text
EngineVersion
CookerVersion
CompressionFlags
FCompressedChunk[]
```

где chunk:

```text
UncompressedOffset
UncompressedSize
CompressedOffset
CompressedSize
```

Результаты:

```text
Core:
CompressionFlags = 0x00000002
Chunks = 2

Engine:
CompressionFlags = 0x00000002
Chunks = 2

EngineResources:
CompressionFlags = 0x00000002
Chunks = 3

EngineFonts:
CompressionFlags = 0x00000002
Chunks = 2
```

Полный scan:

```text
Total              6043
OK                 6043
HeaderPastEOF       695
  compressed        695
  uncompressed        0
Compressed total   6042
Unsupported           0
Not UE3               0
Errors                0
```

Вывод:

**Core.u и Engine.u не являются stub-файлами.**

`HeaderSize > physical FileSize` полностью объясняется UE3 package compression и виртуальными uncompressed offsets.

---

# 6. Поддержка package version 563/32

Изначально 8 пакетов версии:

```text
563 / 32
```

не поддерживались parser'ом.

Список включал, например:

```text
UIDistrict_CrimeScene_ArtProps.APB
UIDistrict_SkatePark.APB
WaterfrontDistrict_ArtProps_Block12.apb
WaterfrontDistrict_ArtProps_Block32.apb
APBMenus_Art_Medals.upk
APBMenus_Utilities.upk
Baked_UI_Scene_Vehicle_1.upk
CrimeScene_Kissaki.upk
```

Для них был применён тот же extended package summary layout, что и для `564/32`.

После этого:

```text
Total       6043
OK          6043
Unsupported    0
Errors         0
```

То есть весь комплект клиента теперь успешно читается.

---

# 7. Созданные CSV

Dumper создаёт:

```text
...\dump\packages.csv
...\dump\generations.csv
```

`packages.csv` содержит:

```text
Package
Extension
RelativePath
FileSize
Version
LicenseeVersion
HeaderSize
GUID
GUID2
GenerationCount
LatestNetObjectCount
ExportCount
NameCount
ImportCount
EngineVersion
CookerVersion
CompressionFlags
CompressedChunkCount
HasPackageCompression
HeaderPastEOF
Status
Error
```

`generations.csv`:

```text
Package
RelativePath
Generation
ExportCount
NameCount
NetObjectCount
```

---

# 8. Первоначальная проблема с retail package order

Был внешний ориентир, согласно которому начало retail PackageMap должно было выглядеть:

```text
Core (Gen 2)
Engine (Gen 2)
EngineResources (Gen 1)
EngineFonts (Gen 1)
```

Но локальные package-файлы показывали:

```text
Core GenerationCount = 1
Engine GenerationCount = 1
```

Это породило вопрос:

- другая ли это ревизия пакетов;
- или runtime PackageMap использует generation, которая не равна `Summary.Generations.Count`;
- или внешний retail dump относится к другой версии клиента.

Был специально создан `NetIndexBuilder`, который **не подставляет данные молча**, если нужной generation нет.

При:

```text
Core|2
Engine|2
EngineResources|1
EngineFonts|1
```

получено:

```text
0 Core
  Gen=2
  GENERATION_MISSING

1 Engine
  Gen=2
  GENERATION_MISSING

2 EngineResources
  Gen=1
  Count=194
  OK

3 EngineFonts
  Gen=1
  Count=11
  OK
```

Builder сознательно прекращает вычисление последующих `ObjectBase`, если предыдущий ObjectCount неизвестен.

Это было сделано, чтобы не получить тихо неверный NetIndexMap.

---

# 9. Попытка получить runtime `PACKAGEMAP`

В APB input config обнаружено:

```ini
[Engine.Console]
ConsoleKey=UNUSED
TypeKey=Quote
```

Стандартная UE3 console была отключена.

Попытки:

```text
ConsoleKey=Tilde
ConsoleKey=F10
TypeKey=F9
```

не открыли обычную UE console.

Причина частично видна в APB bindings.

Например в `[Engine.PlayerInput]`:

```ini
Bindings=(Name="F9",Command="OpenChatChannelCommands",...)
Bindings=(Name="F10",Command="OpenConsoleCommands",...)
```

а `Grave` уже используется игровым action.

F9/F10 в APB имеют собственные UI actions.

Поэтому вместо открытия console была сделана прямая bind-команда:

```ini
Bindings=(Name="F8",Command="PACKAGEMAP | ScreenShot")
```

Также для диагностики:

```ini
Bindings=(Name="F7",Command="SOCKETS | ScreenShot")
```

---

# 10. Подтверждение того, что custom binding работает

F8 действительно выполнялся.

После нажатий появились новые файлы:

```text
E:\APBClients\APB_1.13.1(2013)\Media\Screenshots\ScreenShot00001.png
...
ScreenShot00013.png
```

Следовательно:

```text
[Engine.PlayerInput] Binding
```

работает.

Однако `PACKAGEMAP` в log ничего не вывел.

Дополнительно бинарники были просканированы на строки.

В:

```text
E:\APBClients\APB_1.13.1(2013)\Binaries\APB.exe
```

найдены:

```text
PACKAGEMAP
BaseIndex
ObjectCount
LocalGeneration
RemoteGeneration
```

Следовательно, команда `PACKAGEMAP` **присутствует в APB.exe**, а не полностью вырезана.

Она просто не дала полезный dump в текущем состоянии.

---

# 11. Первый реальный District Server failure

До исправления сервера клиент доходил до UE3 handshake:

```text
HandshakeChallenge
HandshakeComplete
Challenge
Welcome
Uses
```

После `USES` клиент логировал:

```text
PackageName: Core
GUID: 00000000000000000000000000000000
FileName: None
Generation: 1
BasePkg: None
```

И сразу:

```text
APBGameEngine::PackageVerificationFailed()

Package 'Core' is not downloadable
```

Затем connection закрывался:

```text
Closing connection TcpipConnection_0
```

То есть первоначально проблема возникала **раньше NetIndex replication** — на проверке `NMT_Uses`.

---

# 12. Серверная реализация `NMT_Uses`

На сервере было:

```cpp
// NMT_Uses(7), порядок подтверждён по FPackageInfo::SerializeWire:
//   FGuid(16) | FString PackageName | FString | FString
//   | INT PackageFlags | INT Generation | FString | BYTE
// Три FString становятся FName в структуре клиента.

static const UsesEntry kPackages[] =
{
    { "Core", { 0, 0, 0, 0 }, 1 },
};
```

То есть сервер отправлял:

```text
Core GUID = zero
Generation = 1
```

Это объяснило `PackageVerificationFailed`.

---

# 13. Исправление GUID Core

Локальный package parser показал:

```text
Core package GUID:
0FE825BC4970D0BCE10969A84C498AF9
```

На сервер было поставлено:

```cpp
static const UsesEntry kPackages[] =
{
    {
        "Core",
        {
            0x0FE825BC,
            0x4970D0BC,
            0xE10969A8,
            0x4C498AF9
        },
        1
    },
};
```

После пересборки клиента/сервера клиент получил:

```text
PackageName: Core
GUID: 0FE825BCD0BC4970A86909E1F98A494C
Generation: 1
```

Важно:

вывод GUID в client log имеет иной порядок отображения отдельных внутренних DWORD/byte fields, чем строка, которую показывает package dumper.

Но **клиент данный GUID принял**, следовательно текущую wire serialization менять не надо.

---

# 14. Результат после исправления Core GUID

Это ключевой прорыв.

Раньше после `USES Core`:

```text
PackageVerificationFailed
Package 'Core' is not downloadable
disconnect
```

После исправления GUID клиент продолжает:

```text
PendingLevel received: Uses
PackageName: Core ...

LoadMap:
127.0.0.1:6969/rworldsocialdistrict_master

Bringing World rworldsocialdistrict_master.TheWorld up for play

Finished loading level

cHostingGC2DS::OnConnectSuccess()

ClientState
kCLIENT_STATE_DISTRICTSERVER_CONNECT_COMPLETE
```

То есть клиент:

- принял `USES Core`;
- прошёл package verification;
- загрузил Social District map;
- завершил PendingLevel;
- сообщил successful District Server connection.
- загрузил `rworldsocialdistrict_master`;
- вызвал `OnConnectSuccess`;
- перешёл в `kCLIENT_STATE_DISTRICTSERVER_CONNECT_COMPLETE`.

Это означает:

**предыдущий блокер был не NetIndexMap, а неправильный GUID в `NMT_Uses`.**

---

# 15. Очень важный вывод про Generation

Ранее существовал внешний ориентир:

```text
Core Gen 2
Engine Gen 2
```

Но фактический APB 1.13.1 клиент в runtime handshake сейчас получает:

```text
Core Generation: 1
```

и принимает его.

Локальный package также:

```text
GenerationCount = 1
```

Следовательно, для текущего `NMT_Uses Core`:

```text
Generation = 1
```

является рабочим значением.

На данный момент **не следует менять Core на Generation=2** только ради старого retail-order источника.

Внешнее `Gen 2` пока надо считать неподтверждённым для этой конкретной ревизии/этапа протокола.

---

# 16. Почему пока не добавляли Engine и остальные Uses

Известны GUID:

```text
Engine
8CC8C3484498F5A30556718879EC40E0

EngineResources
44A17FB24FA4F77ECE54BB861C6EDB43

EngineFonts
CAA646224F6BC4EFD6C7A292C4D8D4A1
```

Но после исправления **одного Core Uses** клиент уже смог загрузить district map и завершить connection.

Поэтому было принято решение:

**не отправлять сразу Engine/EngineResources/... вслепую.**

Сначала необходимо понять, что клиент и сервер делают после successful district connection.

Иначе добавление десятков/сотен Uses только усложнит диагностику.

---

# 17. Попытка включить подробный network traffic log

В:

```text
APBGame\Config\APBEngine.ini
Engine\Config\BaseEngine.ini
```

были найдены:

```ini
Suppress=DevNetTraffic
Suppress=DevNetTrafficDetail
```

Их временно закомментировали:

```ini
;Suppress=DevNetTraffic
;Suppress=DevNetTrafficDetail
```

Backup-файлы создавались командой:

```powershell
Copy-Item $file "$file.bak" -Force
```

то есть должны существовать:

```text
APBEngine.ini.bak
BaseEngine.ini.bak
```

Однако после повторного запуска в `Current.log` всё равно не появились полезные строки:

```text
DevNetTraffic
DevNetTrafficDetail
NMT_...
```

Поиск по приложенному логу также не нашёл этих строк.

Вывод:

либо APB shipping build не пишет эти категории,
либо они логируются иначе,
либо соответствующий suppression/config не влияет на этот код path.

Поэтому дальнейшая диагностика только через client DevNetTraffic признана неэффективной.

---

# 18. Текущее состояние клиента

Последний успешный flow:

```text
Login Server
    OK

World Server
    OK

District reserve
    OK

District enter
    OK

Connect 127.0.0.1:6969
    OK

HandshakeChallenge
    OK

HandshakeComplete
    OK

Challenge
    OK

Welcome
    OK

NMT_Uses Core
    OK

Core GUID verification
    OK

Load rworldsocialdistrict_master
    OK

OnConnectSuccess
    OK

DISTRICTSERVER_CONNECT_COMPLETE
    OK
```

Клиент после этого не показывает:

```text
PackageVerificationFailed
not downloadable
Closing connection
```

в исследованном участке.

То есть он уже находится намного дальше первоначального failure point.

---

# 19. Что сейчас считается главным блокером

После:

```text
kCLIENT_STATE_DISTRICTSERVER_CONNECT_COMPLETE
```

в client log нет заметного продолжения UE3 сетевого exchange.

Клиент остаётся живым, но сервер, вероятно, не обрабатывает следующий UE3 control message или не отправляет нужный ответ.

Наиболее вероятный следующий protocol stage:

```text
NMT_NetSpeed
NMT_Join
```

после чего сервер должен:

```text
создать connection player
создать PlayerController
открыть actor channel
начать replication
```

Но это пока нужно **подтвердить серверным RX dump**, а не предполагать.

APB имеет собственные handshake extensions, поэтому номера сообщений нельзя слепо брать из другой UE3 игры.

---

# 20. Следующий правильный шаг

Нужно логировать **все входящие UE3 control channel messages на сервере** после отправки:

```text
Challenge
Welcome
Uses Core
```

То есть в месте, где server reader делает примерно:

```cpp
uint8_t messageType = reader.ReadByte();

switch (messageType)
{
    ...
}
```

добавить:

```cpp
printf(
    "[CONTROL RX] msg=%u (0x%02X), bitsLeft=%d\n",
    messageType,
    messageType,
    reader.GetBitsLeft()
);
```

Если есть доступ к raw bunch payload:

```cpp
printf("[CONTROL RX RAW] ");

for (size_t i = 0; i < payloadSize; ++i)
{
    printf("%02X ", payload[i]);
}

printf("\n");
```

Нужен server log примерно такого вида:

```text
TX Challenge
TX Welcome
TX Uses Core

RX CONTROL msg=...
RX CONTROL msg=...
RX CONTROL msg=...
```

Особенно интересует, приходит ли после загрузки карты:

```text
NMT_NetSpeed
NMT_Join
```

или APB-specific message.

---

# 21. Почему NetIndexMap пока отложен

Изначально работа была сосредоточена на NetIndexMap.

Однако реальные логи показали:

1. Первый disconnect происходил на `NMT_Uses Core`.
2. Причиной был нулевой GUID.
3. После исправления GUID клиент проходит package verification.
4. Клиент успешно загружает district world.
5. Клиент доходит до `DISTRICTSERVER_CONNECT_COMPLETE`.
6. Никакого `NetIndex mismatch`, `SerializeObject failure` или actor-channel error пока не зарегистрировано.

Следовательно:

**строить полный NetIndexMap прямо сейчас преждевременно.**

NetIndex станет нужен, когда сервер начнёт:

```text
actor channel creation
RPC
property replication
SerializeObject
```

Именно тогда неправильный PackageMap/ObjectBase проявится как реальная ошибка.

---

# 22. Что уже готово для будущего NetIndex

Когда дойдём до replication, уже имеется:

- parser всех 6043 пакетов;
- package GUID;
- generation data;
- NetObjectCount;
- package version;
- package compression metadata;
- `packages.csv`;
- `generations.csv`;
- `NetIndexBuilder`.

`NetIndexBuilder` умеет:

```text
Package|Generation|RelativePath|ObjectCountOverride|ExpectedGuid
```

и выдаёт:

```text
Order
Package
RelativePath
Version
LicenseeVersion
GUID
ExpectedGUID
RequestedGeneration
DiskGenerationCount
GenerationExportCount
GenerationNameCount
DiskGenerationNetObjectCount
ObjectCount
ObjectCountSource
ObjectBase
Status
Note
```

Если generation неизвестна, builder не выдумывает ObjectBase.

---

# 23. Изменения клиента, которые потом нужно откатить

## APBInput.ini

Файл:

```text
E:\APBClients\APB_1.13.1(2013)\APBGame\Config\APBInput.ini
```

Временно добавлялись:

```ini
Bindings=(Name="F7",Command="SOCKETS | ScreenShot")
Bindings=(Name="F8",Command="PACKAGEMAP | ScreenShot")
```

`Engine.Console` временно менялся.

Исходное значение было:

```ini
[Engine.Console]
ConsoleKey=UNUSED
TypeKey=Quote
MaxScrollbackSize=1024
HistoryBot=-1
```

В приложенном исходном варианте `[Engine.Console]` виден соответствующий блок.

## APBEngine.ini

```text
E:\APBClients\APB_1.13.1(2013)\APBGame\Config\APBEngine.ini
```

Временно:

```ini
;Suppress=DevNetTraffic
;Suppress=DevNetTrafficDetail
```

Для отката:

```ini
Suppress=DevNetTraffic
Suppress=DevNetTrafficDetail
```

## BaseEngine.ini

```text
E:\APBClients\APB_1.13.1(2013)\Engine\Config\BaseEngine.ini
```

Аналогично:

```ini
;Suppress=DevNetTraffic
;Suppress=DevNetTrafficDetail
```

Для отката убрать `;`.

Backup:

```text
APBEngine.ini.bak
BaseEngine.ini.bak
```

должны существовать.

---

# 24. Не связанные с текущим network failure предупреждения

Во время загрузки Social District есть:

```text
Exception in UObject::GetPackageLinker
Can't find file for package '`~'
while loading `~ (TestLUTs)

Failed to load 'TestLUTs':
TestLUTs referenced by Weather_Redux.upk
```

Но после этого клиент всё равно:

```text
Bringing World rworldsocialdistrict_master.TheWorld up for play
Finished loading level
OnConnectSuccess
DISTRICTSERVER_CONNECT_COMPLETE
```

Поэтому `TestLUTs` на данный момент **не считается причиной network failure**.

Также многочисленные:

```text
Options UI...
Steam failed...
audio warnings...
texture warnings...
```

пока считаются вторичными, потому что они не мешают district connection перейти в COMPLETE.

---

# 25. Главные подтверждённые выводы

### Подтверждено №1

`Core.u` является нормальным compressed UE3 package, не stub.

### Подтверждено №2

Его package metadata:

```text
GUID:
0FE825BC4970D0BCE10969A84C498AF9

GenerationCount:
1

Gen1 NetObjectCount:
3
```

### Подтверждено №3

Сервер отправлял неправильный:

```text
Core GUID = 00000000000000000000000000000000
```

### Подтверждено №4

Именно это вызывало:

```text
PackageVerificationFailed
Package 'Core' is not downloadable
```

### Подтверждено №5

После передачи правильного FGuid клиент принимает `Core`.

### Подтверждено №6

`Generation=1` для Core в текущем `NMT_Uses` работает.

### Подтверждено №7

После исправления клиент успешно загружает:

```text
rworldsocialdistrict_master
```

и переходит в:

```text
kCLIENT_STATE_DISTRICTSERVER_CONNECT_COMPLETE
```

### Подтверждено №8

Текущий блокер находится **после PackageVerification / map loading**, а не до него.

### Подтверждено №9

Полный NetIndexMap пока не доказан как текущая причина остановки.

### Подтверждено №10

Следующий диагностический источник должен быть **server-side control channel RX log**.

---

# 26. Что не подтверждено и не следует пока считать фактом

Не подтверждено:

```text
Core должен использовать Gen 2
Engine должен использовать Gen 2
```

для этой конкретной ревизии клиента и текущего `NMT_Uses`.

Не подтвержден точный полный retail package order.

Не подтверждён полный runtime ObjectBase / BaseIndex map.

Не подтверждено, что сейчас клиент уже дошёл до actor replication.

Не подтверждено, что нужно отправлять `Engine` следующим `NMT_Uses`.

Не подтверждено, что проблема `TestLUTs` имеет отношение к network connection.

---

# 27. Точка продолжения работы

Продолжать следует **не с парсинга файлов и не с NetIndexBuilder**, а с серверного кода.

Нужно взять функцию, которая:

```text
получает UE3 bunch
определяет control channel
читает control message ID
обрабатывает Challenge/Login/Join/etc.
```

и добавить туда полный diagnostic log:

```text
message id
message name, если известен
bits/bytes remaining
raw payload
connection state
channel index
reliable sequence
```

После следующего district connect нужно посмотреть, какой control message приходит после:

```text
TX Welcome
TX Uses(Core)
```

и после клиентского:

```text
DISTRICTSERVER_CONNECT_COMPLETE
```

Если это `NMT_Join`, следующим этапом будет реализация корректного server-side Join/PlayerController flow.

Если после Join начнётся actor replication и появятся errors на UObject/NetIndex, тогда возвращаемся к построению runtime PackageMap и NetIndexMap.