# Отчёт по отладке входа в District — rAPB

## 1. Цель

Проект: `rAPB`, форк эмулятора APB: Reloaded.

Рабочая директория:

```text
E:\ProgrammingProjects\C#\rAPB
```

Основная текущая задача:

```text
Добиться полноценного входа клиента APB в district.
```

На текущем этапе:

- Login/WorldServer работают.
- DistrictServer регистрируется в WorldServer.
- Клиент выбирает district.
- WorldServer передаёт DistrictServer account + session encryption key.
- Клиент начинает UDP-соединение с DistrictServer на `6969`.
- Первый district UDP packet уже частично декодируется.
- XXTEA district crypto подтверждён.
- До `NETSPEED / LOGIN / JOIN` пока не дошли.

---

# 2. Исходное состояние

Изначально DistrictServer не регистрировался нормально в WorldServer.

Позже выяснилось, что часть изменений исходников вообще не попадала в реально запускаемый exe: запускался старый:

```text
Emulator\APB SERVER\DistrictServer.exe
```

После создания build/deploy-процесса проблема исчезла.

Успешная регистрация выглядела примерно так:

```text
WorldServer:
Districts.Listener : Expecting districts to connect at 127.0.0.1:2108
RegisterSuccess : Registered with a following ID: 1
RegisterDistrict : Social-Breakwater Marina-EN-1 tries to register.
RegisterDistrict : Social-Breakwater Marina-EN-1 was registered!

DistrictServer:
Network::Setup(): Ready to connect to World Server
Network::Connect(): Connected to World Server
Network::Send(): Initial data sent
ProcessWorldPacket(): Received response for initial packet
ProcessWorldPacket(): Registered at World Server
```

То есть TCP-канал:

```text
DistrictServer <-> WorldServer
```

сейчас рабочий.

---

# 3. Первый найденный фундаментальный баг DistrictServer

Оригинальный текущий DistrictServer читал UDP примерно так:

```cpp
char data[2048];
strcpy(data, listener->Receive());
int len = strlen(data);
```

А `UdpListener::Receive()` возвращал указатель на локальный массив:

```cpp
char data[2048];

recvfrom(...);

return data;
```

Это сразу две серьёзные ошибки:

1. возвращается pointer на stack memory;
2. бинарный UDP обрабатывается через `strlen()/strcpy()` как строка.

Поэтому старые сообщения вида:

```text
Received data, size = 36
Received data, size = 15
Received data, size = 4
...
```

не являлись реальным размером UDP datagram.

Число могло быть просто позицией первого `00`.

---

# 4. Архитектура UDP была переделана

Отказались от модели:

```text
один UdpListener :6969 на каждый Account thread
```

Это в принципе неправильная схема, потому что второй account не сможет нормально bind'нуться на тот же UDP port.

Сделано:

```text
один глобальный UDP socket
0.0.0.0:6969
```

И теперь используется настоящий:

```cpp
recvfrom(...)
```

с возвращаемым размером datagram.

Текущий рабочий лог:

```text
District UDP:
Listening on 0.0.0.0:6969; UE3 parser + 6-round XXTEA active.
```

---

# 5. Старый рабочий reference implementation

Были предоставлены исходники старого проекта примерно на три года старше:

```text
ApbUdp.cpp
ApbUdp.h
DistrictServer.cpp
Network.cpp
Account.cpp
Account.h
Xtea.cpp
Xtea.h
HandshakeProbe.ini
```

Они использовались как reference implementation, но не копировались целиком, потому что в них огромное количество build-specific значений:

- package GUID;
- package generations;
- NetIndex;
- ClassNetCache fields;
- PlayerController fields;
- GRI fields;
- streaming package lists;
- actor NetIndex;
- pawn/bootstrap IDs.

Это всё относится к старому APB build и не должно переноситься вслепую.

---

# 6. Что хранит Account в старом рабочем проекте

Reference `Account` хранит:

```text
uint32 account ID
20-byte auth token
16-byte district encryption key

UDP endpoint IP/port
Authenticated
server PacketId
reliable ChannelSequence
last client PacketId
HandshakeChallenge
HandshakeState
UDP receive counter
...
```

Это видно в интерфейсе старого `Account`: отдельно предусмотрены 20-byte auth token и 16-byte encryption key, endpoint binding и транспортные sequence counters. 
Для текущего минимального порта auth token пока не является blocker: главный session key уже приходит от WorldServer.

---

# 7. Что было установлено про district crypto

Это один из наиболее надёжно подтверждённых результатов всей работы.

District UDP **НЕ использует обычный XTEA ECB/CBC**.

Старый проект содержит отдельную реализацию обычного XTEA для диагностических экспериментов, но основной APB district cipher — другой.

Reference прямо документирует:

```text
APB district UDP = XXTEA / Corrected Block TEA

whole datagram
little-endian uint32 words
fixed 6 rounds
delta = 0x9E3779B9
16-byte key
```

Причём explicitly:

```text
не textbook 6 + 52/n
а ровно 6 rounds
```

И первый packet plaintext, а все последующие packet'ы после начала district session должны decrypt/encrypt'иться.

Основная encrypt/decrypt реализация reference также использует именно fixed `kBteaRounds = 6`.

---

# 8. Отдельная найденная заметка про RC4

В старом проекте также была найдена пометка про:

```text
GC2LS
GC2WS
```

Там используется RC4.

Вывод:

```text
Login/World TCP:
GC2LS -> RC4
GC2WS -> RC4

District UDP:
XXTEA/BTEA 6 rounds
```

Это разные сетевые подсистемы.

Поэтому RC4 к нашей текущей проблеме UDP district не относится.

---

# 9. WorldServer передаёт правильный district session key

В реальных запусках видим:

```text
WorldControl:
District enter handoff: account=1;
XXTEA key=...
```

Например:

```text
86 A6 D1 54 3A 9E 5B DA D2 30 DB 35 09 C4 50 AD
```

или:

```text
48 AE 1E 18 BA 56 B8 7B 00 F4 82 9A 1D BA 78 35
```

Ключ каждый новый вход может быть другим, что нормально.

Самое важное: этим ключом последующие ciphertext datagram действительно превращаются в осмысленные sequential packet IDs:

```text
packetId=1
packetId=2
packetId=3
...
```

Следовательно:

```text
WorldServer handoff key = правильный
district XXTEA implementation = правильная
key endian = правильный
6 rounds = правильные
```

Это уже экспериментально подтверждено, а не просто предположение.

---

# 10. Первый district UDP packet нового клиента

Самый важный capture:

```text
RX 35 bytes

00 00 00 80 05 40 00 81 06 8D 80 00 00 00 ...
```

Он приходит **plaintext**.

После исправления parser удалось получить:

```text
packetId=0

DATA:
open=1
paused=1
reliable=0
channel=0
type=Control
dataBits=128
```

Это означает:

```text
клиент открывает UE3 ControlChannel 0
```

---

# 11. Старый AUTH FString к новому клиенту неприменим

Старый reference ожидал первый текстовый control message:

```text
AUTH ACCID=<account>
AUTHKEY=<40 hex chars>
```

Старый parser действительно имеет `ParseAuthCommand()` с `ACCID=` и 40 hex chars `AUTHKEY`.

Но новый клиент присылает первый datagram всего:

```text
35 bytes
```

Следовательно, он физически не может содержать старый:

```text
AUTHKEY=<40 ASCII chars>
```

Уже один auth key больше packet'а.

Вывод:

```text
новая версия APB изменила первоначальный district handshake.
```

---

# 12. Найден NMT_HandshakeStart

В первом ControlChannel payload обнаружился дополнительный bit-level framing.

Если его учитывать, первый binary control message:

```text
26
```

То есть:

```text
NMT_HandshakeStart
```

Reference использует:

```text
26 = NMT_HandshakeStart
27 = NMT_HandshakeChallenge
28 = NMT_HandshakeResponse
29 = NMT_HandshakeComplete
```



Текущий лог:

```text
District Binary Control:
RX message=26 packetId=0
open=1
paused=1
payloadBytes=14
```

Например:

```text
payload=
34 02 02 00 00 00
9E FF 3D 3D F3 1D FC 87
```

Важно:

```text
это уже не старый AUTH FString.
```

---

# 13. Дополнительный UE3 bunch bit

Старый parser был несовместим с новым packet header.

Старый формат предполагал примерно:

```text
IsAck
OpenClose
Reliable
Channel
...
```

Но в живом новом packet обнаружился дополнительный:

```text
bIsReplicationPaused
```

И реальный порядок для этого клиента:

```text
IsAck
OpenClose
Open
Close
bIsReplicationPaused
Reliable
ChannelIndex
...
```

Именно отсутствие этого bit раньше сдвигало parser и приводило к:

```text
bunch data exceeds packet payload
```

После добавления `paused` первая часть packet'а стала стабильно декодироваться.

---

# 14. Дополнительный bit внутри первого ControlChannel

Первый payload первоначально выглядел как:

```text
34 ...
```

Но после снятия дополнительного initial/endian framing bit:

```text
34 >> 1 = 1A hex = 26 decimal
```

Именно поэтому сейчас лог показывает одновременно:

```text
controlMessage=52
```

на сыром уровне и:

```text
District Binary Control:
RX message=26
```

после специальной обработки первого ControlChannel packet.

То есть `26` сейчас считается подтверждённым.

---

# 15. Проблема trailing framing первого packet

Первый packet имеет:

```text
payloadBits=279
```

После успешного первого ControlChannel bunch остаётся значительное количество бит.

Parser старого проекта пытается интерпретировать их как дополнительные стандартные bunch/ACK и получает бессмысленные значения вроде:

```text
ACK(228150999)
ACK(1066545500)
```

или падает:

```text
truncated channel type
trailing bunch data exceeds packet payload
```

Был сделан tolerant parser:

```text
если полноценный channel 0 Control bunch уже успешно прочитан,
ошибка в неизвестном trailing framing больше не уничтожает packet.
```

Поэтому теперь получаем:

```text
PLAINTEXT ...
bunches=1
partialTail=trailing bunch data exceeds packet payload

#0 DATA ...
Control
NMT_HandshakeStart(26)
```

Это важный момент:

```text
формат оставшихся ~90 bits packet 0 пока НЕ восстановлен.
```

Очень вероятно, что там находится дополнительная transport/handshake информация новой версии UE3/APB.

---

# 16. Endpoint binding работает

После `NMT_HandshakeStart` сервер связывает:

```text
UDP IP:port
```

с account, который ранее пришёл из WorldServer.

Реальный лог:

```text
District Handshake:
Bound 127.0.0.1:51536
to pending account 1 from WorldServer handoff.
```

После этого все packet'ы от endpoint идут decrypt-first.

---

# 17. Исправлена ложная классификация ciphertext как plaintext

До этого parser был слишком tolerant.

Случайный encrypted datagram иногда чисто случайно проходил UE bit parser и выглядел как:

```text
packetId=48299
ACK(589186723)
ch=1017
```

Это был не настоящий plaintext.

Исправлено:

```text
пока endpoint не связан:
raw packet принимается только если содержит NMT_HandshakeStart(26)

после endpoint binding:
decrypt-first
```

После этого получаем стабильные:

```text
DECRYPTED packetId=1
DECRYPTED packetId=2
DECRYPTED packetId=3
...
```

---

# 18. Transport ACK полностью подтверждён

После получения packet 0 сервер отправляет encrypted ACK.

Например:

```text
District UDP:
TX ACK: 8 bytes
```

После этого клиент **перестаёт повторять исходный 35/36-byte handshake packet**.

Это очень важное наблюдение.

Вывод:

```text
клиент успешно decrypt'ит наш server packet
и принимает packet-level ACK.
```

Следовательно, работоспособны:

```text
server -> client XXTEA encryption
session key
padding как минимум для 8-byte ACK
packet ID acknowledgement
UDP endpoint
```

---

# 19. Попытка №1: Challenge(27)

Сделан вариант:

```text
CLIENT -> HandshakeStart(26)

SERVER -> ACK
SERVER -> NMT_HandshakeChallenge(27)
challenge = 0x12345678
```

Reference действительно использует binary:

```text
NMT_HandshakeChallenge = 27
```

и 4-byte little-endian challenge payload.

Результат:

```text
клиент НЕ прислал HandshakeResponse(28)
```

После ответа клиента пошли только:

```text
RX 8 bytes
DECRYPTED packetId=1 payloadBits=30 bunches=0

через 5 секунд:
packetId=2

ещё через 5:
packetId=3
...
```

То есть только empty keepalive.

Вывод:

```text
Challenge(27) в текущем виде не продвигает handshake.
```

Но это ещё не доказывает, что message 27 вообще не нужен:

- payload может быть другим;
- outgoing ControlChannel framing может отличаться;
- server reliable sequence может быть неверным;
- неизвестный tail первого packet может быть важен.

---

# 20. Попытка №2: HandshakeComplete(29)

Был сделан probe:

```text
CLIENT -> 26

SERVER -> ACK
SERVER -> HandshakeComplete(29)
```

Результат тот же:

```text
только empty 8-byte keepalive каждые 5 секунд
```

`NETSPEED/LOGIN` не появились.

Вывод:

```text
прямой Start -> Complete тоже не подходит.
```

Reference действительно имеет функцию отправки `NMT_HandshakeComplete(29)` после `HandshakeResponse`.

---

# 21. Попытка №3: ACK-only

Чтобы убрать все server control messages, был сделан наиболее чистый probe:

```text
CLIENT -> HandshakeStart(26)

SERVER -> encrypted ACK

и больше ничего.
```

Это тестировалось уже после tolerant parsing, поэтому `26` реально дошёл до обработчика.

Лог:

```text
District Binary Control:
RX message=26 ...

District Handshake:
Bound ...

District UDP:
TX ACK ...

District Handshake:
ACK-only probe after NMT_HandshakeStart(26)
```

После этого:

```text
5 sec -> empty packet 1
5 sec -> empty packet 2
5 sec -> empty packet 3
...
```

Никаких:

```text
NETSPEED
LOGIN
JOIN
```

не появилось.

Это уже сильный вывод:

```text
одного packet-level ACK после HandshakeStart клиенту недостаточно.
```

Клиент ожидает ещё какую-то серверную реакцию или завершение обработки packet 0.

---

# 22. Попытка №4: WelcomeDirect

В старом рабочем проекте `HandshakeProbe.ini` был:

```text
AckMode=plain
ChallengeMode=welcome-direct
```



Reference также содержит комментарий, что retail APB использовал `WelcomeDirect`:

```text
без challenge
немедленный WELCOME LEVEL=<map>
```



Поэтому был сделан probe:

```text
CLIENT -> HandshakeStart(26)

SERVER -> ACK
SERVER -> encrypted WELCOME
```

Лог:

```text
TX WELCOME: 68 bytes

Sent WELCOME
LEVEL=rworldsocialdistrict_master
CHALLENGE=0
```

После этого:

```text
клиент не изменил поведение
```

Снова только:

```text
empty keepalive каждые 5 секунд
```

Вывод:

```text
WELCOME сразу после нового HandshakeStart
тоже недостаточен.
```

---

# 23. Что НЕ получилось доказать этими тестами

Нельзя пока делать вывод:

```text
"27 точно не нужен"
или
"WELCOME точно неправильный"
```

Почему:

Все длинные server responses:

```text
Challenge
Complete
WELCOME
```

являются **ControlChannel bunch'ами**.

ACK — нет.

ACK работает.

Все ControlChannel responses не дают никакой реакции.

Поэтому общий blocker может находиться не в типе message, а в:

```text
server->client ControlChannel serialization
reliable sequence
open/close state
bIsReplicationPaused
channel acceptance state
trailer
padding interaction
first control bunch format
```

Это сейчас более вероятное направление.

---

# 24. Особенно подозрительное место: исходящий ControlChannel writer

Reference `WriteReliableControlBunch()` пишет старый server control bunch примерно так:

```text
not ACK
no open/close
reliable
channel 0
channel sequence
type Control
data length
payload
```



Новый входящий client packet уже показал, что формат его header отличается от старого.

Следовательно, очень возможно:

```text
новый CLIENT parser ожидает новую форму server->client bunch header,
а наши BuildBinaryControlPacket / BuildTextControlPacket всё ещё
не полностью соответствуют этой версии.
```

Это объясняет наблюдение:

```text
ACK работает
любой ControlChannel server packet молча игнорируется
```

---

# 25. Текущий первый plaintext payload

Один из последних captures:

```text
District Binary Control:
RX message=26
packetId=0
open=1
paused=1
payloadBytes=14

payload:
34 02 02 00 00 00 30 08 4F 5D A3 6F 7D 09
```

Другой запуск:

```text
34 02 02 00 00 00 9E FF 3D 3D F3 1D FC 87
```

Первые байты повторяются:

```text
34 02 02 00 00 00
```

а последующие восемь меняются.

После специального initial bit handling первый message byte фактически:

```text
0x1A = 26
```

Остальной payload пока не декодирован.

Очень вероятно, что эти данные содержат:

```text
version/platform/network protocol info
nonce/challenge state
handshake parameters
```

Но это пока гипотеза, не установленный факт.

---

# 26. Почему следующий этап должен быть packet-0 reverse engineering

Первый packet:

```text
payloadBits=279
```

Первый полностью понятный ControlChannel bunch занимает только часть packet.

После него остаётся примерно порядка:

```text
~90 bits
```

которые текущий parser понимает неправильно.

Это может быть критически важно.

Возможная последовательность:

```text
CLIENT packet 0
    |
    +-- ControlChannel open
    |
    +-- HandshakeStart(26)
    |
    +-- дополнительный transport/handshake state
         который мы пока игнорируем
```

Мы ACK'аем весь packet 0.

Клиент видит:

```text
packet delivered
```

и перестаёт его повторять.

Но сервер обработал только первую часть.

После этого клиент ждёт ожидаемой server state transition и лишь отправляет keepalive.

Это хорошо согласуется со всеми наблюдениями.

---

# 27. Текущий наиболее обоснованный вывод

### Уже точно работает

```text
Login/World connection
District registration
World -> District handoff
UDP bind :6969
real recvfrom lengths
session key
6-round district XXTEA
client->server decrypt
server->client encryption
packet ID extraction
NMT_HandshakeStart detection
endpoint binding
packet-level ACK
```

### Пока не работает

```text
переход после NMT_HandshakeStart

нет:
NETSPEED
LOGIN
WELCOME acceptance
JOIN
LoadMap completion
```

### Наиболее вероятный blocker

Не сам cipher.

Не session key.

Не UDP.

Не packet ACK.

Наиболее подозрительны:

1. неполностью разобранный остаток первого plaintext packet;
2. несовпадение server->client ControlChannel bunch framing новой версии;
3. reliable ChannelSequence / channel lifecycle;
4. дополнительные handshake fields внутри `NMT_HandshakeStart`.

---

# 28. Что сейчас НЕ следует делать

Не нужно снова менять:

```text
XXTEA rounds
key endian
16-byte session key handling
UDP socket architecture
packet-level ACK
```

Для них уже есть достаточно сильные экспериментальные подтверждения.

Также пока не следует портировать целиком:

```text
PlayerController
GRI
Pawn
vehicles
inventory
customisation
streaming
spawn zones
```

До:

```text
NETSPEED
LOGIN
JOIN
```

это преждевременно.

---

# 29. Что нужно делать следующим

## Приоритет №1 — полностью разобрать первый 35-byte plaintext packet

Нужно сделать побитовый dump:

```text
bit offset
field
value
remaining bits
```

Для всего:

```text
00 00 00 80 05 40 00 81 06 8D 80 00 00 00 ...
```

до UE trailer marker.

Не останавливаться после первого ControlChannel bunch.

Цель:

```text
объяснить каждый bit первого packet.
```

---

## Приоритет №2 — исследовать настоящий UE3 network code подходящей версии

Нужны:

```text
UNetConnection::ReceivedPacket
UControlChannel
FInBunch
NMT_HandshakeStart
NMT_HandshakeChallenge
```

желательно engine build, близкий к новому APB client.

Особенно нужно выяснить:

```text
точный bunch header
точное положение bIsReplicationPaused
ControlChannel open semantics
первый message endian/platform framing
payload NMT_HandshakeStart
server reply на NMT_HandshakeStart
```

---

## Приоритет №3 — self-parse server control packet

Перед XXTEA полезно строить:

```text
clear Challenge/WELCOME/etc
```

и тут же прогонять его через тот же parser.

Ожидаемый диагностический лог:

```text
server clear packet:
packetId=N
DATA
paused=?
reliable=1
ch=0
seq=?
type=Control
bits=...
message=...
```

Это позволит доказать хотя бы внутреннюю симметрию reader/writer.

---

## Приоритет №4 — проверить ChannelSequence

Нужно точно выяснить, какой sequence должен быть у первого server reliable bunch.

Сейчас reference выделяет server reliable sequence через `AllocateServerReliableSequence()`. Сам `Account` специально хранит отдельный sequence counter.

Если современный UE3 ожидает:

```text
sequence = 0
```

а сервер шлёт:

```text
1
```

или наоборот, ControlChannel packet может молча быть discarded как out-of-order.

Это идеально объясняло бы:

```text
ACK работает
ControlChannel ignored
```

---

# 30. Отдельная аномалия: World handoff приходит два раза

Каждый district enter сейчас часто показывает:

```text
WorldControl:
District enter handoff: account=1 ...

WorldControl:
District enter handoff: account=1 ...
```

дважды подряд с одинаковым ключом.

Пока это не ломает вход, потому что account просто обновляется.

Но позднее нужно проверить:

```text
почему WorldServer посылает AccountEntersDistrict дважды.
```

Это отдельная задача, не текущий blocker.

---

# 31. Build/deploy проблемы, которые уже решены

### inet_ntoa

Новый MSVC отказался собирать:

```text
error C4996: inet_ntoa
```

Исправлялось через:

```cpp
InetNtopA
```

---

### ApbUdp.cpp не попадал в vcxproj

Был linker error:

```text
LNK2019 ApbUdp::ParsePacket
LNK2019 ApbUdp::ParseAuthCommand
LNK2019 ApbUdp::BuildAckPacket
...
```

Причина:

```text
ApbUdp.h был подключён,
но ApbUdp.cpp не был добавлен как ClCompile.
```

Исправлено добавлением:

```xml
<ClCompile Include="ApbUdp.cpp" />
<ClInclude Include="ApbUdp.h" />
```

---

# 32. Созданные patch iterations

Во время работы делались последовательные экспериментальные патчи:

```text
rapb-minimal-handshake-patch
```

Первый минимальный UDP/UE parser/XXTEA transport port.

```text
handshake-v2
```

Добавлено распознавание новой формы первого binary HandshakeStart.

```text
handshake-v3
```

Проверка прямого HandshakeComplete.

```text
handshake-v4
```

ACK-only experiment, но первоначальный запуск оказался испорчен строгим trailing parser.

```text
handshake-v5
```

Tolerant first ControlChannel parsing +
raw ciphertext rejection +
настоящий ACK-only experiment.

```text
handshake-v6
```

APB WelcomeDirect experiment:

```text
HandshakeStart -> ACK -> WELCOME
```

без challenge/complete.

Текущая база — по сути v6 поверх исправлений v5.

---

# 33. Итог экспериментов в таблице

| Тест | Ответ сервера после `26` | Результат |
|---|---|---|
| Transport baseline | ничего | клиент ретранслировал handshake |
| ACK | ACK | packet 0 больше не повторяется |
| ACK + Challenge(27) | binary challenge | только keepalive |
| ACK + Complete(29) | binary complete | только keepalive |
| ACK only | только ACK | только keepalive |
| ACK + WELCOME | WELCOME text control | только keepalive |

Главный вывод из таблицы:

```text
transport ACK принимается,
ControlChannel state transition пока нет.
```

---

# 34. Reference handshake нельзя переносить буквально

Старый reference реализует `NMT_HandshakeStart/Response` обработчики и challenge/complete path.

Но он создавался для другого APB build и содержит множество experimental modes.

Поэтому наличие там:

```text
challenge uint32
response uint32
WelcomeDirect
```

не означает, что payload новой версии идентичен.

Нужно использовать старый проект как:

```text
архитектурный reference
```

а не как byte-exact protocol specification текущего клиента.

---

# 35. Важная информация для следующего разработчика/чата

Не начинать исследование заново с вопроса:

```text
"может быть неправильный XXTEA?"
```

На текущем этапе это уже практически исключено.

Сильнейшее доказательство:

```text
encrypted 8-byte client keepalive
+
World handoff key
+
6-round BTEA decrypt
=
sequential packetId 1,2,3,...
```

и encrypted ACK server->client останавливает retransmit packet 0.

Это двустороннее подтверждение crypto.

Главная неизвестная теперь находится выше crypto layer:

```text
UE3 ControlChannel / handshake framing.
```

---

# 36. Рекомендуемый следующий milestone

Не ставить целью сразу:

```text
"зайти персонажем в district"
```

Следующий маленький milestone:

```text
после packet 0 заставить клиента
отправить любой непустой packet.
```

То есть вместо:

```text
payloadBits=30
bunches=0
```

получить:

```text
ControlChannel data
NETSPEED
LOGIN
или иной binary handshake packet
```

Как только это произойдёт, станет ясно, что server->client initial ControlChannel state принят.

После этого:

```text
LOGIN
 -> WELCOME
 -> JOIN
 -> PlayerController
 -> package map
 -> streaming
 -> pawn
```

можно будет разбирать уже последовательно.

---

# Короткая версия текущего статуса

```text
[OK] WorldServer
[OK] DistrictServer registration
[OK] World -> District account handoff
[OK] UDP :6969
[OK] district 16-byte session key
[OK] 6-round whole-datagram XXTEA
[OK] plaintext first packet
[OK] UE3 ControlChannel open
[OK] NMT_HandshakeStart(26)
[OK] endpoint binding
[OK] encrypted transport ACK
[OK] encrypted client keepalives decode

[FAIL] Challenge(27) path
[FAIL] direct Complete(29)
[FAIL] ACK-only
[FAIL] direct WELCOME
[TODO] fully decode remainder of packet 0
[TODO] exact modern UE3 ControlChannel framing
[TODO] exact HandshakeStart payload
[TODO] correct first server ControlChannel reply
[TODO] NETSPEED
[TODO] LOGIN
[TODO] JOIN
```

## Главный вывод

District connection больше не является проблемой TCP, UDP или encryption.

Текущий blocker локализован до:

```text
первоначального UE3 ControlChannel handshake
между NMT_HandshakeStart(26)
и первым NETSPEED/LOGIN.
```

Наиболее перспективный следующий шаг — перестать перебирать типы server response и полностью восстановить wire format первого plaintext packet и современного server→client ControlChannel bunch.