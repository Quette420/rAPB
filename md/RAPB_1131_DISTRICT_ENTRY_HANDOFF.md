# rAPB — вход в District, клиент APB 1.13.1 (2013)

Отчёт по сессии. Состояние на момент передачи контекста.

Проект: `E:\ProgrammingProjects\C#\rAPB`, репозиторий `github.com/Quette420/rAPB`.
Клиент: `E:\APBClients\APB_1.13.1(2013)`, UE3 build 3908, `GUseSeekFreeLoading = 1`.

**Главный принцип:** живая память клиента — источник истины. Всё остальное — гипотеза,
пока не подтверждено ею. В этом отчёте всё, что не подтверждено, помечено явно.

---

## 1. Итог одной строкой

Транспорт, крипто, APB-handshake и весь UE3 login-слой пройдены полностью.
Клиент доходит до `NMT_Join` и ждёт actor channel.

Единственный блокер: **не знаем настоящие GUID пакетов**, поэтому `NMT_Uses`
отвергается, package map остаётся пустым, и NetIndex в клиенте не существует.

---

## 2. Что было в начале сессии

Работало: Login/World, регистрация district, handoff, UDP :6969, XXTEA 6 раундов,
разбор packet 0, обнаружение `NMT_HandshakeStart(26)`, packet-level ACK.

Не работало: любой серверный ControlChannel bunch молча игнорировался клиентом.
Была перебрана матрица ответов (`ACK only`, `Challenge 27`, `Complete 29`, `WELCOME`)
— все четыре давали одинаковый результат: только keepalive.

---

## 3. Ключевой прорыв: заголовок bunch

Перебор сообщений был бессмысленным — клиент вообще не доходил до разбора типа.
Ошибка была в порядке двух битов заголовка.

### Подтверждённая раскладка

Полный побитовый разбор клиентского packet 0 (35 байт), сходится без остатка:

```
packetId(30)          = 0
bIsAck                = 0    @bit30
bControl              = 1    @bit31
bOpen                 = 1    @bit32
bClose                = 0    @bit33
bReliable             = 1    @bit34
bIsReplicationPaused  = 0    @bit35
ChIndex               = 0    @bit36   SerializeInt(1023) -> 10 бит
ChSequence            = 1    @bit46   SerializeInt(1024) -> 10 бит
ChType                = 1    @bit56   SerializeInt(8)    ->  3 бита
BunchDataBits         = 208  @bit59   SerializeInt(4096) -> 12 бит
payload               @bit71, 208 бит -> ровно 279 = payloadBits
```

Исходный дамп для перепроверки:

```
00 00 00 80 05 40 00 81 06 8D 80 00 00 00 00 FC B5 F4 86 21 E8 BB 72 CE
73 6C F8 20 92 38 95 81 CA 3D D3
```

### Что было неверно

Старый writer писал `bIsReplicationPaused` **перед** `bReliable`. Клиент читал
`reliable=0`, из-за чего не читал `ChSequence`, съезжал на 10 бит и получал
`BunchDataBits=128` при 53 доступных битах → bunch отбрасывался всегда.

ACK при этом работал, потому что у ACK нет ни paused, ни поля длины. Именно эта
асимметрия и была диагностическим ключом.

### Отвергнутые гипотезы (не возвращаться)

| Гипотеза | Почему отвергнута |
|---|---|
| `BunchDataBits` = 13 бит | артефакт разбора обрезанного дампа, дополненного нулями |
| 10-битный «name token» = 128 между ChType и длиной | 128 был самой длиной, прочитанной не с той позиции |
| `bIsReplicationPaused` перед `bReliable` | даёт `rel=0` и несходящуюся длину |
| `MAX_CHANNELS = 2048` (11-битный ChIndex) | даёт `ChIndex=1024`, всё дальше рассыпается |
| Перебор типов серверных сообщений | причина была в заголовке, а не в типе |

---

## 4. Номера control-сообщений

Сняты из jumptable `UNetPendingLevel::NotifyReceivedText` (`FUN_11553720`,
таблица на `0x11554C38`). **Нумерация совпадает со стоковым UE3** — предыдущие
предположения о перенумерации APB были ошибочны и стоили двух сборок.

| № | Сообщение | Статус |
|---:|---|---|
| 0 | Hello | подтверждено на проводе |
| 1 | Welcome | подтверждено |
| 2 | Upgrade | case в таблице (`ClientOutdated`/`ServerOutdated`) |
| 3 | Challenge | подтверждено |
| 4 | Netspeed | подтверждено |
| 5 | Login | подтверждено |
| 6 | Failure | case в таблице |
| 7 | **Uses** | подтверждено клиентским логом |
| 9 | Join | наблюдалось как исходящее от клиента |
| 0x0B | ? | `TArray::Add(conn+0x8FA0)` + `LoadPackage`, сигнатура `FString, FString, INT` |
| 0x0E | ? | работа с `PackageMap`, кандидат NetGUID |
| 0x13 | PeerConnect | строка в логе прямо называет |
| 0x1B | APB HandshakeChallenge | считает ответ по соли |
| 0x1D | APB HandshakeComplete | шлёт `NMT_Hello` |

Сообщения 26–29 — APB-специфичный транспортный handshake, живёт до UE3-слоя.

---

## 5. Подтверждённые сигнатуры

Все получены из декомпиляции клиента, не угаданы.

```
NMT_Hello(0)      int32 MinVer, int32 Ver, int32 Unknown
                  живьём: 3077, 3908, 0

NMT_Welcome(1)    FString LevelName, FString GameName, int32 bStrippedData
                  bStrippedData должен равняться GUseSeekFreeLoading клиента (= 1)
                  при несовпадении: MessageBox "Content Mismatch" и разрыв

NMT_Challenge(3)  int32 ServerNetworkVersion, FString Challenge
                  значение не проверяется: клиент кладёт литерал "0" в ClientResponse

NMT_Netspeed(4)   int32 Rate            (живьём 999999999)

NMT_Login(5)      FString ClientResponse, FString URL, uint64 UniqueNetId
                  живьём: "0", ":6969/APBLoginLevel?Name=Player?team=255", 0

NMT_Uses(7)       FGuid(16 байт)
                  FString PackageName      -> FName info+0x00
                  FString                  -> FName info+0x48
                  FString                  -> член info+0x3C
                  int32  PackageFlags      -> info+0x2C
                  int32  Generation        -> info+0x28
                  FString                  -> FName info+0x30
                  uint8                    -> info+0x38

NMT_Join(9)       без параметров

APB HandshakeStart(26)  uint8 Platform, uint32 AccountId, uint8[20] Token
```

`FString` в UE3: `int32` длина **включая терминатор**, затем символы и `\0`.
Отрицательная длина = UCS2.

Порядок `NMT_Uses` получен из `FPackageInfo::SerializeWire` (`FUN_112A7710`) и
**подтверждён клиентским логом**:

```
DevNet: PendingLevel received: Uses
 ---> PackageName: Core, GUID: 000...0, FileName: None, Generation: 1, BasePkg: None
```

Все пять полей разобраны корректно. Формат менять не нужно.

---

## 6. Текущий блокер: GUID пакетов

### Механика отказа

```
case NMT_Uses:
  FPackageInfo::SerializeWire(...)
  для каждого package cache в conn+0x28 (счётчик conn+0x2C):
      FPackageFileCache::FindPackageFile(cache, FName, &localGuid)
      если localGuid == info.Guid -> принять, PackageMap->AddPackageInfo (vtable+0x134)
  иначе:
      debugf "Failed to match package %s [%s] in guid cache"
      GPackageFileCache->vtable+8 (name, &info.Guid, &outFilename, 0)
      если не найдено:
          info.PackageFlags |= 0x8000        // PKG_Need
          Localize("NoDownload", "Engine")
          -> разрыв соединения
```

Мы шлём нулевой GUID → совпадения нет → `PKG_Need` → клиент выходит из района.
В серверном логе это видно как `close=1 bits=0` на канале 0.

### Где взять GUID — подтверждённая структура кэша

Из декомпиляции `FPackageFileCache::FindPackageFile`:

```c
FUN_112a5ef0(this+0x40, &index, &FName);        // поиск по имени
elem = *(int*)(this+0x40) + index * 0x20;       // элемент 0x20 байт
out[0] = *(int64*)(elem + 0x08);
out[1] = *(int64*)(elem + 0x10);                // итого 16 байт = FGuid
```

Отсюда:

```
GPackageFileCache = [DAT_124F822C]
  +0x40   Data (массив)
  +0x44   Num
  запись 0x20 байт:
    +0x00  FName  (Index u32, Number u32)
    +0x08  FGuid  (16 байт)
    +0x18  8 байт, назначение неизвестно
```

`+0x44 = Num` — **не подтверждено чтением**, выведено из типового layout `TArray`.
Проверить первым делом.

### Процедура снятия

1. `cache = read_u32(GPackageFileCache_addr)`
2. `data = read_u32(cache + 0x40)`, `num = read_u32(cache + 0x44)`
3. Санити: `num` в диапазоне сотен-тысяч, `data` — валидный указатель кучи.
   Если нет — смотреть `FUN_112A5EF0`, там видна реальная индексация.
4. Для каждой записи: `FName` с `+0x00` через `GNames`, `FGuid` с `+0x08`.
5. Найти `Core`, подставить GUID в `UsesEntry`.

`Generation` в кэше отсутствует. Ретейл-лог даёт для `Core` значение 2, у нас
сейчас 1. Проверить обе величины — сравнение идёт после GUID, так что это
вторая по счёту переменная, а не первая.

---

## 7. Смещения и адреса (база модуля 1.13.1)

Все адреса — как показывает Ghidra для загруженного образа. Пересчитать под
фактическую базу перед использованием в скриптах.

### Функции

| Адрес | Имя |
|---|---|
| `0x11553720` | `UNetPendingLevel::NotifyReceivedText` |
| `0x11554C38` | jumptable этой функции |
| `0x11554892` | `case NMT_Welcome` |
| `0x11554597` | `case NMT_Challenge` (отправляет Login) |
| `0x115547FA` | `case 0x0B` — LoadPackage по имени, **не Uses** |
| `0x11554A07` | `case NMT_PeerConnect` |
| `0x11554057` | `case NMT_Uses`, ветка прямого поиска файла |
| `0x11554C10` | `case default` |
| `0x11303BE0` | `FNetControlMessage<>::Receive` (одна инстанциация на Welcome и Uses) |
| `0x112A7470` | `operator<<(FArchive&, FPackageInfo&)` |
| `0x112A7710` | `FPackageInfo::SerializeWire` |
| `0x112A6390` | `FPackageFileCache::FindPackageFile` (возвращает FGuid) |
| `0x112A5EF0` | поиск в кэше по `FName` |
| `0x115557E0` | `UNetPendingLevel::ReceiveNextFile` |
| `0x112A77A0` | `UNetConnection::ReceiveFile` |
| `0x1154FD50` | `UDownload::CleanUp` |
| `0x11555950` | `UNetConnection::SendLogin` (кандидат) |
| `0x11555A70` | `UNetConnection::SendHello` (кандидат) |
| `0x11555B90` | `UNetConnection::SendHandshakeResponse` (кандидат) |
| `0x11041530` | хэш handshake-ответа |
| `0x11171AE0` | `ULocalPlayer::GetNickname` |
| `0x10AAD850` | `FArchive::Serialize(void*, INT)` |
| `0x110301D0` | `FArchive::operator<<(FString&)` |

### Глобальные

| Адрес | Имя | Значение |
|---|---|---|
| `0x12538938` | `GNames` | |
| `0x125A7D60` | `GEngine` | `+0x350/+0x354` = `GamePlayers` |
| `0x12549BF4` | `GUseSeekFreeLoading` | 1 |
| `0x12100070` | `GEngineMinNetVersion` | 3077 |
| `0x12100078` | `GEngineVersion` | 3908 |
| `0x124F822C` | `GPackageFileCache` | |
| `0x12549B84` | флаг включения guid-кэша | |
| `0x12538A04` | `GMalloc` | |

### Структуры

```
UNetConnection
  +0x00E0   PackageMap
  +0x8F9C   Download
  +0x8FA0   TArray, элемент 0x20 (case 0x0B), НЕ то же, что PackageMap->List

UPackageMap
  +0x0040   List.Data
  +0x0044   List.Num
  vtable+0x134  AddPackageInfo

UDownload
  +0x0040   Connection
  +0x005C   освобождаемый буфер

FPackageInfo            (на стеке 0xD4, реальный размер >= 0x4C)
  +0x0000   PackageName   FName
  +0x000C   Guid          FGuid
  +0x0028   Generation    INT
  +0x002C   PackageFlags  DWORD   (PKG_Need = 0x8000)
  +0x0030   FName
  +0x0038   BYTE
  +0x003C   FString
  +0x0048   FName

FPackageFileCache
  +0x0040   Data, элемент 0x20
  +0x0044   Num                     [НЕ ПОДТВЕРЖДЕНО]
  запись:  +0x00 FName, +0x08 FGuid(16), +0x18 ?
```

---

## 8. Бонусы, снятые попутно

**APB handshake разгадан полностью.** Case `0x1B` строит строку
`"895fcf626f55798667e4e94cb7a636af %d"` из полученного challenge и хэширует её
через `FUN_11041530`. Отсюда `challenge=0x12345678 -> response=0xEE483B07`.
Соль зашита в клиент, значение challenge произвольное. Это позволит валидировать
ответ на сервере, когда дойдут руки.

Case `0x1D` читает `GEngineMinNetVersion`/`GEngineVersion` и отправляет `NMT_Hello`.

**`NMT_Challenge` не криптографический.** Клиент кладёт в `ClientResponse`
литерал `"0"` независимо от того, что мы прислали. Проверять нечего.

---

## 9. Что не работает и почему

| Приём | Результат |
|---|---|
| Software-брейк в сетевом коде клиента | клиент ловит INT3 собственным обработчиком, пишет `ErrorCode : <адрес>` и падает. Использовать только hardware-брейки (`type=access`) |
| Поиск xref на объект stat-таймера | ведёт в `.CRT$XCU`, тупик |
| Парсинг `.u` через UELib | файлы зашифрованы, весят ~1 КБ |
| Арифметика по адресам jumptable | дважды дала неверный номер сообщения. Только декомпиляция switch |

---

## 10. Дальнейший путь

```
1. Прочитать GPackageFileCache -> подтвердить +0x44 = Num
2. Дампнуть все записи: имя + GUID
3. Подставить GUID для Core, Generation = 2 (при отказе 1)
4. Убедиться, что клиент дошёл до Join после Uses, а не вместо него
5. Дослать полный список пакетов в правильном порядке
6. Проверить PackageMap->List.Num > 0
7. Найти UObject::NetIndex диффом снимка UObject до/после Uses
   (до Uses все NetIndex = -1, поле неотличимо)
8. Построить NetIndexMap для 1.13.1
9. Первый actor open: PlayerController
```

Шаг 7 нельзя делать раньше шага 6 — `UPackageMap::Compute()` не вызывается,
пока список пуст, и `NetIndex` в клиенте физически не существует.

Порядок пакетов в списке критичен: `ObjectBase` каждого следующего считается
кумулятивно от `ObjectCount` предыдущих. Ошибка в один пакет сдвигает всю карту
и выглядит как «пакеты доходят, ничего не происходит».

---

## 11. Состояние кода

Файл: `Emulator/DistrictServer/DistrictServer.cpp`, `ApbUdp.cpp`, `ApbUdp.h`.

Реализовано и работает:
`ControlReader` (курсор по bunch, несколько сообщений в одном bunch),
`AppendInt32` / `AppendFString` / `AppendGuid`,
`SendNetChallenge`, `SendNetWelcome`, `SendPackageUses`,
идемпотентный `SendAck` с дедупликацией по `packetId`,
общий packet-level ACK на любой пакет с data-bunch.

Диагностика `TracePacket0Layouts` и перебор кандидатов заголовка удалены —
заголовок зафиксирован.

Осталось от старой версии и подлежит чистке:
переменная окружения `RAPB_HANDSHAKE_PROBE` и связанный `HandshakeProbeMode` —
режимы `ack`/`complete`/`welcome` больше не нужны, рабочий путь один.
