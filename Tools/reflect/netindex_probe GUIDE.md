# `netindex_probe` — практический гайд по reflection/network RE APB Reloaded 1.13.1

## 1. Что это за инструмент

`netindex_probe_v12.py` читает **живую память запущенного 32-битного клиента APB Reloaded 1.13.1 / UE3 build 3908**.

Главная задача — не угадывать сетевые индексы по дампам, а связывать:

```text
UObject
   ↓
reflection
   ↓
UPackage::NetObjects
   ↓
UPackageMap
   ↓
FClassNetCache
   ↓
реальный wire index
```

Инструмент память **не изменяет**.

Адреса объектов вида:

```text
0x07298398
0x3D2DC570
```

относятся только к конкретному запуску процесса и после перезапуска клиента могут измениться.

Структурные offsets и индексы, подтверждённые инвариантами, от этого не меняются.

---

# 2. Самое важное: в UE3 есть несколько разных «индексов»

Нельзя смешивать их между собой.

## 2.1 `UObject::NetIndex`

Это NetIndex самого объекта внутри package.

Для APB:

```text
UObject::NetIndex = +0x24
```

Например:

```text
APBGame.cAPBPlayerController
    local UObject NetIndex = 12772
```

или:

```text
APBGame.Default__cAPBPlayerController
    local UObject NetIndex = 12773
```

---

## 2.2 Global PackageMap NetIndex

Это уже индекс объекта на wire при `UPackageMap::SerializeObject`.

Формула:

```text
GlobalNetIndex =
    FPackageInfo.ObjectBase
    +
    UObject.NetIndex
```

Для APBGame:

```text
ObjectBase = 33506
```

Поэтому:

```text
cAPBPlayerController UClass:

33506 + 12772 = 46278
```

а CDO/archetype:

```text
Default__cAPBPlayerController:

33506 + 12773 = 46279
```

Именно `46279` используется при actor-open.

---

## 2.3 `FFieldNetCache::FieldNetIndex`

Совершенно другое пространство индексов.

Оно используется внутри actor channel для:

```text
replicated property
RPC/UFunction
```

Например для live `cAPBPlayerController`:

```text
FieldNetIndex 80
    -> Engine.PlayerController.ServerSyncState

FieldNetIndex 138
    -> Receive_GC2DS_ASK_DISTRICT_ENTER

FieldNetIndex 139
    -> Receive_DS2GC_ANS_DISTRICT_ENTER

FieldNetIndex 158
    -> m_nActiveDailyActivityValue
```

Здесь число `139` **никак не связано** с `UFunction.NetIndex=7383`.

Одна и та же функция одновременно имеет:

```text
UObject::NetIndex = 7383
FieldNetIndex     = 139
```

Первое относится к объекту `UFunction` в package map.

Второе — к `FClassNetCache` конкретного actor class.

---

# 3. Базовый запуск

Сначала всегда полезно посмотреть help:

```powershell
python netindex_probe_v12.py --help
```

Для этой сборки подтверждён:

```text
UObject::NetIndex offset = 0x24
```

Поэтому рабочие команды обычно начинаются:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    ...
```

---

# 4. Как найти любой UObject по имени

Если известно имя объекта или поля:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --find NetIndex
```

Другие примеры:

```powershell
--find nDynRefsIndex
```

```powershell
--find cAPBPlayerController
```

```powershell
--find Receive_DS2GC_ANS_DISTRICT_ENTER
```

```powershell
--find bNetInitialRotation
```

Probe перебирает `GObjects`, восстанавливает:

```text
Name
Class
Outer
Package
Path
NetIndex
address
```

Главный принцип:

```text
имя само по себе недостаточно
```

Смотри полный path.

Например правильный объект:

```text
APBGame.cHostingPlayerController.Receive_DS2GC_ANS_DISTRICT_ENTER
```

а не просто любой объект с похожим именем.

---

# 5. Как понимать UObject path

UE3 объект имеет:

```text
UObject::Outer +0x2C
```

Через Outer chain строится path:

```text
Package.Class.Field
```

Например:

```text
APBGame
    ↓
cHostingPlayerController
    ↓
Receive_DS2GC_ANS_DISTRICT_ENTER
```

даёт:

```text
APBGame.cHostingPlayerController.Receive_DS2GC_ANS_DISTRICT_ENTER
```

Это один из самых сильных sanity-check при поиске reflection объектов.

---

# 6. Как найти поле класса

Допустим, нужно найти:

```text
Engine.Actor.bNetInitialRotation
```

Запускаем:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --find bNetInitialRotation
```

Нужно убедиться:

```text
path  = Engine.Actor.bNetInitialRotation
class = BoolProperty
```

После этого reflection metadata поля читается через `UProperty`.

Для этой сборки подтверждено:

```text
UProperty::ArrayDim       +0x44
UProperty::ElementSize    +0x48
UProperty::PropertyFlags  +0x4C  // uint64
UProperty::PropertySize   +0x54
UProperty::Offset         +0x64
```

Особенно важно:

```text
UProperty::Offset +0x64
```

говорит, где это поле находится внутри экземпляра объекта.

Например:

```text
PlayerController.NetPlayerIndex
    PropertyOffset = 0x554
```

Значит значение конкретного PlayerController находится:

```text
PlayerControllerAddress + 0x554
```

---

# 7. Type-specific metadata поля

Для многих subclasses `UProperty` дополнительная информация находится около:

```text
+0x74
```

## BoolProperty

Подтверждено:

```text
UBoolProperty::BitMask = +0x74
```

Пример:

```text
bNetInitialRotation

PropertyOffset = 0x44
BitMask        = 0x20000000
```

Чтение значения:

```cpp
raw = *(uint32*)(Object + 0x44);

value =
    (raw & 0x20000000) != 0;
```

---

## ByteProperty

`+0x74` может содержать:

```text
UEnum*
```

Если pointer null:

```text
raw BYTE
```

Если Enum существует — можно определить допустимые значения.

---

## ObjectProperty

Обычно type-specific pointer указывает на:

```text
PropertyClass*
```

---

## StructProperty

Указывает на:

```text
UStruct*
```

---

## ArrayProperty

Указывает на:

```text
Inner UProperty*
```

---

# 8. Как найти локальный UObject NetIndex

У каждого `UObject`:

```text
Object + 0x24
```

содержится local NetIndex.

Пример:

```text
APBGame.Default__cAPBPlayerController
local NetIndex = 12773
```

Это ещё **не готовое wire значение**.

Для wire object reference нужен package base.

---

# 9. Как узнать package map

Запуск:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-packagemap
```

На корректно подключённом клиенте сейчас получаем:

```text
Core
    Base=0
    Count=1575
    LocalGen=2
    RemoteGen=2

Engine
    Base=1575
    Count=31931
    LocalGen=2
    RemoteGen=2

APBGame
    Base=33506
    Count=30964
    LocalGen=2
    RemoteGen=2
```

После этого global index объекта считается просто:

```text
packageBase + localNetIndex
```

---

# 10. Как проверить UPackage::NetObjects

Если исследуется package:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-package-net APBGame
```

Probe ищет `UPackage::NetObjects` и проверяет главный инвариант:

```text
NetObjects[Object.NetIndex] == Object*
```

Именно этот инвариант намного сильнее простого «похоже на TArray».

Подтверждён layout:

```text
UPackage::NetObjects               +0x80
UPackage::CurrentNumNetObjects     +0x8C
UPackage::GenerationNetObjectCount +0x90
```

---

# 11. Как получить GUID package

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-package-guids
```

Подтверждено:

```text
UPackage::Guid = +0x6C
```

Для текущей сборки:

```text
Core
0FE825BC-4970D0BC-E10969A8-4C498AF9

Engine
8CC8C348-4498F5A3-05567188-79EC40E0

APBGame
726ED7C5-49A968E8-50E644AA-50ED3A99
```

---

# 12. Как найти UFunction

Допустим нужен:

```text
Receive_DS2GC_ANS_DISTRICT_ENTER
```

Сначала можно просто:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --find Receive_DS2GC_ANS_DISTRICT_ENTER
```

Правильный объект:

```text
Class = Function

Path =
APBGame.cHostingPlayerController.Receive_DS2GC_ANS_DISTRICT_ENTER
```

У него собственный UObject NetIndex:

```text
7383
```

Но ещё раз:

```text
7383 != RPC FieldNetIndex
```

Для actor wire нам впоследствии понадобился `139`.

---

# 13. Как получить сигнатуру любой UFunction

Главная команда:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-function-params Receive_DS2GC_ANS_DISTRICT_ENTER
```

Probe:

1. находит живой `UFunction`;
2. берёт:

```text
UStruct::Children +0x50
```

3. проходит linked list через:

```text
UField::Next +0x40
```

4. выбирает `UProperty` с:

```text
CPF_Parm
```

5. отдельно отмечает:

```text
CPF_ReturnParm
```

6. выводит:

```text
type
name
offset
ElementSize
ArrayDim
PropertySize
PropertyFlags
type-specific metadata
```

---

# 14. Пример живой сигнатуры

Для:

```text
Receive_DS2GC_ANS_DISTRICT_ENTER
```

получено:

```text
UStruct::PropertySize = 0xC

[0]
IntProperty
nReturnCode
Offset=0x0
ElementSize=4
Flags=Parm

[1]
IntProperty
nDistrictUID
Offset=0x4
ElementSize=4
Flags=Parm

[2]
IntProperty
nInstanceNo
Offset=0x8
ElementSize=4
Flags=Parm
```

Следовательно:

```cpp
Receive_DS2GC_ANS_DISTRICT_ENTER(
    int32 nReturnCode,
    int32 nDistrictUID,
    int32 nInstanceNo);
```

Это уже runtime-confirmed signature.

---

# 15. Важное отличие: сигнатура функции ≠ wire serialization RPC

Reflection говорит:

```text
какие параметры существуют
каких они типов
где расположены в params memory
```

Но wire RPC дополнительно следует правилам UE3 networking.

Для non-bool RPC parameters UE3 пишет:

```text
presence/default bit
```

и затем значение только если bit=true.

Например `int32 value=123`:

```text
1
0x0000007B
```

Поэтому нельзя автоматически сериализовать RPC тем же builder, которым сериализуется replicated IntProperty.

---

# 16. Как получить FieldNetIndex функции или replicated property

Самый надёжный способ — читать **реальный `FClassNetCache`**.

Для PlayerController:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-live-classnetcache
```

На текущем клиенте direct live результат:

```text
cAPBPlayerController

FieldsBase  = 158
Fields.Num  = 526
GetMaxIndex = 684
```

Super chain:

```text
cAPBPlayerController
    Base=158 Num=526 Max=684

cAPBPlayerControllerAnimation
    Base=157 Num=1 Max=158

cHostingPlayerController
    Base=127 Num=30 Max=157

Engine.PlayerController
    Base=26 Num=101 Max=127

Engine.Controller
    Base=21 Num=5 Max=26

Engine.Actor
    Base=0 Num=21 Max=21

Core.Object
    Base=0 Num=0 Max=0
```

---

# 17. Direct FieldNetIndex lookup

`v12` делает прямой аналог:

```cpp
FClassNetCache::GetFromIndex()
```

Получено:

```text
80 ->
Engine.PlayerController.ServerSyncState

138 ->
APBGame.cHostingPlayerController.Receive_GC2DS_ASK_DISTRICT_ENTER

139 ->
APBGame.cHostingPlayerController.Receive_DS2GC_ANS_DISTRICT_ENTER

158 ->
APBGame.cAPBPlayerController.m_nActiveDailyActivityValue
```

При этом читается непосредственно:

```text
FFieldNetCache.Field*
FFieldNetCache.FieldNetIndex
FFieldNetCache.ConditionIndex
```

Это самый сильный способ определить wire field handle.

---

# 18. Layout настоящего FClassNetCache

Для этого клиента stock UE3 layout подтвердился runtime-инвариантами:

```text
FClassNetCache

+0x00 TArray<FFieldNetCache*> RepProperties
+0x0C FieldsBase
+0x10 Super*
+0x14 RepConditionCount
+0x18 UClass* Class
+0x1C TArray<FFieldNetCache> Fields
```

`FFieldNetCache`:

```text
+0x00 UField* Field
+0x04 int32 FieldNetIndex
+0x08 int32 ConditionIndex

sizeof = 0x0C
```

И:

```text
GetMaxIndex =
    FieldsBase + Fields.Num
```

Для нашего PlayerController:

```text
158 + 526 = 684
```

Это число теперь DIRECT LIVE CONFIRMED.

---

# 19. Ограничение текущего v12

`--probe-live-classnetcache` сейчас специализирован на:

```text
APBGame.cAPBPlayerController
```

То есть для любого объекта / поля / функции `--find` и `--probe-function-params` уже generic.

Но direct `FClassNetCache` lookup пока hardcoded на PlayerController.

В функции `probe_live_classnetcache()` сейчас выбирается:

```python
_find_class_object(
    objs,
    groups,
    "APBGame",
    "cAPBPlayerController",
)
```

Для другого actor class можно временно заменить:

```text
"APBGame"
"cAPBPlayerController"
```

на нужные:

```text
Package
ClassName
```

Например концептуально:

```python
"APBGame",
"cAPBPawn"
```

После этого тот же алгоритм найдёт heap `FClassNetCache` этого класса.

Лучшее дальнейшее улучшение инструмента — сделать generic CLI:

```text
--probe-live-classnetcache APBGame.cAPBPawn
```

чтобы ничего не редактировать вручную.

---

# 20. Как искать network fields класса без direct cache

Есть вспомогательный режим:

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-playercontroller-netfields
```

Он использует:

```text
UStruct::SuperField +0x4C
UClass::NetFields   +0xF4
```

и реконструирует cache.

Для PlayerController реконструкция дала:

```text
684
```

а затем direct heap probe независимо подтвердил:

```text
684
```

Поэтому алгоритм оказался правильным.

Но правило:

```text
если доступен настоящий FClassNetCache,
доверяем ему больше, чем reconstruction.
```

---

# 21. Как найти «все поля класса»

Здесь важно различать два понятия.

## Reflection fields

Все обычные свойства/functions класса можно искать через:

```text
UStruct::Children
```

Цепочка:

```text
Class
  |
  +-> Children
        |
        +-> UField
             |
             +-> Next
```

`Children` включает reflection fields, не обязательно networked.

---

## Network fields

Для network mapping используется:

```text
UClass::NetFields
```

а окончательные wire handles находятся в:

```text
FClassNetCache::Fields
```

То есть:

```text
Children
    = reflection

NetFields
    = кандидаты для networking

FClassNetCache
    = фактическая network map класса
```

---

# 22. Практический рецепт: «хочу найти объект и его global NetIndex»

Допустим нужен:

```text
APBGame.SomeObject
```

### Шаг 1

```powershell
--find SomeObject
```

Получить:

```text
package
path
local NetIndex
```

### Шаг 2

```powershell
--probe-packagemap
```

Получить:

```text
APBGame.ObjectBase
```

### Шаг 3

Посчитать:

```text
global =
ObjectBase + local
```

### Шаг 4

Проверить:

```text
global < ObjectBase + ObjectCount
```

---

# 23. Практический рецепт: «хочу найти offset поля»

Например:

```text
SomeClass.SomeProperty
```

### 1.

```powershell
--find SomeProperty
```

### 2.

Убедиться:

```text
Outer = SomeClass
Class = IntProperty / BoolProperty / ...
```

### 3.

Прочитать:

```text
UProperty::Offset @ PropertyObject+0x64
```

Это offset значения внутри экземпляра `SomeClass`.

Для bool также:

```text
BitMask @ BoolPropertyObject+0x74
```

---

# 24. Практический рецепт: «хочу сигнатуру функции»

```powershell
python netindex_probe_v12.py `
    --netindex-off 0x24 `
    --probe-function-params FunctionName
```

Смотреть:

```text
PARAMETERS
RETURN PARAMETERS
PropertySize
Offset
ElementSize
PropertyFlags
```

Если несколько функций с таким именем — выбирать по полному:

```text
Package.Class.Function
```

---

# 25. Практический рецепт: «хочу RPC FieldNetIndex»

Нужно знать actor class, по которому открыт channel.

Например actor:

```text
cAPBPlayerController
```

### 1. Найти функцию

```text
--find RPCName
```

### 2. Убедиться, что она находится в actor class или superclass.

### 3. Получить live `FClassNetCache`.

Для PC:

```powershell
--probe-live-classnetcache
```

### 4. Найти:

```text
Field* == нужный UFunction*
```

### 5. Взять:

```text
FFieldNetCache.FieldNetIndex
```

### 6. Для `SerializeInt(FieldIndex, Max)` использовать:

```text
Max = FClassNetCache::GetMaxIndex()
```

Например:

```text
field=139
max=684
```

---

# 26. Практический рецепт: «wire пакет начинается с неизвестного handle»

Если actor bunch содержит:

```text
field index X
```

нельзя сразу искать объект с:

```text
UObject.NetIndex == X
```

Это неправильно.

Нужно:

```text
actor channel
    ↓
Actor->Class
    ↓
FClassNetCache for that class
    ↓
GetFromIndex(X)
```

Например wire:

```text
138
```

дал:

```text
Receive_GC2DS_ASK_DISTRICT_ENTER
```

---

# 27. Практический рецепт: «replicated property или RPC?»

После разрешения `FieldNetIndex` смотри класс объекта.

Если:

```text
Class = Function
```

это RPC.

Если:

```text
IntProperty
BoolProperty
ObjectProperty
StructProperty
...
```

это property replication.

Например:

```text
138 -> Function
```

RPC.

А:

```text
158 -> IntProperty
```

replicated property.

Это исправило нашу раннюю ошибку, когда bunch с `158` был ошибочно принят за RPC.

---

# 28. Как оценивать качество доказательства

Используй три уровня.

## CONFIRMED DIRECT LIVE

Пример:

```text
FClassNetCache.GetMaxIndex=684
```

потому что число прочитано прямо из heap cache и проверено через массив реальных `FFieldNetCache`.

Или:

```text
UProperty::Offset=+0x64
```

потому что reflection поля `NetIndex`, `InternalIndex`, `nDynRefsIndex` замкнулись на реальные offsets объекта.

---

## STRONGLY DERIVED

Например найден TArray, у которого:

```text
256/256 элементов
```

имеют правильный тип и Outer.

Это очень сильный кандидат, но всё ещё reconstruction/invariant.

---

## HYPOTHESIS

Например:

```text
«первый actor channel скорее всего ch=1»
```

до фактической проверки клиентом.

После успешного actor-open это можно повысить по уровню уверенности.

---

# 29. Как не получить ложное подтверждение

Плохой критерий:

```text
«на offset лежит красивое число»
```

Хороший критерий:

```text
offset работает на сотнях/тысячах объектов
```

Например `UBoolProperty::BitMask`:

```text
+0x74

7781 / 7782 BoolProperty
имеют one-hot mask
```

Это сильный invariant.

Другой пример:

```text
NetObjects[Object.NetIndex] == Object*
```

для всего package.

---

# 30. Подтверждённые offsets, которые сейчас можно использовать как базу

## UObject

```text
sizeof(UObject) 0x40

+0x20 InternalIndex
+0x24 NetIndex
+0x28 nDynRefsIndex
+0x2C Outer
+0x30 FName.Index
+0x34 FName.Number
+0x38 Class
```

## UField / UStruct

```text
UField::Next       +0x40

UStruct::SuperField +0x4C
UStruct::Children   +0x50
UStruct::PropertySize +0x54
```

`SuperField +0x4C` очень сильно runtime-валидирован полной реальной class chain.

## UProperty

```text
+0x44 ArrayDim
+0x48 ElementSize
+0x4C PropertyFlags [uint64]
+0x54 PropertySize
+0x64 Offset
```

## BoolProperty

```text
+0x74 BitMask
```

## UPackage

```text
+0x6C Guid
+0x80 NetObjects
+0x8C CurrentNumNetObjects
+0x90 GenerationNetObjectCount
```

## UNetConnection

```text
+0xE0 PackageMap
```

## UPackageMap

```text
+0x40 List.Data
+0x44 List.Num
```

## FPackageInfo

```text
sizeof = 0x50

+0x08 Parent
+0x0C Guid
+0x1C ObjectBase
+0x20 ObjectCount
+0x24 LocalGeneration
+0x28 RemoteGeneration
```

## FClassNetCache

```text
+0x0C FieldsBase
+0x10 Super
+0x14 RepConditionCount
+0x18 Class
+0x1C Fields
```

## FFieldNetCache

```text
sizeof = 0x0C

+0x00 Field
+0x04 FieldNetIndex
+0x08 ConditionIndex
```

---

# 31. Что пока не надо считать подтверждённым автоматически

Не смешивать с proven offsets:

```text
FPackageInfo::PackageFlags +0x2C
PKG_Need = 0x8000

UNetConnection::Download +0x8F9C
UDownload::Connection +0x40
UDownload::_field_0x5C
```

Они имеют другой уровень доказательства.

---

# 32. Краткий cheat sheet

## Найти UObject

```powershell
python netindex_probe_v12.py `
  --netindex-off 0x24 `
  --find ObjectName
```

## Найти property

```powershell
--find PropertyName
```

Смотреть:

```text
Path
Property class
NetIndex
```

`PropertyOffset` читается через:

```text
UProperty + 0x64
```

## Найти function

```powershell
--find FunctionName
```

## Получить signature

```powershell
--probe-function-params FunctionName
```

## Проверить package NetObjects

```powershell
--probe-package-net APBGame
```

## GUID packages

```powershell
--probe-package-guids
```

## Active PackageMap

```powershell
--probe-packagemap
```

## PlayerController actor-open metadata

```powershell
--probe-playercontroller-open
```

## Reconstruction PlayerController network fields

```powershell
--probe-playercontroller-netfields
```

## Настоящий live PlayerController `FClassNetCache`

```powershell
--probe-live-classnetcache
```

---

# 33. Ментальная модель

Когда смотришь на неизвестный wire value, задавай вопросы именно в таком порядке:

```text
Что это за channel?
        ↓
Какой Actor привязан к channel?
        ↓
Какой UClass у Actor?
        ↓
Какой FClassNetCache используется?
        ↓
Какой GetMaxIndex?
        ↓
Какой FFieldNetCache соответствует handle?
        ↓
Field — Function или Property?
        ↓
Если Function:
    какие UProperty parameters?
        ↓
Как каждый parameter NetSerialize'ится?
```

А для UObject reference:

```text
Какой package?
        ↓
Какой local UObject::NetIndex?
        ↓
Какой PackageMap ObjectBase?
        ↓
GlobalNetIndex = Base + Local
```

Это две разные ветки исследования, и смешивать их нельзя.

---

# 34. Текущее состояние нашего district-enter RE

Уже закрыто:

```text
handshake                       PASS
NMT_Uses                        PASS
PackageMap                      PASS
NMT_Welcome                     PASS
NMT_Join                        PASS
PlayerController archetype      PASS
actor-open                      PASS
HandleClientPlayer              PASS
LocalPlayer_0                   PASS

live cAPBPlayerController FClassNetCache:
    GetMaxIndex=684             CONFIRMED

GC2DS_ASK_DISTRICT_ENTER:
    FieldNetIndex=138           CONFIRMED

DS2GC_ANS_DISTRICT_ENTER:
    FieldNetIndex=139           CONFIRMED

signature:
    int32 nReturnCode
    int32 nDistrictUID
    int32 nInstanceNo           CONFIRMED
```

Текущий эксперимент:

```text
client:
    RPC 138
        GC2DS_ASK_DISTRICT_ENTER
            ↓
server:
    RPC 139
        DS2GC_ANS_DISTRICT_ENTER(
            0,
            districtUID,
            1)
```

Причём каждый non-bool RPC parameter должен иметь:

```text
presence bit = 1
value
```

Главный следующий end-to-end критерий:

```text
Receive [DS2GC_ANS_DISTRICT_ENTER]
```

и смена:

```text
DISTRICT_ENTER2_IN_PROGRESS
```

на следующую стадию.