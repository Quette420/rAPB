# netindex_probe.py — инструкция по использованию

## 1. Назначение

`netindex_probe.py` — runtime-инструмент для исследования APB Reloaded / UE3 непосредственно в памяти запущенного `APB.exe`.

Основные задачи:

- поиск `UObject` по имени;
- поиск `UClass`;
- поиск живых экземпляров класса;
- просмотр состояния reflection-visible полей конкретного объекта;
- просмотр структуры класса;
- получение offsets и типов `UProperty`;
- получение списка `UFunction` и их сигнатур;
- чтение `FunctionFlags` / `PropertyFlags`;
- восстановление actor-channel `FieldIndex`;
- прямой поиск живого `FClassNetCache`;
- исследование `PackageMap`;
- исследование `UObject::NetIndex`;
- исследование `UScriptStruct`;
- исследование SDD schemas;
- поиск native SDD-таблиц в памяти;
- экспорт найденных таблиц в CSV/JSON.

Скрипт работает с живым процессом и читает память. Адреса объектов действуют только для текущего запуска `APB.exe`.

---

# 2. Требования

Рядом со скриптом должен быть доступен:

```text
apb_reflect.py
```

Обычно рабочая директория:

```text
Tools\reflect\
```

Перед запуском:

```text
APB.exe должен быть запущен
```

Основная форма команды:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    <команда>
```

Для исследуемого клиента подтверждено:

```text
UObject::NetIndex = +0x24
```

Поэтому рекомендуется указывать:

```text
--netindex-off 0x24
```

явно.

---

# 3. Важнейшее правило: не путать адреса и индексы

UE3 использует несколько совершенно разных пространств.

## 3.1 Адрес UObject

Например:

```text
0x0F8DE9D0
```

Это адрес объекта в памяти текущего процесса.

Он перестанет быть актуальным после перезапуска клиента.

---

## 3.2 Адрес UClass

Если:

```text
APBGame.cAPBVehicle
Address = 0x0F8DE9D0
```

это адрес самого reflection-объекта:

```cpp
UClass* cAPBVehicleClass;
```

Это НЕ адрес конкретной машины.

---

## 3.3 Адрес runtime instance

Например:

```text
0x31234560 rworlddistrict.cAPBVehicle_17
```

Это уже конкретный экземпляр машины.

Его можно передать в:

```text
--instance-fields 0x31234560
```

---

## 3.4 CDO

Для класса обычно существует:

```text
APBGame.Default__cAPBVehicle
```

Это Class Default Object.

Он не является реальной spawned машиной, но содержит default state класса.

---

# 4. Три пространства network index

Нельзя их смешивать.

## UObject NetIndex

Локальный индекс объекта внутри network package:

```text
UObject + 0x24
```

Пример:

```text
APBGame.cAPBVehicle
localNet = 13637
```

---

## Global PackageMap NetIndex

Для объекта из известного network package:

```text
globalNet =
    Package.ObjectBase
    +
    UObject.NetIndex
```

Например:

```text
APBGame ObjectBase = 33506
localNet           = 13637

globalNet          = 47143
```

Это индекс UObject в `PackageMap`.

---

## FieldIndex

`FieldIndex` — отдельное пространство actor-channel replication.

Он принадлежит:

```text
FClassNetCache
```

и используется для:

```text
replicated UProperty
RPC / UFunction
```

Например:

```text
ServerSelectSpawnZone

UFunction UObject NetIndex = 10318
FieldIndex                 = 392
```

Эти числа совершенно не обязаны совпадать.

---

# 5. Быстрый рабочий cheat sheet

Найти UObject по точному имени:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --find ServerSelectSpawnZone
```

Найти runtime instances класса:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instances cAPBVehicle
```

Поля конкретного runtime instance:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instance-fields 0xADDRESS `
    --fields-inherited
```

Функции класса:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-functions cAPBVehicle `
    --functions-inherited
```

Network FieldIndex:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-netfields cAPBPawn
```

Полный class dump:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-class cAPBVehicle
```

Schema структуры:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct APBGame.cWeapon.WeaponType
```

Найти SDD native table по старому CSV:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cWeapon.WeaponType `
    --signature-csv WeaponTypes.csv
```

---

# 6. Поиск UObject по имени — `--find`

Команда:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --find ServerSelectSpawnZone
```

`--find` ищет точное:

```text
UObject.Name == заданное имя
```

Это не substring search.

Может найти несколько объектов с одинаковым short name.

Например:

```text
APBGame.cAPBPlayerController.ServerSelectSpawnZone
```

Вывод включает:

```text
full object path
package
UObject class
local NetIndex
memory address
PropertyOffset — если это UProperty
```

Другие примеры:

```powershell
--find Default__cAPBVehicle
```

```powershell
--find m_fHeatAmount
```

```powershell
--find Receive_DS2GC_ANS_DISTRICT_ENTER
```

Если имя неизвестно точно, лучше использовать специализированные substring-команды, например:

```text
--discover-classes
--classnetcache-find
--struct-find
```

---

# 7. Поиск классов по подстроке — `--discover-classes`

Например:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --discover-classes cSDD
```

Полезно для быстрого поиска семейства классов:

```text
cSDD
cSDDWeapon
cSDDItem
cSDDVehicle
...
```

Можно передать несколько фильтров:

```powershell
--discover-classes Weapon,Vehicle
```

---

# 8. Найти живые экземпляры класса — `--instances`

Основная команда:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instances cAPBVehicle
```

По умолчанию ищутся:

```text
target class
+
все subclasses
```

То есть если реальный объект имеет класс:

```text
cAPBVehicle
  -> cAPBVehicleCar
  -> cSomeConcreteVehicle
```

он всё равно будет найден.

Вывод показывает:

```text
object address
actual class
package
full path
local UObject NetIndex
global PackageMap NetIndex, если вычислим
```

---

# 9. Только exact class

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instances cAPBVehicle `
    --instances-exact
```

Тогда subclasses исключаются.

---

# 10. Ограничить количество instances

По умолчанию максимум:

```text
200
```

Можно изменить:

```powershell
--class-instances-limit 500
```

Пример:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instances Engine.Actor `
    --class-instances-limit 500
```

---

# 11. Отличие `--instances` от `--probe-class-instances`

Для обычной работы рекомендуется:

```text
--instances
```

Низкоуровневый диагностический режим:

```text
--probe-class-instances
```

Пример:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-class-instances APBGame.cPlayerCharacterSpawnZone
```

Он дополнительно показывает:

```text
target UClass
UClass inheritance
matching instances
package summary
PackageMap addressability
local/global NetIndex
```

Для исследования незнакомого класса этот режим полезнее.

---

# 12. Посмотреть состояние конкретного объекта

Сначала найти адрес:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instances cAPBVehicle
```

Получили, например:

```text
0x31234560
```

Теперь:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instance-fields 0x31234560
```

По умолчанию показываются только properties фактического класса объекта.

То же явно:

```powershell
--instance-fields 0x31234560 `
--fields-own
```

---

# 13. Поля объекта вместе с родителями

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instance-fields 0x31234560 `
    --fields-inherited
```

Например для машины будут объединены поля:

```text
Core.Object
Engine.Actor
Engine.Pawn
Engine.Vehicle
Engine.SVehicle
APBGame.cAPBVehicleBase
APBGame.cAPBVehicle
```

и отсортированы по runtime offset.

---

# 14. Что показывает `--instance-fields`

Для каждого `UProperty`:

```text
offset
property type
name
current runtime value
owner class
ElementSize
ArrayDim
PropertyFlags
type-specific metadata
```

Пример:

```text
0x554 IntProperty NetPlayerIndex = 0
```

или:

```text
0x44 BoolProperty bSomething =
    true
    raw=0x20000000
    mask=0x20000000
```

---

# 15. Какие значения умеет декодировать instance dump

Скалярные:

```text
ByteProperty
IntProperty
UIntProperty
FloatProperty
DoubleProperty
QWordProperty
UInt64Property
```

Имена:

```text
NameProperty
```

Строки:

```text
StrProperty / FString
```

UObject pointers:

```text
ObjectProperty
ClassProperty
ComponentProperty
InterfaceProperty
```

Для UObject выводится:

```text
pointer + Full.Object.Path
```

если pointer присутствует среди распознанных `GObjects`.

---

# 16. BoolProperty

UE3 bool часто хранится в общем `uint32`.

Поэтому вывод выглядит так:

```text
true
raw=0x00000120
mask=0x00000020
```

Это правильнее, чем читать bool как один byte.

---

# 17. ArrayProperty

Для `TArray` сейчас выводится header:

```text
TArray(
    Data=0x........
    Num=N
    Max=N
)
```

Элементы произвольного `TArray` автоматически рекурсивно не раскрываются.

---

# 18. StructProperty

Для общего `StructProperty` показываются:

```text
Struct type
raw bytes
```

Произвольный nested struct автоматически не интерпретируется как C++ layout.

Если нужен сам layout структуры, используй:

```text
--dump-struct
```

---

# 19. Ограничение instance dump

Команда показывает только:

```text
reflection-visible UProperty
```

Если внутри native C++ класса есть скрытое поле, которое не зарегистрировано в UE3 reflection, скрипт его не увидит.

То есть:

```text
UProperty layout
```

не всегда равен:

```text
полному native C++ layout
```

---

# 20. Список функций класса

Только функции, объявленные непосредственно в классе:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-functions cAPBVehicle `
    --functions-own
```

`--functions-own` фактически является default behavior.

---

# 21. Свои + inherited functions

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-functions cAPBVehicle `
    --functions-inherited
```

Будет обойдена вся class chain.

---

# 22. Что показывает `--class-functions`

Для каждой функции:

```text
return type
function name
parameter types
parameter names
parameter offsets
owner class
UState, если функция state-specific
UFunction address
local UObject NetIndex
global PackageMap NetIndex
FieldIndex, если функция networked
FunctionFlags
PropertySize / params frame
type-specific parameter metadata
```

---

# 23. State functions

UE3 может иметь одинаковую функцию в разных `UState`.

Например:

```text
cAPBPlayerController.Dead.ClientReceiveRespawnInfo
```

Скрипт учитывает такие state overrides и показывает state отдельно.

---

# 24. Сигнатура конкретного UFunction

Когда известно имя:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-function-params ServerSelectSpawnZone
```

Несколько сразу:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-function-params ServerSelectSpawnZone,ClientSpawnZoneElected,ServerAcknowledgePossession
```

---

# 25. `--probe-function-params` показывает

```text
UFunction address
local UObject NetIndex
UStruct::SuperField
UStruct::Children
PropertySize
parameters
return values
```

Для каждого параметра:

```text
property type
name
offset
ElementSize
ArrayDim
PropertyFlags
ObjectProperty class
StructProperty type
Enum metadata
```

Это основной режим для восстановления RPC wire semantics.

---

# 26. Получить FieldIndex класса

Основная команда:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-netfields cAPBPawn
```

Вывод формата:

```text
class cAPBPawn extends cAPBPawnAnimation
  base=44 ownSlots=66 fieldMax=110 (...) [APBGame] order=ordinal asc

    44 DoPayForHeatServerNative [function] ...
    45 OnPayForHeat             [function] ...
    ...
    58 m_PvPFlags               [property] ...
```

---

# 27. Что такое `base`

Если:

```text
base=44
```

это означает:

```text
первые 44 FieldIndex заняты родительской hierarchy
```

Первое собственное network field класса начинается с:

```text
44
```

---

# 28. Что такое `ownSlots`

```text
ownSlots=66
```

означает:

```text
класс добавляет 66 собственных network fields
```

---

# 29. Что такое `fieldMax`

```text
fieldMax = base + ownSlots
```

Например:

```text
44 + 66 = 110
```

Этот предел участвует в actor-channel:

```cpp
SerializeInt(FieldIndex, fieldMax);
```

---

# 30. Полный inherited FieldIndex space

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-netfields cAPBPawn `
    --netfields-inherited
```

Тогда выводятся handles всей hierarchy.

---

# 31. LIVE и DERIVED FieldIndex

Скрипт сначала пытается найти реальный:

```text
FClassNetCache
```

в heap.

Если найден:

```text
mapping source = LIVE heap FClassNetCache
```

Это лучший уровень доказательства.

Если live cache ещё не создан, скрипт пытается восстановить mapping через:

```text
UClass::NetFields
inheritance
PackageMap support
```

Тогда:

```text
mapping source =
DERIVED from UClass::NetFields + PackageMap
```

DERIVED полезен, но не является прямым heap proof.

---

# 32. Прямой live FClassNetCache probe

Когда требуется именно direct runtime proof:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-live-classnetcache `
    --classnetcache-class APBGame.cAPBPlayerController `
    --classnetcache-handles 80,138,139,260,261
```

Он ищет реальный heap `FClassNetCache`.

---

# 33. Искать network field по имени

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-live-classnetcache `
    --classnetcache-class APBGame.cAPBPlayerController `
    --classnetcache-find Spawn,Streaming,District
```

Ищутся подстроки в:

```text
Name
Full Path
```

реальных `FFieldNetCache` target class + super chain.

---

# 34. Прямая проверка конкретного FieldIndex

Например:

```powershell
--classnetcache-handles 392
```

может дать:

```text
392 ->
APBGame.cAPBPlayerController.ServerSelectSpawnZone
```

Это именно actor FieldIndex, не UObject NetIndex.

---

# 35. Полный dump класса

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-class cAPBVehicle
```

Можно полным path:

```powershell
--dump-class APBGame.cAPBVehicle
```

Если short name неоднозначен, скрипт покажет candidates и предложит указать `Package.Class`.

---

# 36. Что содержит `--dump-class`

Раздел:

```text
[CLASS]
```

содержит:

```text
UClass path
UClass address
package
UClass local UObject NetIndex
UClass global PackageMap NetIndex
```

ВАЖНО:

```text
Address
```

в этом разделе — адрес `UClass`, а не spawned object.

---

Раздел:

```text
[INHERITANCE]
```

показывает всю hierarchy.

---

Раздел:

```text
[NETWORK CACHE]
```

показывает:

```text
LIVE / DERIVED / unavailable
FClassNetCache address, если LIVE
GetMaxIndex
```

---

Раздел:

```text
[PROPERTIES]
```

показывает:

```text
offset
type
name
owner
UProperty address
local/global UObject NetIndex
FieldIndex
ConditionIndex
ElementSize
ArrayDim
flags
type metadata
```

---

Раздел:

```text
[FUNCTIONS]
```

показывает:

```text
signature
owner
state
UFunction address
local/global UObject NetIndex
FieldIndex
parameters
return values
```

---

# 37. Сохранить полный class dump в JSON

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-class cAPBVehicle `
    --dump-class-json cAPBVehicle.json
```

Удобно для:

```text
diff между builds
автоматической генерации SDK
индексации классов
последующей обработки
```

---

# 38. FunctionFlags

Для функции могут отображаться:

```text
Final
Defined
Net
NetReliable
Simulated
Native
Event
Static
Public
NetServer
NetClient
...
```

Например:

```text
0x40:Net
0x80:NetReliable
0x200000:NetServer
```

---

# 39. PropertyFlags

Например:

```text
0x1:Editable
0x20:Net
0x2000:Transient
0x400000:CtorLink
0x100000000:RepNotify
```

По ним удобно понимать replication semantics.

---

# 40. Осторожность с FunctionFlags

`FunctionFlags` читаются по текущей APB/UE3 layout.

При переходе на другую версию клиента желательно перепроверять известными RPC:

```text
Server... -> NetServer
Client... -> NetClient
```

---

# 41. PackageMap

Основной probe:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-packagemap
```

Он ищет активный:

```text
UNetConnection::PackageMap
```

и проверяет package list.

---

# 42. Проверить UPackage::NetObjects

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-package-net APBGame
```

Несколько packages:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-package-net Core `
    --probe-package-net Engine `
    --probe-package-net APBGame
```

Основной invariant:

```text
NetObjects[UObject.NetIndex] == UObject*
```

---

# 43. Package GUID

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-package-guids
```

Используется для проверки network package identity.

---

# 44. Диапазон поиска UPackage NetObjects

По умолчанию:

```text
--package-scan-start 0x40
--package-scan-end   0x400
```

Если исследуется другая UE3 build:

```powershell
--package-scan-start 0x20 `
--package-scan-end 0x600
```

---

# 45. Dump package

Диагностический режим:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-package APBGame
```

С output file:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-package APBGame `
    --out APBGame_dump.txt
```

Используется для низкоуровневой работы с объектами одного package.

---

# 46. UScriptStruct — найти nested structures класса

Например все weapon SDD structs:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --nested-structs cSDDWeapon
```

С полной schema:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --nested-structs cSDDWeapon `
    --structs-with-schema
```

---

# 47. Фильтр nested structs

Например только Vehicle:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --nested-structs cSDDItem `
    --struct-find Vehicle `
    --structs-with-schema
```

Несколько substring:

```powershell
--struct-find Weapon,Grenade
```

---

# 48. Dump конкретного UScriptStruct

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct APBGame.cWeapon.WeaponType
```

Вывод:

```text
ScriptStruct address
PropertySize
SuperStruct
field offsets
field types
ElementSize
ArrayDim
PropertyFlags
Bool BitMask
Enum type
Object class
Struct type
```

---

# 49. Struct inheritance

По умолчанию:

```text
только поля самого struct
```

Чтобы добавить SuperStruct:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct Some.Struct `
    --struct-fields-inherited
```

---

# 50. Что означает `PropertySize` структуры

Например:

```text
APBGame.cWeapon.WeaponType

PropertySize = 0x94
```

Для contiguous native rows это означает ожидаемый stride:

```text
148 bytes
```

То есть:

```cpp
row[i] = Data + i * 0x94;
```

если storage действительно представляет собой простой contiguous array этих structs.

---

# 51. SDD discovery

Общий режим:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --sdd-discover
```

По умолчанию ищутся слова:

```text
Weapon
Vehicle
Item
Ranged
Grenade
H2H
Setup
```

Можно задать свои:

```powershell
--sdd-discover Vehicle,Audio,Damage
```

Он показывает:

```text
cSDD-related properties
functions
nested structs
enums
global reflection matches
```

---

# 52. SDD class scan

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --sdd-scan cSDDWeapon
```

Команда:

1. находит `UClass`;
2. находит exact instances/CDO;
3. выбирает наиболее вероятный instance;
4. ищет reflection-visible table-like properties.

---

# 53. Что означает `[TABLE-LIKE PROPERTIES] <none>`

Это важный результат.

Он означает:

```text
в этом UObject нет reflected ArrayProperty/static-array,
которые скрипт может считать таблицей напрямую
```

Это НЕ означает:

```text
SDD данных нет
```

Данные могут находиться:

```text
в native static storage
в non-reflected pointer
в custom manager
в contiguous native arrays
в другой структуре/container
```

Для основных current SDD weapon/item/vehicle tables сейчас именно такой случай.

---

# 54. `--sdd-dump-table`

Этот режим применим только если `--sdd-scan` реально обнаружил table-like property.

Пример общего случая:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --sdd-class SomeSDDClass `
    --sdd-dump-table SomeTable `
    --sdd-csv SomeTable.csv
```

Если:

```text
Available table-like properties:
<пусто>
```

использовать `--sdd-dump-table` бессмысленно.

---

# 55. SDD preview

Если reflected table существует:

```powershell
--sdd-limit 5
```

показывает только первые строки.

---

# 56. Рекомендуемый способ поиска native SDD таблиц

Для текущего APB основной режим:

```text
--scan-struct-csv
```

Он сочетает:

```text
старую CSV таблицу
+
текущий live UScriptStruct
+
semantic memory validation
```

Важно:

```text
старый CSV НЕ определяет layout
```

Layout всегда берётся из текущей reflection schema.

CSV используется только как:

```text
signature oracle
```

для общих колонок.

---

# 57. Пример поиска GrenadeWeaponType

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cSDDWeapon.GrenadeWeaponType `
    --signature-csv GrenadeWeaponType.csv
```

---

# 58. Пример WeaponItemType

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cSDDItem.WeaponItemType `
    --signature-csv WeaponItemTypes.csv
```

---

# 59. Пример WeaponType

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cWeapon.WeaponType `
    --signature-csv WeaponTypes.csv
```

---

# 60. Пример VehicleSetupType

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cSDDVehicle.VehicleSetupType `
    --signature-csv VehicleSetupTypes.csv
```

---

# 61. Как работает `--scan-struct-csv`

Сначала текущий client reflection определяет:

```text
struct size / stride
field names
offsets
types
ArrayDim
Bool masks
enum metadata
```

Потом CSV headers сравниваются с текущими field names.

Участвуют только колонки, существующие и:

```text
в старом CSV
и
в текущем struct
```

Удалённые или переименованные поля автоматически игнорируются.

---

# 62. Memory anchors

Скрипт выбирает редкие ненулевые `IntProperty/UIntProperty` values из старого CSV.

Например:

```text
m_eWeaponType = 17
```

или другой достаточно характерный ID.

По этим значениям выполняется raw process memory scan.

Затем от найденного значения вычисляется потенциальный:

```text
row base
```

через текущий reflection offset.

---

# 63. Независимая semantic validation

Кандидат не принимается только потому, что совпало старое значение.

Дополнительно проверяются текущие live semantics:

```text
Bool masks
Byte enum ranges
FString headers
finite floats
reasonable enum-like ints
readability
```

Это защищает от случайного совпадения памяти.

---

# 64. Несколько независимых anchor rows

Скрипт берёт несколько разных old rows.

По умолчанию:

```text
--csv-anchor-rows 8
```

Для каждой:

```text
rowBase = найденный адрес - current field offset
```

После этого:

```text
tableBase = rowBase - oldRowIndex * currentStride
```

Если несколько независимых old rows указывают на один и тот же:

```text
tableBase
```

это очень сильная улика.

---

# 65. Как читать результат CSV scan

Пример хорошего кандидата:

```text
#00 Data=0x31200000
    votes=7
    goodPrefix=11/12
    fieldMatch=96.4%
    semantic=12/12
```

Особенно важны:

```text
votes
goodPrefix
fieldMatch
semantic
```

---

## `votes`

Сколько независимых old rows вывели точно один и тот же Data base.

Чем больше, тем лучше.

---

## `goodPrefix`

Сколько первых строк старой таблицы хорошо совпали по текущим shared fields.

Например:

```text
11/12
```

очень сильный результат.

---

## `fieldMatch`

Общая доля совпавших полей.

Например:

```text
98%
```

намного убедительнее:

```text
55%
```

---

## `semantic`

Сколько rows независимо выглядят валидными по текущей live schema.

---

# 66. Задать конкретный anchor

Например:

```powershell
--csv-anchor m_eWeaponType
```

Полная команда:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cWeapon.WeaponType `
    --signature-csv WeaponTypes.csv `
    --csv-anchor m_eWeaponType
```

Для items:

```powershell
--csv-anchor m_eInventoryItemType
```

Обычно сначала лучше использовать автоматический выбор.

---

# 67. Настройки CSV signature scan

Количество anchor rows:

```text
--csv-anchor-rows 8
```

Минимальная доля совпавших старых/current fields:

```text
--csv-min-row-match 0.70
```

Минимальная independent semantic sanity:

```text
--csv-min-semantic 0.85
```

Число первых rows для проверки inferred base:

```text
--csv-validate-prefix 12
```

Максимальное число raw hits одного anchor:

```text
--csv-max-hits 150000
```

Максимум результатов:

```text
--csv-max-results 20
```

---

# 68. Если scan ничего не находит

Сначала можно ослабить только CSV similarity:

```powershell
--csv-min-row-match 0.55
```

Например:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cSDDWeapon.GrenadeWeaponType `
    --signature-csv GrenadeWeaponType.csv `
    --csv-min-row-match 0.55
```

Не рекомендуется сразу сильно снижать:

```text
--csv-min-semantic
```

потому что это основная защита от случайной памяти.

---

# 69. Что означает отсутствие кандидатов

Возможные причины:

```text
rows были сильно изменены
порядок rows изменился
таблица больше не contiguous
старые значения полностью устарели
таблица лежит в custom container
таблица ещё не загружена
```

Отсутствие результата не означает отсутствие SDD данных.

---

# 70. Dump найденного contiguous Data

Если scan дал:

```text
Data=0x31200000
```

используется:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct-run APBGame.cSDDWeapon.GrenadeWeaponType `
    --data-address 0x31200000 `
    --row-count 8
```

---

# 71. Preview нескольких rows

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct-run APBGame.cSDDWeapon.GrenadeWeaponType `
    --data-address 0x31200000 `
    --row-count 8 `
    --table-limit 3
```

---

# 72. Экспорт найденной native table

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct-run APBGame.cSDDWeapon.GrenadeWeaponType `
    --data-address 0x31200000 `
    --row-count 8 `
    --table-csv GrenadeWeaponType_current.csv `
    --table-json GrenadeWeaponType_current.json
```

Здесь:

```text
--data-address
```

это адрес первой строки, а НЕ `TArray` header.

---

# 73. Осторожно с `--row-count`

Старое количество строк можно использовать как гипотезу, но не как доказательство.

Например старый CSV мог иметь:

```text
45 rows
```

а текущая версия:

```text
34
или 46
или совершенно другую организацию
```

Перед полным export желательно сначала проверить несколько rows.

---

# 74. Старый TArray scanner

В скрипте остаётся:

```text
--scan-struct-tarrays
```

Пример:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-tarrays APBGame.cWeapon.WeaponType `
    --struct-counts 33,34,35
```

Этот режим ищет структуры вида:

```cpp
TArray
{
    Data;
    Num;
    Max;
}
```

по предполагаемому `Num`.

---

# 75. Важное ограничение TArray scanner

Этот режим является эвристическим и может давать очень много false positives.

Само совпадение:

```text
Num=34
Max=34
```

почти ничего не доказывает.

Поэтому для current SDD рекомендуется:

```text
--scan-struct-csv
```

а не:

```text
--scan-struct-tarrays
```

---

# 76. Dump конкретного TArray

Использовать только если действительно известен адрес 12-byte TArray header:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct-tarray Some.Struct `
    --tarray-address 0xACTUAL_ADDRESS `
    --table-limit 8
```

Формат header:

```text
+0x00 Data
+0x04 Num
+0x08 Max
```

Адрес вроде:

```text
0x12345678
```

в примерах — просто placeholder. Его нельзя копировать как реальный адрес.

---

# 77. Экспорт TArray

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct-tarray Some.Struct `
    --tarray-address 0xACTUAL_ADDRESS `
    --table-csv table.csv `
    --table-json table.json
```

---

# 78. Определение GNames / GObjects

По умолчанию текущая конфигурация использует:

```text
GNames   = 0x12538938
GObjects = 0x1259EF3C
```

Можно переопределить:

```powershell
--gnames 0xADDRESS `
--gobjects 0xADDRESS
```

---

# 79. `--rebase`

Если переданы адреса из Ghidra image, а не runtime addresses:

```powershell
--rebase `
--ghidra-base 0x10900000
```

Скрипт вычислит:

```text
runtime delta =
    actual module base
    -
    Ghidra image base
```

и скорректирует `GNames/GObjects`.

По умолчанию:

```text
--gnames
--gobjects
```

считаются runtime addresses.

---

# 80. Другой executable

По умолчанию:

```text
--exe APB.exe
```

Если нужно:

```powershell
--exe SomeOther.exe
```

---

# 81. `--name-number-mode`

Доступны:

```text
mem
uelib
```

По умолчанию:

```text
mem
```

Для текущего исследования менять обычно не нужно.

---

# 82. Auto-detection NetIndex offset

Если не указывать:

```text
--netindex-off
```

скрипт может запускать старые discovery phases для поиска UObject layout/package invariants.

Также существует:

```text
--expect PKG=N
```

например:

```powershell
--expect Core=1546 `
--expect Engine=29382
```

Но для уже подтверждённого клиента проще и надёжнее:

```text
--netindex-off 0x24
```

---

# 83. Специализированные PlayerController probes

Остаются диагностические режимы:

```text
--probe-playercontroller-netfields
```

для исследования network fields `cAPBPlayerController`.

И:

```text
--probe-playercontroller-open
```

для:

```text
Default__cAPBPlayerController
global archetype NetIndex
bNetInitialRotation
NetPlayerIndex
```

Это специализированные RE-команды, не общие class inspection tools.

---

# 84. Рекомендуемый workflow — исследование неизвестного класса

Допустим интересует:

```text
cAPBVehicle
```

Шаг 1 — class overview:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-class cAPBVehicle
```

Шаг 2 — network handles:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-netfields cAPBVehicle `
    --netfields-inherited
```

Шаг 3 — functions:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-functions cAPBVehicle `
    --functions-inherited
```

Шаг 4 — runtime instances:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instances cAPBVehicle
```

Шаг 5 — state конкретного объекта:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --instance-fields 0xADDRESS `
    --fields-inherited
```

---

# 85. Workflow — неизвестный actor-channel FieldIndex

Есть:

```text
FieldIndex = 392
```

Известен actor class:

```text
cAPBPlayerController
```

Сначала:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --class-netfields cAPBPlayerController `
    --netfields-inherited
```

Находим:

```text
392 ServerSelectSpawnZone
```

Затем:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-function-params ServerSelectSpawnZone
```

Получаем аргументы RPC.

---

# 86. Workflow — direct proof FieldIndex

Если derived result недостаточен:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --probe-live-classnetcache `
    --classnetcache-class APBGame.cAPBPlayerController `
    --classnetcache-handles 392
```

Если настоящий live cache найден:

```text
392 -> UFunction
```

это direct runtime proof.

---

# 87. Workflow — неизвестный UObject network reference

Если в протоколе виден object index:

```text
global PackageMap index
```

НЕ искать его через:

```text
FieldIndex
```

Нужно:

```text
PackageMap
    ->
FPackageInfo range
    ->
local = global - ObjectBase
    ->
UPackage::NetObjects[local]
```

Для этого используются:

```text
--probe-packagemap
--probe-package-net
```

---

# 88. Workflow — найти archetype actor

Например нужен `cAPBVehicle`.

Сначала:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --find Default__cAPBVehicle
```

Получаем CDO и его NetIndex.

При actor-open очень часто нужен именно:

```text
Default__ClassName
```

а не сам:

```text
UClass ClassName
```

Не подменять CDO индекс UClass индексом без проверки.

---

# 89. Workflow — SDD оружия

Шаг 1:

```powershell
--discover-classes cSDD
```

Шаг 2:

```powershell
--nested-structs cSDDWeapon --structs-with-schema
```

Шаг 3:

```powershell
--dump-struct APBGame.cWeapon.WeaponType
```

Шаг 4:

```powershell
--scan-struct-csv APBGame.cWeapon.WeaponType `
--signature-csv WeaponTypes.csv
```

Шаг 5:

```text
оценить votes / fieldMatch / semantic
```

Шаг 6:

```powershell
--dump-struct-run ... `
--data-address 0xFOUND `
--row-count N `
--table-limit 5
```

Шаг 7:

```text
проверить значения вручную
```

Шаг 8:

```text
export CSV/JSON
```

---

# 90. Workflow — SDD машин

Schema:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct APBGame.cSDDVehicle.VehicleSetupType
```

Storage:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cSDDVehicle.VehicleSetupType `
    --signature-csv VehicleSetupTypes.csv
```

После найденного DATA base:

```powershell
--dump-struct-run APBGame.cSDDVehicle.VehicleSetupType `
--data-address 0xFOUND `
--row-count N
```

---

# 91. Workflow — SDD inventory items

Schema:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --dump-struct APBGame.cSDDItem.InventoryItemType
```

Weapon items:

```powershell
python netindex_probe.py `
    --netindex-off 0x24 `
    --scan-struct-csv APBGame.cSDDItem.WeaponItemType `
    --signature-csv WeaponItemTypes.csv
```

---

# 92. Confidence levels при работе со скриптом

Лучше мысленно делить результаты на три уровня.

## DIRECT LIVE

Прочитано непосредственно из текущей памяти:

```text
UObject
UClass
UProperty offset
UFunction params
runtime value
live FClassNetCache
PackageMap
```

Это лучший уровень.

---

## DERIVED

Восстановлено из нескольких live structures:

```text
FieldIndex через UClass::NetFields + inheritance
global PackageMap index
reconstructed class net map
```

Сильно, но это не прямой `FClassNetCache` proof.

---

## HEURISTIC

Результаты memory scanning:

```text
TArray candidate
CSV signature table candidate
raw native storage candidate
```

Их обязательно надо подтверждать dump'ом реальных rows.

---

# 93. Что считать хорошим подтверждением native table

Недостаточно:

```text
Num совпал со старой таблицей
```

Недостаточно:

```text
один ID совпал
```

Хорошее подтверждение:

```text
несколько independent anchors
одинаковый inferred Data base
много совпавших shared fields
валидные current enum values
валидные bool masks
валидные FString
несколько последовательных rows выглядят семантически правильно
```

И финально:

```text
CSV export действительно содержит узнаваемые игровые данные
```

---

# 94. Адреса нельзя сохранять как constants

После рестарта:

```text
UClass address
UFunction address
FClassNetCache address
runtime actor address
SDD Data address
```

могут измениться.

Для долгосрочной документации сохраняй прежде всего:

```text
Full.Object.Path
class hierarchy
property offsets
PropertySize
Function signature
local NetIndex
PackageMap relationship
FieldIndex
flags
struct layouts
```

---

# 95. Если команда находит `<bad:N>` у enum

Это означает:

```text
enum object/cardinality найден,
но декодирование имен UEnum entries для этой build ещё не полностью подтверждено
```

Само число элементов может быть полезным sanity check, но `<bad:N>` не следует трактовать как настоящее имя enum entry.

---

# 96. Если объект не найден

Сообщение:

```text
не найден
```

может означать:

```text
имя неверно
объект ещё не загружен
package ещё не загружен
используется другой subclass
объект вообще native/non-UObject
```

Для class поиска попробуй:

```text
--discover-classes
```

Для nested structs:

```text
--nested-structs
```

Для runtime actors:

```text
--instances BaseClass
```

---

# 97. Если `--instance-fields` отвергает адрес

Команда специально требует:

```text
address присутствует среди распознанных GObjects
```

Произвольный указатель на native structure туда передавать нельзя.

Для native structs используются:

```text
--dump-struct-run
--dump-struct-tarray
```

---

# 98. Как отличить UObject и native struct

UObject обычно имеет:

```text
Class
Outer
FName
ObjectFlags
NetIndex
```

и присутствует в `GObjects`.

Строка SDD таблицы:

```text
WeaponType row
VehicleSetupType row
```

обычно является просто областью памяти:

```text
Data + index * stride
```

и не является отдельным UObject.

Поэтому у неё нет собственного:

```text
UObject NetIndex
UClass pointer
Outer
Object name
```

---

# 99. Рекомендуемые основные команды для ежедневной работы

Если нужны реальные объекты:

```text
--instances
--instance-fields
```

Если нужен reflection класса:

```text
--dump-class
--class-functions
```

Если нужен RPC/replication:

```text
--class-netfields
--probe-live-classnetcache
--probe-function-params
```

Если нужна struct schema:

```text
--nested-structs
--dump-struct
```

Если нужны current SDD rows:

```text
--scan-struct-csv
--dump-struct-run
```

Если нужен PackageMap:

```text
--probe-packagemap
--probe-package-net
```

---

# 100. Короткая карта выбора команды

```text
Знаю имя UObject?
    -> --find

Знаю класс и хочу реальные экземпляры?
    -> --instances

Знаю адрес UObject?
    -> --instance-fields

Хочу полный reflection класса?
    -> --dump-class

Хочу функции?
    -> --class-functions

Хочу параметры одной функции?
    -> --probe-function-params

Хочу actor RPC/property handle?
    -> --class-netfields

Нужен direct runtime FieldIndex proof?
    -> --probe-live-classnetcache

Ищу nested UScriptStruct?
    -> --nested-structs

Хочу layout одного struct?
    -> --dump-struct

Ищу SDD schemas?
    -> --discover-classes cSDD
    -> --nested-structs cSDD...

Ищу реальные current SDD rows?
    -> --scan-struct-csv

Уже нашёл DATA base?
    -> --dump-struct-run

Уже точно знаю TArray header?
    -> --dump-struct-tarray

Исследую object PackageMap index?
    -> --probe-packagemap
    -> --probe-package-net
```

---

# 101. Рекомендуемая базовая дисциплина RE

Не переходить от одного найденного числа сразу к hardcode.

Лучший цикл:

```text
1. reflection discovery
2. определить точный тип объекта/поля/function
3. получить offsets/signature
4. определить правильное index space
5. direct live validation, если возможно
6. построить минимальную гипотезу
7. проверить runtime поведением
8. только после этого использовать значение в emulator/server
```

Особенно внимательно разделять:

```text
UClass address
runtime instance address
CDO address

UObject NetIndex
global PackageMap NetIndex
FieldIndex

reflection schema
native runtime storage
```

Это три наиболее частых источника ошибок при reverse engineering UE3.