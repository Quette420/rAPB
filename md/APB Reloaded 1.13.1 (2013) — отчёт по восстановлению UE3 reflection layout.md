# APB Reloaded 1.13.1 (2013) — отчёт по восстановлению UE3 reflection layout

## 1. Цель исследования

Цель — восстановить reflection-структуры UE3 клиента **APB: Reloaded 1.13.1 (2013)** и адаптировать под эту версию `polivilas/UnrealEngineSDKGenerator`.

Основные задачи:

- определить `GNames` и `GObjects`;
- восстановить layout `UObject`, `UField`, `UStruct`, `UProperty`, `UFunction`, `UClass`;
- определить размеры reflection-классов;
- восстановить offsets, необходимые SDK generator;
- в дальнейшем перечислить классы, свойства и функции офлайн из полноценного memory dump либо из работающего процесса при допустимом способе доступа.

Основной анализ ведётся статически в Ghidra по `APB_dump.exe`.

---

# 2. Исходная версия generator

Используется:

`https://github.com/polivilas/UnrealEngineSDKGenerator`

Target из репозитория относится к более поздней APB 1.19.4.758903 и **не может использоваться как готовый layout** для APB 1.13.1.

Полезные target-файлы:

```text
Target/AllPointsBulletin/NamesStore.cpp
Target/AllPointsBulletin/ObjectsStore.cpp
Target/AllPointsBulletin/EngineClasses.hpp
Target/AllPointsBulletin/Generator.cpp
```

Generator уже был успешно собран после:

```text
Windows SDK -> установленная Windows 10 SDK
v141 -> v143
C++17
std::experimental::filesystem -> std::filesystem
```

DLL:

```text
E:\ProgrammingProjects\Cpp\UnrealEngineSDKGenerator\
x86\Debug\AllPointsBulletin.dll
```

---

# 3. Ограничение текущего APB_dump.exe

Несмотря на название, исследуемый `APB_dump.exe` в Ghidra выглядит как восстановленный PE/module image, а не полноценный process memory dump.

Mapped ranges примерно:

```text
108F0000  headers
108F1000  .text
119F0000  .rdata
120E3000  .data
125FE000  .tls
12600000  .rsrc
...
```

Но heap-области, на которые указывают реальные UE3 globals, отсутствуют.

Например:

```text
GNames.Data   = 0x33F90000
GObjects.Data = 0x0E340000
```

Эти адреса в Ghidra dump не mapped.

Следствие:

> Статически можно восстановить globals и layout, но непосредственно перечислить все runtime `FNameEntry`/`UObject` из одного `APB_dump.exe` нельзя.

Для полной offline enumeration нужен полноценный memory dump, содержащий эти heap ranges.

---

# 4. GNames

## Адрес

```text
GNames = 0x12538938
```

Найден через сигнатуру:

```asm
8B 0D ?? ?? ?? ?? 83 3C 81 00
```

Конкретный код:

```asm
110079DC  MOV ECX,[0x12538938]
...
```

Runtime TArray:

```text
GNames @ 0x12538938

Data  = 0x33F90000
Count = 0x299FF = 170495
Max   = 0x2B011 = 176145
```

Статус:

```text
CONFIRMED
```

---

# 5. GObjects

## Адрес

```text
GObjects = 0x1259EF3C
```

Найден в object subsystem shutdown / cleanup routine:

```asm
MOV EAX,[0x1259EF3C]
MOV ESI,[EAX+EDI*4]
TEST ESI,ESI
```

Для APB 1.13.1 сигнатура:

```text
A1 ?? ?? ?? ?? 8B 34 B8 85 F6
```

В target APB 1.19 было:

```text
A1 ?? ?? ?? ?? 8B 34 B0 85 F6
```

Различие `B0 -> B8` связано с другим index register.

Runtime:

```text
GObjects @ 0x1259EF3C

Data  = 0x0E340000
Count = 0x949CD = 608717
Max   = 0xC96B8 = 825016
```

Статус:

```text
CONFIRMED
```

Для `ObjectsStore.cpp` APB 1.13.1 следует использовать:

```cpp
auto address = FindPattern(
    GetModuleHandleW(nullptr),
    reinterpret_cast<const unsigned char*>(
        "\xA1\x00\x00\x00\x00\x8B\x34\xB8\x85\xF6"
    ),
    "x????xxxxx"
);
```

Извлечение pointer operand через `address + 1` остаётся корректным.

---

# 6. Связанный объектный bit array

По адресу:

```text
0x1259F000
```

находится структура с тем же количеством элементов, что и GObjects.

Она **не является GObjects**.

Код использует её как bitmap/bit-array, индексируемый через:

```text
UObject::InternalIndex
```

Например:

```asm
MOV param_1,[ESI+20]
SAR EAX,5
OR [bitArray + EAX*4],EDX
```

То есть это вспомогательная per-object bitset.

---

# 7. UObject APB 1.13.1

Текущий подтверждённый layout:

```cpp
struct FName
{
    int32_t Index;          // +0x00 CONFIRMED
    int32_t Number;         // +0x04 CONFIRMED
};

class UObject
{
public:
    void*     VTable;       // 0x00

    UObject*  HashNext;     // 0x04 CONFIRMED

    uint64_t  ObjectFlags;  // 0x08 CONFIRMED

    UObject*  HashOuterNext;// 0x10 CONFIRMED

    uint8_t   Unknown14[0x0C];
                              // 0x14-0x1F

    int32_t   InternalIndex;// 0x20 CONFIRMED

    uint32_t  Unknown24;    // 0x24

    int32_t   DynRefsIndex; // 0x28
                              // semantics confirmed,
                              // exact historical name inferred

    UObject*  Outer;        // 0x2C CONFIRMED

    FName     Name;         // 0x30 CONFIRMED
                              // Index  +0x30
                              // Number +0x34

    UClass*   Class;        // 0x38 CONFIRMED

    uint32_t  Unknown3C;    // 0x3C
};

// sizeof(UObject) = 0x40 CONFIRMED
```

---

# 8. Обоснование UObject offsets

## 8.1 HashNext = +0x04

В object registration routine `FUN_11068f50`:

```asm
MOV ECX,[EDI+34]
XOR ECX,[EDI+30]
AND ECX,7FFF

MOV EAX,[hashTable + ECX*4]
MOV [EDI+04],EAX
MOV [hashTable + ECX*4],EDI
```

Это стандартная insertion chain для hash по имени.

Статус:

```text
CONFIRMED
```

---

## 8.2 ObjectFlags = +0x08/+0x0C

Пара DWORD по `+0x08/+0x0C` постоянно обрабатывается как единый 64-bit flag value.

Статус:

```text
CONFIRMED
```

---

## 8.3 HashOuterNext = +0x10

В той же registration routine:

```asm
MOV ECX,[EDI+2C]
SAR ECX,4

XOR ECX,[EDI+34]
XOR ECX,[EDI+30]
AND ECX,7FFF

MOV EAX,[secondHash + ECX*4]

MOV [EDI+10],EAX
MOV [secondHash + ECX*4],EDI
```

Hash вычисляется из:

```text
Outer + Name
```

Статус:

```text
CONFIRMED
```

---

## 8.4 InternalIndex = +0x20

Критический registration fragment:

```asm
MOV ESI,EAX

MOV ECX,[GObjects.Data]
MOV [ECX+ESI*4],EDI

MOV [EDI+20],ESI
```

То есть:

```cpp
GObjects[Index] = Object;
Object->InternalIndex = Index;
```

Статус:

```text
CONFIRMED
```

---

## 8.5 поле +0x28

Поведение:

```text
-1 = объект отсутствует во вспомогательном массиве
иначе = индекс объекта в массиве
```

При swap-remove индекс перемещённого объекта исправляется:

```asm
MOV [movedObject+28],newIndex
```

То есть семантика membership/back-reference index подтверждена.

Вероятное UE3 имя:

```cpp
nDynRefsIndex
```

Но оригинальное имя из исходников конкретной APB-сборки непосредственно не доказано.

Статус:

```text
SEMANTICS CONFIRMED
NAME INFERRED
```

---

## 8.6 Outer = +0x2C

Независимо найдено несколько self-chain:

```asm
MOV EAX,[Object+2C]

loop:
...
MOV EAX,[EAX+2C]
```

Также `+0x2C` участвует в hash `(Outer >> 4) ^ Name`.

Статус:

```text
CONFIRMED
```

---

## 8.7 FName = +0x30

Прямое использование:

```asm
MOV EAX,[ESI+30]
MOV ECX,[GNames.Data]
MOV EAX,[ECX+EAX*4]
```

Следовательно:

```text
+0x30 = FName.Index
```

Другие места используют:

```text
+0x30
+0x34
```

как двух-DWORD `FName`.

Итого:

```cpp
FName Name; // +0x30
```

Статус:

```text
CONFIRMED
```

---

## 8.8 Class = +0x38

Классический `IsA`:

```asm
MOV EAX,[Object+38]

loop:
CMP EAX,WantedClass
JZ  found

MOV EAX,[EAX+4C]
TEST EAX,EAX
JNZ loop
```

Статус:

```text
CONFIRMED
```

---

# 9. UField

Был найден полноценный reflection traversal:

```asm
MOV ESI,[EDI+50]

loop:
TEST ESI,ESI
JZ ...

MOV EAX,[ESI+38]       ; Field->Class
...
MOV ESI,[ESI+40]       ; Field->Next
TEST ESI,ESI
JNZ loop
```

Такой паттерн повторяется независимо в нескольких функциях.

Итого:

```cpp
class UField : public UObject
{
public:
    UField* Next;       // 0x40 CONFIRMED
};
```

Следовательно:

```text
sizeof(UObject) = 0x40
sizeof(UField)  = 0x44
```

Размер `UField=0x44` впоследствии независимо подтвердился через native class registration. Для `Field` в `FUN_1109f070` в тот же size argument передаётся `0x44`.

---

# 10. UStruct

Подтверждено:

```cpp
class UStruct : public UField
{
public:
    uint8_t  Unknown44[0x08];

    UStruct* SuperField;     // 0x4C CONFIRMED
    UField*  Children;       // 0x50 CONFIRMED
    uint32_t PropertySize;   // 0x54 CONFIRMED

    // remainder until sizeof == 0x88
};
```

---

## 10.1 SuperField = +0x4C

Классический `IsA`:

```asm
MOV EAX,[Object+38]

loop:
CMP EAX,WantedClass
JZ ...

MOV EAX,[EAX+4C]
TEST EAX,EAX
JNZ loop
```

Это superclass chain.

Статус:

```text
CONFIRMED
```

---

## 10.2 Children = +0x50

Найден полный traversal:

```asm
MOV ESI,[Struct+50]

loop:
MOV EAX,[ESI+38]       ; child->Class
...
MOV ESI,[ESI+40]       ; child->Next
```

То есть:

```cpp
for (UField* Field = Struct->Children;
     Field;
     Field = Field->Next)
```

Статус:

```text
CONFIRMED
```

---

## 10.3 PropertySize = +0x54

Caller:

```asm
MOV EAX,[EDI+4C]       ; SuperField
TEST EAX,EAX
JZ ...

MOV EAX,[EAX+54]
PUSH EAX
...
CALL FUN_110a15c0
```

Внутри `FUN_110a15c0` значение последнего аргумента используется как верхняя граница layout properties.

Для child property вычисляется:

```cpp
Offset =
    Property->ElementSize * ArrayIndex +
    Property->Offset;

if (Offset + Property->ElementSize <= param_4)
{
    ...
}
```

А `param_4` caller получает из:

```cpp
Struct->SuperField->field54
```

Следовательно поле является inherited structure/property layout size.

Статус:

```text
UStruct::PropertySize = 0x54 CONFIRMED
```

---

# 11. Размер UStruct

Это теперь подтверждено native reflection registration.

`Struct` создаётся через:

```asm
PUSH L"Struct"
PUSH 0x800000
PUSH 0x10000000
PUSH 0x88
PUSH 0
CALL FUN_1109cec0
```



Сравнение с классами, размер которых уже независимо известен, показывает, что этот argument действительно является размером экземпляра reflection-класса.

Итого:

```text
sizeof(UStruct) = 0x88 CONFIRMED
```

Это очень важное отличие от target APB 1.19.4, где используемый generator layout подразумевает существенно больший `UStruct`.

---

# 12. UProperty

Из `FUN_110a15c0` восстановлены как минимум:

```cpp
class UProperty : public UField
{
public:
    int32_t ArrayDim;       // +0x44 CONFIRMED
    int32_t ElementSize;    // +0x48 CONFIRMED

    uint8_t Unknown4C[0x18];

    int32_t Offset;         // +0x64 CONFIRMED

    // remainder
};
```

Обоснование:

```cpp
for (i = 0; i < Property->ArrayDim; i++)
{
    elementOffset =
        Property->ElementSize * i +
        Property->Offset;

    if (elementOffset + Property->ElementSize
        <= StructSize)
    {
        ...
    }
}
```

То есть:

```text
+0x44 = ArrayDim
+0x48 = ElementSize
+0x64 = Offset
```

---

# 13. Размер UProperty

Native registration:

```asm
PUSH L"Property"
PUSH 0x8
PUSH 0x10000001
PUSH 0x74
PUSH 0
CALL FUN_1109cec0
```



Итого:

```text
sizeof(UProperty) = 0x74 CONFIRMED
```

Это отлично согласуется с найденным `Offset @ +0x64`.

---

# 14. Native reflection class registration

Очень важная функция:

```text
FUN_1109cec0
```

Используется при регистрации intrinsic UE3 classes.

Сравнение вызовов показывает, что один из аргументов является размером instance класса.

Подтверждённые регистрации:

```text
Object   -> 0x40
Field    -> 0x44
Struct   -> 0x88
Function -> 0xA8
Property -> 0x74
Class    -> 0x1CC
```

---

## 14.1 Object

Регистрация:

```asm
PUSH L"Object"
PUSH 0
PUSH 0x101
PUSH 0x40
PUSH 0
CALL FUN_1109cec0
```



Итого:

```text
sizeof(UObject) = 0x40
```

Это независимо подтверждает ранее восстановленный layout.

---

## 14.2 Field

```text
sizeof(UField) = 0x44
```



---

## 14.3 Struct

```text
sizeof(UStruct) = 0x88
```



---

## 14.4 Function

Декомпиляция:

```cpp
undefined4* __cdecl FUN_1109f0d0(undefined4 param_1)
{
    void* this;
    undefined4* result;

    this =
        (void*)(**(code **)
            (*DAT_12538a04 + 0x48))
            (0x1cc, 8);

    if (this != nullptr)
    {
        result = FUN_1109cec0(
            this,
            0,
            0xa8,
            0x10000000,
            0x40,
            L"Function",
            param_1,
            L"Engine",
            0x4000,
            0x4084084,
            FUN_1109f7f0,
            &LAB_110a4630,
            FUN_10e0b1f0
        );

        return result;
    }

    return nullptr;
}
```

Assembler registration также показывает `0xA8` в том же size argument.

Поскольку:

```text
Object   -> known size 0x40
Field    -> known size 0x44
Struct   -> structurally consistent 0x88
Property -> structurally consistent 0x74
Class    -> 0x1CC
```

используют тот же argument slot, назначение аргумента практически однозначно.

Итого:

```text
sizeof(UFunction) = 0xA8 CONFIRMED
```

Это один из важнейших последних результатов.

---

# 15. Следствие для UFunction layout

Target APB 1.19.4 `EngineClasses.hpp` нельзя использовать для `UFunction` напрямую.

В target layout:

```text
UStruct заканчивается примерно на 0xA0
UFunction имеет поля вплоть до ~0xBC
```

Но APB 1.13.1:

```text
sizeof(UStruct)   = 0x88
sizeof(UFunction) = 0xA8
```

Следовательно весь уникальный хвост `UFunction` APB 1.13.1 помещается в:

```text
0x88 .. 0xA7
```

То есть всего:

```text
0x20 bytes
```

после `UStruct`.

Это резко сужает дальнейший поиск.

---

# 16. UClass

Native registration `Class`:

```asm
PUSH L"Class"
PUSH 0x400000
PUSH 0x10000000
PUSH 0x1CC
PUSH 0
CALL FUN_1109cec0
```



Итого:

```text
sizeof(UClass) = 0x1CC CONFIRMED
```

Это также объясняет, почему все intrinsic class creators сначала делают allocation:

```cpp
allocator(0x1CC, 8)
```

Они выделяют объект `UClass`, а затем инициализируют его как descriptor конкретного reflection class.

Например для Function:

```text
allocate sizeof(UClass) = 0x1CC
descriptor says represented class size = 0xA8
```

То есть:

```text
сам объект descriptor: UClass = 0x1CC
описываемый им объект: UFunction = 0xA8
```

---

# 17. Важная поправка к предыдущему поиску UFunction

Ранее выполнялся эвристический поиск IsA-контекстов по offsets, похожим на target APB 1.19.

Он дал:

```text
IsA-like patterns = 3679
Candidates        = 59
```

Но лучшие совпадения оказались ложными.

Например `+0xA8/+0xB8` использовались как `float`:

```asm
ADDSS XMM1,[ESI+A8]
MOVSS [ESI+A8],XMM1
...
ADDSS XMM1,[ESI+B8]
```



Следовательно:

> Нельзя определять UFunction только по совпадению offsets с target build.

Нужен type-specific anchor.

---

# 18. Reflection string `"Function"`

Было найдено:

```text
UTF16 L"Function"
```

с прямой ссылкой из:

```text
FUN_1109f0d0
```

Это именно intrinsic `UFunction` class registration.

ASCII `"Function"` в другой функции (`FUN_110426c0`) используется иначе, вероятно как name table/FName registration, и для определения `UFunction::StaticClass` пока не используется.

---

# 19. Текущая карта классов

```cpp
class UObject
{
    // 0x00 .. 0x3F
};
// sizeof = 0x40

class UField : public UObject
{
    UField* Next;          // 0x40
};
// sizeof = 0x44

class UStruct : public UField
{
    uint8_t  Unknown44[8]; // 0x44

    UStruct* SuperField;   // 0x4C
    UField*  Children;     // 0x50
    uint32_t PropertySize; // 0x54

    uint8_t Unknown58[0x30];
};
// sizeof = 0x88

class UFunction : public UStruct
{
    // UNKNOWN 0x88 .. 0xA7
};
// sizeof = 0xA8

class UProperty : public UField
{
    int32_t ArrayDim;       // 0x44
    int32_t ElementSize;    // 0x48

    uint8_t Unknown4C[0x18];

    int32_t Offset;         // 0x64

    uint8_t Unknown68[0x0C];
};
// sizeof = 0x74

class UClass : public UStruct
{
    // unknown class-specific fields
};
// sizeof = 0x1CC
```

---

# 20. Уровни уверенности

| Finding | Status |
|---|---|
| `GNames = 0x12538938` | CONFIRMED |
| `GObjects = 0x1259EF3C` | CONFIRMED |
| `UObject::HashNext = 0x04` | CONFIRMED |
| `UObject::ObjectFlags = 0x08` | CONFIRMED |
| `UObject::HashOuterNext = 0x10` | CONFIRMED |
| `UObject::InternalIndex = 0x20` | CONFIRMED |
| `UObject field +0x28` membership index semantics | CONFIRMED |
| exact source name `nDynRefsIndex` | INFERRED |
| `UObject::Outer = 0x2C` | CONFIRMED |
| `UObject::Name = 0x30` | CONFIRMED |
| `UObject::Class = 0x38` | CONFIRMED |
| `sizeof(UObject)=0x40` | CONFIRMED |
| `UField::Next = 0x40` | CONFIRMED |
| `sizeof(UField)=0x44` | CONFIRMED |
| `UStruct::SuperField = 0x4C` | CONFIRMED |
| `UStruct::Children = 0x50` | CONFIRMED |
| `UStruct::PropertySize = 0x54` | CONFIRMED |
| `sizeof(UStruct)=0x88` | CONFIRMED |
| `UProperty::ArrayDim = 0x44` | CONFIRMED |
| `UProperty::ElementSize = 0x48` | CONFIRMED |
| `UProperty::Offset = 0x64` | CONFIRMED |
| `sizeof(UProperty)=0x74` | CONFIRMED |
| `sizeof(UFunction)=0xA8` | CONFIRMED |
| exact UFunction field layout 0x88–0xA7 | NOT YET RECOVERED |
| `sizeof(UClass)=0x1CC` | CONFIRMED |

---

# 21. Что осталось неизвестным в UObject

Пока не идентифицированы исходные имена/семантика:

```text
+0x14
+0x18
+0x1C
+0x24
+0x3C
```

Для SDK generator они, вероятно, не критичны.

`+0x28` по поведению понятен, но историческое исходное имя окончательно не доказано.

---

# 22. Следующий приоритет: UFunction 0x88–0xA7

Теперь поиск UFunction стал гораздо проще.

Известно:

```text
base UStruct = 0x88
UFunction size = 0xA8
```

Нужно восстановить всего 32 байта:

```text
+0x88
+0x8C
+0x90
+0x94
+0x98
+0x9C
+0xA0
+0xA4
```

с возможными byte/word fields между ними.

Наиболее вероятные семантические цели:

```text
FunctionFlags
iNative
RepOffset
OperPrecedence
FriendlyName
NumParms
ParmsSize
ReturnValueOffset
Func/native function pointer
```

Но **offsets из APB 1.19 переносить нельзя**.

---

# 23. Лучший следующий способ найти UFunction fields

Нужно получить конкретный `UClass*` descriptor для `Function`.

Известен intrinsic class creator:

```text
FUN_1109f0d0
```

Следующий шаг:

1. Найти все CALL xrefs на `FUN_1109f0d0`.

2. Найти wrapper/cache вида:

```asm
MOV EAX,[g_FunctionClass]
TEST EAX,EAX
JNZ ready

PUSH ...
CALL FUN_1109f0d0
MOV [g_FunctionClass],EAX

ready:
MOV EAX,[g_FunctionClass]
```

3. Получить:

```text
g_FunctionClass = DAT_xxxxxxxx
```

4. После этого искать IsA **именно против этого class descriptor**, а не против произвольного `UClass`.

5. После доказанного UFunction type-check собирать обращения только в диапазоне:

```text
Field + 0x88 .. Field + 0xA7
```

Это должно позволить восстановить весь UFunction достаточно быстро.

---

# 24. Возможный альтернативный путь

Intrinsic creator `FUN_1109f0d0` получает callbacks:

```text
FUN_1109f7f0
LAB_110a4630
FUN_10e0b1f0
```

`FUN_1109f7f0` особенно интересна.

Она может быть:

```text
UFunction constructor
StaticRegisterNatives
serializer/linker
class-specific initializer
```

Поэтому стоит отдельно декомпилировать:

```text
FUN_1109f7f0
```

и проверить обращения:

```text
[this + 0x88 .. 0xA7]
```

Если это constructor/init routine UFunction, она может сразу раскрыть layout.

---

# 25. Ключевые функции для дальнейшего анализа

```text
FUN_11068f50
    UObject registration / AddObject-like
    подтверждает HashNext, HashOuterNext,
    InternalIndex, Outer, Name, +0x28

FUN_1106dc90
    GNames / UObject Name usage

FUN_10deea70
FUN_10deeb40
FUN_112ce670
    классический IsA
    подтверждают UObject::Class и UStruct::SuperField

FUN_110a15c0
    reflection/property traversal
    подтверждает Children, Next, Property layout,
    PropertySize

FUN_1109cec0
    intrinsic UClass descriptor initialization

FUN_1109f070
    intrinsic Field class creator

FUN_1109f0d0
    intrinsic Function class creator

FUN_1109f1f0
    intrinsic Struct class creator

FUN_11050f10
    intrinsic Property class creator

FUN_1109efb0
    intrinsic Class class creator

FUN_1109f7f0
    next high-priority target for UFunction
```

---

# 26. Критические сигнатуры для generator

## GNames

```text
8B 0D ?? ?? ?? ?? 83 3C 81 00
```

Resolved global:

```text
0x12538938
```

## GObjects

```text
A1 ?? ?? ?? ?? 8B 34 B8 85 F6
```

Resolved global:

```text
0x1259EF3C
```

---

# 27. Главный вывод на текущем этапе

Reflection layout APB 1.13.1 уже восстановлен достаточно далеко, чтобы считать старый target APB 1.19 лишь ориентиром, а не источником offsets.

Наиболее важное отличие:

```text
APB 1.13.1:

UObject   = 0x40
UField    = 0x44
UProperty = 0x74
UStruct   = 0x88
UFunction = 0xA8
UClass    = 0x1CC
```

`UObject/UField` частично совпадают с более поздним target, но начиная с `UStruct` layout существенно расходится.

Поэтому следующий этап — не дальнейшее угадывание по target `EngineClasses.hpp`, а точечное восстановление оставшихся `0x20` байт `UFunction`.

## Следующая рекомендуемая операция

```text
1. Xrefs -> FUN_1109f0d0
2. найти g_FunctionClass cache/wrapper
3. декомпилировать FUN_1109f7f0
4. искать UFunction fields только в +0x88..+0xA7
5. после UFunction адаптировать EngineClasses.hpp
6. затем перейти к UClass и generator traversal
```

Это текущее состояние исследования.