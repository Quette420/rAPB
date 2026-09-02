# Отчёт по поиску GNames, GObjects и восстановлению UObject в APB: Reloaded 1.13.1

## 1. Цель исследования

Целью работы было восстановить ключевые глобальные структуры Unreal Engine 3 в клиенте **APB: Reloaded 1.13.1 (2013)**, чтобы в дальнейшем получить список UE3-классов, объектов и функций с использованием `UnrealEngineSDKGenerator`.

Нас интересовали прежде всего:

- `GNames`;
- `GObjects`;
- реальный layout `UObject`;
- offsets `Outer`, `Name`, `Class`;
- возможность адаптации готового target `AllPointsBulletin` из `UnrealEngineSDKGenerator` под APB 1.13.1.

Исследование выполнялось офлайн в Ghidra на `APB_dump.exe`. Отладка запущенного клиента не использовалась.

---

# 2. Исходная проблема

В старом клиенте присутствуют UE3 script packages:

```text
APBEditor.u
APBGame.u
APBUserInterface.u
Core.u
Engine.u
GFxUI.u
GFxUIEditor.u
IpDrv.u
UnrealEd.u
```

Однако файлы имеют размер порядка нескольких сотен байт и фактически являются stripped/stub packages.

Поэтому стандартное извлечение UnrealScript из `.u` не даёт полного списка классов и методов.

Было принято решение восстанавливать reflection-структуры непосредственно из клиента UE3.

Для этого был выбран:

```text
polivilas/UnrealEngineSDKGenerator
```

В репозитории уже существует target `AllPointsBulletin`, но он рассчитан на более позднюю APB 1.19.4, поэтому его offsets и signatures нельзя было считать совместимыми с APB 1.13.1 без проверки.

---

# 3. Поиск GNames

## 3.1. Исходная сигнатура

В target APB генератора использовалась характерная сигнатура обращения к глобальной таблице имён:

```text
8B 0D ?? ?? ?? ?? 83 3C 81 00
```

В APB 1.13.1 она действительно была обнаружена.

Один из найденных участков:

```asm
110079DC  MOV ECX,[12538938]
          ...
```

Таким образом:

```text
GNames = 0x12538938
```

---

## 3.2. Проверка структуры

По адресу `0x12538938` находилось:

```text
12538938  00 00 F9 33
1253893C  FF 99 02 00
12538940  11 B0 02 00
```

В представлении UE3 `TArray`:

```cpp
template<class T>
struct TArray
{
    T*      Data;
    int32_t Count;
    int32_t Max;
};
```

получается:

```text
GNames
Address = 0x12538938

Data  = 0x33F90000
Count = 0x000299FF = 170495
Max   = 0x0002B011 = 176145
```

Числа согласованы:

```text
Data != NULL
Count > 0
Max >= Count
```

что является первым структурным подтверждением.

---

## 3.3. Поведенческое подтверждение

Позже был обнаружен особенно важный код:

```asm
MOV EAX,[ESI+30]
MOV ECX,[12538938]
MOV EAX,[ECX+EAX*4]
```

То есть значение из объекта используется непосредственно как индекс:

```cpp
Entry = GNames[ObjectField];
```

Причём операция повторяется в той же функции.

Это уже подтверждает не только сам `GNames`, но и позволяет определить offset `FName` внутри `UObject`.

Итог:

```text
GNames = 0x12538938
```

**Степень уверенности: практически 100 %.**

---

# 4. Проблема отсутствующей heap memory

Поле:

```text
GNames.Data = 0x33F90000
```

указывает на runtime heap.

Однако в Memory Map импортированного в Ghidra `APB_dump.exe` область около:

```text
0x33F90000
```

отсутствует.

Следовательно, исследуемый `APB_dump.exe` содержит статический PE/module image и значения глобальных переменных, но не содержит всей runtime heap memory процесса.

Поэтому descriptor `GNames` можно восстановить, но сами `FNameEntry`, лежавшие в `0x33F90000`, из этого файла напрямую прочитать нельзя.

Это ограничение самого имеющегося дампа, а не ошибка в найденном адресе `GNames`.

---

# 5. Поиск GObjects

## 5.1. Почему старая сигнатура не работала

Target APB 1.19.4 использует pattern:

```text
A1 ?? ?? ?? ?? 8B 34 B0 85 F6
```

В APB 1.13.1 поиск этого pattern дал:

```text
0 results
```

Первоначально это могло означать либо отсутствие `GObjects`, либо изменение компиляции между версиями.

В дальнейшем подтвердилось второе.

---

# 6. Структурный поиск TArray в `.data`

Поскольку сигнатура от APB 1.19.4 не подходила, был написан Ghidra Java script, который сканировал `.data`:

```text
0x120E3000 – 0x125FDFFF
```

и искал последовательности:

```cpp
Data
Count
Max
```

с условиями:

```text
Data похож на runtime pointer
Count разумного размера
Max >= Count
```

Скрипт обнаружил 109 кандидатов.

Среди них присутствовал уже известный:

```text
12538938:
Data  = 33F90000
Count = 170495
Max   = 176145
```

то есть `GNames`.

Это подтвердило корректность самого сканера.

---

# 7. Первоначальный ложный кандидат GObjects

Особенно выделялся:

```text
0x1259F000

Data  = 0x22A10000
Count = 608717
Max   = 825536
```

По большому `Count` первоначально возникла гипотеза:

```text
GObjects ?= 0x1259F000
```

Однако анализ XREF показал другое.

В коде значение `Object + 0x20` используется так:

```asm
MOV ECX,[ESI+20]

...

SAR EAX,5
...
OR [EBX+EAX*4],EDX
```

То есть индекс делится на 32 и затем используется для установки одного бита в массиве DWORD.

Семантически это соответствует:

```cpp
Bits[Index >> 5] |= 1 << (Index & 31);
```

Следовательно:

```text
0x1259F000
```

не является `TArray<UObject*>`.

Это битовый массив, вероятно UE3 `TBitArray` или специализированная object bitmap.

Дополнительным аргументом является совпадение его текущего количества бит с количеством объектов:

```text
608717
```

То есть bitmap, вероятно, содержит один бит состояния на объект.

---

# 8. Обнаружение настоящего GObjects

Рядом с этим bitmap находилась другая структура:

```text
0x1259EF3C

Data  = 0x0E340000
Count = 0x000949CD = 608717
Max   = 0x000C96B8 = 825016
```

В функции завершения object subsystem был найден следующий цикл:

```asm
CMP EDI,[1259EF40]

MOV EAX,[1259EF3C]
MOV ESI,[EAX+EDI*4]

TEST ESI,ESI
```



Он эквивалентен:

```cpp
for (int i = 0; i < GObjects.Count; ++i)
{
    UObject* Object = GObjects.Data[i];

    if (Object)
    {
        ...
    }
}
```

Это практически точное поведение:

```cpp
TArray<UObject*>
```

---

# 9. Дополнительное подтверждение GObjects через destructor/cleanup

В той же функции object subsystem производится очистка массива.

Сначала:

```text
Count = 0
```

затем проверяется `Max`, после чего освобождается `Data`.

То есть структура действительно имеет layout:

```text
1259EF3C Data
1259EF40 Count
1259EF44 Max
```

Итог:

```text
GObjects = 0x1259EF3C
```

**Степень уверенности: практически 100 %.**

---

# 10. Почему старая GObjects signature не находилась

После идентификации `GObjects` нашёлся характерный цикл:

```asm
MOV EAX,[1259EF3C]
MOV ESI,[EAX+EDI*4]
TEST ESI,ESI
```

Его байтовый шаблон:

```text
A1 ?? ?? ?? ?? 8B 34 B8 85 F6
```

В target APB 1.19.4 использовалось:

```text
A1 ?? ?? ?? ?? 8B 34 B0 85 F6
```

Разница:

```text
B0 -> B8
```

связана с тем, что компилятор использовал другой индексный регистр.

Иными словами:

```text
APB 1.19.4:
[EAX + ESI*4]

APB 1.13.1:
[EAX + EDI*4]
```

Поэтому отсутствие старой signature было ожидаемым следствием отличий версии, а не отсутствием `GObjects`.

Для APB 1.13.1 pattern можно заменить на:

```text
A1 ?? ?? ?? ?? 8B 34 B8 85 F6
```

---

# 11. Восстановление UObject

После нахождения `GObjects` следующим этапом стал поиск реального layout `UObject`.

Использовать `EngineClasses.hpp` от APB 1.19.4 напрямую нельзя, потому что offsets между версиями отличаются.

Для определения offsets были найдены функции, одновременно использующие:

```text
GObjects
GNames
```

Автоматический Ghidra script обнаружил всего семь таких функций:

```text
1106DC90
111EA6B0
110DD860
10C45D70
113DF700
11056530
11189550
```

Это позволило вместо сотен XREF анализировать только наиболее интересные функции.

---

# 12. UObject::Name

Наиболее чистый фрагмент был обнаружен в:

```text
FUN_1106DC90
```

В этой функции `ESI` сопоставляется с элементом массива `GObjects`, что подтверждает, что `ESI` является `UObject*`.

Затем выполняется:

```asm
MOV EAX,[ESI+30]
MOV ECX,[12538938]
MOV EAX,[ECX+EAX*4]
```



Это непосредственно означает:

```cpp
Index = Object->Name.Index;
Entry = GNames[Index];
```

Следовательно:

```text
UObject::Name.Index = 0x30
```

Так как используемый в target `FName` имеет два `int32`:

```cpp
struct FName
{
    int32_t Index;
    int32_t Number;
};
```

получаем:

```text
0x30 Name.Index
0x34 Name.Number
```

Таким образом:

```text
UObject::Name = 0x30
```

**Степень уверенности: подтверждено непосредственно кодом.**

---

# 13. UObject::Outer

В другом участке объект извлекается из `GObjects`:

```asm
MOV EDI,[GObjects + index*4]
```

после чего:

```asm
MOV EAX,[EDI+2C]

TEST EAX,EAX
JZ end

loop:
CMP EAX,ESI
JZ found

MOV EAX,[EAX+2C]
TEST EAX,EAX
JNZ loop
```



Семантически:

```cpp
UObject* Current = Object->Outer;

while (Current)
{
    if (Current == Target)
        break;

    Current = Current->Outer;
}
```

То есть одно и то же поле `+0x2C` содержит указатель на следующий объект в outer-chain.

Следовательно:

```text
UObject::Outer = 0x2C
```

**Степень уверенности: практически 100 %.**

---

# 14. UObject::Class

Ещё один фрагмент:

```asm
MOV ESI,[GObjects + index*4]

MOV EAX,[ESI+38]
MOV ECX,[EAX+D0]

TEST ECX,02000001
```



После обращения через `Object+0x38` код читает поле уже из полученной структуры:

```text
+0xD0
```

и проверяет битовые flags.

При этом отдельно проверяются `ObjectFlags` самого исходного `UObject` через:

```asm
MOV EAX,[ESI+08]
...
```

То есть `Object+0x38` является отдельным metadata/class object, а не собственными flags `UObject`.

Поведение соответствует:

```cpp
UClass* Class = Object->Class;

if (Class->SomeFlags & ...)
{
    ...
}
```

Следовательно:

```text
UObject::Class = 0x38
```

**Степень уверенности: очень высокая.**

---

# 15. ObjectFlags

На множестве объектов наблюдается работа с:

```text
Object + 0x08
Object + 0x0C
```

Например:

```asm
AND [ESI+08],...
AND [ESI+0C],...
```



Это соответствует 64-битному набору Unreal Engine object flags:

```cpp
uint64_t ObjectFlags;
```

Следовательно:

```text
ObjectFlags = 0x08
```

где:

```text
+0x08 low DWORD
+0x0C high DWORD
```

**Степень уверенности: очень высокая.**

---

# 16. Поле +0x28

Поле:

```text
Object + 0x28
```

регулярно сравнивается с:

```text
-1
```

При добавлении объекта в вспомогательный массив:

```asm
CALL FUN_10B66640
MOV [ESI+28],EAX
```

полученный индекс сохраняется в объекте.

При удалении:

```asm
MOV EAX,[ESI+28]

...
CALL FUN_10AA9520

...
MOV [ESI+28],FFFFFFFF
```

То есть `+0x28` содержит индекс объекта во вспомогательной глобальной структуре.

Это очень хорошо соответствует полю типа:

```text
nDynRefsIndex
```

из более позднего target APB.

Однако название поля пока выводится по аналогии с target 1.19.4, а не доказано напрямую.

Поэтому корректная запись:

```text
+0x28 = auxiliary/dynamic reference index
```

с высокой вероятностью:

```text
nDynRefsIndex
```

---

# 17. Поле +0x20

Поле:

```text
Object + 0x20
```

используется как индекс в bitmap:

```cpp
Bits[Index >> 5] |= 1 << (Index & 31);
```

Это означает, что поле является стабильным object index.

Наиболее вероятная интерпретация:

```text
InternalIndex
```

Однако прямого подтверждения его официального имени пока нет.

Поэтому:

```text
+0x20 = object index
вероятно InternalIndex
```

---

# 18. Текущий восстановленный UObject APB 1.13.1

На данный момент безопасно использовать следующий промежуточный layout:

```cpp
struct FName
{
    int32_t Index;                 // 0x00
    int32_t Number;                // 0x04
};

class UObject
{
public:

    void* VTable;                  // 0x00

    char Unknown04[0x04];          // 0x04

    uint64_t ObjectFlags;          // 0x08

    char Unknown10[0x10];          // 0x10 - 0x1F

    int32_t ObjectIndex;           // 0x20
                                    // probably InternalIndex

    char Unknown24[0x04];          // 0x24

    int32_t DynRefsIndex;          // 0x28
                                    // probable name

    UObject* Outer;                // 0x2C  CONFIRMED

    FName Name;                    // 0x30  CONFIRMED
                                    // Index  0x30
                                    // Number 0x34

    UClass* Class;                 // 0x38  CONFIRMED

    // дальше структура пока не восстановлена
};
```

---

# 19. Сводка найденных глобальных структур

## GNames

```text
Address = 0x12538938

Data  = 0x33F90000
Count = 170495
Max   = 176145
```

Статус:

```text
CONFIRMED
```

---

## GObjects

```text
Address = 0x1259EF3C

Data  = 0x0E340000
Count = 608717
Max   = 825016
```

Статус:

```text
CONFIRMED
```

---

## Object bitmap

```text
Address = 0x1259F000

Data  = 0x22A10000
Count = 608717
Max   = 825536
```

Статус:

```text
не GObjects
вероятно TBitArray / object state bitmap
```

---

# 20. Сводка UObject offsets

| Offset | Назначение | Уверенность |
|---|---|---|
| `0x08` | `ObjectFlags` | очень высокая |
| `0x20` | object index, вероятно `InternalIndex` | высокая |
| `0x28` | auxiliary/dynamic reference index, вероятно `nDynRefsIndex` | высокая |
| `0x2C` | `Outer` | подтверждено |
| `0x30` | `Name.Index` | подтверждено |
| `0x34` | `Name.Number` | подтверждается layout `FName` |
| `0x38` | `Class` | очень высокая |

---

# 21. Главный вывод относительно target APB 1.19.4

Готовый target `AllPointsBulletin` из `UnrealEngineSDKGenerator` нельзя использовать с APB 1.13.1 без адаптации.

Как минимум отличаются:

### GObjects signature

Старый target:

```text
A1 ?? ?? ?? ?? 8B 34 B0 85 F6
```

APB 1.13.1:

```text
A1 ?? ?? ?? ?? 8B 34 B8 85 F6
```

### UObject layout

Layout из более позднего клиента не совпадает с APB 1.13.1.

Для исследуемой версии уже подтверждены:

```text
Outer = 0x2C
Name  = 0x30
Class = 0x38
```

Следовательно, запуск генератора со старым `EngineClasses.hpp` привёл бы к чтению неправильных полей объектов и некорректным именам/классам.

---

# 22. Что удалось доказать

На данном этапе подтверждены три фундаментальные составляющие UE3 reflection:

```text
GNames   = 0x12538938
GObjects = 0x1259EF3C

UObject::Outer = 0x2C
UObject::Name  = 0x30
UObject::Class = 0x38
```

Это означает, что уже возможно корректно:

1. перебирать глобальные объекты;
2. определять их `FName`;
3. определять их `UClass`;
4. строить outer-chain объекта;
5. начинать восстановление `UField`, `UStruct`, `UClass` и `UFunction`.

---

# 23. Следующий этап

Для получения полного списка классов и методов необходимо восстановить минимум:

```text
UField::Next
UStruct::SuperField
UStruct::Children
UStruct::PropertySize
UFunction::FunctionFlags
UFunction::iNative
UFunction::ParmsSize
UFunction::Func
```

Особенно важен:

```text
UStruct::Children
```

поскольку через него UE3 reflection связывает поля и функции класса.

После определения этих offsets можно будет пройти примерно так:

```cpp
for (UObject* Object : GObjects)
{
    if (Object->Class == UClass::StaticClass())
    {
        UClass* Class = (UClass*)Object;

        for (UField* Field = Class->Children;
             Field;
             Field = Field->Next)
        {
            if (Field->IsA(UFunction::StaticClass()))
            {
                UFunction* Function = (UFunction*)Field;

                // имя функции
                // flags
                // native index
                // параметры
            }
        }
    }
}
```

Именно этот этап должен привести к первоначальной цели исследования — восстановлению списка классов и методов APB: Reloaded 1.13.1.

---

# 24. Итог

Исходный подход через `.u` packages оказался непригоден из-за stripped script packages.

Переход к анализу runtime reflection структур оказался успешным.

Методика состояла из:

```text
known signatures
        ↓
GNames
        ↓
структурный scan .data
        ↓
кандидаты TArray
        ↓
XREF
        ↓
поведенческий анализ кода
        ↓
GObjects
        ↓
совместное использование GObjects + GNames
        ↓
восстановление UObject offsets
```

Самым важным результатом стало то, что адреса и offsets не просто найдены по pattern matching, а подтверждены по реальному поведению машинного кода.

Текущее состояние исследования можно считать достаточным для перехода от поиска глобальных массивов к восстановлению reflection hierarchy `UField -> UStruct -> UClass/UFunction`.