struct FName
{
int32_t Index;
int32_t Number;
};

class UObject
{
public:
void*     VTable;            // 0x00

    UObject*  HashNext;          // 0x04

    uint64_t  ObjectFlags;       // 0x08

    UObject*  HashOuterNext;     // 0x10

    uint8_t   Unknown14[0x0C];   // 0x14

    int32_t   InternalIndex;     // 0x20

    uint32_t  Unknown24;         // 0x24

    int32_t   DynRefsIndex;      // 0x28
                                  // exact original name still inferred

    UObject*  Outer;             // 0x2C

    FName     Name;              // 0x30

    UClass*   Class;             // 0x38

    uint32_t  Unknown3C;         // 0x3C
};
// sizeof = 0x40

class UField : public UObject
{
public:
UField* Next;                // 0x40
};
// sizeof = 0x44

class UStruct : public UField
{
public:
uint8_t  Unknown44[0x08];    // 0x44

    UStruct* SuperField;         // 0x4C
    UField*  Children;           // 0x50

    uint32_t PropertySize;       // 0x54 ? NEEDS PROOF
};

APB 1.13.1 UObject

0x08 ObjectFlags
0x20 InternalIndex        вероятно
0x28 auxiliary index     вероятно DynRefsIndex
0x2C Outer               очень вероятно
0x30 Name.Index          подтверждено
0x34 Name.Number         следует из FName layout
0x38 Class               очень вероятно


FUN_11068f50
Да, эта функция очень ценная. По сути она показывает процедуру регистрации UObject в глобальной object system, и из неё можно уже без догадок закрепить несколько полей.

Главная последовательность:

*(void **)(DAT_1259ef3c + iVar3 * 4) = this;
*(int *)((int)this + 0x20) = iVar3;

То есть:

GObjects.Data[iVar3] = this;
this->InternalIndex = iVar3;

Поэтому:

GObjects              = 0x1259EF3C
UObject::InternalIndex = +0x20

здесь уже подтверждены напрямую. Причём сама функция содержит диагностическую строку:

"GObjAvailable contained an index into a GObjObjects slot that is not NULL!"
"GObjObjects[InIndex] : ..."



-app 113400 -depot 113401 -manifest 6826695581950117729 26 September 2012 