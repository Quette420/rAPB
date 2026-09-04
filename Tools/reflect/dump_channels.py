import apb_reflect as R
from netindex_probe import NameTable, Objects

GNAMES   = 0x12538938
GOBJECTS = 0x1259EF3C

# Из текущего --probe-packagemap
CONNECTION = 0x43130000

# Из APB 1.13.1 UPackageMapLevel::SerializeObject:
CHANNELS_OFFSET = 0xF30

# Из того же runtime reverse UChannel:
CH_FLAGS_OFFSET = 0x44
CH_INDEX_OFFSET = 0x48
CH_TYPE_OFFSET  = 0x54
CH_ACTOR_OFFSET = 0x78

mem = R.LiveProcess("APB.exe")
names = NameTable(mem, GNAMES)
objs = Objects(mem, GOBJECTS, names)

print("pid=%d connection=0x%08X" % (mem.pid, CONNECTION))
print()

for slot in [
    0, 1,
    2, 3, 4, 5,
    6, 8, 10,
    20, 21, 22,
    40, 42, 44
]:
    ch = mem.try_u32(
        CONNECTION + CHANNELS_OFFSET + slot * 4,
        None
    )

    if not ch:
        print("slot %-2d -> NULL" % slot)
        continue

    flags = mem.try_u32(ch + CH_FLAGS_OFFSET, None)
    chindex = mem.try_u32(ch + CH_INDEX_OFFSET, None)
    chtype = mem.try_u32(ch + CH_TYPE_OFFSET, None)
    actor = mem.try_u32(ch + CH_ACTOR_OFFSET, None)

    if actor:
        try:
            actor_class = objs.class_name(actor)
            actor_path = objs.path(actor)
        except Exception as exc:
            actor_class = "<error>"
            actor_path = str(exc)
    else:
        actor_class = "<null>"
        actor_path = "<null>"

    print(
        "slot %-2d -> Channel=0x%08X "
        "ChIndex=%s Type=%s Flags=%s "
        "Actor=0x%08X %-28s %s"
        % (
            slot,
            ch,
            "?" if chindex is None else str(chindex),
            "?" if chtype is None else str(chtype),
            "?" if flags is None else "0x%08X" % flags,
            actor or 0,
            actor_class,
            actor_path,
        )
    )