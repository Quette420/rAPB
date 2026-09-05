# -*- coding: utf-8 -*-

import argparse

import apb_reflect as R
import netindex_probe as N


DEFAULT_TARGET_PACKAGE = "financialdistrict_master"
WORLDINFO_STREAMING_LEVELS_OFF = 0x38C


def find_property(objs, mem, obj, wanted_name):
    cls = mem.ptr(obj + N.UO_CLASS)
    if not cls:
        return None

    chain = N._class_chain_root_to_target(
        objs,
        mem,
        cls,
    )

    for class_obj in chain:
        for prop in N._direct_properties_for_class(
            objs,
            mem,
            class_obj,
        ):
            if objs.name(prop) == wanted_name:
                return prop

    return None


def property_value(
    objs,
    mem,
    known_objects,
    obj,
    name,
):
    prop = find_property(
        objs,
        mem,
        obj,
        name,
    )

    if prop is None:
        return "<not found>"

    return N._instance_property_value(
        objs,
        mem,
        known_objects,
        obj,
        prop,
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Dump the live WorldInfo.StreamingLevels array for an APB map"
        )
    )
    parser.add_argument(
        "--package",
        default=DEFAULT_TARGET_PACKAGE,
        help=(
            "master package name (default: %s)"
            % DEFAULT_TARGET_PACKAGE
        ),
    )
    args = parser.parse_args()
    target_package = args.package.lower()

    mem = R.LiveProcess("APB.exe")

    print(
        "process pid=%d module=0x%08X"
        % (
            mem.pid,
            mem.module_base or 0,
        )
    )

    names = N.NameTable(
        mem,
        N.DEFAULT_GNAMES,
    )

    objs = N.Objects(
        mem,
        N.DEFAULT_GOBJECTS,
        names,
    )

    known_objects = set()
    world_info = None

    print("scanning GObjects...")

    for index, obj in objs.iter_objects(
        progress=True
    ):
        known_objects.add(obj)

        try:
            if objs.class_name(obj) != "WorldInfo":
                continue

            path = objs.path(obj)

            if path.lower().startswith(
                target_package + "."
            ):
                world_info = obj
        except Exception:
            pass

    if world_info is None:
        raise SystemExit(
            "%s WorldInfo not found"
            % target_package
        )

    print()
    print(
        "WorldInfo = 0x%08X"
        % world_info
    )
    print(
        "Path      = %s"
        % objs.path(world_info)
    )

    array_addr = (
        world_info
        + WORLDINFO_STREAMING_LEVELS_OFF
    )

    data = mem.ptr(array_addr + 0x00)
    num = mem.i32(array_addr + 0x04)
    maxv = mem.i32(array_addr + 0x08)

    print()
    print(
        "StreamingLevels @ WorldInfo+0x%X"
        % WORLDINFO_STREAMING_LEVELS_OFF
    )
    print(
        "Data=0x%08X Num=%d Max=%d"
        % (
            data,
            num,
            maxv,
        )
    )

    if not data:
        raise SystemExit(
            "StreamingLevels.Data == NULL"
        )

    if num < 0 or num > 4096:
        raise SystemExit(
            "Invalid StreamingLevels.Num=%d"
            % num
        )

    print()
    print(
        "============================================================"
    )
    print("STREAMING LEVELS")
    print(
        "============================================================"
    )

    for i in range(num):
        try:
            obj = mem.ptr(
                data + i * 4
            )
        except Exception as exc:
            print(
                "[%03d] <read error: %s>"
                % (i, exc)
            )
            continue

        if not obj:
            print(
                "[%03d] NULL"
                % i
            )
            continue

        try:
            class_name = objs.class_name(obj)
            path = objs.path(obj)
        except Exception as exc:
            print(
                "[%03d] 0x%08X <bad UObject: %s>"
                % (
                    i,
                    obj,
                    exc,
                )
            )
            continue

        package_name = property_value(
            objs,
            mem,
            known_objects,
            obj,
            "PackageName",
        )

        should_load = property_value(
            objs,
            mem,
            known_objects,
            obj,
            "bShouldBeLoaded",
        )

        should_visible = property_value(
            objs,
            mem,
            known_objects,
            obj,
            "bShouldBeVisible",
        )

        should_block = property_value(
            objs,
            mem,
            known_objects,
            obj,
            "bShouldBlockOnLoad",
        )

        loaded_level = property_value(
            objs,
            mem,
            known_objects,
            obj,
            "LoadedLevel",
        )

        print()
        print(
            "[%03d] 0x%08X %s"
            % (
                i,
                obj,
                class_name,
            )
        )

        print(
            "      path=%s"
            % path
        )

        print(
            "      PackageName=%s"
            % package_name
        )

        print(
            "      bShouldBeLoaded=%s"
            % should_load
        )

        print(
            "      bShouldBeVisible=%s"
            % should_visible
        )

        print(
            "      bShouldBlockOnLoad=%s"
            % should_block
        )

        print(
            "      LoadedLevel=%s"
            % loaded_level
        )


if __name__ == "__main__":
    main()
