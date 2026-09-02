using System;

[Flags]
public enum Opcodes : uint
{
    // =========================================================
    // GC -> LS
    // APB 1.13.1.647319
    // =========================================================

    ASK_LOGIN = 0x3E8,                 // 1000 confirmed
    LOGIN_PROOF = 0x3E9,               // 1001 confirmed

    ASK_CHARACTER_INFO = 0x3EA,        // 1002
    ASK_WORLD_LIST = 0x3EB,            // 1003

    ASK_CHARACTER_NAME_CHECK = 0x3EC,  // 1004
    ASK_CHARACTER_NAME_CHANGE = 0x3ED, // 1005

    ASK_CHARACTER_CREATE = 0x3EE,      // 1006
    ASK_CHARACTER_DELETE = 0x3EF,      // 1007

    ASK_WORLD_ENTER = 0x3F0,           // 1008

    ASK_CONFIGFILE_LOAD = 0x3F1,       // 1009 confirmed by client
    ASK_CONFIGFILE_SAVE = 0x3F2,       // 1010


    // =========================================================
    // LS -> GC
    // =========================================================

    ERROR = 0x7D0,
    KICK = 0x7D1,

    LOGIN_PUZZLE = 0x7D2,
    LOGIN_SALT = 0x7D3,
    ANS_LOGIN_SUCCESS = 0x7D4,
    ANS_LOGIN_FAILED = 0x7D5,

    CHARACTER_LIST = 0x7D6,
    ANS_CHARACTER_INFO = 0x7D7,
    WORLD_LIST = 0x7D8,

    ANS_CHARACTER_NAME_CHECK = 0x7D9,
    ANS_CHARACTER_NAME_CHANGE = 0x7DA,
    ANS_CHARACTER_CREATE = 0x7DB,
    ANS_CHARACTER_DELETE = 0x7DC,
    ANS_WORLD_ENTER = 0x7DD,

    WORLD_STATUS = 0x7DE,

    ANS_CONFIGFILE_LOAD = 0x7DF,
    ANS_CONFIGFILE_SAVE = 0x7E0,


    // =========================================================
    // Unknown / later additions
    // Do not trust these yet for 1.13.1
    // =========================================================

    ASK_NUM_ADDITIONAL_CHARACTER_SLOTS = 0x3F7,
    KEY_EXCHANGE = 0x3F8,
    HARDWARE_INFO = 0x3F9,
    ASK_SSO_TOKEN = 0x3FB,
    ASK_PREMIUM_STATUS = 0x3FC,
    TICK_TOGGLE_LOGIN_POPUP = 0x402,

    ANS_NUM_ADDITIONAL_CHARACTER_SLOTS = 0x7E1,
    ANS_SSO_TOKEN = 0x7E2,
    ANS_PREMIUM_STATUS = 0x7E4,
    WMI_REQUEST = 0x7E5,
}