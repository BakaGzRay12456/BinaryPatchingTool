import re

def parse_loc_or_hex_token(tok):
    """
    尝试把 token 解析为地址整数：
    - loc_xxx / sub_xxx -> int
    - 0x... -> int
    否则返回 None
    """
    if not tok:
        return None
    m = re.match(r'^(?:loc_|sub_)?([0-9A-Fa-f]+)$', tok)
    if m:
        return int(m.group(1), 16)
    if tok.startswith("0x") or tok.startswith("0X"):
        try:
            return int(tok, 16)
        except ValueError:
            return None
    return None

def format_addr(a):
    return f"0x{a:X}"

def convert_arm64_ida_code(old_base, new_base, ida_code, special_map=None):
    """
    old_base, new_base: ints
    ida_code: raw string copied from IDA disasm
    special_map: dict, keys can be int (old addr) or str (names), values can be int (new addr) or str (new name)
    """
    if special_map is None:
        special_map = {}

    # 去掉注释（分号及之后的内容）
    no_comment = "\n".join(line.split(";", 1)[0] for line in ida_code.splitlines())

    # 普遍行模式：抓 __text:ADDR 之后的 指令及其剩余所有内容（保持 operands 原样）
    line_re = re.compile(r'^\s*__text:([0-9A-Fa-f]+)\s+([A-Za-z0-9\._]+)\s*(.*)$')
    # 还支持没有 __text: 前缀的纯指令行（备用）
    instr_only_re = re.compile(r'^\s*([A-Za-z0-9\._]+)\s*(.*)$')

    out_lines = []

    for raw in no_comment.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        m = line_re.match(line)
        if not m:
            # 不是带 __text: 的行，尝试纯指令行（保留）
            m2 = instr_only_re.match(line)
            if m2:
                instr = m2.group(1)
                operands = m2.group(2).strip()
                # 仍然需要处理 ADRL 可能出现的情况 even without __text
                if instr.upper() == "ADRL":
                    # ADRL <reg>, <target>
                    parts = operands.split(",", 1)
                    if len(parts) >= 1:
                        reg = parts[0].strip()
                        targ = parts[1].strip() if len(parts) > 1 else ""
                        hexaddr = None
                        if targ in special_map and isinstance(special_map[targ], int):
                            hexaddr = f"{special_map[targ]:X}"
                        else:
                            parsed = parse_loc_or_hex_token(targ.replace("0x","").replace("0X",""))
                            if parsed is not None:
                                hexaddr = f"{parsed:X}"
                            else:
                                # 无法解析，直接输出原行（去掉前后空）
                                out_lines.append(f"{instr} {operands}".strip())
                                continue
                        if len(hexaddr) > 3:
                            base = hexaddr[:-3] + "000"
                            offset = hexaddr[-3:]
                            out_lines.append(f"ADRP {reg}, 0x{base}")
                            out_lines.append(f"ADD  {reg}, {reg}, #0x{offset}")
                        else:
                            out_lines.append(f"{instr} {operands}".strip())
                    else:
                        out_lines.append(f"{instr} {operands}".strip())
                else:
                    out_lines.append(f"{instr} {operands}".strip())
            continue

        instr_addr = int(m.group(1), 16)
        instr = m.group(2)
        operands_full = m.group(3).strip()  # 保留剩余字符串，包括逗号和多个操作数

        # ADRL 特殊拆解 (优先)
        if instr.upper() == "ADRL":
            # 形如: ADRL    X1, loc_100D40524
            # 先用逗号分割取第二个操作数作为 target token
            parts = [p.strip() for p in operands_full.split(",", 1)]
            if len(parts) >= 2:
                reg = parts[0]
                target_tok = parts[1]
                # 尝试从 special_map 或 loc/sub/0x 获取 hex 字符串
                hexaddr = None
                if target_tok in special_map and isinstance(special_map[target_tok], int):
                    hexaddr = f"{special_map[target_tok]:X}"
                else:
                    # target_tok 可能有前缀 loc_ 或 0x...
                    if target_tok.startswith("loc_") or target_tok.startswith("sub_"):
                        hexaddr = target_tok.split("_")[-1]
                    elif target_tok.startswith("0x") or target_tok.startswith("0X"):
                        hexaddr = target_tok[2:]
                    else:
                        # 也可能是 plain name not mappable
                        # 直接输出去掉前缀的原行
                        out_lines.append(f"{instr} {operands_full}")
                        continue

                # 硬拆后三位
                if len(hexaddr) > 3:
                    base = hexaddr[:-3] + "000"
                    offset = hexaddr[-3:]
                    out_lines.append(f"ADRP {reg}, 0x{base}")
                    out_lines.append(f"ADD  {reg}, {reg}, #0x{offset}")
                else:
                    out_lines.append(f"{instr} {operands_full}")
            else:
                out_lines.append(f"{instr} {operands_full}")
            continue

        # 判断是否为分支/跳转类指令 —— 通用策略：
        # 如果指令以 'B' 开头（B, BL, B.<cond>）, 或者是 CBZ/CBNZ/TBZ/TBNZ/BLR 等，我们按“最后一个操作数是目标”处理
        instr_up = instr.upper()
        is_branch_like = instr_up.startswith("B") or instr_up in ("CBNZ","CBZ","TBZ","TBNZ","BL","BLR")

        if is_branch_like and operands_full:
            # 分割操作数，取最后一个操作数作为候选目标
            ops = [p.strip() for p in operands_full.split(",") if p.strip() != ""]
            if ops:
                target_tok = ops[-1]
                new_target_str = None
                # 优先按字符串 special_map 匹配（函数名映射）
                if target_tok in special_map:
                    mapped = special_map[target_tok]
                    if isinstance(mapped, int):
                        new_target_str = format_addr(mapped)
                    else:
                        new_target_str = str(mapped)
                else:
                    # 尝试解析 loc_/sub_/0x
                    parsed = None
                    if target_tok.startswith("loc_") or target_tok.startswith("sub_"):
                        parsed = int(target_tok.split("_")[-1], 16)
                    elif target_tok.startswith("0x") or target_tok.startswith("0X"):
                        try:
                            parsed = int(target_tok, 16)
                        except ValueError:
                            parsed = None
                    else:
                        # 也可能是 plain name that maps to an int in special_map by name (checked above)
                        parsed = None

                    if parsed is not None:
                        # 数字地址形式
                        if parsed in special_map:
                            mapped = special_map[parsed]
                            if isinstance(mapped, int):
                                new_target_str = format_addr(mapped)
                            else:
                                new_target_str = str(mapped)
                        else:
                            # 通过相对偏移计算 new_target
                            new_instr_addr = instr_addr - old_base + new_base
                            offset = parsed - instr_addr
                            new_target = new_instr_addr + offset
                            new_target_str = format_addr(new_target)

                if new_target_str is not None:
                    # 用新的目标替换最后一个操作数，其它操作数保持
                    new_ops = ops[:-1] + [new_target_str]
                    # 恢复成用逗号分隔的 operands（统一用 ", "）
                    new_operands = ", ".join(new_ops)
                    out_lines.append(f"{instr} {new_operands}")
                    continue
                else:
                    # 无法解析目标，直接输出原样（剥去 __text: 前缀）
                    out_lines.append(f"{instr} {operands_full}")
                    continue

        # 非 ADRL 且非可识别为跳转的指令 —— 原样输出指令+操作数（剥去 __text: 前缀）
        out_lines.append(f"{instr} {operands_full}")

    return "\n".join(out_lines)

if __name__ == "__main__":
    '''
    Usage:
    1.Copy a ribbon IDA code into the ida_code string
    2. Make a special map to the address of the external function (for example: B at 1005C55D8, jumps to another code area, you need a special map, because you don't know whether 616 will insert new things in the middle, and you can't rely on this to calculate the offset)
    3, write old_base and new_base (old base address and new base address, old is filled with the start address of this function, new is the new start address, and then it will calculate the offset for you, calculate the jump address inside "but you have to separate map outside")
    4. Check the code after the output to see if there are any problems, focusing on the jump
    5. You have to replace the strings manually, not automatically, because you don't know if a new string will be inserted
    '''

    old_base = 0x1005C55D4
    new_base = 0x1006BDADC

    special_map = {
        0x1007DFC28: 0x100944CA8,
        0x1007DFC38:0x100944CB8,
        "._ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc": 0x100E1BC8C,
        "_ZN11CoreManager9singletonE": 0x1011AD558,
    }

    ida_code = """
__text:00000001005C55D4 loc_1005C55D4                           ; CODE XREF: SongDifficulty::getRatingString(bool)+2C↓j
__text:00000001005C55D4                 CBNZ            W0, loc_1005C55E8
__text:00000001005C55D8                 B               loc_1007DFC28
__text:00000001005C55DC ; ---------------------------------------------------------------------------
__text:00000001005C55DC
__text:00000001005C55DC loc_1005C55DC                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A5E4↓j
__text:00000001005C55DC                                         ; SongDifficulty::getRatingString(bool)-21A5D0↓j ...
__text:00000001005C55DC                 MOV             X0, X19
__text:00000001005C55E0                 BL              ._ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc ; std::string::assign(char const*)
__text:00000001005C55E4                 B               loc_1007DFC38
__text:00000001005C55E8 ; ---------------------------------------------------------------------------
__text:00000001005C55E8
__text:00000001005C55E8 loc_1005C55E8                           ; CODE XREF: SongDifficulty::getRatingString(bool):loc_1005C55D4↑j
__text:00000001005C55E8                 CMN             W0, #1
__text:00000001005C55EC                 B.NE            loc_1005C55FC
__text:00000001005C55F0                 ADRL            X1, aX_6 ; "x"
__text:00000001005C55F8                 B               loc_1005C55DC
__text:00000001005C55FC ; ---------------------------------------------------------------------------
__text:00000001005C55FC
__text:00000001005C55FC loc_1005C55FC                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A5F0↑j
__text:00000001005C55FC                 CMP             W0, #0xE
__text:00000001005C5600                 B.NE            loc_1005C5610
__text:00000001005C5604                 ADRL            X1, asc_100D40524 ; "狂"
__text:00000001005C560C                 B               loc_1005C55DC
__text:00000001005C5610 ; ---------------------------------------------------------------------------
__text:00000001005C5610
__text:00000001005C5610 loc_1005C5610                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A5DC↑j
__text:00000001005C5610                 CMP             W0, #0xF
__text:00000001005C5614                 B.NE            loc_1005C5624
__text:00000001005C5618                 ADRL            X1, asc_100D40528 ; "速"
__text:00000001005C5620                 B               loc_1005C55DC
__text:00000001005C5624 ; ---------------------------------------------------------------------------
__text:00000001005C5624
__text:00000001005C5624 loc_1005C5624                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A5C8↑j
__text:00000001005C5624                 CMP             W0, #0x10
__text:00000001005C5628                 B.NE            loc_1005C563C
__text:00000001005C562C                 ADRL            X1, asc_100D4052C ; "朝"
__text:00000001005C5634                 B               loc_1005C55DC
__text:00000001005C5638 ; ---------------------------------------------------------------------------
__text:00000001005C5638
__text:00000001005C5638 loc_1005C5638                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A478↓j
__text:00000001005C5638                 B               loc_1007DFC0C
__text:00000001005C563C ; ---------------------------------------------------------------------------
__text:00000001005C563C
__text:00000001005C563C loc_1005C563C                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A5B4↑j
__text:00000001005C563C                 CMP             W0, #0x11
__text:00000001005C5640                 B.NE            loc_1005C5650
__text:00000001005C5644                 ADRL            X1, aE_7 ; "暮"
__text:00000001005C564C                 B               loc_1005C55DC
__text:00000001005C5650 ; ---------------------------------------------------------------------------
__text:00000001005C5650
__text:00000001005C5650 loc_1005C5650                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A59C↑j
__text:00000001005C5650                 CMP             W0, #0x12
__text:00000001005C5654                 B.NE            loc_1005C5664
__text:00000001005C5658                 ADRL            X1, asc_100D0A40D ; "Æ"
__text:00000001005C5660                 B               loc_1005C55DC
__text:00000001005C5664 ; ---------------------------------------------------------------------------
__text:00000001005C5664
__text:00000001005C5664 loc_1005C5664                           ; CODE XREF: SongDifficulty::getRatingString(bool)-21A588↑j
__text:00000001005C5664                 CMP             W0, #0x13
__text:00000001005C5668                 B.NE            loc_1005C5748
__text:00000001005C566C                 ADRL            X1, asc_100D40541 ; "Я"
__text:00000001005C5674                 B               loc_1005C55DC
"""

    print(convert_arm64_ida_code(old_base, new_base, ida_code, special_map))