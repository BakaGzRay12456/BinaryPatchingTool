import sys
import re
import os
import binascii
import lief
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, KsError

def assemble_arm64(assembly_code, base_address=0):
    """
    将多行ARM64汇编指令转换为机器码
    :param assembly_code: 多行汇编指令字符串
    :param base_address: 汇编基地址
    :return: 机器码字节串
    """
    # 预处理汇编代码：移除注释和多余空格
    cleaned_lines = []
    for line in assembly_code.splitlines():
        # 移除行内注释（以#或;开头的内容）
        line = re.sub(r'[#;].*$', '', line).strip()
        if line:  # 保留非空行
            cleaned_lines.append(line)
    
    # 将多行合并为Keystone可处理的格式
    asm_text = '\n'.join(cleaned_lines)
    
    if not asm_text:
        raise ValueError("Assembly code can't be empty")
    
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    try:
        encoding, count = ks.asm(asm_text, addr=base_address)
        if count == 0:
            raise ValueError("Unable to assemble any instructions")
        return bytes(encoding)
    except KsError as e:
        # 获取详细的错误信息
        error_line = max(0, e.get_asm_count() - 1)
        error_source = cleaned_lines[error_line] if error_line < len(cleaned_lines) else "<unknown>"
        raise ValueError(f"Error Assembly (Line {error_line + 1}):\n"
                         f"  {error_source}\n"
                         f"  {str(e)}") from e

def modify_binary(input_file, output_file, offset, machine_code):
    """
    修改二进制文件指定位置
    :param input_file: 输入文件名
    :param output_file: 输出文件名
    :param offset: 文件偏移量（整数）
    :param machine_code: 要写入的机器码字节串
    """
    try:
        # 确保偏移量是整数
        offset = int(offset)
    except ValueError:
        raise ValueError("Offset must be an integer")
    
    try:
        with open(input_file, 'rb') as f:
            data = bytearray(f.read())
    except IOError as e:
        raise IOError(f"Unable to read the file: {str(e)}") from e
    
    if offset < 0 or offset > len(data):
        raise ValueError(f"The offset is wrong for the file (0-{len(data)})")
    
    data[offset:offset+len(machine_code)] = machine_code
    
    try:
        with open(output_file, 'wb') as f:
            f.write(data)
    except IOError as e:
        raise IOError(f"Unable to apply changes into the file: {str(e)}") from e

def convert_ida_va_to_file_offset(file_path, va):
    """
    将IDA中的虚拟地址(VA)转换为文件偏移地址
    :param file_path: 二进制文件路径
    :param va: IDA虚拟地址
    :return: 文件偏移地址
    """
    # 使用lief库解析二进制文件
    binary = lief.parse(file_path)
    
    if binary is None:
        raise ValueError(f"Unable to parse the binary file: {file_path}")
    
    # 遍历所有段
    for segment in binary.segments:
        # 检查虚拟地址是否在此段内
        if segment.virtual_address <= va < (segment.virtual_address + segment.virtual_size):
            # 计算文件偏移
            file_offset = va - segment.virtual_address + segment.file_offset
            return file_offset
    
    # 如果没有找到匹配的段
    raise ValueError(f"Unable to locate the VA 0x{va:X} witch matches any segment in the binary file")

def main(input_file, patch_content, offset):
    """
    主处理函数 - 应用补丁到文件
    :param input_file: 输入文件路径
    :param patch_content: 补丁内容（汇编字符串或机器码十六进制字符串）
    :param offset: 文件偏移量或IDA虚拟地址（可以是字符串或整数）
    """
    output_file = input_file
    
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        raise FileNotFoundError(f"Input file doesn't exist: {input_file}")
    
    # 转换偏移量为整数
    try:
        # 处理偏移量（支持十六进制和十进制）
        if isinstance(offset, str):
            if offset.startswith("0x"):
                offset_value = int(offset, 16)
            else:
                offset_value = int(offset)
        else:
            offset_value = int(offset)
    except ValueError:
        raise ValueError("Invalid offset format (hexadecimal with decimal or 0x prefix)")
    
    # 将IDA虚拟地址转换为文件偏移地址
    print(f"[*] VA: 0x{offset_value:X} (IDA Virtual Address)")
    file_offset = convert_ida_va_to_file_offset(input_file, offset_value)
    print(f"[+] File Offset: 0x{file_offset:X}")
    

    if patch_content == "_INPUT":
        # 如果补丁内容是特殊标记，提示用户输入
        user_input = input("请输入补丁内容（字符串）:\n")
        # 编码为字节串并添加空终止符
        machine_code = user_input.encode('utf-8') + b'\x00'

    elif isinstance(patch_content, bytes):
        # 已经是机器码字节串
        machine_code = patch_content

    elif all(c in "0123456789abcdefABCDEF " for c in patch_content):
        # 纯十六进制字符串（无空格）
        hex_str = patch_content.replace(" ", "")
        if len(hex_str) % 2 != 0:
            raise ValueError("机器码十六进制字符串长度应为偶数")
        machine_code = bytes.fromhex(hex_str)
        
    else:
        # 汇编指令
        print(f"[*] 检测到汇编指令，正在编译...")
        machine_code = assemble_arm64(patch_content, base_address=offset_value)
    
    # 确保machine_code是字节串
    if isinstance(machine_code, str):
        machine_code = machine_code.encode('utf-8')
    
    hex_code = ' '.join(f"{b:02x}" for b in machine_code)
    print(f"[+] 机器码 ({len(machine_code)} 字节): {hex_code}")
    print(f"[*] 在文件偏移 0x{file_offset:X} 处应用补丁...")

    modify_binary(input_file, output_file, file_offset, machine_code)
    
    print(f"[+] 成功创建补丁文件: {output_file}")
    return output_file