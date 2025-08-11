import core,json,os
from colorama import init, Fore, Style

# 初始化colorama
init(autoreset=True)

def print_header(title):
    """打印带颜色的标题"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{title.center(60)}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

def print_section(title):
    """打印带颜色的部分标题"""
    print(f"\n{Fore.YELLOW}{title}{Style.RESET_ALL}")
    print(f"{'-'*len(title)}")

def print_error(message):
    """打印错误信息"""
    print(f"{Fore.RED}ERROR: {message}{Style.RESET_ALL}")

def print_success(message):
    """打印成功信息"""
    print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def print_warning(message):
    """打印警告信息"""
    print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

def main():
    # 显示工具标题
    print_header("BINARY PATCHING TOOL")
    
    # 平台选择部分
    print_section("TARGET PLATFORM SELECTION")
    print(f"{Fore.BLUE}1. iOS{Style.RESET_ALL}")
    print(f"{Fore.BLUE}2. Android{Style.RESET_ALL}")
    
    # 获取有效的平台输入
    while True:
        targetPlatform = input(f"{Fore.MAGENTA}> Enter platform ID (1-2): {Style.RESET_ALL}")
        if targetPlatform in ("1", "2"):
            break
        print_error("Invalid input. Please enter 1 or 2.")
    
    targetPlatform = "iOS" if targetPlatform == "1" else "android"
    
    # 加载版本列表
    version_file = f"{targetPlatform}/versionList.json"
    if not os.path.exists(version_file):
        print_error(f"Version list not found at {version_file}")
        return
    
    try:
        with open(version_file, 'r') as f:
            versionList = json.load(f)
    except json.JSONDecodeError:
        print_error("Invalid JSON format in version list")
        return
    
    # 显示可用版本
    print_section(f"AVAILABLE VERSIONS ({targetPlatform.upper()})")
    for i, version in enumerate(versionList, 1):
        print(f"{Fore.CYAN}{i}. {version['version']}{Style.RESET_ALL}")
    
    # 获取有效的版本输入
    while True:
        try:
            targetVersion = int(input(f"{Fore.MAGENTA}> Enter version ID: {Style.RESET_ALL}"))
            if 1 <= targetVersion <= len(versionList):
                break
            print_error(f"Please enter a number between 1 and {len(versionList)}.")
        except ValueError:
            print_error("Please enter a valid number.")
    
    # 获取文件路径
    print_section("FILE SELECTION")
    while True:
        filePath = input(f"{Fore.MAGENTA}> Enter file path to patch: {Style.RESET_ALL}")
        if os.path.isfile(filePath):
            break
        print_error("File not found. Please enter a valid file path.")
    
    # 创建补丁后的文件
    with open(filePath, 'rb') as f:
        fileTemp = bytearray(f.read())
    
    patched_path = filePath + "_patched"
    with open(patched_path, 'wb') as f:
        f.write(fileTemp)
    
    # 准备补丁数据
    patchList = versionList[targetVersion-1]["patchList"]
    patchFile = versionList[targetVersion-1]["patchFile"]
    
    # 加载补丁代码
    try:
        with open(f"{targetPlatform}/{patchFile}", 'r') as f:
            code = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        print_error("Failed to load patch data")
        return
    
    # 补丁选择循环
    while True:
        print_section(f"AVAILABLE PATCHES ({versionList[targetVersion-1]['version']})")
        
        # 显示补丁选项
        for i, patch in enumerate(patchList, 1):
            print(f"{Fore.CYAN}{i}. {patch['Description']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{len(patchList)+1}. Apply all patches{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{len(patchList)+2}. Finish and exit{Style.RESET_ALL}")
        
        # 获取补丁选择
        while True:
            try:
                patchID = input(f"{Fore.MAGENTA}> Enter patch ID: {Style.RESET_ALL}")
                if patchID.lower() in ("exit", "quit"):
                    print("\nExiting patch tool.")
                    return
                
                patchID = int(patchID)
                if 1 <= patchID <= len(patchList) + 2:
                    break
                print_error(f"Please enter a number between 1 and {len(patchList)+2}.")
            except ValueError:
                print_error("Please enter a valid number.")
        
        # 处理退出选项
        if patchID == len(patchList) + 2:
            print_header("PATCHING COMPLETE")
            print_success(f"Modified file saved to: {patched_path}")
            print_warning("Original file remains unchanged.")
            break
        
        # 应用补丁
        if patchID == len(patchList) + 1:  # 应用所有补丁
            print("\nApplying all patches...")
            for patch_index in range(len(patchList)):
                for patch_data in code[patch_index]["patches"]:
                    core.main(patched_path, patch_data["code"], patch_data["offset"])
            print_success("All patches applied successfully!")
        else:  # 应用单个补丁
            patch_index = patchID - 1
            print(f"\nApplying patch: {Fore.CYAN}{patchList[patch_index]['Description']}{Style.RESET_ALL}")
            for patch_data in code[patch_index]["patches"]:
                core.main(patched_path, patch_data["code"], patch_data["offset"])
            print_success("Patch applied successfully!")

if __name__ == "__main__":
    main()