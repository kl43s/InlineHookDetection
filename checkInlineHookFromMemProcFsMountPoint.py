import pefile
import sys 
import os

def isNearJmp(first_bytes):
    if first_bytes[:1] == b'\xe9':
        return True, int.from_bytes(first_bytes[1:5], "little", signed="True"), None
    else:
        return False, None, None
    
def isAbsoluteJmp(first_bytes):
    instructions32 = {
        b'\xb8':'mov eax',
        b'\xbb':'mov ebx',
        b'\xb9':'mov ecx',
        b'\xba':'mov edx',
    }
    
    instructions64 = {
        b'\x48\xb8':'mov rax',
        b'\x48\xbb':'mov rbx',
        b'\x48\xb9':'mov rcx',
        b'\x48\xba':'mov rdx',
    }
    
    jmp32 = {
       b'\xff\xe0':'jmp eax',
       b'\xff\xe3':'jmp ebx',
       b'\xff\xe1':'jmp ecx',
       b'\xff\xe2':'jmp edx'
    }
    
    jmp64 = {
       b'\xff\xe0':'jmp rax',
       b'\xff\xe3':'jmp rbx',
       b'\xff\xe1':'jmp rcx',
       b'\xff\xe2':'jmp rdx'
    }
    
    # 32 bits mode
    if ( instructions32.get(first_bytes[:1]) ) and ( jmp32.get(first_bytes[5:7]) ):
        return True, int.from_bytes(first_bytes[1:5], "little", signed="True"), f'{instructions32[first_bytes[:1]]}::{jmp32[first_bytes[5:7]]}', True
    
    # 64 bits mode
    elif ( instructions64.get(first_bytes[:2]) ) and ( jmp64.get(first_bytes[9:11]) ):
        return True, int.from_bytes(first_bytes[2:9], "little", signed="True"), f'{instructions32[first_bytes[:2]]}::{jmp32[first_bytes[9:11]]}', False
        
    else:
        return False, None, None, None

def isAddressValid(pe, hookFuncAddr, base_address, func_name):
    address = base_address + hookFuncAddr
    for section in pe.sections:
        section_start = base_address + section.VirtualAddress
        section_end = base_address + section_start + section.Misc_VirtualSize
        if section_start <= address < section_end:
            return True 
    return False
     
def checkHookInFunc(cDLL, num_bytes, cProcess, cModule):
    #print(cDLL)
    countHook = 0
    try:
        pe = pefile.PE(cDLL)
    except pefile.PEFormatError:
        return countHook
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        #print(f'{cProcess}::{cModule} contains no export table.')
        return countHook
    
    base_address = pe.OPTIONAL_HEADER.ImageBase
    exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
    mask = 0
    for exp in exports:
        if exp.name:
            func_name = exp.name.decode()
            if func_name in ['GetFileBandwidthReservation', '_mbscpy_s', '_spawnve', '_wexeclpe', 'NtUserAllowForegroundActivation', 'NtUserEnablePerMonitorMenuScaling', 'NtUserIsQueueAttached', 'NtUserYieldTask', 'CPNameUtil_ConvertToRoot', 'g_module_open_utf8']: # trop de faux positif, sonne pour chaque processus
                continue
            
            try:
                file_offset = pe.get_offset_from_rva(exp.address)
            except pefile.PEFormatError:
                #print(f'Format error for -> {cProcess}::{cModule}::{func_name}')
                continue
            
            with open(cDLL, 'rb') as dll_file:
                dll_file.seek(file_offset)
                first_bytes = dll_file.read(num_bytes)
                
            isNear, hookFuncAddr, __ = isNearJmp(first_bytes)
            isAbsolute, hookFuncAddrAbs, instructions, isWow64 = isAbsoluteJmp(first_bytes)
            if isWow64:
                mask = 0xffffffff
            else:
                mask = 0xffffffffffffffff
                
            if isNear:
                if not isAddressValid(pe, file_offset+hookFuncAddr, base_address, func_name):
                    countHook += 1
                    print(f'[+] {cProcess}::{cModule}::{func_name} :\n\tjmp {hex(hookFuncAddr & 0xffffffff)}\n')
            elif isAbsolute:
                if not isAddressValid(pe, file_offset+hookFuncAddrAbs, base_address, func_name):
                    countHook += 1
                    instruction1, instruction2 = instructions.split('::')
                    print(f'[+] {cProcess}::{cModule}::{func_name}  :\n\t{instruction1}, {hex(hookFuncAddrAbs & mask)}\n\t{instruction2}\n')      
    return countHook
        
def process(MemProcFsPath, num_bytes):
    MemProcFsPath += '\\name\\'
    ProcessList = os.listdir(MemProcFsPath)
    for cProcess in ProcessList:
        if cProcess in ['System-4']:
            continue
        ModulesList = os.listdir(MemProcFsPath + cProcess + '\\modules\\')
        totalCountHook = 0
        for cModule in ModulesList:
            #if cModule.lower() not in ['kernel32.dll','kernelbase.dll','ntdll.dll', 'ws2_32.dll']:
            if ".dll" not in cModule.lower():
                continue
            cDLL = MemProcFsPath + cProcess + '\\modules\\' + cModule + '\\pefile.dll'
            countHook = checkHookInFunc(cDLL, num_bytes, cProcess, cModule)
            totalCountHook += countHook
        if totalCountHook == 0:
            print(f'No hook found on {cProcess.split("-")[0]}::{cProcess.split("-")[1]} process')
        else:
            print(f'number of hook -> {totalCountHook}')

if __name__ == '__main__':
    MemProcFsPath = sys.argv[1] if len(sys.argv) > 1 else 'M:'
    num_bytes = 12
    process(MemProcFsPath, num_bytes)
