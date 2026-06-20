"""StubExec v1.0.0 | Copyright (c) 2026 Alan. All Rights Reserved.
StubExec stubs a executable with a default: "StubExec says hi!" 
You can change the print to anything with the --print <Sentence>
option!
"""
import sys
import puremagic as pm
from pathlib import Path
import struct
import subprocess; subprocess.run("", shell=True)
import tempfile
import os
import shutil

#Determine if running as frozen/compiled or source
if getattr(sys, 'frozen', False):
    #PyInstaller, cx_Freeze, etc.
    STUB_DIR = Path(sys.executable).parent / "Stubs"
elif 'nuitka' in sys.modules or hasattr(sys.modules.get('__main__'), '__file__'):
    #Nuitka compiled binary
    main_file = getattr(sys.modules.get('__main__'), '__file__', None)
    if main_file:
        STUB_DIR = Path(main_file).parent / "Stubs"
    else:
        STUB_DIR = Path(sys.executable).parent / "Stubs"
else:
    #Source code execution
    STUB_DIR = Path(__file__).parent / "Stubs"

STUB_WIN = STUB_DIR / "Stub.exe"
STUB_ELF = STUB_DIR / "Stub"

if len(sys.argv) < 2:
    print("\033[31mNo arguments given!\033[0m\nUsage: StubExec <FILENAME> [--print <Sentence]: Optional")
    print("StubExec stubs a executable with a builtin file that says \"StubExec says hi!\" by default!")
    sys.exit(1)

args = sys.argv[1:]

#Function below uses puremagic to resolve ELF files
def CheckELFExec(filename: str) -> str:
    file = Path(filename)
    if not file.exists():
        print(f"\033[31mFile: {filename} does not exist!\033[0m")
        sys.exit(1)
    ReturnableResult = pm.magic_file(filename)
    if ReturnableResult and "Executable and Linkable Format" in ReturnableResult[0].name:
        return "ELF"
    elif ReturnableResult and "Windows" in ReturnableResult[0].name:
        return "PE"
    else:
        print(f"\033[31mUnknown file type: {ReturnableResult[0].name if ReturnableResult else 'Unknown'}\033[0m")
        sys.exit(1)

#Now we have to figure out how to argument:
filename = args[0]
PrintSentence = "StubExec says hi!"

if "--print" in args:
    try:
        idx = args.index("--print")
        if idx + 1 < len(args):
            PrintSentence = args[idx + 1]
        else:
            print("\033[31mError: --print requires a sentence after it.\033[0m\n\033[33mExample: StubExec MyFile.exe --print Hello!\033[0m")
            sys.exit(1)
    except (ValueError, IndexError):
        print("\033[31mError caught, exiting!\033[0m")
        sys.exit(1)

FileType = CheckELFExec(filename)

def StubELF(filepath: str, message: str) -> None:
    try:
        if not STUB_ELF.exists():
            print(f"\033[31mStub binary not found at {STUB_ELF}!\033[0m")
            sys.exit(1)
        
        # Read stub binary
        with open(STUB_ELF, 'rb') as f:
            stub_data = bytearray(f.read())
        
        # Parse ELF header of stub
        if stub_data[:4] != b'\x7fELF':
            print("\033[31mInvalid stub ELF header!\033[0m")
            sys.exit(1)
        
        ei_class = stub_data[4]
        ei_data = stub_data[5]
        is_64bit = (ei_class == 2)
        is_little_endian = (ei_data == 1)
        
        # Read ELF header offsets
        if is_64bit:
            e_shoff = struct.unpack('<Q' if is_little_endian else '>Q', stub_data[32:40])[0]
            e_shentsize = struct.unpack('<H' if is_little_endian else '>H', stub_data[58:60])[0]
            e_shnum = struct.unpack('<H' if is_little_endian else '>H', stub_data[60:62])[0]
            e_shstrndx = struct.unpack('<H' if is_little_endian else '>H', stub_data[62:64])[0]
        else:
            e_shoff = struct.unpack('<I' if is_little_endian else '>I', stub_data[32:36])[0]
            e_shentsize = struct.unpack('<H' if is_little_endian else '>H', stub_data[46:48])[0]
            e_shnum = struct.unpack('<H' if is_little_endian else '>H', stub_data[48:50])[0]
            e_shstrndx = struct.unpack('<H' if is_little_endian else '>H', stub_data[50:52])[0]
        
        #Find .rodata or .data section
        rodata_offset = None
        rodata_size = 0
        
        for i in range(e_shnum):
            sh_offset = e_shoff + (i * e_shentsize)
            if is_64bit:
                sh_name = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset:sh_offset+4])[0]
                sh_type = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset+4:sh_offset+8])[0]
                sh_addr = struct.unpack('<Q' if is_little_endian else '>Q', stub_data[sh_offset+16:sh_offset+24])[0]
                sh_offset_data = struct.unpack('<Q' if is_little_endian else '>Q', stub_data[sh_offset+24:sh_offset+32])[0]
                sh_size = struct.unpack('<Q' if is_little_endian else '>Q', stub_data[sh_offset+32:sh_offset+40])[0]
            else:
                sh_name = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset:sh_offset+4])[0]
                sh_type = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset+4:sh_offset+8])[0]
                sh_addr = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset+12:sh_offset+16])[0]
                sh_offset_data = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset+16:sh_offset+20])[0]
                sh_size = struct.unpack('<I' if is_little_endian else '>I', stub_data[sh_offset+20:sh_offset+24])[0]
            
            if sh_type == 1 and sh_size > 0:
                if rodata_offset is None or sh_size > rodata_size:
                    rodata_offset = sh_offset_data
                    rodata_size = sh_size
        
        if rodata_offset is None:
            print("\033[31mCould not find suitable section in stub for injection!\033[0m")
            sys.exit(1)
        
        #Inject message (null-terminated)
        message_bytes = (message + '\x00').encode('utf-8')
        if len(message_bytes) > rodata_size:
            print(f"\033[31mMessage too long! Max: {rodata_size - 1} bytes\033[0m")
            sys.exit(1)
        
        #Overwrite section with message only (don't zero-fill the rest)
        stub_data[rodata_offset:rodata_offset + len(message_bytes)] = message_bytes
        
        #NOTE: Create backup [REMOVE COMMENT #s WHEN PATCHING]
        #backup_path = str(Path(filepath)) + '_backup'
        #shutil.copy2(filepath, backup_path)
        
        # Write to original file
        with open(filepath, 'wb') as f:
            f.write(stub_data)
        
        os.chmod(filepath, 0o755)
        print(f"\033[33mModified: {filepath}\033[0m")
        print(f"\033[33mMessage: '{message}'\033[0m")
        
    except Exception as e:
        print(f"\033[31mELF stubbing failed: {str(e)}\033[0m")
        sys.exit(1)

def StubPE(filepath: str, message: str) -> None:
    try:
        if not STUB_WIN.exists():
            print(f"\033[31mStub binary not found at {STUB_WIN}!\033[0m")
            sys.exit(1)
        
        #Read stub binary
        with open(STUB_WIN, 'rb') as f:
            stub_data = bytearray(f.read())
        
        #Parse DOS header
        if stub_data[:2] != b'MZ':
            print("\033[31mInvalid stub PE header!\033[0m")
            sys.exit(1)
        
        #Get PE header offset
        pe_offset = struct.unpack('<I', stub_data[0x3C:0x40])[0]
        
        if stub_data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            print("\033[31mInvalid stub PE signature!\033[0m")
            sys.exit(1)
        
        #Parse COFF header
        machine = struct.unpack('<H', stub_data[pe_offset+4:pe_offset+6])[0]
        num_sections = struct.unpack('<H', stub_data[pe_offset+6:pe_offset+8])[0]
        size_of_optional = struct.unpack('<H', stub_data[pe_offset+20:pe_offset+22])[0]
        
        #PE optional header starts at pe_offset + 24
        opt_header_offset = pe_offset + 24
        
        #Find .data section
        sections_offset = opt_header_offset + size_of_optional
        data_section_offset = None
        data_virtual_size = 0
        data_raw_size = 0
        data_raw_offset = 0
        
        for i in range(num_sections):
            sec_header_offset = sections_offset + (i * 40)
            sec_name = stub_data[sec_header_offset:sec_header_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            sec_virtual_size = struct.unpack('<I', stub_data[sec_header_offset+8:sec_header_offset+12])[0]
            sec_raw_size = struct.unpack('<I', stub_data[sec_header_offset+16:sec_header_offset+20])[0]
            sec_raw_offset = struct.unpack('<I', stub_data[sec_header_offset+20:sec_header_offset+24])[0]
            
            if sec_name == '.data':
                data_section_offset = sec_header_offset
                data_virtual_size = sec_virtual_size
                data_raw_size = sec_raw_size
                data_raw_offset = sec_raw_offset
                break
        
        if data_section_offset is None:
            print("\033[31mCould not find .data section in stub!\033[0m")
            sys.exit(1)
        
        #Inject message
        message_bytes = (message + '\x00').encode('utf-8')
        available_space = data_raw_size
        
        if len(message_bytes) > available_space:
            print(f"\033[31mMessage too long! Max: {available_space - 1} bytes\033[0m")
            sys.exit(1)
        
        #Overwrite .data section with message only (don't zero-fill the rest)
        stub_data[data_raw_offset:data_raw_offset + len(message_bytes)] = message_bytes
        
        #NOTE: Create backup [ONLY REMOVE THIS WHILE PATCHING]
        #backup_path = str(Path(filepath)) + '_backup'
        #shutil.copy2(filepath, backup_path)
        
        # Write to original file
        with open(filepath, 'wb') as f:
            f.write(stub_data)
        
        print(f"\033[33mModified: {filepath}\033[0m")
        print(f"\033[33mMessage: '{message}'\033[0m")
        
    except Exception as e:
        print(f"\033[31mPE stubbing failed: {str(e)}\033[0m")
        sys.exit(1)

if FileType == "ELF":
    print(f"\033[33mStubbing sentence: {PrintSentence}!\033[0m")
    StubELF(filename, PrintSentence)
else:
    print(f"\033[33mStubbing sentence: {PrintSentence}!\033[0m")
    StubPE(filename, PrintSentence)
