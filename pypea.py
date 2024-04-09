import argparse
import pefile
from colorama import Fore, Style


Fore.RESET = Style.RESET_ALL = ''


BANNER = """
.______   ____    ____ .______    _______      ___      
|   _  \  \   \  /   / |   _  \  |   ____|    /   \     
|  |_)  |  \   \/   /  |  |_)  | |  |__      /  ^  \    
|   ___/    \_    _/   |   ___/  |   __|    /  /_\  \   
|  |          |  |     |  |      |  |____  /  _____  \  
| _|          |__|     | _|      |_______|/__/     \__\ 
                                                        
"""

def load_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        return pe
    except pefile.PEFormatError as e:
        print(f"{Fore.RED}Error loading PE file: {e}{Style.RESET_ALL}")
        return None

def read_standard_headers(pe):
    print(f"{Fore.WHITE}Entry Point:{Style.RESET_ALL} 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
    print(f"{Fore.WHITE}Image Base:{Style.RESET_ALL} 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
    print(f"{Fore.WHITE}Number of Sections:{Style.RESET_ALL} {pe.FILE_HEADER.NumberOfSections}")

def iterate_sections(pe):
    print(f"{Fore.WHITE}Sections:{Style.RESET_ALL}")
    for section in pe.sections:
        print(f"  {Fore.WHITE}Section Name:{Style.RESET_ALL} {section.Name.decode().strip()}")
        print(f"  {Fore.WHITE}Virtual Address:{Style.RESET_ALL} {Fore.GREEN}0x{section.VirtualAddress:08X}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Virtual Size:{Style.RESET_ALL} 0x{section.Misc_VirtualSize:08X}")
        print(f"  {Fore.WHITE}Size of Raw Data:{Style.RESET_ALL} 0x{section.SizeOfRawData:08X}\n")

def list_imported_symbols(pe):
    pe.parse_data_directories()
    print(f"{Fore.WHITE}Imported Symbols:{Style.RESET_ALL}")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(f"  {Fore.WHITE}Imported DLL:{Style.RESET_ALL} {Fore.GREEN}{entry.dll.decode()}{Style.RESET_ALL}")
        for imp in entry.imports:
            print(f"    {Fore.WHITE}Address:{Style.RESET_ALL} {Fore.GREEN}0x{imp.address:08X}{Style.RESET_ALL} {Fore.YELLOW}Name:{Style.RESET_ALL} {Fore.YELLOW}{imp.name.decode()}{Style.RESET_ALL}")
        print()

def list_exported_symbols(pe):
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"{Fore.WHITE}Exported Symbols:{Style.RESET_ALL}")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"  {Fore.WHITE}Exported Address:{Style.RESET_ALL} {Fore.GREEN}0x{pe.OPTIONAL_HEADER.ImageBase + exp.address:08X}{Style.RESET_ALL} {Fore.WHITE}Name:{Style.RESET_ALL} {exp.name.decode()}")

def list_signature(pe):
    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        print(f"{Fore.WHITE}Digital Signature:{Style.RESET_ALL} {Fore.GREEN}Present{Style.RESET_ALL}")
    else:
        print(f"{Fore.WHITE}Digital Signature:{Style.RESET_ALL} {Fore.RED}Not present{Style.RESET_ALL}")

def check_mz_signature(file_path):
    with open(file_path, 'rb') as f:
        mz_signature = f.read(2)
        if mz_signature == b'MZ':
            print(f"{Fore.WHITE}MZ Signature:{Style.RESET_ALL} {Fore.GREEN}Present{Style.RESET_ALL} {Fore.WHITE}(Value:{Style.RESET_ALL} {mz_signature.hex()}{Fore.WHITE}){Style.RESET_ALL}")
        else:
            print(f"{Fore.WHITE}MZ Signature:{Style.RESET_ALL} {Fore.RED}Not present{Style.RESET_ALL}")

def full_dump(pe):
    print(f"{Fore.WHITE}Full Dump:{Style.RESET_ALL}")
    print(pe.dump_info())

def detect_packer(pe):
    suspicious_strings = [b'UPX', b'NSIS', b'PECompact', b'VMProtect']
    file_content = pe.get_memory_mapped_image()
    for s in suspicious_strings:
        if s in file_content:
            print(f"{Fore.WHITE}Packer detected:{Style.RESET_ALL} {Fore.RED}{s.decode()}{Style.RESET_ALL}")

def main():
    
    print(f"{Fore.GREEN}{BANNER}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}@0xeleven{Style.RESET_ALL}\n")

    parser = argparse.ArgumentParser(description="Analyze PE file using pefile.")
    parser.add_argument("-f", "--file", metavar="FILE", help="Path to the PE file", required=True)
    parser.add_argument("--header", action="store_true", help="Display standard headers")
    parser.add_argument("--sections", action="store_true", help="List sections")
    parser.add_argument("--imports", action="store_true", help="List imported symbols")
    parser.add_argument("--exports", action="store_true", help="List exported symbols")
    parser.add_argument("--signature", action="store_true", help="Check digital signature")
    parser.add_argument("--mz-signature", action="store_true", help="Check MZ (DOS) signature")
    parser.add_argument("--all", action="store_true", help="Full dump")  # Remove default value
    parser.add_argument("--packer", action="store_true", help="Detect packer")
    args = parser.parse_args()

    
    if not any([args.header, args.sections, args.imports, args.exports, args.signature, args.mz_signature, args.packer]):
        args.all = True

    pe = load_pe(args.file)
    if pe:
        if args.header:
            read_standard_headers(pe)
        if args.sections:
            iterate_sections(pe)
        if args.imports:
            list_imported_symbols(pe)
        if args.exports:
            list_exported_symbols(pe)
        if args.signature:
            list_signature(pe)
        if args.mz_signature:
            check_mz_signature(args.file)
        if args.all:
            full_dump(pe)
        if args.packer:
            detect_packer(pe)

if __name__ == "__main__":
    main()
