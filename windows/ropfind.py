# Author: Inon Weber and Or Chechik
# Email : inonweber@gmail.com, orchechik@gmail.com
# Twitter: @orchechik
# Description: Volatility plugin to detect rop gadgets in Windows memory dumps

import struct
import volatility.utils as utils
import volatility.plugins.taskmods as taskmods
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.modscan as modscan
import volatility.debug as debug
import volatility.obj as obj

try:
    import distorm3
    has_distorm3 = True
except ImportError:
    has_distorm3 = False
    debug.warning("distorm3 isn't found, install distorm3 using pip")

# Constants:

PAGE_SIZE = 4096

# Critical Functions
CRITICAL_FUNCTIONS = {'ntdll.dll': ['NtSetInformationProcess', 'ZwSetInformationProcess', 'NtProtectVirtualMemory',
                                    'ZwProtectVirtualMemory', 'NtAllocateVirtualMemory', 'NtAllocateVirtualMemoryEx',
                                    'ZwAllocateVirtualMemory', 'ZwAllocateVirtualMemoryEx', 'NtCreateProcess',
                                    'NtCreateProcessEx', 'ZwCreateProcess', 'ZwCreateProcessEx', 'LdrLoadDll'],
                      'kernel32.dll': ['SetProcessInformation', 'VirtualProtect', 'VirtualProtectEx', 'VirtualAlloc',
                                       'VirtualAllocEx', 'VirtualAllocExNuma', 'CreateProcessA', 'CreateProcessW',
                                       'CreateProcessAsUserA', 'CreateProcessAsUserW', 'CreateProcessInternalA',
                                       'CreateProcessInternalW', 'LoadLibraryA', 'LoadLibraryW', 'GetProcAddressStub',
                                       'GetProcAddress', ],
                      'shell32.dll': ['ShellExecuteA', 'ShellExecuteW', 'ShellExecuteEx', 'ShellExecuteExA',
                                      'ShellExecuteExW']}

# Code Control Instructions
CODE_CONTROL_INSTRUCTIONS = ['RET', 'INT', "SYSCALL", "SYSENTER"]

# Jump instructions
JUMP_INSTRUCTIONS = ['CALL', 'JMP', 'JNZ', 'JZ', 'JL', 'JE', 'JNE', 'JB', 'JS', 'JG', 'JA', 'JNP', 'JECXZ']

# Junk instructions
JUNK_INSTRUCTIONS = ['IN', 'OUT', 'INS', 'OUTS', 'DB', 'HLT', 'CLC', 'STI', 'ADC', 'SBB', 'LOOPNZ', 'RCR', 'PSUBSW',
                     'CWDE', 'CDQ', 'STD', 'DAA', 'CMPSB', 'CLD', 'STC']

# Vtypes:

wow64_vtypes = {
  '_WOW64_CONTEXT' : [ 0x2cc, {
    'ContextFlags' : [ 0x0, ['unsigned long']],
    'Dr0' : [ 0x4, ['unsigned long']],
    'Dr1' : [ 0x8, ['unsigned long']],
    'Dr2' : [ 0xc, ['unsigned long']],
    'Dr3' : [ 0x10, ['unsigned long']],
    'Dr6' : [ 0x14, ['unsigned long']],
    'Dr7' : [ 0x18, ['unsigned long']],
    'FloatSave' : [ 0x1c, ['_FLOATING_SAVE_AREA']],
    'SegGs' : [ 0x8c, ['unsigned long']],
    'SegFs' : [ 0x90, ['unsigned long']],
    'SegEs' : [ 0x94, ['unsigned long']],
    'SegDs' : [ 0x98, ['unsigned long']],
    'Edi' : [ 0x9c, ['unsigned long']],
    'Esi' : [ 0xa0, ['unsigned long']],
    'Ebx' : [ 0xa4, ['unsigned long']],
    'Edx' : [ 0xa8, ['unsigned long']],
    'Ecx' : [ 0xac, ['unsigned long']],
    'Eax' : [ 0xb0, ['unsigned long']],
    'Ebp' : [ 0xb4, ['unsigned long']],
    'Eip' : [ 0xb8, ['unsigned long']],
    'SegCs' : [ 0xbc, ['unsigned long']],
    'EFlags' : [ 0xc0, ['unsigned long']],
    'Esp' : [ 0xc4, ['unsigned long']],
    'SegSs' : [ 0xc8, ['unsigned long']],
    'ExtendedRegisters' : [ 0xcc, ['array', 512, ['unsigned char']]]}]
    }


# Profile modification
class Wow64Context(obj.ProfileModification):
    before = ['WindowsObjectClasses', 'WindowsOverlay']
    conditions = {'os': lambda x: x == 'windows'}

    def modification(self, profile):
        profile.vtypes.update(wow64_vtypes)


# Address Symbol class
class AddressSymbol(object):
    """ A class for representing an address and its function symbol"""

    def __init__(self, address, address_lib, address_symbol, address_symbol_offset):
        """
        :param address: address object
        :param address_lib: name of address' containing vad
        :param address_symbol: symbol name
        :param address_symbol_offset: offset into symbol\vad of address
        """
        self.address = address
        self.address_lib = address_lib
        self.address_symbol = address_symbol
        self.address_symbol_offset = address_symbol_offset

    @property
    def Address(self):
        return self.address

    @property
    def LibName(self):
        if ".dll" in str(self.address_lib).lower():
            return str(self.address_lib).split('\\')[-1].split('.')[0].lower()
        return str(self.address_lib).lower()

    @property
    def Symbol(self):
        return self.address_symbol

    @property
    def SymbolOffset(self):
        return self.address_symbol_offset

    @property
    def Valid(self):
        return True if (self.address_lib or self.address_symbol or self.address_symbol_offset) else False

    def __str__(self):
        if not self.Valid:
            return "{0:#18x}".format(self.Address)
        elif not self.address_symbol:
            return "{0:#18x} {1}+{2}".format(self.Address, self.LibName, hex(self.SymbolOffset).strip('L'))
        elif not self.SymbolOffset:
            return "{0:#18x} {1}!{2}".format(self.Address, self.LibName, self.Symbol)
        else:
            return "{0:#18x} {1}!{2}+{3}".format(self.Address, self.LibName, self.Symbol,
                                                 hex(self.SymbolOffset).strip('L'))

    def __repr__(self):
        if not self.Valid:
            return "{0:#18x}".format(self.Address)
        elif not self.address_symbol:
            return "{0:#18x} {1}+{2}".format(self.Address, self.LibName, hex(self.SymbolOffset).strip('L'))
        elif not self.SymbolOffset:
            return "{0:#18x} {1}!{2}".format(self.Address, self.LibName, self.Symbol)
        else:
            return "{0:#18x} {1}!{2}+{3}".format(self.Address, self.LibName, self.Symbol,
                                                 hex(self.SymbolOffset).strip('L'))

    @staticmethod
    def get_symbols(task):
        """
        Gets all symbols in a specific task, used on every process for caching purposes.
        :param task:
        :return: dict of {pid: {address:symbol}} or empty dict if none found.
        """
        symbols_dict = {}

        for module in task.get_load_modules():
            dll_name = module.FullDllName

            # Iterate every export for each module
            for o, f, n in module.exports():
                if n and f:
                    symbols_dict[f] = AddressSymbol(f + module.DllBase, dll_name, n, 0)

        return symbols_dict

    @staticmethod
    def find_symbols(task, search_list, search_by_name=False, specified_modules=False):
        """"
        Find symbols-addresses mapping in specified task.
        :param task: the _EPROCESS object to search the symbols in
        :param search_list: a list of either addresses or symbols, depending on search_by_name parameter
        :param search_by_name: search by symbols parameter, default is False for addresses search, use True is for symbols
        :param specified_modules: specify modules to search in. If True, search_list will be module name-symbols dictionary
        :return address-AddressSymbol class dictionary or None if not found
        """
        symbols_dict = dict()

        # Check if search mode is by symbol name list
        if search_by_name:

            # Specific modules are specified, check them first
            if specified_modules:

                # Iterate only modules specified and loaded by process
                for module in task.get_load_modules():
                    if not module.BaseDllName:
                        continue
                    lib_name = str(module.BaseDllName).lower()
                    searched_symbols = []

                    if lib_name not in search_list:

                        if lib_name == "kernelbase.dll":

                            if "kernel32.dll" in search_list:
                                searched_symbols = search_list["kernel32.dll"]
                            if "advapi32.dll" in search_list:
                                for symbol in search_list["advapi32"]:
                                    searched_symbols.append(symbol)
                        else:
                            continue
                    if len(searched_symbols) == 0:
                        searched_symbols = search_list[lib_name]

                    # Iterate every export for each module
                    for o, f, n in module.exports():
                        if n and f:
                            if str(n) in searched_symbols:
                                symbols_dict[int(f)+module.DllBase] = AddressSymbol(f + module.DllBase, lib_name, n, 0)

            else:

                # Iterate every module loaded by process
                for module in task.get_load_modules():

                    # Iterate every export for each module
                    for o, f, n in module.exports():
                        if n and f:
                            if str(n) in search_list:
                                lib_name = module.FullDllName
                                symbols_dict[f] = AddressSymbol(f + module.DllBase, lib_name, n, 0)

        # Search mode is by address list
        else:

            # Iterate addresses in address list to search
            for address in search_list:

                    # Iterate every module loaded by process
                    for module in task.get_load_modules():

                        # Iterate every export for each module
                        for o, f, n in module.exports():
                            if n and f:
                                symbol_addr = f + module.DllBase
                                if symbol_addr == address:
                                    lib_name = module.FullDllName
                                    symbols_dict[symbol_addr] = AddressSymbol(symbol_addr, lib_name, n, 0)

        return symbols_dict


# Whitelist Rules - Mechanism for whitelisting gadgets.
# You can whitelist using just gadget instructions bytes or make it stricter by supplying gadget symbols info.
# The idea is that you can whitelist gadgets by context using info on the stack so those gadgets only get whitelisted
# on those specific contexts.

whitelist_gadgets = {
    #MOV EAX, EAX
    #RET
    '8bc0c390909090908bff558bec83ec14': [AddressSymbol(None, "RPCRT4", "NdrFreeBuffer", 0x2fb)],

    #MOV EAX, [ECX+0x50]
    #PUSH ECX
    #PUSH DWORD [EAX]
    #MOV EAX, [0x77bf8450]
    #CALL DWORD [EAX+0x34]
    '8b415051ff30a15084bf77ff5034c3f6': [AddressSymbol(None, "RPCRT4", "RpcMgmtSetCancelTimeout", 0xf9),],

    #MOV ECX, 0x17766ac1
    #RET 0x766a
    #...
    'b9c16a7617c26a7690909090908bff55': [AddressSymbol(None, "ole32", "CoCreateInstanceEx", 0x185a)],
    '00000100000000000000f00f3400f00f':None,
    '0f3400f00f3400021004000000000000':None
}

# Whitelist symbols - whitelist using symbols only
whitelist_symbols = ['KiFastSystemCallRet', 'KiFastSystemCall']

# Stack view class
class StackItem(object):
    """ A class for organizing the stack view into items"""

    def __init__(self, stack_address, stack_value_symbol):
        """
        :param stack_address: address on stack
        :param stack_value_symbol: AddressSymbol object of the address found in stack
        """
        self.stack_address = stack_address
        self.stack_value_symbol = stack_value_symbol

    @property
    def StackAddress(self):
        return self.stack_address

    @property
    def StackValueSymbol(self):
        return self.stack_value_symbol

    def __str__(self):
        return "{0:#x} {1}".format(self.StackAddress, str(self.StackValueSymbol))

    def __repr__(self):
        return "{0:#x} {1}".format(self.StackAddress, str(self.StackValueSymbol))


# ROP Gadget class
class Gadget(object):
    """A class for representing a single gadget"""

    def __init__(self, gadget_address, gadget_content, gadget_stack_address, is_critical_function, symbol, gadget_vad,
                 stack_start, stack_end, stack_view_list):
        """
        :param gadget_address: the gadget address
        :param gadget_content: gadget instruction data
        :param gadget_stack_address: the address in stack on which the gadget is found
        :param is_critical_function: boolean to mark if the gadget is a critical function
        :param symbol: AddressSymbol object of gadget
        :param gadget_vad: vad object that contains the gadget
        :param stack_start: start address of the stack found
        :param stack_end: end address of the stack found
        :param stack_view_list: a list of StackItem objects
        """
        self.gadget_address = gadget_address
        self.gadget_content = gadget_content
        self.gadget_stack_address = gadget_stack_address
        self.is_critical_function = is_critical_function
        self.symbol = symbol
        self.gadget_vad = gadget_vad
        self.stack_start = stack_start
        self.stack_end = stack_end
        self.stack_view_list = stack_view_list

    @property
    def Address(self):
        return self.gadget_address

    @property
    def InstructionsContent(self):
        return self.gadget_content.encode('hex')

    @property
    def StackAddress(self):
        return self.gadget_stack_address

    @property
    def CriticalFunction(self):
        return self.is_critical_function

    @property
    def AddressSymbol(self):
        return self.symbol

    @property
    def VAD(self):
        return self.gadget_vad

    @property
    def StackStart(self):
        return self.stack_start

    @property
    def StackEnd(self):
        return self.stack_end

    @property
    def StackView(self):
        return self.stack_view_list

    def __repr__(self):
        return "{0:#x}".format(self.Address)


def get_map_by_addr(task, address, vad_list=None):
    """
        Find a memory mapping (vad) by its address, Optionally, search in a specified vad list.
        :param task: the _EPROCESS object to search in
        :param address: address to search for
        :param vad_list: a list of vad objects to search in
        :return a vad object or None
    """
    if vad_list:
        for vad in vad_list:
            if vad.Start <= address <= vad.End:
                return vad
    else:
        for vad in task.VadRoot.traverse():
            if vad.Start <= address <= vad.End:
                return vad
    return None


def get_executable_regions(task):
    """
    Gets executable regions in address space using vad permissions.
    :param task: the _EPROCESS object to search in
    :return a list of vad objects with executable permissions
    """
    executable_regions = []
    for vad in task.VadRoot.traverse():
        protect = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), "")
        if "EXECUTE" in protect:
            executable_regions.append(vad)
    return sorted(executable_regions, key=lambda item: vad.Start)


def is_pointer_to_executable(address, executable_regions):
    """
    Checks if the address is in an executable region.
    :param address: the address to check
    :param executable_regions: a list of vad objects with executable permissions
    :return True or False
    """
    for vad in executable_regions:
        if vad.Start <= address <= vad.End:
            return vad
    return None


class Ropfind(taskmods.DllList):
    """ Volatility Plugin to find rop gadgets in Windows physical memory dumps. """

    def __init__(self, config, *args, **kwargs):
        config.add_option("NO-WHITELIST", short_option='N', default=False,
                          action='store_true',
                          help='No whitelist (show all gadgets)')
        config.add_option("ABSOLUTE", short_option='-AB', default=False,
                          action='store_true',
                          help='Show absolute address jumps')
        self._config = config
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        self.addr_space = utils.load_as(self._config)

        if self.addr_space.profile.metadata.get("memory_model", "32bit") == "32bit":
            self.set_32_bitness()

        else:
            self.set_64_bitness()

        self.current_process_gadgets = None
        self.executable_regions = dict()
        self.functions_dict = None
        self.gadget_symbols = dict()
        self.task_vad_symbols = dict()
        self.pid_task = dict()
        self.teb_dict = dict()
        self.task_symbols = dict()

    def set_32_bitness(self):
        """
        Set plugin mode to 32bit/ wow64 - used to read pointers/ dissassemble / determine ret address
        :return:
        """
        self.bits = distorm3.Decode32Bits
        self.address_size = 4
        self.regular_call_instruction_size = 5
        self.direct_call_instruction_size = 6
        self.indirect_call_instruction_size = 2

    def set_64_bitness(self):
        """
        Sets plugin mode to 64bit - used to read pointers/ dissassemble / determine ret address
        :return:
        """
        self.bits = distorm3.Decode64Bits
        self.address_size = 8
        self.regular_call_instruction_size = 8
        self.direct_call_instruction_size = 6
        self.indirect_call_instruction_size = 2


    def read_address(self, space, start, length=None):
        """
        Read an address in a space, at a location, of a certain length.
        :param space: the address space
        :param start: the address
        :param length: size of the value
        :return address
        """
        if not length:
            length = self.address_size
        fmt = "<I" if length == 4 else "<Q"
        data = space.read(start, length)

        # Address might be paged out
        if data:
            return struct.unpack(fmt, data)[0]
        else:
            return None

    def get_executable_regions(self, task):
        """
        Return the executable regions for the specified process
        :param task: the EPROCESS object to get executable regions from
        :return: executable vads dictionary
        """
        if task.UniqueProcessId.v() in self.executable_regions:
            executable_regions = self.executable_regions[task.UniqueProcessId.v()]
        else:
            executable_regions = get_executable_regions(task)
            self.executable_regions[task.UniqueProcessId.v()] = executable_regions
        return executable_regions

    def get_symbol_offset(self, task, vad, address):
        """
        Search address symbol with offset into function
        :param task: the task_struct object
        :param vad: the vad to search in
        :param address: the address to search the symbol for
        :return: AddressSymbol object appropriate for address
        """

        # Check if this vad was already scanned for symbols
        if (task.UniqueProcessId, vad) in self.task_vad_symbols:

            # Check if there are any symbols in this vad
            if self.task_vad_symbols[(task.UniqueProcessId, vad)]:
                prev_symbol = self.task_vad_symbols[(task.UniqueProcessId, vad)][0]
                last_symbol = self.task_vad_symbols[(task.UniqueProcessId, vad)][-1]
                for symbol in self.task_vad_symbols[(task.UniqueProcessId, vad)]:

                    # Check if found symbol range
                    if address < symbol.Address:

                        # If found, use the previous symbol
                        address_symbol_offset = address - prev_symbol.Address
                        return AddressSymbol(address, prev_symbol.LibName, prev_symbol.Symbol, address_symbol_offset)

                    # Address is in last symbol
                    elif symbol == last_symbol:
                        address_symbol_offset = address - symbol.Address
                        return AddressSymbol(address, symbol.LibName, symbol.Symbol, address_symbol_offset)
                    prev_symbol = symbol

            # There are no symbols in this vad
            else:
                lib_name = ''
                try:
                    if vad.FileObject:
                        lib_name = vad.FileObject.file_name_with_device()
                except AttributeError:
                    lib_name = str(task.ImageFileName)
                return AddressSymbol(address, lib_name, None, address - vad.Start)

        # Scan for symbols in vad
        else:

            for module in task.get_load_modules():

                # Find the correct module for the specified vad
                if vad.Start == module.DllBase.v():
                    lib_name = module.FullDllName
                    vad_symbols = []

                    # Iterate all vad symbols and add them to list
                    for o, f, n in module.exports():
                        if n and f:
                            symbol_addr = f + module.DllBase
                            address_symbol = AddressSymbol(symbol_addr, lib_name, n, 0)
                            vad_symbols.append(address_symbol)
                    if len(vad_symbols) > 0:
                        self.task_vad_symbols[(task.UniqueProcessId, vad)] = sorted(vad_symbols,
                                                                                    key=lambda item: item.Address)
                    else:
                        self.task_vad_symbols[(task.UniqueProcessId, vad)] = None

            # No appropriate module found for vad
            if (task.UniqueProcessId, vad) not in self.task_vad_symbols:
                self.task_vad_symbols[(task.UniqueProcessId, vad)] = None

            # Run again to search the scanned symbols
            return self.get_symbol_offset(task, vad, address)

    def find_gadget_symbol(self, task, address):
        """
        Search rop gadget symbol by address, will search in already found gadgets gadget_symbols dict
        :param task: the EPROCESS object
        :param address: the address to search the symbol for
        :return: the symbol found or None if not found
        """
        not_found = True

        # Search in existing gadgets dict
        if task.UniqueProcessId.v() in self.gadget_symbols:
            for gadget_symbol_dict in self.gadget_symbols[task.UniqueProcessId.v()]:
                if address in gadget_symbol_dict:
                    return gadget_symbol_dict[address]
            not_found = False

        # If not found by now, do the search using find_symbols
        task_symbols = self.task_symbols.get(task.UniqueProcessId.v())

        address_symbol = task_symbols.get(address, None)
        gadget_symbol_dict = {address: address_symbol}

        if address_symbol is not None:

            # Check if it's the first time a gadget is found in this task
            if not_found:
                self.gadget_symbols[task.UniqueProcessId.v()] = [gadget_symbol_dict]
            else:
                self.gadget_symbols[task.UniqueProcessId.v()].append(gadget_symbol_dict)
            return gadget_symbol_dict[address]
        return None

    def find_code_control_instructions(self, task_as, instructions, executable_regions, depth=0):
        """
        Validates if the suspicious rop gadget is indeed a rop gadget by checking if couple of the following
        instructions are part of the CODE_CONTROL_INSTRUCTIONS list.
        :param task_as: the process address space
        :param instructions: string of the disassembled gadget
        :param executable_regions: a list of vad objects with executable permissions
        :param depth: recursion depth
        :return True or False
        """

        # Stop after 3 calls
        if depth == 3:
            return False

        # Skip null bytes
        if len(instructions) >= 2:
            if instructions[0][-1] == '0000' and instructions[1][-1] == '0000':
                return False
            if 'LEAVE' in instructions[0][-2] and 'RET' in instructions[1][-2]:
                return False

        #callback functions that are not used with CALL and are not a critical function can be filtered.
        if len(instructions) >= 3:
            if 'MOV EDI, EDI' in instructions[0][-2] and 'PUSH EBP' in instructions[1][-2] \
                    and 'MOV EBP, ESP' in instructions[2][-2]:
                return False

        for instruction in instructions:

            # Filter pointers to junk code
            for junk_instruction in JUNK_INSTRUCTIONS:
                if junk_instruction in instruction[-2]:
                    return False

            if self.bits == distorm3.Decode32Bits:
                sp = "ESP"
            else:
                sp = "RSP"

            # Filter MOV ESP, Absolute Address instructions as they make no sense in rop gadgets
            if 'MOV {}, 0x'.format(sp) in instruction[-2]:
                return False

            # Filter global variables access
            if '0x' in instruction[-2]  and '[' in instruction[-2] and ']' in instruction[-2]:
                return False
            if 'ADD' in instruction[-2] and ', 0x' in instruction[-2]:
                return False

            #filter big constant ret

            if 'RET' in instruction[-2] and '0x' in instruction[-2]:
                hex_addr = instruction[-2].strip(' ;NOT TAKEN').split(' ')[-1]
                try:
                    addr = int(hex_addr, 16)
                    if addr > 16:
                        return False
                except:
                    pass

            # Filter variable function calls/jmps out
            if 'CALL' in instruction[-2] or 'JMP' in instruction[-2] and '[' in instruction[-2] \
                    and '+0x' in instruction[-2] or '-0x' in instruction[-2]:
                return False

            # Filter XMM registers in gadgets as they are not used.
            if 'XMM' in instruction[-2]:
                return False

            # Return true if non-jump code control function
            for critical_code_control_instruction in CODE_CONTROL_INSTRUCTIONS:
                if critical_code_control_instruction in instruction[-2]:
                    return True

            for jump_instruction in JUMP_INSTRUCTIONS:
                if jump_instruction in instruction[-2]:
                    hex_addr = instruction[-2].strip(' ;NOT TAKEN').split(' ')[-1]

                    if hex_addr.startswith('['):
                        hex_addr = hex_addr.strip('[').strip(']')

                    # If jumps to absolute address, try to find code control instructions in it
                    if hex_addr.startswith('0x'):

                        try:
                            addr = int(hex_addr, 16)
                        except ValueError as ve:

                            # Ignore far calls that cause a value error here
                            if 'FAR' in instruction[-2] and ':' in hex_addr:
                                return False
                            debug.warning("Error converting address at {0}: {1}".format(hex_addr, ve.message))

                            # If it's not a valid address, assume there a code control instruction
                            return True

                        if task_as.is_valid_address(addr):

                            # Break if an absolute address jump is not specified
                            if not self._config.ABSOLUTE:
                                return False
                            vad = is_pointer_to_executable(addr, executable_regions)
                            if vad:
                                content = task_as.read(addr, 16)
                                addr_instructions = distorm3.Decode(addr, content, self.bits)
                                return self.find_code_control_instructions(task_as, addr_instructions,
                                                                           executable_regions, depth + 1)

                            # Jumps to non-executable address
                            else:
                                return False

                        # Jumps to non-valid address
                        else:
                            return False

                    # Indirect jump
                    else:

                        # Skip jmp rip+0xAAAA-style jumps because they are not used in rop chains
                        if ('RIP' in instruction[-2] and self.bits is distorm3.Decode64Bits) or (
                                'EIP' in instruction[-2] and self.bits is distorm3.Decode32Bits):
                            return False
                        return True
        return False

    def is_rop_gadget_address(self, address, task):
        """
        Checks if the address is a rop gadget address by checking if its not a return address
        (the preceding instruction is not a 'CALL') and if the disassembly of the address
        contains code control instruction.
        :param address: the address to check
        :param task: the EPROCESS object
        :return a tuple of the address, its instructions or None if not disassembled, True or False if it's
        a critical function and the symbol name of the critical function or None if it's not a rop gadget address.
        """

        gadget = self.current_process_gadgets.get(address, None)

        if gadget is not None:
            return gadget

        task_as = task.get_process_address_space()
        executable_regions = self.get_executable_regions(task)

        # Return a ROP gadget if it's a pointer to a critical function
        if address in self.functions_dict:
            value = address, None,  True, self.functions_dict[address]
            self.current_process_gadgets[address] = value
            return value

        try:

            # Check if it's a return address, A return address should be placed in the stack with the CALL instruction
            caller_address = address - self.regular_call_instruction_size
            caller_instructions = distorm3.Decode(caller_address, task_as.read(caller_address,
                                                                               self.regular_call_instruction_size),
                                                  self.bits)

            if caller_instructions:
                if 'CALL' in caller_instructions[-1][2]:
                    return None

            # Test for x86 module with 5 opcodes CALL used in 64-bit first
            if self.bits == distorm3.Decode64Bits:
                x86_caller_address = address - 5
                x86_caller_instructions = distorm3.Decode(x86_caller_address, task_as.read(x86_caller_address, 5),
                                                          self.bits)
                if x86_caller_instructions:
                    if 'CALL' in x86_caller_instructions[-1][2]:
                        return None

            # Check if the address is calculated using direct address calls:
            direct_caller_address = address - self.direct_call_instruction_size
            direct_caller_instructions = distorm3.Decode(direct_caller_address, task_as.read(direct_caller_address,
                                                                                             self.direct_call_instruction_size), self.bits)
            if direct_caller_instructions:
                if 'CALL' in direct_caller_instructions[-1][2]:
                    return None

            # Check if the address is calculated using indirect address calls:
            indirect_caller_address = address - self.indirect_call_instruction_size
            indirect_caller_instructions = distorm3.Decode(indirect_caller_address, task_as.read(
                indirect_caller_address, self.indirect_call_instruction_size), self.bits)
            if indirect_caller_instructions:
                if 'CALL' in indirect_caller_instructions[-1][2]:
                    return None

            content = task_as.read(address, 16)
            instructions = distorm3.Decode(address, content, self.bits)

            # If not called with the call instruction, check if it's an address to a ROP gadget
            if self.find_code_control_instructions(task_as, instructions, executable_regions):
                gadget_symbol = self.find_gadget_symbol(task, address)
                if gadget_symbol:
                    return None
                else:
                    value = address, content, False, None
                    self.current_process_gadgets[address] = value
                    return value

        except Exception as e:
            debug.warning("Error disassembling instructions at {0}: {1}".format(address, e.message))

        return None

    def find_rop_gadgets(self, task, stack_start, stack_end):
        """
        Find rop gadgets by scanning for addresses on the stack that reference code segments.
        :param task: the EPROCESS object
        :param stack_start: stack start address
        :param stack_end: stack end address
        :return a list of stack address found and rop gadget tuples with the corresponding gadget vad
        """
        task_as = task.get_process_address_space()
        curr_address = stack_start
        executable_regions = self.get_executable_regions(task)

        try:

            # Iterate the stack region one address size at the time
            # For each valid code pointer address found check if it's a rop gadget address
            while curr_address <= stack_end:
                if task_as.is_valid_address(curr_address):

                    # Read an address from the stack
                    curr_stack_value = self.read_address(task_as, curr_address, self.address_size)
                    if curr_stack_value and curr_stack_value != 0:

                        # Check if it's a gadget only if it's a valid executable address
                        if task_as.is_valid_address(curr_stack_value):

                            gadget_vad = is_pointer_to_executable(curr_stack_value, executable_regions)
                            if gadget_vad:
                                rop_gadget = self.is_rop_gadget_address(curr_stack_value, task)
                                if rop_gadget:
                                    yield curr_address, rop_gadget, gadget_vad
                curr_address += self.address_size

        except Exception as e:
            debug.warning("Error finding gadgets at {0}: {1}".format(curr_address, e.message))

    def analyze_stack(self, thread, thread_task, wow64=False):
        """
        Analyzes the stack of a thread to find rop gadgets.
        :param thread: the ETHREAD object of the thread to scan
        :param thread_task: the EPROCESS object of the thread's process
        :param wow64: indicates whether the thread is in a wow64 process and scans the thread's 32-bit stack if True
        :return a list of found rop gadgets that contains tuples with
        the address on the stack the gadget address was found, the actual gadget address,
        the gadget instructions content at the address, True or False if it's a critical function
        and the corresponding critical function's symbol name or None if the stack wasn't not found.
        """

        thread_as = thread_task.get_process_address_space()
        if (thread.Cid.UniqueProcess.v(), thread.Cid.UniqueThread.v()) not in self.teb_dict:
            thread_teb = obj.Object('_TEB', offset=thread.Tcb.Teb.v(), vm=thread_as)
        else:
            thread_teb = self.teb_dict[(thread.Cid.UniqueProcess.v(), thread.Cid.UniqueThread.v())]
        x86_teb = None
        if thread_teb:
            thread_tib = obj.Object('_NT_TIB', offset=thread_teb.NtTib.v(), vm=thread_as)

            if thread_tib:

                if wow64:
                    if thread_tib.ExceptionList:
                        x86_teb = obj.Object('_TEB32', offset=thread_tib.ExceptionList.v(), vm=thread_as)
                        if x86_teb:
                            thread_tib = obj.Object('_NT_TIB32', offset=x86_teb.NtTib.v(), vm=thread_as)
                        else:
                            thread_tib = None
                    else:
                        thread_tib = None

                if thread_tib:

                    stack_start = thread_tib.StackLimit.v()
                    stack_end = thread_tib.StackBase.v()

                    # Check if valid stack address
                    if stack_start <= stack_end:

                        if wow64:
                            # According to Microsoft documentation, wow64_context can be found at 64-bit TEB's
                            # TlsSlots[1] at offset 4
                            context = obj.Object('_WOW64_CONTEXT', offset=thread_teb.TlsSlots[1] + 4, vm=thread_as)
                            if context:

                                # Get 32-bit version of thread registers in a wow64 process from wow64_context
                                sp_address = context.Esp.v()
                                if x86_teb:
                                    thread_teb = x86_teb
                            else:
                                sp_address = None

                        else:

                            # Get thread registers via trap frame
                            trap_frame = thread.Tcb.TrapFrame.dereference_as("_KTRAP_FRAME")

                            if trap_frame:

                                if self.bits == distorm3.Decode32Bits:

                                    sp_address = trap_frame.HardwareEsp.v()
                                else:
                                    sp_address = trap_frame.Rsp.v()
                            else:
                                sp_address = None

                        if sp_address:

                            # Check for stack pivot
                            if not (stack_start <= sp_address <= stack_end):
                                debug.info("Possible Stack pivoting found at 0x{:016x} when the the Stack range "
                                           "is 0x{:016x}-0x{:016x} in PID {} and TID {}".format(sp_address,
                                                                                                stack_start,
                                                                                                stack_end,
                                                                                                thread_task.UniqueProcessId.v(),
                                                                                                thread.Cid.UniqueThread.v()))
                                sp_vad = get_map_by_addr(thread_task, sp_address)

                                # If there's a pivot, scan sp address' vad if found instead for gadgets
                                if sp_vad:
                                    stack_start = sp_vad.Start
                                    stack_end = sp_vad.End

                                else:
                                    stack_start = sp_address
                                    stack_end = sp_address + 4096
                    else:
                        executable_regions = self.get_executable_regions(thread_task)
                        curr_stack_view = stack_end - self.address_size
                        stack_pivot = True

                        # Every thread should have BaseThreadInitThunk in its callstack
                        # If it doesn't, assume a stack pivot has occurred
                        while curr_stack_view >= stack_start:

                            curr_stack_value = self.read_address(thread_as, curr_stack_view, self.address_size)

                            # Check if value on stack is valid address
                            if thread_as.is_valid_address(curr_stack_value):

                                vad = is_pointer_to_executable(curr_stack_value, executable_regions)

                                # Check if value on stack is executable
                                if vad:
                                    symbol_offset = self.get_symbol_offset(thread_task, vad, curr_stack_value)

                                    if "BaseThreadInitThunk" in symbol_offset.Symbol:
                                        stack_pivot = False
                                        break

                            curr_stack_view -= self.address_size

                        if stack_pivot:
                            debug.info("Possible Stack pivoting - ntdll!BaseThreadInitThunk symbol wasn't found, the Stack range "
                                       "is 0x{:016x}-0x{:016x} in PID {} and TID {}".format(stack_start, stack_end,
                                                                                            thread_task.UniqueProcessId.v(),
                                                                                            thread.Cid.UniqueThread.v()))
                    executable_regions = self.get_executable_regions(thread_task)

                    for gadget_stack_address, rop_gadget, gadget_vad in self.find_rop_gadgets(thread_task, stack_start,
                                                                                              stack_end):
                        gadget_address, gadget_content, is_critical_function, symbol = rop_gadget
                        curr_stack_view = gadget_stack_address - 4 * self.address_size
                        stack_view_end = gadget_stack_address + 4 * self.address_size
                        stack_view_list = []
                        while curr_stack_view <= stack_view_end:
                            curr_stack_value = self.read_address(thread_as, curr_stack_view, self.address_size)
                            # Check if the read was successful
                            if curr_stack_value:

                                # Check if value on stack is valid address
                                if thread_as.is_valid_address(curr_stack_value):

                                    vad = is_pointer_to_executable(curr_stack_value, executable_regions)

                                    # Check if value on stack is executable
                                    if vad:
                                        symbol_offset = self.get_symbol_offset(thread_task, vad, curr_stack_value)
                                    else:
                                        symbol_offset = AddressSymbol(curr_stack_value, None, None, None)
                                else:
                                    symbol_offset = AddressSymbol(curr_stack_value, None, None, None)

                                if curr_stack_value == gadget_address:
                                    symbol = symbol_offset

                                stack_item = StackItem(curr_stack_view, symbol_offset)
                                stack_view_list.append(stack_item)
                            curr_stack_view += self.address_size

                        yield Gadget(gadget_address, gadget_content, gadget_stack_address, is_critical_function, symbol,
                                     gadget_vad, stack_start, stack_end, stack_view_list)

        else:

            # Skip if thread isn't running anymore and has broken TEB link or if it's a system thread
            if (not thread.Tcb.Running.v() and thread.Tcb.State.v() == 4) or thread_task.UniqueProcessId.v() == 4:
                yield None

    def analyze_vad(self, task, target_vad):
        """
        Scan a vad for rop gadgets, treat the vad as a "stack" as it can be a pivoted stack.
        :param task: the EPROCESS object of the process
        :param target_vad: the MMVAD object to scan
        :return: a list of found rop gadgets that contains tuples with
        the address on the stack the gadget address was found, the actual gadget address,
        the gadget instructions content at the address, True or False if it's a critical function
        and the corresponding critical function's symbol name or None if the stack wasn't not found.
        """
        task_as = task.get_process_address_space()
        executable_regions = self.get_executable_regions(task)

        for gadget_stack_address, rop_gadget, gadget_vad in self.find_rop_gadgets(task, target_vad.Start, target_vad.End):
            gadget_address, gadget_content, is_critical_function, symbol = rop_gadget
            curr_stack_view = gadget_stack_address - 4 * self.address_size
            stack_view_end = gadget_stack_address + 4 * self.address_size
            stack_view_list = []
            while curr_stack_view <= stack_view_end:
                curr_stack_value = self.read_address(task_as, curr_stack_view, self.address_size)

                # Check if read was successful
                if curr_stack_value:
                    # Check if value on stack is valid address
                    if task_as.is_valid_address(curr_stack_value):

                        vad = is_pointer_to_executable(curr_stack_value, executable_regions)

                        # Check if value on stack is executable
                        if vad:
                            symbol_offset = self.get_symbol_offset(task, vad, curr_stack_value)
                        else:
                            symbol_offset = AddressSymbol(curr_stack_value, None, None, None)
                    else:
                        symbol_offset = AddressSymbol(curr_stack_value, None, None, None)

                    if curr_stack_value == gadget_address:
                        symbol = symbol_offset

                    stack_item = StackItem(curr_stack_view, symbol_offset)
                    stack_view_list.append(stack_item)
                curr_stack_view += self.address_size

            yield Gadget(gadget_address, gadget_content, gadget_stack_address, is_critical_function, symbol,
                         gadget_vad, target_vad.Start, target_vad.End, stack_view_list)

    def calculate(self):

        seen_threads = dict()

        # Check Memory dump's OS architecture
        if self.addr_space.profile.metadata.get('memory_model', '32bit') == '32bit':
            bits = '32bit'
        else:
            bits = '64bit'

        # Gather threads by list traversal of active/linked processes
        for task in taskmods.DllList(self._config).calculate():
            self.current_process_gadgets = {}  # Address: rop gadget tuple

            # resolve critical functions pointers once per process
            self.functions_dict = AddressSymbol.find_symbols(task, CRITICAL_FUNCTIONS, True, True)

            self.pid_task[task.UniqueProcessId.v()] = task
            # Cache symbols per process
            self.task_symbols[task.UniqueProcessId.v()] = AddressSymbol.get_symbols(task)

            task_as = task.get_process_address_space()
            executable_regions = []

            # Add Teb and executable mappings while also scanning RW small allocations
            for vad in task.VadRoot.traverse():
                if vad.u5.VadFlags3.Teb.v():
                    teb = obj.Object('_TEB', offset=vad.Start, vm=task_as)
                    if teb:
                        self.teb_dict[(teb.ClientId.UniqueProcess.v(), teb.ClientId.UniqueThread.v())] = teb
                protect = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), "")
                if "EXECUTE" in protect:
                    executable_regions.append(vad)

            self.executable_regions[task.UniqueProcessId.v()] = sorted(executable_regions, key=lambda item: vad.Start)

            # Enumerate threads
            for thread in task.ThreadListHead. \
                    list_of_type("_ETHREAD", "ThreadListEntry"):
                seen_threads[thread.obj_vm.vtop(thread.obj_offset)] = (False, thread)

            # Scan vads for rop gadgets, called the second time so executable regions will be updated.
            for vad in task.VadRoot.traverse():

                # Skip large allocations and stick to page sized allocations
                if vad.End - vad.Start <= PAGE_SIZE:
                    for rop_gadget in self.analyze_vad(task, vad):
                        yield task, None, rop_gadget, bits

        # Now scan for threads and save any that haven't been seen
        #for thread in modscan.ThrdScan(self._config).calculate():
        #    if thread.obj_offset not in seen_threads:
        #        seen_threads[thread.obj_offset] = (True, thread)

        for _offset, (found_by_scanner, thread) in seen_threads.items():

            # Get thread's corresponding EPROCESS object from prepared dictionary
            if thread.Cid.UniqueProcess.v() not in self.pid_task:

                # If the dictionary does not contain the object, try extracting the EPROCESS from the ETHREAD itself
                thread_task = thread.owning_process()
                if not thread_task.is_valid():
                    continue
            else:
                thread_task = self.pid_task[thread.Cid.UniqueProcess.v()]

            # Scan Stack for 32/64bit stacks
            for rop_gadget in self.analyze_stack(thread, thread_task):
                if rop_gadget:
                    yield thread_task, thread, rop_gadget, bits

            # Scan again with special flag for WOW64 stack - There are 2 stacks for WOW64 processes
            if thread_task.IsWow64:

                # Set bitness for WOW64
                self.set_32_bitness()
                bits = '32bit'

                for rop_gadget in self.analyze_stack(thread, thread_task, True):
                    if rop_gadget:
                        yield thread_task, thread, rop_gadget, bits

                # Set bitness back to 64bit
                self.set_64_bitness()


    def render_text(self, outfd, data):

        for thread_task, thread, rop_gadget, bits in data:

            if not self._config.NO_WHITELIST:
                whitelisted = False

                # Filter out whitelisted gadgets, will not filter out critical functions
                if not rop_gadget.CriticalFunction:
                    if rop_gadget.InstructionsContent in whitelist_gadgets:
                        if whitelist_gadgets[rop_gadget.InstructionsContent] != None:
                            for address_symbol in whitelist_gadgets[rop_gadget.InstructionsContent]:
                                if address_symbol.LibName and address_symbol.Symbol:
                                    if address_symbol.LibName == rop_gadget.AddressSymbol.LibName and \
                                            address_symbol.Symbol == str(rop_gadget.AddressSymbol.Symbol):

                                        if address_symbol.SymbolOffset:

                                            if address_symbol.SymbolOffset == rop_gadget.AddressSymbol.SymbolOffset:
                                                whitelisted = True

                                            else:
                                                whitelisted = False
                                                break

                                        # If no specific address was specified, skip this gadget
                                        if not address_symbol.Address:
                                            whitelisted = True
                                            break

                                        # If a specific address was specified, skip only if there's a match
                                        elif address_symbol.Address == rop_gadget.AddressSymbol.Address:
                                            whitelisted = True
                                            break
                        else:
                            whitelisted = True
                    # Filter out whitelist symbols
                    if str(rop_gadget.AddressSymbol.Symbol) in whitelist_symbols:
                            whitelisted = True

                if whitelisted:
                    continue

            if thread:
                outfd.write("PID: {0}  Process name: {1} TID: {2}\n".format(
                    thread_task.UniqueProcessId.v(), thread_task.ImageFileName, thread.Cid.UniqueThread.v()))
            else:
                outfd.write("PID: {0}  Process name: {1}\n".format(
                    thread_task.UniqueProcessId.v(), thread_task.ImageFileName))
            outfd.write("Stack address: {0} Gadget address: {1} \n".format(hex(rop_gadget.StackAddress).strip('L'),
                                                                           hex(rop_gadget.Address).strip('L')))
            vad_protection = vadinfo.PROTECT_FLAGS.get(rop_gadget.VAD.VadFlags.Protection.v(),
                                                       hex(rop_gadget.VAD.VadFlags.Protection))
            outfd.write("Gadget VAD: {0} Gadget VAD permissions: {1} \n".format(hex(rop_gadget.VAD.v()).strip('L'),
                                                                                vad_protection))

            # Print either critical function or disassembly of the gadget with its symbol
            if rop_gadget.CriticalFunction:
                outfd.write("\nCritical function Gadget with symbol: {0} \n\n".format(rop_gadget.AddressSymbol.Symbol))

            else:

                # Non critical function symbol found for gadget, show disassembly anyway
                if rop_gadget.AddressSymbol and rop_gadget.AddressSymbol.SymbolOffset:
                    outfd.write("Gadget Symbol: {0}+{1}\n".format(str(rop_gadget.AddressSymbol.Symbol),
                                                                  hex(rop_gadget.AddressSymbol.SymbolOffset)
                                                                  .strip('L')))
                outfd.write("Gadget address disassembly: \n")
                outfd.write("\n")
                outfd.write("\n".join(
                    ["{0:#x} {1:<16} {2}".format(o, h, i)
                     for o, i, h in malfind.Disassemble(rop_gadget.InstructionsContent.decode('hex'),
                                                        rop_gadget.Address, bits=bits)
                     ]))
                outfd.write("\n\n")

            stack_vad = get_map_by_addr(thread_task, rop_gadget.StackStart)
            if stack_vad:
                stack_protection = vadinfo.PROTECT_FLAGS.get(stack_vad.VadFlags.Protection.v(),
                                                             hex(stack_vad.VadFlags.Protection))
                outfd.write("Stack Start: {0} Stack End: {1} Stack Permissions: {2}\n".format(
                    hex(rop_gadget.StackStart).strip('L'), hex(rop_gadget.StackEnd).strip('L'), stack_protection))
            outfd.write("Stack view: \n")
            for stack_item in rop_gadget.StackView:
                outfd.write("{0}\n".format(str(stack_item)))
            outfd.write("\n\n")

