# Author: Inon Weber and Or Chechik
# Email : inonweber@gmail.com, orchechik@gmail.com
# Twitter: @orchechik
# Description: Volatility plugin to detect rop gadgets in Linux memory dumps

import struct
import volatility.plugins.linux.pslist as linux_pslist
import volatility.plugins.linux.info_regs as linux_info_regs
import volatility.plugins.linux.common as linux_common
import volatility.plugins.malware.malfind as malfind
import volatility.debug as debug
import volatility.obj as obj

try:
    import distorm3
    distorm_loaded = True
except ImportError:
    distorm_loaded = False
    debug.warning("distorm3 isn't found, install distorm3 using pip")

# Constants:

# Critical Functions
CRITICAL_FUNCTIONS = ['__libc_system', 'mmap', 'mmap64', 'mprotect', 'sigreturn']

# Code Control Instructions
CODE_CONTROL_INSTRUCTIONS = ['RET', 'LEAVE', 'INT', "SYSCALL", "SYSENTER"]

# Jump instructions
JUMP_INSTRUCTIONS = ['CALL', 'JMP', 'JNZ', 'JZ', 'JL', 'JE', 'JNE', 'JB', 'JS', 'JG', 'JA', 'JNP', 'JECXZ']

# Junk instructions
JUNK_INSTRUCTIONS = ['IN', 'OUT', 'INS', 'OUTS', 'DB', 'HLT', 'CLC', 'STI', 'ADC', 'SBB', 'LOOPNZ']


# Address Symbol class
class AddressSymbol(object):
    """ A class for representing an address and its function symbol"""

    def __init__(self, address, address_lib, address_symbol, address_symbol_offset):
        """
        :param address: address object
        :param address_lib: name of address' containing VMA
        :param address_symbol: symbol name
        :param address_symbol_offset: offset into symbol\vma of address
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
        if ".so" in self.address_lib:
            return self.address_lib.split('/')[-1].split('.')[0]
        return self.address_lib

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
    def find_symbols(task, search_list, vma=None, search_by_name=False):
        """"
        Find symbols-addresses mapping in specified vma or task.
        :param task: The task_struct object to search the symbols in
        :param search_list: A list of either addresses or symbols, depending on search_by_name parameter
        :param vma: The vma to search in, optional
        :param search_by_name: Search by symbols parameter, default is False for addresses search, use True is for symbols
        :return address-AddressSymbol class dictionary or None if not found
        """
        symbols_dict = {}
        proc_as = task.get_process_address_space()

        # Check if search mode is by symbol name list
        if search_by_name:
            if vma:
                vma_elf = obj.Object("elf_hdr", offset=vma.vm_start, vm=proc_as)
                if vma_elf:

                    # Iterate every symbol in program header dynamic sections
                    for sym in vma_elf.symbols():
                        sym_name = vma_elf.symbol_name(sym)
                        if sym_name in search_list:
                            sym_address = vma_elf.obj_offset + sym.st_value
                            lib_name = vma.vm_name(task)
                            symbols_dict[sym_address] = AddressSymbol(sym_address, lib_name, sym_name, 0)
                else:
                    return symbols_dict
            else:
                return symbols_dict

        # Search mode is by address list
        else:

            # Iterate addresses in address list to search
            for address in search_list:
                if not vma:
                    vma = get_map_by_addr(task, address)
                    if not vma:
                        continue
                vma_elf = obj.Object("elf_hdr", offset=vma.vm_start, vm=proc_as)
                if vma_elf:

                    # Iterate every symbol in program header dynamic sections
                    for sym in vma_elf.symbols():
                        sym_name = vma_elf.symbol_name(sym)
                        sym_addr = vma_elf.obj_offset + sym.st_value
                        if sym_addr == address:
                            sym_address = vma_elf.obj_offset + sym.st_value
                            lib_name = vma.vm_name(task)
                            symbols_dict[vma_elf.obj_offset + sym.st_value] = AddressSymbol(sym_address, lib_name,
                                                                                            sym_name, 0)
                else:
                    continue

        return symbols_dict


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

    def __init__(self, gadget_address, gadget_content, gadget_stack_address, is_critical_function, symbol, gadget_vma,
                 stack_vma, stack_view_list):
        """
        :param gadget_address: the gadget address
        :param gadget_content: gadget instruction data
        :param gadget_stack_address: the address in stack on which the gadget is found
        :param is_critical_function: boolean to mark if the gadget is a critical function
        :param symbol: AddressSymbol object of gadget
        :param gadget_vma: vma object that contains the gadget
        :param stack_vma: vma object that contains the stack found
        :param stack_view_list: a list of StackItem objects
        """
        self.gadget_address = gadget_address
        self.gadget_content = gadget_content
        self.gadget_stack_address = gadget_stack_address
        self.is_critical_function = is_critical_function
        self.symbol = symbol
        self.gadget_vma = gadget_vma
        self.stack_vma = stack_vma
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
    def VMA(self):
        return self.gadget_vma

    @property
    def StackVMA(self):
        return self.stack_vma

    @property
    def StackView(self):
        return self.stack_view_list

    def __repr__(self):
        return "{0:#x}".format(self.Address)


def get_map_by_name(task, name, permissions='r-x'):
    """
    Find a memory mapping (vm_area) by its name (not exact match). Optionally, check permissions.
    Used only for finding libc but can be used to find other vma objects by name.
    :param task: The task_struct object to search in
    :param name: The mapped name to find.
    :param permissions: Permissions in 'rwx' format
    :return a vma object or None
    """
    for vma in task.get_proc_maps():
        libname = linux_common.get_path(task, vma.vm_file)
        if str(vma.vm_flags) == permissions and name in libname:
            return vma
    return None


def get_map_by_addr(task, address, vma_list=None):
    """
        Find a memory mapping (vm_area) by its address, Optionally, search in a specified vma list.
        :param task: The task_struct object to search in
        :param address: Address to search for
        :param vma_list: A list of vma objects to search in
        :return a vma object or None
    """
    if vma_list:
        for vma in vma_list:
            if vma.vm_start.v() <= address <= vma.vm_end.v():
                return vma
    else:
        for vma in task.get_proc_maps():
            if vma.vm_start.v() <= address <= vma.vm_end.v():
                return vma
    return None


def find_stack_vma(task, rsp_address):
    """
    Find the stack vma using the rsp address.
    :param task: the task_struct object to search the stack in
    :param rsp_address: the rsp register address
    :return a tuple of vma object, True or False for is there a possible stack pivoting or None for not finding any vma
    """
    vma = get_map_by_addr(task, rsp_address)
    if not vma:
        return None

    # Secondary threads stack, other threads allocate Anonymous Mapping for their stack
    if vma.vm_name(task) == "Anonymous Mapping" and "rw-" in str(vma.vm_flags):
        return vma, False

    # Main thread stack
    elif vma.vm_name(task) == "[stack]":
        return vma, False

    # Possible Stack Pivoting found
    return vma, True


def get_executable_regions(task):
    """
    Gets executable regions in address space using vma permissions.
    :param task: the task_struct object to search in
    :return a list of vma objects with executable permissions
    """
    executable_regions = []
    for vma in task.get_proc_maps():
        if vma.vm_flags.is_executable():
            executable_regions.append(vma)
    return sorted(executable_regions, key=lambda item: item.vm_start)


def is_pointer_to_executable(address, executable_regions):
    """
    Checks if the address is in an executable region.
    :param address: the address to check
    :param executable_regions: a list of vma objects with executable permissions
    :return True or False
    """
    for vma in executable_regions:
        if vma.vm_start.v() <= address <= vma.vm_end.v():
            return vma
    return None


# Whitelist Rules - Mechanism for whitelisting gadgets.
# You can whitelist using just gadget instructions bytes or make it stricter by supplying gadget symbols info.
# The idea is that you can whitelist gadgets by context using info on the stack so those gadgets only get whitelisted
# on those specific contexts.

whitelist_dict = {
    #MOV RAX, 0xf
    #SYSCALL LibName
    #NOP DWORD [RAX+0x0]
    "48c7c00f0000000f050f1f8000000000": None,
    "488b4708c366662e0f1f840000000000": None
}


class linux_ropfind(linux_pslist.linux_pslist):
    """
    Volatility Plugin to find rop gadgets in Physical memory dumps.
    """

    def __init__(self, config, *args, **kwargs):
        config.add_option("NO-WHITELIST", short_option='N', default=False,
                          action='store_true',
                          help='No whitelist (show all gadgets)')
        config.add_option("ABSOLUTE", short_option='-AB', default=False,
                          action='store_true',
                          help='Show absolute address jumps')
        self._config = config
        linux_pslist.linux_pslist.__init__(self, config, *args, **kwargs)
        linux_common.set_plugin_members(self)
        if self.profile.metadata.get('memory_model', '32bit') == '32bit':
            address_size = 4
            call_instruction_size = 5
            other_call_instruction_size = 8
        else:
            address_size = 8
            call_instruction_size = 8
            other_call_instruction_size = 5
        self.address_size = address_size
        self.call_instruction_size = call_instruction_size
        self.other_call_instruction_size = other_call_instruction_size
        self.thread_offset = self.profile.vtypes['task_struct'][1]['thread_group'][0]

        regs_info = {}
        for (task, name, thread_registers) in linux_info_regs.linux_info_regs(config).calculate():
            regs_info[task.pid.v()] = thread_registers
        self.regs_info = regs_info
        self.dump_file = None
        self.gadget_symbols = {}
        self.task_vma_symbols = {}

        if distorm_loaded:
            self.decode_as = distorm3.Decode32Bits if address_size == 4 else distorm3.Decode64Bits
        else:
            debug.error("You really need the distorm3 python module for this plugin to function properly.")

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

    def get_symbol_offset(self, task, proc_as, vma, address):
        """
        Search address symbol with offset into function
        :param task: The task_struct object
        :param proc_as: The process address space
        :param vma: The vma to search in
        :param address: The address to search the symbol for
        :return: AddressSymbol object appropriate for address
        """

        # Check if this vma was already scanned for symbols
        if vma in self.task_vma_symbols:

            # Check if there are any symbols in this vma
            if self.task_vma_symbols[vma]:
                prev_symbol = self.task_vma_symbols[vma][0]
                last_symbol = self.task_vma_symbols[vma][-1]
                for symbol in self.task_vma_symbols[vma]:

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

            # There are no symbols in this vma
            else:
                lib_name = vma.vm_name(task)
                return AddressSymbol(address, lib_name, None, address - vma.vm_start)

        # Scan for symbols in vma
        else:

            vma_elf = obj.Object("elf_hdr", offset=vma.vm_start, vm=proc_as)
            lib_name = vma.vm_name(task)
            if vma_elf:
                vma_symbols = []

                # Iterate all vma symbols and add them to list
                for sym in vma_elf.symbols():

                    sym_name = vma_elf.symbol_name(sym)

                    sym_address = vma_elf.obj_offset + sym.st_value
                    address_symbol = AddressSymbol(sym_address, lib_name, sym_name, 0)
                    vma_symbols.append(address_symbol)
                if len(vma_symbols) > 0:
                    self.task_vma_symbols[vma] = sorted(vma_symbols, key=lambda item: item.Address)
                else:
                    self.task_vma_symbols[vma] = None
            else:
                self.task_vma_symbols[vma] = None

            # Run again to search the scanned symbols
            return self.get_symbol_offset(task, proc_as, vma, address)

    def find_gadget_symbol(self, task, address):
        """
        Search rop gadget symbol by address, will search in already found gadgets gadget_symbols dict
        :param task: the task_struct object
        :param address: the address to search the symbol for
        :return: the symbol found or None if not found
        """
        not_found = True

        # Search in existing gadgets dict
        if task.pid.v() in self.gadget_symbols:
            for gadget_symbol_dict in self.gadget_symbols[task.pid.v()]:
                if address in gadget_symbol_dict:
                    return gadget_symbol_dict[address]
            not_found = False

        # If not found by now, do the search using find_symbols
        gadget_symbol_dict = AddressSymbol.find_symbols(task, [address])
        if address in gadget_symbol_dict:

            # Check if it's the first time a gadget is found in this task
            if not_found:
                self.gadget_symbols[task.pid.v()] = [gadget_symbol_dict]
            else:
                self.gadget_symbols[task.pid.v()].append(gadget_symbol_dict)
            return gadget_symbol_dict[address]
        return None

    def find_code_control_instructions(self, proc_as, instructions, executable_regions, depth=0):
        """
        Validates if the suspicious rop gadget is indeed a rop gadget by checking if couple of the following
        instructions are part of the CODE_CONTROL_INSTRUCTIONS list.
        :param proc_as: the process address space
        :param instructions: string of the disassembled gadget
        :param executable_regions: a list of vma objects with executable permissions
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

        for instruction in instructions:

            # Filter pointers to junk code
            for junk_instruction in JUNK_INSTRUCTIONS:
                if junk_instruction in instruction[-2]:
                    return False

            if 'MOV ' in instruction[-2] or 'JMP' in instruction[-2] and\
                    '[' in instruction[-2] and ']' in instruction[-2] and '+0x' in instruction[-2]:
                return False

            if 'ADD RSP, 0x' in instruction[-2]:
                return False

            # Return true if non-jump code control function
            for critical_code_control_instruction in CODE_CONTROL_INSTRUCTIONS:
                if critical_code_control_instruction in instruction[-2]:
                    return True

            for jump_instruction in JUMP_INSTRUCTIONS:
                if jump_instruction in instruction[-2]:
                    hex_addr = instruction[-2].split(' ')[-1]

                    # If jumps to absolute address, try to find code control instructions in it
                    if hex_addr.startswith('0x'):

                        try:
                            addr = int(hex_addr, 16)
                        except ValueError as ve:
                            debug.warning("Error converting address at {0}: {1}".format(hex_addr, ve.message))

                            # If it's not a valid address, assume there a code control instruction
                            return True

                        if proc_as.is_valid_address(addr):

                            # Break if an absolute address jump is not specified
                            if not self._config.ABSOLUTE:
                                return False
                            vma = is_pointer_to_executable(addr, executable_regions)
                            if vma:
                                content = proc_as.read(addr, 16)
                                addr_instructions = distorm3.Decode(addr, content, self.decode_as)
                                return self.find_code_control_instructions(proc_as, addr_instructions,
                                                                           executable_regions, depth + 1)

                            # Jumps to non-executable address
                            else:
                                return False
                        # Jumps to non-valid address
                        else:
                            return False

                    # Indirect jump
                    else:
                        return True
        return False

    def is_rop_gadget_address(self, address, task, functions_dict, executable_regions):
        """
        Checks if the address is a rop gadget address by checking if its not a return address
        (the preceding instruction is not a 'CALL') and if the disassembly of the address
        contains code control instruction.
        :param address: the address to check
        :param task: the task_struct object
        :param functions_dict: critical functions dictionary of address-symbol name pairs
        :param executable_regions: a list of vma objects with executable permissions
        :return a tuple of the address, its instructions or None if not disassembled, True or False if it's
        a critical function and the symbol name of the critical function or None if it's not a rop gadget address.
        """

        proc_as = task.get_process_address_space()

        # Return a ROP gadget if it's a pointer to a critical function
        if address in functions_dict:
            return address, None,  True, functions_dict[address]

        # Check if it's a return address, A return address should be placed in the stack with the CALL instruction
        caller_address = address - self.call_instruction_size
        caller_instructions = distorm3.Decode(caller_address, proc_as.read(caller_address,
                                                                           self.call_instruction_size), self.decode_as)

        if caller_instructions:
            try:
                if 'CALL' not in caller_instructions[-1][2]:

                    # Check if the address is calculated using different architecture(32 or 64 bits)
                    other_caller_address = address - self.other_call_instruction_size
                    other_caller_instructions = distorm3.Decode(other_caller_address,
                                                                proc_as.read(other_caller_address,
                                                                             self.other_call_instruction_size),
                                                                self.decode_as)
                    if other_caller_instructions:
                        if 'CALL' not in other_caller_instructions[-1][2]:
                            content = proc_as.read(address, 16)
                            instructions = distorm3.Decode(address, content, self.decode_as)

                            # If not called with the call instruction, check if it's an address to a ROP gadget
                            if self.find_code_control_instructions(proc_as, instructions, executable_regions):
                                gadget_symbol = self.find_gadget_symbol(task, address)
                                if gadget_symbol:
                                    return None
                                else:
                                    return address, content, False, None

            except Exception as e:
                debug.warning("Error disassembling instructions at {0}: {1}".format(address, e.message))

        return None

    def find_rop_gadgets(self, task, stack_start, stack_end, functions_dict, executable_regions):
        """
        Find rop gadgets by scanning for addresses on the stack that reference code segments.
        :param task: the task_struct object
        :param stack_start: stack start address
        :param stack_end: stack end address
        :param functions_dict: critical functions dictionary of address-symbol name pairs
        :param executable_regions: a list of vma objects with executable permissions
        :return a list of stack address found and rop gadget tuples
        """
        proc_as = task.get_process_address_space()
        curr_address = stack_start
        try:

            # Iterate the stack's vma region one address size at the time
            # For each valid code pointer address found check if it's a rop gadget address
            while curr_address <= stack_end:
                if proc_as.is_valid_address(curr_address):

                    # Read an address from the stack
                    curr_stack_value = self.read_address(proc_as, curr_address, self.address_size)
                    if curr_stack_value and curr_stack_value != 0:

                        # Check if it's a gadget only if it's a valid executable address
                        if proc_as.is_valid_address(curr_stack_value):
                            gadget_vma = is_pointer_to_executable(curr_stack_value, executable_regions)
                            if gadget_vma:
                                rop_gadget = self.is_rop_gadget_address(curr_stack_value, task, functions_dict,
                                                                        executable_regions)
                                if rop_gadget:
                                    yield curr_address, rop_gadget, gadget_vma
                curr_address += self.address_size

        except Exception as e:
            debug.warning("Error finding gadgets at {0}: {1}".format(curr_address, e.message))

    def analyze_stack(self, task, thread_task, functions_dict, executable_regions):
        """
        Analyzes the stack of a thread to find rop gadgets.
        :param task: the task_struct object of the thread's process
        :param thread_task: the task_struct object of the thread
        :param functions_dict: critical functions dictionary of address-symbol name pairs
        :param executable_regions: a list of vma objects with executable permissions
        :return a list of found rop gadgets that contains tuples with
        the address on the stack the gadget address was found, the actual gadget address,
        the gadget instructions content at the address, True or False if it's a critical function
        and the corresponding critical function's symbol name or None if the stack wasn't not found.
        """

        proc_as = task.get_process_address_space()

        # linux_info_regs found registers for this thread
        if thread_task.pid.v() in self.regs_info:

            # Get thread registers for this thread
            thread_registers = self.regs_info[thread_task.pid.v()]

            # Check if valid thread registers
            if thread_registers[-1][-1]:

                # Get stack pointer for this thread
                rsp_address = thread_registers[-1][-1].get("rsp")

                # Check if invalid rsp address
                if rsp_address:
                    stack_result = find_stack_vma(thread_task, rsp_address)

                    # Check if any stack is found in vma, could be invalid rsp address
                    if stack_result:
                        (stack_vma, stack_pivot_found) = stack_result

                        if stack_pivot_found:

                            # In this case, stack_vma will NOT be the actual stack
                            debug.info("Possible Stack pivoting found at 0x{:016x} when the the Stack range "
                                       "is 0x{:016x}-0x{:016x} in PID {} and Thread PID {}".format(rsp_address,
                                                                                                   stack_vma.vm_start.v(),
                                                                                                   stack_vma.vm_end.v(),
                                                                                                   task.tgid,
                                                                                                   str(thread_task.pid)))

                        for gadget_stack_address, rop_gadget, gadget_vma in \
                                self.find_rop_gadgets(task, stack_vma.vm_start.v(), stack_vma.vm_end.v(),
                                                      functions_dict, executable_regions):
                            gadget_address, gadget_content, is_critical_function, symbol = rop_gadget

                            # Calculate stack view addresses
                            curr_stack_view = gadget_stack_address - 4 * self.address_size
                            stack_view_end = gadget_stack_address + 4 * self.address_size
                            stack_view_list = []
                            while curr_stack_view <= stack_view_end:
                                curr_stack_value = self.read_address(proc_as, curr_stack_view, self.address_size)

                                # Check if value on stack is valid address
                                if proc_as.is_valid_address(curr_stack_value):
                                    vma = is_pointer_to_executable(curr_stack_value, executable_regions)

                                    # Check if value on stack is executable
                                    if vma:
                                        symbol_offset = self.get_symbol_offset(thread_task, proc_as, vma,
                                                                               curr_stack_value)
                                    else:
                                        symbol_offset = AddressSymbol(curr_stack_value, None, None, None)
                                else:
                                    symbol_offset = AddressSymbol(curr_stack_value, None, None, None)

                                if curr_stack_value == gadget_address:
                                    symbol = symbol_offset

                                stack_item = StackItem(curr_stack_view, symbol_offset)
                                stack_view_list.append(stack_item)
                                curr_stack_view += self.address_size

                            yield Gadget(gadget_address, gadget_content, gadget_stack_address, is_critical_function,
                                         symbol, gadget_vma, stack_vma, stack_view_list)

    def calculate(self):

        for task in linux_pslist.linux_pslist.calculate(self):
            if task:
                self.task_vma_symbols = {}
                libc_vma = get_map_by_name(task, 'libc-', 'r-x')
                if not libc_vma:
                    critical_functions_dict = {}
                else:
                    critical_functions_dict = AddressSymbol.find_symbols(task, CRITICAL_FUNCTIONS, libc_vma, True)
                executable_regions = get_executable_regions(task)
                task_threads = []
                thread = obj.Object('task_struct', task.thread_group.next.v() - self.thread_offset, self.addr_space)
                while thread not in task_threads:
                    task_threads.append(thread)
                    thread = obj.Object('task_struct', thread.thread_group.next.v() - self.thread_offset,
                                        self.addr_space)
                for thread_task in task_threads:
                    for rop_gadget in self.analyze_stack(task, thread_task, critical_functions_dict,
                                                         executable_regions):
                        if rop_gadget:
                            yield thread_task, rop_gadget

    def render_text(self, outfd, data):

        if self.addr_space.profile.metadata.get('memory_model', '32bit') == '32bit':
            bits = '32bit'
        else:
            bits = '64bit'

        for thread_task, rop_gadget in data:

            if not self._config.NO_WHITELIST:
                whitelisted = False

                # Filter out whitelisted gadgets, will not filter out critical functions
                if not rop_gadget.CriticalFunction:
                    if rop_gadget.InstructionsContent in whitelist_dict:
                        if whitelist_dict[rop_gadget.InstructionsContent] !=None:
                            for address_symbol in whitelist_dict[rop_gadget.InstructionsContent]:
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

                if whitelisted:
                    continue

            outfd.write("PID: {0}  Thread name:{1} \n".format(
                thread_task.pid, thread_task.comm))
            outfd.write("Stack address: {0} Gadget address: {1} \n".format(hex(rop_gadget.StackAddress).strip('L'),
                                                                           hex(rop_gadget.Address).strip('L')))
            outfd.write("Gadget VMA name: {0} Gadget VMA permissions: {1} \n".format(rop_gadget.VMA.vm_name
                                                                                     (thread_task),
                                                                                     str(rop_gadget.VMA.vm_flags)))

            # Print either critical function or disassembly of the gadget with its symbol
            if rop_gadget.CriticalFunction:
                outfd.write("Found critical function with symbol: {0} \n".format(rop_gadget.AddressSymbol.Symbol))

            else:

                # Non critical function symbol found for gadget, show disassembly anyway
                if rop_gadget.AddressSymbol and rop_gadget.AddressSymbol.SymbolOffset:
                    outfd.write("Gadget Symbol: {0}+{1}\n".format(rop_gadget.AddressSymbol.Symbol,
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

            outfd.write("Stack VMA: {0} Stack Permissions: {1}\n".format(rop_gadget.StackVMA.vm_name(thread_task),
                                                                         str(rop_gadget.StackVMA.vm_flags)))
            outfd.write("Stack view: \n")
            for stack_item in rop_gadget.StackView:
                outfd.write("{0}\n".format(str(stack_item)))
            outfd.write("\n\n")
