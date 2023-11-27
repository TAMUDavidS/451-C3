#TODO write a description for this script
#@author Table 11
#@category Functions
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

import csv
import os

from ghidra.program.flatapi import FlatProgramAPI

listing = currentProgram.getListing()

#not a full list, but an educated list of common unsafe c++ funcs
unsafe_functions = [
    'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'gets', 'scanf', 'fscanf', 'sscanf',
    'memcpy', 'memmove', 'memset',
    'strncpy', 'strncat', 'snprintf', 'vsnprintf',
    'fopen', 'freopen', 'tmpnam', 'tempnam', 'mktemp',
    'system', 'popen', 'unlink', 'remove', 'rename',
    'strtok', 'strtok_r', 'strpbrk',
    'rand', 'srand', 'rand_r',
    'asctime', 'ctime', 'gmtime', 'localtime',
    'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf', 'vsscanf',
    'memcpy', 'memmove', 'memset', 'memchr', 'memcmp',
    'gets', 'puts',
    'scanf', 'fscanf', 'sscanf',
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'system', 'popen', 'remove', 'rename', 'tmpnam', 'tempnam', 'mktemp',
]
IO_functions = [
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf', 'vsscanf',
    'fopen', 'freopen', 'tmpnam', 'tempnam', 'mktemp',
    'system', 'popen', 'unlink', 'remove', 'rename',
    'gets', 'puts', 'read', 'write', 'open', 'close', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind']
file_operations = ['open', 'close', 'read', 'write', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind']
    
def is_unsafe_function(function):
    return function.getName() in unsafe_functions

def calls_unsafe_function(function):
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and is_unsafe_function(caller_function):
            return True
    return False

def is_thunk(function):
    instructions = listing.getInstructions(function.getEntryPoint(), True)
    if instructions.hasNext():
        first_instruction = instructions.next()
        return first_instruction.getMnemonicString() == "jmp"
    return False

def is_unused_function(function):
    references = getReferencesTo(function.getEntryPoint())
    return len(references) == 0

def is_IO_function(function):
    # check if any in func
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and caller_function.getName() in IO_functions:
            return True

    # file operations check
    function_name = function.getName()
    for operation in file_operations:
        if operation in function_name:
            return True

    # Check if the function's body contains an I/O function call
    instructions = listing.getInstructions(function.getEntryPoint(), True)
    for instr in instructions:
        mnemonic = instr.getMnemonicString()
        if mnemonic in IO_functions:
            return True

    return False

def is_operation(function):
    # this should be safe because it is a reserved word in c++
    return function.getName().startswith("operator")

def start():
    currentProgram = getCurrentProgram()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    desktopDir = os.path.join(os.path.expanduser("~"), "Desktop")
    outputPath = os.path.join(desktopDir, "functions.csv")

    with open(outputPath, 'wb') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Function Name', 'Address', 'Is Unsafe', 'Calls Unsafe Function', 'Is Thunk', 'Is Unused', 'Is IO Function', 'Is Operation'])

        for function in functions:
            function_name = function.getName()
            function_address = function.getEntryPoint()

            is_unsafe = is_unsafe_function(function)
            calls_unsafe = calls_unsafe_function(function)
            is_potential_thunk = is_thunk(function)
            is_unused = is_unused_function(function)
            is_IO = is_IO_function(function)
            is_op = is_operation(function)

            csvwriter.writerow([function_name, function_address, is_unsafe, calls_unsafe, is_potential_thunk, is_unused, is_IO, is_op])

	print("Export completed. CSV file saved to:", outputPath)

start()

