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

networking_functions = ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'gethostbyname', 'getaddrinfo']

#not a full list, but an educated list of common unsafe c++ funcs
unsafe_functions = [
    'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'gets', 'scanf', 'fscanf', 'sscanf',
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
    
def contains_unsafe_function(function):
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and caller_function.getName() in unsafe_functions:
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

def contains_IO_function(function):
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and caller_function.getName() in IO_functions:
            return True

    return False

def contains_network_function(function):
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and caller_function.getName() in networking_functions:
            return True

    return False

def contains_system_function(function):
    pass
    #TODO

def contains_externals(functions):
    pass
    #TODO

def is_compiler_created(function):
    pass
    #TODO

def is_method(function):
    pass
    #TODO

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
        csvwriter.writerow(['Function Name', 'Address', 'Contains Unsafe Function', 'Contains Thunk', 'Is Unused', 'Contains IO Function', 'Contains Network Function'])

        for function in functions:
            function_name = function.getName()
            function_address = function.getEntryPoint()

            contains_unsafe = contains_unsafe_function(function)
            is_op = is_operation(function)
            is_unused = is_unused_function(function)
            is_th = is_thunk(function)
            contains_IO = contains_IO_function(function)
            contains_network = contains_network_function(function)

            csvwriter.writerow([function_name, function_address, contains_unsafe, is_th, is_unused, contains_IO, contains_network])

    print("Export completed. CSV file saved to:", outputPath)

start()

