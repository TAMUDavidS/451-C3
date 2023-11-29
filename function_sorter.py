#TODO write a description for this script
#@author Table 11
#@category 451-C3
#@keybinding 
#@menupath 
#@toolbar 


#TODO Add User Code Here

import csv
import os
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.symbol import SourceType, RefType
from java.awt import Color
from ghidra.app.script import GhidraScript

listing = currentProgram.getListing()
referenceManager = currentProgram.getReferenceManager()

networking_functions = ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'gethostbyname', 'getaddrinfo']

system_functions = ['system', 'popen', 'unlink', 'remove', 'rename', 'tmpnam', 'tempnam', 'mktemp']

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

def is_compiler_created(function):
    functionName = function.getName()
    if functionName.startswith("~") or functionName.startswith("_"):
        return True
    return False

def is_operation(function):
    # this should be safe because it is a reserved word in c++
    return function.getName().startswith("operator")

def is_thunk(function):
    instructions = listing.getInstructions(function.getEntryPoint(), True)
    if instructions.hasNext():
        instr = instructions.next()
        for opIndex in range(instr.getNumOperands()):
                refs = instr.getOperandReferences(opIndex)
                for ref in refs:
                    if ref.getReferenceType() == RefType.THUNK:
                        return True
    return False

def is_unused_function(function):
    references = referenceManager.getReferencesTo(function.getEntryPoint())
    if not any(reference.getReferenceType().isCall() for reference in references):
        return True
    return False

#### contains functions ####

def contains_IO_function(function):
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and caller_function.getName() in IO_functions:
            return True

    return False

def get_calling_function_and_address(function):
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function:
            return "{}@{}".format(caller_function.getName(), reference.getFromAddress())

    return None

def contains_unsafe_function(function):
    calling_info = get_calling_function_and_address(function)
    if calling_info and calling_info.split('@')[0] in unsafe_functions:
        return "{}".format(calling_info)
    return None

def contains_IO_function(function):
    calling_info = get_calling_function_and_address(function)
    if calling_info and calling_info.split('@')[0] in IO_functions:
        return "{}".format(calling_info)
    return None

def contains_network_function(function):
    calling_info = get_calling_function_and_address(function)
    if calling_info and calling_info.split('@')[0] in networking_functions:
        return "{}".format(calling_info)
    return None

def contains_system_function(function):
    calling_info = get_calling_function_and_address(function)
    if calling_info and calling_info.split('@')[0] in system_functions:
        return "{}".format(calling_info)
    return None

def contains_externals(function):
    functionBody = function.getBody()
    for addr in functionBody.getAddresses(True):
        instr = currentProgram.getListing().getInstructionAt(addr)
        if instr:
            # Check if the instruction has any external references
            for opIndex in range(instr.getNumOperands()):
                refs = instr.getOperandReferences(opIndex)
                for ref in refs:
                    if ref.getReferenceType().isCall() and ref.getToAddress().isExternalAddress():
                        return "external references, {}@{}".format(function.getName(), addr)
    return None

#methods for help

def highlight_row(function, color):
    currentProgram = function.getProgram()
    listing = currentProgram.getListing()
    functionBody = function.getBody()

    for addr in functionBody.getAddresses(True):
        setBackgroundColor(addr, color)

def start():
    currentProgram = getCurrentProgram()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    desktopDir = os.path.join(os.path.expanduser("~"), "Desktop")
    outputPath = os.path.join(desktopDir, "{}_functions.csv".format(currentProgram.getName().replace(".o","")))
    #outputPath = "C:\\college\\semesterVII\\csce451\\451-C3\\{}_function.csv".format(currentProgram.getName().replace(".o",""))

    results = {
        "unsafe functions": [],
        "IO functions": [],
        "network functions": [],
        "system functions": [],
        "unused functions": [],
        "operator functions": [],
        "thunk functions": [],
        "compiler-created functions": [],
        "external references": []
    }

    for function in functions:
        function_name = function.getName()
        function_address = function.getEntryPoint()
        calling_info_unsafe = contains_unsafe_function(function)
        is_op = is_operation(function)
        is_unused = is_unused_function(function)
        calling_info_IO = contains_IO_function(function)
        calling_info_network = contains_network_function(function)
        calling_info_system = contains_system_function(function)
        contains_external = contains_externals(function)
        is_th = is_thunk(function)
        is_compiler = is_compiler_created(function)

        if calling_info_unsafe:
            results["unsafe functions"].append(calling_info_unsafe)
            highlight_row(function, Color(255, 0, 0))  # Red for unsafe functions
        if is_unused:
            results["unused functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(0, 255, 0))  # Green for unused functions
        if is_op:
            results["operator functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(0, 0, 255))  # Blue for operator functions
        if calling_info_IO:
            results["IO functions"].append(calling_info_IO)
            highlight_row(function, Color(255, 255, 0))  # Yellow for IO functions
        if calling_info_network:
            results["network functions"].append(calling_info_network)
            highlight_row(function, Color(255, 0, 255))  # Magenta for network functions
        if calling_info_system:
            results["system functions"].append(calling_info_system)
            highlight_row(function, Color(0, 255, 255))  # Cyan for system functions
        if contains_external:
            results["external references"].append(contains_external)
            highlight_row(function, Color(128, 128, 128))  # Gray for external references
        if is_th:
            results["thunk functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(255, 165, 0))  # Orange for thunk functions
        if is_compiler:
            results["compiler-created functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(0, 128, 0))  # Dark Green for compiler-created functions

    with open(outputPath, 'wb') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Function Type', 'Function Details'])

        for func_type, func_list in results.items():
            if func_list:
                row_data = [func_type] + func_list
                csvwriter.writerow(row_data)

    print("Export completed. CSV file saved to: {}".format(outputPath))

start()

