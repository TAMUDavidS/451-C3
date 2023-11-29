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

listing = currentProgram.getListing()

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

visited = ['free']

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
        instr = instructions.next()
        for opIndex in range(instr.getNumOperands()):
                refs = instr.getOperandReferences(opIndex)
                for ref in refs:
                    if ref.getReferenceType() == RefType.THUNK:
                        return True
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
    references = getReferencesTo(function.getEntryPoint())
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function and caller_function.getName() in system_functions:
            return True
    return False
    
def contains_conditional_statement(function):
    functionBody = function.getBody()
    for addr in functionBody.getAddresses(True):
        instr = currentProgram.getListing().getInstructionAt(addr)
        if instr:
            # Check if the instruction has any external references
            for opIndex in range(instr.getNumOperands()):
                refs = instr.getOperandReferences(opIndex)
                for ref in refs:
                    if ref.getReferenceType().isConditional():
                        return True
    return False


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
                        return True
    
    return False

def is_compiler_created(function):
    functionName = function.getName().encode('utf-8')
    if functionName in visited:
        return True
    
    elif functionName.startswith("~") or functionName.startswith("_"):
        visited.append(functionName)
        visited.append(functionName[1:])
        return True
    elif is_operation(function):
        return True
    
    return False

def is_operation(function):
    # this should be safe because it is a reserved word in c++
    return function.getName().startswith("operator")

def start():
    #change me to generate a csv to a local folder instead.
    currentProgram = getCurrentProgram()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    desktopDir = os.path.join(os.path.expanduser("~"), "Desktop")
    outputPath = os.path.join(desktopDir, "{}_functions.csv".format(currentProgram.getName().replace(".o","")))
    #outputPath = "C:\\college\\semesterVII\\csce451\\451-C3\\{}_function.csv".format(currentProgram.getName().replace(".o",""))

    with open(outputPath, 'wb') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Function Name', 'Address', 'Contains Unsafe Function', 'Is Thunk', 'Is Operation' ,'Is Unused', 'Contains IO Function', 'Contains Network Function', 'Contains System Function'])

        for function in functions:
            function_name = function.getName()
            function_address = function.getEntryPoint()
            # print("{} : {}".format(function_name, function_address))

            contains_unsafe = contains_unsafe_function(function)
            is_op = is_operation(function)
            is_unused = is_unused_function(function)
            is_th = is_thunk(function)
            contains_IO = contains_IO_function(function)
            contains_network = contains_network_function(function)
            compiler_generated = is_compiler_created(function)
            contains_external = contains_externals(function)
            contains_conditional = contains_conditional_statement(function)
            contains_system = contains_system_function(function)
            
            csvwriter.writerow([function_name, function_address, contains_unsafe, is_th, is_op ,is_unused, contains_IO, contains_network, contains_system])

    print("Export completed. CSV file saved to: {}".format(outputPath))

start()

