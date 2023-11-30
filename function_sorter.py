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
from ghidra.program.model.address import AddressFactory
from javax.swing import JFrame, JCheckBox, JButton, JPanel
from java.awt import BorderLayout

selected_functions = {}  # Added line

listing = currentProgram.getListing()
referenceManager = currentProgram.getReferenceManager()

network_functions = ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'gethostbyname', 'getaddrinfo']

system_functions = ['system', 'popen', 'unlink', 'remove', 'rename', 'tmpnam', 'tempnam', 'mktemp']

# Not a full list, but an educated list of common unsafe c++ funcs
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
    'gets', 'puts', 'read', 'write', 'open', 'close', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind'
]

file_operations = ['open', 'close', 'read', 'write', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind']


class FunctionSelectionFrame(JFrame):
    def __init__(self, function_types):
        super(JFrame, self).__init__("Select Functions to Highlight")

        self.selected_functions = set()

        # Create checkboxes for each function type
        self.checkboxes = []
        for function_type in function_types:
            checkbox = JCheckBox(function_type)
            checkbox.addItemListener(self.checkboxListener)
            self.checkboxes.append(checkbox)

        # Create a button to apply the selection
        apply_button = JButton("Apply Selection", actionPerformed=self.applySelection)

        # Set up the layout
        panel = self.getContentPane()
        panel.setLayout(BorderLayout())

        checkbox_panel = JPanel()
        for checkbox in self.checkboxes:
            checkbox_panel.add(checkbox)

        panel.add(checkbox_panel, BorderLayout.CENTER)
        panel.add(apply_button, BorderLayout.SOUTH)

        # Set frame properties
        self.setSize(300, 400)
        self.setLocationRelativeTo(None)
        self.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)

    def checkboxListener(self, event):
        checkbox = event.getSource()
        function_type = checkbox.getText()

        if checkbox.isSelected():
            self.selected_functions.add(function_type)
        else:
            self.selected_functions.discard(function_type)

    def applySelection(self, event):
        self.dispose()

def highlight_row(function, color):
    currentProgram = function.getProgram()
    listing = currentProgram.getListing()
    functionBody = function.getBody()

    for addr in functionBody.getAddresses(True):
        setBackgroundColor(addr, color)

def print_to_console(selected_functions, results):
    for func_type, func_list in zip(results.keys(), results.values()):
        if len(func_list) == 0:
            continue
        for func_detail in func_list:
            if isinstance(func_detail, list):
                for detail in func_detail:
                    print_detail(selected_functions, func_type, detail)
            elif isinstance(func_detail, str):
                print_detail(selected_functions, func_type, func_detail)

def print_detail(selected_functions, func_type, func_detail):
    if '@' in func_detail:
        function_name, function_address = func_detail.split('@')
        if function_address:
            address = currentProgram.getAddressFactory().getAddress(function_address)
            if address:
                symbol = currentProgram.getSymbolTable().createLabel(address, function_name, SourceType.USER_DEFINED)
                symbol.setPrimary()
                # Print information to the console
                println("Function Type: {} | Function Name: {} | Function Address: {}".format(func_type,
                                                                                            function_name,
                                                                                            function_address))

def show_results_gui(results):
    function_types = list(results.keys())

    # Create and display the custom JFrame
    frame = FunctionSelectionFrame(function_types)
    frame.setVisible(True)

    while frame.isVisible():
        continue

    # Process the user's selection
    global selected_functions
    selected_functions = frame.selected_functions
    print(selected_functions)
    for selected_function in selected_functions:
        if selected_function in results:
            for func_details_list in results[selected_function]:
                for func_detail in func_details_list:
                    function_name, function_address = func_detail.split('@')
                    address = currentProgram.getAddressFactory().getAddress(function_address)
                    highlight_function(address)

def is_compiler_created(function):
    calling_info = None
    functionName = function.getName()
    if functionName.startswith("~") or functionName.startswith("_"):
	calling_info = get_calling_info(function)
    return calling_info if not None else None

def is_operation(function):
    calling_info = None
    # this should be safe because it is a reserved word in c++
    if function.getName().startswith("operator"):
	calling_info = get_calling_info(function)
    return calling_info if not None else None

def is_thunk(function):
    calling_info = None
    instructions = listing.getInstructions(function.getEntryPoint(), True)
    if instructions.hasNext():
        instr = instructions.next()
        if instr.getMnemonicString() == "JMP":
            calling_info = get_calling_info(function)
    return calling_info if not None else None


def is_unused_function(function):
    function_address = function.getEntryPoint()
    references = referenceManager.getReferencesTo(function_address)
    if not any(reference.getReferenceType().isCall() for reference in references) and not function.getName().startswith("_"):
        return "{}@{}".format(function.getName(), function_address)
    return None


#### contains functions ####

def get_calling_info(function):
    references = getReferencesTo(function.getEntryPoint())
    calling_info = []
    for reference in references:
        caller_function = getFunctionContaining(reference.getFromAddress())
        if caller_function:
            calling_info.append("{}@{}".format(caller_function.getName(), reference.getFromAddress()))

    return calling_info if calling_info else None

# Modify the contains_IO_function
def contains_IO_function(function):
    if function.getName() in IO_functions:
	return None
    calling_info = get_calling_info(function)
    return calling_info if not None else None

# Modify the contains_unsafe_function
def contains_unsafe_function(function):
    if function.getName() in unsafe_functions:
	return None
    calling_info = get_calling_info(function)
    return calling_info if not None else None

# Modify the contains_network_function
def contains_network_function(function):
    if function.getName() in network_functions:
	return None
    calling_info = get_calling_info(function)
    return calling_info if not None else None

# Modify the contains_system_function
def contains_system_function(function):
    if function.getName() in system_functions:
	return None
    calling_info = get_calling_info(function)
    return calling_info if not None else None

# methods for help

def start():
    currentProgram = getCurrentProgram()
    functions = currentProgram.getFunctionManager().getFunctions(True)
    desktopDir = os.path.join(os.path.expanduser("~"), "Desktop")
    outputPath = os.path.join(desktopDir, "{}_functions.csv".format(currentProgram.getName().replace(".o", "")))

    results = {
        "unsafe functions": [],
        "IO functions": [],
        "network functions": [],
        "system functions": [],
        "unused functions": [],
        "operator functions": [],
        "thunk functions": [],
        "compiler-created functions": [],
    }

    show_results_gui(results)

    for function in functions:
        function_name = function.getName()
        function_address = function.getEntryPoint()

        # conditional that checks if a function type is in selected, if so, call the corresponding function
        if "unsafe functions" in selected_functions:
            calling_info_unsafe = contains_unsafe_function(function)
        else:
            calling_info_unsafe = None

        if "unused functions" in selected_functions:
            is_unused = is_unused_function(function)
        else:
            is_unused = None

        if "operator functions" in selected_functions:
            is_op = is_operation(function)
        else:
            is_op = None

        if "IO functions" in selected_functions:
            calling_info_IO = contains_IO_function(function)
        else:
            calling_info_IO = None

        if "network functions" in selected_functions:
            calling_info_network = contains_network_function(function)
        else:
            calling_info_network = None

        if "system functions" in selected_functions:
            calling_info_system = contains_system_function(function)
        else:
            calling_info_system = None

        if "thunk functions" in selected_functions:
            is_th = is_thunk(function)
        else:
            is_th = None

        if "compiler-created functions" in selected_functions:
            is_compiler = is_compiler_created(function)
        else:
            is_compiler = None

        # check if any of the calling info is not None, and highlight the row accordingly
        if calling_info_unsafe and "unsafe functions" in selected_functions:
            results["unsafe functions"].append(calling_info_unsafe)
            highlight_row(function, Color(255, 0, 0))
        if is_unused and "unused functions" in selected_functions:
            results["unused functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(0, 255, 0))
        if is_op and "operator functions" in selected_functions:
            results["operator functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(0, 0, 125))
        if calling_info_IO and "IO functions" in selected_functions:
            results["IO functions"].append(calling_info_IO)
            highlight_row(function, Color(255, 255, 0))
        if calling_info_network and "network functions" in selected_functions:
            results["network functions"].append(calling_info_network)
            highlight_row(function, Color(255, 0, 255))
        if calling_info_system and "system functions" in selected_functions:
            results["system functions"].append(calling_info_system)
            highlight_row(function, Color(0, 255, 255))
        if is_th and "thunk functions" in selected_functions:
            results["thunk functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(255, 165, 0))
        if is_compiler and "compiler-created functions" in selected_functions:
            results["compiler-created functions"].append("{}@{}".format(function_name, function_address))
            highlight_row(function, Color(0, 128, 0))
    #
    with open(outputPath, 'wb') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Function Type', 'Function Details'])

        for func_type, func_list in results.items():
            if func_list:
                row_data = [func_type] + func_list
                csvwriter.writerow(row_data)

    print("Export completed. CSV file saved to: {}".format(outputPath))
    print_to_console(selected_functions, results)

start()
