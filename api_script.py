# ghidra script that can link our program to ghidra
# see instructions to use in Resources in our google drive folder, or at https://class.malware.re/2021/03/08/ghidra-scripting.html
# @category csce451

from ghidra.app.decompiler.flatapi import FlatDecompilerAPI
from ghidra.program.flatapi import FlatProgramAPI

program = FlatProgramAPI(getState().getCurrentProgram())
decompiler = FlatDecompilerAPI(program)

# all of the tools we can use in the decompiler using this specific api
for x in dir(decompiler): print(x)

# the decompiled version of the first function is printed to the ghidra console -- just an example of usage
first_decompile = decompiler.decompile(program.firstFunction)
print(first_decompile)