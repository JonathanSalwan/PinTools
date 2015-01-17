Dynamic Binary Analysis and Instrumentation Covering a function using a DSE approach
====================================================================================

**Abstract**: This talk is about binary analysis and instrumentation. We will see how it's 
possible to target a specific function, snapshot the context memory/registers before the 
function, translate the instrumentation into an intermediate representation,apply a taint 
analysis based on this IR, build/keep formulas for a Dynamic Symbolic Execution (DSE), 
generate a concrete value to go through a specific path, restore the context memory/register 
and generate another concrete value to go through another path then repeat this operation 
until the target function is covered. 


