Dynamic Behavior Analysis Using Binary Instrumentation 
=======================================================

**Abstract**: This talk can be considered like the part 2 of my talk at SecurityDay. In the 
previous part, I talked about how it was possible to cover a targeted function in memory 
using the DSE (Dynamic Symbolic Execution) approach. Cover a function (or its states) 
doesn't mean find all vulnerabilities, some vulnerability doesn't crashes the program. 
That's why we must implement specific analysis to find specific bugs. These analysis are 
based on the binary instrumentation and the runtime behavior analysis of the program. In 
this talk, we will see how it's possible to find these following kind of bugs : off-by-one, 
stack / heap overflow, use-after-free, format string and {write, read}-what-where.

