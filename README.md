# llap (low-level analysis processor)
llap is a collection of analysis passes for LLVM that generate enriched program dependency graphs (in JSON format) from program source code for use in Vulchecker ML models. llap is used for both processing source code for querying models and for creating training datasets by optionally supplying label data from an input JSON file. This component is the "narrow waist" for the Vulchecker (previously called HECTOR) system. Currently, the following CWE-specific processing pipelines are supported:

 1. CWE-121 (CWE-122): Stack-based (heap-based) Overflow 
 2. CWE-190 (CWE-191): Integer Overflow (Integer Underflow)
 3. CWE-415: Double-Free
 4. CWE-416: Use-After-Free

While this tool was originally developed as part of Vulchecker, it can be readily adapted to create new pipelines for other types of AI/ML modeling. For example, the pipelines above were adapted to a mathematics recovery and lifting project called CORBIN. The provided pipelines are intended to provide examples for other users to extend. Ultimately the big difference between applications is altering the code provided to apply labels for your specific use case. For Vulchecker, labels are provided for vulnerability root cause and manifestation points, which is specific to this use case.

Author: Michael D. Brown

## Installation
llap analysis passes are designed to be run as LLVM middle-end optimizer passes using `opt`. Pipeline source code is most easily built in conjunction with LLVM's source. Fortunately LLVM is deisgned to make this rather painless. To further simplify this process, an Ubuntu VM that can be used to build develop and run llap is available.

### Instructions:

 1. Import the VM into your hypervisor of choice and run it.
 2. Login with the credentials provided with VM.
 3. Switch to the `~/$user/llap/` directory (this repo).
 4. Execute `git pull` to fetch the latest version of this code.
 5. Switch to the `src` directory.
 6. Copy the contents (`HECTOR_XXX` directories and CMakeLists.txt) to the `~/llvm-project/llvm/lib/Transforms/` directory.
 7. Switch to the `~/llvm-build/llvm` directory
 8. execute `cmake ~/llvm-project/llvm/`
 9. execute `sudo make install`
 
 ## Running llap
llap is run as a run-time loaded optimization module. It takes as input a program source code file in llvm IR (.ll, memory-representation) and optionally a set of labels in JSON format. To use clang to create the input files from C/C++ code, use the following command:
 
 `clang -O0 -g -S -isystem [include directory]  -emit-llvm [source_file(s)]`
 
If the program in question consists of multiple source files, then the following command can be used to link the multiple resulting .ll files into a single file processable by llap.

 `llvm-link -S *.ll -o [merged_filename].ll`

In order to remove as many procedural boundaries as possible (across which it is difficult for the ML model to learn about control- and data-flow dependencies in vulnerable code) the program's LLVM IR file (or merged IR file if there were multiple sources code files) needs to be optimized. To do so, we must first preprocess the file to allow function inlining (which gets turned off when using -O0): 

`sed -i 's/noinline//g' [merged_filename].ll`

`sed -i 's/optnone//g' [merged_filename].ll`

Then, we must run some built in LLVM optimization passes to eliminate indirect jumps, inline functions aggressively, and eliminate functions after they have been inlined:

 `opt --indirectbr-expand --inline-threshold=10000 --inline -S -o [merged_filename].ll [merged_filename].ll`
 
 `opt --internalize-public-api-list="main" --internalize --globaldce -S -o [merged_filename].ll [merged_filename].ll`

Finally, to run llap, use the following command (optionally setting the `outputFilename` parameter):

 `opt -load ~/llvm-build/llvm/lib/LLVM_HECTOR_[CWE_number].so -HECTOR_[CWE_number] < [.ll file] -labelFilename=[label_filename].json -outputFilename=[output_filename].json > /dev/null`
 
Note that all labels must be in a single file for llap to consume, regardless of the number of source files.
 
  ## Test Cases
An automated test cases puller/runner is available in the `tst` directory. It automatically pulls selected test cases from the HECTOR/labeled-dataset repository and runs the appropriate pipeline. Test files are placed in the `tst/cases` directory, where output can be validated.

To run the test case script, first empty the contents of the `tst/cases` directory (except for the placeholder text file). Then execute:

`python runcases.py`

  
