###############################################################################
# DARPA AIMEE - llap Test Case Puller / Runner
# Author: Michael D. Brown
# Copyright Georgia Tech Research Institute, 2020
###############################################################################

# Standard library imports
import os
import sys
import subprocess
import glob
import time


# Test Case List
cases = [   "CWE190_Integer_Overflow__char_fscanf_add_17_omitbad",          #1
            "CWE190_Integer_Overflow__char_fscanf_multiply_45_omitgood",    #2
            "CWE190_Integer_Overflow__char_max_add_21_omitgood",            #3
            "CWE190_Integer_Overflow__char_rand_square_08_omitgood",        #4
            "CWE190_Integer_Overflow__int_max_postinc_41_omitgood",         #5
            "CWE190_Integer_Overflow__int_rand_preinc_09_omitgood",         #6
            "CWE190_Integer_Overflow__char_rand_preinc_63_omitgood",        #7
            "CWE415_Double_Free__malloc_free_char_01_omitbad",              #8
            "CWE415_Double_Free__malloc_free_char_01_omitgood",             #9
            "CWE415_Double_Free__malloc_free_struct_42_omitgood",           #10
            "CWE415_Double_Free__new_delete_array_class_17_omitgood",       #11
            "CWE415_Double_Free__new_delete_class_31_omitgood",             #12
            "CWE415_Double_Free__new_delete_int_33_omitgood",               #13
            "CWE415_Double_Free__new_delete_long_53_omitgood",              #14
            "CWE416_Use_After_Free__malloc_free_char_01_omitbad",           #15
            "CWE416_Use_After_Free__malloc_free_char_01_omitgood",          #16
            "CWE416_Use_After_Free__malloc_free_wchar_t_07_omitgood",       #17
            "CWE416_Use_After_Free__new_delete_array_long_15_omitgood",     #18
            "CWE416_Use_After_Free__return_freed_ptr_01_omitgood",          #19
            "CWE416_Use_After_Free__new_delete_int64_t_63_omitgood",        #20
	    "CWE190_Integer_Overflow__char_fscanf_add_51_omitgood",         #21
	    "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_omitbad",     #22
            "CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_omitgood",    #23
            "CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_06_omitgood",       #24
            "CWE121_Stack_Based_Buffer_Overflow__CWE135_01_omitgood",                      #25
            "CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_14_omitgood",        #26
            "CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cpy_33_omitgood",       #27
            "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_connect_socket_01_omitbad",       #28
            "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_connect_socket_01_omitgood",      #29
            "CWE122_Heap_Based_Buffer_Overflow__c_CWE129_rand_06_omitgood",                #30
            "CWE122_Heap_Based_Buffer_Overflow__c_CWE193_char_loop_43_omitgood",           #31
            "CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memmove_17_omitgood", #32
            "CWE122_Heap_Based_Buffer_Overflow__c_CWE806_char_ncpy_43_omitgood",           #33
]

dataset_dir = "/home/hector/labeled-dataset/"
count = 0

# Iterate through test case list to pull the necessary files
for case in cases:    
    count += 1

    cwe_type = case[:case.find("_")]
    cwe_number = cwe_type[cwe_type.rfind("E")+1:]

    # Correct CWE number if needed
    if cwe_number == "122":
        cwe_number = "121"

    tc = "tc" + str(count)
    
    # Try to create an testcase directory
    try:
        testcase_dir = "cases/testcase_" + str(count)
        os.makedirs(testcase_dir)
    except OSError as oserr:
        sys.exit("An OS Error occurred during creation of results directory: " + oserr.strerror)

    # Copy / rename .ll file
    command = "cp " + dataset_dir + cwe_type + "/ll_files/optimized/" + case + ".ll " + testcase_dir + "/" + tc + ".ll"
    sub = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    subprocess_return = sub.stdout.read()
    print(subprocess_return.decode("utf-8"))
        

    # Copy / rename label file
    command = "cp " + dataset_dir + cwe_type + "/source_labels/combined/" + case + ".json " + testcase_dir + "/" + tc + "_labels.json"
    sub = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    subprocess_return = sub.stdout.read()
    print(subprocess_return.decode("utf-8"))

    # Copy / rename source file
    command = "cp " + dataset_dir + cwe_type + "/source_files/" + case + ".* " + testcase_dir + "/" + tc + "_source.cpp"
    sub = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    subprocess_return = sub.stdout.read()
    print(subprocess_return.decode("utf-8"))        

    # Run the test    
    command = "opt -load ~/llvm-build/llvm/lib/LLVM_HECTOR_" + cwe_number + ".so -HECTOR_" + cwe_number + " < " + testcase_dir + "/" + tc + ".ll" +  " -labelFilename=" + testcase_dir + "/" + tc + "_labels.json" + " -outputFilename=" + testcase_dir + "/" + tc + "_output.json" + " > /dev/null"
    sub = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    subprocess_return = sub.stdout.read()
    print(subprocess_return.decode("utf-8"))

