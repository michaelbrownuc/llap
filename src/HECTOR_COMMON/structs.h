/*************
DARPA AIMEE - HECTOR source code
Author: Michael D. Brown
Copyright Georgia Tech Research Institute, 2020
*************/

#include <string>
#include <sstream>

#include "llvm/IR/Instruction.h"
#include "llvm/IR/Type.h"


// enumeration definitions
enum Operation { // Refer to llvm's Instruction.def. Multiple separate enums in LLVM with complementary ranges, combined here for simplicity.
    // Termination operations
    Return = 1, Branch = 2, Switch = 3, IndirectBranch = 4, Invoke = 5, Resume = 6, Unreachable = 7, CleanupReturn = 8, 
    CatchReturn = 9, CatchSwitch = 10, CallBranch = 11,
    // Unary operations
    Negation = 12,
    // Binary operations
    Add = 13, FloatAdd = 14, Subtract = 15, FloatSubtract = 16, Multiply = 17, FloatMultiply = 18, UnsignedDivide = 19, 
    SignedDivide = 20, FloatDivide = 21, UnsignedModulus = 22, SignedModulus = 23, FloatModulus = 24, ShiftLeft = 25,
    LogicalShiftRight = 26, ArithmeticShiftRight = 27, And = 28, Or = 29, Xor = 30, 
    // Memory operations
    Allocate = 31, Load = 32, Store = 33, GetElementPointer = 34, Fence = 35, AtomicCompareExchange = 36, AtomicReadModifyWrite = 37,
    // Cast operations
    IntTruncate = 38, ZeroExtend = 39, SignExtend = 40, FloatToUInt = 41, FloatToSInt = 42, UIntToFloat = 43, SIntToFloat = 44,
    FloatTruncate = 45, FloatExtend = 46, PointerToInt = 47, IntToPointer = 48, BitCast = 49, AddressSpaceCast = 50,
    // Pad operations
    CleanupPad = 51, CatchPad = 52,
    // Other operations
    IntCompare = 53, FloatCompare = 54, PhiNode = 55, Call = 56, Select = 57, User1 = 58, User2 = 59, VarArgument = 60,
    ExtractElement = 61, InsertElement = 62, ShuffleVector = 63, ExtractValue = 64, InsertValue = 65, LandingPad = 66, Freeze =  67
}; 

enum LinkType  { ControlFlow, ControlDependence, DefUse };

// struct definitions for the output objects llap provides to the machine learning component.
struct Graph {
    std::string file;
};

struct Node {
    uint id;                        // Unique ID
    llvm::Instruction* instruction; // Corresponding LLVM instruciton 
    std::string static_value;       // Numerical static value if present in instruction, "None" otherwise.
    Operation operation;            // Type of operation performed, obtained via llvm::Instruction::getOpcode.
    std::string function;           // Name of the target function for function call operations. Empty string indicates no target function.
    llvm::Type::TypeID dtype;       // Here we directly use the LLVM TypeID enum
    bool condition;                 // Indicates whether the node is a conditional branch statement.
    std::string tags;               // Tag(s) applied to a node.
    std::string labels;             // Labels associated with line from JSON input.
    int line_number;                // Line in source code. Value of 0 indicates no source line number found in debug information from Clang.
    std::string filename;           // Source code filename. Empty string indicates no source file found in debug information from Clang. 
    std::string containing_function;// Parent function name
};

struct Link {
    uint source;              // Unique ID of source node
    uint target;              // Unique ID of the target node
    LinkType type;            // Kind of edge in the graph
    llvm::Type::TypeID dtype; // Type of data (for DefUse links). VoidTyID for links that are not DefUse.
};

// Struct JSON String Functions:
std::string boolToJSON(bool b){
    if(b)
        return "true";
    else
        return "false";
}

std::string dtypeToJSON(llvm::Type::TypeID dt){
    switch (dt){
        case llvm::Type::VoidTyID: return "\"dtype\": \"void\"";
        case llvm::Type::HalfTyID:  return "\"dtype\": \"16bit_float\"";
        case llvm::Type::FloatTyID: return "\"dtype\": \"32bit_float\"";
        case llvm::Type::DoubleTyID: return "\"dtype\": \"64bit_float\"";
        case llvm::Type::X86_FP80TyID: return "\"dtype\": \"80bit_x87_float\"";
        case llvm::Type::FP128TyID: return "\"dtype\": \"128bit_float\"";
        case llvm::Type::PPC_FP128TyID: return "\"dtype\": \"128bit_PPC_float\"";
        case llvm::Type::LabelTyID: return "\"dtype\": \"labels\"";
        case llvm::Type::MetadataTyID: return "\"dtype\": \"metadata\"";
        case llvm::Type::X86_MMXTyID: return "\"dtype\": \"64_bit_x86_mmx_vectors\"";
        case llvm::Type::TokenTyID: return "\"dtype\": \"tokens\"";
        case llvm::Type::IntegerTyID: return "\"dtype\": \"integers\"";
        case llvm::Type::FunctionTyID: return "\"dtype\": \"functions\"";
        case llvm::Type::StructTyID: return "\"dtype\": \"structs\"";
        case llvm::Type::ArrayTyID: return "\"dtype\": \"arrays\"";
        case llvm::Type::PointerTyID : return "\"dtype\": \"pointers\"";
        case llvm::Type::VectorTyID : return "\"dtype\": \"vectors\"";
    }
    return "\"dtype\": \"void\"";
}

std::string graphToJSON(Graph g){
    std::string json = "\"graph\": { \"file\": \"";
    json += g.file;
    json += "\" }";
    return json;
}

std::string nodeToJSON(Node n){    
    std::string json = "{ \"id\": ";
    json += std::to_string(n.id);
    if(n.static_value == "none") 
        json += ", \"static_value\": \"none\", ";
    else
        json += ", \"static_value\": " + n.static_value + ", ";
    json += "\"operation\": \"";

    switch(n.operation){
        case Return: json += "return\", "; break;
        case Branch: json += "branch\", "; break;
        case Switch: json += "switch\", "; break;
        case IndirectBranch: json += "indirect_branch\", "; break;
        case Invoke: json += "invoke\", "; break;
        case Resume: json += "resume\", "; break;
        case Unreachable: json += "unreachable\", "; break;
        case CleanupReturn: json += "cleanup_return\", "; break;
        case CatchReturn: json += "catch_return\", "; break;
        case CatchSwitch: json += "catch_switch\", "; break;
        case CallBranch: json += "call_branch\", "; break;
        case Negation: json += "negate\", "; break;
        case Add: json += "add\", "; break;
        case FloatAdd: json += "float_add\", "; break;
        case Subtract: json += "subtract\", "; break;
        case FloatSubtract: json += "float_subtract\", "; break;
        case Multiply: json += "multiply\", "; break;
        case FloatMultiply: json += "float_multiply\", "; break;
        case UnsignedDivide: json += "unsigned_divide\", "; break;
        case SignedDivide: json += "signed_divide\", "; break;
        case FloatDivide: json += "float_divide\", "; break;
        case UnsignedModulus: json += "unsigned_modulus\", "; break;
        case SignedModulus: json += "signed_modulus\", "; break;
        case FloatModulus: json += "float_modulus\", "; break;
        case ShiftLeft: json += "shift_left\", "; break;
        case LogicalShiftRight: json += "logical_shift_right\", "; break;
        case ArithmeticShiftRight: json += "arithmetic_shift_right\", "; break;
        case And: json += "and\", "; break;
        case Or: json += "or\", "; break;
        case Xor: json += "xor\", "; break;
        case Allocate: json += "allocate\", "; break;
        case Load: json += "load\", "; break;
        case Store: json += "store\", "; break;
        case GetElementPointer: json += "get_element_pointer\", "; break;
        case Fence: json += "fence\", "; break;
        case AtomicCompareExchange: json += "atomic_compare_exchange\", "; break;
        case AtomicReadModifyWrite: json += "atomic_read_write_modify\", "; break;
        case IntTruncate: json += "int_truncate\", "; break;
        case ZeroExtend: json += "zero_extend\", "; break;
        case SignExtend: json += "sign_extend\", "; break;
        case FloatToUInt: json += "float_to_uint\", "; break;
        case FloatToSInt: json += "float_to_sint\", "; break;
        case UIntToFloat: json += "uint_to_float\", "; break;
        case SIntToFloat: json += "sint_to_float\", "; break;
        case FloatTruncate: json += "float_truncate\", "; break;
        case FloatExtend: json += "float_extend\", "; break;
        case PointerToInt: json += "pointer_to_int\", "; break;
        case IntToPointer: json += "int_to_pointer\", "; break;
        case BitCast: json += "bit_cast\", "; break;
        case AddressSpaceCast: json += "address_space_cast\", "; break;
        case CleanupPad: json += "cleanup_pad\", "; break;
        case CatchPad: json += "catch_pad\", "; break;
        case IntCompare: json += "int_compare\", "; break;
        case FloatCompare: json += "float_compare\", "; break;
        case PhiNode: json += "phi_node\", "; break;
        case Call: json += "call\", "; break;
        case Select: json += "select\", "; break;
        case User1: json += "user_1\", "; break;
        case User2: json += "user_2\", "; break;
        case VarArgument: json += "var_argument\", "; break;
        case ExtractElement: json += "extract_element\", "; break;
        case InsertElement: json += "insert_element\", "; break;
        case ShuffleVector: json += "shuffle_vector\", "; break;
        case ExtractValue: json += "extract_value\", "; break;
        case InsertValue: json += "insert_value\", "; break;
        case LandingPad: json += "landing_pad\", "; break;
        case Freeze: json += "freeze\", "; break;
    }

    // Empty string indicates no target function
    if(n.function != "")
        json += "\"function\": \"" + n.function + "\", ";
    else
        json += "\"function\": null, ";
    
    json += dtypeToJSON(n.dtype);
    json += ", \"condition\": " + boolToJSON(n.condition) + ", ";
    json += "\"tag\": [" + n.tags + "]";
    json += ", \"line_number\": ";
    json += std::to_string(n.line_number);
    json += ", \"filename\": \"" + n.filename + "\"";
    json += ", \"containing_function\": \"" + n.containing_function + "\", ";
    json += "\"label\": [" + n.labels + "]}";
    return json;
}

std::string linkToJSON(Link l){
    std::string json = "{ \"source\": ";
    json += std::to_string(l.source);
    json += ", \"target\": ";
    json += std::to_string(l.target);
    json += ", \"type\": \"";

    switch(l.type){
        case ControlFlow: json += "control_flow\", "; break;
        case ControlDependence: json += "control_dependence\", "; break;
        case DefUse: json += "def_use\", "; break;
    }

    json += dtypeToJSON(l.dtype);

    json += "}";
    return json;
}