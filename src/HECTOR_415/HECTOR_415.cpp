/*************
DARPA AIMEE - HECTOR source code CWE-415 pipeline
Author: Michael D. Brown
Copyright Georgia Tech Research Institute, 2020
*************/

#include <string>
#include <fstream>
#include <utility>
#include <map>

#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"

#include "../HECTOR_COMMON/rapidjson/document.h"
#include "../HECTOR_COMMON/rapidjson/stringbuffer.h"
#include "../HECTOR_COMMON/rapidjson/istreamwrapper.h"

#include "../HECTOR_COMMON/structs.h"
#include "../HECTOR_COMMON/utils.h"

using namespace llvm;

#define DEBUG_TYPE "HECTOR_415"

static cl::opt<std::string> labelFilename("labelFilename", cl::desc("Optionally specify input filename for labels."), cl::value_desc("filename"), cl::init(""));
static cl::opt<std::string> outputFilename("outputFilename", cl::desc("Optionally specify output filename for JSON output."), cl::value_desc("outputFilename"), cl::init(""));

namespace {
  using Label = std::pair<std::string, std::string>;
  using NodeMapping = std::pair<Instruction*, Node*>;

  struct HECTOR_415 : public ModulePass {
    static char ID;
    HECTOR_415() : ModulePass(ID) {}

	void getAnalysisUsage(AnalysisUsage &AU) const override {
		AU.addRequired<TargetLibraryInfoWrapperPass>();
	}

    bool runOnModule(Module &M) override {
    	errs() << "HECTOR (CWE-415) is starting.\n";
	
		// First step: Check to see if we have labels.
		std::vector<std::pair<std::string, std::string>> labels;
		
		if(labelFilename != ""){
			errs() << "Reading labels from: " << labelFilename << "\n";

			// Use rapidjson to read the file into a data structure.
			std::ifstream ifs(labelFilename);
			if ( !ifs.is_open() )
			{
				errs() << "ERROR: Could not open file for reading!\n";
				return false;
			}

			rapidjson::IStreamWrapper isw (ifs);
			rapidjson::Document doc;
			doc.ParseStream(isw);
			assert(doc.IsArray());

			// Maps extracted filename/line number to the rapidJSON value object.
			for (rapidjson::SizeType i = 0; i < doc.Size(); i++){			
				assert(doc[i].IsObject());
				assert(doc[i]["filename"].IsString());
				assert(doc[i]["line_number"].IsInt());
				assert(doc[i]["label"].IsString());
				
				std::string sourceline = doc[i]["filename"].GetString();
				sourceline += ":";
				sourceline += std::to_string(doc[i]["line_number"].GetInt());

				labels.push_back(Label(sourceline, doc[i]["label"].GetString()));
			}
		}
		else { errs() << "No labels specified.\n"; }
		
		// Create Graph output structure
		Graph graph;
		
		// Name the graph with the source filename (rstrip off the relative path)
		std::string src_path = M.getSourceFileName();
		graph.file = src_path.substr(src_path.find_last_of("/") + 1 );

		// Initialize Collections of Nodes, Links, and map between instructions and nodes.
		SetVector<Node*> nodes;
		SetVector<Link*> links;
		DenseMap<Instruction*, Node*> node_mappings;  

		// For Node ID generation
		uint next_node_id = 0;
		
		errs() << "Analyzing Module " << M.getSourceFileName() << "\n";

		// Second step: Iterate through the functions and instructions in the module, build up nodes.
		for (Module::iterator F = M.begin(), E = M.end(); F != E; ++F){
			Function* func = &(*F);	
			
			// Check for function headers
			if(func->size() <= 0) {
				errs() << "  " << func->getName() << " is a function declaration, ignoring.\n";
				continue;
			}
			
			TargetLibraryInfo *TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(*F);

			errs() << "  Analyzing function: " << func->getName() << "\n";
			for (Function::iterator BB = func->begin(), BBE = func->end(); BB != BBE; ++BB){
				BasicBlock* block = (&(*BB));
				for(BasicBlock::iterator I = block->begin(), IE = block->end(); I != IE; ++I){
					Instruction* instr = (&(*I));

					// Create a node for this instruction, and create mapping to node for control flow link creation.
					Node* node = new Node;
					node->instruction = instr;
					node_mappings.insert(NodeMapping(instr, node));

					// Assign a unique ID number and start populating its features
					node->id = next_node_id++;
					node->containing_function = func->getName().str();
					node->operation = (Operation) instr->getOpcode();
					node->dtype = instr->getType()->getTypeID();
					
					// Get source filename and line number with debug info
					DILocation* loc = instr->getDebugLoc();
					if(loc){
						node->line_number = loc->getLine();
						node->filename = loc->getDirectory().str() + "/" + loc->getFilename().str();
					}
					else{
						node->line_number = 0;  // Indicates that no debug info was found.
						node->filename = "";
					}

					// Iterate through operands of this instruction and add first numeric constant found to static value feature
					node->static_value = "none";
					for(User::op_iterator O = instr->op_begin(); O != instr->op_end(); ++O){
						if(ConstantInt* ci = dyn_cast<ConstantInt>(&(*O))) { 
							node->static_value = std::to_string(ci->getSExtValue());
							break;
						}
					}

					// Check instruction types to identify conditional branch statements (Compare/Branch) and apply tags.					
					node->condition = false;
					node->tags = "";					
					// All compare instructions are part of conditional branches.
					if(dyn_cast<CmpInst>(instr)) { node->condition = true; }
					
					// Branch instructions might be, have to check their flag.
					else if(BranchInst* bi = dyn_cast<BranchInst>(instr)){
						if(bi->isConditional()) { node->condition = true; }
					}					
					
					// Call instructions have features to extract, and may also require tagging as root cause or manifestation points
					else if(CallBase* cbi = dyn_cast<CallBase>(instr)){
						// Record the function call target
						if(cbi->isInlineAsm()) { node->function = "inline_assembly"; }
						else if (Function* called_func = cbi->getCalledFunction()) { 
							// To reduce node dimensionality we only record target function names for external calls.
							if(called_func->size() <= 0){
								 node->function = called_func->getName().str();
							}
							else { node->function = ""; }
						}
						else { node->function = "indirect call"; }

						// Only tag the call if it is a call to a builtin free function.
						/// NOTE: For now we assume any free call can be both a root cause and manifestation point.
						///       The possibility exists to refine this at some point
						if(isFreeCall(instr, TLI) != nullptr){ 
							node->tags = "\"root_cause\", \"manifestation\""; 

							// Check to see if this free call was inlined, if so use the inlined line number (some projects use wrappers for free())
							// We only do this for processing data for evaluation. When generating, training data, labeling will be messed up of we do this.
							if(labels.size() == 0 && loc && loc->getInlinedAt() != nullptr){
								loc = loc->getInlinedAt();
								node->line_number = loc->getLine();
								node->filename = loc->getDirectory().str() + "/" + loc->getFilename().str();
							}
						}
					}

					node->labels = "";
					
					// Check imported labels for supplementary information, only label tagged instructions that have debug data associated with them
					if(labels.size() != 0 && node->filename != "" && node->tags != ""){		
						std::string sourceline = node->filename + ":" + std::to_string(node->line_number);
						for(Label lbl : labels){
							if(endsWith(sourceline, lbl.first) ){
								if(node->labels == "")
									node->labels = "\"" + lbl.second + "\"";
								else
									node->labels += ", \"" + lbl.second + "\"";
							}
						}
					}

					// Add node to node list
					nodes.insert(node);
				}	
			}	
		}

		// Third step: Iterate through each node and build links based off of program graphs (CFG, DDG, PDG, DT, etc).
		for(Node* node : nodes){
			// Control Flow Links: Create a link from each node to its successor nodes.
			for(Instruction* succ : getSuccs(node->instruction)){
				Link* link = new Link;
				link->source = node->id;
				link->target = node_mappings[succ]->id;
				link->type = ControlFlow;
				link->dtype = Type::VoidTyID;
				links.insert(link);
			}

			// Def-Use Links: Create a link from each node to the nodes that use its value.
			// NOTE: Becasue LLVM is in SSA form, each instruction is a new value. They aren't aliased to source code variables. This is the most basic 
			//       form of Def-Use analysis. If we need def-use chains at the source code variable level, we will need to scan the code and do this.
			
			/* NOTE: We may not need Def-Use Links at all for Double-Free vulnerabilities. For now, don't generate Def-use Information
			for(User* user : node->instruction->users()){
				if(Instruction* i_user = dyn_cast<Instruction>(user)){
					Link* link = new Link;
					link->source = node->id;
					link->target = node_mappings[i_user]->id;
					link->type = DefUse;
					link->dtype = node->dtype;
					links.insert(link);
				}
			}*/
		}
	
		// Debug Prints, kept here in comments as we will need to make several changes to the print functions.
		// These are useful for rapid debugging of output.
		/*
		errs() << "JSON Output: \n" << graphToJSON(graph) << "\n";

		for(Node* n : nodes){
			errs() << "Node: \n" << nodeToJSON(*n) << "\n";
		}

		for(Link* l : links){
			errs() << "Link: \n" << linktoJSON(*l) << "\n";
		}
		*/
		
		// Final step: Create and output JSON
		std::ofstream outfile;
		std::string filename;
		if(outputFilename == ""){ filename = graph.file + ".json"; }
		else { filename =  outputFilename; }
    	
		outfile.open(filename);
		
		bool first = true;
		outfile << "{ " << graphToJSON(graph) << ", \"nodes\": [";
		for(Node* n : nodes){
			if(first){
				outfile << nodeToJSON(*n);
				first = false;
			}
			else
				outfile << ", " << nodeToJSON(*n);
		}

		first = true;
		outfile << "], \"links\": [";
		for(Link* l : links){
			if(first){
				outfile << linkToJSON(*l);
				first = false;
			}
			else
				outfile << ", " << linkToJSON(*l);
		}

		outfile << "] }\n";
		outfile.close();
		errs() << "HECTOR (CWE-415) is finished.\n" ;
		return false;
    }
  };
}

char HECTOR_415::ID = 0;
static RegisterPass<HECTOR_415> X("HECTOR_415", "HECTOR (CWE-415) Label Association and Feature Generation Pass");
