/*************
DARPA AIMEE - HECTOR source code
Author: Michael D. Brown
Copyright Georgia Tech Research Institute, 2020
*************/

#include <string>
#include <sstream>

#include "llvm/IR/Instruction.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/ADT/SetVector.h"

using namespace llvm;

bool endsWith(const std::string &haystack, const std::string &needle) {
	if (haystack.length() < needle.length()) {
		return false;
	}
	return std::equal(needle.rbegin(), needle.rend(), haystack.rbegin());
}

// Helper function to get predecessors at the instruction level
std::vector<Instruction*> getPreds(Instruction* I){
	std::vector<Instruction*> preds;
	BasicBlock* BB = I->getParent();
	for(BasicBlock::reverse_iterator i = BB->rbegin(), e = BB->rend(); i != e; ++i){
		if (&(*i) == I){
			++i;
			if(i == e){
				for(pred_iterator pre = pred_begin(BB), BE = pred_end(BB); pre != BE;  ++pre)
					preds.push_back(&(*((*pre)->rbegin())));
			}
			else{ preds.push_back(&(*i)); }
			break;
		}
	}
	return preds;
}

// Helper function to get successors at the instruction level
std::vector<Instruction*> getSuccs(Instruction* I){
	std::vector<Instruction*> succs;
	BasicBlock* BB = I->getParent();
	for(BasicBlock::iterator i = BB->begin(), e = BB->end(); i != e; ++i){
		if (&(*i) == I){
			++i;
			if(i == e){
				for(succ_iterator succ = succ_begin(BB), BS = succ_end(BB); succ != BS;  ++succ)
					succs.push_back(&(*((*succ)->begin())));
			}
			else{ succs.push_back(&(*i)); }
			break;
		}
	}
	return succs;
}

// Helper function to see if a SetVector contains an element
bool setVectorContains(SetVector<Value*>* sv, Value* v){
	for(Value* item : *sv)
		if(item == v) return true;
	return false;
}
