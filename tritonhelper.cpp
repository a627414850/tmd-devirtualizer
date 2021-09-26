#include "pch.h"

#include "tritonhelper.hpp"

triton::engines::symbolic::SharedSymbolicVariable get_symbolic_var(const triton::ast::SharedAbstractNode &node)
{
	return node->getType() == triton::ast::VARIABLE_NODE ?
		std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable() : nullptr;
}

std::set<triton::ast::SharedAbstractNode> collect_variable_nodes(const triton::ast::SharedAbstractNode& node)
{
	std::set<triton::ast::SharedAbstractNode> result;
	if (!node)
		return result;

	std::stack<triton::ast::AbstractNode*>                worklist;
	std::unordered_set<const triton::ast::AbstractNode*>  visited;

	worklist.push(node.get());
	while (!worklist.empty()) {
		auto current = worklist.top();
		worklist.pop();

		// This means that node is already in work_stack and we will not need to convert it second time
		if (visited.find(current) != visited.end()) {
			continue;
		}

		visited.insert(current);
		if (current->getType() == triton::ast::VARIABLE_NODE)
			result.insert(current->shared_from_this());

		if (current->getType() == triton::ast::REFERENCE_NODE) {
			worklist.push(reinterpret_cast<triton::ast::ReferenceNode*>(current)->getSymbolicExpression()->getAst().get());
		}
		else {
			for (const auto& child : current->getChildren()) {
				worklist.push(child.get());
			}
		}
	}
	return result;
}


bool is_unary_operation(const triton::arch::Instruction &triton_instruction)
{
	switch (triton_instruction.getType())
	{
		case triton::arch::x86::ID_INS_INC:
		case triton::arch::x86::ID_INS_DEC:
		case triton::arch::x86::ID_INS_NEG:
		case triton::arch::x86::ID_INS_NOT:
			return true;

		default:
			return false;
	}
}
bool is_binary_operation(const triton::arch::Instruction &triton_instruction)
{
	switch (triton_instruction.getType())
	{
		case triton::arch::x86::ID_INS_ADD:
		case triton::arch::x86::ID_INS_SUB:
		case triton::arch::x86::ID_INS_SHL:
		case triton::arch::x86::ID_INS_SHR:
		case triton::arch::x86::ID_INS_RCR:
		case triton::arch::x86::ID_INS_RCL:
		case triton::arch::x86::ID_INS_ROL:
		case triton::arch::x86::ID_INS_ROR:
		case triton::arch::x86::ID_INS_AND:
		case triton::arch::x86::ID_INS_OR:
		case triton::arch::x86::ID_INS_XOR:
		case triton::arch::x86::ID_INS_CMP:
		case triton::arch::x86::ID_INS_TEST:
			return true;

		case triton::arch::x86::ID_INS_IMUL:
		{
			// imul can have 3 operands but eh
			return triton_instruction.operands.size() == 2;
		}

		default:
			return false;
	}
}
bool is_mov_operation(const triton::arch::Instruction& triton_instruction)
{
	switch (triton_instruction.getType())
	{
		case triton::arch::x86::ID_INS_MOV:
		case triton::arch::x86::ID_INS_MOVSX:
		case triton::arch::x86::ID_INS_MOVZX:
			return true;

		default:
			return false;
	}
}