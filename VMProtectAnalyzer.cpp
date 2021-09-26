#include "pch.h"

#include "VMProtectAnalyzer.hpp"
#include "x86_instruction.hpp"
#include "AbstractStream.hpp"
#include "CFG.hpp"
#include "tritonhelper.hpp"

// helper?
void print_basic_blocks(const std::shared_ptr<BasicBlock> &first_basic_block)
{
	std::set<unsigned long long> visit_for_print;
	std::shared_ptr<BasicBlock> basic_block = first_basic_block;
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const auto& instruction = *it;
		if (++it != basic_block->instructions.end())
		{
			// loop until it reaches end
			instruction->print();
			continue;
		}

		// dont print unconditional jmp, they are annoying
		if (instruction->get_category() != XED_CATEGORY_UNCOND_BR
			|| instruction->get_branch_displacement_width() == 0)
		{
			instruction->print();
		}

		visit_for_print.insert(basic_block->leader);
		if (basic_block->next_basic_block && visit_for_print.count(basic_block->next_basic_block->leader) <= 0)
		{
			// print next
			basic_block = basic_block->next_basic_block;
		}
		else if (basic_block->target_basic_block && visit_for_print.count(basic_block->target_basic_block->leader) <= 0)
		{
			// it ends with jmp?
			basic_block = basic_block->target_basic_block;
		}
		else
		{
			// perhaps finishes?
			break;
		}

		it = basic_block->instructions.begin();
	}
}

// VMProtectAnalyzer
VMProtectAnalyzer::VMProtectAnalyzer(triton::arch::architecture_e arch)
{
	triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(arch);
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);
	//triton_api->setAstRepresentationMode(triton::ast::representations::PYTHON_REPRESENTATION);
	this->m_scratch_size = 0;
	this->m_temp = 0;
}
VMProtectAnalyzer::~VMProtectAnalyzer()
{
}

bool VMProtectAnalyzer::is_x64() const
{
	const triton::arch::architecture_e architecture = this->triton_api->getArchitecture();
	switch (architecture)
	{
		case triton::arch::ARCH_X86:
			return false;

		case triton::arch::ARCH_X86_64:
			return true;

		default:
			throw std::runtime_error("invalid architecture");
	}
}

triton::uint64 VMProtectAnalyzer::get_bp() const
{
	switch (triton_api->getArchitecture())
	{
		case triton::arch::ARCH_X86:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_ebp).convert_to<triton::uint64>();

		case triton::arch::ARCH_X86_64:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_rbp).convert_to<triton::uint64>();

		default:
			throw std::runtime_error("invalid architecture");
	}
}
triton::uint64 VMProtectAnalyzer::get_sp() const
{
	switch (triton_api->getArchitecture())
	{
		case triton::arch::ARCH_X86:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_esp).convert_to<triton::uint64>();

		case triton::arch::ARCH_X86_64:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_rsp).convert_to<triton::uint64>();

		default:
			throw std::runtime_error("invalid architecture");
	}
}
triton::uint64 VMProtectAnalyzer::get_ip() const
{
	switch (triton_api->getArchitecture())
	{
		case triton::arch::ARCH_X86:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_eip).convert_to<triton::uint64>();

		case triton::arch::ARCH_X86_64:
			return triton_api->getConcreteRegisterValue(triton_api->registers.x86_rip).convert_to<triton::uint64>();

		default:
			throw std::runtime_error("invalid architecture");
	}
}

void VMProtectAnalyzer::symbolize_registers()
{
	// symbolize all registers;
	if (this->is_x64())
	{
		triton::engines::symbolic::SharedSymbolicVariable symvar_eax = triton_api->symbolizeRegister(triton_api->registers.x86_rax);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebx = triton_api->symbolizeRegister(triton_api->registers.x86_rbx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ecx = triton_api->symbolizeRegister(triton_api->registers.x86_rcx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edx = triton_api->symbolizeRegister(triton_api->registers.x86_rdx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esi = triton_api->symbolizeRegister(triton_api->registers.x86_rsi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edi = triton_api->symbolizeRegister(triton_api->registers.x86_rdi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebp = triton_api->symbolizeRegister(triton_api->registers.x86_rbp);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esp = triton_api->symbolizeRegister(triton_api->registers.x86_rsp);


		triton::engines::symbolic::SharedSymbolicVariable symvar_r8 = triton_api->symbolizeRegister(triton_api->registers.x86_r8);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r9 = triton_api->symbolizeRegister(triton_api->registers.x86_r9);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r10 = triton_api->symbolizeRegister(triton_api->registers.x86_r10);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r11 = triton_api->symbolizeRegister(triton_api->registers.x86_r11);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r12 = triton_api->symbolizeRegister(triton_api->registers.x86_r12);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r13 = triton_api->symbolizeRegister(triton_api->registers.x86_r13);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r14 = triton_api->symbolizeRegister(triton_api->registers.x86_r14);
		triton::engines::symbolic::SharedSymbolicVariable symvar_r15 = triton_api->symbolizeRegister(triton_api->registers.x86_r15);

		symvar_eax->setAlias("rax");
		symvar_ebx->setAlias("rbx");
		symvar_ecx->setAlias("rcx");
		symvar_edx->setAlias("rdx");
		symvar_esi->setAlias("rsi");
		symvar_edi->setAlias("rdi");
		symvar_ebp->setAlias("rbp");
		symvar_esp->setAlias("rsp");
		symvar_r8->setAlias("r8");
		symvar_r9->setAlias("r9");
		symvar_r10->setAlias("r10");
		symvar_r11->setAlias("r11");
		symvar_r12->setAlias("r12");
		symvar_r13->setAlias("r13");
		symvar_r14->setAlias("r14");
		symvar_r15->setAlias("r15");
	}
	else
	{
		triton::engines::symbolic::SharedSymbolicVariable symvar_eax = triton_api->symbolizeRegister(triton_api->registers.x86_eax);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebx = triton_api->symbolizeRegister(triton_api->registers.x86_ebx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ecx = triton_api->symbolizeRegister(triton_api->registers.x86_ecx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edx = triton_api->symbolizeRegister(triton_api->registers.x86_edx);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esi = triton_api->symbolizeRegister(triton_api->registers.x86_esi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_edi = triton_api->symbolizeRegister(triton_api->registers.x86_edi);
		triton::engines::symbolic::SharedSymbolicVariable symvar_ebp = triton_api->symbolizeRegister(triton_api->registers.x86_ebp);
		triton::engines::symbolic::SharedSymbolicVariable symvar_esp = triton_api->symbolizeRegister(triton_api->registers.x86_esp);
		symvar_eax->setAlias("eax");
		symvar_ebx->setAlias("ebx");
		symvar_ecx->setAlias("ecx");
		symvar_edx->setAlias("edx");
		symvar_esi->setAlias("esi");
		symvar_edi->setAlias("edi");
		symvar_ebp->setAlias("ebp");
		symvar_esp->setAlias("esp");
	}
}

const triton::arch::Register& VMProtectAnalyzer::get_source_register(const triton::arch::Instruction &triton_instruction) const
{
	if (triton_instruction.getType() == triton::arch::x86::ID_INS_POP)
	{
		// idk...
		return  triton_api->registers.x86_eflags;
	}

	if (triton_instruction.getType() != triton::arch::x86::ID_INS_MOV)
	{
		std::stringstream ss;
		ss << "memory has written by undefined opcode\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}

	// mov MEM,REG
	const std::vector<triton::arch::OperandWrapper> &operands = triton_instruction.operands;
	if (operands.size() != 2
		|| operands[0].getType() != triton::arch::OP_MEM
		|| operands[1].getType() != triton::arch::OP_REG)
	{
		std::stringstream ss;
		ss << "memory has written by unknown instruction\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}
	return operands[1].getConstRegister();
}
const triton::arch::Register& VMProtectAnalyzer::get_dest_register(const triton::arch::Instruction &triton_instruction) const
{
	const triton::uint32 instruction_type = triton_instruction.getType();
	if (instruction_type != triton::arch::x86::ID_INS_MOV
		&& instruction_type != triton::arch::x86::ID_INS_MOVZX)
	{
		std::stringstream ss;
		ss << "memory has read by undefined opcode\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}

	// [mov|movzx] REG,MEM
	const std::vector<triton::arch::OperandWrapper> &operands = triton_instruction.operands;
	if (operands.size() != 2
		|| operands[0].getType() != triton::arch::OP_REG
		|| operands[1].getType() != triton::arch::OP_MEM)
	{
		std::stringstream ss;
		ss << "memory has read by unknown instruction\n"
			<< "\t" << triton_instruction << "\"\n"
			<< "\tFile: " << __FILE__ << ", L: " << __LINE__;
		throw std::runtime_error(ss.str());
	}
	return operands[0].getConstRegister();
}

bool VMProtectAnalyzer::is_bytecode_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	// return true if lea_ast is constructed by bytecode
	const std::set<triton::ast::SharedAbstractNode> symvars = collect_variable_nodes(lea_ast);
	if (symvars.empty())
		return false;

	for (auto it = symvars.begin(); it != symvars.end(); ++it)
	{
		const triton::ast::SharedAbstractNode &node = *it;
		const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
		if (symvar->getId() != context->symvar_bytecode->getId())
			return false;
	}
	return true;
}
bool VMProtectAnalyzer::is_stack_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	// return true if lea_ast is constructed by stack
	const std::set<triton::ast::SharedAbstractNode> symvars = collect_variable_nodes(lea_ast);
	if (symvars.empty())
		return false;

	for (auto it = symvars.begin(); it != symvars.end(); ++it)
	{
		const triton::ast::SharedAbstractNode &node = *it;
		const triton::engines::symbolic::SharedSymbolicVariable &symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(node)->getSymbolicVariable();
		if (symvar != context->symvar_stack)
			return false;
	}
	return true;
}
bool VMProtectAnalyzer::is_scratch_area_address(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	// size is hardcoded for now (can see in any push handler perhaps)
	const triton::uint64 runtime_address = lea_ast->evaluate().convert_to<triton::uint64>();
	return context->x86_sp <= runtime_address && runtime_address < (context->x86_sp + context->scratch_area_size);
}
bool VMProtectAnalyzer::is_fetch_arguments(const triton::ast::SharedAbstractNode &lea_ast, VMPHandlerContext *context)
{
	if (lea_ast->getType() != triton::ast::VARIABLE_NODE)
		return false;

	const triton::engines::symbolic::SharedSymbolicVariable &symvar =
		std::dynamic_pointer_cast<triton::ast::VariableNode>(lea_ast)->getSymbolicVariable();
	return context->arguments.find(symvar->getId()) != context->arguments.end();
}

bool VMProtectAnalyzer::is_push(VMPHandlerContext *context)
{
	// 1 destination (stack)
	// stack_offset < 0
	char buf[256];
	if (context->destinations.size() != 1)
		return false;

	triton::sint64 stack_offset = this->get_bp() - context->stack;	// needs to be signed
	if (stack_offset >= 0)
		return false;

	// <runtime_address, <dest, source>>
	std::pair<triton::uint64,
		std::pair<triton::ast::SharedAbstractNode, triton::ast::SharedAbstractNode>> _pair = *context->destinations.begin();
	const triton::uint64 runtime_address = _pair.first;
	const triton::ast::SharedAbstractNode& dest = _pair.second.first;
	const triton::ast::SharedAbstractNode& source = _pair.second.second;
	if (!this->is_stack_address(dest, context))
		return false;

	// [stack] = source
	if (source->isSymbolized())
	{
		const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(source, true);
		const triton::engines::symbolic::SharedSymbolicVariable symvar = get_symbolic_var(simplified);
		if (symvar)
		{
			if (context->vmvars.find(symvar->getId()) != context->vmvars.end())
			{
				// push VM_VAR
				std::cout << "push VM_VAR handler detected" << std::endl;

				// disgusting impl
				const std::size_t _pos = symvar->getAlias().find("VM_VAR_");
				if (_pos != std::string::npos)
				{
					unsigned long long scratch_offset = std::stoi(symvar->getAlias().substr(_pos + strlen("VM_VAR_")));
					if (stack_offset == (-8))
						sprintf_s(buf, 256, "push qword ptr Scratch:[0x%llX]", scratch_offset);
					else if (stack_offset == (-4))
						sprintf_s(buf, 256, "push dword ptr Scratch:[0x%llX]", scratch_offset);
					output_strings.push_back(buf);
					return true;
				}
			}
			else if (symvar->getId() == context->symvar_stack->getId())
			{
				// push stack(ebp)
				std::cout << "push SP handler detected" << std::endl;
				output_strings.push_back("push SP");
				return true;
			}
		}
	}
	else
	{
		// push immediate
		const triton::uint64 immediate = source->evaluate().convert_to<triton::uint64>();
		if (stack_offset == (-8))
		{
			std::cout << "push Qword(" << immediate << ") handler detected" << std::endl;
			sprintf_s(buf, 256, "push Qword(0x%llX)", immediate);
			output_strings.push_back(buf);
		}
		else if (stack_offset == (-4))
		{
			std::cout << "push Dword(" << immediate << ") handler detected" << std::endl;
			sprintf_s(buf, 256, "push Dword(0x%llX)", immediate);
			output_strings.push_back(buf);
		}
		else if (stack_offset == (-2))
		{
			std::cout << "push Word(" << immediate << ") handler detected" << std::endl;
			sprintf_s(buf, 256, "push Word(0x%llX)", immediate);
			output_strings.push_back(buf);
		}
		else
		{
			throw std::runtime_error("invalid stack offset");
		}
		return true;
	}
	return false;
}
bool VMProtectAnalyzer::is_pop(VMPHandlerContext *context)
{
	char buf[256];
	const triton::sint64 stack_offset = this->get_bp() - context->stack;	// needs to be signed
	if (stack_offset != 2 && stack_offset != 4 && stack_offset != 8)
		return false;

	// 1 arg, 1 dest(stack), stack_offset>0
	if (context->arguments.size() != 1 || context->destinations.size() != 1)
		return false;

	const auto _pair = *context->destinations.begin();
	const triton::uint64 runtime_address = _pair.first;
	const triton::ast::SharedAbstractNode& dest = _pair.second.first;
	const triton::ast::SharedAbstractNode& source = _pair.second.second;
	if (!this->is_scratch_area_address(dest, context))
		return false;

	const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(source, true);
	if (simplified->getType() == triton::ast::VARIABLE_NODE)
	{
		const triton::engines::symbolic::SharedSymbolicVariable symvar =
			std::dynamic_pointer_cast<triton::ast::VariableNode>(simplified)->getSymbolicVariable();
		if (symvar->getAlias() == "arg0")
		{
			if (stack_offset == 8)
			{
				std::cout << "pop qword [VM_VAR] handler detected" << std::endl;
				sprintf_s(buf, 256, "pop qword ptr Scratch:[0x%llX]", runtime_address - context->x86_sp);
				output_strings.push_back(buf);
			}
			else if (stack_offset == 4)
			{
				std::cout << "pop dword ptr [VM_VAR] handler detected" << std::endl;
				sprintf_s(buf, 256, "pop dword ptr Scratch:[0x%llX]", runtime_address - context->x86_sp);
				output_strings.push_back(buf);
			}
			else if (stack_offset == 2)
			{
				std::cout << "pop word ptr [VM_VAR] handler detected" << std::endl;
				sprintf_s(buf, 256, "pop word ptr Scratch:[0x%llX]", runtime_address - context->x86_sp);
				output_strings.push_back(buf);
			}
			else
			{
				throw std::runtime_error("invalid stack offset");
			}
			return true;
		}
	}
	return false;
}

void VMProtectAnalyzer::load(AbstractStream& stream,
	unsigned long long module_base, unsigned long long vmp0_address, unsigned long long vmp0_size)
{
	// concretize vmp section memory
	unsigned long long vmp_section_address = (module_base + vmp0_address);
	unsigned long long vmp_section_size = vmp0_size;
	void *vmp0 = malloc(vmp_section_size);

	stream.seek(vmp_section_address);
	if (stream.read(vmp0, vmp_section_size) != vmp_section_size)
		throw std::runtime_error("stream.read failed");

	triton_api->setConcreteMemoryAreaValue(vmp_section_address, (const triton::uint8 *)vmp0, vmp_section_size);
	free(vmp0);
}
void VMProtectAnalyzer::analyze_vm_enter(AbstractStream& stream, unsigned long long address)
{
	// reset symbolic
	triton_api->concretizeAllMemory();
	//triton_api->concretizeAllRegister();
	this->symbolize_registers();

	// set esp
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	triton_api->setConcreteRegisterValue(sp_register, 0x1000);

	const triton::uint64 previous_sp = this->get_sp();
	bool check_flags = true;

	std::shared_ptr<BasicBlock> basic_block = make_cfg(stream, address);
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const std::shared_ptr<x86_instruction> instruction = *it;
		const std::vector<xed_uint8_t> bytes = instruction->get_bytes();

		// fix ip
		if (this->is_x64())
			triton_api->setConcreteRegisterValue(triton_api->registers.x86_rip, instruction->get_addr());
		else
			triton_api->setConcreteRegisterValue(triton_api->registers.x86_eip, instruction->get_addr());

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(instruction->get_addr());
		triton_api->processing(triton_instruction);

		// check flags
		if (check_flags)
		{
			// symbolize eflags if pushfd
			if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFD)
			{
				const auto stores = triton_instruction.getStoreAccess();
				if (stores.size() != 1)
					throw std::runtime_error("bluh");

				triton_api->symbolizeMemory(stores.begin()->first)->setAlias("eflags");
			}
			else if (triton_instruction.getType() == triton::arch::x86::ID_INS_PUSHFQ)
			{
				const auto stores = triton_instruction.getStoreAccess();
				if (stores.size() != 1)
					throw std::runtime_error("bluh");

				triton_api->symbolizeMemory(stores.begin()->first)->setAlias("rflags");
			}

			// written_register
			for (const auto &pair : triton_instruction.getWrittenRegisters())
			{
				const triton::arch::Register &written_register = pair.first;
				if (written_register.getId() == triton::arch::ID_REG_X86_EFLAGS)
				{
					check_flags = false;
					break;
				}
			}
		}

		if (++it != basic_block->instructions.end())
		{
			// loop until it reaches end
			std::cout << triton_instruction << std::endl;
			continue;
		}

		if (instruction->get_category() != XED_CATEGORY_UNCOND_BR || instruction->get_branch_displacement_width() == 0)
		{
			std::cout << triton_instruction << std::endl;
		}

		if (basic_block->next_basic_block && basic_block->target_basic_block)
		{
			// it ends with conditional branch
			if (triton_instruction.isConditionTaken())
			{
				basic_block = basic_block->target_basic_block;
			}
			else
			{
				basic_block = basic_block->next_basic_block;
			}
		}
		else if (basic_block->target_basic_block)
		{
			// it ends with jmp?
			basic_block = basic_block->target_basic_block;
		}
		else if (basic_block->next_basic_block)
		{
			// just follow :)
			basic_block = basic_block->next_basic_block;
		}
		else
		{
			// perhaps finishes?
			break;
		}

		it = basic_block->instructions.begin();
	}

	const triton::uint64 bp = this->get_bp();
	const triton::uint64 sp = this->get_sp();
	const triton::uint64 scratch_size = bp - sp;
	const triton::uint64 scratch_length = scratch_size / triton_api->getGprSize();
	const triton::uint64 var_length = (previous_sp - bp) / triton_api->getGprSize();
	for (triton::uint64 i = 0; i < var_length; i++)
	{
		triton::ast::SharedAbstractNode mem_ast = triton_api->getMemoryAst(
			triton::arch::MemoryAccess(previous_sp - (i * triton_api->getGprSize()) - triton_api->getGprSize(), triton_api->getGprSize()));
		triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(mem_ast, true);
		if (simplified->getType() == triton::ast::BV_NODE)
		{
			triton::uint64 val = simplified->evaluate().convert_to<triton::uint64>();

			char buf[1024];
			if (this->is_x64())
				sprintf_s(buf, 1024, "push Qword(0x%llX)", val);
			else
				sprintf_s(buf, 1024, "push Dword(0x%llX)", val);
			output_strings.push_back(buf);
		}
		else if (simplified->getType() == triton::ast::VARIABLE_NODE)
		{
			char buf[1024];
			sprintf_s(buf, 1024, "push %s",
				std::dynamic_pointer_cast<triton::ast::VariableNode>(simplified)->getSymbolicVariable()->getAlias().c_str());
			output_strings.push_back(buf);
		}
		else
		{
			throw std::runtime_error("vm enter error");
		}
	}

	printf("scratch_size: 0x%016llX, scratch_length: %lld\n", scratch_size, scratch_length);
	this->m_scratch_size = scratch_size;
}
void VMProtectAnalyzer::analyze_vm_handler(AbstractStream& stream, unsigned long long handler_address)
{
	// reset
	triton_api->concretizeAllMemory();
	triton_api->concretizeAllRegister();

	// allocate scratch area
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	const triton::arch::Register si_register = this->is_x64() ? triton_api->registers.x86_rsi : triton_api->registers.x86_esi;

	constexpr unsigned long c_stack_base = 0x1000;
	triton_api->setConcreteRegisterValue(rb_register, c_stack_base);
	triton_api->setConcreteRegisterValue(sp_register, c_stack_base - this->m_scratch_size);

	unsigned int arg0 = c_stack_base;
	triton_api->setConcreteMemoryAreaValue(c_stack_base, (const triton::uint8*)&arg0, 4);

	// ebp = VM's "stack" pointer
	triton::engines::symbolic::SharedSymbolicVariable symvar_stack = triton_api->symbolizeRegister(rb_register);

	// esi = pointer to VM bytecode
	triton::engines::symbolic::SharedSymbolicVariable symvar_bytecode = triton_api->symbolizeRegister(si_register);

	// x86 stack pointer
	triton::engines::symbolic::SharedSymbolicVariable symvar_x86_sp = triton_api->symbolizeRegister(sp_register);

	symvar_stack->setAlias("stack");
	symvar_bytecode->setAlias("bytecode");
	symvar_x86_sp->setAlias("sp");

	// yo...
	VMPHandlerContext context;
	context.scratch_area_size = this->is_x64() ? 0x140 : 0x60;
	context.address = handler_address;
	context.stack = triton_api->getConcreteRegisterValue(rb_register).convert_to<triton::uint64>();
	context.bytecode = triton_api->getConcreteRegisterValue(si_register).convert_to<triton::uint64>();
	context.x86_sp = triton_api->getConcreteRegisterValue(sp_register).convert_to<triton::uint64>();
	context.symvar_stack = symvar_stack;
	context.symvar_bytecode = symvar_bytecode;
	context.symvar_x86_sp = symvar_x86_sp;

	std::shared_ptr<BasicBlock> basic_block;
	auto handler_it = this->m_handlers.find(handler_address);
	if (handler_it == this->m_handlers.end())
	{
		basic_block = make_cfg(stream, handler_address);
		this->m_handlers.insert(std::make_pair(handler_address, basic_block));
	}
	else
	{
		basic_block = handler_it->second;
	}

	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const std::shared_ptr<x86_instruction> xed_instruction = *it;
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());
		triton_api->processing(triton_instruction);
		if (++it != basic_block->instructions.end())
		{
			// check store
			this->storeAccess(triton_instruction, &context);

			// check load
			this->loadAccess(triton_instruction, &context);

			// loop until it reaches end
			std::cout << "\t" << triton_instruction << std::endl;
			continue;
		}

		if (xed_instruction->get_category() != XED_CATEGORY_UNCOND_BR 
			|| xed_instruction->get_branch_displacement_width() == 0)
		{
			std::cout << "\t" << triton_instruction << std::endl;
		}
		if (basic_block->next_basic_block && basic_block->target_basic_block)
		{
			// it ends with conditional branch
			if (triton_instruction.isConditionTaken())
			{
				basic_block = basic_block->target_basic_block;
			}
			else
			{
				basic_block = basic_block->next_basic_block;
			}
		}
		else if (basic_block->target_basic_block)
		{
			// it ends with jmp?
			basic_block = basic_block->target_basic_block;
		}
		else if (basic_block->next_basic_block)
		{
			// just follow :)
			basic_block = basic_block->next_basic_block;
		}
		else
		{
			// perhaps finishes?
			break;
		}

		it = basic_block->instructions.begin();
	}

	this->categorize_handler(&context);
}
void VMProtectAnalyzer::analyze_vm_exit(unsigned long long handler_address)
{
	// not the best impl but faspofkapwskefo
	std::stack<x86_register> modified_registers;
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::uint64 previous_stack = triton_api->getConcreteRegisterValue(rb_register).convert_to<triton::uint64>();

	std::shared_ptr<BasicBlock> basic_block = this->m_handlers[handler_address];
	for (auto it = basic_block->instructions.begin(); it != basic_block->instructions.end();)
	{
		const auto instruction = *it;
		const std::vector<xed_uint8_t> bytes = instruction->get_bytes();

		// do stuff with triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(instruction->get_addr());
		triton_api->processing(triton_instruction);

		std::vector<x86_register> written_registers = instruction->get_written_registers();
		for (const auto& reg : written_registers)
		{
			if (this->is_x64())
			{
				if ((reg == XED_REG_RFLAGS || reg.get_gpr_class() == XED_REG_CLASS_GPR64) && reg != XED_REG_RSP)
				{
					modified_registers.push(reg);
				}
			}
			else
			{
				if ((reg == XED_REG_EFLAGS || reg.get_gpr_class() == XED_REG_CLASS_GPR32) && reg != XED_REG_ESP)
				{
					modified_registers.push(reg);
				}
			}
		}

		if (++it != basic_block->instructions.end())
		{
			// loop until it reaches end
			std::cout << triton_instruction << std::endl;
			continue;
		}

		if (!instruction->is_branch())
		{
			std::cout << triton_instruction << std::endl;
		}

		if (basic_block->next_basic_block && basic_block->target_basic_block)
		{
			// it ends with conditional branch
			if (triton_instruction.isConditionTaken())
			{
				basic_block = basic_block->target_basic_block;
			}
			else
			{
				basic_block = basic_block->next_basic_block;
			}
		}
		else if (basic_block->target_basic_block)
		{
			// it ends with jmp?
			basic_block = basic_block->target_basic_block;
		}
		else if (basic_block->next_basic_block)
		{
			// just follow :)
			basic_block = basic_block->next_basic_block;
		}
		else
		{
			// perhaps finishes?
			break;
		}

		it = basic_block->instructions.begin();
	}

	std::set<x86_register> _set;
	std::stack<x86_register> _final;
	while (!modified_registers.empty())
	{
		x86_register r = modified_registers.top();
		modified_registers.pop();

		if (_set.count(r) == 0)
		{
			_set.insert(r);
			_final.push(r);
		}
	}

	while (!_final.empty())
	{
		x86_register r = _final.top();
		_final.pop();

		std::string s = "pop " + std::string(r.get_name());
		this->output_strings.push_back(s);
	}
	this->output_strings.push_back("ret");
}

void VMProtectAnalyzer::loadAccess(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context)
{
	const auto& loadAccess = triton_instruction.getLoadAccess();
	for (const std::pair<triton::arch::MemoryAccess, triton::ast::SharedAbstractNode>& pair : loadAccess)
	{
		const triton::arch::MemoryAccess &mem = pair.first;
		const triton::ast::SharedAbstractNode &mem_ast = pair.second;
		const triton::uint64 address = mem.getAddress();
		triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
		if (!lea_ast)
		{
			// most likely can be ignored
			continue;
		}

		lea_ast = triton_api->processSimplification(lea_ast, true);
		if (!lea_ast->isSymbolized())
		{
			// most likely can be ignored
			continue;
		}

		const triton::arch::Register& dest_register = this->get_dest_register(triton_instruction);
		if (this->is_bytecode_address(lea_ast, context))
		{
			switch (mem.getSize())
			{
				case 1:
				case 2:
				case 4:
				case 8:
				{
					// valid mem size
					break;
				}
				default:
				{
					std::stringstream ss;
					ss << "invalid mem size";
					throw std::runtime_error(ss.str());
				}
			}

			// bytecode can be considered const value
			if (0)
			{
				std::string alias = "bytecode-" + std::to_string(mem.getSize());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias(alias);
				context->bytecodes.insert(std::make_pair(symvar->getId(), symvar));
			}
			printf("%s=bytecode(%d)\n", dest_register.getName().c_str(), mem.getSize());
		}
		else if (this->is_scratch_area_address(lea_ast, context))
		{
			unsigned long long offset = lea_ast->evaluate().convert_to<unsigned long long>() - context->x86_sp;

			char var_name[64];
			sprintf_s(var_name, 64, "VM_VAR_%lld", offset);

			const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
			symvar->setAlias(var_name);
			context->vmvars.insert(std::make_pair(symvar->getId(), symvar));

			std::cout << dest_register.getName() << "= [x86_sp + 0x" << std::hex << offset << "]" << std::endl;
		}
		else if (this->is_stack_address(lea_ast, context))
		{
			const triton::uint64 arg_offset = address - context->stack;
			if (arg_offset == 0)
			{
				printf("%s=arg0(%dbytes)\n", dest_register.getName().c_str(), mem.getSize());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg0");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else if (arg_offset == 2)
			{
				printf("%s=arg1(%dbytes)\n", dest_register.getName().c_str(), mem.getSize());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg1");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else if (arg_offset == 4)
			{
				printf("%s=arg1(%dbytes)\n", dest_register.getName().c_str(), mem.getSize());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg1");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else if (arg_offset == 8)
			{
				printf("%s=arg2(%dbytes)\n", dest_register.getName().c_str(), mem.getSize());
				const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
				symvar->setAlias("arg2");
				context->arguments.insert(std::make_pair(symvar->getId(), symvar));
			}
			else
			{
				throw std::runtime_error("invalid arg offset");
			}
		}
		else if (this->is_fetch_arguments(lea_ast, context))
		{
			const triton::arch::Register &segment_register = mem.getConstSegmentRegister();
			if (segment_register.getId() == triton::arch::ID_REG_INVALID)
			{
				// DS?
			}

			std::string alias = "fetch_" + segment_register.getName() + ":"
				+ std::dynamic_pointer_cast<triton::ast::VariableNode>(lea_ast)->getSymbolicVariable()->getAlias();
			const triton::arch::Register& dest_register = this->get_dest_register(triton_instruction);
			const triton::engines::symbolic::SharedSymbolicVariable symvar = triton_api->symbolizeRegister(dest_register);
			symvar->setAlias(alias);
			context->fetched.insert(std::make_pair(symvar->getId(), symvar));

			printf("fetched to %s\n", dest_register.getName().c_str());
		}
		else
		{
			std::cout << triton_instruction << std::endl;
			std::cout << lea_ast << std::endl;
			//throw std::runtime_error("unknown memory read has found.");
		}
	}
}
void VMProtectAnalyzer::storeAccess(triton::arch::Instruction &triton_instruction, VMPHandlerContext *context)
{
	const auto& storeAccess = triton_instruction.getStoreAccess();
	for (const std::pair<triton::arch::MemoryAccess, triton::ast::SharedAbstractNode>& pair : storeAccess)
	{
		const triton::arch::MemoryAccess &mem = pair.first;
		const triton::ast::SharedAbstractNode &mem_ast = pair.second;
		const triton::uint64 address = mem.getAddress();
		triton::ast::SharedAbstractNode lea_ast = mem.getLeaAst();
		if (!lea_ast)
		{
			// most likely can be ignored
			continue;
		}

		lea_ast = triton_api->processSimplification(lea_ast, true);
		if (!lea_ast->isSymbolized())
		{
			// most likely can be ignored
			continue;
		}

		if (this->is_scratch_area_address(lea_ast, context))
		{
			// mov MEM, REG
			const triton::arch::Register& source_register = this->get_source_register(triton_instruction);
			const triton::ast::SharedAbstractNode register_ast = triton_api->processSimplification(triton_api->getRegisterAst(source_register), true);
			context->insert_scratch(lea_ast, register_ast);

			const triton::uint64 scratch_offset = lea_ast->evaluate().convert_to<triton::uint64>() - context->x86_sp;
			std::cout << "[x86_sp + 0x" << std::hex << scratch_offset << "] = " << register_ast << std::endl;
		}
		else if (this->is_stack_address(lea_ast, context))
		{
			// stores to stack
			const triton::arch::Register& source_register = this->get_source_register(triton_instruction);
			const triton::ast::SharedAbstractNode register_ast = triton_api->processSimplification(triton_api->getRegisterAst(source_register), true);
			context->insert_scratch(lea_ast, register_ast);
			std::cout << "[" << lea_ast << "]=" << register_ast << std::endl;
		}
		else if (this->is_fetch_arguments(lea_ast, context))
		{
			// mov MEM, REG
			const triton::arch::Register& source_register = this->get_source_register(triton_instruction);
			const triton::ast::SharedAbstractNode register_ast = triton_api->processSimplification(triton_api->getRegisterAst(source_register), true);
			context->insert_scratch(lea_ast, register_ast);
			std::cout << "[" << lea_ast << "]=" << register_ast << std::endl;
		}
		else
		{
			std::cout << lea_ast << std::endl;
		}
	}
}
void VMProtectAnalyzer::categorize_handler(VMPHandlerContext *context)
{
	const triton::arch::Register rb_register = this->is_x64() ? triton_api->registers.x86_rbp : triton_api->registers.x86_ebp;
	const triton::arch::Register sp_register = this->is_x64() ? triton_api->registers.x86_rsp : triton_api->registers.x86_esp;
	const triton::arch::Register si_register = this->is_x64() ? triton_api->registers.x86_rsi : triton_api->registers.x86_esi;
	const triton::uint64 bytecode = triton_api->getConcreteRegisterValue(si_register).convert_to<triton::uint64>();
	const triton::uint64 sp = this->get_sp();
	const triton::uint64 stack = this->get_bp();

	std::cout << "handlers outputs:" << std::endl;
	printf("\tbytecode: 0x%016llX -> 0x%016llX\n", context->bytecode, bytecode);
	printf("\tsp: 0x%016llX -> 0x%016llX\n", context->x86_sp, sp);
	printf("\tstack: 0x%016llX -> 0x%016llX\n", context->stack, stack);
	for (const auto &pair : context->destinations)
	{
		std::cout << "\t" << pair.second.first << "(0x" << std::hex << pair.first << ")="
			<< triton_api->processSimplification(pair.second.second, true) << std::endl;
	}

	bool handler_detected = false;
	auto it = context->destinations.begin();

	// check if push
	triton::sint64 stack_offset = stack - context->stack;	// needs to be signed
	if (this->is_push(context))
	{
		handler_detected = true;
	}

	// check if pop
	else if (this->is_pop(context))
	{
		handler_detected = true;
	}

	else if (context->destinations.size() == 0)
	{
		const triton::ast::SharedAbstractNode simplified_stack_ast =
			triton_api->processSimplification(triton_api->getRegisterAst(rb_register), true);

		const triton::ast::SharedAbstractNode simplified_sp_ast =
			triton_api->processSimplification(triton_api->getRegisterAst(sp_register), true);

		const triton::ast::SharedAbstractNode simplified_bytecode_ast =
			triton_api->processSimplification(triton_api->getRegisterAst(si_register), true);

		if (simplified_stack_ast->getType() == triton::ast::VARIABLE_NODE
			&& std::dynamic_pointer_cast<triton::ast::VariableNode>(simplified_stack_ast)->getSymbolicVariable()->getAlias() == "arg0")
		{
			// EBP is loaded from ARG0
			std::cout << "Store SP handler detected" << std::endl;
			output_strings.push_back("pop esp"); // XD
			handler_detected = true;
		}
		else
		{
			std::set<triton::ast::SharedAbstractNode> symvars = collect_variable_nodes(simplified_sp_ast);
			if (symvars.size() == 1)
			{
				const triton::ast::SharedAbstractNode _node = *symvars.begin();
				const triton::engines::symbolic::SharedSymbolicVariable symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(_node)->getSymbolicVariable();
				if (symvar->getId() == context->symvar_stack->getId())
				{
					// sp = computed by stack
					analyze_vm_exit(context->address);
					std::cout << "Ret handler detected" << std::endl;
					handler_detected = true;
				}
			}

			symvars = collect_variable_nodes(simplified_bytecode_ast);
			if (symvars.size() == 1)
			{
				const triton::ast::SharedAbstractNode _node = *symvars.begin();
				const triton::engines::symbolic::SharedSymbolicVariable symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(_node)->getSymbolicVariable();
				if (context->arguments.find(symvar->getId()) != context->arguments.end())
				{
					// bytecode can be computed by arg -> Jmp handler perhaps
					std::cout << "Jmp handler detected" << std::endl;
					handler_detected = true;
				}
			}
		}
	}
	else if (context->destinations.size() == 1)
	{
		const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(it->second.second, true);
		std::set<triton::ast::SharedAbstractNode> symvars = collect_variable_nodes(simplified);

		// check if push handlers
		const triton::uint64 runtime_address = it->first;
		if (simplified->getType() == triton::ast::VARIABLE_NODE)
		{
			const triton::engines::symbolic::SharedSymbolicVariable symvar = std::dynamic_pointer_cast<triton::ast::VariableNode>(simplified)->getSymbolicVariable();
			if (runtime_address == context->stack
				&& context->stack == stack
				&& symvar->getAlias() == "fetch_ss:arg0")	// holy fuck
			{
				// pop t0
				// push dword ss:[t0]
				std::cout << "fetch ss handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				std::string variable_name = "t" + std::to_string(++this->m_temp);
				char buf[256];
				sprintf_s(buf, 256, "pop %s", variable_name.c_str());
				output_strings.push_back(buf);

				// push DWORD SS:[t0]
				sprintf_s(buf, 256, "push SS:[%s]", variable_name.c_str());
				output_strings.push_back(buf);
			}

			else if (runtime_address == context->stack
				&& context->stack == stack
				&& symvar->getAlias() == "fetch_unknown:arg0")	// holy fuck
			{
				// t = pop()
				// t1 = fetch(t)
				// push(t1)
				std::cout << "fetch handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				std::string variable_name = "t" + std::to_string(++this->m_temp);
				char buf[256];
				sprintf_s(buf, 256, "pop %s", variable_name.c_str());
				output_strings.push_back(buf);

				// push DWORD SS:[t0]
				sprintf_s(buf, 256, "push dword ptr [%s]", variable_name.c_str());
				output_strings.push_back(buf);
			}
			else if (runtime_address == (context->stack + 2)
				&& context->stack == (stack - 2)
				&& symvar->getAlias() == "fetch_unknown:arg0")
			{
				// pop t0
				// push word ptr [t0]
				std::cout << "fetch2 handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				std::string variable_name = "t" + std::to_string(++this->m_temp);
				char buf[256];
				sprintf_s(buf, 256, "pop %s", variable_name.c_str());
				output_strings.push_back(buf);

				// push DWORD SS:[t0]
				sprintf_s(buf, 256, "push word ptr [%s]", variable_name.c_str());
				output_strings.push_back(buf);
			}

			else if (stack_offset == 8) // this needs to be updated
			{
				// pop t0
				// pop t1
				// [t0] = t1
				std::string t0 = "t" + std::to_string(++this->m_temp);
				std::string t1 = "t" + std::to_string(++this->m_temp);

				// push dword ss:[t0]
				std::cout << "write4 handler detected" << std::endl;
				handler_detected = true;

				// pop t0
				char buf[256];
				sprintf_s(buf, 256, "pop %s", t0.c_str());
				output_strings.push_back(buf);

				// pop t1
				sprintf_s(buf, 256, "pop %s", t1.c_str());
				output_strings.push_back(buf);

				// [t1] = t0
				sprintf_s(buf, 256, "[%s] = %s", t0.c_str(), t1.c_str());
				output_strings.push_back(buf);
			}
		}

	}
	else if (context->destinations.size() == 2)
	{
		for (; it != context->destinations.end(); it++)
		{
			const triton::ast::SharedAbstractNode simplified_source = triton_api->processSimplification(it->second.second, true);
			std::set<triton::ast::SharedAbstractNode> symvars = collect_variable_nodes(simplified_source);
			if (symvars.size() == 2) // binary operations
			{
				// a, b = BINOP(OP_0, OP_1)
				if (simplified_source->getType() == triton::ast::BVADD_NODE)
				{
					// add handler right?
					std::vector<triton::ast::SharedAbstractNode>& add_children = simplified_source->getChildren();
					if (add_children.size() == 2
						&& add_children[0]->getType() == triton::ast::VARIABLE_NODE
						&& add_children[1]->getType() == triton::ast::VARIABLE_NODE)
					{
						std::cout << "ADD handler detected" << std::endl;
						handler_detected = true;

						// t0 = pop
						// t1 = pop
						// t2 = t0 + t1
						// push t2
						// push flags t2
						std::string t0 = "t" + std::to_string(++this->m_temp);
						std::string t1 = "t" + std::to_string(++this->m_temp);
						std::string t2 = "t" + std::to_string(++this->m_temp);

						// pop pop add push push
						// dbg
						char buf[256];
						sprintf_s(buf, 256, "pop %s", t0.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "pop %s", t1.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "%s = %s + %s", t2.c_str(), t0.c_str(), t1.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "push %s", t2.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "push flags %s", t2.c_str());
						output_strings.push_back(buf);
					}
				}
				else if (simplified_source->getType() == triton::ast::BVLSHR_NODE)
				{
					/*
					auto symvars_it = symvars.begin();
					auto _left_node = *symvars_it;
					symvars_it++;
					auto _right_node = *symvars_it;
					printf("SHR(%d, %d)\n", _left_node->getBitvectorSize(), _right_node->getBitvectorSize());
					*/

					// (bvlshr arg0 (concat (_ bv0 1B) ((_ extract 4 0) arg1)))
					std::cout << "SHR handler detected" << std::endl;
					handler_detected = true;

					// t0 = pop
					// t1 = pop
					// t2 = t0 << t1
					// push t2
					// push flags t2
					std::string t0 = "t" + std::to_string(++this->m_temp);
					std::string t1 = "t" + std::to_string(++this->m_temp);
					std::string t2 = "t" + std::to_string(++this->m_temp);

					// pop pop add push push
					// dbg
					char buf[256];
					sprintf_s(buf, 256, "pop %s", t0.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "pop %s", t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "%s = SHR(%s, %s)", t2.c_str(), t0.c_str(), t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push %s", t2.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push flags %s", t2.c_str());
					output_strings.push_back(buf);
				}
				else if (simplified_source->getType() == triton::ast::BVNOT_NODE)
				{
					// (bvnot (bvor arg0 arg1))
					std::cout << "NOR handler detected" << std::endl;
					handler_detected = true;

					// t0 = pop
					// t1 = pop
					// t2 = ~t0 & ~t1
					// push t2
					// push flags t2
					std::string t0 = "t" + std::to_string(++this->m_temp);
					std::string t1 = "t" + std::to_string(++this->m_temp);
					std::string t2 = "t" + std::to_string(++this->m_temp);

					// pop pop add push push
					// dbg
					char buf[256];
					sprintf_s(buf, 256, "pop %s", t0.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "pop %s", t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "%s = NOR(%s, %s)", t2.c_str(), t0.c_str(), t1.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push %s", t2.c_str());
					output_strings.push_back(buf);

					sprintf_s(buf, 256, "push flags %s", t2.c_str());
					output_strings.push_back(buf);
				}
			}
		}
	}
	else if (context->destinations.size() == 3)
	{
		for (; it != context->destinations.end(); it++)
		{
			const triton::ast::SharedAbstractNode simplified = triton_api->processSimplification(it->second.second, true);
			std::set<triton::ast::SharedAbstractNode> symvars = collect_variable_nodes(simplified);
			if (symvars.size() == 2)
			{
				// (bvmul arg1 arg0)
				if (simplified->getType() == triton::ast::BVMUL_NODE)
				{
					std::vector<triton::ast::SharedAbstractNode>& mul_children = simplified->getChildren();
					if (mul_children.size() == 2
						&& mul_children[0]->getType() == triton::ast::VARIABLE_NODE
						&& mul_children[1]->getType() == triton::ast::VARIABLE_NODE)
					{
						std::cout << "(MUL/IMUL) handler detected" << std::endl;
						handler_detected = true;

						// dbg
						char buf[256];
						std::string t0 = "t" + std::to_string(++this->m_temp);
						std::string t1 = "t" + std::to_string(++this->m_temp);
						std::string t2 = "t" + std::to_string(++this->m_temp);
						std::string t3 = "t" + std::to_string(++this->m_temp);
						std::string t4 = "t" + std::to_string(++this->m_temp);

						// pop, pop, mul, push, push, push
						sprintf_s(buf, 256, "pop %s", t0.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "pop %s", t1.c_str());
						output_strings.push_back(buf);

						sprintf_s(buf, 256, "%s, %s, %s = MUL/IMUL(%s, %s)", 
							t2.c_str(), t3.c_str(), t4.c_str(), t0.c_str(), t1.c_str());
						output_strings.push_back(buf);

						// push eax, edx, flags
						sprintf_s(buf, 256, "push %s(eax)", t2.c_str());
						output_strings.push_back(buf);
						sprintf_s(buf, 256, "push %s(edx)", t3.c_str());
						output_strings.push_back(buf);
						sprintf_s(buf, 256, "push %s(flags)", t4.c_str());
						output_strings.push_back(buf);
					}
				}
			}
		}
	}

	if (!handler_detected)
	{
		this->print_output();
		getchar();
	}
}