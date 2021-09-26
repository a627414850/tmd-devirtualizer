#include "pch.h"

#include "CFG.hpp"
#include "AbstractStream.hpp"
#include "x86_instruction.hpp"

triton::uint64 getStackPointerValue(triton::API* api)
{
	return api->getConcreteRegisterValue(api->getCpuInstance()->getStackPointer()).convert_to<triton::uint64>();
}
triton::uint64 getProgramCounterValue(triton::API* api)
{
	return api->getConcreteRegisterValue(api->getCpuInstance()->getProgramCounter()).convert_to<triton::uint64>();
}

static triton::uint64 g_cfg_stack = 0;
static void cfg_mem_read(triton::API& api, const triton::arch::MemoryAccess& mem)
{
	const triton::uint64 runtime_address = mem.getAddress();
	const triton::uint64 current_stack_pointer = getStackPointerValue(&api);
	if (current_stack_pointer <= runtime_address && runtime_address <= g_cfg_stack)
	{
		// valid local variable
		return;
	}

	auto node = mem.getLeaAst();
	if (!node || !node->isSymbolized() 
		//&& api.isConcreteMemoryValueDefined(mem)
		)
	{
		return;
	}

	// symbolize unknown memory
	char _alias[256];
	sprintf_s(_alias, 256, "read_%llx_%d", runtime_address, mem.getSize());
	auto symvar = api.symbolizeMemory(mem, _alias);
	std::cout << "symbolized 0x" << std::hex << runtime_address << '\n';
}
static void cfg_mem_write(triton::API& api, const triton::arch::MemoryAccess& mem, const triton::uint512& value)
{
}

static void explore(AbstractStream& stream, uint64_t address, 
	std::multiset<triton::uint64>& leaders, std::map<triton::uint64, std::shared_ptr<x86_instruction>>& visit)
{
	printf("explore %llx\n", address);

	auto triton_api = std::make_shared<triton::API>();
	triton_api->setArchitecture(stream.is_x86_64() ? triton::arch::ARCH_X86_64 : triton::arch::ARCH_X86);

	// track path constraints even when not symbolized
	triton_api->setMode(triton::modes::PC_TRACKING_SYMBOLIC, false);

	// push/pop gud
	triton_api->setMode(triton::modes::ALIGNED_MEMORY, true);

	// apply simple simplification (ex: A ^ 0 -> A)
	triton_api->setMode(triton::modes::AST_OPTIMIZATIONS, true);
	triton_api->setMode(triton::modes::CONSTANT_FOLDING, true);
	triton_api->setMode(triton::modes::ONLY_ON_SYMBOLIZED, true);

	triton_api->addCallback(cfg_mem_read);
	triton_api->addCallback(cfg_mem_write);

	g_cfg_stack = 0x1001000;
	triton_api->setConcreteRegisterValue(triton_api->getParentRegister(triton_api->registers.x86_ebp), 0x1401151f8ull);
	triton_api->setConcreteRegisterValue(triton_api->getCpuInstance()->getStackPointer(), g_cfg_stack);

	// symbolize everything now
	auto _symbolizeRegister = [triton_api](const triton::arch::Register& reg)
	{
		auto symvar = triton_api->symbolizeRegister(reg);
		symvar->setAlias(reg.getName());
	};
	if (stream.is_x86_64())
	{
		_symbolizeRegister(triton_api->registers.x86_rax);
		_symbolizeRegister(triton_api->registers.x86_rbx);
		_symbolizeRegister(triton_api->registers.x86_rcx);
		_symbolizeRegister(triton_api->registers.x86_rdx);
		_symbolizeRegister(triton_api->registers.x86_rsi);
		_symbolizeRegister(triton_api->registers.x86_rdi);
		_symbolizeRegister(triton_api->registers.x86_rbp);
		//_symbolizeRegister(triton_api->registers.x86_rsp);
		_symbolizeRegister(triton_api->registers.x86_r8);
		_symbolizeRegister(triton_api->registers.x86_r9);
		_symbolizeRegister(triton_api->registers.x86_r10);
		_symbolizeRegister(triton_api->registers.x86_r11);
		_symbolizeRegister(triton_api->registers.x86_r12);
		_symbolizeRegister(triton_api->registers.x86_r13);
		_symbolizeRegister(triton_api->registers.x86_r14);
		_symbolizeRegister(triton_api->registers.x86_r15);
	}
	else
	{
		_symbolizeRegister(triton_api->registers.x86_eax);
		_symbolizeRegister(triton_api->registers.x86_ebx);
		_symbolizeRegister(triton_api->registers.x86_ecx);
		_symbolizeRegister(triton_api->registers.x86_edx);
		_symbolizeRegister(triton_api->registers.x86_esi);
		_symbolizeRegister(triton_api->registers.x86_edi);
		_symbolizeRegister(triton_api->registers.x86_ebp);
		//_symbolizeRegister(triton_api->registers.x86_esp);
	}

	for (; visit.count(address) == 0 && address != 0;)
	{
		// read instruction
		//printf("explore %llx\n", address);
		stream.seek(address);
		std::shared_ptr<x86_instruction> xed_instruction = stream.readNext();
		const std::vector<xed_uint8_t> bytes = xed_instruction->get_bytes();
		visit.insert(std::make_pair(address, xed_instruction));

		// triton
		triton::arch::Instruction triton_instruction;
		triton_instruction.setOpcode(&bytes[0], (triton::uint32)bytes.size());
		triton_instruction.setAddress(xed_instruction->get_addr());
		if (!triton_api->processing(triton_instruction))
		{
			throw std::runtime_error("triton processing failed");
		}

		if (xed_instruction->get_category() != XED_CATEGORY_UNCOND_BR
			|| xed_instruction->get_branch_displacement_width() == 0)
		{
			std::cout << "\t" << triton_instruction << '\n';
		}

		if (!triton_instruction.isControlFlow())
		{
			address = triton_instruction.getNextAddress();
			continue;
		}

		const auto& pathConstraints = triton_api->getPathConstraints();
		if (pathConstraints.empty())
			throw std::runtime_error("path constraints is empty");

		const auto& pathConstraint = pathConstraints.back();

		// <taken, srcAddr, dstAddr, pc>
		const auto& branches = pathConstraint.getBranchConstraints();
		if (branches.size() == 1)
		{
			// CONSTANT_FOLDING can remove paths
			auto node = std::get<3>(branches[0]);
			if (node->isSymbolized())
			{
				// if one way path is symbolized it's terminator
				// printf("destination is symbolized\n");
				return;
			}

			// semantically direct jmp (x86_opcode can be call/jcc/ret etc...)
			const triton::uint64 dest_addr = std::get<2>(branches[0]);
			if (dest_addr != 0)
			{
				leaders.insert(dest_addr);
			}
			address = dest_addr;
		}
		else
		{
			assert(!branches.empty());
			for (auto it = branches.begin(); it != branches.end(); it++)
			{
				// obviously taken path is satisfiable so just check not taken path
				const bool taken = std::get<0>(*it);
				const triton::uint64 dest_addr = std::get<2>(*it);
				auto node = std::get<3>(*it);
				if (!taken)
				{
					if (triton_api->isSat(node))
					{
						// can SAT
						//printf("realjcc\n");
						//getchar();
						leaders.insert(dest_addr);
					}
					else
					{
						// cannot SAT
					}
				}
				else
				{
					if (dest_addr != 0)
					{
						leaders.insert(dest_addr);
					}
					address = dest_addr;
				}
			}
		}
		triton_api->clearPathConstraints();
	}
}

static bool isCall0(const std::shared_ptr<x86_instruction>& instruction)
{
	static xed_uint8_t s_bytes[5] = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
	const auto bytes = instruction->get_bytes();
	if (bytes.size() != 5)
		return false;

	for (int i = 0; i < 5; i++)
	{
		if (s_bytes[i] != bytes[i])
			return false;
	}
	return true;
}

static std::shared_ptr<BasicBlock> make_basic_blocks(uint64_t address,
	const std::multiset<uint64_t>& leaders,
	const std::map<uint64_t, std::shared_ptr<x86_instruction>>& visit,
	std::map<uint64_t, std::shared_ptr<BasicBlock>>& basic_blocks)
{
	// return basic block if it exists
	auto it = basic_blocks.find(address);
	if (it != basic_blocks.end())
		return it->second;

	// make basic block
	std::shared_ptr<BasicBlock> current_basic_block = std::make_shared<BasicBlock>();
	current_basic_block->leader = address;
	current_basic_block->terminator = false;
	current_basic_block->dead_flags = 0;
	basic_blocks.insert(std::make_pair(address, current_basic_block));
	for (;;)
	{
		auto visit_iterator = visit.find(address);
		if (visit_iterator == visit.end())
		{
			printf("%llx\n", address);
			throw std::runtime_error("not in visit");
		}
		std::shared_ptr<x86_instruction> instruction = visit_iterator->second;
		uint64_t next_address = instruction->get_addr();
		if (!current_basic_block->instructions.empty() && leaders.count(next_address) > 0)
		{
			// make basic block with a leader
			current_basic_block->next_basic_block = make_basic_blocks(next_address, leaders, visit, basic_blocks);
			goto return_basic_block;
		}

		next_address = instruction->get_addr() + instruction->get_length();
		current_basic_block->instructions.push_back(instruction);
		switch (instruction->get_category())
		{
			case XED_CATEGORY_COND_BR:		// conditional branch
			{
				const uint64_t target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
				if (leaders.count(target_address) <= 0)
				{
					// fake conditional branch
					next_address = next_address;
					current_basic_block->instructions.pop_back();
				}
				else if (leaders.count(next_address) <= 0)
				{
					// fake conditional branch
					next_address = target_address;
					current_basic_block->instructions.pop_back();
				}
				else
				{
					// real jcc
					current_basic_block->target_basic_block = make_basic_blocks(target_address, leaders, visit, basic_blocks);
					current_basic_block->next_basic_block = make_basic_blocks(next_address, leaders, visit, basic_blocks);
					goto return_basic_block;
				}
				break;
			}
			case XED_CATEGORY_UNCOND_BR:	// unconditional branch
			{
				xed_uint_t width = instruction->get_branch_displacement_width();
				if (width == 0)
				{
					current_basic_block->terminator = true;
					return current_basic_block;
				}

				// follow unconditional branch (target should be leader)
				const uint64_t target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
				if (leaders.count(target_address) <= 0)
				{
					// should be "identify_leaders" bug
					throw std::runtime_error("unconditional branch target is somehow not leader.");
				}

				current_basic_block->target_basic_block = make_basic_blocks(target_address, leaders, visit, basic_blocks);
				goto return_basic_block;
			}
			case XED_CATEGORY_CALL:
			{
				if (isCall0(instruction))
				{
					// call +5 is not leader or some shit
					break;
				}
				else
				{
					// follow call
					const uint64_t target_address = instruction->get_addr() + instruction->get_length() + instruction->get_branch_displacement();
					if (leaders.count(target_address) <= 0)
					{
						// should be "identify_leaders" bug
						throw std::runtime_error("call's target is somehow not leader.");
					}

					current_basic_block->target_basic_block = make_basic_blocks(target_address, leaders, visit, basic_blocks);
					goto return_basic_block;
				}
			}
			case XED_CATEGORY_RET:			// or return
			{
				current_basic_block->terminator = true;
				goto return_basic_block;
			}
			default:
			{
				break;
			}
		}

		address = next_address;
	}

return_basic_block:
	return current_basic_block;
}

static std::shared_ptr<BasicBlock> _make_cfg(AbstractStream& stream, uint64_t address)
{
	// identify leaders
	std::multiset<triton::uint64> leaders;
	std::map<triton::uint64, std::shared_ptr<x86_instruction>> visit;
	explore(stream, address, leaders, visit);
	for (auto it = leaders.begin(); it != leaders.end();)
	{
		const triton::uint64 leader = *it;
		if (visit.find(leader) == visit.end())
		{
			explore(stream, leader, leaders, visit);
			it = leaders.begin();
		}
		else
		{
			++it;
		}
	}

	// make basic blocks
	std::map<uint64_t, std::shared_ptr<BasicBlock>> basic_blocks;
	std::shared_ptr<BasicBlock> first_basic_block = make_basic_blocks(address, leaders, visit, basic_blocks);

	// deobfuscate
	constexpr bool _deobfuscate = 1;
	if (_deobfuscate)
	{
		for (int llll = 0; llll < 10; llll++)
		{
			constexpr bool _constant_folding = 0;
			if (_constant_folding)
			{
				for (auto it = basic_blocks.rbegin(); it != basic_blocks.rend(); ++it)
				{
					//apply_constant_folding(it->second->instructions);
				}
			}

			// can possibly improve by checking dead_registers/flags after deobfuscate
			unsigned int removed_bytes;
			for (int i = 0; i < 5; i++)
			{
				removed_bytes = 0;
				for (auto it = basic_blocks.rbegin(); it != basic_blocks.rend(); ++it)
				{
					removed_bytes += deobfuscate_basic_block(it->second);
				}
			}

			// reconstruct cfg, messy buf who cares...
			std::multiset<xed_uint64_t> refcount;
			std::function<void(std::shared_ptr<BasicBlock>)> get_ref_count = [&get_ref_count, &refcount](std::shared_ptr<BasicBlock> bb)
			{
				if (bb->next_basic_block)
				{
					const auto leader = bb->next_basic_block->leader;
					refcount.insert(leader);
					if (refcount.count(leader) == 1)
						get_ref_count(bb->next_basic_block);
				}
				if (bb->target_basic_block)
				{
					const auto leader = bb->target_basic_block->leader;
					refcount.insert(leader);
					if (refcount.count(leader) == 1)
						get_ref_count(bb->target_basic_block);
				}
			};
			get_ref_count(first_basic_block);

			auto bb = first_basic_block;
			while (bb)
			{
				if (bb->next_basic_block
					&& !bb->target_basic_block
					&& refcount.count(bb->next_basic_block->leader) == 1)
				{
					// combine them
					auto next_basic_block = bb->next_basic_block;
					bb->instructions.insert(bb->instructions.end(),
						next_basic_block->instructions.begin(), next_basic_block->instructions.end());

					bb->terminator = next_basic_block->terminator;
					bb->next_basic_block = next_basic_block->next_basic_block;
					bb->target_basic_block = next_basic_block->target_basic_block;

					refcount.erase(next_basic_block->leader);
					basic_blocks.erase(next_basic_block->leader);
				}
				else if (!bb->next_basic_block
					&& bb->target_basic_block
					&& refcount.count(bb->target_basic_block->leader) == 1)
				{
					// combine them
					auto target_basic_block = bb->target_basic_block;

					// pop last instruction if jmp
					const auto& instr = bb->instructions.back();
					if (instr->get_iclass() == XED_ICLASS_JMP)
						bb->instructions.pop_back();

					// copy
					bb->instructions.insert(bb->instructions.end(),
						target_basic_block->instructions.begin(), target_basic_block->instructions.end());
					bb->terminator = target_basic_block->terminator;
					bb->next_basic_block = target_basic_block->next_basic_block;
					bb->target_basic_block = target_basic_block->target_basic_block;

					// deref
					refcount.erase(target_basic_block->leader);
					basic_blocks.erase(target_basic_block->leader);
				}
				else if (bb->next_basic_block)
				{
					// what if basicblock has 2 path tho
					bb = bb->next_basic_block;
				}
				else
				{
					bb = bb->target_basic_block;
				}
			}
		}
	}

	return first_basic_block;
}

std::shared_ptr<BasicBlock> triton_make_cfg(AbstractStream& stream, uint64_t address)
{
	return _make_cfg(stream, address);
}