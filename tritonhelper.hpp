#pragma once

// return symbolic variable if node is variable
extern triton::engines::symbolic::SharedSymbolicVariable get_symbolic_var(const triton::ast::SharedAbstractNode &node);

// unroll and collect variable nodes
extern std::set<triton::ast::SharedAbstractNode> collect_variable_nodes(const triton::ast::SharedAbstractNode &parent);

extern bool is_unary_operation(const triton::arch::Instruction &triton_instruction);
extern bool is_binary_operation(const triton::arch::Instruction &triton_instruction);

// return true if inst is (mov | movsx | movzx)
extern bool is_mov_operation(const triton::arch::Instruction& triton_instruction);