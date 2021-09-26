#pragma once

#include <variant>

namespace new_il
{
	struct register_
	{
		std::string m_name;
		triton::uint64 m_offset;
		triton::arch::Register m_register;
	};
	struct memory
	{
		triton::uint32 m_size;
		triton::arch::Register m_segment_register;
		std::shared_ptr<Expression> m_expr;
	};
	struct immediate
	{
		triton::uint32 m_size;
		triton::uint64 m_immediate;
	};
	struct variable
	{
		std::string m_name;
		triton::uint32 m_size;
	};
	struct binop
	{

	};
	struct unop
	{

	};

	struct expression
	{
		std::variant<register_, memory, immediate, variable, binop, unop> f;

		expression()
		{
		}
	};
}