#include "pch.h"

#include "ThemidaIR.hpp"

namespace IR
{
	int Variable::s_index = 0;

	// Register
	Register::Register(const triton::arch::Register &triton_register) : Expression(expression_type::register_)
	{
		this->m_name = triton_register.getName();
		this->m_offset = 0;
		this->m_register = triton_register;
	}
	triton::uint32 Register::get_bit_size() const
	{
		return this->m_register.getBitSize();
	}
	triton::uint32 Register::get_size() const
	{
		return this->m_register.getSize();
	}
	void Register::to_string(std::ostream& stream) const
	{
		stream << this->get_name();
	}
	std::string Register::get_name() const
	{
		return this->m_name;
	}
	triton::uint64 Register::get_offset() const
	{
		return this->m_offset;
	}
	void Register::set_offset(triton::uint64 offset)
	{
		this->m_offset = offset;
	}


	// Memory
	Memory::Memory(const std::shared_ptr<Expression> &expr, const triton::arch::Register& segment_register, triton::uint32 size) : Expression(expression_type::memory)
	{
		this->m_expr = expr;
		this->m_segment_register = segment_register;
		this->m_size = size;
	}
	triton::uint32 Memory::get_bit_size() const
	{
		return this->get_size() * 8;
	}
	triton::uint32 Memory::get_size() const
	{
		return this->m_size;
	}
	void Memory::to_string(std::ostream& stream) const
	{
		switch (this->m_size)
		{
			case 1: stream << "byte"; break;
			case 2: stream << "word"; break;
			case 4: stream << "dword"; break;
			case 8: stream << "qword"; break;
			default:
			{
				throw std::runtime_error("invalid size");
			}
		}
		stream << " ptr " << m_segment_register.getName() << ":[" << this->m_expr << "]";
	}
	std::shared_ptr<Expression> Memory::get_expression() const
	{
		return this->m_expr;
	}
	void Memory::set_expression(std::shared_ptr<Expression> expr)
	{
		this->m_expr = expr;
	}


	// Variable
	Variable::Variable(triton::uint32 size) : Expression(expression_type::variable)
	{
		this->m_name = "t" + std::to_string(++s_index);
		this->m_size = size;
	}
	Variable::Variable(const std::string &name, triton::uint32 size) : Expression(expression_type::variable)
	{
		this->m_name = name;
		this->m_size = size;
	}
	triton::uint32 Variable::get_bit_size() const
	{
		return this->get_size() * 8;
	}
	triton::uint32 Variable::get_size() const
	{
		return this->m_size;
	}
	void Variable::to_string(std::ostream& stream) const
	{
		stream << this->get_name();
	}
	std::string Variable::get_name() const
	{
		return this->m_name;
	}
	std::shared_ptr<Variable> Variable::create_variable(triton::uint32 size)
	{
		return std::make_shared<Variable>(size);
	}


	// Immediate
	Immediate::Immediate(triton::uint64 value, triton::uint32 size) : Expression(expression_type::immediate)
	{
		this->m_immediate = value;
		this->m_size = size;
	}
	triton::uint32 Immediate::get_bit_size() const
	{
		return this->get_size() * 8;
	}
	triton::uint32 Immediate::get_size() const
	{
		return this->m_size;
	}
	void Immediate::to_string(std::ostream& stream) const
	{
		triton::sint64 imm = this->m_immediate;
		if (-0x10000 < imm && imm < 0)
		{
			stream << "-0x" << std::hex << -imm << std::dec;
		}
		else
		{
			stream << "0x" << std::hex << this->m_immediate << std::dec;
		}
	}


	// UnaryOperation
	UnaryOperation::UnaryOperation(const std::shared_ptr<Expression> &op, unary_op t) : Expression(expression_type::unary_op)
	{
		this->m_op = op;
		this->m_type = t;
	}
	triton::uint32 UnaryOperation::get_bit_size() const
	{
		return this->m_op->get_bit_size();
	}
	triton::uint32 UnaryOperation::get_size() const
	{
		return this->m_op->get_size();
	}
	UnaryOperation::UnaryOperation(UnaryOperation&& src) : Expression(expression_type::unary_op)
	{
		this->m_op = src.m_op;
		this->m_type = src.m_type;
	}


	// BinaryOperation
	BinaryOperation::BinaryOperation(const std::shared_ptr<Expression> &op0, const std::shared_ptr<Expression> &op1, 
		binary_op t) : Expression(expression_type::binary_op)
	{
		this->m_op0 = op0;
		this->m_op1 = op1;
		this->m_binary_type = t;
	}
	BinaryOperation::BinaryOperation(BinaryOperation&& from) : Expression(expression_type::binary_op)
	{
		this->m_op0 = from.m_op0;
		this->m_op1 = from.m_op1;
		this->m_binary_type = from.m_binary_type;
	}

	triton::uint32 BinaryOperation::get_bit_size() const
	{
		return this->m_op0->get_bit_size();
	}
	triton::uint32 BinaryOperation::get_size() const
	{
		return this->m_op1->get_size();
	}
	binary_op BinaryOperation::get_binary_type() const
	{
		return this->m_binary_type;
	}


	//
	std::ostream& operator<<(std::ostream& stream, const Expression& expr)
	{
		expr.to_string(stream);
		return stream;
	}
	std::ostream& operator<<(std::ostream& stream, const Expression* expr)
	{
		expr->to_string(stream);
		return stream;
	}


	// i suck tho :'(
	std::shared_ptr<Expression> simplify_expression(const std::shared_ptr<Expression> &expression)
	{
		if (expression->get_type() == IR::expression_type::unary_op)
		{
			expression->set_operand(0, simplify_expression(expression->get_operand(0)));
		}
		else if (expression->get_type() == IR::expression_type::binary_op)
		{
			std::shared_ptr<IR::BinaryOperation> binary_op = std::dynamic_pointer_cast<IR::BinaryOperation>(expression);
			if (binary_op->get_binary_type() == IR::binary_op::add
				|| binary_op->get_binary_type() == IR::binary_op::sub
				|| binary_op->get_binary_type() == IR::binary_op::xor_)
			{
				// (add|sub|xor) X,0 -> X
				if (binary_op->get_operand(0)->get_type() == IR::expression_type::immediate
					&& binary_op->get_operand(0)->get_value() == 0)
				{
					return binary_op->get_operand(1);
				}
				else if (binary_op->get_operand(1)->get_type() == IR::expression_type::immediate
					&& binary_op->get_operand(1)->get_value() == 0)
				{
					return binary_op->get_operand(0);
				}
			}

			// return <expr, imm>
			auto parse_binary_expression = [](const std::shared_ptr<IR::BinaryOperation> &binary_op) -> 
				std::tuple<std::shared_ptr<IR::Expression>, std::shared_ptr<IR::Expression>>
			{
				std::shared_ptr<IR::Expression> immediate_node;
				std::shared_ptr<IR::Expression> the_other_node;

				auto expr0 = binary_op->get_operand(0);
				auto expr1 = binary_op->get_operand(1);
				if (expr0->get_type() == IR::expression_type::immediate)
				{
					immediate_node = expr0;
					the_other_node = expr1;
				}
				else if (expr1->get_type() == IR::expression_type::immediate)
				{
					the_other_node = expr0;
					immediate_node = expr1;
				}
				return std::make_tuple(the_other_node, immediate_node);
			};

			// add(add(x, imm0), imm1) -> add(x, imm0 + imm1)
			if (binary_op->get_binary_type() == IR::binary_op::add
				|| binary_op->get_binary_type() == IR::binary_op::sub)
			{
				auto [possible_binary_expr, imm_node_0] = parse_binary_expression(binary_op);
				if (possible_binary_expr && imm_node_0 && possible_binary_expr->get_type() == IR::expression_type::binary_op)
				{
					std::shared_ptr<IR::BinaryOperation> sub_binary_node = std::dynamic_pointer_cast<IR::BinaryOperation>(possible_binary_expr);
					if (sub_binary_node->get_binary_type() == IR::binary_op::add || sub_binary_node->get_binary_type() == IR::binary_op::sub)
					{
						auto [rest_of_node, imm_node_1] = parse_binary_expression(sub_binary_node);
						if (rest_of_node && imm_node_1)
						{
							triton::sint64 value0 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_0)->get_value();
							if (binary_op->get_binary_type() == IR::binary_op::sub)
								value0 = -value0;

							triton::sint64 value1 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_1)->get_value();
							if (sub_binary_node->get_binary_type() == IR::binary_op::sub)
								value1 = -value1;

							return std::make_shared<IR::Add>(rest_of_node, std::make_shared<IR::Immediate>(value0 + value1));
						}
					}
				}
			}
			else if (binary_op->get_binary_type() == IR::binary_op::xor_)
			{
				auto [possible_binary_expr, imm_node_0] = parse_binary_expression(binary_op);
				if (possible_binary_expr && imm_node_0 && possible_binary_expr->get_type() == IR::expression_type::binary_op)
				{
					std::shared_ptr<IR::BinaryOperation> sub_binary_node = std::dynamic_pointer_cast<IR::BinaryOperation>(possible_binary_expr);
					if (sub_binary_node->get_binary_type() == IR::binary_op::xor_)
					{
						auto [rest_of_node, imm_node_1] = parse_binary_expression(sub_binary_node);
						if (rest_of_node && imm_node_1)
						{
							triton::sint64 value0 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_0)->get_value();
							triton::sint64 value1 = std::dynamic_pointer_cast<IR::Immediate>(imm_node_1)->get_value();
							return std::make_shared<IR::Xor>(rest_of_node, std::make_shared<IR::Immediate>(value0 ^ value1));
						}
					}
				}

				// x ^ x -> 0
				auto lhs = binary_op->get_operand(0);
				auto rhs = binary_op->get_operand(1);
				if (lhs == rhs)
				{
					return std::make_shared<IR::Immediate>(0);
				}

				// xor(xor(x,y), x) -> y
				if (lhs->get_type() == IR::expression_type::binary_op)
				{
					std::shared_ptr<IR::BinaryOperation> lhs_bin_op = std::dynamic_pointer_cast<IR::BinaryOperation>(lhs);
					if (lhs_bin_op->get_binary_type() == IR::binary_op::xor_)
					{
						if (lhs_bin_op->get_operand(0) == rhs)
							return lhs_bin_op->get_operand(1);
						else if (lhs_bin_op->get_operand(1) == rhs)
							return lhs_bin_op->get_operand(0);
					}
				}

				auto _save = lhs;
				lhs = rhs;
				rhs = _save;
				if (lhs->get_type() == IR::expression_type::binary_op)
				{
					std::shared_ptr<IR::BinaryOperation> lhs_bin_op = std::dynamic_pointer_cast<IR::BinaryOperation>(lhs);
					if (lhs_bin_op->get_binary_type() == IR::binary_op::xor_)
					{
						if (lhs_bin_op->get_operand(0) == rhs)
							return lhs_bin_op->get_operand(1);
						else if (lhs_bin_op->get_operand(1) == rhs)
							return lhs_bin_op->get_operand(0);
					}
				}
			}

			// simplify
			std::shared_ptr<Expression> simplified_expr0 = simplify_expression(binary_op->get_operand(0));
			std::shared_ptr<Expression> simplified_expr1 = simplify_expression(binary_op->get_operand(1));
			binary_op->set_operand(0, simplified_expr0);
			binary_op->set_operand(1, simplified_expr1);
		}
		return expression;
	}



	exprptr make_copy(const exprptr exp)
	{
		expression_type type = exp->get_type();
		switch (type)
		{
			case expression_type::register_:
			{
				// if register return?
				return exp;
			}
			case expression_type::memory:
			{
				auto _mem = std::dynamic_pointer_cast<IR::Memory>(exp);
				return std::make_shared<IR::Memory>(*_mem);
			}
			case expression_type::variable:
			{
				// no copy if variable?
				return exp;
			}
			case expression_type::immediate:
			{
				auto _imm = std::dynamic_pointer_cast<IR::Immediate>(exp);
				return std::make_shared<IR::Immediate>(*_imm);
			}
			case expression_type::unary_op:
			{
				auto unary_op = std::dynamic_pointer_cast<IR::UnaryOperation>(exp);
				auto op0 = make_copy(unary_op->get_operand(0));
				switch (unary_op->get_unary_op())
				{
					case IR::unary_op::inc: return std::make_shared<IR::Inc>(op0);
					case IR::unary_op::dec: return std::make_shared<IR::Dec>(op0);
					case IR::unary_op::not_: return std::make_shared<IR::Not>(op0);
					case IR::unary_op::neg: return std::make_shared<IR::Neg>(op0);
					case IR::unary_op::extend:
					{
						auto _extend = std::dynamic_pointer_cast<IR::Extend>(unary_op);
						return std::make_shared<IR::Extend>(op0, _extend->get_size());
					}
					case IR::unary_op::signextend: return std::make_shared<IR::SignExtend>(op0);
					case IR::unary_op::zeroextend: return std::make_shared<IR::ZeroExtend>(op0);
					case IR::unary_op::extract:
					{
						auto _extract = std::dynamic_pointer_cast<IR::Extract>(unary_op);
						return std::make_shared<IR::Extract>(op0, _extract->get_high(), _extract->get_low());
					}
					case IR::unary_op::flagsof: return std::make_shared<IR::Flags>(op0);
					default:
						break;
				}
			}
			case expression_type::binary_op:
			{
				auto binop = std::dynamic_pointer_cast<IR::BinaryOperation>(exp);
				auto op0 = make_copy(binop->get_operand(0));
				auto op1 = make_copy(binop->get_operand(1));
				switch (binop->get_binary_type())
				{
					case IR::binary_op::add: return std::make_shared<IR::Add>(op0, op1);
					case IR::binary_op::sub: return std::make_shared<IR::Sub>(op0, op1);
					case IR::binary_op::imul: return std::make_shared<IR::Imul>(op0, op1);
					case IR::binary_op::shl: return std::make_shared<IR::Shl>(op0, op1);
					case IR::binary_op::shr: return std::make_shared<IR::Shr>(op0, op1);
					case IR::binary_op::rcr: return std::make_shared<IR::Rcr>(op0, op1);
					case IR::binary_op::rcl: return std::make_shared<IR::Rcl>(op0, op1);
					case IR::binary_op::rol: return std::make_shared<IR::Rol>(op0, op1);
					case IR::binary_op::ror: return std::make_shared<IR::Ror>(op0, op1);
					case IR::binary_op::and_: return std::make_shared<IR::And>(op0, op1);
					case IR::binary_op::or_: return std::make_shared<IR::Or>(op0, op1);
					case IR::binary_op::xor_: return std::make_shared<IR::Xor>(op0, op1);
					case IR::binary_op::cmp: return std::make_shared<IR::Cmp>(op0, op1);
					case IR::binary_op::test: return std::make_shared<IR::Test>(op0, op1);
					default:
						break;
				}
			}
			default:
			{
				throw std::runtime_error("make_copy unexpected expression type");
			}
		}
	}
}