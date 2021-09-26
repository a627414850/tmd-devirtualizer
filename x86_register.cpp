#include "pch.h"

#include "x86_register.hpp"

x86_register::x86_register(xed_reg_enum_t xed_reg) : m_xed_reg(xed_reg)
{
}
x86_register::~x86_register()
{
}

bool x86_register::is_gpr() const
{
	return this->get_class() == XED_REG_CLASS_GPR;
}
bool x86_register::is_low_gpr() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_CL:
		case XED_REG_DL:
		case XED_REG_BL:
		case XED_REG_SPL:
		case XED_REG_BPL:
		case XED_REG_SIL:
		case XED_REG_DIL:
			return true;

		case XED_REG_AH:
		case XED_REG_CH:
		case XED_REG_DH:
		case XED_REG_BH:
			return false;

		default:
		{
			throw std::invalid_argument(__FUNCTION__);
		}
	}
}
bool x86_register::is_high_gpr() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_CL:
		case XED_REG_DL:
		case XED_REG_BL:
		case XED_REG_SPL:
		case XED_REG_BPL:
		case XED_REG_SIL:
		case XED_REG_DIL:
			return false;

		case XED_REG_AH:
		case XED_REG_CH:
		case XED_REG_DH:
		case XED_REG_BH:
			return true;

		default:
		{
			throw std::invalid_argument(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr8_low() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
		case XED_REG_RAX:
			return XED_REG_AL;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
		case XED_REG_RCX:
			return XED_REG_CL;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
		case XED_REG_RDX:
			return XED_REG_DL;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
		case XED_REG_RBX:
			return XED_REG_BL;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
		case XED_REG_RSP:
			return XED_REG_SPL;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
		case XED_REG_RBP:
			return XED_REG_BPL;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
		case XED_REG_RSI:
			return XED_REG_SIL;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
		case XED_REG_RDI:
			return XED_REG_DIL;

		case XED_REG_R8B:
		case XED_REG_R8W:
		case XED_REG_R8D:
		case XED_REG_R8:
			return XED_REG_R8B;

		case XED_REG_R9B:
		case XED_REG_R9W:
		case XED_REG_R9D:
		case XED_REG_R9:
			return XED_REG_R9B;

		case XED_REG_R10B:
		case XED_REG_R10W:
		case XED_REG_R10D:
		case XED_REG_R10:
			return XED_REG_R10B;

		case XED_REG_R11B:
		case XED_REG_R11W:
		case XED_REG_R11D:
		case XED_REG_R11:
			return XED_REG_R11B;

		case XED_REG_R12B:
		case XED_REG_R12W:
		case XED_REG_R12D:
		case XED_REG_R12:
			return XED_REG_R12B;

		case XED_REG_R13B:
		case XED_REG_R13W:
		case XED_REG_R13D:
		case XED_REG_R13:
			return XED_REG_R13B;

		case XED_REG_R14B:
		case XED_REG_R14W:
		case XED_REG_R14D:
		case XED_REG_R14:
			return XED_REG_R14B;

		case XED_REG_R15B:
		case XED_REG_R15W:
		case XED_REG_R15D:
		case XED_REG_R15:
			return XED_REG_R15B;

		default:
		{
			std::cout << this->get_name() << std::endl;
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr8_high() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
		case XED_REG_RAX:
			return XED_REG_AH;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
		case XED_REG_RCX:
			return XED_REG_CH;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
		case XED_REG_RDX:
			return XED_REG_DH;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
		case XED_REG_RBX:
			return XED_REG_BH;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
		case XED_REG_RSP:
			return XED_REG_INVALID;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
		case XED_REG_RBP:
			return XED_REG_INVALID;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
		case XED_REG_RSI:
			return XED_REG_INVALID;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
		case XED_REG_RDI:
			return XED_REG_INVALID;

		case XED_REG_R8B:
		case XED_REG_R8W:
		case XED_REG_R8D:
		case XED_REG_R8:
			return XED_REG_INVALID;

		case XED_REG_R9B:
		case XED_REG_R9W:
		case XED_REG_R9D:
		case XED_REG_R9:
			return XED_REG_INVALID;

		case XED_REG_R10B:
		case XED_REG_R10W:
		case XED_REG_R10D:
		case XED_REG_R10:
			return XED_REG_INVALID;

		case XED_REG_R11B:
		case XED_REG_R11W:
		case XED_REG_R11D:
		case XED_REG_R11:
			return XED_REG_INVALID;

		case XED_REG_R12B:
		case XED_REG_R12W:
		case XED_REG_R12D:
		case XED_REG_R12:
			return XED_REG_INVALID;

		case XED_REG_R13B:
		case XED_REG_R13W:
		case XED_REG_R13D:
		case XED_REG_R13:
			return XED_REG_INVALID;

		case XED_REG_R14B:
		case XED_REG_R14W:
		case XED_REG_R14D:
		case XED_REG_R14:
			return XED_REG_INVALID;

		case XED_REG_R15B:
		case XED_REG_R15W:
		case XED_REG_R15D:
		case XED_REG_R15:
			return XED_REG_INVALID;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr16() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
		case XED_REG_RAX:
			return XED_REG_AX;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
		case XED_REG_RCX:
			return XED_REG_CX;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
		case XED_REG_RDX:
			return XED_REG_DX;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
		case XED_REG_RBX:
			return XED_REG_BX;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
		case XED_REG_RSP:
			return XED_REG_SP;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
		case XED_REG_RBP:
			return XED_REG_BP;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
		case XED_REG_RSI:
			return XED_REG_SI;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
		case XED_REG_RDI:
			return XED_REG_DI;

		case XED_REG_R8B:
		case XED_REG_R8W:
		case XED_REG_R8D:
		case XED_REG_R8:
			return XED_REG_R8W;

		case XED_REG_R9B:
		case XED_REG_R9W:
		case XED_REG_R9D:
		case XED_REG_R9:
			return XED_REG_R9W;

		case XED_REG_R10B:
		case XED_REG_R10W:
		case XED_REG_R10D:
		case XED_REG_R10:
			return XED_REG_R10W;

		case XED_REG_R11B:
		case XED_REG_R11W:
		case XED_REG_R11D:
		case XED_REG_R11:
			return XED_REG_R11W;

		case XED_REG_R12B:
		case XED_REG_R12W:
		case XED_REG_R12D:
		case XED_REG_R12:
			return XED_REG_R12W;

		case XED_REG_R13B:
		case XED_REG_R13W:
		case XED_REG_R13D:
		case XED_REG_R13:
			return XED_REG_R13W;

		case XED_REG_R14B:
		case XED_REG_R14W:
		case XED_REG_R14D:
		case XED_REG_R14:
			return XED_REG_R14W;

		case XED_REG_R15B:
		case XED_REG_R15W:
		case XED_REG_R15D:
		case XED_REG_R15:
			return XED_REG_R15W;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr32() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
		case XED_REG_RAX:
			return XED_REG_EAX;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
		case XED_REG_RCX:
			return XED_REG_ECX;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
		case XED_REG_RDX:
			return XED_REG_EDX;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
		case XED_REG_RBX:
			return XED_REG_EBX;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
		case XED_REG_RSP:
			return XED_REG_ESP;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
		case XED_REG_RBP:
			return XED_REG_EBP;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
		case XED_REG_RSI:
			return XED_REG_ESI;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
		case XED_REG_RDI:
			return XED_REG_EDI;

		case XED_REG_R8B:
		case XED_REG_R8W:
		case XED_REG_R8D:
		case XED_REG_R8:
			return XED_REG_R8D;

		case XED_REG_R9B:
		case XED_REG_R9W:
		case XED_REG_R9D:
		case XED_REG_R9:
			return XED_REG_R9D;

		case XED_REG_R10B:
		case XED_REG_R10W:
		case XED_REG_R10D:
		case XED_REG_R10:
			return XED_REG_R10D;

		case XED_REG_R11B:
		case XED_REG_R11W:
		case XED_REG_R11D:
		case XED_REG_R11:
			return XED_REG_R11D;

		case XED_REG_R12B:
		case XED_REG_R12W:
		case XED_REG_R12D:
		case XED_REG_R12:
			return XED_REG_R12D;

		case XED_REG_R13B:
		case XED_REG_R13W:
		case XED_REG_R13D:
		case XED_REG_R13:
			return XED_REG_R13D;

		case XED_REG_R14B:
		case XED_REG_R14W:
		case XED_REG_R14D:
		case XED_REG_R14:
			return XED_REG_R14D;

		case XED_REG_R15B:
		case XED_REG_R15W:
		case XED_REG_R15D:
		case XED_REG_R15:
			return XED_REG_R15D;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}
x86_register x86_register::get_gpr64() const
{
	switch (this->m_xed_reg)
	{
		case XED_REG_AL:
		case XED_REG_AH:
		case XED_REG_AX:
		case XED_REG_EAX:
		case XED_REG_RAX:
			return XED_REG_RAX;

		case XED_REG_CL:
		case XED_REG_CH:
		case XED_REG_CX:
		case XED_REG_ECX:
		case XED_REG_RCX:
			return XED_REG_RCX;

		case XED_REG_DL:
		case XED_REG_DH:
		case XED_REG_DX:
		case XED_REG_EDX:
		case XED_REG_RDX:
			return XED_REG_RDX;

		case XED_REG_BL:
		case XED_REG_BH:
		case XED_REG_BX:
		case XED_REG_EBX:
		case XED_REG_RBX:
			return XED_REG_RBX;

		case XED_REG_SPL:
		case XED_REG_SP:
		case XED_REG_ESP:
		case XED_REG_RSP:
			return XED_REG_RSP;

		case XED_REG_BPL:
		case XED_REG_BP:
		case XED_REG_EBP:
		case XED_REG_RBP:
			return XED_REG_RBP;

		case XED_REG_SIL:
		case XED_REG_SI:
		case XED_REG_ESI:
		case XED_REG_RSI:
			return XED_REG_RSI;

		case XED_REG_DIL:
		case XED_REG_DI:
		case XED_REG_EDI:
		case XED_REG_RDI:
			return XED_REG_RDI;

		case XED_REG_R8B:
		case XED_REG_R8W:
		case XED_REG_R8D:
		case XED_REG_R8:
			return XED_REG_R8;

		case XED_REG_R9B:
		case XED_REG_R9W:
		case XED_REG_R9D:
		case XED_REG_R9:
			return XED_REG_R9;

		case XED_REG_R10B:
		case XED_REG_R10W:
		case XED_REG_R10D:
		case XED_REG_R10:
			return XED_REG_R10;

		case XED_REG_R11B:
		case XED_REG_R11W:
		case XED_REG_R11D:
		case XED_REG_R11:
			return XED_REG_R11;

		case XED_REG_R12B:
		case XED_REG_R12W:
		case XED_REG_R12D:
		case XED_REG_R12:
			return XED_REG_R12;

		case XED_REG_R13B:
		case XED_REG_R13W:
		case XED_REG_R13D:
		case XED_REG_R13:
			return XED_REG_R13;

		case XED_REG_R14B:
		case XED_REG_R14W:
		case XED_REG_R14D:
		case XED_REG_R14:
			return XED_REG_R14;

		case XED_REG_R15B:
		case XED_REG_R15W:
		case XED_REG_R15D:
		case XED_REG_R15:
			return XED_REG_R15;

		default:
		{
			throw std::runtime_error(__FUNCTION__);
		}
	}
}

bool x86_register::is_pseudo() const
{
	return (XED_REG_PSEUDO_FIRST <= this->m_xed_reg && this->m_xed_reg <= XED_REG_PSEUDO_LAST)
		|| xed_reg_enum_t_last() <= this->m_xed_reg;
}
bool x86_register::is_flag() const
{
	return XED_REG_FLAGS_FIRST <= this->m_xed_reg && this->m_xed_reg <= XED_REG_FLAGS_LAST;
}