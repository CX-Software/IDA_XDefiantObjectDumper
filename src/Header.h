#pragma once

#include <windows.h>
#include <stdio.h>
#include <fstream>
#include <vector>
#include <string>

#include <ida.hpp>
#include <idp.hpp>

#include <xref.hpp>
#include <loader.hpp>
#include <allins.hpp>
#include <search.hpp>
#include <xref.hpp>

#include <dbg.hpp>

#include <bytes.hpp>
#include <nalt.hpp>
#include <name.hpp>

#include "Logger.h"

static bool z80_get_reg_info(
	const char** main_regname,
	bitrange_t* bitrange,
	const char* regname )
{
	// Sanity checks.
	if ( regname == NULL || regname[0] == '\0' )
		return false;

	static const char* const subregs[][3] =
	{
	  { "af",  "a",  "f"  },
	  { "bc",  "b",  "c"  },
	  { "de",  "d",  "e"  },
	  { "hl",  "h",  "l"  },
	  { "af'", "a'", "f'" },
	  { "bc'", "b'", "c'" },
	  { "de'", "d'", "e'" },
	  { "hl'", "h'", "l'" },
	  { "ix",  NULL, NULL },
	  { "iy",  NULL, NULL },
	  { "sp",  NULL, NULL },
	  { "pc",  NULL, NULL },
	};

	// Check if we are dealing with paired or single registers and return
	// the appropriate information.
	for ( size_t i = 0; i < qnumber( subregs ); i++ ) {
		for ( size_t j = 0; j < 3; j++ ) {
			if ( subregs[i][j] == NULL )
				break;
			if ( strieq( regname, subregs[i][j] ) ) {
				if ( main_regname != NULL )
					*main_regname = subregs[i][0];
				if ( bitrange != NULL ) {
					switch ( j ) {
					case 0: *bitrange = bitrange_t( 0, 16 ); break;
					case 1: *bitrange = bitrange_t( 8, 8 ); break;
					case 2: *bitrange = bitrange_t( 0, 8 ); break;
					}
				}
				return true;
			}
		}
	}

	return false;
}

static sval_t named_regval(
	const char* regname )
{
	// Get register info.
	const char* main_regname;
	bitrange_t bitrange;
	if ( !z80_get_reg_info( &main_regname, &bitrange, regname ) )
		return 0;
	regval_t rv;
	// Get main register value and apply bitrange.
	if ( !get_reg_val( main_regname, &rv ) )
		return 0;
	auto ret = rv.ival;
	ret >>= bitrange.bitoff();
	ret &= ( 1ULL << bitrange.bitsize() ) - 1;
	return ret;
}

static sval_t regval(
	const op_t& op )
{
	// Check for bad register number.
	if ( op.reg > ph.regs_num )
		return 0;
	return named_regval( ph.reg_names[op.reg] );
}

static bool resolve_op_value(const insn_t& decodedInsn, uint64& resolved )
{
	// Get operand value (possibly an ea).
	uint64 v = 0;
	const op_t& op = decodedInsn.ops[0].type != o_reg ? decodedInsn.ops[0] : decodedInsn.ops[1];

	//LOG("type %i\n", op.type);

	switch ( op.type ) {
	case o_reg:
	case o_phrase:
		v = regval( op );
		break;
	case o_mem:
	case o_near:
		v = op.addr;
		break;
	case o_void:
	case o_displ:
		// Memory references using register and address value.
		v = regval( op ) + op.value + op.addr;
		if ( v < inf.min_ea )
			v += inf.min_ea - 0x1000;
		break;
	case o_imm:
		// Immediates are stored in op.value.
		v = op.value;
		break;

	default:
	{
		LOG( "unknown insn (%d)\n", op.type );
		return false;
	}
	}

	resolved = v;

	return true;
}

static ea_t resolve_op_ea(const insn_t & decodedInsn) {

	ea_t result = BADADDR64;

	resolve_op_value(decodedInsn, result);

	return result;
}

struct idafn_t
{
	ea_t fnaddr;
	func_t* pfn;
	range_t areafnl;
	size_t fnsize;
	insn_t decodedInsn;
	ea_t eaToDecode;

	__forceinline bool is_valid()
	{
		return pfn != NULL;
	};

	__forceinline void goto_func()
	{
		jumpto(areafnl.start_ea);
	};

	__forceinline void load_func_block(ea_t addr, size_t range)
	{
		fnaddr = addr;	
		areafnl.start_ea = addr;
		areafnl.end_ea = addr + range;
		fnsize = areafnl.end_ea - areafnl.start_ea;
		eaToDecode = fnaddr;
	};


	__forceinline void load_func(ea_t addr)
	{
		//fnaddr = addr;
		pfn = get_func(addr);
		
		auto rs = rangeset_t(areafnl);
		bool fnlim = get_func_ranges(&rs, pfn);

		if (!fnlim)
			find_func_bounds(pfn, FIND_FUNC_NORMAL);

		fnaddr = fnlim ? areafnl.start_ea : pfn->start_ea;
		fnsize = fnlim ? areafnl.end_ea - areafnl.start_ea : pfn->size();
		eaToDecode = fnlim ? pfn->start_ea : BADADDR;
	};

	__forceinline bool decode_next_insn()
	{
		if (eaToDecode == BADADDR)
		{
			return false;
		}
		if (eaToDecode >= areafnl.end_ea)
		{
			return false;
		}

		insn_t insn;
		decode_insn(&insn, eaToDecode);
		eaToDecode += insn.size;
		memcpy(&decodedInsn, &insn, sizeof(insn_t));
		return true;
	};

	__forceinline bool peek_next_insn(insn_t & nextInsn)
	{
		if ( eaToDecode == BADADDR ) {
			return false;
		}
		if ( eaToDecode >= areafnl.end_ea ) {
			return false;
		}

		insn_t insn;
		decode_insn( &insn, eaToDecode );

		nextInsn = insn;

		return true;
	};

	ea_t find_pattern(int* asmPat, size_t asmCount) const
	{
		/*
		finds an asm pattern
		asm patterns differ a little from byte patterns, as they only compare each sequential asm instruction and not every byte
		no wildcard support

		for ex:
		.text:00C0F518                 mov     ecx, ds:off_1451598[edi]
		.text:00C0F51E                 add     edi, 8
		.text:00C0F521                 add     esp, 4
		.text:00C0F524                 mov     [ecx], eax
		.text:00C0F526                 mov     [esp+14h+var_4], edi
		.text:00C0F52A                 cmp     edi, 4960h
		.text:00C0F530                 jb      loc_C0F480
		.text:00C0F536                 pop     edi
		.text:00C0F537                 pop     esi
		.text:00C0F538                 pop     ebp
		.text:00C0F539                 pop     ebx
		.text:00C0F53A                 pop     ecx
		.text:00C0F53B                 retn

		in this case to get the pointer, the asm pattern would be...
		{ NN_mov, NN_add, NN_add, NN_mov, NN_mov, NN_cmp }
		*/

		size_t asmPatIdx = 0;
		size_t asmPatSize = 0;
		uint16 cmdSize = 0;

		for (ea_t i = pfn->start_ea; i <  pfn->end_ea; i += cmdSize)
		{
			insn_t instn;
			decode_insn(&instn, i);
			cmdSize = instn.size;

			if (instn.itype != asmPat[asmPatIdx])
			{
				asmPatIdx = 0;
				asmPatSize = 0;
			}

			else
			{
				++asmPatIdx;
				asmPatSize += cmdSize;
			}	

			if (asmPatIdx >= asmCount)
			{
				return instn.ea + instn.size - asmPatSize;
			}
		}

		return BADADDR;
	};
};

struct SFilePathA
{
	char szPath[_MAX_PATH];
	char szDrive[_MAX_DRIVE];
	char szDir[_MAX_DIR];
	char szName[_MAX_FNAME];
	char szExt[_MAX_EXT];

	__forceinline void init_file(const char* file)
	{
		strcpy_s(szPath, file);
		_splitpath_s(szPath, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, szName, _MAX_FNAME, szExt, _MAX_EXT);
	};

	__forceinline void init_module(const char* name)
	{
		char modfile[MAX_PATH];
		GetModuleFileNameA(GetModuleHandleA(name), modfile, MAX_PATH);
		init_file(modfile);
	};
};

struct SFilePathW
{
	wchar_t szPath[_MAX_PATH];
	wchar_t szDrive[_MAX_DRIVE];
	wchar_t szDir[_MAX_DIR];
	wchar_t szName[_MAX_FNAME];
	wchar_t szExt[_MAX_EXT];

	__forceinline void init_file(const wchar_t* file)
	{
		wcscpy_s(szPath, file);
		_wsplitpath_s(szPath, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, szName, _MAX_FNAME, szExt, _MAX_EXT);
	};

	__forceinline void init_module(const wchar_t* name)
	{
		wchar_t modfile[MAX_PATH];
		GetModuleFileNameW(GetModuleHandleW(name), modfile, MAX_PATH);
		init_file(modfile);
	};
};

#ifdef _UNICODE
#define SFilePath SFilePathW
#else
#define SFilePath SFilePathA
#endif
