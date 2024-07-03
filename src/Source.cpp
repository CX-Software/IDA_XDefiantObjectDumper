#include "Header.h"

bool handle_object_name( const ea_t object_name_ea, qstring& qsObjectName ) {

	auto len = get_max_strlit_length( object_name_ea, STRTYPE_C, ALOPT_ONLYTERM );

	auto ssz = get_strlit_contents( &qsObjectName, object_name_ea, len, STRTYPE_C );

	if ( qsObjectName.empty()) {

		return false;
	}

	return true;
}

ea_t get_nested_virtual_method( ea_t ea_start )
{
	auto resolved_ea = get_64bit( ea_start );

	if ( resolved_ea ) {

		resolved_ea += 0x58; // into virtual table

		resolved_ea = get_64bit( resolved_ea );

		if ( resolved_ea ) {

			auto pFunc = get_func( resolved_ea );
			if ( pFunc ) {

				const auto searchString2 = "48 ? ? ? ? ? ? 66";

				resolved_ea = find_binary( pFunc->start_ea, pFunc->end_ea, searchString2, get_default_radix(), SEARCH_DOWN );

				if ( resolved_ea != BADADDR ) {
					insn_t insn;

					decode_insn( &insn, resolved_ea );

					resolved_ea = insn.ops[1].addr;

					resolved_ea += 0x78; // into virtual table

					resolved_ea = get_64bit( resolved_ea );

					return resolved_ea;
				}
			}
		}
	}

	return BADADDR;
}

bool run_plugin() {

	segment_t* base_seg = get_segm_by_name( ".text" );

	const auto searchString = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8D 05 ? ? ? ? 48 8B FA 48 89 01 48 8B D9";

	ea_t xref_to_call_array[20000]{};
	int found = 0;

	ea_t ea_insn = find_binary( base_seg->start_ea, base_seg->end_ea, searchString, get_default_radix(), SEARCH_DOWN );

	if ( ea_insn == BADADDR64 )
		return false;

	func_t* fn = get_func( ea_insn );

	if ( fn ) {

		xrefblk_t xr;
		xr = { 0 };
		for ( bool success = xr.first_to( (ea_t)fn->start_ea, XREF_FAR ); success; success = xr.next_to() ) {
			if ( xr.iscode == 0 ) {
				break;
			}

			xref_to_call_array[found++] = xr.from;
		}
	}

	LOG( "Found %i xrefs to fn\n", found );

	for ( int i = 0; i < found; i++ ) {

		auto chunk_start_ea = xref_to_call_array[i], 
			chunk_end_ea = xref_to_call_array[i] + 0x48;

		auto range = chunk_end_ea - chunk_start_ea;

		idafn_t ifn;

		ifn.load_func_block( chunk_start_ea, chunk_end_ea - chunk_start_ea );

		bool bfoundins = false;

		while ( ifn.decode_next_insn() ) {

			if ( ifn.decodedInsn.itype == NN_mov ) {

				insn_t nextInsn;

				if ( ifn.peek_next_insn( nextInsn ) && nextInsn.itype == NN_mov ) {

					ea_t resolved_ea = nextInsn.ops[0].addr;

					resolved_ea = get_nested_virtual_method( resolved_ea );

					if ( resolved_ea != BADADDR ) {
						ifn.decode_next_insn();
						if ( ifn.decode_next_insn() && ifn.peek_next_insn( nextInsn ) &&
							nextInsn.itype == NN_lea ) {

							ea_t ea_object_name; qstring qs_object_name;
							if ( resolve_op_value( nextInsn, ea_object_name ) ) {

								handle_object_name( ea_object_name, qs_object_name );

								set_name( resolved_ea, qs_object_name.c_str(), SN_PUBLIC | SN_FORCE );

								LOG( "%s = %llX\n", qs_object_name.c_str(), resolved_ea );
							}

							else {

								LOG( "Unk_%llX at %llX\n", resolved_ea, resolved_ea );
							}
						}


					}
				}
			}
		}
	}

	return true;
}

//IDA plugin exports
plugmod_t* _stdcall IDAP_init( void ) {

	msg( "Initializing IDA XDF Object Finder...\nBeluga © 2024\n\n" );

	return PLUGIN_KEEP;
}

void _stdcall IDAP_term( void ) {
	//Cleanup...
}

bool _stdcall IDAP_run( size_t arg ) {

	LOG( "Begin object scan...\n" );

	DWORD scanStartTick = GetTickCount64();

	run_plugin();

	DWORD scanTimeTakenSec = ( GetTickCount64() - scanStartTick ) / 1000;

	msg( "Scan Finished. Time Taken: (approx.) %d Second(s).\n", scanTimeTakenSec );

	PLUGIN.flags |= PLUGIN_UNL;

	return true;
}

const char* IDAP_hotkey = "Ctrl-Q";
const char* IDAP_name = "XDefiant Object Dumper";
const char* IDAP_help = "";
const char* IDAP_comment = "A plugin To locate and dump objects in XDefiant";
plugin_t PLUGIN = { IDP_INTERFACE_VERSION, PLUGIN_UNL, IDAP_init, IDAP_term, IDAP_run, IDAP_comment, IDAP_help, IDAP_name, IDAP_hotkey };
