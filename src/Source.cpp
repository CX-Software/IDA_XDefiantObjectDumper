#include "Header.h"

size_t g_num_obj_found = 0;

void sanitize_utf8_string( qstring& string ) {

	int start = 0, end = string.length() - 1;

	while ( end >= 0 && string[end] == ' ' )
		--end;

	while ( start <= end && string[start] == ' ' )
		++start;

	string = string.substr( start, end - start + 1 );
}

bool resolve_utf8_str( const ea_t ea, qstring& outString ) {

	auto len = get_max_strlit_length( ea, STRTYPE_C, ALOPT_ONLYTERM );

	auto ssz = get_strlit_contents( &outString, ea, len, STRTYPE_C );

	if ( outString.empty() )
		return false;

	sanitize_utf8_string( outString );

	return true;
}

ea_t get_nested_virtual_method( ea_t ea_start ) {
    auto resolved_ea = ea_start;

    if ( resolved_ea == BADADDR ) return BADADDR;

    resolved_ea += 0x58; // into virtual table
    resolved_ea = get_64bit( resolved_ea );

    if ( resolved_ea == BADADDR ) return BADADDR;

    auto pFunc = get_func( resolved_ea );
    if ( !pFunc ) return BADADDR;

    idafn_t ifn;
    ifn.load_func_block( pFunc->start_ea, pFunc->end_ea - pFunc->start_ea );

    while ( ifn.decode_next_insn() ) {
        if ( ifn.decodedInsn.itype == NN_jmp ) {
            resolve_op_value( ifn.decodedInsn, resolved_ea );
            LOG( "Resolved nested jmp ( %llX -> %llX ) searching again...\n", ifn.decodedInsn.ea, resolved_ea );
            pFunc = get_func( resolved_ea );
            break;
        }
    }

    if ( !pFunc ) return BADADDR;

    ifn.load_func_block( pFunc->start_ea, pFunc->end_ea - pFunc->start_ea );
    resolved_ea = BADADDR;

    while ( ifn.decode_next_insn() ) {
        if ( ifn.decodedInsn.itype == NN_lea && ifn.decodedInsn.ops[1].type == o_mem ) {
            resolved_ea = ifn.decodedInsn.ea;
        }
    }

    if ( resolved_ea == BADADDR ) return BADADDR;

    insn_t insn;
    decode_insn( &insn, resolved_ea );
    resolved_ea = insn.ops[1].addr;
    resolved_ea += 0x78; // into virtual table
    resolved_ea = get_64bit( resolved_ea );

    return resolved_ea;
}

bool is_address_in_seg( ea_t ea, const char* pchSegmentName ) {

	segment_t* seg = getseg( ea );

	if ( seg == nullptr ) {

		LOG( "early out: no seg! (ea=0x%llX)\n", ea );

		return false;
	}

	qstring seg_name;
	auto ssize = get_segm_name( &seg_name, seg );
	return !seg_name.empty() && seg_name == pchSegmentName;
}

bool run_plugin() {
    segment_t* base_seg = get_segm_by_name( ".text" );
    if ( !base_seg ) return false;

    const auto searchString = "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 20 48 8D 05 ? ? ? ? 48 8B FA 48 89 01 48 8B D9";
    ea_t xref_to_call_array[20000]{};
    int found = 0;

    ea_t ea_insn = find_binary( base_seg->start_ea, base_seg->end_ea, searchString, get_default_radix(), SEARCH_DOWN );
    if ( ea_insn == BADADDR ) return false;

    func_t* fn = get_func( ea_insn );
    if ( !fn ) return false;

    xrefblk_t xr = { 0 };
    for ( bool success = xr.first_to( (ea_t)fn->start_ea, XREF_FAR ); success; success = xr.next_to() ) {
        if ( xr.iscode == 0 ) break;
        xref_to_call_array[found++] = xr.from;
    }

    LOG( "Found %i xrefs to fn\n", found );

    for ( int i = 0; i < found; i++ ) {
        auto chunk_start_ea = xref_to_call_array[i];
        auto chunk_end_ea = chunk_start_ea + 0x48;

        idafn_t ifn;
        ifn.load_func_block( chunk_start_ea, chunk_end_ea - chunk_start_ea );

        while ( ifn.decode_next_insn() ) {
            if ( ifn.decodedInsn.itype != NN_mov ||
                ( ifn.decodedInsn.ops[1].value != 1 &&
                    ( ifn.decodedInsn.ops[1].type != o_reg ||
                        ( ifn.decodedInsn.ops[1].reg != 3 && ifn.decodedInsn.ops[1].reg != 14 ) ) ) ) {
                continue;
            }

            if ( !ifn.decode_next_insn() || ifn.decodedInsn.itype != NN_mov || ifn.decodedInsn.ops[1].type != o_reg ) {
                continue;
            }

            ea_t resolved_func_ea = BADADDR;
            if ( !resolve_op_value( ifn.decodedInsn, resolved_func_ea ) ) {
                LOG( "Can't resolve op value @ %llX\n", ifn.decodedInsn.ea );
                continue;
            }

            if ( !is_address_in_seg( resolved_func_ea, ".data" ) ) {
                LOG( "Address is not in seg! %llX @ %llX\n", resolved_func_ea, ifn.decodedInsn.ea );
                continue;
            }

            bool bFirstItr = true;
            while ( !is_address_in_seg( resolved_func_ea, ".rdata" ) && resolved_func_ea != BADADDR ) {
                resolved_func_ea = get_64bit( resolved_func_ea );
                bFirstItr = false;
            }

            if ( bFirstItr ) continue;

            resolved_func_ea = get_nested_virtual_method( resolved_func_ea );
            if ( resolved_func_ea == BADADDR ) {
                LOG( "Found unusual control flow @ %llX\n", ifn.decodedInsn.ea );
                continue;
            }

            while ( ifn.decode_next_insn() ) {
                if ( ifn.decodedInsn.itype != NN_lea || ifn.decodedInsn.ops[0].type != o_reg || ifn.decodedInsn.ops[0].reg != 0 || ifn.decodedInsn.ops[1].type != o_mem ) {
                    continue;
                }

                ea_t ea_object_name;
                qstring qs_object_name;
                if ( !resolve_op_value( ifn.decodedInsn, ea_object_name ) ) {
                    LOG( "Unk_%llX at %llX\n", resolved_func_ea, resolved_func_ea );
                    break;
                }

                auto pfn = get_func( resolved_func_ea );
                if ( !pfn && !add_func( resolved_func_ea ) ) {
                    LOG( "failed to resolve any function @ %llX\n", resolved_func_ea );
                }

                if ( !resolve_utf8_str( ea_object_name, qs_object_name ) ) {
                    LOG( "failed to resolve function name in .rdata @ %llX ref ea: %llX\n", ea_object_name, chunk_start_ea );
                }

                set_name( resolved_func_ea, qs_object_name.c_str(), SN_NOCHECK | SN_PUBLIC | SN_WEAK | SN_NON_AUTO | SN_DELTAIL | SN_FORCE );
                LOG( "%s = %llX\n", qs_object_name.c_str(), resolved_func_ea );
                g_num_obj_found++;
                break;
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

	g_num_obj_found = 0;

	DWORD scanStartTick = GetTickCount64();

	run_plugin();

	DWORD scanEndTick = GetTickCount64();

	double scanTimeTakenSec = ( scanEndTick - scanStartTick ) / 1000.0;

	msg( "Scan Finished. Renamed %d functions. Time Taken: (approx.) %.3f sec(s).\n", g_num_obj_found, scanTimeTakenSec );

	PLUGIN.flags |= PLUGIN_UNL;

	return true;
}

const char* IDAP_hotkey = "Ctrl-Q";
const char* IDAP_name = "XDefiant Object Dumper";
const char* IDAP_help = "";
const char* IDAP_comment = "A plugin To locate and dump objects in XDefiant";
plugin_t PLUGIN = { IDP_INTERFACE_VERSION, PLUGIN_UNL, IDAP_init, IDAP_term, IDAP_run, IDAP_comment, IDAP_help, IDAP_name, IDAP_hotkey };
