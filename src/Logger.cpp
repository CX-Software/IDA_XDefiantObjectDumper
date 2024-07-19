#include "Header.h"

namespace Utility {
	HMODULE ourModuleHandle;

	HMODULE GetOurModuleHandle() {

		if ( !ourModuleHandle ) {
			GetModuleHandleExA( GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
				reinterpret_cast<LPCSTR>( &GetOurModuleHandle ),
				&ourModuleHandle );
		}

		return ourModuleHandle;
	}

	const std::string GetRunningExecutableFolder() {

		const auto hModule = GetOurModuleHandle();

		char inBuf[MAX_PATH];

		ZeroMemory( inBuf, MAX_PATH );

		GetModuleFileNameA( hModule, inBuf, MAX_PATH );

		auto str = std::string( inBuf );

		auto seperator = str.find_last_of( "\\" );

		if ( seperator != std::string::npos )
			seperator += 1;

		return str.substr( 0, seperator );

	}

	Logger::Logger() {

		//Remove();
	}

	void Logger::Write( int logLevel, const char* format, ... ) const {

		if ( !format || *format == '\0' )
			return;

		char buffer[0x1498];

		va_list va;
		va_start( va, format );
		vsprintf_s( buffer, format, va );
		va_end( va );

		if ( logLevel != 0 ) {

			auto logPath = GetRunningExecutableFolder() + "output.log";

			std::ofstream ofs( logPath, std::ios::app );

			ofs << buffer << std::endl;
			ofs.close();
		}

		if ( logLevel == 1 )
			return;

		msg( buffer );

		OutputDebugStringA( buffer );
	}

	void Logger::Remove() const {

		auto logPath = GetRunningExecutableFolder() + "\\output.log";


		remove( logPath.c_str() );
	}

	Logger::~Logger() {

	}
}
