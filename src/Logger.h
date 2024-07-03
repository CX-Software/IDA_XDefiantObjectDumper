#pragma once

#define LOG(x,...) g_logfile.Write(0, x, __VA_ARGS__);

#define LOG(x,...) g_logfile.Write(0, x, __VA_ARGS__);

#define LOG_SILENT(x,...) g_logfile.Write(1, x, __VA_ARGS__);

#define LOG_FATAL(x,...) g_logfile.Write(4, x, __VA_ARGS__);

#define LOG_SERVER(x,...) g_logfile.Write(103, x, __VA_ARGS__);

enum class eLogLevel
{
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_ERRROR,
	LOG_LEVEL_FATAL,
	LOG_LEVEL_SERVER = LOG_LEVEL_FATAL + 100,
};

namespace Utility
{
	class Logger sealed {
	public:
		explicit Logger(std::string filename) {}
		Logger();
		void Write(int logLevel, const char* format, ...) const;
		void Remove() const;
		~Logger();

	};

}

static Utility::Logger g_logfile;