#pragma once

namespace hash
{
	template <uint64_t FnvPrime, uint64_t OffsetBasis>
	struct basic_fnv_1
	{
		uint64_t operator()(std::string const& text) const
		{
			uint64_t hash = OffsetBasis;
			auto str = text.c_str();
			auto len = strlen(str);

			for (int i = 0; i < len; i++)
			{
				hash *= FnvPrime;
				hash ^= tolower(str[i]);
			}

			return hash;
		}
	};

	template <uint64_t FnvPrime, uint64_t OffsetBasis>
	struct basic_fnv_1a
	{
		uint64_t operator()(std::string const& text) const
		{
			uint64_t hash = OffsetBasis;
			for (std::string::const_iterator it = text.begin(), end = text.end();
				it != end; ++it)
			{
				hash ^= tolower(*it);
				hash *= FnvPrime;
			}

			return hash;
		}
	};

	// For 32 bit machines:
	//const std::size_t fnv_prime = 16777619u;
	//const std::size_t fnv_offset_basis = 2166136261u;

	// For 64 bit machines:

	const uint64_t fnv_prime = 1099511628211u;
	const uint64_t fnv_offset_basis = 14695981039346656037u;

	// For 128 bit machines:
	// const std::size_t fnv_prime = 309485009821345068724781401u;
	// const std::size_t fnv_offset_basis =
	//     275519064689413815358837431229664493455u;

	// For 256 bit machines:
	// const std::size_t fnv_prime =
	//     374144419156711147060143317175368453031918731002211u;
	// const std::size_t fnv_offset_basis =
	//     100029257958052580907070968620625704837092796014241193945225284501741471925557u;

	typedef basic_fnv_1<fnv_prime, fnv_offset_basis> fnv_1;
	typedef basic_fnv_1a<fnv_prime, fnv_offset_basis> fnv_1a;
}