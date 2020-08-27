/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <test/tools/ossfuzz/SolidityBaseVisitor.h>

#include <libsolutil/Whiskers.h>

#include <random>

namespace solidity::test::fuzzer {
	using RandomEngine = std::mt19937_64;

	struct Generator {
		std::string operator()(std::string&& _template, std::map<std::string, std::string>&& _args);
	};

	class SolidityMutator: public SolidityBaseVisitor
	{
	public:
		SolidityMutator(unsigned int _seed): Rand(_seed) {}
		std::string toString()
		{
			return Out.str();
		}

		antlrcpp::Any visitPragmaDirective(SolidityParser::PragmaDirectiveContext* _ctx) override;
		antlrcpp::Any visitImportDirective(SolidityParser::ImportDirectiveContext* _ctx) override;
		antlrcpp::Any visitContractDefinition(SolidityParser::ContractDefinitionContext* _ctx) override;
		antlrcpp::Any visitContractBodyElement(SolidityParser::ContractBodyElementContext* _ctx) override;
		antlrcpp::Any visitConstructorDefinition(SolidityParser::ConstructorDefinitionContext* _ctx) override;
		antlrcpp::Any visitParameterList(SolidityParser::ParameterListContext* _ctx) override;
		antlrcpp::Any visitParameterDeclaration(SolidityParser::ParameterDeclarationContext* _ctx) override;
		antlrcpp::Any visitBlock(SolidityParser::BlockContext* _ctx) override;
		antlrcpp::Any visitFunctionDefinition(SolidityParser::FunctionDefinitionContext* _ctx) override;
		antlrcpp::Any visitEnumDefinition(SolidityParser::EnumDefinitionContext* _ctx) override;
		antlrcpp::Any visitStructDefinition(SolidityParser::StructDefinitionContext* _ctx) override;
		antlrcpp::Any visitEventDefinition(SolidityParser::EventDefinitionContext* _ctx) override;
		antlrcpp::Any visitEventParameter(SolidityParser::EventParameterContext* _ctx) override;
		antlrcpp::Any visitSourceUnit(SolidityParser::SourceUnitContext* _ctx) override;
		antlrcpp::Any visitInterfaceDefinition(SolidityParser::InterfaceDefinitionContext* _ctx) override;
		antlrcpp::Any visitLibraryDefinition(SolidityParser::LibraryDefinitionContext* _ctx) override;
		antlrcpp::Any visitModifierDefinition(SolidityParser::ModifierDefinitionContext* _ctx) override;
		/// Types
		antlrcpp::Any visitTypeName(SolidityParser::TypeNameContext* _ctx) override;
	private:
		enum class Type
		{
			CONTRACT,
			ABSCONTRACT,
			INTERFACE,
			LIBRARY,
			GLOBAL
		};

		bool globalScope()
		{
			return m_type == Type::GLOBAL;
		}

		bool absContractScope()
		{
			return m_type == Type::ABSCONTRACT;
		}

		bool contractScope()
		{
			return m_type == Type::CONTRACT;
		}

		bool libraryScope()
		{
			return m_type == Type::LIBRARY;
		}

		bool interfaceScope()
		{
			return m_type == Type::INTERFACE;
		}

		template <class C>
		antlrcpp::Any genericVisitor(C* _ctx, std::string _ctxName);

		template <typename T>
		void interfaceContractLibraryVisitor(T* _ctx);

		template <typename T>
		void visitItemsOrGenerate(T _container, std::function<void()> _generator);

		template <typename T>
		void visitItemOrGenerate(T _item, std::function<void()> _generator);

		bool likely()
		{
			return Rand() % s_largePrime != 0;
		}

		/// @returns either true or false with roughly the same probability
		bool coinToss()
		{
			return Rand() % 2 == 0;
		}

		/// @returns a pseudo randomly chosen unsigned number between one
		/// and @param _n
		unsigned randOneToN(unsigned _n = 20)
		{
			return Rand() % _n + 1;
		}

		/// @returns a pseudo randomly generated path string of
		/// the form `<name>.sol` where `<name>` is a single
		/// character in the ascii range [A-Z].
		std::string genRandomPath()
		{
			return "\"" + genRandString(1, 'A', 'Z') + ".sol" + "\"";
		}

		/// @returns a pseudo randomly generated identifier that
		/// comprises a single character in the ascii range [a-z].
		std::string genRandomId(std::string _prefix, unsigned _n = 3)
		{
			return _prefix + std::to_string(Rand() % _n);
		}

		template <typename T>
		void genRule(T* _ctx);

		template <typename T>
		void mutateRule(T* _ctx);

		void genContract();

		void genModifier();

		std::string generator(std::function<std::string()> _gen, unsigned _n, std::string _separator, bool _removeDups);

		std::string genImport();

		std::string genFunctionName();

		/// @returns bit width as a string where bit width is a multiple
		/// of 8 and in the range [8, 256].
		std::string bitWidth()
		{
			return std::to_string(randOneToN(32) * 8);
		}

		/// @returns byte width as a string where byte width is in
		/// the range [1, 32].
		std::string byteWidth()
		{
			return std::to_string(randOneToN(32));
		}

		/// @returns a Solidity event parameter as string
		std::string eventParam();

		/// @returns a pseudo randomly chosen elementary Solidity type name
		/// as a string including address payable type if @param _allowAddressPayable
		/// is true (default), excluding otherwise.
		std::string elementaryType(bool _allowAddressPayable = true);

		/// @returns a pseudo randomly chosen Solidity type name as a string.
		std::string typeName();

		/// @returns a pseudo randomly chosen Solidity data location
		std::string dataLocation();

		/// @returns a pseudo randomly chosen Solidity function visibility.
		std::string visibility();

		/// @returns a pseudo randomly chosen Solidity function state mutability.
		std::string mutability();

		/// @returns a pseudo randomly generated user defined
		/// type name that comprises at most @param _numIds identifiers separated
		/// by a period ('.').
		/// Each identifier is at most @param _len characters long each
		/// character being choosen uniformly at random in the character
		/// range between [@param _start, @param _end]
		std::string genRandomUserDefinedTypeName(
			unsigned _numIds = 2,
			unsigned _len = 1,
			char _start = 'a',
			char _end = 'z'
		);


		/// @returns a pseudo randomly generated string of length at most
		/// @param _maxLen characters where each character in the string
		/// is in the ASCII character range between @param _start and
		/// @param _end characters.
		std::string genRandString(unsigned _maxLen, char _start = '!', char _end = '~');

		/// Mutant stream
		std::ostringstream Out;
		/// Random number generator
		RandomEngine Rand;
		/// Flag that indicates if contract constructor has been defined
		bool constructorDefined = false;

		unsigned m_numStructs = 0;
		unsigned m_numFunctions = 0;
		unsigned m_numLibraries = 0;
		unsigned m_numContracts = 0;
		unsigned m_numInterfaces = 0;
		unsigned m_numEnums = 0;
		unsigned m_numModifiers = 0;
		Type m_type = Type::GLOBAL;

		static constexpr unsigned s_maxPragmas = 2;
		static constexpr unsigned s_maxImports = 2;

		static constexpr unsigned s_largePrime = 1009;
		void gen(SolidityParser::PragmaDirectiveContext*);
		std::string mutatePragma();
		template<typename T>
		void fuzzRule(T* _ctx);
		void mutate(SolidityParser::PragmaDirectiveContext*);
		template<typename F, typename... Args>
		auto mayRun(F&& _func, Args&&... _args, unsigned int _n = 101);
		template<typename T, typename F, typename... Args>
		void visitItemsOrGenerate(T _container, F&& _generator, Args&&... _args);
	};
}