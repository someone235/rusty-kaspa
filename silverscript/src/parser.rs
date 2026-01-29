use pest::Parser;
use pest::error::Error;
use pest::iterators::Pairs;
use pest_derive::Parser;
use solang_parser::diagnostics::Diagnostic as SolidityDiagnostic;
use solang_parser::pt::{Comment as SolidityComment, SourceUnit as SoliditySourceUnit};

#[derive(Parser)]
#[grammar = "cashscript.pest"]
pub struct CashScriptParser;

pub fn parse_source_file(input: &str) -> Result<Pairs<Rule>, Error<Rule>> {
    CashScriptParser::parse(Rule::source_file, input)
}

pub fn parse_expression(input: &str) -> Result<Pairs<Rule>, Error<Rule>> {
    CashScriptParser::parse(Rule::expression, input)
}

#[derive(Debug)]
pub struct SolidityParseResult {
    pub source_unit: SoliditySourceUnit,
    pub comments: Vec<SolidityComment>,
}

pub fn parse_solidity_source(input: &str) -> Result<SolidityParseResult, Vec<SolidityDiagnostic>> {
    solang_parser::parse(input, 0)
        .map(|(source_unit, comments)| SolidityParseResult { source_unit, comments })
        .map_err(|diagnostics| diagnostics)
}
