use pest::error::Error;
use pest::iterators::Pairs;
use pest::Parser;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "cashscript.pest"]
pub struct CashScriptParser;

pub fn parse_source_file(input: &str) -> Result<Pairs<Rule>, Error<Rule>> {
    CashScriptParser::parse(Rule::source_file, input)
}

pub fn parse_expression(input: &str) -> Result<Pairs<Rule>, Error<Rule>> {
    CashScriptParser::parse(Rule::expression, input)
}
