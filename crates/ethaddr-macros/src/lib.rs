//! Procedural macro for Ethereum address literals.
//!
//! See [`ethaddr`](https://docs.rs/ethaddr/latest/ethaddr/macro.address.html)
//! documentation for more information.

extern crate proc_macro;

mod checksum;
#[allow(dead_code)]
mod hex;

use proc_macro::{Delimiter, Literal, Span, TokenStream, TokenTree};
use std::fmt::Write as _;

#[proc_macro]
pub fn address(input: TokenStream) -> TokenStream {
    match AddressLiteral::generate(input) {
        Ok(address) => address.into_tokens(),
        Err(err) => err.into_tokens(),
    }
}

struct AddressLiteral([u8; 20], String);

impl AddressLiteral {
    fn generate(input: TokenStream) -> Result<Self, CompileError> {
        let input = Input::parse(input)?;

        let bytes = hex::decode(&input.value).map_err(|err| CompileError {
            message: format!("invalid address literal: {err}"),
            // TODO(nlordell): If the `Span` API changes to allow offseting in
            // the future, we can add more details in the case of bad hex
            // character errors.
            span: Some(input.span),
        })?;
        if input.checksum {
            checksum::verify(&bytes, &input.value).map_err(|checksum| {
                let suggestion = if input.value.starts_with("0x") {
                    checksum.as_str()
                } else {
                    checksum.as_str().strip_prefix("0x").unwrap()
                };
                CompileError {
                    message: format!("invalid address checksum; did you mean `{suggestion}`?"),
                    span: Some(input.span),
                }
            })?;
        }

        Ok(Self(bytes, input.crate_name))
    }

    fn into_tokens(self) -> TokenStream {
        let mut buf = String::new();
        write!(buf, "{}::Address(*b\"", self.1).unwrap();
        for byte in self.0 {
            write!(buf, "\\x{byte:02x}").unwrap();
        }
        write!(buf, "\")").unwrap();

        buf.parse().unwrap()
    }
}

struct Input {
    checksum: bool,
    value: String,
    span: Span,
    crate_name: String,
}

impl Input {
    fn parse(input: TokenStream) -> Result<Self, CompileError> {
        let mut result = Input {
            checksum: true,
            value: String::new(),
            span: Span::call_site(),
            crate_name: "::ethaddr".to_string(),
        };
        ParserState::start().input(input, &mut result)?.end()?;

        Ok(result)
    }
}

enum ParserState {
    TildeOrString,
    String,
    CommaOrEof,
    Crate,
    EqualCrateName,
    CrateName,
    Eof,
}

impl ParserState {
    fn start() -> Self {
        Self::TildeOrString
    }

    fn input(self, input: TokenStream, result: &mut Input) -> Result<Self, CompileError> {
        input
            .into_iter()
            .try_fold(self, |state, token| state.next(token, result))
    }

    fn next(self, token: TokenTree, result: &mut Input) -> Result<Self, CompileError> {
        match (&self, &token) {
            // Procedural macros invoked from withing `macro_rules!` expansions
            // may be grouped with a `Ø` delimiter (which allows operator
            // precidence to be preserved).
            //
            // See <https://doc.rust-lang.org/stable/proc_macro/enum.Delimiter.html#variant.None>
            (_, TokenTree::Group(g)) if g.delimiter() == Delimiter::None => {
                self.input(g.stream(), result)
            }

            (Self::TildeOrString, TokenTree::Punct(p)) if p.as_char() == '~' => {
                result.checksum = false;
                Ok(Self::String)
            }
            (Self::TildeOrString | Self::String, TokenTree::Literal(l)) => match parse_string(l) {
                Some(value) => {
                    result.value = value;
                    result.span = token.span();
                    Ok(Self::CommaOrEof)
                }
                None => Err(self.unexpected(Some(token))),
            },

            (Self::CommaOrEof, TokenTree::Punct(p)) if p.as_char() == ',' => Ok(Self::Crate),
            (Self::Crate, TokenTree::Ident(c)) if c.to_string() == "crate" => {
                Ok(Self::EqualCrateName)
            }
            (Self::EqualCrateName, TokenTree::Punct(p)) if p.as_char() == '=' => {
                Ok(Self::CrateName)
            }
            (Self::CrateName, TokenTree::Literal(l)) => match parse_string(l) {
                Some(value) => {
                    result.crate_name = value;
                    Ok(Self::Eof)
                }
                None => Err(self.unexpected(Some(token))),
            },

            _ => Err(self.unexpected(Some(token))),
        }
    }

    fn end(self) -> Result<(), CompileError> {
        match self {
            Self::CommaOrEof | Self::Eof => Ok(()),
            _ => Err(self.unexpected(None)),
        }
    }

    fn unexpected(self, token: Option<TokenTree>) -> CompileError {
        let expected = match self {
            Self::TildeOrString => "`~` or string literal",
            Self::String => "string literal",
            Self::CommaOrEof => "`,` or <eof>",
            Self::Crate => "`crate` identifier",
            Self::EqualCrateName => "`=`",
            Self::CrateName => "crate name string literal",
            Self::Eof => "<eof>",
        };
        let (value, span) = match token {
            Some(TokenTree::Group(g)) => {
                let delim = match g.delimiter() {
                    Delimiter::Parenthesis => "(",
                    Delimiter::Brace => "{",
                    Delimiter::Bracket => "[",
                    Delimiter::None => "Ø",
                };
                (delim.to_string(), Some(g.span_open()))
            }
            Some(t) => (t.to_string(), Some(t.span())),
            None => ("<eof>".to_owned(), None),
        };

        CompileError {
            message: format!("expected {expected} but found `{value}`"),
            span,
        }
    }
}

struct CompileError {
    message: String,
    span: Option<Span>,
}

impl CompileError {
    fn into_tokens(self) -> TokenStream {
        let error = format!("compile_error!({:?})", self.message)
            .parse::<TokenStream>()
            .unwrap();

        match self.span {
            Some(span) => error
                .into_iter()
                .map(|mut token| {
                    token.set_span(span);
                    token
                })
                .collect(),
            None => error,
        }
    }
}

fn parse_string(literal: &Literal) -> Option<String> {
    Some(
        literal
            .to_string()
            .strip_prefix('"')?
            .strip_suffix('"')?
            .to_owned(),
    )
}
