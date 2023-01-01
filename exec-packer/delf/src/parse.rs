#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(full_input: parse::Input) -> parse::Result<Self> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };

                let (i, val) = $number_parser(full_input)?;
                match Self::try_from(val) {
                    Ok(val) => Ok((i, val)),
                    Err(_) => Err(nom::Err::Failure(parse::Error::from_string(
                        full_input,
                        format!("Unknown {} {} (0x{:x})", stringify!($type), val, val),
                    )))
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_bit_enum {
    ($type: ident, $bits: expr) => {
        impl $type {
            pub fn parse(full_input: parse::BitInput) -> parse::BitResult<Self> {
                use nom::bits::complete::take;

                let (i, val): (_, u8) = take($bits)(full_input)?;
                match Self::try_from(val) {
                    Ok(val) => Ok((i, val)),
                    Err(_) => Err(nom::Err::Failure(parse::Error::from_string(
                        full_input,
                        format!("Unknown {} {} (0x{:x})", stringify!($type), val, val),
                    ))),
                }
            }
        }
    }
}

#[macro_export]
macro_rules! impl_parse_for_enumflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: parse::Input) -> parse::Result<enumflags2::BitFlags<Self>> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };
                let parser = map_res($number_parser, |x| {
                    enumflags2::BitFlags::<Self>::from_bits(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Nom(nom::error::ErrorKind),
    Context(&'static str),
    String(String),
}

pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

use std::fmt;

impl fmt::Debug for Error<&[u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (input, err) in &self.errors {
            writeln!(f, "{:?}:", err)?;
            writeln!(f, "input: {:?}", crate::HexDump(input))?;
        }
        Ok(())
    }
}

impl<I> Error<I> {
    pub fn from_string<S: Into<String>>(input: I, s: S) -> Self {
        let errors = vec![(input, ErrorKind::String(s.into()))];
        Self { errors } 
    }
}

impl<I, E> nom::error::FromExternalError<I, E> for Error<I> {
    fn from_external_error(input: I, kind: nom::error::ErrorKind, e: E) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }
}

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, Error<Input<'a>>>;

pub type BitInput<'a> = (&'a [u8], usize);
pub type BitResult<'a, O> = nom::IResult<BitInput<'a>, O, Error<BitInput<'a>>>;

use nom::{ErrorConvert, Slice};
use std::ops::RangeFrom;

impl<I> ErrorConvert<Error<I>> for Error<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> Error<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();
        Error { errors }
    }
}

use nom::error::ParseError;

impl<I> ParseError<I> for Error<I> {
    fn from_error_kind(i: I, e: nom::error::ErrorKind) -> Self {
        let errors = vec![(i, ErrorKind::Nom(e))];
        Self { errors } 
    }

    fn append(i: I, f: nom::error::ErrorKind, mut k: Self) -> Self {
        k.errors.push((i, ErrorKind::Nom(f)));
        k
    }
}

use nom::error::ContextError;

impl ContextError<&[u8]> for Error<&[u8]> {
    
}
