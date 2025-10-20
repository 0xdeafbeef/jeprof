use anyhow::Result;
use aya::maps::stack_trace::StackTrace;
use blazesym::symbolize::{
    source::{Process, Source},
    Input, Symbolized,
};
use blazesym::Pid;
use std::num::NonZeroU32;

pub trait SymbolResolver {
    fn resolve_stacktrace(&self, stacktrace: &StackTrace, pid: u32) -> Result<ResolvedStackTrace>;
}

pub struct BlazeResolver {
    symbolizer: blazesym::symbolize::Symbolizer,
}

impl BlazeResolver {
    pub fn new() -> Self {
        Self {
            symbolizer: blazesym::symbolize::Symbolizer::new(),
        }
    }
}

impl Default for BlazeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolResolver for BlazeResolver {
    fn resolve_stacktrace(&self, stacktrace: &StackTrace, pid: u32) -> Result<ResolvedStackTrace> {
        let pid = Pid::Pid(NonZeroU32::new(pid).unwrap());
        let frames: Vec<_> = stacktrace.frames().iter().map(|f| f.ip).collect();
        let frames = Input::AbsAddr(frames.as_slice());
        let resolved = self
            .symbolizer
            .symbolize(&Source::Process(Process::new(pid)), frames)?
            .into_iter()
            .map(|symbol| match symbol {
                Symbolized::Sym(sym) => FrameSymbol {
                    address: sym.addr,
                    symbol: sym.name.to_string(),
                },
                Symbolized::Unknown(reason) => FrameSymbol {
                    address: 0,
                    symbol: reason.to_string(),
                },
            })
            .collect();

        Ok(ResolvedStackTrace { symbols: resolved })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedStackTrace {
    pub symbols: Vec<FrameSymbol>,
}

impl ResolvedStackTrace {
    pub fn as_inferno_line(&self, weight: u64) -> String {
        let mut stack = self
            .symbols
            .iter()
            .map(|frame| frame.symbol.clone())
            .collect::<Vec<_>>()
            .join(";");
        stack.push(' ');
        stack.push_str(&format!("{weight}"));
        stack
    }
}

#[derive(Debug, Clone)]
pub struct FrameSymbol {
    pub address: u64,
    pub symbol: String,
}
