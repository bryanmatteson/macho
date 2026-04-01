use std::fmt;

use super::types::{ThinFileOffset, Va};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AddressRange<A: Copy> {
    pub start: A,
    pub size: u64,
}

impl<A: Copy + fmt::Debug + std::ops::Add<u64, Output = A>> AddressRange<A> {
    pub fn new(start: A, size: u64) -> Self {
        Self { start, size }
    }

    pub fn end(&self) -> A {
        self.start + self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl<A: Copy + fmt::Debug + std::ops::Add<u64, Output = A> + PartialOrd> AddressRange<A> {
    pub fn contains(&self, addr: A) -> bool {
        addr >= self.start && addr < self.end()
    }
}

impl<A: Copy + fmt::Debug> fmt::Debug for AddressRange<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddressRange")
            .field("start", &self.start)
            .field("size", &self.size)
            .finish()
    }
}

pub type FileRange = AddressRange<ThinFileOffset>;
pub type VaRange = AddressRange<Va>;
