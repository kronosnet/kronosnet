// Copyright (C) 2021-2023 Red Hat, Inc.  All rights reserved.
//
// Authors: Christine Caulfield <ccaulfie@redhat.com>
//
// This software licensed under LGPL-2.0+
//

//! This crate provides access to the kronosnet libraries libknet and libnozzle
//! from Rust. They are a fairly thin layer around the actual API calls but with Rust data types
//! and iterators.
//!
//! No more information about knet itself will be provided here, it is expected that if
//! you feel you need access to the knet API calls, you know what they do :)
//!
//! # Example
//! ```
//! use nozzle_bindings::nozzle_bindings as nozzle;
//! use std::io::{Result};
//! use std::env;
//! use std::{thread, time};
//!
//! fn main() -> Result<()>
//! {
//!     let mut nozzle_name = String::from("rustnoz");
//!     let handle = match nozzle::open(&mut nozzle_name,  &String::from(env::current_dir().unwrap().to_str().unwrap())) {
//!         Ok(h) => {
//!             println!("Opened device {}", nozzle_name);
//!             h
//!         },
//!         Err(e) => {
//!             println!("Error from open: {}", e);
//!             return Err(e);
//!         }
//!     };
//!
//!     let if Err(e) = nozzle::add_ip(handle, &"192.160.100.1".to_string(), &"24".to_string()) {
//!         println!("Error from add_ip: {}", e);
//!         return Err(e);
//!     }
//!
//!     let if Err(e) = nozzle::set_mtu(handle, 157) {
//!         println!("Error from set_mtu: {}", e);
//!         return Err(e);
//!     }
//!
//!     Ok(())
//! }


mod sys;
pub mod nozzle_bindings;

use std::os::raw::c_char;
use std::ptr::copy_nonoverlapping;
use std::ffi::CString;
use std::io::{Error, Result, ErrorKind};

// General internal routine to copy bytes from a C array into a Rust String
fn string_from_bytes(bytes: *const ::std::os::raw::c_char, max_length: usize) -> Result<String>
{
    let mut newbytes = vec![0u8; max_length];

    // Get length of the string in old-fashioned style
    let mut length: usize = 0;
    let mut count = 0;
    let mut tmpbytes = bytes;
    while count < max_length || length == 0 {
	if unsafe {*tmpbytes} == 0 && length == 0 {
	    length = count;
	    break;
	}
	count += 1;
	tmpbytes = unsafe { tmpbytes.offset(1) }
    }

    // Cope with an empty string
    if length == 0 {
	return Ok(String::new());
    }

    unsafe {
	// We need to fully copy it, not shallow copy it.
	// Messy casting on both parts of the copy here to get it to work on both signed
	// and unsigned char machines
	copy_nonoverlapping(bytes as *mut i8, newbytes.as_mut_ptr() as *mut i8, length);
    }


    let cs = CString::new(&newbytes[0..length])?;

    // This is just to convert the error type
    match cs.into_string() {
	Ok(s) => Ok(s),
	Err(_) => Err(Error::new(ErrorKind::Other, "Cannot convert to String")),
    }
}

// As below but always returns a string even if there was an error doing the conversion
fn string_from_bytes_safe(bytes: *const ::std::os::raw::c_char, max_length: usize) -> String
{
    match string_from_bytes(bytes, max_length) {
	Ok(s) => s,
	Err(_)=> "".to_string()
    }
}

fn string_to_bytes(s: &str, bytes: &mut [c_char]) -> Result<()>
{
    let c_name = match CString::new(s) {
	Ok(n) => n,
	Err(_) => return Err(Error::new(ErrorKind::Other, "Rust conversion error")),
    };

    if c_name.as_bytes().len() > bytes.len() {
	return Err(Error::new(ErrorKind::Other, "String too long"));
    }

    unsafe {
	// NOTE param order is 'wrong-way round' from C
	copy_nonoverlapping(c_name.as_ptr(), bytes.as_mut_ptr(), c_name.as_bytes().len());
    }
    Ok(())
}
