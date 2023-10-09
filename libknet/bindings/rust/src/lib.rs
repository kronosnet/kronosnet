// Copyright (C) 2021-2023 Red Hat, Inc.  All rights reserved.
//
// Authors: Christine Caulfield <ccaulfie@redhat.com>
//
// This software licensed under LGPL-2.0+
//

//! This crate provides access to the kronosnet library 'libknet'
//! from Rust. They are a fairly thin layer around the actual API calls but with Rust data types
//! and iterators.
//!
//! No more information about knet itself will be provided here, it is expected that if
//! you feel you need access to the knet API calls, you know what they do :)
//!
//! # Example
//! ```
//! use knet_bindings::knet_bindings as knet;
//! use std::net::{SocketAddr, IpAddr, Ipv4Addr};
//! use std::thread::spawn;
//! use std::sync::mpsc::Receiver;
//! use std::sync::mpsc::channel;
//! use std::io::{Result, ErrorKind, Error};
//! use std::{thread, time};
//!
//! const CHANNEL: i8 = 1;
//!
//! pub fn main() -> Result<()>
//! {
//!     let host_id = knet::HostId::new(1);
//!     let other_host_id = knet::HostId::new(2);
//!
//!     let (log_sender, log_receiver) = channel::<knet::LogMsg>();
//!     spawn(move || logging_thread(log_receiver));
//!
//!     let knet_handle = match knet::handle_new(&our_hostid, Some(log_sender),
//!                                              knet::LogLevel::Debug, knet::HandleFlags::NONE) {
//!         Ok(h) => h,
//!         Err(e) => {
//!             return Err(e);
//!         }
//!     };
//!
//!     if let Err(e) = knet::host_add(knet_handle, &other_hostid) {
//!         return Err(e);
//!     }
//!     if let Err(e) = knet::link_set_config(knet_handle, &other_hostid, 0,
//!                                 knet::TransportId::Udp,
//!                                 &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000+(our_hostid.to_u16())),
//!                                 &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000+(other_hostid.to_u16())),
//!                                 knet::LinkFlags::NONE) {
//!         return Err(e);
//!     }
//!     if let Err(e) = knet::handle_add_datafd(knet_handle, 0, CHANNEL) {
//!         return Err(e);
//!     }
//!
//!     if let Err(e) = knet::handle_crypto_rx_clear_traffic(knet_handle, knet::RxClearTraffic::Allow) {
//!         return Err(e);
//!     }
//!
//!     if let Err(e) = knet::link_set_enable(knet_handle, &other_hostid, 0, true) {
//!         return Err(e);
//!     }
//!
//!     if let Err(e) = knet::handle_setfwd(knet_handle, true) {
//!         return Err(e);
//!     }
//!
//!     Ok()
//! }
//!


mod sys;
pub mod knet_bindings;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate bitflags;

use std::os::raw::c_char;
use std::ptr::copy_nonoverlapping;
use std::ffi::CString;
use std::io::{Error, Result, ErrorKind};


// Quick & dirty u8 to boolean
fn u8_to_bool(val: u8) -> bool
{
    val != 0
}

fn u32_to_bool(val: u32) -> bool
{
    val != 0
}

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
