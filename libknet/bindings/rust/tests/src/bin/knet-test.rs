// Testing the Knet Rust APIs
//
// Copyright (C) 2021-2024 Red Hat, Inc.
//
// All rights reserved.
//
// Author: Christine Caulfield (ccaulfi@redhat.com)
//

use knet_bindings::knet_bindings as knet;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::thread::spawn;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::channel;
use std::io::{Result, ErrorKind, Error};
use std::{thread, time};
use std::env;

const CHANNEL: i8 = 1;

// Dirty C function to set the plugin path for testing (only)
extern {
    fn set_plugin_path(knet_h: u64);
}

fn is_memcheck() -> bool
{
    match env::var("KNETMEMCHECK") {
	Ok(s) => {
	    s == "yes"
	}
	Err(_) => false
    }
}

// Probably this will never happen, but just-in-case
fn is_helgrind() -> bool
{
    match env::var("KNETHELGRIND") {
	Ok(s) => {
	    s == "yes"
	}
	Err(_) => false
    }
}

fn get_scaled_tmo(millis: u64) -> time::Duration
{
    if is_memcheck() || is_helgrind() {
	println!("Running under valgrind, increasing timer from {} to {}", millis, millis*16);
	time::Duration::from_millis(millis * 16)
    } else {
	time::Duration::from_millis(millis)
    }
}

// Callbacks
fn sock_notify_fn(private_data: u64,
		  datafd: i32,
		  channel: i8,
		  txrx: knet::TxRx,
		  _res: Result<()>)
{
    println!("sock notify called for host {private_data}, datafd: {datafd}, channel: {channel}, {txrx}");
}


fn link_notify_fn(private_data: u64,
		  host_id: knet::HostId,
		  link_id: u8,
		  connected: bool,
		  _remote: bool,
		  _external: bool)
{
    println!("link status notify called ({}) for host {}, linkid: {}, connected: {}",
	     private_data, host_id.to_u16(), link_id, connected);
}

fn host_notify_fn(private_data: u64,
		  host_id: knet::HostId,
		  connected: bool,
		  _remote: bool,
		  _external: bool)
{
    println!("host status notify called ({}) for host {}, connected: {}",
	     private_data, host_id.to_u16(), connected);
}

fn pmtud_fn(private_data: u64, data_mtu: u32) {
    println!("PMTUD notify: host {private_data}, MTU:{data_mtu} ");
}

fn onwire_fn(private_data: u64,
	     onwire_min_ver: u8,
	     onwire_max_ver: u8,
	     onwire_ver: u8) {
    println!("Onwire ver notify for {private_data} : {onwire_min_ver}/{onwire_max_ver}/{onwire_ver}");
}

fn filter_fn(private_data: u64,
	     _outdata: &[u8],
	     txrx: knet::TxRx,
	     this_host_id: knet::HostId,
	     src_host_id: knet::HostId,
	     channel: &mut i8,
	     dst_host_ids: &mut Vec<knet::HostId>) -> knet::FilterDecision
{
    println!("Filter ({private_data}) called {txrx} to {this_host_id} from {src_host_id}, channel: {channel}");

    let dst: u16 = (private_data & 0xFFFF) as u16;

    match txrx {
	knet::TxRx::Tx => {
	    dst_host_ids.push(knet::HostId::new(3-dst));
	    knet::FilterDecision::Unicast
	}
	knet::TxRx::Rx => {
	    dst_host_ids.push(this_host_id);
	    knet::FilterDecision::Unicast
	}
    }
}

fn logging_thread(recvr: Receiver<knet::LogMsg>)
{
    for i in &recvr {
	eprintln!("KNET: {}", i.msg);
    }
    eprintln!("Logging thread finished");
}

fn setup_node(our_hostid: &knet::HostId, other_hostid: &knet::HostId, name: &str) -> Result<knet::Handle>
{
    let (log_sender, log_receiver) = channel::<knet::LogMsg>();
    spawn(move || logging_thread(log_receiver));

    let knet_handle = match knet::handle_new(our_hostid, Some(log_sender),
					     knet::LogLevel::Debug, knet::HandleFlags::NONE) {
	Ok(h) => h,
	Err(e) => {
	    println!("Error from handle_new: {e}");
	    return Err(e);
	}
    };

    // Make sure we use the build-tree plugins if LD_LIBRRAY_PATH points to them
    unsafe {
	set_plugin_path(knet_handle.knet_handle);
    }

    if let Err(e) = knet::host_add(&knet_handle, other_hostid) {
	println!("Error from host_add: {e}");
	return Err(e);
    }
    if let Err(e) = knet::host_set_name(&knet_handle, other_hostid, name) {
	println!("Error from host_set_name: {e}");
	return Err(e);
    }

    Ok(knet_handle)
}

// Called by the ACL tests to get a free port for a dynamic link
fn setup_dynamic_link(handle: &knet::Handle, hostid: &knet::HostId, link: u8,
		      lowest_port: u16) -> Result<()>
{
    let mut src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    for p in lowest_port..=65535 {
	src_addr.set_port(p);

	if let Err(e) = knet::link_set_config(handle, hostid, link,
					      knet::TransportId::Udp,
					      &src_addr,
					      None,
					      knet::LinkFlags::NONE) {
	    if let Some(os_err) = e.raw_os_error() {
		if os_err != libc::EADDRINUSE {
		    println!("Error from link_set_config(dyn): {e}");
		    return Err(e);
		}
		// In use - try the next port number
	    }
	} else {
	    println!("Dynamic link - Using port {p}");
	    return Ok(())
	}
    }
    Err(Error::new(ErrorKind::Other, "No ports available"))
}

// This is the bit that configures two links on two handles that talk to each other
// while also making sure they don't clash with anything else on the system
fn setup_links(handle1: &knet::Handle, hostid1: &knet::HostId,
	       handle2: &knet::Handle, hostid2: &knet::HostId) -> Result<u16>
{
    let mut src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let mut dst_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    for p in 1025..=65534 {
	src_addr.set_port(p);
	dst_addr.set_port(p+1);

	if let Err(e) = knet::link_set_config(handle1, hostid2, 0,
					      knet::TransportId::Udp,
					      &src_addr,
					      Some(&dst_addr),
					      knet::LinkFlags::NONE) {
	    if let Some(os_err) = e.raw_os_error() {
		if os_err != libc::EADDRINUSE {
		    println!("Error from link_set_config(1): {e}");
		    return Err(e);
		}
		// In use - try the next port number
	    } else {
		return Err(Error::new(ErrorKind::Other, "Error returned from link_set_config(1) was not an os_error"));
	    }
	} else {
	    // Now try the other handle
	    if let Err(e) = knet::link_set_config(handle2, hostid1, 0,
						  knet::TransportId::Udp,
						  &dst_addr,
						  Some(&src_addr),
						  knet::LinkFlags::NONE) {
		if let Some(os_err) = e.raw_os_error() {
		    if os_err != libc::EADDRINUSE {
			println!("Error from link_set_config(2): {e}");
			return Err(e);
		    } else {
			// In use - clear handle1 and try next pair of ports
			knet::link_clear_config(handle1, hostid2, 0)?;
		    }
		} else {
		    return Err(Error::new(ErrorKind::Other, "Error returned from link_set_config(1) was not an os_error"));
		}
	    }
	    println!("Bound to ports {} & {}",p, p+1);
	    return Ok(p+2)
	}
    }
    Err(Error::new(ErrorKind::Other, "No ports available"))
}

// Finish configuring links
fn configure_link(knet_handle: &knet::Handle, our_hostid: &knet::HostId, other_hostid: &knet::HostId) -> Result<()>
{
    if let Err(e) = knet::handle_enable_sock_notify(knet_handle, our_hostid.to_u16() as u64, Some(sock_notify_fn)) {
	println!("Error from handle_enable_sock_notify: {e}");
	return Err(e);
    }

    if let Err(e) = knet::link_enable_status_change_notify(knet_handle, our_hostid.to_u16() as u64, Some(link_notify_fn)) {
	println!("Error from handle_enable_link_notify: {e}");
	return Err(e);
    }
    if let Err(e) = knet::host_enable_status_change_notify(knet_handle, our_hostid.to_u16() as u64, Some(host_notify_fn)) {
	println!("Error from handle_enable_host_notify: {e}");
	return Err(e);
    }
    if let Err(e) = knet::handle_enable_filter(knet_handle, our_hostid.to_u16() as u64, Some(filter_fn)) {
	println!("Error from handle_enable_filter: {e}");
	return Err(e);
    }

    if let Err(e) = knet::handle_enable_pmtud_notify(knet_handle, our_hostid.to_u16() as u64, Some(pmtud_fn)) {
	println!("Error from handle_enable_pmtud_notify: {e}");
	return Err(e);
    }
    if let Err(e) = knet::handle_enable_onwire_ver_notify(knet_handle, our_hostid.to_u16() as u64, Some(onwire_fn)) {
	println!("Error from handle_enable_onwire_ver_notify: {e}");
	return Err(e);
    }
    match knet::handle_add_datafd(knet_handle, 0, CHANNEL) {
	Ok((fd,chan)) => {
	    println!("Added datafd, fd={fd}, channel={chan}");
	},
	Err(e) => {
	    println!("Error from add_datafd: {e}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::handle_crypto_rx_clear_traffic(knet_handle, knet::RxClearTraffic::Allow) {
	println!("Error from handle_crypto_rx_clear_traffic: {e}");
	return Err(e);
    }

    if let Err(e) = knet::link_set_enable(knet_handle, other_hostid, 0, true) {
	println!("Error from set_link_enable(true): {e}");
	return Err(e);
    }

    if let Err(e) = knet::link_set_ping_timers(knet_handle, other_hostid, 0,
					       500, 1000, 1024) {
	println!("Error from set_link_ping_timers: {e}");
	return Err(e);
    }

    match knet::link_get_ping_timers(knet_handle, other_hostid, 0) {
	Ok((a,b,c)) => {
	    if a != 500 || b != 1000 || c != 1024 {
		println!("get_link_ping_timers returned wrong values {a}, {b},{c} (s/b 500,1000,1024)");
		return Err(Error::new(ErrorKind::Other, "Error in ping timers"));
	    }
	},
	Err(e) => {
	    println!("Error from set_link_ping_timers: {e}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::handle_setfwd(knet_handle, true) {
	println!("Error from setfwd(true): {e}");
	return Err(e);
    }

    // Check status
    let data_fd =
    match knet::handle_get_datafd(knet_handle, CHANNEL) {
	Ok(f) => {
	    println!("got datafd {f} for channel");
	    f
	}
	Err(e) => {
	    println!("Error from handle_get_datafd: {e}");
	    return Err(e);
	}
    };
    match knet::handle_get_channel(knet_handle, data_fd) {
	Ok(c) =>
	    if c != CHANNEL {
		println!("handle_get_channel returned wrong channel ID: {c}, {CHANNEL}");
		return Err(Error::new(ErrorKind::Other, "Error in handle_get_channel"));
	    }
	Err(e) => {
	    println!("Error from handle_get_channel: {e}");
	    return Err(e);
	}
    }

    match knet::link_get_enable(knet_handle, other_hostid, 0) {
	Ok(b) => if !b {
	    println!("link not enabled (according to link_get_enable()");
	},
	Err(e) => {
	    println!("Error from link_get_enable: {e}");
	    return Err(e);
	}
    }

    Ok(())
}

fn recv_stuff(handle: &knet::Handle, host: knet::HostId) -> Result<()>
{
    let buf = [0u8; 1024];

    loop {
	match knet::recv(handle, &buf, CHANNEL) {
	    Ok(len) => {
		let recv_len = len as usize;
		if recv_len == 0 {
		    break; // EOF??
		} else {
		    let s = String::from_utf8(buf[0..recv_len].to_vec()).unwrap();
		    println!("recvd on {}: {} {:?}  {} ", host, recv_len, &buf[0..recv_len], s);
		    if s == *"QUIT" {
			println!("got QUIT on {host}, exitting");
			break;
		    }
		}
	    }
	    Err(e) => {
		if e.kind() == ErrorKind::WouldBlock {
		    thread::sleep(get_scaled_tmo(100));
		} else {
		    println!("recv failed: {e}");
		    return Err(e);
		}
	    }
	}
    }
    Ok(())
}


fn close_handle(handle: &knet::Handle, remnode: u16) -> Result<()>
{
    let other_hostid = knet::HostId::new(remnode);

    if let Err(e) = knet::handle_setfwd(handle, false) {
	println!("Error from setfwd 1 (false): {e}");
	return Err(e);
    }

    let data_fd =
    match knet::handle_get_datafd(handle, CHANNEL) {
	Ok(f) => {
	    println!("got datafd {f} for channel");
	    f
	}
	Err(e) => {
	    println!("Error from handle_get_datafd: {e}");
	    return Err(e);
	}
    };
    if let Err(e) = knet::handle_remove_datafd(handle, data_fd) {
	println!("Error from handle_remove_datafd: {e}");
	return Err(e);
    }

    if let Err(e) = knet::link_set_enable(handle, &other_hostid, 0, false) {
	println!("Error from set_link_enable(false): {e}");
	return Err(e);
    }

    if let Err(e) = knet::link_clear_config(handle, &other_hostid, 0) {
	println!("clear config failed: {e}");
	return Err(e);
    }

    if let Err(e) = knet::host_remove(handle, &other_hostid) {
	println!("host remove failed: {e}");
	return Err(e);
    }

    if let Err(e) = knet::handle_free(handle) {
	println!("handle_free failed: {e}");
	return Err(e);
    }
    Ok(())
}


fn set_compress(handle: &knet::Handle) -> Result<()>
{
    let compress_config = knet::CompressConfig {
	compress_model: "zlib".to_string(),
	compress_threshold : 10,
	compress_level: 1,
    };
    if let Err(e) = knet::handle_compress(handle, &compress_config) {
	println!("Error from handle_compress: {e}");
	Err(e)
    } else {
	Ok(())
    }
}

fn set_crypto(handle: &knet::Handle) -> Result<()>
{
    let private_key = [55u8; 2048];

    // Add some crypto
    let crypto_config = knet::CryptoConfig {
	crypto_model: "openssl".to_string(),
	crypto_cipher_type: "aes256".to_string(),
	crypto_hash_type: "sha256".to_string(),
	private_key: &private_key,
    };

    if let Err(e) = knet::handle_crypto_set_config(handle, &crypto_config, 1) {
	println!("Error from handle_crypto_set_config: {e}");
	return Err(e);
    }

    if let Err(e) = knet::handle_crypto_use_config(handle, 1) {
	println!("Error from handle_crypto_use_config: {e}");
	return Err(e);
    }

    if let Err(e) = knet::handle_crypto_rx_clear_traffic(handle, knet::RxClearTraffic::Disallow) {
	println!("Error from handle_crypto_rx_clear_traffic: {e}");
	return Err(e);
    }
    Ok(())
}


fn send_messages(handle: &knet::Handle, send_quit: bool) -> Result<()>
{
    let mut buf : [u8; 20] = [b'0'; 20];
    for i in 0..10 {
	buf[i as usize + 1] = i + b'0';
	match knet::send(handle, &buf, CHANNEL) {
	    Ok(len) => {
		if len as usize != buf.len() {
		    println!("sent {} bytes instead of {}", len, buf.len());
		}
	    },
	    Err(e) => {
		println!("send failed: {e}");
		return Err(e);
	    }
	}
    }

    let s = String::from("SYNC TEST").into_bytes();
    if let Err(e) = knet::send_sync(handle, &s, CHANNEL) {
	println!("send_sync failed: {e}");
	return Err(e);
    }

    if send_quit {
	// Sleep to allow messages to calm down before we tell the RX thread to quit
	thread::sleep(get_scaled_tmo(3000));

	let b = String::from("QUIT").into_bytes();
	match knet::send(handle, &b, CHANNEL) {
	    Ok(len) => {
		if len as usize != b.len() {
		    println!("sent {} bytes instead of {}", len, b.len());
		}
	    },
	    Err(e) => {
		println!("send failed: {e}");
		return Err(e);
	    }
	}
    }
    Ok(())
}

fn test_link_host_list(handle: &knet::Handle) -> Result<()>
{
    match knet::host_get_host_list(handle) {
	Ok(hosts) => {
	    for i in &hosts {
		print!("host {i}: links: ");
		match knet::link_get_link_list(handle, i) {
		    Ok(ll) => {
			for j in ll {
			    print!(" {j}");
			}
		    },
		    Err(e) => {
			println!("link_get_link_list failed: {e}");
			return Err(e);
		    }
		}
		println!();
	    }
	}
	Err(e) => {
	    println!("link_get_host_list failed: {e}");
	    return Err(e);
	}
    }
    Ok(())
}

// Try some metadata calls
fn test_metadata_calls(handle: &knet::Handle, host: &knet::HostId) -> Result<()>
{
    if let Err(e) = knet::handle_set_threads_timer_res(handle, 190000) {
	println!("knet_handle_set_threads_timer_res failed: {e:?}");
	return Err(e);
    }
    match knet::handle_get_threads_timer_res(handle) {
	Ok(v) => {
	    if v != 190000 {
		println!("knet_handle_get_threads_timer_res returned wrong value {v}");
	    }
	},
	Err(e) => {
	    println!("knet_handle_set_threads_timer_res failed: {e:?}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::handle_pmtud_set(handle, 1000) {
	println!("knet_handle_pmtud_set failed: {e:?}");
	return Err(e);
    }
    match knet::handle_pmtud_get(handle) {
	Ok(v) => {
	    if v != 1000 {
		println!("knet_handle_pmtud_get returned wrong value {v} (ALLOWED)");
		// Don't fail on this, it might not have been set yet
	    }
	},
	Err(e) => {
	    println!("knet_handle_pmtud_get failed: {e:?}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::handle_pmtud_setfreq(handle, 1000) {
	println!("knet_handle_pmtud_setfreq failed: {e:?}");
	return Err(e);
    }
    match knet::handle_pmtud_getfreq(handle) {
	Ok(v) => {
	    if v != 1000 {
		println!("knet_handle_pmtud_getfreq returned wrong value {v}");
	    }
	},
	Err(e) => {
	    println!("knet_handle_pmtud_getfreq failed: {e:?}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::handle_set_transport_reconnect_interval(handle, 100) {
	println!("knet_handle_set_transport_reconnect_interval failed: {e:?}");
	return Err(e);
    }
    match knet::handle_get_transport_reconnect_interval(handle) {
	Ok(v) => {
	    if v != 100 {
		println!("knet_handle_get_transport_reconnect_interval {v}");
	    }
	},
	Err(e) => {
	    println!("knet_handle_get_transport_reconnect_interval failed: {e:?}");
	    return Err(e);
	}
    }


    if let Err(e) = knet::link_set_pong_count(handle, host, 0, 4) {
	println!("knet_link_set_pong_count failed: {e:?}");
	return Err(e);
    }
    match knet::link_get_pong_count(handle, host, 0) {
	Ok(v) => {
	    if v != 4 {
		println!("knet_link_get_pong_count returned wrong value {v}");
	    }
	},
	Err(e) => {
	    println!("knet_link_get_pong_count failed: {e:?}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::host_set_policy(handle, host, knet::LinkPolicy::Active) {
	println!("knet_host_set_policy failed: {e:?}");
	return Err(e);
    }
    match knet::host_get_policy(handle, host) {
	Ok(v) => {
	    if v != knet::LinkPolicy::Active {
		println!("knet_host_get_policy returned wrong value {v}");
	    }
	},
	Err(e) => {
	    println!("knet_host_get_policy failed: {e:?}");
	    return Err(e);
	}
    }


    if let Err(e) = knet::link_set_priority(handle, host, 0, 5) {
	println!("knet_link_set_priority failed: {e:?}");
	return Err(e);
    }
    match knet::link_get_priority(handle, host, 0) {
	Ok(v) => {
	    if v != 5 {
		println!("knet_link_get_priority returned wrong value {v}");
	    }
	},
	Err(e) => {
	    println!("knet_link_get_priority failed: {e:?}");
	    return Err(e);
	}
    }

    let name = match knet::host_get_name_by_host_id(handle, host) {
	Ok(n) => {
	    println!("Returned host name is {n}");
	    n
	},
	Err(e) => {
	    println!("knet_host_get_name_by_host_id failed: {e:?}");
	    return Err(e);
	}
    };
    match knet::host_get_id_by_host_name(handle, &name) {
	Ok(n) => {
	    println!("Returned host id is {n}");
	    if n != *host {
		println!("Returned host id is not 2");
		return Err(Error::new(ErrorKind::Other, "Error in get_id_by_host_name"));
	    }
	},
	Err(e) => {
	    println!("knet_host_get_id_by_host_name failed: {e:?}");
	    return Err(e);
	}
    }

    match knet::link_get_config(handle, host, 0) {
	Ok((t, s, d, _f)) => {
	    println!("Got link config: {}, {:?}, {:?}", t.to_string(),s,d);
	},
	Err(e) => {
	    println!("knet_link_get_config failed: {e:?}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::handle_set_host_defrag_bufs(handle, 4, 32, 25, knet::DefragReclaimPolicy::Absolute) {
	println!("handle_config_set_host_defrag_bufs failed: {e:?}");
	return Err(e);
    }
    match knet::handle_get_host_defrag_bufs(handle) {
	Ok((min, max, shrink, policy)) => {
	    if min != 4 || max != 32 ||
		shrink != 25 || policy != knet::DefragReclaimPolicy::Absolute {
		    println!("handle_config_get_host_defrag_bufs returned bad values");
		    println!("Got {min},{max},{shrink},{policy}. expected 4,32,2,Absolute");
		} else {
		    println!("Defrag params correct: {min},{max},{shrink},{policy}");
		}
	}
	Err(e) => {
	    println!("handle_config_get_host_defrag_bufs failed: {e:?}");
	    return Err(e);
	}
    }



    // Can't set this to anything different
    if let Err(e) = knet::handle_set_onwire_ver(handle, 1) {
	println!("knet_link_set_onwire_ver failed: {e:?}");
	return Err(e);
    }

    match knet::handle_get_onwire_ver(handle, host) {
	Ok((min, max, ver)) => {
	    println!("get_onwire_ver: Got onwire ver: {min}/{max}/{ver}");
	},
	Err(e) => {
	    println!("knet_link_get_onwire_ver failed: {e:?}");
	    return Err(e);
	}
    }

    // Logging
    match knet::log_get_subsystem_name(3) {
	Ok(n) => println!("subsystem name for 3 is {n}"),
	Err(e) => {
	    println!("knet_log_get_subsystem_name failed: {e:?}");
	    return Err(e);
	}
    }
    match knet::log_get_subsystem_id("TX") {
	Ok(n) => println!("subsystem ID for TX is {n}"),
	Err(e) => {
	    println!("knet_log_get_subsystem_id failed: {e:?}");
	    return Err(e);
	}
    }
    match knet::log_get_loglevel_id("DEBUG") {
	Ok(n) => println!("loglevel ID for DEBUG is {n}"),
	Err(e) => {
	    println!("knet_log_get_loglevel_id failed: {e:?}");
	    return Err(e);
	}
    }

    match knet::log_get_loglevel_id("TRACE") {
	Ok(n) => println!("loglevel ID for TRACE is {n}"),
	Err(e) => {
	    println!("knet_log_get_loglevel_id (Trace) failed: {e:?}");
	    return Err(e);
	}
    }

    match knet::log_get_loglevel_name(1) {
	Ok(n) => println!("loglevel name for 1 is {n}"),
	Err(e) => {
	    println!("knet_log_get_loglevel_name failed: {e:?}");
	    return Err(e);
	}
    }

    if let Err(e) = knet::log_set_loglevel(handle, knet::SubSystem::Handle , knet::LogLevel::Debug) {
	println!("knet_log_set_loglevel failed: {e:?}");
	return Err(e);
    }
    match knet::log_get_loglevel(handle, knet::SubSystem::Handle) {
	Ok(n) => println!("loglevel for Handle is {n}"),
	Err(e) => {
	    println!("knet_log_get_loglevel failed: {e:?}");
	    return Err(e);
	}
    }

    Ok(())
}


fn test_acl(handle: &knet::Handle, host: &knet::HostId, low_port: u16) -> Result<()>
{
    if let Err(e) = knet::handle_enable_access_lists(handle, true) {
	println!("Error from handle_enable_access_lists: {e:?}");
	return Err(e);
    }

    // Dynamic link for testing ACL APIs (it never gets used)
    if let Err(e) = setup_dynamic_link(handle, host, 1, low_port) {
	println!("Error from link_set_config (dynamic): {e}");
	return Err(e);
    }

    // These ACLs are nonsense on stilts
    if let Err(e) = knet::link_add_acl(handle, host, 1,
				       &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8003_u16),
				       &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8003_u16),
				       knet::AclCheckType::Address, knet::AclAcceptReject::Reject) {
	println!("Error from link_add_acl: {e:?}");
	return Err(e);
    }
    if let Err(e) = knet::link_insert_acl(handle, host, 1,
					  0,
					  &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8004_u16),
					  &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 8004_u16),
					  knet::AclCheckType::Address, knet::AclAcceptReject::Reject) {
	println!("Error from link_add_acl: {e:?}");
	return Err(e);
    }
    if let Err(e) = knet::link_rm_acl(handle, host, 1,
				      &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8003_u16),
				      &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8003_u16),
				      knet::AclCheckType::Address, knet::AclAcceptReject::Reject) {
	println!("Error from link_rm_acl: {e:?}");
	return Err(e);
    }
    if let Err(e) = knet::link_clear_acl(handle, host, 1) {
	println!("Error from link_clear_acl: {e:?}");
	return Err(e);
    }

    // Get rid of this link before it messes things up
    if let Err(e) = knet::link_clear_config(handle, host, 1) {
	println!("clear config (dynamic) failed: {e}");
	return Err(e);
    }

    if let Err(e) = knet::handle_enable_access_lists(handle, false) {
	println!("Error from handle_enable_access_lists: {e:?}");
	return Err(e);
    }
    Ok(())
}

fn main() -> Result<()>
{
    // Start with some non-handle information
    match knet::get_crypto_list() {
	Ok(l) => {
	    print!("Crypto models:");
	    for i in &l {
		print!(" {}", i.name);
	    }
	    println!();
	}
	Err(e) => {
	    println!("link_get_crypto_list failed: {e:?}");
	    return Err(e);
	}
    }

    match knet::get_compress_list() {
	Ok(l) => {
	    print!("Compress models:");
	    for i in &l {
		print!(" {}", i.name);
	    }
	    println!();
	}
	Err(e) => {
	    println!("link_get_compress_list failed: {e:?}");
	    return Err(e);
	}
    }

    match knet::get_transport_list() {
	Ok(l) => {
	    print!("Transports:");
	    for i in &l {
		print!(" {}", i.name);
	    }
	    println!();
	}
	Err(e) => {
	    println!("link_get_transport_list failed: {e:?}");
	    return Err(e);
	}
    }
    let host1 = knet::HostId::new(1);
    let host2 = knet::HostId::new(2);

    // Now test traffic
    let handle1 = setup_node(&host1, &host2, "host2")?;
    let handle2 = setup_node(&host2, &host1, "host1")?;
    let low_port = setup_links(&handle1, &host1, &handle2, &host2)?;
    configure_link(&handle1, &host1, &host2)?;
    configure_link(&handle2, &host2, &host1)?;

    // Copy stuff for the threads
    let handle1_clone = handle1.clone();
    let handle2_clone = handle2.clone();
    let host1_clone = host1;
    let host2_clone = host2;

    // Wait for links to start
    thread::sleep(get_scaled_tmo(10000));
    test_link_host_list(&handle1)?;
    test_link_host_list(&handle2)?;

    // Start recv threads for each handle
    let thread_handles = vec![
	spawn(move || recv_stuff(&handle1_clone, host1_clone)),
	spawn(move || recv_stuff(&handle2_clone, host2_clone))
    ];

    send_messages(&handle1, false)?;
    send_messages(&handle2, false)?;
    thread::sleep(get_scaled_tmo(3000));

    set_crypto(&handle1)?;
    set_crypto(&handle2)?;

    set_compress(&handle1)?;
    set_compress(&handle2)?;

    thread::sleep(get_scaled_tmo(3000));

    send_messages(&handle1, true)?;
    send_messages(&handle2, true)?;

    test_acl(&handle1, &host2, low_port)?;

    // Wait for recv threads to finish
    for handle in thread_handles {
        if let Err(error) = handle.join() {
            println!("thread join error: {error:?}");
	}
    }

    // Try some statses
    match knet::handle_get_stats(&handle1) {
	Ok(s) => println!("handle stats: {s}"),
	Err(e) => {
	    println!("handle_get_stats failed: {e:?}");
	    return Err(e);
	}
    }
    match knet::host_get_status(&handle1, &host2) {
	Ok(s) => println!("host status: {s}"),
	Err(e) => {
	    println!("host_get_status failed: {e:?}");
	    return Err(e);
	}
    }
    match knet::link_get_status(&handle1, &host2, 0) {
	Ok(s) => println!("link status: {s}"),
	Err(e) => {
	    println!("link_get_status failed: {e:?}");
	    return Err(e);
	}
    }
    if let Err(e) = knet::handle_clear_stats(&handle1, knet::ClearStats::Handle) {
	println!("handle_clear_stats failed: {e:?}");
	return Err(e);
    }

    test_metadata_calls(&handle1, &knet::HostId::new(2))?;

    close_handle(&handle1, 2)?;
    close_handle(&handle2, 1)?;

    // Sleep to see if log thread dies
    thread::sleep(get_scaled_tmo(3000));
    Ok(())
}
