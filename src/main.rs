use std::ffi::{c_char, CStr, OsString};
use core::ffi::c_void;

use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::Foundation::{GetLastError, FARPROC, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use tracing_subscriber::util::SubscriberInitExt;
use windows::core::{s, PCWSTR, Error};
use tracing::{error, info, warn};
use clap::{Parser, ValueHint};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
	/// The name of the target process
	#[arg(required = true)]
	target: OsString,
	/// The path to the DLL file that will be injected
	#[arg(required = true, value_hint = ValueHint::FilePath)]
	dll: OsString,
	/// Enables verbose logging for events
	#[arg(short, long)]
	verbose: bool,
}

fn main() -> Result<(), Error> {
	tracing_subscriber::fmt()
		.without_time()
		.with_ansi(true)
		.finish()
		.init();

	let args = Args::parse();
	
	let mut critical_args = [args.target, args.dll];
	
	for arg in &mut critical_args {
		arg.push("\0")
	}
	
	let dll_name = critical_args[1].clone();
	
	let target_handle = process_enumerate_and_search(
		PCWSTR::from_raw(
			critical_args[0].clone()
				.to_string_lossy()
				.replace('\u{FFFD}', "")
				.encode_utf16()
				.collect::<Vec<u16>>()
				.as_mut_ptr()
		),
		args.verbose
	)?;
	
	inject_dll(
		PCWSTR::from_raw(
			dll_name.clone()
				.to_string_lossy()
				.encode_utf16()
				.collect::<Vec<u16>>()
				.as_ptr()
		),
		dll_name.len() * size_of::<u16>(),
		target_handle
	)?;
	
	Ok(())
}

fn process_enumerate_and_search(process_name: PCWSTR, verbose: bool) -> Result<HANDLE, Error> {
	let mut process_handle: Option<HANDLE> = None;
	let snapshot_handle: HANDLE;
	let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };

	match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, std::mem::zeroed()) } {
		Ok(handle) => snapshot_handle = handle,
		Err(error) => {
			error!("CreateToolhelp32Snapshot failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)
		}
	}

	process_entry.dwSize = size_of_val(&process_entry) as u32;

	if let Err(error) = unsafe { Process32First(snapshot_handle, &mut process_entry) } {
		error!("Process32First failed: {} (Error code: {})", error.message(), error.code());

		return Err(error)
	}

	loop {
		{
			let sz_exe_file = unsafe {
				CStr::from_ptr(process_entry.szExeFile.clone().as_ptr() as *mut c_char)
			};

			if verbose {
				info!("Checking: {sz_exe_file:?}");
			}

			if unsafe { PCWSTR::from_raw({
				let mut str = sz_exe_file
					.to_string_lossy()
					.replace('\u{FFFD}', "");
				
				str.push('\0');
					
				str
					.encode_utf16()
					.collect::<Vec<u16>>()
					.as_ptr()
			}).to_string()?.trim() } == unsafe { process_name.to_string()?.trim() } {
				match unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID) } {
					Ok(handle) => {
						process_handle = Some(handle);

						info!("Opened process with PID {}", process_entry.th32ProcessID);

						break
					}
					Err(error) => {
						error!("OpenProcess failed: {} (Error code: {})", error.message(), error.code());

						return Err(error)
					}
				}
			}
		}

		if unsafe { Process32Next(snapshot_handle, &mut process_entry) }.is_err() {
			error!(
				"The process \"{}\" could not be found",
				unsafe {
					process_name
						.to_string()
						.unwrap_or(String::from("[ERROR GETTING NAME]"))
				}
			);
			warn!("Check if the provided name matches the target process's exactly");

			break
		}
	}

	if process_handle.is_none(){
		error!("Process handle is None");

		return Err(Error::empty())
	} else if process_handle.unwrap().is_invalid() {
		error!("Process handle is invalid: {process_handle:?}");

		return Err(Error::empty())
	}

	Ok(process_handle.unwrap())
}

fn inject_dll(dll_name: PCWSTR, sz_dll_name: usize, target_process_handle: HANDLE) -> Result<(), Error> {
	let module: HMODULE;
	let load_library_handle: FARPROC;
	let thread_handle: HANDLE;
	let mut sz_written_bytes: usize = 0;

	match unsafe { GetModuleHandleA(s!("kernel32.dll")) } {
		Ok(module_handle) => module = module_handle,
		Err(error) => {
			error!("GetModuleHandleA failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)
		}
	}

	match unsafe { GetProcAddress(module, s!("LoadLibraryW")) } {
		Some(process_address) => load_library_handle = Some(process_address),
		None => {
			let error = unsafe { GetLastError().to_hresult() };

			error!("GetProcAddress failed: {} (Error code: {})", error.message(), error.0);

			return error.ok()
		}
	}

	let library_address = unsafe {
		VirtualAllocEx(target_process_handle, None, sz_dll_name, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
	};

	if library_address.is_null() {
		let error = unsafe { GetLastError().to_hresult() };

		error!("VirtualAllocEX failed: {} (Error code: {})", error.message(), error.0);

		return error.ok()
	}

	match unsafe {
		WriteProcessMemory(
			target_process_handle,
			library_address,
			dll_name.as_ptr() as *const c_void,
			sz_dll_name,
			Some(&mut sz_written_bytes)
		)
	} {
		Ok(()) => {}
		Err(error) => {
			error!("WriteProcessMemory failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)
		}
	}

	match unsafe {
		CreateRemoteThread(
			target_process_handle,
			None, 
			0, 
			std::mem::transmute::<FARPROC, LPTHREAD_START_ROUTINE>(load_library_handle),
			Some(library_address),
			0,
			None
		)
	} {
		Ok(handle) => {
			thread_handle = handle;
			
			info!("Created remote thread with handle {:?}", thread_handle)
		}
		Err(error) => {
			error!("CreateRemoteThread failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)	
		}
	}
	
	Ok(())
}