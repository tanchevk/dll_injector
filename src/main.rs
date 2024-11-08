use core::ffi::c_void;
use std::ffi::{c_char, CStr, CString, OsString};

use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::Foundation::{GetLastError, FARPROC, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::core::{s, PWSTR};
use tracing::{debug, error, info, warn};

fn main() -> Result<(), String> {
	tracing_subscriber::fmt::init();

	let args = std::env::args_os().collect::<Vec<OsString>>();
	
	if args.len() < 3 || args.len() > 3 {
		println!("Usage: dll_injector [TARGET_NAME] [PATH_TO_DLL]");
		return Err(String::from("Provide exactly one target and one dll"))
	}
	
	let dll_name = args[2].clone();
	
	let target_handle = process_enumerate_and_search(PWSTR::from_raw(
		args[1].clone()
			.to_string_lossy()
			.encode_utf16()
			.collect::<Vec<u16>>()
			.as_mut_ptr()
	))
		.map_err(|error| error.message())?;
	
	inject_dll(
		PWSTR::from_raw(
			dll_name.clone()
				.to_string_lossy()
				.encode_utf16()
				.collect::<Vec<u16>>()
				.as_mut_ptr()
		),
		dll_name.len() * size_of::<u16>(),
		target_handle
	)
		.map_err(|error| error.message())?;
	
	Ok(())
}

fn process_enumerate_and_search(process_name: PWSTR) -> Result<HANDLE, windows::core::Error> {
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
		let sz_exe_file = unsafe {
			CStr::from_ptr(process_entry.szExeFile.clone().as_ptr() as *mut c_char)
		};
		
		// debug!("Checking: {sz_exe_file:?}");
		
		if PWSTR::from_raw(
			sz_exe_file
				.to_string_lossy()
				.encode_utf16()
				.collect::<Vec<u16>>()
				.as_mut_ptr()
		) == process_name {
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

		if unsafe { Process32Next(snapshot_handle, &mut process_entry) }.is_err() {
			error!("The process \"{}\" could not be found", unsafe { process_name.display() });
			warn!("Check if the provided name matches the target process's exactly");
			
			break
		}
	}

	if process_handle.is_none(){
		error!("Process handle is None");

		return Err(windows::core::Error::empty())
	} else if process_handle.unwrap().is_invalid() {
		error!("Process handle is invalid: {process_handle:?}");

		return Err(windows::core::Error::empty())
	}

	Ok(process_handle.unwrap())
}

fn inject_dll(dll_name: PWSTR, sz_dll_name: usize, target_process_handle: HANDLE) -> Result<(), windows::core::Error> {
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