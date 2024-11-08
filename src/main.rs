use core::ffi::c_void;

use windows::core::s;
use windows::Win32::Foundation::{GetLastError, FARPROC, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use windows::Win32::System::Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS};

fn main() -> Result<(), String> {
	let args = std::env::args().collect::<Vec<String>>();
	
	if args.len() < 3 || args.len() > 3 {
		println!("Usage: dll_injector [TARGET_NAME] [PATH_TO_DLL]");
		return Err(String::from("Provide exactly one target and one dll"))
	}
	
	let dll_name = args[2].clone();
	
	let target_handle = process_enumerate_and_search(args[1].clone())
		.map_err(|error| error.message())?;
	
	inject_dll(dll_name.clone(), (dll_name.len() + 1) * size_of::<u16>(), target_handle)
		.map_err(|error| error.message())?;
	
	Ok(())
}

fn process_enumerate_and_search(process_name: String) -> Result<HANDLE, windows::core::Error> {
	let mut process_handle: HANDLE = unsafe { std::mem::zeroed() };
	let snapshot_handle: HANDLE;
	let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };

	match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, std::mem::zeroed()) } {
		Ok(handle) => snapshot_handle = handle,
		Err(error) => {
			println!("CreateToolhelp32Snapshot failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)
		}
	}

	process_entry.dwSize = size_of_val(&process_entry) as u32;

	if let Err(error) = unsafe { Process32First(snapshot_handle, &mut process_entry) } {
		println!("Process32First failed: {} (Error code: {})", error.message(), error.code());

		return Err(error)
	}

	loop {
		if String::from_utf8_lossy(
			&process_entry.szExeFile
				.map(|char| unsafe { std::mem::transmute::<i8, u8>(char) })
		) == process_name {
			match unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_entry.th32ProcessID) } {
				Ok(handle) => {
					process_handle = handle;
					
					println!("Opened process with PID {}", process_entry.th32ProcessID);
					
					break
				}
				Err(error) => {
					println!("OpenProcess failed: {} (Error code: {})", error.message(), error.code());

					return Err(error)
				}
			}
		}
		
		if unsafe { Process32Next(snapshot_handle, &mut process_entry) }.is_err() {
			break
		}
	}

	Ok(process_handle)
}

fn inject_dll(dll_name: String, sz_dll_name: usize, target_process_handle: HANDLE) -> Result<(), windows::core::Error> {
	let mut module: HMODULE = unsafe { std::mem::zeroed() };
	let load_library_handle: FARPROC;
	let mut sz_written_bytes: usize = 0;
	let mut thread_handle: HANDLE = unsafe { std::mem::zeroed() };
	
	match unsafe { GetModuleHandleA(s!("kernel32.dll")) } {
		Ok(module_handle) => module = module_handle,
		Err(error) => {
			println!("GetModuleHandleA failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)
		}
	}

	match unsafe { GetProcAddress(module, s!("LoadLibraryW")) } {
		Some(process_address) => load_library_handle = Some(process_address),
		None => {
			let error = unsafe { GetLastError().to_hresult() };

			println!("GetProcAddress failed: {} (Error code: {})", error.message(), error.0);

			return error.ok()
		}
	}

	let library_address = unsafe {
		VirtualAllocEx(target_process_handle, None, sz_dll_name, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
	};

	if library_address.is_null() {
		let error = unsafe { GetLastError().to_hresult() };

		println!("VirtualAllocEX failed: {} (Error code: {})", error.message(), error.0);

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
			println!("WriteProcessMemory failed: {} (Error code: {})", error.message(), error.code());

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
			
			println!("Created remote thread with handle {:?}", thread_handle)
		}
		Err(error) => {
			println!("CreateRemoteThread failed: {} (Error code: {})", error.message(), error.code());

			return Err(error)	
		}
	}
	
	Ok(())
}