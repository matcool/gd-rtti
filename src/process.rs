use read_process_memory::{copy_address, CopyAddress, Pid, ProcessHandle};

#[cfg(windows)]
pub fn fetch_base_address(handle: &ProcessHandle) -> std::io::Result<usize> {
    use std::{mem::size_of, ptr::null_mut};

    use winapi::shared::minwindef::{HMODULE, MAX_PATH};
    use winapi::um::psapi;

    let mut name = vec![0u16; MAX_PATH];
    if unsafe {
        winapi::um::winbase::QueryFullProcessImageNameW(
            **handle,
            0,
            name.as_mut_ptr(),
            &mut (name.len() as u32),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let Ok(process_name) = String::from_utf16(&name) else { return Err(std::io::Error::new(std::io::ErrorKind::Other, "Invalid string")); };

    let mut modules = [null_mut() as HMODULE; 1024];
    let mut needed: u32 = 0;
    if unsafe {
        psapi::EnumProcessModules(
            **handle,
            modules.as_mut_ptr(),
            modules.len() as u32,
            &mut needed,
        )
    } != 0
    {
        let needed = needed as usize / size_of::<HMODULE>();
        for module in modules.into_iter().take(needed) {
            let mut module_name = [0u16; MAX_PATH];
            if unsafe {
                psapi::GetModuleFileNameExW(
                    **handle,
                    module,
                    module_name.as_mut_ptr(),
                    module_name.len() as u32,
                )
            } != 0
            {
                let Ok(module_name) = String::from_utf16(&module_name) else { continue };
                if module_name == process_name {
                    let base = module as usize;
                    return Ok(base);
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Module not found",
        ))
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
// pass a mach_port_name_t !! i was too lazy to quality the type
pub fn fetch_base_address(handle: u32) -> io::Result<usize> {
    use mach::{
        kern_return::KERN_SUCCESS,
        message::mach_msg_type_number_t,
        vm::mach_vm_region_recurse,
        vm_types::{
            vm_map_size_t,
            vm_map_offset_t
        },
        vm_region::{
            vm_region_submap_info,
            vm_region_submap_info_t,
            vm_region_recurse_info_t
        }
    };

    let task = handle;
    let mut vm_offset: vm_map_offset_t = 0;
    let mut vmsize: vm_map_size_t = 0;
    let mut nesting_depth: u32 = 0;

    let mut vbr = vm_region_submap_info::default();
    let mut vbrcount: mach_msg_type_number_t = 16;

    if unsafe {
        // these types are a mess
        mach_vm_region_recurse(
            task,
            &mut vm_offset,
            &mut vmsize,
            &mut nesting_depth,
            &mut vbr as vm_region_submap_info_t as vm_region_recurse_info_t,
            &mut vbrcount)
    } != KERN_SUCCESS {
        Err(io::Error::last_os_error())
    } else {
        Ok(vm_offset.try_into().unwrap())
    }
}

#[cfg(target_os = "macos")]
fn get_handle_from_pid(pid: Pid) -> io::Result<u32> {
    // copied from ProcessHandle, we want the native handle type though
    use mach::{port::MACH_PORT_NULL, kern_return::KERN_SUCCESS};

    let mut task = MACH_PORT_NULL;

    if unsafe {
        mach::traps::task_for_pid(mach::traps::mach_task_self(), pid, &mut task)
    } != KERN_SUCCESS {
        return Err(io::Error::last_os_error());
    }

    Ok(task)
}
pub struct Process {
    base_address: usize,
    handle: ProcessHandle,
    pointer_size: usize,
}

use std::io;

#[derive(Debug)]
pub enum ProcessError {
    InvalidPointer,
    InvalidRTTI,
    InvalidClass,
    InvalidString,
}

type ProcResult<T> = Result<T, ProcessError>;

impl Process {
    #[cfg(windows)]
    pub fn try_new(pid: Pid) -> io::Result<Self> {
        use winapi::um::{processthreadsapi, winnt};

        let handle = unsafe {
            processthreadsapi::OpenProcess(
                winnt::PROCESS_VM_READ | winnt::PROCESS_QUERY_LIMITED_INFORMATION,
                0,
                pid,
            )
        };
        if handle as usize == 0 {
            Err(io::Error::last_os_error())
        } else {
            let handle = ProcessHandle::from(handle);
            Ok(Self {
                base_address: fetch_base_address(&handle)?,
                handle,
                pointer_size: 4,
            })
        }
    }

    #[cfg(target_os = "macos")]
    pub fn try_new(pid: Pid) -> io::Result<Self> {
        let handle = get_handle_from_pid(pid)?;

        Ok(Self {
            base_address: fetch_base_address(handle)?,
            handle: ProcessHandle::try_from(handle)?,
            pointer_size: 8,
        })
    }

    pub fn base_address(&self) -> usize {
        self.base_address
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn read_at(&self, addr: usize, size: usize) -> ProcResult<Vec<u8>> {
        copy_address(addr, size, &self.handle).map_err(|_| ProcessError::InvalidPointer)
    }

    pub fn read_u32(&self, addr: usize) -> ProcResult<u32> {
        let mut buf = [0; 4];
        self.handle
            .copy_address(addr, &mut buf)
            .map_err(|_| ProcessError::InvalidPointer)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u64(&self, addr: usize) -> ProcResult<u64> {
        let mut buf = [0; 8];
        self.handle
            .copy_address(addr, &mut buf)
            .map_err(|_| ProcessError::InvalidPointer)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_i64(&self, addr: usize) -> ProcResult<i64> {
        let mut buf = [0; 8];
        self.handle
            .copy_address(addr, &mut buf)
            .map_err(|_| ProcessError::InvalidPointer)?;
        Ok(i64::from_le_bytes(buf))
    }

    pub fn read_ptr(&self, addr: usize) -> ProcResult<usize> {
        if self.pointer_size == 4 {
            self.read_u32(addr).map(|x| x as usize)
        } else if self.pointer_size == 8 {
            self.read_u64(addr).map(|x| x as usize)
        } else {
            unreachable!()
        }
    }

    pub fn read_c_str(&self, mut addr: usize, max_size: usize) -> ProcResult<String> {
        const BUFFER_SIZE: usize = 128;
        let mut str = String::new();
        while max_size == 0 || str.len() < max_size {
            let bytes: Vec<u8> = (self.read_at(addr, BUFFER_SIZE)?)
                .into_iter()
                .take_while(|x| *x != 0)
                .collect();
            let size = bytes.len();
            str += std::str::from_utf8(&bytes).map_err(|_| ProcessError::InvalidString)?;
            if size < BUFFER_SIZE {
                break;
            }
            addr += BUFFER_SIZE;
        }
        Ok(str)
    }

    #[cfg(target_os = "macos")]
    pub fn read_class_name(&self, addr: usize) -> ProcResult<String> {
        let vtable = self.read_ptr(addr)?;
        if vtable < 16 {
            return Err(ProcessError::InvalidPointer);
        }
        let type_info = self.read_ptr(vtable - 8)?;
        let name = self.read_ptr(type_info + 8)?;
        self.read_c_str(name, 256)
    }

    #[cfg(target_os = "macos")]
    pub fn read_vtable_info(&self, vtable: usize) -> ProcResult<String> {
        fn get_class_offset(process: &Process, type_info: usize, i: usize) -> ProcResult<(u64, usize)> {
            let addr = type_info + 24 + i * 16;
            let base_type_info = process.read_ptr(addr)?;
            let flags = process.read_u64(addr + 8)?;
            let class_offset = flags >> 8;
            Ok((class_offset, base_type_info))
        }
        fn look_for_offset(process: &Process, type_info: usize, offset: u64) -> ProcResult<usize> {
            let base_count = process.read_u32(type_info + 20)? as usize;
            for i in 0..base_count {
                let (base_offset, base_type_info) = get_class_offset(process, type_info, i)?;
                if base_offset == offset {
                    return process.read_ptr(base_type_info + 8)
                } else if i < base_count - 1 {
                    let (base_offset, _) = get_class_offset(process, type_info, i + 1)?;
                    // if the next base class has a higher offset, then recurse through the current one
                    if base_offset > offset {
                        return look_for_offset(process, base_type_info, offset)
                    }
                }
            }
            Err(ProcessError::InvalidRTTI)
        }
        if vtable < 16 {
            return Err(ProcessError::InvalidPointer);
        }
        let offset = self.read_i64(vtable - 16)?;
        let offset = (-offset) as u64;
        let type_info = self.read_ptr(vtable - 8)?;
        let name_ptr = look_for_offset(self, type_info, offset)?;
        self.read_c_str(name_ptr, 256)
    }
    
    #[cfg(target_os = "macos")]
    pub fn demangle_class_name(&self, name: &str) -> ProcResult<String> {
        Ok(name.into())
    }

    #[cfg(windows)]
    pub fn read_class_name(&self, addr: usize) -> ProcResult<String> {
        let vtable = self.read_ptr(addr)?;
        if vtable < 4 {
            return Err(ProcessError::InvalidPointer);
        }
        let rtti_object_locator = self.read_ptr(vtable - 4)?;
        if self.read_u32(rtti_object_locator)? != 0 {
            return Err(ProcessError::InvalidRTTI);
        }
        let rtti_type_descriptor = self.read_ptr(rtti_object_locator + 12)?;
        self.read_c_str(rtti_type_descriptor + 8, 256)
    }

    #[cfg(windows)]
    pub fn read_vtable_info(&self, addr: usize) -> ProcResult<String> {
        if addr < 4 {
            return Err(ProcessError::InvalidPointer);
        }

        let rtti_object_locator = self.read_ptr(addr - 4)?;
        // signature
        if self.read_u32(rtti_object_locator)? != 0 {
            return Err(ProcessError::InvalidRTTI);
        }
        let offset = self.read_u32(rtti_object_locator + 4)?;

        let rtti_class_hierarchy = self.read_ptr(rtti_object_locator + 16)?;
        // signature
        if self.read_u32(rtti_object_locator)? != 0 {
            return Err(ProcessError::InvalidRTTI);
        }
        let base_classes = self.read_u32(rtti_class_hierarchy + 8)? as usize;

        let rtti_base_class_array = self.read_ptr(rtti_class_hierarchy + 12)?;
        for i in 0..base_classes {
            let rtti_base_class_descriptor = self.read_ptr(rtti_base_class_array + i * 4)?;
            let pmd_offset = self.read_u32(rtti_base_class_descriptor + 8)?;
            if pmd_offset == offset {
                let rtti_type_descriptor = self.read_ptr(rtti_base_class_descriptor)?;
                return self.read_c_str(rtti_type_descriptor + 8, 256);
            }
        }

        Err(ProcessError::InvalidPointer)
    }

    #[cfg(windows)]
    pub fn demangle_class_name(&self, name: &str) -> ProcResult<String> {
        let Some(name) = name.strip_prefix(".?AV") else {
            return Err(ProcessError::InvalidClass);
        };
        let Some(name) = name.strip_suffix("@@") else {
            return Err(ProcessError::InvalidClass);
        };
        Ok(name.split('@').rev().intersperse("::").collect())
    }
}
