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

pub struct Process {
    base_address: usize,
    handle: ProcessHandle,
    pointer_size: usize,
}

use std::io;

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

    #[cfg(not(windows))]
    pub fn try_new(pid: Pid) -> io::Result<Self> {
        Ok(Self {
            base_address: 0,
            handle: ProcessHandle::try_from(pid)?,
            pointer_size: 8,
        })
    }

    pub fn base_address(&self) -> usize {
        self.base_address
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn read_at(&self, addr: usize, size: usize) -> io::Result<Vec<u8>> {
        copy_address(addr, size, &self.handle)
    }

    pub fn read_u32(&self, addr: usize) -> io::Result<u32> {
        let mut buf = [0; 4];
        self.handle.copy_address(addr, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_u64(&self, addr: usize) -> io::Result<u64> {
        let mut buf = [0; 8];
        self.handle.copy_address(addr, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    pub fn read_ptr(&self, addr: usize) -> io::Result<usize> {
        if self.pointer_size == 4 {
            self.read_u32(addr).map(|x| x as usize)
        } else if self.pointer_size == 8 {
            self.read_u64(addr).map(|x| x as usize)
        } else {
            unreachable!()
        }
    }

    pub fn read_c_str(&self, mut addr: usize, max_size: usize) -> io::Result<String> {
        const BUFFER_SIZE: usize = 128;
        let mut str = String::new();
        while max_size == 0 || str.len() < max_size {
            let bytes: Vec<u8> = (self.read_at(addr, BUFFER_SIZE)?)
                .into_iter()
                .take_while(|x| *x != 0)
                .collect();
            let size = bytes.len();
            str += std::str::from_utf8(&bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Invalid utf8"))?;
            if size < BUFFER_SIZE {
                break;
            }
            addr += BUFFER_SIZE;
        }
        Ok(str)
    }

    #[cfg(windows)]
    pub fn read_class_name(&self, addr: usize) -> io::Result<String> {
        let vtable = self.read_ptr(addr)?;
        if vtable < 4 {
            return Err(io::Error::new(io::ErrorKind::Other, "Invalid address"));
        }
        let rtti_object_locator = self.read_ptr(vtable - 4)?;
        let rtti_type_descriptor = self.read_ptr(rtti_object_locator + 12)?;
        self.read_c_str(rtti_type_descriptor + 8, 256)
    }
}
