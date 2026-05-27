use env_logger::Env;
use std::io::Write as _;

use pyo3::exceptions::PyException;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use pyo3_stub_gen::define_stub_info_gatherer;
use pyo3_stub_gen::derive::gen_stub_pyclass;
use pyo3_stub_gen::derive::gen_stub_pymethods;
use pyo3_stub_gen::derive::gen_stub_pyfunction;

use libmwemu::console::Console;
use libmwemu::emu32;
use libmwemu::emu64;
use libmwemu::maps::mem64::Permission;

#[gen_stub_pyclass]
#[pyclass(unsendable, module="pymwemu._pymwemu")]
pub struct Emu {
    emu: std::cell::UnsafeCell<libmwemu::emu::Emu>,
}

impl Emu {
    #[allow(clippy::mut_from_ref)]
    fn inner_mut(&self) -> &mut libmwemu::emu::Emu {
        unsafe { &mut *self.emu.get() }
    }
    fn inner(&self) -> &libmwemu::emu::Emu {
        unsafe { &*self.emu.get() }
    }
}

#[gen_stub_pymethods]
#[pymethods]
#[allow(deprecated)]
impl Emu {
    /// get pymwemu version.
    fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// get last emulated mnemonic with name and parameters.
    fn get_prev_mnemonic(&self) -> PyResult<String> {
        match self.inner_mut().last_decoded {
            Some(decoded) => Ok(self.inner_mut().format_instruction(&decoded)),
            None => Err(PyValueError::new_err("no instruction decoded yet")),
        }
    }

    /// reset the instruction counter to zero.
    fn reset_pos(&self) {
        self.inner_mut().pos = 0;
    }

    /// check if the emulator is in 64bits mode.
    fn is_64bits(&self) -> PyResult<bool> {
        Ok(self.inner_mut().cfg.is_x64())
    }

    /// check if the emulator is in 32bits mode.
    fn is_32bits(&self) -> PyResult<bool> {
        Ok(!self.inner_mut().cfg.is_x64())
    }

    /// change base address on ldr entry of a module
    fn update_ldr_entry_base(&self, libname: &str, base: u64) {
        self.inner_mut().update_ldr_entry_base(libname, base);
    }

    /// Set 64bits mode, it's necessary to load the 64bits maps with load_maps() method.
    /// Or better can use: emu = pymwemu.init64()
    fn set_64bits(&self) {
        self.inner_mut().cfg.arch = libmwemu::arch::Arch::X86_64;
    }

    /// Set 32bits mode, it's necessary to load the 32bits maps with load_maps() method.
    /// Or better can use: emu = pymwemu.init32()
    fn set_32bits(&self) {
        self.inner_mut().cfg.arch = libmwemu::arch::Arch::X86;
    }

    /// disable the colored mode for instructions, api calls and other logs.
    fn disable_colors(&self) {
        self.inner_mut().cfg.nocolors = true;
    }

    /// enable the colored mode.
    fn enable_colors(&self) {
        self.inner_mut().cfg.nocolors = false;
    }

    /// trace all memory reads and writes.
    fn enable_trace_mem(&self) {
        self.inner_mut().cfg.trace_mem = true;
    }

    /// disable the memory tracer.
    fn disable_trace_mem(&self) {
        self.inner_mut().cfg.trace_mem = false;
    }

    /// trace all the registers printing them in every step.
    fn enable_trace_regs(&self) {
        self.inner_mut().cfg.trace_regs = true;
    }

    /// disable the register tracer.
    fn disable_trace_regs(&self) {
        self.inner_mut().cfg.trace_regs = false;
    }

    /// trace a specific list of registers, provide  array of strings with register names in lower case.
    fn enable_trace_reg(&self, regs: Vec<String>) {
        self.inner_mut().cfg.trace_reg = true;
        self.inner_mut().cfg.reg_names = regs;
    }

    /// disable the multi-register tracer.
    fn disable_trace_reg(&self) {
        self.inner_mut().cfg.trace_reg = false;
        self.inner_mut().cfg.reg_names.clear();
    }

    /// inspect sequence
    fn inspect_seq(&self, s: &str) {
        self.inner_mut().cfg.inspect = true;
        self.inner_mut().cfg.inspect_seq = s.to_string();
    }

    /// address to api name
    fn api_addr_to_name(&self, addr: u64) -> String {
        self.inner_mut().api_addr_to_name(addr)
    }

    /// api name to address
    fn api_name_to_addr(&self, name: &str) -> u64 {
        self.inner_mut().api_name_to_addr(name)
    }

    /// set the verbosity between 0 and 3.
    ///     0: only show api calls.
    ///     1: show api calls and some logs.
    ///     2: show also instructions (slower).
    ///     3: show every iteration of rep preffix.
    fn set_verbose(&self, verbose: u32) {
        self.inner_mut().cfg.verbose = verbose;
    }

    /// Set the base address of stack memory map
    fn set_stack_base(&self, addr: u64) {
        self.inner_mut().cfg.stack_addr = addr;
    }

    /// when the execution reached a specified amount of steps will spawn an interactive console.
    fn spawn_console_at_pos(&self, position: u64) {
        //self.inner_mut().cfg.console = true;
        //self.inner_mut().cfg.console_num = position;
        self.inner_mut().cfg.console_enabled = true;
        self.inner_mut().spawn_console_at(position);
    }

    /// when the execution reached a specified address will spawn an interactive console.
    fn spawn_console_at_addr(&self, addr: u64) {
        self.inner_mut().cfg.console2 = true;
        self.inner_mut().cfg.console_addr = addr;
        self.inner_mut().cfg.console_enabled = true;
    }

    /// disable the console spawning.
    fn disable_spawn_console_at_pos(&self) {
        self.inner_mut().cfg.console_num = 0;
    }

    /// allow to enable the console if its needed.
    fn enable_console(&self) {
        self.inner_mut().cfg.console_enabled = true;
    }

    /// disable the console, to prevent to be spawned in some situations.
    fn disable_console(&self) {
        self.inner_mut().cfg.console_enabled = false;
    }

    /// enable the loops counter, this feature slows down the emulation but count the iteration number.
    fn enable_count_loops(&self) {
        self.inner_mut().cfg.loops = true;
    }

    /// disable the loops counting system.
    fn disable_count_loops(&self) {
        self.inner_mut().cfg.loops = false;
    }

    /// Allow emulating zero-filled code blocks (disables the empty block detector).
    fn allow_empty_code_blocks(&self) {
        self.inner_mut().cfg.allow_empty_code_blocks = true;
    }

    /// enable tracing a string on a specified memory address.
    fn enable_trace_string(&self, addr: u64) {
        self.inner_mut().cfg.trace_string = true;
        self.inner_mut().cfg.string_addr = addr;
    }

    /// disable the string tracer.
    fn disable_trace_string(&self) {
        self.inner_mut().cfg.trace_string = false;
        self.inner_mut().cfg.string_addr = 0;
    }

    /// inspect a memory area by providing a stirng like 'dword ptr [esp + 0x8]'
    fn enable_inspect_sequence(&self, seq: &str) {
        self.inner_mut().cfg.inspect = true;
        self.inner_mut().cfg.inspect_seq = seq.to_string();
    }

    fn enable_shellcode_mode(&self) {
        self.inner_mut().cfg.shellcode = true;
    }

    /// disable the memory inspector.
    fn disable_inspect_sequence(&self) {
        self.inner_mut().cfg.inspect = false;
    }

    /*
    /// give the binary the posibility of connecting remote hosts to get next stage, use it safelly.
    fn enable_endpoint_mode(&self) {
        self.inner_mut().cfg.endpoint = true;
    }

    /// disable the endpoint mode.
    fn disable_endpoint_mode(&self) {
        self.inner_mut().cfg.endpoint = false;
    }*/

    /// change the default entry point.
    fn set_entry_point(&self, addr: u64) {
        self.inner_mut().cfg.entry_point = addr;
    }

    /// rebase the program address.
    fn set_base_address(&self, addr: u64) {
        self.inner_mut().cfg.code_base_addr = addr;
    }

    /// enable the stack tracer.
    fn enable_stack_trace(&self) {
        self.inner_mut().cfg.stack_trace = true;
    }

    /// disable the stack tracer.
    fn disable_stack_trace(&self) {
        self.inner_mut().cfg.stack_trace = false;
    }

    /// test mode use inline assembly to contrast the result of emulation and detect bugs.
    fn enable_test_mode(&self) {
        self.inner_mut().cfg.test_mode = true;
    }

    /// disable the test mode.
    fn disable_test_mode(&self) {
        self.inner_mut().cfg.test_mode = false;
    }

    /// Enable banzai mode. This mode keep emulating after finding unimplemented instructions or apis.
    fn enable_banzai_mode(&self) {
        self.inner_mut().cfg.skip_unimplemented = true;
        self.inner_mut().maps.set_banzai(true);
    }

    /// disable banzai mode.
    fn disable_banzai_mode(&self) {
        self.inner_mut().cfg.skip_unimplemented = false;
    }

    /// Add API to banzai.
    fn banzai_add(&self, apiname: &str, nparams: i32) {
        self.inner_mut().banzai_add(apiname, nparams);
    }

    /// enable the Control-C handling for spawning console.
    fn enable_ctrlc(&self) {
        self.inner_mut().enable_ctrlc();
    }

    /// disable the Control-C handling.
    fn disable_ctrlc(&self) {
        self.inner_mut().disable_ctrlc();
    }

    // end of config

    /// It is necessary to load the 32bits or 64bits maps folder for having a realistic memory layout.
    /// The maps can be downloaded from the https://github.com/sha0coder/mwemu
    fn load_maps(&self, folder: &str) {
        self.inner_mut().cfg.maps_folder = folder.to_string();
    }

    /// load_binary() already calls init_win32() if its PE or shellcode.
    /// if you dont use load_binary and need the windows simulation
    /// then call this to have peb/teb/ldr/dlls loaded.
    fn init_win32(&self) {
        self.inner_mut().init_win32(false, false);
    }

    /// load_binary() already calls init_linux64() if its ELF
    /// if you dont use load_binary and need the linux simulation
    /// then call this to have libc etc loaded.
    fn init_linux64(&self, dynamic: bool) {
        self.inner_mut().init_linux64(dynamic);
    }

    /// Load the binary to be emulated.
    fn load_binary(&self, filename: &str) {
        self.inner_mut().load_code(filename);
    }

    /// Load code from bytes
    fn load_code_bytes(&self, bytes: Vec<u8>) {
        self.inner_mut().load_code_bytes(&bytes);
    }

    /// allocate a buffer on the emulated process address space.
    fn alloc(&self, name: &str, size: u64) -> PyResult<u64> {
        Ok(self.inner_mut().alloc(name, size, Permission::READ_WRITE_EXECUTE))
    }

    /// allocate at specific address
    fn alloc_at(&self, name: &str, addr: u64, size: u64) {
        self.inner_mut()
            .maps
            .create_map(name, addr, size, Permission::READ_WRITE_EXECUTE)
            .expect("pymwemu alloc_at out of memory");
    }

    /// load an aditional blob to the memory layout.
    fn load_map(&self, name: &str, filename: &str, base_addr: u64) {
        let map = self
            .inner_mut()
            .maps
            .create_map(name, base_addr, 1, Permission::READ_WRITE_EXECUTE)
            .expect("pymwemu load_map out of memory");
        map.load(filename);
    }

    /// link library
    fn link_library(&self, filepath: &str) -> PyResult<u64> {
        Ok(self.inner_mut().link_library(filepath))
    }

    /// push a 32bits value to the stack.
    fn stack_push32(&self, value: u32) -> PyResult<bool> {
        if self.inner_mut().stack_push32(value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("pushing error"))
        }
    }

    /// push a 64bits value to the stack.
    fn stack_push64(&self, value: u64) -> PyResult<bool> {
        if self.inner_mut().stack_push64(value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("pushing error"))
        }
    }

    /// pop a 32bits value from the stack.
    fn stack_pop32(&self) -> PyResult<u32> {
        match self.inner_mut().stack_pop32(false) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("popping error")),
        }
    }

    /// pop a 64bits value from the stack.
    fn stack_pop64(&self) -> PyResult<u64> {
        match self.inner_mut().stack_pop64(false) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("popping error")),
        }
    }

    /// set program counter (works for any arch).
    fn set_pc(&self, addr: u64) {
        self.inner_mut().set_pc(addr);
    }

    /// get program counter (works for any arch).
    fn get_pc(&self) -> u64 {
        self.inner_mut().pc()
    }

    /// get stack pointer (works for any arch).
    fn get_sp(&self) -> u64 {
        self.inner_mut().sp()
    }

    /// set stack pointer (works for any arch).
    fn set_sp(&self, addr: u64) {
        self.inner_mut().set_sp(addr);
    }

    /// set rip register, if rip point to an api will be emulated.
    fn set_rip(&self, addr: u64) -> PyResult<bool> {
        Ok(self.inner_mut().set_rip(addr, false))
    }

    /// set eip register, if eip point to an api will be emulated.
    fn set_eip(&self, addr: u64) -> PyResult<bool> {
        Ok(self.inner_mut().set_eip(addr, false))
    }

    /// spawn an interactive console.
    fn spawn_console(&self) {
        self.inner_mut().cfg.console_enabled = true;
        Console::spawn_console(self.inner_mut());
    }

    /// disassemble an address.
    fn disassemble(&self, addr: u64, amount: u32) -> PyResult<String> {
        Ok(self.inner_mut().disassemble(addr, amount))
    }

    /*
    fn stop(&self) {
        self.inner_mut().stop();
    }*/

    /// start emulating the binary after finding the first return.
    fn run_until_return(&self) -> PyResult<u64> {
        match self.inner_mut().run_until_ret() {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// emulate a single step, this is slower than run(address) or run(0)
    fn step(&self) -> PyResult<bool> {
        Ok(self.inner_mut().step())
    }

    /// Start emulating the binary until reach the provided end_addr.
    /// Use run() with no params for emulating forever. or call32/call64 for calling a function.
    fn run(&self, end_addr: Option<u64>) -> PyResult<u64> {
        match self.inner_mut().run(end_addr) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// Emulate until reaching a specific instruction position (number of instructions).
    fn run_to(&self, position: u64) -> PyResult<u64> {
        match self.inner_mut().run_to(position) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// read the number of instructions emulated since now.
    fn get_position(&self) -> PyResult<u64> {
        Ok(self.inner_mut().pos)
    }

    /// call a 32bits function, internally pushes params in reverse order.
    fn call32(&self, address: u64, params: Vec<u32>) -> PyResult<u32> {
        match self.inner_mut().call32(address, &params) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    /// call a 64bits function, internally pushes params in reverse order.
    fn call64(&self, address: u64, params: Vec<u64>) -> PyResult<u64> {
        match self.inner_mut().call64(address, &params) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    fn linux_call64(&self, address: u64, params: Vec<u64>) -> PyResult<u64> {
        match self.inner_mut().linux_call64(address, &params) {
            Ok(pc) => Ok(pc),
            Err(e) => Err(PyValueError::new_err(e.message)),
        }
    }

    // registers

    /// read register value ie get_reg('rax') or get_reg('x0')
    fn get_reg(&self, reg: &str) -> PyResult<u64> {
        if self.inner_mut().cfg.arch.is_aarch64() {
            match self.inner_mut().regs_aarch64().get_by_name(reg) {
                Some(val) => Ok(val),
                None => Err(PyValueError::new_err("invalid aarch64 register name")),
            }
        } else if self.inner_mut().regs().is_reg(reg) {
            Ok(self.inner_mut().regs().get_by_name(reg))
        } else {
            Err(PyValueError::new_err("invalid register name"))
        }
    }

    /// set register value ie  set_reg('rax', 0x123) or set_reg('x0', 0x123), returns previous value.
    fn set_reg(&self, reg: &str, value: u64) -> PyResult<u64> {
        if self.inner_mut().cfg.arch.is_aarch64() {
            match self.inner_mut().regs_aarch64().get_by_name(reg) {
                Some(prev) => {
                    self.inner_mut().regs_aarch64_mut().set_by_name(reg, value);
                    Ok(prev)
                }
                None => Err(PyValueError::new_err("invalid aarch64 register name")),
            }
        } else if self.inner_mut().regs().is_reg(reg) {
            let prev = self.inner_mut().regs().get_by_name(reg);
            self.inner_mut().regs_mut().set_by_name(reg, value);
            Ok(prev)
        } else {
            Err(PyValueError::new_err("invalid register name"))
        }
    }

    /// get the value of a xmm register (x86 only).
    fn get_xmm(&self, reg: &str) -> PyResult<u128> {
        if self.inner_mut().cfg.arch.is_aarch64() {
            return Err(PyValueError::new_err(
                "xmm registers not available on aarch64",
            ));
        }
        if self.inner_mut().regs().is_xmm_by_name(reg) {
            return Ok(self.inner_mut().regs().get_xmm_by_name(reg));
        }
        Err(PyValueError::new_err("invalid register name"))
    }

    /// set a value to a xmm register (x86 only).
    fn set_xmm(&self, reg: &str, value: u128) -> PyResult<u128> {
        if self.inner_mut().cfg.arch.is_aarch64() {
            return Err(PyValueError::new_err(
                "xmm registers not available on aarch64",
            ));
        }
        if self.inner_mut().regs().is_xmm_by_name(reg) {
            let prev = self.inner_mut().regs().get_xmm_by_name(reg);
            self.inner_mut().regs_mut().set_xmm_by_name(reg, value);
            Ok(prev)
        } else {
            Err(PyValueError::new_err("invalid register name"))
        }
    }

    // memory

    /*fn create_map(&self,  name:&str) {
        self.inner_mut().maps.create_map(name);
    }*/

    /// write a little endian qword on memory.
    fn write_qword(&self, addr: u64, value: u64) -> PyResult<bool> {
        if self.inner_mut().maps.write_qword(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// write a little endian dword on memory.
    fn write_dword(&self, addr: u64, value: u32) -> PyResult<bool> {
        if self.inner_mut().maps.write_dword(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// write a little endian word on memory.
    fn write_word(&self, addr: u64, value: u16) -> PyResult<bool> {
        if self.inner_mut().maps.write_word(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// write a byte on memory.
    fn write_byte(&self, addr: u64, value: u8) -> PyResult<bool> {
        if self.inner_mut().maps.write_byte(addr, value) {
            Ok(true)
        } else {
            Err(PyValueError::new_err("writting on non allocated address"))
        }
    }

    /// read 128bits big endian.
    fn read_128bits_be(&self, addr: u64) -> PyResult<u128> {
        match self.inner_mut().maps.read_128bits_be(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read 128bits little endian.
    fn read_128bits_le(&self, addr: u64) -> PyResult<u128> {
        match self.inner_mut().maps.read_128bits_le(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read little endian qword.
    fn read_qword(&self, addr: u64) -> PyResult<u64> {
        match self.inner_mut().maps.read_qword(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read little endian dword.
    fn read_dword(&self, addr: u64) -> PyResult<u32> {
        match self.inner_mut().maps.read_dword(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read little endian word.
    fn read_word(&self, addr: u64) -> PyResult<u16> {
        match self.inner_mut().maps.read_word(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// read a byte from a memory address.
    fn read_byte(&self, addr: u64) -> PyResult<u8> {
        match self.inner_mut().maps.read_byte(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("reading on non allocated address")),
        }
    }

    /// fill a memory chunk starting at `address`, with a specified `amount` of bytes defined in `byte`.
    fn memset(&self, addr: u64, byte: u8, amount: usize) {
        self.inner_mut().maps.memset(addr, byte, amount);
    }

    /// get the size of a wide string.
    fn sizeof_wide(&self, unicode_str_ptr: u64) -> PyResult<usize> {
        Ok(self.inner_mut().maps.sizeof_wide(unicode_str_ptr))
    }

    /// write string on memory.
    fn write_string(&self, to: u64, _from: &str) {
        self.inner_mut().maps.write_string(to, _from);
    }

    /// write a wide string on memory.
    pub fn write_wide_string(&self, to: u64, _from: &str) {
        self.inner_mut().maps.write_wide_string(to, _from);
    }

    /// write a python list of int bytes to the emulator memory.
    pub fn write_buffer(&self, to: u64, _from: Vec<u8>) {
        self.inner_mut().maps.write_buffer(to, &_from);
    }

    /// read a buffer &from the emulator memory to a python list of int bytes.
    pub fn read_buffer(&self, _from: u64, sz: usize) -> PyResult<Vec<u8>> {
        Ok(self.inner_mut().maps.read_buffer(_from, sz))
    }

    /// write a python list of int bytes to the emulator memory.
    pub fn write_bytes(&self, to: u64, _from: Vec<u8>) {
        self.inner_mut().maps.write_buffer(to, &_from);
    }

    /// print all the maps that match a substring of the keyword provided.
    pub fn print_maps_by_keyword(&self, kw: &str) {
        self.inner_mut().maps.print_maps_keyword(kw);
    }

    /// print all the memory maps on the process address space.
    pub fn print_maps(&self) {
        self.inner_mut().maps.print_maps();
    }

    /// get the base address of a given address. Will make an exception if it's invalid address.
    pub fn get_addr_base(&self, addr: u64) -> PyResult<u64> {
        match self.inner_mut().maps.get_addr_base(addr) {
            Some(v) => Ok(v),
            None => Err(PyValueError::new_err("provided address is not allocated")),
        }
    }

    /// this method checks if the given address is allocated or not.
    pub fn is_mapped(&self, addr: u64) -> PyResult<bool> {
        Ok(self.inner_mut().maps.is_mapped(addr))
    }

    /// get the memory map name where is the given address.
    /// Will cause an exception if the address is not allocated.
    pub fn get_addr_name(&self, addr: u64) -> PyResult<String> {
        match self.inner_mut().maps.get_addr_name(addr) {
            Some(v) => Ok(v.to_string()),
            None => Err(PyValueError::new_err(
                "the address doesnt pertain to an allocated block",
            )),
        }
    }

    /// visualize the bytes on the given address.
    pub fn dump(&self, addr: u64) {
        self.inner_mut().maps.dump(addr);
    }

    /// visualize the `amount` of bytes provided on `address`.
    pub fn dump_n(&self, addr: u64, amount: u64) {
        self.inner_mut().maps.dump_n(addr, amount);
    }

    /// visualize a number of qwords on given address.
    pub fn dump_qwords(&self, addr: u64, n: u64) {
        self.inner_mut().maps.dump_qwords(addr, n);
    }

    /// visualize a number of dwords on a given address.
    pub fn dump_dwords(&self, addr: u64, n: u64) {
        self.inner_mut().maps.dump_dwords(addr, n);
    }

    /// read an amount of bytes from an address to a python object.
    pub fn read_bytes(&self, addr: u64, sz: usize) -> PyResult<Vec<u8>> {
        Ok(self.inner_mut().maps.read_bytes(addr, sz).to_vec())
    }

    /// read an amount of bytes from an address to a string of spaced hexa bytes.
    pub fn read_string_of_bytes(&self, addr: u64, sz: usize) -> PyResult<String> {
        Ok(self.inner_mut().maps.read_string_of_bytes(addr, sz))
    }

    /// read an ascii string from a memory address,
    /// if the address point to a non allocated zone string will be empty.
    pub fn read_string(&self, addr: u64) -> PyResult<String> {
        Ok(self.inner_mut().maps.read_string(addr))
    }

    /// read a wide string from a memory address,
    /// if the address point to a non allocated zone string will be empty.
    pub fn read_wide_string(&self, addr: u64) -> PyResult<String> {
        Ok(self.inner_mut().maps.read_wide_string(addr))
    }

    /// search a substring on a specific memory map name, it will return a list of matched addresses.
    /// if the string is not found, it will return an empty list.
    pub fn search_string(&self, kw: &str, map_name: &str) -> PyResult<Vec<u64>> {
        match self.inner_mut().maps.search_string(kw, map_name) {
            Some(v) => Ok(v),
            None => Ok(Vec::new()),
        }
    }

    /// write on emulators memory a spaced hexa bytes
    pub fn write_spaced_bytes(&self, addr: u64, spaced_hex_bytes: &str) -> PyResult<bool> {
        if self.inner_mut().maps.write_spaced_bytes(addr, spaced_hex_bytes) {
            Ok(true)
        } else {
            Err(PyValueError::new_err(
                "couldnt write the bytes on that address",
            ))
        }
    }

    /// search one occurence of a spaced hex bytes from a specific address, will return zero if it's not found.
    pub fn search_spaced_bytes_from(&self, saddr: u64, sbs: &str) -> PyResult<u64> {
        Ok(self.inner_mut().maps.search_spaced_bytes_from(sbs, saddr))
    }

    /// search one occcurence of a spaced hex bytes from an especific address backward,
    /// will return zero if it's not found.
    pub fn search_spaced_bytes_from_bw(&self, saddr: u64, sbs: &str) -> PyResult<u64> {
        Ok(self.inner_mut().maps.search_spaced_bytes_from_bw(sbs, saddr))
    }

    /// search spaced hex bytes string on specific map using its map name,
    /// will return a list with the addresses found if there are matches,
    /// otherwise the list will be empty.
    pub fn search_spaced_bytes(&self, sbs: &str, map_name: &str) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().maps.search_spaced_bytes(sbs, map_name))
    }

    /// search spaced hex bytes string on all the memory layout,
    /// will return a list with the addresses found if there are matches,
    /// otherwise the list will be empty.
    pub fn search_spaced_bytes_in_all(&self, sbs: &str) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().maps.search_spaced_bytes_in_all(sbs))
    }

    /// Search a substring in all the memory layout except on libs, will print the results.
    /// In the future will return a list with results instead of printing.
    pub fn search_string_in_all(&self, kw: String) {
        self.inner_mut().maps.search_string_in_all(kw);
    }

    /// search a bytes object on specific map, will return a list with matched addresses if there are any.
    pub fn search_bytes(&self, bkw: Vec<u8>, map_name: &str) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().maps.search_bytes(bkw, map_name))
    }

    /// show the total allocated memory.
    pub fn allocated_size(&self) -> PyResult<usize> {
        Ok(self.inner_mut().maps.size())
    }

    /// show if there are memory blocks overlaping eachother.
    pub fn memory_overlaps(&self, addr: u64, sz: u64) -> PyResult<bool> {
        Ok(self.inner_mut().maps.overlaps(addr, sz))
    }

    /// show all the memory blocks allocated during the emulation.
    pub fn show_allocs(&self) {
        self.inner_mut().maps.show_allocs();
    }

    /// free a memory map by its name
    pub fn free(&self, name: &str) {
        self.inner_mut().maps.free(name);
    }

    /// basic allocator, it looks for a free block of given size,
    /// it only returns the address if its possible, but dont really allocates,
    /// just find the address, you have to load to that address something.
    /// use alloc() method instead if possible.
    pub fn memory_alloc(&self, sz: u64) -> PyResult<u64> {
        match self.inner_mut().maps.alloc(sz) {
            Some(addr) => Ok(addr),
            None => Err(PyValueError::new_err("couldnt found a space of that size")),
        }
    }

    /// Save all memory blocks allocated during emulation to disk.
    /// Provide a folder where every alloc will be a file.
    pub fn save_all_allocs(&self, path: String) {
        self.inner_mut().maps.save_all_allocs(path);
    }

    /// save a chunk of memory to disk.
    pub fn save(&self, addr: u64, size: u64, filename: String) {
        self.inner_mut().maps.save(addr, size, filename);
    }

    /// perform a memory test to see overlapps or other possible problems.
    pub fn mem_test(&self) -> PyResult<bool> {
        Ok(self.inner_mut().maps.mem_test())
    }

    /// breakpoints
    /// show breakpoints
    pub fn bp_show(&self) {
        self.inner_mut().bp.show();
    }

    /// clear all the breakpoints
    pub fn bp_clear_all(&self) {
        self.inner_mut().bp.clear_bp();
    }

    /// set breakpoint on an address
    pub fn bp_set_addr(&self, addr: u64) {
        self.inner_mut().bp.add_bp(addr);
    }

    /// get the current address breakpoint
    pub fn bp_get_addr(&self) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().bp.addr.clone())
    }

    /// set breakpoint on a instruction counter
    pub fn bp_set_inst(&self, ins: u64) {
        self.inner_mut().bp.add_bp_instruction(ins);
    }

    /// get breakpoint on a instrunction counter
    pub fn bp_get_inst(&self) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().bp.instruction.clone())
    }

    /// set a memory breakpoint on read
    pub fn bp_set_mem_read(&self, addr: u64) {
        self.inner_mut().bp.add_bp_mem_read(addr);
    }

    /// get the memory breakpoint on read
    pub fn bp_get_mem_read(&self) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().bp.mem_read_addr.clone())
    }

    /// set a memory breakpoint on write
    pub fn bp_set_mem_write(&self, addr: u64) {
        self.inner_mut().bp.add_bp_mem_write(addr);
    }

    /// get the memory breakpoint on write
    pub fn bp_get_mem_write(&self) -> PyResult<Vec<u64>> {
        Ok(self.inner_mut().bp.mem_write_addr.clone())
    }

    /// handle winapi address
    pub fn handle_winapi(&self, addr: u64) {
        self.inner_mut().handle_winapi(addr);
    }

    /// emulate until next winapi call
    pub fn run_until_apicall(&self) -> PyResult<(u64, String)> {
        self.inner_mut().skip_apicall = true;
        self.inner_mut().is_break_on_api = true;
        // run until api
        let _ = self.inner_mut().run(None);
        match self.inner_mut().its_apicall {
            Some(addr) => {
                self.inner_mut().skip_apicall = false;
                let name = self.inner_mut().api_addr_to_name(addr);
                let new_pc = self.inner_mut().pc() + self.inner_mut().last_instruction_size as u64;
                self.inner_mut().set_pc(new_pc);
                return Ok((addr, name));
            }

            _ => Err(PyException::new_err(
                "breakpoint on apicall fail because there isn't any address return",
            )),
        }
    }


    // --- Hooks ---
    fn on_memory_read(&self, callback: Py<PyAny>) {
        Python::with_gil(|py| {
            let callback_clone = callback.clone_ref(py);
            self.inner_mut().hooks.on_memory_read(move |_emu_mut, pc, addr, size| {
                Python::with_gil(|py| {
                    if let Err(e) = callback_clone.call1(py, (pc, addr, size)) {
                        e.print(py);
                    }
                });
            });
        });
    }

    fn on_memory_write(&self, callback: Py<PyAny>) {
        Python::with_gil(|py| {

            let callback_clone = callback.clone_ref(py);
            self.inner_mut().hooks.on_memory_write(move |_emu_mut, pc, addr, size, val| {
                Python::with_gil(|py| {
                    match callback_clone.call1(py, (pc, addr, size, val)) {
                        Ok(result) => result.extract::<u128>(py).unwrap_or(val),
                        Err(e) => {
                            e.print(py);
                            val
                        }
                    }
                })
            });
        });
    }

    fn on_interrupt(&self, callback: Py<PyAny>) {
        Python::with_gil(|py| {
            let callback_clone = callback.clone_ref(py);
            self.inner_mut().hooks.on_interrupt(move |_emu_mut, int_no, pc| {
                Python::with_gil(|py| {
                    match callback_clone.call1(py, (int_no, pc)) {
                        Ok(result) => result.extract::<bool>(py).unwrap_or(true),
                        Err(e) => {
                            e.print(py);
                            true
                        }
                    }
                })
            })
        });
    }

    fn on_winapi_call(&self, callback: Py<PyAny>) {
        Python::with_gil(|py| {
            let callback_clone = callback.clone_ref(py);
            self.inner_mut().hooks.on_winapi_call(move |_emu_mut, api_addr, pc| {
                Python::with_gil(|py| {
                    match callback_clone.call1(py, (api_addr, pc)) {
                        Ok(result) => result.extract::<bool>(py).unwrap_or(true),
                        Err(e) => {
                            e.print(py);
                            true
                        }
                    }
                })
            })
        });
    }

    fn on_pre_instruction(&self, callback: Py<PyAny>) {
        Python::with_gil(|py| {
            let callback_clone = callback.clone_ref(py);
            self.inner_mut().hooks.on_pre_instruction(move |_emu_mut, pc, _ins, _size| {
                Python::with_gil(|py| {
                    match callback_clone.call1(py, (pc,)) {
                        Ok(result) => result.extract::<bool>(py).unwrap_or(true),
                        Err(e) => {
                            e.print(py);
                            true
                        }
                    }
                })
            })
        });
    }

    fn on_post_instruction(&self, callback: Py<PyAny>) {
        Python::with_gil(|py| {
            let callback_clone = callback.clone_ref(py);
            self.inner_mut().hooks.on_post_instruction(move |_emu_mut, pc, _ins, _size, _has_executed| {
                Python::with_gil(|py| {
                    if let Err(e) = callback_clone.call1(py, (pc,)) {
                        e.print(py);
                    }
                });
            });
        });
    }

    // --- Serialization ---
    /// serialize the whole emulator state to a bytes object, which can be saved to disk for example
    pub fn serialize(&self) -> PyResult<Vec<u8>> {
        Ok(libmwemu::serialization::Serialization::serialize(self.inner()))
    }

    /// serialize the whole emulator state to a file, which can be loaded later with deserialize_dump
    pub fn dump_to_file(&self, filename: &str) -> PyResult<()> {
        libmwemu::serialization::Serialization::dump_to_file(self.inner(), filename);
        Ok(())
    }

    /// serialize the whole emulator state to a minidump file, which can be loaded later with load_from_minidump
    pub fn dump_to_minidump(&self, filename: &str) -> PyResult<()> {
        libmwemu::serialization::Serialization::dump_to_minidump(self.inner(), filename)?;
        Ok(())
    }

}

// --- Serialization ---

#[gen_stub_pyfunction(module="pymwemu._pymwemu")]
#[pyfunction]
/// deserialize the emulator state from a bytes object, which can be loaded from disk for example
pub fn deserialize(data: Vec<u8>) -> PyResult<Emu> {
    Ok(Emu { emu: std::cell::UnsafeCell::new(libmwemu::serialization::Serialization::deserialize(&data),
    ) })
}
#[gen_stub_pyfunction(module="pymwemu._pymwemu")]
#[pyfunction]
/// deserialize the emulator state from a minidump file, which can be dumped with dump_to_minidump
pub fn load_from_minidump(filename: &str) -> PyResult<Emu> {
    Ok(Emu { emu: std::cell::UnsafeCell::new(libmwemu::serialization::Serialization::load_from_minidump(filename),
    ) })
}

#[gen_stub_pyfunction(module="pymwemu._pymwemu")]
#[pyfunction]
/// deserialize the emulator state from a file, which can be dumped with dump_to_file
pub fn load_from_file(filename: &str) -> PyResult<Emu> {
    Ok(Emu { emu: std::cell::UnsafeCell::new(libmwemu::serialization::Serialization::load_from_file(filename),
    ) })
}

#[gen_stub_pyfunction(module="pymwemu._pymwemu")]
#[pyfunction]
fn init32() -> PyResult<Emu> {
    let mut emu = Emu { emu: std::cell::UnsafeCell::new(emu32()) };
    emu.emu.get_mut().cfg.console_enabled = false;
    emu.emu.get_mut().cfg.verbose = 0;
    emu.emu.get_mut().cfg.shellcode = false;

    Ok(emu)
}

#[gen_stub_pyfunction(module = "pymwemu._pymwemu")]
#[pyfunction]
fn init64() -> PyResult<Emu> {
    let mut emu = Emu { emu: std::cell::UnsafeCell::new(emu64()) };
    emu.emu.get_mut().cfg.console_enabled = false;
    emu.emu.get_mut().cfg.verbose = 0;
    emu.emu.get_mut().cfg.shellcode = false;

    Ok(emu)
}

#[pymodule]
fn _pymwemu(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    // Filter `goblin=warn` to drop the LoadCommand / Mach-o header / Ctx
    // spam goblin emits via `debug!()` while parsing Mach-O / PE / ELF —
    // the mwemu CLI does the equivalent via a fast_log Filter.
    env_logger::Builder::from_env(Env::default().default_filter_or("trace,goblin=warn"))
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .init();
    log::info!("Initialized logging");

    // we register Emu inside the _pymwemu module, which would re-export as pymwemu.Emu
    m.add_class::<Emu>()?;
    m.add_function(wrap_pyfunction!(init32, m)?)?;
    m.add_function(wrap_pyfunction!(init64, m)?)?;
    m.add_function(wrap_pyfunction!(deserialize, m)?)?;
    m.add_function(wrap_pyfunction!(load_from_minidump, m)?)?;
    m.add_function(wrap_pyfunction!(load_from_file, m)?)?;
    Ok(())
}
//

// Re-export the module members of _pymwemu to pymwemu
pyo3_stub_gen::reexport_module_members!("pymwemu" from "pymwemu._pymwemu");

//  Define a stub info gatherer, to generate the .pyi
define_stub_info_gatherer!(stub_gen);
