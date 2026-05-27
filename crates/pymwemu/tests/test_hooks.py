#!/usr/bin/env python3
"""
Test the hooking system for pymwemu
"""

import unittest
import pymwemu

class TestHooks(unittest.TestCase):
    def setUp(self):
        self.emu = pymwemu.init32()
        self.emu.enable_banzai_mode()

    def test_pre_and_post_instruction_hooks(self):
        """Test on_pre_instruction and on_post_instruction hooks"""
        code_base = self.emu.alloc("code", 0x1000)
        # NOP (90) NOP (90) NOP (90)
        self.emu.write_spaced_bytes(code_base, "90 90 90")
        
        pre_instructions = []
        post_instructions = []

        def pre_hook(pc):
            pre_instructions.append(pc)
            # Continue normally
            return True

        def post_hook(pc):
            post_instructions.append(pc)

        self.emu.on_pre_instruction(pre_hook)
        self.emu.on_post_instruction(post_hook)

        self.emu.set_reg('eip', code_base)
        
        # Step twice
        self.emu.step()
        self.emu.step()

        self.assertEqual(len(pre_instructions), 2)
        self.assertEqual(len(post_instructions), 2)
        self.assertEqual(pre_instructions[0], code_base)
        self.assertEqual(pre_instructions[1], code_base + 1)
        self.assertEqual(post_instructions[0], code_base)
        self.assertEqual(post_instructions[1], code_base + 1)

    def test_skip_instruction(self):
        """Test skipping an instruction by returning False in on_pre_instruction"""
        code_base = self.emu.alloc("code", 0x1000)
        # INC EAX (40)
        # INC EAX (40)
        self.emu.write_spaced_bytes(code_base, "40 40")
        
        self.emu.set_reg('eax', 0)
        
        call_count = 0
        def pre_hook(pc):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Skip the first INC EAX
                self.emu.set_reg('eip', pc + 1)
                return False
            return True

        self.emu.on_pre_instruction(pre_hook)
        
        self.emu.set_reg('eip', code_base)
        
        # Step through the two instructions
        # Since we skip the first one, step will execute the second one
        self.emu.step()

        # because step evaluates one fetch-execute cycle, skipping means it didn't execute context.
        # eax should be 1, not 2.
        self.assertEqual(self.emu.get_reg('eax'), 1)

    def test_memory_write_hook(self):
        """Test on_memory_write modifying the value"""
        code_base = self.emu.alloc("code", 0x1000)
        data_base = self.emu.alloc("data", 0x1000)
        
        writes = []
        def mem_write_hook(pc, addr, size, val):
            writes.append((pc, addr, size, val))
            # Modify the written value
            return val + 1

        self.emu.on_memory_write(mem_write_hook)
        
        # write_dword won't trigger the hook...
        # self.emu.write_dword(data_base, 0x10)
        
        # Instead, let's execute code that writes to memory
        # MOV DWORD PTR [data_base], 0x10
        # Assuming data_base is a 32‑bit address (e.g., 0x06001000)
        addr_bytes = data_base.to_bytes(4, 'little')   # produces bytes: 00 10 00 06
        addr_hex = ' '.join(f'{b:02x}' for b in addr_bytes)  # "00 10 00 06"

        # Build the instruction: MOV DWORD PTR [disp32], imm32
        # Opcode bytes: C7 05, then address (4 bytes LE), then immediate 10 00 00 00
        machine_code = f"C7 05 {addr_hex} 10 00 00 00"
        self.emu.write_spaced_bytes(code_base, machine_code)
        self.emu.set_reg('eip', code_base)
        self.emu.step()
        
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][1], data_base)
        self.assertEqual(writes[0][3], 0x10)
        
        # Ensure the written value was actually modified!
        self.assertEqual(self.emu.read_dword(data_base), 0x11)
        
    def test_memory_read_hook(self):
        """Test on_memory_read callback"""
        data_base = self.emu.alloc("data", 0x1000)
        self.emu.write_dword(data_base, 0x1337)
        
        reads = []
        def mem_read_hook(pc, addr, size):
            reads.append((pc, addr, size))

        self.emu.on_memory_read(mem_read_hook)
        
        _ = self.emu.read_dword(data_base)
        
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0][1], data_base)
        self.assertEqual(reads[0][2], 4)

if __name__ == '__main__':
    unittest.main()
