from __future__ import annotations

from tests.test_bridge import _load_bridge


def test_registers_preserve_multiline_vector_values(monkeypatch):
    bridge_mod, gdb = _load_bridge(monkeypatch)
    execute = gdb.execute
    output = (
        "rax            0x2a                42\n"
        "ymm0           {\n"
        "  v8_float = {1, 2, 3, 4, 5, 6, 7, 8},\n"
        "  v4_int64 = {0x1, 0x2, 0x3, 0x4}\n"
        "}\n"
        "ymm1           {\n"
        "  v8_float = {8, 7, 6, 5, 4, 3, 2, 1},\n"
        "  v4_int64 = {0x4, 0x3, 0x2, 0x1}\n"
        "}\n"
        "ymm2           <unavailable>\n"
    )

    def registers(command, to_string=False):
        if command == "info all-registers":
            return output
        return execute(command, to_string=to_string)

    monkeypatch.setattr(gdb, "execute", registers)
    result = bridge_mod.GdbBridge()._dispatch_op("registers", {"all": True})
    assert [row["name"] for row in result] == ["rax", "ymm0", "ymm1", "ymm2"]
    assert result[1]["value"] == (
        "{\n  v8_float = {1, 2, 3, 4, 5, 6, 7, 8},\n"
        "  v4_int64 = {0x1, 0x2, 0x3, 0x4}\n}"
    )
    assert "v8_float = {8, 7, 6, 5, 4, 3, 2, 1}" in result[2]["value"]
    assert result[3]["value"] == "<unavailable>"


def test_function_disassembly_restores_symbol_for_relative_annotations(monkeypatch):
    bridge_mod, gdb = _load_bridge(monkeypatch)
    execute = gdb.execute

    def disassemble(command, to_string=False):
        if command == "disassemble convert":
            return (
                "Dump of assembler code for function convert<int>(int):\n"
                "   0x00401000 <+0>:\tpush %rbp\n"
                "=> 0x00401001 <+1>:\tmov %rsp,%rbp\n"
                "End of assembler dump.\n"
            )
        return execute(command, to_string=to_string)

    monkeypatch.setattr(gdb, "execute", disassemble)
    result = bridge_mod.GdbBridge()._dispatch_op("disasm", {"location": "convert"})
    assert [row["symbol"] for row in result] == ["convert<int>(int)+0", "convert<int>(int)+1"]
    assert [row["asm"] for row in result] == ["push %rbp", "mov %rsp,%rbp"]


def test_range_disassembly_preserves_each_function_symbol(monkeypatch):
    bridge_mod, gdb = _load_bridge(monkeypatch)
    execute = gdb.execute

    def disassemble(command, to_string=False):
        if command == "disassemble 0x401000,0x401005":
            return (
                "Dump of assembler code from 0x401000 to 0x401005:\n"
                "   0x00401000 <Box<int>::call()+4>:\tcall 0x402000 <Box<int>::get()>\n"
                "   0x00401001 <second+0>:\tpush %rbp\n"
                "End of assembler dump.\n"
            )
        return execute(command, to_string=to_string)

    monkeypatch.setattr(gdb, "execute", disassemble)
    result = bridge_mod.GdbBridge()._dispatch_op(
        "disasm", {"start": "0x401000", "end": "0x401005"}
    )
    assert [row["symbol"] for row in result] == ["Box<int>::call()+4", "second+0"]
    assert result[0]["asm"] == "call 0x402000 <Box<int>::get()>"
