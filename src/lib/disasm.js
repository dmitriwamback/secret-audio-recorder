import { loadCapstone, Capstone, Const } from 'capstone-wasm';

let ready = false;

async function ensureLoaded() {
	if (!ready) {
		await loadCapstone();
		ready = true;
	}
}

// Determine the architecture and mode for Capstone based on the parsed binary's format and header information
function resolveArchMode(parsed) {
    
    // ELF binaries
	if (parsed.format === 'elf') {
		switch (parsed.header.e_machine) {
			case 0x3e: // EM_X86_64
				return { arch: Const.CS_ARCH_X86, mode: Const.CS_MODE_64 };
			case 0x03: // EM_386
				return { arch: Const.CS_ARCH_X86, mode: Const.CS_MODE_32 };
			case 0xb7: // EM_AARCH64
				return { arch: Const.CS_ARCH_ARM64, mode: Const.CS_MODE_ARM };
			default:
				throw new Error('Unsupported ELF machine type: ' + parsed.header.e_machine);
		}
	}

    // Mach-O binaries
	if (parsed.format === 'macho') {
		switch (parsed.header.cputype) {
			case 0x01000007: // CPU_TYPE_X86_64
				return { arch: Const.CS_ARCH_X86, mode: Const.CS_MODE_64 };
			case 0x0100000c: // CPU_TYPE_ARM64
				return { arch: Const.CS_ARCH_ARM64, mode: Const.CS_MODE_ARM };
			default:
				throw new Error('Unsupported Mach-O cputype: ' + parsed.header.cputype);
		}
	}

	throw new Error('Unknown format for arch resolution');
}

// Classify an instruction mnemonic into a group: 'call', 'ret', 'jump', 'cmp', or 'normal'
function classify(mnemonic) {
    // Normalize the mnemonic to lowercase for consistent comparison
    const m = mnemonic.toLowerCase();

    // Classify based on common instruction patterns
	if (m === 'call' || m === 'bl' || m === 'blr') return 'call';
	if (m === 'ret' || m === 'retq') return 'ret';
	if (m.startsWith('j') || m.startsWith('b.') || m === 'b' || m === 'cbz' || m === 'cbnz')
		return 'jump';
	if (m.startsWith('cmp') || m === 'test') return 'cmp';
	return 'normal';
}

// Extract a target address from an instruction's operand string
function extractTarget(opStr) {
	const match = opStr && opStr.match(/0x[0-9a-fA-F]+/);
	return match ? parseInt(match[0], 16) : null;
}

// Find the symbol (if any) that covers a given address. `symbols` must be
// sorted ascending by address — parseSymbols() (elf.js) and
// parseMachoSymbols() (macho.js) both already guarantee this.
// Binary-searches for the last symbol whose address <= addr, then checks
// addr actually falls within that symbol's size (so addresses in a gap
// between two known functions correctly resolve to "no symbol").
export function resolveSymbol(addr, symbols) {
	if (!symbols || symbols.length === 0) return null;

	let lo = 0,
		hi = symbols.length - 1,
		found = -1;
	while (lo <= hi) {
		const mid = (lo + hi) >> 1;
		if (symbols[mid].address <= addr) {
			found = mid;
			lo = mid + 1;
		} else {
			hi = mid - 1;
		}
	}

	if (found === -1) return null;
	const sym = symbols[found];
	if (sym.size > 0 && addr >= sym.address + sym.size) return null; // addr is past this symbol's end
	return sym;
}

// Human-readable label for an address: the symbol name if one covers it
// (with a "+0x.." suffix if addr is mid-function), otherwise a
// Ghidra/IDA-style synthetic "sub_<hex>" label for unnamed code.
export function labelForAddress(addr, symbols) {
	const sym = resolveSymbol(addr, symbols);
	if (!sym) return 'sub_' + addr.toString(16);
	const delta = addr - sym.address;
	return delta === 0 ? sym.name : `${sym.name}+0x${delta.toString(16)}`;
}

// Group a flat instruction stream into functions using symbol boundaries.
// Any code not covered by a known symbol (stripped regions, gaps between
// functions) becomes its own synthetic "sub_<hex>" function so every
// instruction still ends up inside *some* function — useful for a
// function-list sidebar in the UI.
export function buildFunctions(instructions, symbols, textBase, textSize) {
	const starts = symbols.map((s) => s.address);
	if (starts.length === 0 || starts[0] !== textBase) starts.unshift(textBase);
	starts.push(textBase + textSize); // synthetic end boundary
	const bounds = [...new Set(starts)].sort((a, b) => a - b);

	const functions = [];
	for (let i = 0; i < bounds.length - 1; i++) {
		const start = bounds[i];
		const end = bounds[i + 1];
		if (start >= end) continue;
		const sym = symbols.find((s) => s.address === start);
		functions.push({
			name: sym ? sym.name : 'sub_' + start.toString(16),
			start,
			end,
			instructions: []
		});
	}

	// instructions come out of Capstone already sorted by address, so a
	// single linear pass (rather than a binary search per instruction) is
	// enough to bucket them into the right function.
	let fi = 0;
	for (const insn of instructions) {
		while (fi < functions.length - 1 && insn.address >= functions[fi].end) fi++;
		if (fi < functions.length) functions[fi].instructions.push(insn);
	}

	return functions;
}

// Disassemble the binary and return structured instruction data along with cross-references
export async function disassembleBinary(parsed) {
	await ensureLoaded();

	const { arch, mode } = resolveArchMode(parsed);
	const cs = new Capstone(arch, mode);

	const raw = cs.disasm(parsed.text.bytes, parsed.text.baseAddr);

	// Capstone-wasm returns insn.address as an offset relative to the
	// start of the buffer (0-based), NOT the real virtual address, even
	// though we passed baseAddr in. Re-apply it manually here so every
	// address in the app (rows, xrefs, patch targets) is a real vaddr.
	const base = parsed.text.baseAddr;

	const symbols = parsed.symbols || [];

	const instructions = raw.map((insn) => {
		const group = classify(insn.mnemonic);
		const rawTarget = group === 'jump' || group === 'call' ? extractTarget(insn.opStr) : null;

		// jump/call targets embedded in the operand string were computed
		// by Capstone using the same wrong 0-based frame, so they need
		// the identical correction to stay consistent with `address`.
		const target = rawTarget !== null ? base + rawTarget : null;

		return {
			address: base + insn.address, // <-- corrected
			bytes: Array.from(insn.bytes)
				.map((b) => b.toString(16).padStart(2, '0'))
				.join(' '),
			mnemonic: insn.mnemonic,
			operands: insn.opStr,
			size: insn.size,
			group,
			target,
			// e.g. "memcpy" or "sub_401120+0x8" for calls/jumps — use this
			// in the UI instead of the raw hex target where you have it.
			targetName: target !== null ? labelForAddress(target, symbols) : null
		};
	});

	const xrefs = new Map();
	for (const insn of instructions) {
		if (insn.target !== null) {
			if (!xrefs.has(insn.target)) xrefs.set(insn.target, []);
			xrefs.get(insn.target).push(insn.address);
		}
	}

	// Grouped by symbol/function boundary — this is what a function-list
	// sidebar should be built from, rather than the flat instruction array.
	const functions = buildFunctions(instructions, symbols, base, parsed.text.size);

	return { instructions, xrefs, functions };
}

export function reslice(parsed, fullFileBytes) {
	const sec = parsed.sections.find(
		(s) => s.name === '.text' || s.name === '__text'
	);
	if (!sec) throw new Error('Could not find .text/__text section to reslice');

	const fileOffset = sec.offset !== undefined ? sec.offset : sec.fileOffset;

	return {
		...parsed,
		text: {
			...parsed.text,
			bytes: fullFileBytes.slice(fileOffset, fileOffset + sec.size)
		}
	};
}