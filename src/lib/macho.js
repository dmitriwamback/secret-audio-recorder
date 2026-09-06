// Handles non-fat, 64-bit Mach-O only for now.
// LC_SEGMENT_64 = 0x19, tells you where sections live.

const LC_SEGMENT_64 = 0x19;
const LC_SYMTAB = 0x02;

// nlist_64 flags (n_type field)
const N_STAB = 0xe0; // if any of these bits are set, it's a debugger symbol (stab), not a real symbol
const N_TYPE = 0x0e; // mask for the type bits
const N_SECT = 0x0e; // type value meaning "defined in a section" (n_sect gives which one)

export function parseMachoHeader(buf) {
	const dv = new DataView(buf);
	const magic = dv.getUint32(0, false); // read raw bytes as big-endian for comparison

	// Determine endianness based on the magic number and validate that it's a supported Mach-O format
	let le;
	if (magic === 0xcffaedfe) {
		le = true; // MH_MAGIC_64 stored little-endian (normal on Intel/Apple Silicon Macs)
	} 
    else if (magic === 0xfeedfacf) {
		le = false; // MH_MAGIC_64 stored big-endian (rare, old PowerPC-era)
	} 
    else if (magic === 0xcefaedfe) {
		le = true; // MH_MAGIC (32-bit), little-endian
		throw new Error('32-bit Mach-O not supported yet — only 64-bit is implemented');
	} 
    else if (magic === 0xfeedface) {
		le = false; // MH_MAGIC (32-bit), big-endian
		throw new Error('32-bit Mach-O not supported yet — only 64-bit is implemented');
	} 
    else {
		throw new Error('Unrecognized Mach-O magic: ' + magic.toString(16));
	}

	return {
		magic, // The magic number identifying the Mach-O format
		le, // Endianness of the Mach-O file (true for little-endian, false for big-endian)
		cputype: dv.getUint32(0x04, le), // CPU type (e.g., x86_64, arm64)
		cpusubtype: dv.getUint32(0x08, le), // CPU subtype (specific variant of the CPU type)
		filetype: dv.getUint32(0x0c, le), // File type (e.g., executable, dylib, bundle)
		ncmds: dv.getUint32(0x10, le), // Number of load commands in the Mach-O header
		sizeofcmds: dv.getUint32(0x14, le), // Total size of all load commands in bytes
		flags: dv.getUint32(0x18, le), // Flags indicating various attributes of the Mach-O file
		headerSize: 32 // Size of the Mach-O header (fixed at 32 bytes for 64-bit Mach-O)
	};
}

// Read a null-terminated string from the buffer starting at the given offset, with a maximum length
function readCString(buf, offset, maxLen) {
    // Create a Uint8Array view of the buffer starting at the specified offset and limited to maxLen
	const bytes = new Uint8Array(buf, offset, maxLen);
	let end = 0;
    // Iterate through the bytes until a null terminator is found or the maximum length is reached
	while (bytes[end] !== 0 && end < maxLen) end++;
	return new TextDecoder().decode(bytes.slice(0, end));
}

// Parse the sections of a Mach-O binary and return structured information about each section
export function parseMachoSections(buf, hdr) {
	const dv = new DataView(buf);
	let offset = hdr.headerSize;
	const sections = [];

    // Iterate over the number of load commands specified in the Mach-O header
	for (let i = 0; i < hdr.ncmds; i++) {

        // Read the load command type and size from the current offset
		const cmd = dv.getUint32(offset, hdr.le);
		const cmdsize = dv.getUint32(offset + 4, hdr.le);

        // If the load command is a 64-bit segment command, parse its sections
		if (cmd === LC_SEGMENT_64) {
			const segname = readCString(buf, offset + 8, 16); // Read the segment name (16 bytes) from the load command
			const nsects = dv.getUint32(offset + 64, hdr.le); // Number of sections in this segment

			let sectOff = offset + 72; // sizeof(segment_command_64) = 72 bytes
			for (let s = 0; s < nsects; s++) {
				sections.push({
					name: readCString(buf, sectOff, 16), // Read the section name (16 bytes) from the section header
					segment: readCString(buf, sectOff + 16, 16) || segname, // Read the segment name (16 bytes) from the section header or fallback to the segment name
					addr: Number(dv.getBigUint64(sectOff + 32, hdr.le)), // Virtual address of the section in memory
					size: Number(dv.getBigUint64(sectOff + 40, hdr.le)), // Size of the section in bytes
					fileOffset: dv.getUint32(sectOff + 48, hdr.le) // Offset of the section in the file
				});
				sectOff += 80; // sizeof(section_64)
			}
		}

		offset += cmdsize; // Move to the next load command based on the size of the current command
	}

	return sections;
}

// Walk the load commands looking for LC_SYMTAB, which tells us where the
// symbol table (array of nlist_64 entries) and its string table live.
// Returns null if the binary was stripped of LC_SYMTAB entirely.
export function findSymtabCommand(buf, hdr) {
	const dv = new DataView(buf);
	let offset = hdr.headerSize;

	for (let i = 0; i < hdr.ncmds; i++) {
		const cmd = dv.getUint32(offset, hdr.le);
		const cmdsize = dv.getUint32(offset + 4, hdr.le);

		if (cmd === LC_SYMTAB) {
			// struct symtab_command { uint32_t cmd, cmdsize, symoff, nsyms, stroff, strsize; }
			return {
				symoff: dv.getUint32(offset + 8, hdr.le), // file offset to the array of nlist_64 entries
				nsyms: dv.getUint32(offset + 12, hdr.le), // number of nlist_64 entries
				stroff: dv.getUint32(offset + 16, hdr.le), // file offset to the string table
				strsize: dv.getUint32(offset + 20, hdr.le) // size of the string table in bytes
			};
		}

		offset += cmdsize;
	}

	return null;
}

// Parse the Mach-O symbol table (nlist_64 entries) and return function
// symbols — i.e. defined, non-debug symbols whose n_sect points at
// __TEXT,__text. Sizes aren't stored in Mach-O symtabs, so they're
// derived by sorting on address and diffing against the next symbol
// (or the end of __text for the last one).
export function parseMachoSymbols(buf, hdr, sections) {
	const symtab = findSymtabCommand(buf, hdr);
	if (!symtab) return []; // stripped binary, no LC_SYMTAB at all

	// n_sect is a 1-based ordinal into the flattened list of sections
	// across every segment, in the order they appear in the load
	// commands — which is exactly the order parseMachoSections builds.
	const textOrdinal = sections.findIndex((s) => s.name === '__text' && s.segment === '__TEXT') + 1;
	if (textOrdinal === 0) return []; // no __text section to attribute symbols to
	const textSection = sections[textOrdinal - 1];

	const dv = new DataView(buf);
	const ENTRY_SIZE = 16; // sizeof(nlist_64): n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8)

	const raw = [];
	for (let i = 0; i < symtab.nsyms; i++) {
		const base = symtab.symoff + i * ENTRY_SIZE;
		const n_strx = dv.getUint32(base + 0x00, hdr.le);
		const n_type = dv.getUint8(base + 0x04);
		const n_sect = dv.getUint8(base + 0x05);
		const n_value = Number(dv.getBigUint64(base + 0x08, hdr.le));

		if (n_type & N_STAB) continue; // skip debugger/stab symbols
		if ((n_type & N_TYPE) !== N_SECT) continue; // only "defined in a section" symbols have a real address
		if (n_sect !== textOrdinal) continue; // only symbols living in __TEXT,__text
		if (n_strx === 0) continue; // no name

		const name = readCString(buf, symtab.stroff + n_strx, symtab.strsize - n_strx);
		if (!name) continue;

		raw.push({ name, address: n_value });
	}

	// Sort by address, then derive each symbol's size from the gap to
	// the next one (last symbol's size runs to the end of __text).
	raw.sort((a, b) => a.address - b.address);
	const textEnd = textSection.addr + textSection.size;

	return raw.map((sym, i) => {
		const nextAddr = i + 1 < raw.length ? raw[i + 1].address : textEnd;
		return { name: sym.name, address: sym.address, size: Math.max(0, nextAddr - sym.address) };
	});
}

// Parse a Mach-O binary and return structured information about it
export function parseMacho(buf) {
	const header = parseMachoHeader(buf); // Parse the Mach-O header to extract metadata about the binary
	const sections = parseMachoSections(buf, header); // Parse the sections of the Mach-O binary to extract information about each section

	// The code section is __text inside the __TEXT segment
	const textSection = sections.find((s) => s.name === '__text');
	if (!textSection) throw new Error('No __text section found');

    // Create a Uint8Array view of the text section bytes from the buffer using the file offset and size of the section
	const textBytes = new Uint8Array(buf, textSection.fileOffset, textSection.size);

	const symbols = parseMachoSymbols(buf, header, sections); // Parse LC_SYMTAB for __text function symbols

	return {
		format: 'macho', // Indicate that the parsed binary is in Mach-O format
		header, // Include the parsed Mach-O header information
		sections, // Include the parsed sections of the Mach-O binary
		symbols, // Function symbols found in __TEXT,__text, sorted by address
		text: {
			bytes: textBytes, // Uint8Array view of the text section bytes for disassembly
			baseAddr: textSection.addr, // Virtual address of the text section in memory
			fileOffset: textSection.fileOffset, // File offset of the text section in the Mach-O binary
			size: textSection.size // Size of the text section in bytes
		}
	};
}