import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * Exports a catalog of the program's memory layout and defined data:
 *
 * - memory blocks (sections) with ranges, so arbitrary addresses can be
 *   mapped to a section without Ghidra
 * - every defined data item: address, size, primary label, data type name,
 *   and contents when the data holds a string
 *
 * The catalog is a one-time cache used by tools/ai_decomp/data_analysis.py
 * to enrich PowerPC-derived global references with Ghidra's data model.
 *
 * Output: tools/ghidra/output/data_catalog.json (git-ignored)
 */
public class ExportDataCatalog extends GhidraScript {

    private static final int MAX_STRING_LENGTH = 4096;

    private String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String hex(Address a) {
        return a.toString();
    }

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        SymbolTable symbols = currentProgram.getSymbolTable();
        Memory memory = currentProgram.getMemory();

        File outputDir = new File(
            System.getProperty("user.home"),
            "Decomp/LegoCloneWarsWii/tools/ghidra/output"
        );
        outputDir.mkdirs();

        File outputFile = new File(outputDir, "data_catalog.json");

        try (PrintWriter out = new PrintWriter(new BufferedWriter(
                new FileWriter(outputFile), 1 << 20))) {

            out.write("{\n");
            out.write("  \"program\": \"" +
                    jsonEscape(currentProgram.getName()) + "\",\n");

            // ---- memory blocks ----
            MemoryBlock[] blocks = memory.getBlocks();
            out.write("  \"memory_blocks\": [\n");
            for (int i = 0; i < blocks.length; i++) {
                MemoryBlock b = blocks[i];
                out.write("    {\n");
                out.write("      \"name\": \"" + jsonEscape(b.getName()) + "\",\n");
                out.write("      \"start\": \"" + hex(b.getStart()) + "\",\n");
                out.write("      \"end\": \"" + hex(b.getEnd()) + "\",\n");
                out.write("      \"size\": " + b.getSize() + ",\n");
                out.write("      \"initialized\": " + b.isInitialized() + "\n");
                out.write("    }");
                if (i + 1 < blocks.length) {
                    out.write(",");
                }
                out.write("\n");
            }
            out.write("  ],\n");

            // ---- defined data ----
            out.write("  \"data\": [\n");

            DataIterator it = listing.getDefinedData(true);
            long count = 0;

            while (it.hasNext()) {
                Data data = it.next();

                Address addr = data.getAddress();
                Symbol sym = symbols.getPrimarySymbol(addr);
                String label = sym != null ? sym.getName() : null;

                boolean isString = data.hasStringValue();
                String value = null;

                if (isString) {
                    Object v = data.getValue();
                    if (v instanceof String) {
                        value = (String) v;
                        if (value.length() > MAX_STRING_LENGTH) {
                            value = value.substring(0, MAX_STRING_LENGTH);
                            isString = false; // keep flag meaning "full value present"
                        }
                    }
                }

                StringBuilder sb = new StringBuilder(128);
                sb.append("    [\"");
                sb.append(hex(addr));
                sb.append("\",");
                sb.append(data.getLength());
                sb.append(",");
                sb.append(label != null
                        ? "\"" + jsonEscape(label) + "\"" : "null");
                sb.append(",");
                sb.append("\"" +
                        jsonEscape(data.getDataType().getName()) + "\"");
                sb.append(",");
                sb.append(value != null
                        ? "\"" + jsonEscape(value) + "\"" : "null");
                sb.append("]");

                if (it.hasNext()) {
                    sb.append(",");
                }
                out.write(sb.toString());
                out.write("\n");

                count++;
            }

            out.write("  ],\n");
            out.write("  \"data_count\": " + count + "\n");
            out.write("}\n");
        }

        println("Exported data catalog to " + outputFile.getAbsolutePath());
    }
}
