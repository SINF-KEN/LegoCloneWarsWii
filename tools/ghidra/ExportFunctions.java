import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class ExportFunctions extends GhidraScript {

    static class FunctionInfo {
        String address;
        String name;
        long size;
        boolean thunk;
        boolean external;

        FunctionInfo(Function f) {
            address = f.getEntryPoint().toString();
            name = f.getName();
            size = f.getBody().getNumAddresses();
            thunk = f.isThunk();
            external = f.isExternal();
        }
    }

    private String jsonEscape(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    @Override
    public void run() throws Exception {
        FunctionManager manager = currentProgram.getFunctionManager();
        FunctionIterator iterator = manager.getFunctions(true);

        List<FunctionInfo> functions = new ArrayList<>();

        while (iterator.hasNext()) {
            functions.add(new FunctionInfo(iterator.next()));
        }

        functions.sort(Comparator.comparingLong(
            f -> Long.parseLong(f.address, 16)
        ));

        File outputDir = new File(
            System.getProperty("user.home"),
            "Decomp/LegoCloneWarsWii/tools/ghidra/output"
        );
        outputDir.mkdirs();

        File outputFile = new File(outputDir, "functions.json");

        try (FileWriter out = new FileWriter(outputFile)) {
            out.write("{\n");
            out.write("  \"program\": \"" +
                jsonEscape(currentProgram.getName()) + "\",\n");
            out.write("  \"language\": \"" +
                jsonEscape(currentProgram.getLanguageID().toString()) + "\",\n");
            out.write("  \"compiler\": \"" +
                jsonEscape(currentProgram.getCompilerSpec()
                    .getCompilerSpecID().toString()) + "\",\n");
            out.write("  \"function_count\": " +
                functions.size() + ",\n");
            out.write("  \"functions\": [\n");

            for (int i = 0; i < functions.size(); i++) {
                FunctionInfo f = functions.get(i);

                out.write("    {\n");
                out.write("      \"address\": \"" + f.address + "\",\n");
                out.write("      \"name\": \"" +
                    jsonEscape(f.name) + "\",\n");
                out.write("      \"size\": " + f.size + ",\n");
                out.write("      \"thunk\": " + f.thunk + ",\n");
                out.write("      \"external\": " + f.external + "\n");
                out.write("    }");

                if (i + 1 < functions.size()) {
                    out.write(",");
                }

                out.write("\n");
            }

            out.write("  ]\n");
            out.write("}\n");
        }

        println("Exported " + functions.size() +
                " functions to " + outputFile.getAbsolutePath());
    }
}
