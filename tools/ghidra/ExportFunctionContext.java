import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

public class ExportFunctionContext extends GhidraScript {

    private String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private Function findFunction(FunctionManager manager, String addressText)
            throws Exception {
        Address address;
        try {
            address = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace()
                    .getAddress(addressText);
        } catch (AddressFormatException e) {
            return null;
        }

        if (address == null) {
            return null;
        }

        Function f = manager.getFunctionAt(address);
        if (f != null) {
            return f;
        }

        return manager.getFunctionContaining(address);
    }

    private List<Function> getCallers(Function function) {
        List<Function> result = new ArrayList<>();
        ReferenceManager refs = currentProgram.getReferenceManager();
        FunctionManager manager = currentProgram.getFunctionManager();

        ReferenceIterator it = refs.getReferencesTo(function.getEntryPoint());

        while (it.hasNext()) {
            Reference ref = it.next();
            Function caller = manager.getFunctionContaining(ref.getFromAddress());

            if (caller != null && caller != function && !result.contains(caller)) {
                result.add(caller);
            }
        }

        return result;
    }

    private List<Function> getCallees(Function function) {
        List<Function> result = new ArrayList<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();

        Instruction instruction = listing.getInstructionAt(function.getEntryPoint());

        if (instruction == null) {
            instruction = listing.getInstructionAfter(function.getEntryPoint());
        }

        while (instruction != null &&
               function.getBody().contains(instruction.getAddress())) {

            Reference[] refs = instruction.getReferencesFrom();

            for (Reference ref : refs) {
                Function callee = manager.getFunctionContaining(ref.getToAddress());

                if (callee != null && callee != function && !result.contains(callee)) {
                    result.add(callee);
                }
            }

            instruction = listing.getInstructionAfter(instruction.getAddress());
        }

        return result;
    }

    private void writeFunctionList(FileWriter out, List<Function> functions)
            throws Exception {

        out.write("[\n");

        for (int i = 0; i < functions.size(); i++) {
            Function f = functions.get(i);

            out.write("        {\n");
            out.write("          \"address\": \"" +
                    jsonEscape(f.getEntryPoint().toString()) + "\",\n");
            out.write("          \"name\": \"" +
                    jsonEscape(f.getName()) + "\",\n");
            out.write("          \"size\": " +
                    f.getBody().getNumAddresses() + "\n");
            out.write("        }");

            if (i + 1 < functions.size()) {
                out.write(",");
            }

            out.write("\n");
        }

        out.write("      ]");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();

        if (args.length < 1) {
            printerr("Usage: ExportFunctionContext.java <address>");
            return;
        }

        String addressText = args[0];

        FunctionManager manager = currentProgram.getFunctionManager();
        Function function = findFunction(manager, addressText);

        if (function == null) {
            printerr("No function found at or containing " + addressText);
            return;
        }

        File outputDir = new File(
            System.getProperty("user.home"),
            "Decomp/LegoCloneWarsWii/tools/ghidra/output"
        );
        outputDir.mkdirs();

        File outputFile = new File(
            outputDir,
            "function_" + function.getEntryPoint().toString() + ".json"
        );

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        DecompileResults decomp =
            decompiler.decompileFunction(function, 30, monitor);

        List<Function> callers = getCallers(function);
        List<Function> callees = getCallees(function);

        Listing listing = currentProgram.getListing();
        List<String> dataReferences = new ArrayList<>();
        List<String> strings = new ArrayList<>();
        List<String> instructions = new ArrayList<>();
        List<String> dataRefDetails = new ArrayList<>();

        InstructionIterator instructionIterator =
                listing.getInstructions(function.getBody(), true);

        while (instructionIterator.hasNext()) {
            Instruction instruction = instructionIterator.next();

            instructions.add(
                instruction.getAddress().toString() + ": " +
                instruction.toString()
            );

            Reference[] refs = instruction.getReferencesFrom();

            for (Reference ref : refs) {
                Address target = ref.getToAddress();
                String refType = ref.getReferenceType().getName();

                Data data = listing.getDefinedDataAt(target);

                if (data != null) {
                    String value = data.getValue() != null
                            ? data.getValue().toString()
                            : data.getDataType().getDisplayName();

                    String entry =
                        instruction.getAddress().toString() +
                        " -> " +
                        target.toString() +
                        ": " +
                        value;

                    if (!dataReferences.contains(entry)) {
                        dataReferences.add(entry);
                    }

                    if (data.getDataType().getDisplayName()
                            .toLowerCase().contains("string") &&
                        !strings.contains(entry)) {
                        strings.add(entry);
                    }
                }

                boolean interesting = refType.contains("READ")
                        || refType.contains("WRITE")
                        || refType.startsWith("DATA");

                if (interesting) {
                    dataRefDetails.add(
                        "{\"instruction_address\": \"" +
                        instruction.getAddress().toString() +
                        "\", \"instruction\": \"" +
                        jsonEscape(instruction.toString()) +
                        "\", \"target\": \"" +
                        target.toString() +
                        "\", \"reference_type\": \"" +
                        jsonEscape(refType) +
                        "\", \"defined\": " +
                        (data != null) +
                        "}");
                }
            }
        }

        try (FileWriter out = new FileWriter(outputFile)) {
            out.write("{\n");

            out.write("  \"program\": \"" +
                    jsonEscape(currentProgram.getName()) + "\",\n");

            out.write("  \"address\": \"" +
                    jsonEscape(function.getEntryPoint().toString()) + "\",\n");

            out.write("  \"name\": \"" +
                    jsonEscape(function.getName()) + "\",\n");

            out.write("  \"size\": " +
                    function.getBody().getNumAddresses() + ",\n");

            out.write("  \"signature\": \"" +
                    jsonEscape(function.getSignature().getPrototypeString()) +
                    "\",\n");

            out.write("  \"return_type\": \"" +
                    jsonEscape(function.getReturnType().getDisplayName()) +
                    "\",\n");

            out.write("  \"decompilation\": \"" +
                    jsonEscape(
                        decomp != null && decomp.decompileCompleted()
                            ? decomp.getDecompiledFunction().getC()
                            : "DECOMPILATION_FAILED"
                    ) +
                    "\",\n");

            out.write("  \"instructions\": [\n");

            for (int i = 0; i < instructions.size(); i++) {
                out.write("    \"" +
                        jsonEscape(instructions.get(i)) +
                        "\"");

                if (i + 1 < instructions.size()) {
                    out.write(",");
                }

                out.write("\n");
            }

            out.write("  ],\n");

            out.write("  \"data_references\": [\n");
            for (int i = 0; i < dataReferences.size(); i++) {
                out.write("    \"" +
                        jsonEscape(dataReferences.get(i)) +
                        "\"");
                if (i + 1 < dataReferences.size()) {
                    out.write(",");
                }
                out.write("\n");
            }
            out.write("  ],\n");

            out.write("  \"strings\": [\n");
            for (int i = 0; i < strings.size(); i++) {
                out.write("    \"" +
                        jsonEscape(strings.get(i)) +
                        "\"");
                if (i + 1 < strings.size()) {
                    out.write(",");
                }
                out.write("\n");
            }
            out.write("  ],\n");

            out.write("  \"data_ref_details\": [\n");
            for (int i = 0; i < dataRefDetails.size(); i++) {
                out.write("    " + dataRefDetails.get(i));
                if (i + 1 < dataRefDetails.size()) {
                    out.write(",");
                }
                out.write("\n");
            }
            out.write("  ],\n");

            out.write("  \"callers\": ");
            writeFunctionList(out, callers);
            out.write(",\n");

            out.write("  \"callees\": ");
            writeFunctionList(out, callees);
            out.write("\n");

            out.write("}\n");
        }

        decompiler.dispose();

        println("Exported context for " +
                function.getEntryPoint() +
                " (" + function.getName() + ")");

        println("Output: " + outputFile.getAbsolutePath());
    }
}
