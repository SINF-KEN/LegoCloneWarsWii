import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;

/**
 * Finds example functions for regression tests:
 *
 *   FindFunctionsReferencing.java strings <limit>
 *   FindFunctionsReferencing.java globals <limit>
 *   FindFunctionsReferencing.java all    <limit>
 *
 * strings: functions referencing defined string data (smallest first)
 * globals: functions with direct READ/WRITE references to defined,
 *          non-string data (smallest first)
 */
public class FindFunctionsReferencing extends GhidraScript {

    private static class Hit {
        Function fn;
        Address target;
        String refType;
        String detail;

        Hit(Function fn, Address target, String refType, String detail) {
            this.fn = fn;
            this.target = target;
            this.refType = refType;
            this.detail = detail;
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "all";
        int limit = args.length > 1 ? Integer.parseInt(args[1]) : 10;

        Listing listing = currentProgram.getListing();
        FunctionIterator functions =
                currentProgram.getFunctionManager().getFunctions(true);

        List<Hit> stringHits = new ArrayList<>();
        List<Hit> globalHits = new ArrayList<>();

        while (functions.hasNext()) {
            Function fn = functions.next();

            for (Instruction ins : listing.getInstructions(fn.getBody(),
                                                           true)) {
                for (Reference ref : ins.getReferencesFrom()) {
                    String refType = ref.getReferenceType().getName();
                    if (!refType.contains("READ")
                            && !refType.contains("WRITE")
                            && !refType.startsWith("DATA")) {
                        continue;
                    }

                    Address target = ref.getToAddress();
                    Data data = listing.getDefinedDataAt(target);
                    if (data == null) {
                        continue;
                    }

                    if (data.hasStringValue()) {
                        String value = String.valueOf(data.getValue());
                        stringHits.add(new Hit(fn, target, refType,
                                "\"" + value + "\""));
                    } else {
                        globalHits.add(new Hit(fn, target, refType,
                                data.getDataType().getName()));
                    }
                }
            }
        }

        if (mode.equals("strings") || mode.equals("all")) {
            printHits("STRINGS", stringHits, limit);
        }
        if (mode.equals("globals") || mode.equals("all")) {
            printHits("GLOBALS", globalHits, limit);
        }
    }

    private void printHits(String label, List<Hit> hits, int limit) {
        println("=== " + label + " (" + hits.size() + " references) ===");

        hits.sort((a, b) -> Long.compare(
                a.fn.getBody().getNumAddresses(),
                b.fn.getBody().getNumAddresses()));

        int shown = 0;
        for (Hit hit : hits) {
            println(String.format("%s %s %s -> %s (%s) size=%d",
                    hit.fn.getEntryPoint(), hit.fn.getName(),
                    hit.refType, hit.target, hit.detail,
                    hit.fn.getBody().getNumAddresses()));
            if (++shown >= limit) {
                break;
            }
        }
    }
}
