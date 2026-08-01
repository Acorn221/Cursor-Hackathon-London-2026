/* Ghidra headless post-script: export the attack surface of a native messaging host.
 *
 * Native messaging hosts share a shape: a 4-byte little-endian length prefix
 * read from stdin, a JSON parse, an opcode dispatcher, and a handful of
 * handlers that reach OS sinks. This dumps the three things an analyst needs
 * to follow that path, so the reading happens over C rather than over a
 * disassembler UI:
 *
 *   decomp/<addr>_<name>.c   decompiled C, for every function that can reach a
 *                            dangerous sink (plus entry candidates)
 *   sinks.json               sink import -> call sites -> reverse call paths
 *   strings.json             defined strings, with the functions referencing them
 *   summary.json             counts, entry-point candidates, tool metadata
 *
 * Usage (via scripts/ghidra_decompile.py, or directly):
 *   analyzeHeadless <proj_dir> <proj> -import <binary> \
 *     -scriptPath <this dir> -postScript ExportNativeHostSurface.java <outdir> \
 *     -deleteProject
 *
 * @category NativeHost
 */

import java.io.File;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.DefinedDataIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;

public class ExportNativeHostSurface extends GhidraScript {

    /* Sinks that give C:H/I:H/A:H if attacker-controlled data reaches them.
     * Matched as a case-insensitive prefix so CreateProcessW/A both hit. */
    private static final String[] SINKS = {
        // direct execution
        "CreateProcess", "ShellExecute", "WinExec", "system", "popen", "_popen",
        "_wsystem", "execve", "execl", "execvp", "posix_spawn",
        // code loading
        "LoadLibrary", "dlopen", "CoCreateInstance", "AssemblyLoad",
        // persistence / indirect execution
        "RegSetValue", "RegCreateKey", "CreateFile", "WriteFile", "CopyFile",
        "MoveFile", "DeleteFile", "SHFileOperation", "fopen", "fwrite", "rename",
        // fetch-then-run
        "URLDownloadToFile", "InternetOpenUrl", "WinHttpConnect", "curl_easy_setopt",
        // token / credential reach
        "CryptUnprotectData", "OpenProcess", "WriteProcessMemory",
    };

    /* Reading 4 bytes then N bytes from stdin is the native messaging loop. */
    private static final String[] ENTRY_HINTS = {
        "ReadFile", "GetStdHandle", "fread", "read", "_read", "getchar",
        "std::cin", "ReadConsole",
    };

    private static final int MAX_DEPTH = 6;      // reverse call-graph depth
    private static final int MAX_FUNCS = 4000;   // decompilation budget

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ExportNativeHostSurface: need an output directory argument");
            return;
        }
        File out = new File(args[0]);
        File decompDir = new File(out, "decomp");
        decompDir.mkdirs();

        Program prog = currentProgram;
        FunctionManager fm = prog.getFunctionManager();
        ReferenceManager rm = prog.getReferenceManager();
        SymbolTable st = prog.getSymbolTable();

        // ---- 1. locate sink symbols and who calls them ---------------------
        Map<String, List<Function>> sinkCallers = new LinkedHashMap<>();
        Set<Function> interesting = new LinkedHashSet<>();

        SymbolIterator syms = st.getAllSymbols(true);
        while (syms.hasNext() && !monitor.isCancelled()) {
            Symbol s = syms.next();
            String name = s.getName();
            String matched = matchSink(name);
            if (matched == null) {
                continue;
            }
            List<Function> callers = sinkCallers.computeIfAbsent(
                    name, k -> new ArrayList<>());
            for (Reference ref : rm.getReferencesTo(s.getAddress())) {
                Function f = fm.getFunctionContaining(ref.getFromAddress());
                if (f != null && !callers.contains(f)) {
                    callers.add(f);
                    interesting.add(f);
                }
            }
        }

        // ---- 2. walk the call graph backwards from every sink caller -------
        Map<Function, Integer> depth = new LinkedHashMap<>();
        Deque<Function> queue = new ArrayDeque<>(interesting);
        for (Function f : interesting) {
            depth.put(f, 0);
        }
        while (!queue.isEmpty() && !monitor.isCancelled()) {
            Function f = queue.poll();
            int d = depth.get(f);
            if (d >= MAX_DEPTH) {
                continue;
            }
            for (Function caller : f.getCallingFunctions(monitor)) {
                if (!depth.containsKey(caller)) {
                    depth.put(caller, d + 1);
                    interesting.add(caller);
                    queue.add(caller);
                }
            }
        }

        // ---- 3. entry-point candidates: the stdin read loop ----------------
        List<Function> entries = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) {
                break;
            }
            if (callsAnyOf(f, ENTRY_HINTS)) {
                entries.add(f);
                interesting.add(f);
            }
        }

        // ---- 4. decompile everything interesting ---------------------------
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(prog);
        int written = 0;
        for (Function f : interesting) {
            if (monitor.isCancelled() || written >= MAX_FUNCS) {
                break;
            }
            DecompileResults res = decomp.decompileFunction(f, 60, monitor);
            if (res == null || !res.decompileCompleted()) {
                continue;
            }
            String safe = f.getName().replaceAll("[^A-Za-z0-9_.-]", "_");
            File cf = new File(decompDir,
                    f.getEntryPoint() + "_" + safe + ".c");
            try (PrintWriter pw = new PrintWriter(cf, "UTF-8")) {
                pw.println("// " + f.getName() + " @ " + f.getEntryPoint());
                pw.println("// reaches a sink within " + depth.getOrDefault(f, -1)
                        + " call(s); -1 = entry-point candidate");
                pw.println(res.getDecompiledFunction().getC());
            }
            written++;
        }
        decomp.dispose();

        // ---- 5. reports ----------------------------------------------------
        try (PrintWriter pw = new PrintWriter(new File(out, "sinks.json"), "UTF-8")) {
            pw.println("{");
            pw.println("  \"binary\": " + q(prog.getExecutablePath()) + ",");
            pw.println("  \"sinks\": {");
            int i = 0;
            for (Map.Entry<String, List<Function>> e : sinkCallers.entrySet()) {
                pw.print("    " + q(e.getKey()) + ": [");
                List<String> cs = new ArrayList<>();
                for (Function f : e.getValue()) {
                    cs.add("{\"function\": " + q(f.getName())
                            + ", \"entry\": " + q(f.getEntryPoint().toString())
                            + ", \"depth_to_sink\": " + depth.getOrDefault(f, 0) + "}");
                }
                pw.print(String.join(", ", cs));
                pw.println("]" + (++i < sinkCallers.size() ? "," : ""));
            }
            pw.println("  }");
            pw.println("}");
        }

        try (PrintWriter pw = new PrintWriter(new File(out, "strings.json"), "UTF-8")) {
            pw.println("[");
            List<String> rows = new ArrayList<>();
            for (Data d : DefinedDataIterator.definedStrings(prog)) {
                if (monitor.isCancelled()) {
                    break;
                }
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
                String v = sdi.getStringValue();
                if (v == null || v.length() < 4 || v.length() > 300) {
                    continue;
                }
                List<String> refs = new ArrayList<>();
                for (Reference r : rm.getReferencesTo(d.getAddress())) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    if (f != null && !refs.contains(f.getName())) {
                        refs.add(f.getName());
                    }
                }
                rows.add("  {\"addr\": " + q(d.getAddress().toString())
                        + ", \"value\": " + q(v)
                        + ", \"refs\": [" + q(String.join(",", refs)) + "]}");
            }
            pw.println(String.join(",\n", rows));
            pw.println("]");
        }

        try (PrintWriter pw = new PrintWriter(new File(out, "summary.json"), "UTF-8")) {
            pw.println("{");
            pw.println("  \"program\": " + q(prog.getName()) + ",");
            pw.println("  \"language\": " + q(prog.getLanguageID().getIdAsString()) + ",");
            pw.println("  \"functions_total\": " + fm.getFunctionCount() + ",");
            pw.println("  \"functions_decompiled\": " + written + ",");
            pw.println("  \"sink_symbols_found\": " + sinkCallers.size() + ",");
            pw.print("  \"entry_candidates\": [");
            List<String> es = new ArrayList<>();
            for (Function f : entries) {
                es.add("{\"function\": " + q(f.getName())
                        + ", \"entry\": " + q(f.getEntryPoint().toString()) + "}");
            }
            pw.println(String.join(", ", es) + "]");
            pw.println("}");
        }

        println("ExportNativeHostSurface: wrote " + written + " decompiled functions, "
                + sinkCallers.size() + " sink symbols, " + entries.size()
                + " entry candidates to " + out);
    }

    private String matchSink(String symbolName) {
        String lower = symbolName.toLowerCase();
        for (String s : SINKS) {
            if (lower.startsWith(s.toLowerCase()) || lower.contains("_" + s.toLowerCase())) {
                return s;
            }
        }
        return null;
    }

    private boolean callsAnyOf(Function f, String[] names) {
        for (Function callee : f.getCalledFunctions(monitor)) {
            String n = callee.getName().toLowerCase();
            for (String want : names) {
                if (n.contains(want.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String q(String s) {
        if (s == null) {
            return "\"\"";
        }
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.append('"').toString();
    }
}
