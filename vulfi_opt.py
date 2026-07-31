from ast import expr_context
from cmath import exp
import collections
from email.policy import default
from uuid import RESERVED_FUTURE
import idaapi
import idc
import ida_ua
import os
import json
import re
import idautils
import ida_kernwin
import ida_name
import ida_hexrays
import ida_funcs
import traceback
if idaapi.IDA_SDK_VERSION >= 900:
    import ida_ida

icon_id = -1

class utils:
    def create_dummy_hexrays_const(value):
        num = ida_hexrays.cexpr_t()
        num.op = ida_hexrays.cot_num
        num.n = ida_hexrays.cnumber_t()
        num.n._value = value
        return num

    def get_negative_disass(op):
        # Get negative value based on the size of the operand
        if op.dtype == 0x0: # Byte
            return -(((op.value & 0xff) ^ 0xff) + 1)
        elif op.dtype == 0x1: # Word
            return -(((op.value & 0xffff) ^ 0xffff) + 1)
        elif op.dtype == 0x2: # Dword
            return -(((op.value & 0xffffffff) ^ 0xffffffff) + 1)
        elif op.dtype == 0x7: # Qword
            return -((op.value ^ 0xffffffffffffffff) + 1)

    def get_func_name(ea):
        # Get pretty function name
        func_name = utils.get_pretty_func_name(idc.get_func_name(ea))
        if not func_name:
            func_name = utils.get_pretty_func_name(idc.get_name(ea))
        return func_name

    def get_pretty_func_name(name):
        # Demangle function name
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        # Return as is if failed to demangle
        if not demangled_name:
            return name
        # Cut arguments
        return demangled_name[:demangled_name.find("(")]

    def prep_func_name(name):
        if name[0] != "." and name[0] != "_":
            # Name does not start with dot or underscore
            return [name,f".{name}",f"_{name}"]
        else:
            return [name[1:],f".{name[1:]}",f"_{name[1:]}"]

class null_after_visitor(ida_hexrays.ctree_visitor_t):
    def __init__(self,decompiled_function,call_xref,func_name,matched):
        self.found_call = False
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST) # CV_FAST does not keep parents nodes in CTREE
        self.decompiled_function = decompiled_function
        self.call_xref = call_xref
        self.func_name = func_name
        self.insn_counter = 0
        self.matched = matched

    def visit_insn(self, i):
        if self.found_call:
            self.insn_counter += 1
        return 0

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            xref_func_name = utils.get_func_name(e.x.obj_ea)
            if not xref_func_name:
                xref_func_name = idc.get_name(e.x.obj_ea)
            if xref_func_name.lower() == self.func_name.lower() and e.ea == self.call_xref:
                self.found_call = True
        if self.found_call and self.insn_counter < 2:
            if e.op == ida_hexrays.cot_asg:
                # The expression is assignment, check the right side of the assign
                if e.y.op == ida_hexrays.cot_num:
                    # The right side is number
                    if e.y.numval() == 0:
                        # Set to null
                        self.matched["set_to_null"] = True
        return 0



class VulFiScanner:
    DYNAMIC_RULES_FILE = "vulfi_opt_dynamic_rules.json"
    CURL_OPT_URL = 10002
    CURL_OPT_FOLLOWLOCATION = 52
    CURL_OPT_PROTOCOLS = 181
    CURL_OPT_REDIR_PROTOCOLS = 182
    CURLPROTO_GOPHER = 1 << 25
    CURLPROTO_GOPHERS = 1 << 29

    def __init__(self,custom_rules=None):

        self.functions_list = []
        if not custom_rules:
            with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"vulfi_opt_rules.json"),"r") as rules_file:
                self.rules = json.load(rules_file)
        else:
            self.rules = custom_rules
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)),"vulfi_opt_prototypes.json"),"r") as proto_file:
            self.prototypes = json.load(proto_file)
        self.load_dynamic_rules()
        # get pointer size
        if idaapi.IDA_SDK_VERSION >= 900:
            if ida_ida.inf_is_64bit():
                self.ptr_size = 8
            elif ida_ida.inf_is_32bit_exactly():
                self.ptr_size = 4
            else:
                self.ptr_size = 2
        else:
            info = idaapi.get_inf_structure()
            if info.is_64bit():
                self.ptr_size = 8
            elif info.is_32bit():
                self.ptr_size = 4
            else:
                self.ptr_size = 2
        # Get endianness
        if idaapi.IDA_SDK_VERSION >= 900:
            self.endian = "big" if ida_ida.inf_is_be() else "little"
        else:
            self.endian = "big" if idaapi.cvar.inf.is_be() else "little"
        # Check whether Hexrays can be used
        if not ida_hexrays.init_hexrays_plugin():
            self.hexrays = False
            self.strings_list = idautils.Strings()
        else:
            self.hexrays = True
            #self.strings_list = idautils.Strings()

    def load_dynamic_rules(self):
        """Load optional LLM-produced vendor-defined wrapper sink rules.

        This sidecar is for vendor-defined wrapper sinks and relatively niche
        dangerous functions defined in this program or its related firmware
        libraries, e.g. a vendor `systemCall(cmd)` wrapper around system/popen,
        a DB query wrapper, a file open/download wrapper, or a network request
        wrapper. It is not a hardcoded-secret scanner; do not scan all functions blindly.

        LLM workflow expected by this file:
        1. Start from function name/symbol hints: system/cmd/exec/run/shell,
           query/sql/db, file/open/download/upload/path, http/url/curl/request.
        2. Confirm local context or xrefs show a real dangerous operation.
        3. Identify the dangerous parameter index and whether wrapper tracking
           should be enabled.
        4. Emit normal VulFi JSON rules/prototypes only after that evidence.

        Expected sidecar shape:
        {
          "llm_guidance": {... ignored by the plugin ...},
          "rules": [VulFi rule objects],
          "prototypes": {"func_name": "ret func(args);"}
        }
        A plain list is also accepted and is treated as "rules".
        """
        dynamic_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), self.DYNAMIC_RULES_FILE)
        if not os.path.exists(dynamic_path):
            return []
        try:
            with open(dynamic_path, "r", encoding="utf-8") as rules_file:
                raw = json.load(rules_file)
            if isinstance(raw, dict):
                rules = raw.get("rules", [])
                prototypes = raw.get("prototypes", {})
            else:
                rules = raw
                prototypes = {}
            if isinstance(prototypes, dict):
                self.prototypes.update({k.lower(): v for k, v in prototypes.items()})
            loaded = []
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                if not all(k in rule for k in ["name", "function_names", "wrappers", "mark_if"]):
                    continue
                mark_if = rule.get("mark_if", {})
                if not all(k in mark_if for k in ["High", "Medium", "Low"]):
                    continue
                self.rules.append(rule)
                loaded.append(rule)
            print(f"[VulFi] Loaded {len(loaded)} dynamic LLM rule(s) from {dynamic_path}")
            return loaded
        except Exception:
            print(f"[VulFi] Failed to load dynamic rules from {dynamic_path}")
            print(traceback.format_exc())
            return []

    def start_scan(self,ignore_addr_list):
        results = []
        ida_kernwin.show_wait_box("VulFi scan running ... ")
        self.prepare_functions_list()
        for rule in self.rules:
            try:
                if rule["function_names"] == ["Array Access"]:
                    xrefs_dict = self.get_array_accesses()
                elif rule["function_names"] == ["Loop Check"]:
                    xrefs_dict = self.get_loops()
                else:
                    xrefs_dict = self.find_xrefs_by_name(rule["function_names"],rule["wrappers"])
            except:
                ida_kernwin.warning("This does not seem like a correct rule file. Aborting scan.")
                return None
            for scanned_function in xrefs_dict:
            # For each function in the rules
                skip_count = 0
                counter = 0 # For UI only
                total_xrefs = len(xrefs_dict[scanned_function]) # For UI only
                for scanned_function_xref_tuple in xrefs_dict[scanned_function]:
                    counter += 1
                    if ida_kernwin.user_cancelled():
                        print("[VulFi] Scan canceled!")
                        ida_kernwin.hide_wait_box()
                        return None
                    if skip_count > 0:
                        skip_count -= 1
                        continue
                    param = []
                    param_count = 0
                    function_call = None
                    scanned_function_xref = scanned_function_xref_tuple[0] # Address
                    scanned_function_name = scanned_function_xref_tuple[1] # Name
                    scanned_function_display_name = scanned_function_xref_tuple[2] # Display Name
                    # Update progress bar
                    ida_kernwin.replace_wait_box(f"Scanning {scanned_function_display_name} ({counter}/{total_xrefs})")
                    # If this rule is already verified for this address, move on
                    if f"{rule['name']}_{hex(scanned_function_xref)}" in ignore_addr_list:
                        continue
                    # For each xref to the function in the rules
                    # If ida_hexrays can be used eval the conditions in the rules file
                    if rule["function_names"] == ["Array Access"]:
                        param = [VulFiScanner.Param(self,scanned_function_xref_tuple[3],scanned_function_xref,scanned_function_name),VulFiScanner.Param(self,scanned_function_xref_tuple[4],scanned_function_xref,scanned_function_name)]
                    elif rule["function_names"] == ["Loop Check"]:
                        param = [VulFiScanner.Param(self,scanned_function_xref_tuple[3],scanned_function_xref,scanned_function_name),VulFiScanner.Param(self,scanned_function_xref_tuple[4],scanned_function_xref,scanned_function_name)]
                    else:
                        params_raw = self.get_xref_parameters(scanned_function_xref,scanned_function_name)
                        if params_raw is None:
                            if self.hexrays:
                                # Likely decompiler failure, we have to skip
                                continue
                            else:
                                # Params were not found, lets mark all XREFS
                                params_raw = []
                        for p in params_raw:
                            param.append(VulFiScanner.Param(self,p,scanned_function_xref,scanned_function_name))
                        param_count = len(param)

                    function_call = VulFiScanner.FunctionCall(self,scanned_function_xref,scanned_function_name)
                    # Name of the function where the xref is located
                    found_in_name = utils.get_func_name(scanned_function_xref)
                    priority = ""
                    # Every xref will be marked as Info in case that params fetch fails
                    try:
                        if not param:
                            priority = "Info"
                        elif eval(rule["mark_if"]["High"],dict(self=self, param=param,param_count=param_count,function_call=function_call)):
                            priority = "High"
                        elif eval(rule["mark_if"]["Medium"],dict(self=self, param=param,param_count=param_count,function_call=function_call)):
                            priority = "Medium"
                        elif eval(rule["mark_if"]["Low"],dict(self=self, param=param,param_count=param_count,function_call=function_call)):
                            priority = "Low"

                    except IndexError:
                        # Decompiler output has fewer parameters than the function prototype
                        # Mark the issue with Info priority
                        priority = "Info"
                        #results.append(list(VulFi.result_window_row(rule["name"],scanned_function_display_name,found_in_name,hex(scanned_function_xref),"Not Checked","Low","")))
                    except Exception:
                        print(traceback.format_exc())
                        ida_kernwin.warning(f"The rule \"{rule}\" is not valid!")
                        continue
                    # If the rule matched and is not wrapped:
                    #if priority and found_in_name and not "wrapped" in scanned_function_display_name:
                    if priority and not "wrapped" in scanned_function_display_name:
                        results.append(list(VulFi.result_window_row(rule["name"],scanned_function_display_name,found_in_name,hex(scanned_function_xref),"Not Checked",priority,"")))
                    elif "wrapped" in scanned_function_display_name and priority:
                        skip_count = 0 # rule for the wrapped function matched so no need to skip calls to the wrapper
                    elif "wrapped" in scanned_function_display_name and priority == "":
                        # Rule for wrapped function did not match, skip the wrapper
                        skip_count = int(scanned_function_display_name[scanned_function_display_name.find("wrapped:") + 8:-1])
        try:
            results.extend(self.get_network_request_sinks(ignore_addr_list))
        except Exception:
            print("[VulFi] Network request sink engine failed")
            print(traceback.format_exc())
        ida_kernwin.hide_wait_box()
        return results

    def _issue_ignored(self, ignore_addr_list, issue_name, addr):
        return f"{issue_name}_{hex(addr)}" in ignore_addr_list or f"{issue_name}_{addr}" in ignore_addr_list

    def _make_result_row(self, issue_name, function_name, found_in, addr, priority, comment=""):
        return list(VulFi.result_window_row(issue_name, function_name, found_in, hex(addr), "Not Checked", priority, comment))

    def _prepared_names(self, names):
        prepared = []
        for name in names:
            prepared.extend([n.lower() for n in utils.prep_func_name(name)])
        return prepared

    def _expr_number_value(self, expr, call_xref=None, scanned_function=""):
        try:
            return VulFiScanner.Param(self, expr, call_xref or idc.BADADDR, scanned_function).number_value()
        except Exception:
            return None

    def _protocol_allows_gopher(self, protocols_value):
        if protocols_value is None:
            return True
        try:
            protocols_value = int(protocols_value)
        except Exception:
            return True
        if protocols_value < 0 or protocols_value in [0xffffffff, 0xffffffffffffffff]:
            return True
        return bool(protocols_value & (self.CURLPROTO_GOPHER | self.CURLPROTO_GOPHERS))

    def curl_wrapper_profile(self, perform_ea):
        profile = {"url_set": False, "followlocation": None, "protocols": None, "redir_protocols": None, "setopt_count": 0}
        if not self.hexrays:
            return profile
        try:
            decompiled_function = ida_hexrays.decompile(perform_ea)
        except Exception:
            return profile
        if decompiled_function is None:
            return profile
        setopt_names = self._prepared_names(["curl_easy_setopt"])
        for citem in decompiled_function.treeitems:
            if citem.op != ida_hexrays.cot_call:
                continue
            try:
                callee = utils.get_func_name(citem.to_specific_type.x.obj_ea)
                if not callee:
                    callee = idc.get_name(citem.to_specific_type.x.obj_ea)
                if not callee or callee.lower() not in setopt_names:
                    continue
                args = list(citem.to_specific_type.a)
                if len(args) < 2:
                    continue
                opt = self._expr_number_value(args[1], citem.ea, callee)
                val = self._expr_number_value(args[2], citem.ea, callee) if len(args) > 2 else None
                profile["setopt_count"] += 1
                if opt == self.CURL_OPT_URL:
                    profile["url_set"] = True
                elif opt == self.CURL_OPT_FOLLOWLOCATION:
                    profile["followlocation"] = val
                elif opt == self.CURL_OPT_PROTOCOLS:
                    profile["protocols"] = val
                elif opt == self.CURL_OPT_REDIR_PROTOCOLS:
                    profile["redir_protocols"] = val
            except Exception:
                continue
        return profile

    def get_network_request_sinks(self, ignore_addr_list):
        rows = []
        xrefs_dict = self.find_xrefs_by_name(["curl_easy_perform", "curl_multi_perform"], False)
        seen_funcs = set()
        for scanned_function in xrefs_dict:
            for xref_ea, xref_name, display_name in xrefs_dict[scanned_function]:
                func = idaapi.get_func(xref_ea)
                if not func or func.start_ea in seen_funcs:
                    continue
                seen_funcs.add(func.start_ea)
                found_in = utils.get_func_name(func.start_ea) or idc.get_name(func.start_ea) or hex(func.start_ea)
                issue_name = "SSRF Network Request Sink"
                if self._issue_ignored(ignore_addr_list, issue_name, xref_ea):
                    continue
                profile = self.curl_wrapper_profile(xref_ea)
                follows_redirect = profile.get("followlocation") not in [None, 0]
                redir_allows_gopher = self._protocol_allows_gopher(profile.get("redir_protocols"))
                direct_allows_gopher = self._protocol_allows_gopher(profile.get("protocols"))
                priority = "High" if follows_redirect and redir_allows_gopher else "Low"
                comment = (f"curl wrapper; url_set={profile.get('url_set')}; FOLLOWLOCATION={profile.get('followlocation')}; "
                           f"PROTOCOLS={profile.get('protocols')}; REDIR_PROTOCOLS={profile.get('redir_protocols')}; "
                           f"gopher_direct={direct_allows_gopher}; gopher_redirect={redir_allows_gopher}")
                rows.append(self._make_result_row(issue_name, display_name, found_in, xref_ea, priority, comment))
        return rows

    def get_loops(self):
         # Use the trick to extract loop paramters as members of the tuple
         # param[0] will be the counter variable and param[1] will be the check value
         loop_check_list = {"Loop Check":[]}
         if self.hexrays:
            for func in self.functions_list:
                try:
                    decompiled_function = ida_hexrays.decompile(func)
                    if decompiled_function is None:
                        # Decompilation failed
                        return loop_check_list
                    code = decompiled_function.pseudocode
                    for tree_item in decompiled_function.treeitems:
                        if tree_item.op == ida_hexrays.cit_while:
                            #print(f"[*] Found 'while' loop at: {hex(tree_item.ea)} ({ida_name.get_ea_name(func)})")
                            op = tree_item.to_specific_type.cwhile.expr.op
                            if (op >= ida_hexrays.cot_land and op <= ida_hexrays.cot_ult) or op in [ida_hexrays.cot_var, ida_hexrays.cot_lnot]:
                                # Not an infinte loop
                                counter, check_val = self.parse_condition(tree_item.to_specific_type.cwhile.expr)
                                loop_check_list["Loop Check"].append((tree_item.ea,"Loop Check","Loop Check",counter,check_val))
                            else:
                                counter, check_val = self.get_loop_check_val_break(tree_item.to_specific_type.cwhile.body)
                                loop_check_list["Loop Check"].append((tree_item.ea,"Loop Check","Loop Check",counter,check_val))
                        elif tree_item.op == ida_hexrays.cit_for:
                            #print(f"[*] Found 'for' loop at: {hex(tree_item.ea)} ({ida_name.get_ea_name(func)})")
                            if tree_item.to_specific_type.cfor.expr.op == ida_hexrays.cot_empty:
                                # Handle endless FOR loop
                                body = tree_item.to_specific_type.cfor.body
                                counter, check_val = self.get_loop_check_val_break(body)
                                loop_check_list["Loop Check"].append((tree_item.ea,"Loop Check","Loop Check",counter,check_val))
                            else:
                                counter = tree_item.to_specific_type.cfor.init.x
                                loop_check_list["Loop Check"].append((tree_item.ea,"Loop Check","Loop Check",counter,self.get_loop_check_val(counter,tree_item.to_specific_type.cfor.expr)))
                        elif tree_item.op == ida_hexrays.cit_do:
                            op = tree_item.to_specific_type.cdo.expr.op
                            if op >= ida_hexrays.cot_land and op <= ida_hexrays.cot_ult or op in [ida_hexrays.cot_var, ida_hexrays.cot_lnot]:
                                # Not an infinte loop
                                counter, check_val = self.parse_condition(tree_item.to_specific_type.cdo.expr)
                                loop_check_list["Loop Check"].append((tree_item.ea,"Loop Check","Loop Check",counter,check_val))
                            else:
                                counter, check_val = self.get_loop_check_val_break(tree_item.to_specific_type.cdo.body)
                                loop_check_list["Loop Check"].append((tree_item.ea,"Loop Check","Loop Check",counter,check_val))
                except Exception as e:
                    print(e)

         return loop_check_list
    
    def parse_condition(self,condition):
        if condition.op == ida_hexrays.cot_lnot:
            #(!x)
            return condition.x, utils.create_dummy_hexrays_const(0)
        if condition.op == ida_hexrays.cot_var or condition.op == ida_hexrays.cot_call or condition.op == ida_hexrays.cot_cast:
            #(x)
            return condition.x, utils.create_dummy_hexrays_const(1)
        if condition.op >= ida_hexrays.cot_eq and condition.op <= ida_hexrays.cot_ult:
            #(x > y)
            return condition.x, condition.y
        if condition.op == ida_hexrays.cot_lor or condition.op == ida_hexrays.cot_land:
            x_cond = self.parse_condition(condition.x)
            y_cond = self.parse_condition(condition.y)
            if y_cond[1].n:
                return y_cond
            return x_cond
    
    def get_loop_check_val(self,counter,comparison):
        x,y = self.parse_condition(comparison)
        if x == counter:
            return y
        # IDA places constant into the y operand for normal comparisons, for everything else we should return X to avoid marking that as a const
        return x

    def get_loop_check_val_break(self,loop_body):
        bd = loop_body.cblock.begin()
        while bd != loop_body.cblock.end():
            if bd.cur.op == ida_hexrays.cit_if:
                break_if = self.find_break(bd.cur.cif)
                if break_if:
                    return self.parse_condition(break_if.expr)
            bd.next()
        
        return None, None

    def find_break(self,if_insn):
        # TODO switch-case
        bt = if_insn.ithen.cblock.begin()
        while bt != if_insn.ithen.cblock.end():
            if bt.cur.op == ida_hexrays.cit_if:
                found_breaks = self.find_break(bt.cur.cif)
                if found_breaks:
                    return found_breaks
            elif bt.cur.op == ida_hexrays.cit_break or bt.cur.op == ida_hexrays.cit_return:
                return if_insn
            bt.next()
            
        if if_insn.ielse:  
            be = if_insn.ielse.cblock.begin()
            while be != if_insn.ielse.cblock.end():
                if be.cur.op == ida_hexrays.cit_if:
                    found_breaks = self.find_break(be.cur.cif)
                    if found_breaks:
                        return found_breaks
                elif be.cur.op == ida_hexrays.cit_break or bt.cur.op == ida_hexrays.cit_return:
                    return if_insn
                be.next()
        return None

    
    def get_array_accesses(self):
        array_access_list = {"Array Access":[]}
        if self.hexrays:
            for func in self.functions_list:
                try:
                    decompiled_function = ida_hexrays.decompile(func)
                    if decompiled_function is None:
                    # Decompilation failed
                        return array_access_list
                    code = decompiled_function.pseudocode
                    for citem in decompiled_function.treeitems:
                        if citem.op == ida_hexrays.cot_idx:
                            # Uses a trick by adding the index expression as a hidden 4th member of tuple
                            array_access_list["Array Access"].append((citem.ea,"Array Access","Array Access",citem.to_specific_type.x,citem.to_specific_type.y))
                except Exception as e:
                    pass
        return array_access_list

    def prepare_functions_list(self):
        self.functions_list = []
        # Gather all functions in all segments
        for segment in idautils.Segments():
            self.functions_list.extend(list(idautils.Functions(idc.get_segm_start(segment),idc.get_segm_end(segment))))

        # Gather imports
        def imports_callback(ea, name, ordinal):
            self.functions_list.append(ea)
            return True

        # For each import
        number_of_imports = idaapi.get_import_module_qty()
        for i in range(0, number_of_imports):
            idaapi.enum_import_names(i, imports_callback)

    # Returns a list of all xrefs to the function with specified name
    def find_xrefs_by_name(self,func_names,wrappers):
        xrefs_list = {}
        insn = ida_ua.insn_t()
        function_names = []
        for name in func_names:
            function_names.extend(utils.prep_func_name(name))

        # Convert function names to expected format (demangle them if possible)
        function_names = list(map(utils.get_pretty_func_name, function_names))

        # For all addresses of functions and imports check if it is function we are looking for
        for function_address in self.functions_list:
            current_function_name = utils.get_func_name(function_address)
            if not current_function_name:
                current_function_name = ida_name.get_ea_name(function_address)
            # If the type is not defined and the name of the function is known set the type
            prototype = self.prototypes.get(current_function_name.lower(), None)
            if prototype is not None:
                idc.SetType(function_address, prototype)
                idaapi.auto_wait()


            # Seach function "as is" and "ingnore case"
            if current_function_name not in function_names:
                current_function_name = current_function_name.lower()
                if current_function_name not in function_names:
                    continue

            # This is the function we are looking for
            if current_function_name not in xrefs_list.keys():
                xrefs_list[current_function_name] = []
            for xref in idautils.XrefsTo(function_address):
                # This rules out any functions within those that we are already looking at (wrapped)
                # It also makes sure that functions that are not xrefed within another function are not displayed
                xref_func_name = utils.get_func_name(xref.frm)
                if not xref_func_name or xref_func_name.lower() in function_names:
                    continue
                # Make sure that the instrution is indeed a call
                if ida_ua.decode_insn(insn,xref.frm) != idc.BADADDR:
                    if (insn.get_canon_feature() & 0x2 == 0x2 or # The instruction is a call
                    (insn.get_canon_feature() & 0xfff == 0x100 and insn.Op1.type in [idc.o_near,idc.o_far])): # The instruction uses first operand which is of type near/far immediate address
                        xref_tuple = (xref.frm,current_function_name,current_function_name)
                        if wrappers:
                            # If we should look for wrappers, do not includ the wrapped xref
                            retrieved_wrappers = self.get_wrapper_xrefs(xref.frm,current_function_name)
                            if not retrieved_wrappers:
                                # No wrappers
                                if not xref_tuple in xrefs_list[current_function_name]:
                                    xrefs_list[current_function_name].append(xref_tuple)
                            else:
                                # Wrappers were found
                                wrapped_tupple = (xref_tuple[0],xref_tuple[1],f"{xref_tuple[2]} (wrapped:{len(retrieved_wrappers)})")
                                xrefs_list[current_function_name].append(wrapped_tupple) # this makes sure that the wrapped function is right before its wrappers
                                xrefs_list[current_function_name].extend(retrieved_wrappers)
                        else:
                            if not xref_tuple in xrefs_list[current_function_name]:
                                xrefs_list[current_function_name].append(xref_tuple)
        return xrefs_list

    # Check if the xref can be a wrapper
    def get_wrapper_xrefs(self,xref,current_function_name):
        if self.hexrays:
            # Hexrays avaialble, we can use decompiler
            return self.get_wrapper_xrefs_hexrays(xref,current_function_name)
        else:
            # Hexrays not available, decompiler cannot be used
            return self.get_wrapper_xrefs_disass(xref)

    def get_wrapper_xrefs_hexrays(self,function_xref,current_function_name):
        wrapper_xrefs = []
        try:
            decompiled_function = ida_hexrays.decompile(function_xref)
        except:
            return wrapper_xrefs
        if decompiled_function:
            if decompiled_function is None:
                # Decompilation failed
                return wrapper_xrefs
            # Decompilation is fine
            code = decompiled_function.pseudocode
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea == function_xref and tree_item.op == ida_hexrays.cot_call:
                    # Get called function name
                    xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if not xref_func_name:
                        xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if xref_func_name == current_function_name.lower():
                        # This is the correct call
                        lvars = list(decompiled_function.get_lvars()) # Get lvars
                        arg_objects = list(tree_item.to_specific_type.a)
                        found = True
                        while arg_objects:
                            current_obj = arg_objects.pop(0)
                            if current_obj is None:
                                continue
                            if current_obj.op == ida_hexrays.cot_var:
                                # if variable is not an arg_var we do not have a wrapper
                                if not lvars[current_obj.v.idx].is_arg_var:
                                    found = False
                            else:
                                arg_objects.extend([current_obj.to_specific_type.x,current_obj.to_specific_type.y])
                        # The function is likely a wrapper, get XREFs to it
                        if found:
                            for wrapper_xref in idautils.XrefsTo(decompiled_function.entry_ea):
                                wrapper_xref_func_name = utils.get_func_name(decompiled_function.entry_ea)
                                wrapper_xrefs.append((wrapper_xref.frm,wrapper_xref_func_name,f"{wrapper_xref_func_name} ({current_function_name} wrapper)"))
        return wrapper_xrefs


    # There probably is no architecture-agnostic way on how to do this without decompiler
    def get_wrapper_xrefs_disass(self,xref):
        return []

    # Wrapper for getting function params
    def get_xref_parameters(self,function_xref,scanned_function):
        if self.hexrays:
            # Hexrays avaialble, we can use decompiler
            return self.get_xref_parameters_hexrays(function_xref,scanned_function)
        else:
            # Hexrays not available, decompiler cannot be used
            return self.get_xref_parameters_disass(function_xref)

    # Returns list of ordered paramters from disassembly
    def get_xref_parameters_disass(self,function_xref):
        params_list = []
        # Requires the type to be already assigned to functions
        try:
            for param_ea in idaapi.get_arg_addrs(function_xref):
                if param_ea != idc.BADADDR:
                    param_insn = ida_ua.insn_t()
                    # decode the instruction linked to the parameter
                    if ida_ua.decode_insn(param_insn,param_ea) != idc.BADADDR:
                        if param_insn.get_canon_feature() & 0x00100 == 0x100:
                            # First operand - push
                            params_list.append(param_insn.Op1)
                        elif param_insn.get_canon_feature() & 0x00200 == 0x200:
                            # Second operands - mov/lea
                            params_list.append(param_insn.Op2)
                        elif param_insn.get_canon_feature() & 0x00400 == 0x400:
                            # Third operand
                            params_list.append(param_insn.Op3)
        except:
            return None
        return params_list

    # Returns an ordered list of workable object that represent each parameter of the function from decompiled code
    def get_xref_parameters_hexrays(self,function_xref,scanned_function):
        # Decompile function and find the call
        try:
            decompiled_function = ida_hexrays.decompile(function_xref)
        except:
            return None
        if decompiled_function is None:
            # Decompilation failed
            return None
        index = 0
        code = decompiled_function.pseudocode
        for tree_item in decompiled_function.treeitems:
            if tree_item.ea == function_xref and tree_item.op == ida_hexrays.cot_call:
                xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                if not xref_func_name:
                    xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                if xref_func_name == scanned_function.lower():
                    return list(tree_item.to_specific_type.a)
            index += 1
        # Call not found :(
        return None

    class Param:
        def __init__(self,scanner,param,call_xref,scanned_function):
            self.scanner_instance = scanner
            self.param = param
            self.call_xref = call_xref
            self.scanned_function = scanned_function

        def size(self):
            if self.scanner_instance.hexrays:
                return self.size_hexrays()
            else:
                return None
            
        def size_hexrays(self):
            try:
                if self.param.op == ida_hexrays.cot_cast:
                    param = self.param.x
                else:
                    param = self.param
                decompiled_function = ida_hexrays.decompile(self.call_xref)
                if decompiled_function is None:
                    # Decompilation failed
                    return None
                if decompiled_function:
                    code = decompiled_function.pseudocode
                    return decompiled_function.lvars[param.v.idx].width 
                return None
            except AttributeError:
                return None


        def used_as_index(self):
            if self.scanner_instance.hexrays:
                return self.used_as_index_hexrays()
            else:
                return False
            
        def used_as_index_hexrays(self):
            decompiled_function = ida_hexrays.decompile(self.call_xref)
            if decompiled_function is None:
                # Decompilation failed
                return False
            if decompiled_function:
                code = decompiled_function.pseudocode
                for citem in decompiled_function.treeitems:
                    if citem.op == ida_hexrays.cot_idx:
                        if self.param is not None:
                            if citem.to_specific_type.y == self.param:
                                return True
            return False

        def is_constant(self):
            if self.string_value() == "" and self.number_value() == None:
                if self.scanner_instance.hexrays and self.param and self.param.op == ida_hexrays.cot_ref:
                    return False
                asgs = self.__get_var_assignments()
                if asgs: # asgs will be empty with no hexrays
                    for asg in asgs:
                        if self.__is_before_call(asg.ea):
                            if self.string_value(asg.y) == "" and self.number_value(asg.y) == None:
                                # One of the assigns is non-const
                                return False
                    return True
                return False
            else:
                return True

        # Returns True if the param is used in any function call specified in the "function_list" parameter
        def used_in_call_before(self,function_list):
            if self.scanner_instance.hexrays:
                return self.used_in_call_before_hexrays(function_list)
            else:
                return self.used_in_call_before_disass(function_list)

        def used_in_call_before_hexrays(self,function_list):
            # get all calls with the parameter
            calls = self.__get_var_arg_calls()
            # prep function list
            tmp_fun_list = []
            for fun in function_list:
                tmp_fun_list.extend(utils.prep_func_name(fun))
            for call in calls:
                if utils.get_func_name(call.x.obj_ea) in tmp_fun_list and self.__is_before_call(call.ea):
                    return True
            return False

        def used_in_call_before_disass(self,function_list):
            return False

        def used_in_call_after(self,function_list):
            if self.scanner_instance.hexrays:
                return self.used_in_call_after_hexrays(function_list)
            else:
                return self.used_in_call_after_disass(function_list)

        def used_in_call_after_hexrays(self,function_list):
            # get all calls with the parameter
            calls = self.__get_var_arg_calls()
            # prep function list
            tmp_fun_list = []
            for fun in function_list:
                tmp_fun_list.extend(utils.prep_func_name(fun))
            for call in calls:
                if utils.get_func_name(call.x.obj_ea) in tmp_fun_list and not self.__is_before_call(call.ea):
                    return True
            return False
        
        def is_sign_compared(self):
            if self.scanner_instance.hexrays:
                return self.is_sign_compared_hexrays()
            else:
                return False


        def is_sign_compared_hexrays(self):
            decompiled_function = ida_hexrays.decompile(self.call_xref)
            if decompiled_function is None:
                # Decompilation failed
                return False
            if decompiled_function:
                code = decompiled_function.pseudocode
                for citem in decompiled_function.treeitems:
                    if citem.ea == self.call_xref:
                        parent = decompiled_function.body.find_parent_of(citem)
                        while parent:
                            if parent.op == ida_hexrays.cit_if:
                                comps = self.__get_signed_comparisons(parent)
                                if self.__is_var_used_in_comparison(comps):
                                    return True
                            parent = decompiled_function.body.find_parent_of(parent)
            return False
        
        def __is_var_used_in_comparison(self,comp_list):
            if self.param.op == ida_hexrays.cot_cast:
                param = self.param.x
            else:
                param = self.param
            ops = comp_list.copy()
            while ops:
                op = ops.pop()
                if not op:
                    continue
                if param == op:
                    return True
                ops.extend([op.x,op.y])
            return False
        
        def __get_signed_comparisons(self,citem):
            signed_comparisons = []
            signed_ops = [ida_hexrays.cot_sge, ida_hexrays.cot_sle, ida_hexrays.cot_sgt, ida_hexrays.cot_slt]
            exprs = [citem.to_specific_type.cif.expr]
            while exprs:
                expr = exprs.pop()
                if not expr:
                    continue
                if expr.op in signed_ops:
                    signed_comparisons.append(expr)
                else:
                    exprs.extend([expr.x,expr.y])
            return signed_comparisons


        def used_in_call_after_disass(self,function_list):
            return False

        # Simple check whether the given EA is before the call
        def __is_before_call(self,ea):
            func = idaapi.get_func(ea)
            flow = idaapi.FlowChart(func)
            call_block = None
            asg_block = None
            checked_blocks = []
            # Get block of the assignemnt and block of the call
            for block in flow:
                if ea >= block.start_ea and ea <= block.end_ea:
                    asg_block = block
                if self.call_xref >= block.start_ea and self.call_xref <= block.end_ea:
                    call_block = block
                    checked_blocks.append(block.start_ea)
            # If they are in the same block and asg ea is smaller then call_xref ea return True
            if call_block == asg_block:
                if ea < self.call_xref:
                    return True
            else:
                # Blocks are different
                call_preds = list(call_block.preds())
                while call_preds:
                    current_pred = call_preds.pop(0)
                    # Prevent endless loops
                    if current_pred.start_ea in checked_blocks:
                        continue
                    checked_blocks.append(current_pred.start_ea)
                    # Check if we matched the given assign block
                    if current_pred.start_ea == asg_block.start_ea:
                        return True
                    call_preds.extend(list(current_pred.preds()))
            return False

        def __get_var_arg_calls(self):
            calls = []
            # Parameter is cast, get x
            if self.param.op == ida_hexrays.cot_cast:
                param = self.param.x
            else:
                param = self.param
            decompiled_function = ida_hexrays.decompile(self.call_xref)
            if decompiled_function is None:
                # Decompilation failed
                return calls
            code = decompiled_function.pseudocode
            for citem in decompiled_function.treeitems:
                if citem.op == ida_hexrays.cot_call and citem.ea != self.call_xref: # skip calls we are tracing
                    # Potentially interesting call
                    for a in citem.to_specific_type.a:
                        expressions = [a,a.x,a.y,a.z]
                        while expressions:
                            current_expr = expressions.pop(0)
                            if current_expr:
                                if param == current_expr:
                                    # Call operation, add to array
                                    calls.append(citem.to_specific_type)
                                    break # we can break the loop as the variable was found within the arguments
                                expressions.extend([current_expr.x, current_expr.y, current_expr.z])
            return calls

        # Returns list of assign expressions for better accuracy
        def __get_var_assignments(self):
            asg = []
            # Parameter is cast, get x
            if self.param.op == ida_hexrays.cot_cast:
                param = self.param.x
            else:
                param = self.param
            decompiled_function = ida_hexrays.decompile(self.call_xref)
            if decompiled_function is None:
                # Decompilation failed
                return None
            code = decompiled_function.pseudocode
            for citem in decompiled_function.treeitems:
                if param == citem.to_specific_type:
                    parent = decompiled_function.body.find_parent_of(citem)
                    if parent.op >= ida_hexrays.cot_asg and parent.op <= ida_hexrays.cot_asgumod:
                        # Assign operation, add to array
                        asg.append(parent.to_specific_type)
            return asg

        def string_value(self,expr=None):
            if not expr:
                expr = self.param
            if not expr:
                return None
            if self.scanner_instance.hexrays: # hexrays
                string_val = idc.get_strlit_contents(expr.obj_ea)
                if string_val:
                    return string_val.decode()
                # If it is a cast (could happen)
                elif expr.op == ida_hexrays.cot_cast:
                    # If casted op is object
                    if expr.x.op == ida_hexrays.cot_obj:
                        # If that object points to a string
                        string_val = idc.get_strlit_contents(expr.x.obj_ea)
                        if string_val:
                            return string_val.decode()
                elif expr.op == ida_hexrays.cot_ref:
                    string_val = idc.get_strlit_contents(expr.x.obj_ea)
                    if string_val:
                        return string_val.decode()
                    if expr.x.op == ida_hexrays.cot_idx:
                        string_val = idc.get_strlit_contents(expr.x.x.obj_ea)
                        if string_val:
                            return string_val.decode()
                    # Check whether we are looking at CFString
                    if expr.x.obj_ea != idc.BADADDR:
                        c_str_pointer_value = idc.get_bytes(expr.x.obj_ea +  2* self.scanner_instance.ptr_size, self.scanner_instance.ptr_size)
                        tmp_ea = int.from_bytes(c_str_pointer_value,byteorder=self.scanner_instance.endian)
                        c_str_len = int.from_bytes(idc.get_bytes(expr.x.obj_ea +  3* self.scanner_instance.ptr_size, self.scanner_instance.ptr_size),byteorder=self.scanner_instance.endian)
                        c_string_value = idc.get_strlit_contents(tmp_ea)
                        # Having a string at this position and its length following the pointer suggests CFString struct
                        if c_string_value and len(c_string_value) == c_str_len:
                            # If this evaluates to string we have a constant
                            return c_string_value.decode()
                else:
                    # not a direct string
                    byte_value = idc.get_bytes(expr.obj_ea,self.scanner_instance.ptr_size)
                    if byte_value:
                        tmp_ea = int.from_bytes(byte_value,byteorder=self.scanner_instance.endian)
                        string_val = idc.get_strlit_contents(tmp_ea)
                        if string_val:
                            # If this evaluates to string we have a constant
                            return string_val.decode()
            else: # No hexrays
                if expr.type == 0x2:
                    # Reference
                    if idc.get_strlit_contents(expr.addr):
                        return idc.get_strlit_contents(expr.addr).decode()
                    else:
                        # Reference to reference
                        addr = int.from_bytes(idc.get_bytes(expr.addr, self.scanner_instance.ptr_size),byteorder=self.scanner_instance.endian)
                        if idc.get_strlit_contents(addr):
                            return idc.get_strlit_contents(addr).decode()

                if expr.type == 0x5:
                    if idc.get_strlit_contents(expr.value):
                        return idc.get_strlit_contents(expr.value).decode()
                # Reverse appoach of going from strings to calls
                for c_string in self.scanner_instance.strings_list:
                    for str_xref in idautils.XrefsTo(c_string.ea):
                        func = idaapi.get_func(str_xref.frm)
                        if func:
                            if func.start_ea == idaapi.get_func(self.call_xref).start_ea:
                                # The xref and the call are in the same function
                                # look if those are used within 5 instructions
                                if (str_xref.frm < self.call_xref):
                                    # XREF to STR is before the call to XREF
                                    instr_list = list(idautils.Heads(str_xref.frm,self.call_xref))
                                    if len(instr_list) <= 10:
                                        # No more then 10 instructions between the str XREF and the call
                                        for head in instr_list:
                                            current_insn = ida_ua.insn_t()
                                            if ida_ua.decode_insn(current_insn,head) != idc.BADADDR:
                                                if head != self.call_xref and current_insn.get_canon_feature() & 0x2 == 0x2:
                                                    # If it is not a target call but it is a call its false
                                                    return ""
                                        # If we survived the loop it is True
                                        return str(c_string)
            return ""

        def number_value(self,expr=None):
            if not expr:
                expr = self.param
            if not expr:
                return None
            if self.scanner_instance.hexrays: # hexrays
                # If it is number directly
                if expr.op == ida_hexrays.cot_num:
                    return expr.n._value
                # if it is a float
                elif expr.op == ida_hexrays.cot_fnum:
                    return expr.fpc.fnum.float
                # If it is a cast
                elif expr.op == ida_hexrays.cot_cast:
                    if expr.x.op == ida_hexrays.cot_num:
                        return expr.x.n._value
                    elif expr.x.op == ida_hexrays.cot_fnum:
                        return expr.x.fpc.fnum.float
            else: # No hexrays
                # self.param is op_t
                # 0x5 is immediate
                if expr.type == 0x5:
                    return expr.value
            return None

        def is_const_number(self,expr=None):
            if not expr:
                expr = self.param
            if self.scanner_instance.hexrays:
                if expr.op == ida_hexrays.cot_num or expr.op == ida_hexrays.cot_fnum:
                    return True
                elif expr.op == ida_hexrays.cot_cast and expr.x.op == ida_hexrays.cot_num:
                    return True
            else:
                if expr.type == 0x5:
                    return True
            return False

        # Wrapper for the basic UAF filter
        def set_to_null_after_call(self):
            if self.scanner_instance.hexrays:
                # Hexrays avaialble, we can use decompiler
                return self.set_to_null_after_call_hexrays()
            else:
                # Hexrays not available, decompiler cannot be used
                return self.set_to_null_after_call_disass()

        # Simple function that just checks whether the call is followed by an isntruction that sets the parameter to null
        # Note that this is very primitive to keep sort of architecture agnostic approach
        def set_to_null_after_call_disass(self):
            call_insn = ida_ua.insn_t()
            following_insn = ida_ua.insn_t()
            # First get the call instruction
            if ida_ua.decode_insn(call_insn,self.call_xref) != idc.BADADDR:
                # Now use the call instruction to get EA of next insn
                if ida_ua.decode_insn(following_insn,call_insn.ea + call_insn.size) != idc.BADADDR:
                    # following_insn can be used to evaluate whether Op2 is a constant or not
                    if following_insn.Op2.type == 0x5 and following_insn.Op2.value == 0x0:
                        # This should cover most of the cases where a mov instuction is used
                        return True
            return False

        # Using hexrays to figure out whether the function was followed by a null-set
        def set_to_null_after_call_hexrays(self):
            # get size of the call instruction, go past it and get expression that is linked to that address?
            matched = {"set_to_null":False}
            try:
                decompiled_function = ida_hexrays.decompile(self.call_xref)
            except:
                return matched["set_to_null"]
            if decompiled_function is None:
                # Decompilation failed
                return None
            custom_visitor = null_after_visitor(decompiled_function,self.call_xref,self.scanned_function,matched)
            custom_visitor.apply_to(decompiled_function.body, None)

            return matched["set_to_null"]



    class FunctionCall:
        def __init__(self,scanner,call_xref,scanned_function):
            self.scanner_instance = scanner
            self.call_xref = call_xref
            self.scanned_function = scanned_function

        def _decompile(self):
            if not self.scanner_instance.hexrays:
                return None
            try:
                return ida_hexrays.decompile(self.call_xref)
            except Exception:
                return None

        def _call_and_args(self):
            decompiled_function = self._decompile()
            if decompiled_function is None:
                return None, []
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea == self.call_xref and tree_item.op == ida_hexrays.cot_call:
                    try:
                        callee = utils.get_func_name(tree_item.to_specific_type.x.obj_ea)
                        if not callee:
                            callee = idc.get_name(tree_item.to_specific_type.x.obj_ea)
                        if callee and callee.lower() == self.scanned_function.lower():
                            return decompiled_function, list(tree_item.to_specific_type.a)
                    except Exception:
                        continue
            return decompiled_function, []

        def _expr_text(self, expr):
            try:
                return str(expr)
            except Exception:
                return ""

        def _function_text(self):
            decompiled_function = self._decompile()
            if decompiled_function is None:
                return ""
            try:
                return str(decompiled_function)
            except Exception:
                return ""

        def is_cpp_string_sso_copy(self):
            if self.scanned_function.lower() not in ["memcpy", ".memcpy", "_memcpy", "memmove", ".memmove", "_memmove"]:
                return False
            text = self._function_text()
            return any(marker in text for marker in ["_M_is_local", "_M_local_data", "_M_create", "_M_dispose"])

        def copy_len_allocated_before_call(self):
            decompiled_function, args = self._call_and_args()
            if decompiled_function is None or len(args) < 3:
                return False
            n_text = self._expr_text(args[2])
            if not n_text:
                return False
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea == self.call_xref:
                    break
                if tree_item.op != ida_hexrays.cot_call:
                    continue
                try:
                    callee = utils.get_func_name(tree_item.to_specific_type.x.obj_ea)
                    if not callee:
                        callee = idc.get_name(tree_item.to_specific_type.x.obj_ea)
                    callee = (callee or "").lower()
                    if any(name in callee for name in ["malloc", "calloc", "realloc", "operator new", "_m_create"]):
                        for alloc_arg in list(tree_item.to_specific_type.a):
                            if n_text and n_text in self._expr_text(alloc_arg):
                                return True
                except Exception:
                    continue
            return False

        def copy_len_guarded_by_dst_remaining(self):
            decompiled_function, args = self._call_and_args()
            if decompiled_function is None or len(args) < 3:
                return False
            n_text = self._expr_text(args[2])
            if not n_text:
                return False
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea != self.call_xref:
                    continue
                parent = decompiled_function.body.find_parent_of(tree_item)
                depth = 0
                while parent and depth < 8:
                    if parent.op == ida_hexrays.cit_if:
                        expr_text = self._expr_text(parent.to_specific_type.cif.expr)
                        if n_text in expr_text and any(op in expr_text for op in ["<=", ">=", "<", ">"]):
                            return True
                    parent = decompiled_function.body.find_parent_of(parent)
                    depth += 1
            return False

        def copy_len_bounded_by_stack_object(self):
            decompiled_function, args = self._call_and_args()
            if decompiled_function is None or len(args) < 3:
                return False
            try:
                dst = args[0].x if args[0].op == ida_hexrays.cot_cast else args[0]
                n = VulFiScanner.Param(self.scanner_instance, args[2], self.call_xref, self.scanned_function)
                dst_param = VulFiScanner.Param(self.scanner_instance, dst, self.call_xref, self.scanned_function)
                if dst_param.size() and n.number_value() is not None:
                    return n.number_value() <= dst_param.size()
            except Exception:
                pass
            return self.copy_len_guarded_by_dst_remaining()

        def has_length_equality_guard(self):
            decompiled_function, args = self._call_and_args()
            if decompiled_function is None or len(args) < 3:
                return False
            n_text = self._expr_text(args[2])
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea != self.call_xref:
                    continue
                parent = decompiled_function.body.find_parent_of(tree_item)
                depth = 0
                while parent and depth < 10:
                    if parent.op == ida_hexrays.cit_if:
                        expr_text = self._expr_text(parent.to_specific_type.cif.expr)
                        if n_text and n_text in expr_text and "==" in expr_text:
                            return True
                        if any(marker in expr_text for marker in ["length", "size", "strlen"]):
                            return True
                    parent = decompiled_function.body.find_parent_of(parent)
                    depth += 1
            return False


        def reachable_from(self,function_name):
            functions = [idaapi.get_func(self.call_xref)]
            checked_xrefs = []
            while functions:
                current_function = functions.pop(0)
                if current_function:
                    if utils.get_func_name(current_function.start_ea) in utils.prep_func_name(function_name):
                        return True
                    for xref in idautils.XrefsTo(current_function.start_ea):
                        if xref.frm not in checked_xrefs:
                            functions.append(idaapi.get_func(xref.frm))
                            checked_xrefs.append(xref.frm)
            return False

        # Check whether the return value of a function is part of some comparison (verification)
        def return_value_checked(self,check_val = None):
            if self.scanner_instance.hexrays:
                # Hexrays avaialble, we can use decompiler
                return self.return_value_checked_hexrays(check_val)
            else:
                # Hexrays not available, decompiler cannot be used
                return self.return_value_checked_disass(check_val)

        # Check if the return value of a function is verified after the call
        def return_value_checked_disass(self,check_val):
            # To stay architecture agnostic, this simply checks whether there is conditional jump within 5 instructions after the call
            for basic_block in idaapi.FlowChart(idaapi.get_func(self.call_xref)):
                if self.call_xref >= basic_block.start_ea and self.call_xref < basic_block.end_ea and len(list(basic_block.succs())) > 1:
                    # xref call belongs to this block
                    insn_counter = 0
                    current_insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(current_insn,self.call_xref) != idc.BADADDR:
                        while insn_counter < 5:
                            following_insn = ida_ua.insn_t()
                            if ida_ua.decode_insn(following_insn,current_insn.ea + current_insn.size) != idc.BADADDR:
                                current_insn = following_insn
                                # Most of the compare instructions
                                if current_insn.get_canon_feature() & 0xffff == 0x300:
                                    if check_val is not None:
                                        for op in current_insn.ops:
                                            if op.type == 0x5:
                                                negative_value = utils.get_negative_disass(op)
                                                if op.value == check_val or negative_value == check_val:
                                                    return True
                                                else:
                                                    return False
                                    else:
                                        # Likely comparison instruction hit
                                        return True
                                insn_counter += 1
                            else:
                                break
                            # Jumped out of the block within 5 instructions
                            if current_insn.ea >= basic_block.end_ea:
                                return True
            return False

        def return_value_checked_hexrays(self,check_val):
            try:
                decompiled_function = ida_hexrays.decompile(self.call_xref)
            except:
                return None
            if decompiled_function is None:
                # Decompilation failed
                return None
            code = decompiled_function.pseudocode
            index = 0
            for tree_item in decompiled_function.treeitems:
                if tree_item.ea == self.call_xref and tree_item.op == ida_hexrays.cot_call:
                    xref_func_name = utils.get_func_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if not xref_func_name:
                        xref_func_name = idc.get_name(tree_item.to_specific_type.x.obj_ea).lower()
                    if xref_func_name == self.scanned_function.lower():
                        parent = decompiled_function.body.find_parent_of(tree_item)
                        if parent.op == ida_hexrays.cot_cast: # return value is casted
                            parent = decompiled_function.body.find_parent_of(parent)
                        if (parent.op >= ida_hexrays.cot_eq and parent.op <= ida_hexrays.cot_ult):
                            if check_val is not None:
                                parent = parent.to_specific_type
                                if parent.y and (parent.y.n or parent.y.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                    if parent.y.n: # int
                                        value = parent.y.n._value
                                        negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                    else: # float
                                        value = parent.y.fpc.fnum.float
                                        negative_value = value
                                    if negative_value == check_val or value == check_val:
                                        return True
                                    else:
                                        return False
                            else:
                                return True
                        elif parent.op == ida_hexrays.cit_if:
                            if check_val is not None:
                                expr = parent.to_specific_type.cif.expr
                                if not getattr(expr, "y", None):
                                    # There is no Y, likely checked against 0: if(func_call())
                                    if check_val == 0:
                                        return True
                                    else:
                                        return False
                            else:
                                return True
                        elif parent.op in (ida_hexrays.cot_lnot, ida_hexrays.cot_lor, ida_hexrays.cot_land):
                            # These are expression nodes (cexpr_t), not if-statement nodes (cinsn_t),
                            # so they do not have .cif. Treat them as a boolean return-value check,
                            # but not as an exact comparison against check_val.
                            if check_val is None:
                                return True
                            return check_val == 0

                        elif parent.op == ida_hexrays.cot_asg:
                            # return value is assigned to the variable/global
                            # Look through the rest of the function and find any if comparison with this variable and const number
                            if parent.to_specific_type.x.v or parent.to_specific_type.x.op == ida_hexrays.cot_obj:
                                for sub_tree_item in list(decompiled_function.treeitems)[index:]:
                                    if sub_tree_item.to_specific_type.op >= 22 and sub_tree_item.to_specific_type.op <= 31:

                                        if (sub_tree_item.to_specific_type.x.v and sub_tree_item.to_specific_type.x.v.idx == parent.to_specific_type.x.v.idx) or (sub_tree_item.to_specific_type.x.obj_ea and sub_tree_item.to_specific_type.x.obj_ea == parent.to_specific_type.x.obj_ea):
                                            if check_val is not None:
                                                numeric_val = sub_tree_item.to_specific_type.y
                                                if numeric_val and (numeric_val.n or numeric_val.fpc): # Check if there is a Y operand and if it is a number, if it is, get its value
                                                    if numeric_val.n: # int
                                                        value = numeric_val.n._value
                                                        negative_value = -((value ^ 0xffffffffffffffff) + 1)
                                                    else: # float
                                                        value = numeric_val.fpc.fnum.float
                                                        negative_value = value
                                                    if negative_value == check_val or value == check_val:
                                                        return True
                                                    else:
                                                        return False
                                            else:
                                                return True
                                        else:
                                            # Look for embedded assigns in cit_if (look until cit_if or cit_block is found)
                                            embedded_parent = decompiled_function.body.find_parent_of(sub_tree_item)
                                            while True:
                                                if embedded_parent.op == ida_hexrays.cit_if:
                                                    return True
                                                elif embedded_parent.op == ida_hexrays.cit_block:
                                                    return False
                                                else:
                                                    embedded_parent = decompiled_function.body.find_parent_of(embedded_parent)
                                    elif sub_tree_item.op == ida_hexrays.cit_if or sub_tree_item.op == ida_hexrays.cot_lnot or sub_tree_item.op == ida_hexrays.cot_lor or sub_tree_item.op == ida_hexrays.cot_land:
                                        if check_val is not None:
                                            if not parent.is_expr():
                                                if not parent.to_specific_type.cif.expr.y:
                                                    # There is no Y, likely checked against 0: if(func_call())
                                                    if check_val == 0:
                                                        return True
                                                    else:
                                                        return False
                                        else:
                                            return True


                index += 1
            return False

class vulfi_form_t(ida_kernwin.Form):

    def __init__(self,function_name):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rule_name_str}
BUTTON YES* Run
BUTTON CANCEL Cancel
Custom VulFi rule

{FormChangeCb}
Add custom rule to trace function: {function_name}
Custom rule name:
<#Name of the rule#:{rule_name_str}>
Custom Rule:
<#Rule as desribed in README#:{rule_str}>

""", {
            'function_name': F.StringLabel(function_name),
            'rule_name_str': F.StringInput(),
            'rule_str': F.StringInput(),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        return 1

class VulFi_Single_Function(idaapi.action_handler_t):
    result_window_title = "VulFi Optimized Results"
    result_window_columns_names = ["IssueName","FunctionName","FoundIn", "Address","Status", "Priority","Comment"]
    result_window_columns_sizes = [15,20,20,8,8,5,30]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("VulFiResultRow",result_window_columns_names)

    def __init__(self,function_ea):
        idaapi.action_handler_t.__init__(self)
        self.function_ea = function_ea

    # Called when the button is clicked
    def activate(self, ctx):
        custom_rule = custom_rule_name = ""
        if not idc.get_type(self.function_ea) and (idaapi.get_func(self.function_ea) and not idc.get_type(idaapi.get_func(self.function_ea).start_ea)):
            # If the type of the function is not set notify the user
            answer = ida_kernwin.ask_buttons("Yes","No","Cancel",1,f"You should first set type for the function. Continue without type anyway?")
            if answer != 1:
                return

        # Show the form
        function_name = idc.get_func_name(self.function_ea)
        if not function_name:
            function_name = idc.get_name(self.function_ea)
        f = vulfi_form_t(function_name)
        # Compile (in order to populate the controls)
        f.Compile()
        # Execute the form
        ok = f.Execute()
        # If the form was confirmed
        if ok == 1:
            custom_rule_name = f.rule_name_str.value
            custom_rule = f.rule_str.value
        else:
            # Cancel
            return
        # Dispose the form
        f.Free()

        if not custom_rule or not custom_rule_name:
            ida_kernwin.warning("Both rule name and the rule have to be filled!")
            return
        # Craft a temporary rule here:
        tmp_rule = [{"name":f"{custom_rule_name}","function_names":[function_name.lower(),f".{function_name.lower()}"],"wrappers":False,"mark_if":{"High":custom_rule,"Medium":"False","Low":"False"}}]
        vulfi_scanner = VulFiScanner(tmp_rule)
        rows = []
        marked_addrs = []
        vulfi_data = {}
        # Load stored data
        node = idaapi.netnode()
        node.create("vulfi_opt_data")
        if node.getblob(1,"S"):
            vulfi_data = json.loads(node.getblob(1,"S"))
        else:
            vulfi_data = {}
        for item in vulfi_data:
            rows.append([vulfi_data[item]["name"],vulfi_data[item]["function"],vulfi_data[item]["in"],vulfi_data[item]["addr"],vulfi_data[item]["status"],vulfi_data[item]["priority"],vulfi_data[item]["comment"]])
            marked_addrs.append(vulfi_data[item]["addr"])

        # Run the scan for selected function
        print("[VulFi] Started the scan ...")
        scan_result = vulfi_scanner.start_scan(marked_addrs)
        if scan_result is None:
            return
        rows.extend(scan_result)
        print("[VulFi] Scan done!")
        # Save the results
        for item in rows:
            vulfi_data[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
        node.setblob(json.dumps(vulfi_data).encode("ascii"),1,"S")
        # Construct and show the form
        results_window = VulFiEmbeddedChooser(self.result_window_title,self.result_window_columns,rows,icon_id)
        results_window.AddCommand("Mark as False Positive", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Suspicious", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Vulnerable", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Set Vulfi Comment", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Remove Item(s)", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Export Results", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.Show()
        hooks.set_chooser(results_window)

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class vulfi_main_form_t(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rDefault}
BUTTON YES* Run
BUTTON CANCEL Cancel
Custom VulFi rule

{FormChangeCb}
<##What rule set to use?##Default rules:{rDefault}>
<Custom rules:{rCustom}>
<Import previous results (JSON):{rImport}>{cType}>
<#Select a file to open#Browse to open:{iFileOpen}>

""", {
            'iFileOpen': F.FileInput(open=True),
            'cType': F.RadGroupControl(("rDefault", "rCustom","rImport")),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self, fid):
        if fid == -1 or fid == self.cType.id:
            if self.GetControlValue(self.cType) == 0:
                self.EnableField(self.iFileOpen, False)
            else:
                self.EnableField(self.iFileOpen, True)
        return 1

class VulFi(idaapi.action_handler_t):
    result_window_title = "VulFi Optimized Results"
    result_window_columns_names = ["IssueName","FunctionName","FoundIn", "Address","Status", "Priority","Comment"]
    result_window_columns_sizes = [15,20,20,8,8,5,30]
    result_window_columns = [ list(column) for column in zip(result_window_columns_names,result_window_columns_sizes)]
    result_window_row = collections.namedtuple("VulFiResultRow",result_window_columns_names)
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Called when the button is clicked
    def activate(self, ctx):
        answer = 0
        skip_scan = False
        rows = []
        vulfi_data = {}
        marked_addrs = []
        # Load stored data
        node = idaapi.netnode()
        node.create("vulfi_opt_data")
        if node.getblob(1,"S"):
            vulfi_data = json.loads(node.getblob(1,"S"))
        else:
            vulfi_data = {}
        if vulfi_data:
            answer = ida_kernwin.ask_buttons("Load Existing","Scan Again","Cancel",1,f"Previous scan results found.")
        else:
            answer = 2
        if vulfi_data and answer == 1:
            for item in vulfi_data:
                rows.append([vulfi_data[item]["name"],vulfi_data[item]["function"],vulfi_data[item]["in"],vulfi_data[item]["addr"],vulfi_data[item]["status"],vulfi_data[item]["priority"],vulfi_data[item]["comment"]])
                marked_addrs.append(f'{vulfi_data[item]["name"]}_{vulfi_data[item]["addr"]}')
            print("[VulFi] Loading previous data.")
        elif answer == -1:
            # Cancel
            return
        else:
            # Show the form
            f = vulfi_main_form_t()
            # Compile (in order to populate the controls)
            f.Compile()
            # Execute the form
            ok = f.Execute()
            # If the form was confirmed
            if ok == 1:
                if f.cType.value == 0:
                    # Default scan
                    vulfi_scanner = VulFiScanner()
                elif f.cType.value == 1:
                    try:
                        with open(os.path.join(f.iFileOpen.value),"r") as rules_file:
                            vulfi_scanner = VulFiScanner(json.load(rules_file))
                    except:
                        ida_kernwin.warning("Failed to load custom rules!")
                        return
                else:
                    try:
                        with open(os.path.join(f.iFileOpen.value),"r") as import_file:
                            import_data = json.load(import_file)
                        for item in import_data["issues"]:
                            rows.append([item["IssueName"],item["FunctionName"],item["FoundIn"],item["Address"],item["Status"],item["Priority"],item["Comment"]])
                        skip_scan = True
                    except:
                        ida_kernwin.warning("Failed to load custom rules!")
                        return
            else:
                return

            for item in vulfi_data:
                rows.append([vulfi_data[item]["name"],vulfi_data[item]["function"],vulfi_data[item]["in"],vulfi_data[item]["addr"],vulfi_data[item]["status"],vulfi_data[item]["priority"],vulfi_data[item]["comment"]])
                marked_addrs.append(f'{vulfi_data[item]["name"]}_{vulfi_data[item]["addr"]}')
            # Run the scan
            if not skip_scan:
                print("[VulFi] Started the scan ...")
                scan_result = vulfi_scanner.start_scan(marked_addrs)
                if scan_result is None:
                    return
                rows.extend(scan_result)
                print("[VulFi] Scan done!")
            # Save the results
            for item in rows:
                vulfi_data[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
            node.setblob(json.dumps(vulfi_data).encode("ascii"),1,"S")

        # Construct and show the form
        results_window = VulFiEmbeddedChooser(self.result_window_title,self.result_window_columns,rows,icon_id)
        results_window.AddCommand("Mark as False Positive", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Suspicious", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Mark as Vulnerable", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Set Vulfi Comment", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Remove Item(s)", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.AddCommand("Export Results", flags=4, menu_index=-1, icon=icon_id, emb=None, shortcut=None)
        results_window.Show()
        hooks.set_chooser(results_window)


    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class vulfi_export_form_t(ida_kernwin.Form):

    def __init__(self):
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM {id:rJSON}
BUTTON YES* Save
BUTTON CANCEL Cancel
VulFi Results Export

{FormChangeCb}
<##Choose format for export##JSON:{rJSON}>
<CSV:{rCSV}>{cType}>
<#Select the output file#Select the output file:{iFileOpen}>

""", {
            'iFileOpen': F.FileInput(save=True),
            'cType': F.RadGroupControl(("rJSON", "rCSV")),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)
        })

    def OnFormChange(self,fid):
        return 1


class VulFiEmbeddedChooser(ida_kernwin.Choose):
    def __init__(self,title,columns,items,icon,embedded=False):
        ida_kernwin.Choose.__init__(self,title,columns,embedded=embedded,width=100,flags=ida_kernwin.Choose.CH_MULTI + ida_kernwin.Choose.CH_CAN_REFRESH)
        self.items = items
        self.icon = icon
        self.delete = False
        self.comment = False
        self.export = False

    def GetItems(self):
        return self.items

    def SetItems(self,items):
        if items is None:
            self.items = []
        else:
            self.items = items
        self.Refresh()

    def OnRefresh(self,n):
        for item in self.items:
            item[2] = utils.get_func_name(int(item[3],16))
        if self.delete:
            for i in reversed(n):
                self.items.pop(i)
            self.delete = False
            self.save()
        if self.comment:
            if len(n) == 1:
                comment = ida_kernwin.ask_str(self.items[n[0]][6],1,f"Enter the comment: ")
            else:
                comment = ida_kernwin.ask_str("",1,f"Enter the comment: ")
            for i in n:
                self.items[i][6] = comment
            self.comment = False
            self.save()
        if self.export:
            self.export = False
            self.vulfi_export()
            
        return n

    def save(self):
        # On close dumps the results
        vulfi_dict = {}
        for item in self.items:
            vulfi_dict[f"{item[3]}_{item[0]}"] = {"name":item[0],"function":item[1],"in":item[2],"addr":item[3],"status":item[4],"priority":item[5],"comment":item[6]}
        node = idaapi.netnode()
        node.create("vulfi_opt_data")
        # Set the blob
        node.setblob(json.dumps(vulfi_dict).encode("ascii"),1,"S")

    def OnCommand(self,number,cmd_id):
        # Cmd_ids: 0 - FP, 1 - Susp, 2 - Vuln
        if cmd_id < 3:
            if cmd_id == 0:
                status = "False Positive"
            if cmd_id == 1:
                status = "Suspicious"
            if cmd_id == 2:
                status = "Vulnerable"
            # Item at index #3 is status
            self.items[number][4] = status
        if cmd_id == 3:
            # Comment
            self.comment = True
        if cmd_id == 4:
            # Delete selected items
            self.delete = True
        if cmd_id == 5:
            # Export
            self.export = True
            
        self.Refresh()
        # Save the data after every change
        self.save()

    def vulfi_export(self):
        # Show the form
        f = vulfi_export_form_t()
        # Compile (in order to populate the controls)
        f.Compile()
        # Execute the form
        ok = f.Execute()
        # If the form was confirmed
        if ok == 1:
            # Get file name
            file_name = f.iFileOpen.value
            if file_name:
                if f.cType.value == 0:
                    # JSON
                    # Pretify 
                    tmp_json = {"issues":[]}
                    for item in self.items:
                        tmp_json["issues"].append({
                            "IssueName": item[0],
                            "FunctionName": item[1],
                            "FoundIn": item[2],
                            "Address": item[3],
                            "Status": item[4],
                            "Priority": item[5],
                            "Comment": item[6]
                        })
                    with open(file_name,"w") as out_file:
                        json.dump(tmp_json, out_file)
                    ida_kernwin.info(f"Results exported in JSON format to {file_name}")
                else:
                    #CSV
                    csv_string = "IssueName,FunctionName,FoundIn,Address,Status,Priority,Comment\n"
                    for item in self.items:
                        csv_string += f"{item[0]},{item[1]},{item[2]},{item[3]},{item[4]},{item[5]},{item[6]}\n"
                    with open(file_name,"w") as out_file:
                        out_file.write(csv_string)
                    ida_kernwin.info(f"Results exported in comma-separated CSV file to {file_name}")
        

    def OnGetSize(self):
        return len(self.items)

    def OnSelectLine(self,number):
        # By default change to first selected line
        row = VulFi.result_window_row(*self.items[number[0]])
        destination = row.Address
        ida_kernwin.jumpto(int(destination,16))

    def OnGetLineAttr(self, number):
        if self.items[number][4] == "False Positive":
            return (0x9D9D9D,0)
        elif self.items[number][4] == "Suspicious":
            return (0xd0FF,0)
        elif self.items[number][4] == "Vulnerable":
            return (0xFF,0)

    def OnGetLine(self,number):
        try:
            return self.items[number]
        except:
            self.Refresh()
            return None


class vulfi_opt_fetch_t(idaapi.plugin_t):
    comment = "Vulnerability Finder"
    help = "This script helps to reduce the amount of work required when inspecting potentially dangerous calls to functions such as 'memcpy', 'strcpy', etc."
    wanted_name = "VulFi Optimized"
    wanted_hotkey = ""
    flags = idaapi.PLUGIN_KEEP


    def init(self):
        try:
            vulfi_desc = idaapi.action_desc_t(
                'vulfi_opt:fetch',
                'VulFi Optimized',
                VulFi(),
                '',
                'Make VulFi Optimized fetch the potentially interesting places in binary.',
                icon_id)
            try:
                idaapi.unregister_action('vulfi_opt:fetch')
            except Exception:
                pass
            idaapi.register_action(vulfi_desc)
            ida_kernwin.attach_action_to_menu("Search/", "vulfi_opt:fetch", ida_kernwin.SETMENU_APP)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", "vulfi_opt:fetch", ida_kernwin.SETMENU_APP)
            _ensure_vulfi_opt_hooks()
            return idaapi.PLUGIN_KEEP
        except Exception:
            print("[VulFi] init() failed:")
            traceback.print_exc()
            return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        global hooks
        try:
            ida_kernwin.detach_action_from_menu("Search/", "vulfi_opt:fetch")
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", "vulfi_opt:fetch")
            idaapi.unregister_action('vulfi_opt:fetch')
        except Exception:
            pass
        if hooks is not None:
            try:
                hooks.unhook()
            except Exception:
                pass
            hooks = None



class Hooks(idaapi.UI_Hooks):
    def __init__(self):
        self.chooser = None
        idaapi.UI_Hooks.__init__(self)


    def finish_populating_widget_popup(self, form, popup):
        action_text = f"Add '{utils.get_func_name(idc.here())}' function to VulFi Optimized"
        function_ea = idc.here()
        try:
            # Get selected symbol
            selected_symbol, _ = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
            # Check if it is a function name
            for function in idautils.Functions():
                if utils.get_func_name(function) in utils.prep_func_name(selected_symbol):
                    action_text = f"Add '{utils.get_func_name(function)}' function to VulFi Optimized"
                    function_ea = function
        except:
            pass
        action_desc = idaapi.action_desc_t(
        'vulfi_opt:get_one',   # The action name. This acts like an ID and must be unique
        action_text,  # The action text.
        VulFi_Single_Function(function_ea),   # The action handler.
        '',      # Optional: the action shortcut
        'Make VulFi look for all interesting refences of this function.',  # Optional: the action tooltip (available in menus/toolbar)
        icon_id)           # Optional: the action icon (shows when in menus/toolbars)
        idaapi.unregister_action("vulfi_opt:get_one")
        idaapi.register_action(action_desc)
        if ida_kernwin.get_widget_type(form) == idaapi.BWN_DISASM or ida_kernwin.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, "vulfi_opt:get_one", "")

    def current_widget_changed(self, widget, prev_widget):
        title = ida_kernwin.get_widget_title(widget)
        if title and "VulFi Optimized" in title and self.chooser:
            self.chooser.Refresh()

    def set_chooser(self,chooser):
        self.chooser = chooser

hooks = None

def _ensure_vulfi_opt_hooks():
    global hooks
    if hooks is None:
        hooks = Hooks()
        hooks.hook()
    return hooks

def PLUGIN_ENTRY():
    return vulfi_opt_fetch_t()

