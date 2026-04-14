#!/usr/bin/env python3
"""
Multi-stack vulnerability parser - orders call stacks by execution chronology
Enhanced version with stack comparison functionality
"""

import re

def parse_vulnerability_dump(filename):
    """Parse crash dump and return call stacks ordered by execution time"""
    stacks = []
    current_stack = []
    # Multi-stack triggers (UAF, double-free) - order matters for execution timeline
    multi_stack_triggers = [
        ('previously allocated', 1),      # UAF: allocation first
        ('allocated by thread', 1),       # Alternative allocation format
        ('freed by thread', 2),           # UAF: free second  
        ('deallocated by thread', 2),     # Alternative free format
        ('attempting double-free', 3),    # Double-free: second free (crash)
    ]
    
    # Single-stack triggers (buffer overflow, segfault, etc.)
    single_stack_triggers = [
        'READ of size',              # UAF access (but could be single stack)
        'WRITE of size',             # UAF write or buffer overflow
        'stack-buffer-overflow',     # Stack buffer overflow
        'heap-buffer-overflow',      # Heap buffer overflow
        'segmentation fault',        # General segfault
        'assertion failed',          # Assertion failure
    ]
    
    current_priority = 999
    
    in_backtrace = False
    skip_detailed_thread = False
    
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Skip detailed thread info (after "Thread X (Thread ...")
            if line.startswith('Thread ') and '(Thread' in line:
                skip_detailed_thread = True
                continue
            
            # Start parsing when we see (gdb) bt or stack trace indicators
            if '(gdb) bt' in line or line.startswith('#0 ') or 'READ of size' in line or 'WRITE of size' in line:
                in_backtrace = True
                skip_detailed_thread = False
            
            # Check for multi-stack triggers first (UAF, double-free)
            multi_stack_found = False
            for trigger, priority in multi_stack_triggers:
                if trigger.lower() in line.lower():
                    new_priority = priority
                    multi_stack_found = True
                    break
            
            # If multi-stack trigger found, handle it
            if multi_stack_found:
                if current_stack:
                    stacks.append((current_priority, current_stack))
                current_stack = []
                current_priority = new_priority
                in_backtrace = True
                skip_detailed_thread = False
                continue
            
            # Check for single-stack triggers (buffer overflow, segfault)
            for trigger in single_stack_triggers:
                if trigger.lower() in line.lower():
                    in_backtrace = True
                    skip_detailed_thread = False
                    current_priority = 1  # Single stack gets priority 1
                    break
            
            # Stop parsing when we hit summary/metadata, detailed thread info, or frame analysis
            if (any(keyword in line.lower() for keyword in ['summary:', 'shadow bytes', 'legend:', 'this frame has', 'address 0x']) or 
                skip_detailed_thread or 
                (not in_backtrace and not line.startswith('#'))):
                if line.startswith('#') and skip_detailed_thread:
                    continue  # Skip detailed thread frames
                elif not line.startswith('#'):
                    continue
            
            # Parse stack frame - only if we're in a backtrace section
            if not in_backtrace:
                continue
                
            # Handle multiple formats but filter out system functions
            patterns = [
                r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\w+)\s+([^:]+):(\d+)',           # AddressSanitizer
                r'#(\d+)\s+0x[0-9a-fA-F]+.*?in\s+(\w+).*?at\s+([^:]+):(\d+)',      # GDB detailed
                r'==\d+==\s+at\s+0x[0-9A-F]+:\s+(\w+)\s+\(([^:)]+):(\d+)\)',       # Valgrind
                r'#(\d+)\s+(\w+)\s+at\s+([^:]+):(\d+)',                            # Simple format
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    if len(match.groups()) == 4:  # Format with frame number
                        func = match.group(2)
                        file_path = match.group(3).split('/')[-1]
                        line_num = match.group(4)
                    else:  # Valgrind format (3 groups)
                        func = match.group(1)
                        file_path = match.group(2).split('/')[-1]
                        line_num = match.group(3)
                    
                    # Filter out system/library/sanitizer functions, keep only main program
                    system_funcs = ['__interceptor_', '__asan_', '__sanitizer_', '__libc_start_main', '_start', 'start_thread', 'clone', '_init']
                    system_files = ['libc', 'pthread', 'stdio.h', 'bits/', 'sanitizer_', 'compiler-rt', 'asan_']
                    
                    # Keep only if it's not a system function and not from system files
                    if (not any(sf in func for sf in system_funcs) and 
                        not any(sf in file_path for sf in system_files)):
                        
                        location = "{}:{}".format(file_path, line_num)
                        # Avoid duplicates
                        if (func, location) not in current_stack:
                            current_stack.append((func, location))
                    break
    
    # Add the last stack
    if current_stack:
        stacks.append((current_priority, current_stack))
    
    # Sort by priority (execution order) and return just the stacks
    stacks.sort(key=lambda x: x[0])
    return [stack for priority, stack in stacks]


def compare_stacks_and_select_primary(stacks):
    """
    Compare multiple call stacks and select the primary one based on line numbers.
    Start with all stacks as finalists, then eliminate those that don't have
    the largest line numbers at each position until only one remains.
    """
    if len(stacks) <= 1:
        return stacks[0] if stacks else []
    
    # Prepare all stacks in execution order (main first)
    processed_stacks = []
    
    for stack in stacks:
        # Reverse stack to get execution order (main first)
        reversed_stack = list(reversed(stack))
        
        # Find main and start from there
        main_index = -1
        for j, (func, loc) in enumerate(reversed_stack):
            if func == 'main':
                main_index = j
                break
        
        if main_index != -1:
            reversed_stack = reversed_stack[main_index:]
        
        processed_stacks.append(reversed_stack)
    
    # Start with all stacks as finalists
    finalists = list(range(len(stacks)))
    max_length = max(len(stack) for stack in processed_stacks)
    
    for pos in range(max_length):
        if len(finalists) <= 1:
            break
            
        # Get all items at this position from finalist stacks
        items_at_pos = []
        for stack_idx in finalists:
            if pos < len(processed_stacks[stack_idx]):
                func, location = processed_stacks[stack_idx][pos]
                line_num = int(location.split(':')[-1])
                items_at_pos.append((func, line_num, stack_idx))
        
        # Group by function name
        func_groups = {}
        for func, line_num, stack_idx in items_at_pos:
            if func not in func_groups:
                func_groups[func] = []
            func_groups[func].append((line_num, stack_idx))
        
        # For each function that appears multiple times, keep only those with max line number
        stacks_to_keep = set(finalists)
        
        for func, line_stack_pairs in func_groups.items():
            if len(line_stack_pairs) > 1:  # Function appears in multiple finalist stacks
                max_line = max(line_num for line_num, stack_idx in line_stack_pairs)
                
                # Remove stacks that don't have the maximum line number for this function
                stacks_with_smaller_lines = [stack_idx for line_num, stack_idx in line_stack_pairs if line_num < max_line]
                stacks_to_keep -= set(stacks_with_smaller_lines)
        
        # Update finalists
        finalists = list(stacks_to_keep)
    
    # Return the remaining finalist (or first one if multiple remain)
    return stacks[finalists[0]]


def write_stacks_output(stacks, output_filename):
    """Write all call stacks to the output file"""
    with open(output_filename, 'w') as f:
        for i, stack in enumerate(stacks):
            # Reverse stack order - first executed function first
            reversed_stack = list(reversed(stack))
            
            # Remove items from the top if they're not main (find main and start from there)
            main_index = -1
            for j, (func, loc) in enumerate(reversed_stack):
                if func == 'main':
                    main_index = j
                    break
            
            # If main found, start from main; otherwise use full stack
            if main_index != -1:
                reversed_stack = reversed_stack[main_index:]
            
            for j, (func, loc) in enumerate(reversed_stack):
                f.write("{} ({})\n".format(func, loc))
            
            # Add empty line between stacks (except after the last one)
            if i < len(stacks) - 1:
                f.write("\n")


def write_comparison_output(primary_stack, comparison_filename):
    """Write the primary (selected) call stack to the comparison file"""
    if not primary_stack:
        return
        
    with open(comparison_filename, 'w') as f:
        # Reverse stack order - first executed function first
        reversed_stack = list(reversed(primary_stack))
        
        # Remove items from the top if they're not main (find main and start from there)
        main_index = -1
        for j, (func, loc) in enumerate(reversed_stack):
            if func == 'main':
                main_index = j
                break
        
        # If main found, start from main; otherwise use full stack
        if main_index != -1:
            reversed_stack = reversed_stack[main_index:]
        
        for func, loc in reversed_stack:
            f.write("{} ({})\n".format(func, loc))


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python vuln_parser.py <crash_dump_file> [output_file]")
        print("  If output_file not specified, uses <input_file>_callstacks.txt")
        print("  Also creates <input_file>_final.txt when multiple stacks exist")
        sys.exit(1)
    
    try:
        stacks = parse_vulnerability_dump(sys.argv[1])
        
        # Determine output filenames
        if len(sys.argv) == 3:
            output_filename = sys.argv[2]
            comparison_filename = sys.argv[2].rsplit('.', 1)[0] + '_final.txt'
        else:
            input_filename = sys.argv[1]
            base_name = input_filename.rsplit('.', 1)[0]
            output_filename = base_name + '_callstacks.txt'
            comparison_filename = base_name + '_final.txt'
        
        # Write all call stacks
        write_stacks_output(stacks, output_filename)
        print("Call stacks written to: {}".format(output_filename))
        
        # If multiple stacks exist, create comparison file
        if len(stacks) > 1:
            primary_stack = compare_stacks_and_select_primary(stacks)
            write_comparison_output(primary_stack, comparison_filename)
            print("Stack comparison written to: {}".format(comparison_filename))
            print("Selected primary stack based on larger line numbers in common functions")
        else:
            print("Only one stack found, no comparison file created")
            
    except IOError:
        print("Error: File '{}' not found".format(sys.argv[1]))
    except Exception as e:
        print("Error: {}".format(e))
