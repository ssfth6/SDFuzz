#!/usr/bin/env python3
"""
Map call stack locations to their corresponding basic blocks
"""

def load_basic_blocks(basic_blocks_file):
    """Load basic blocks and organize by file"""
    basic_blocks = {}
    
    with open(basic_blocks_file, 'r') as f:
        for line in f:
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Remove trailing colon if present
            if line.endswith(':'):
                line = line[:-1]
            
            # Skip if still empty after removing colon
            if not line:
                continue
                
            if ':' in line:
                file_name, line_num_str = line.split(':', 1)
                
                # Skip if line number part is empty
                if not line_num_str:
                    continue
                    
                try:
                    line_num = int(line_num_str)
                    
                    if file_name not in basic_blocks:
                        basic_blocks[file_name] = []
                    basic_blocks[file_name].append(line_num)
                except ValueError:
                    # Skip lines with invalid line numbers
                    continue
    
    # Sort line numbers for each file for efficient searching
    for file_name in basic_blocks:
        basic_blocks[file_name].sort()
    
    return basic_blocks

def find_basic_block(file_name, line_num, basic_blocks):
    """Find the basic block for a given file:line location using binary search"""
    if file_name not in basic_blocks:
        return None
    
    bb_lines = basic_blocks[file_name]
    
    # Binary search for the largest basic block line number <= target line number
    import bisect
    idx = bisect.bisect_right(bb_lines, line_num) - 1
    
    if idx >= 0:
        return "{}:{}".format(file_name, bb_lines[idx])
    return None

def map_callstack_to_basic_blocks(callstack_file, basic_blocks_file, output_file):
    """Map each call stack entry to its basic block"""
    basic_blocks = load_basic_blocks(basic_blocks_file)
    
    with open(callstack_file, 'r') as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                f_out.write('\n')
                continue
                
            # Parse call stack line: "function (file:line)"
            # Extract only the part within parentheses: file:line
            if ' (' in line and line.endswith(')'):
                func_part, location_part = line.split(' (', 1)
                location = location_part[:-1]  # Remove closing ) to get just "file:line"
                
                if ':' in location:
                    file_name, line_num = location.split(':', 1)
                    try:
                        line_num = int(line_num)
                        basic_block = find_basic_block(file_name, line_num, basic_blocks)
                        
                        if basic_block:
                            f_out.write("{} ({}) -> {}\n".format(func_part, location, basic_block))
                        else:
                            f_out.write("{} ({}) -> NO_BB_FOUND\n".format(func_part, location))
                    except ValueError:
                        f_out.write("{} -> INVALID_LINE_NUM\n".format(line))
                else:
                    f_out.write("{} -> NO_LOCATION\n".format(line))
            else:
                f_out.write("{} -> INVALID_FORMAT\n".format(line))

def map_callstack_to_basic_blocks_clean(callstack_file, basic_blocks_file, output_file):
    """Map call stack to basic blocks - output only unique basic block names, no empty lines"""
    basic_blocks = load_basic_blocks(basic_blocks_file)
    seen_blocks = set()  # For deduplication
    
    with open(callstack_file, 'r') as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue  # Skip empty lines
                
            # Parse call stack line: "function (file:line)"
            if ' (' in line and line.endswith(')'):
                func_part, location_part = line.split(' (', 1)
                location = location_part[:-1]  # Remove closing )
                
                if ':' in location:
                    file_name, line_num = location.split(':', 1)
                    try:
                        line_num = int(line_num)
                        basic_block = find_basic_block(file_name, line_num, basic_blocks)
                        
                        # Only output if we found a basic block and haven't seen it before
                        if basic_block and basic_block not in seen_blocks:
                            f_out.write("{}\n".format(basic_block))
                            seen_blocks.add(basic_block)
                    except ValueError:
                        pass  # Skip invalid line numbers

# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 4:
        print("Usage: python callstack_mapper.py <callstack_file> <basic_blocks_file> <output_file>")
        sys.exit(1)
    
    callstack_file = sys.argv[1]
    basic_blocks_file = sys.argv[2]
    output_file = sys.argv[3]
    
    try:
        map_callstack_to_basic_blocks_clean(callstack_file, basic_blocks_file, output_file)
        print("Clean basic block mapping written to: {}".format(output_file))
        
    except IOError as e:
        print("Error: File not found - {}".format(e))
    except Exception as e:
        print("Error: {}".format(e))