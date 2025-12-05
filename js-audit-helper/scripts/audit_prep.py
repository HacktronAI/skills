import os
import argparse
import jsbeautifier
from tree_sitter import Language, Parser
import tree_sitter_javascript as tsjs
import json
import re

# Initialize Tree-sitter for JS
JS_LANGUAGE = Language(tsjs.language())
parser = Parser(JS_LANGUAGE)

MAX_CHARS_PER_CHUNK = 15000

# Security patterns to detect
SECURITY_PATTERNS = {
    'secrets': [
        (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'API Key'),
        (r'secret[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'Secret Key'),
        (r'password\s*[=:]\s*["\']([^"\']+)["\']', 'Password'),
        (r'token\s*[=:]\s*["\']([^"\']+)["\']', 'Token'),
        (r'bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 'JWT Token'),
        (r'sk_live_[a-zA-Z0-9]+', 'Stripe Key'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    ],
    'dom_xss': [
        (r'\.innerHTML\s*=', 'innerHTML assignment'),
        (r'\.outerHTML\s*=', 'outerHTML assignment'),
        (r'document\.write\s*\(', 'document.write()'),
        (r'eval\s*\(', 'eval()'),
        (r'setTimeout\s*\([^,]*[\'"`]', 'setTimeout with string'),
        (r'setInterval\s*\([^,]*[\'"`]', 'setInterval with string'),
    ],
    'user_input': [
        (r'location\.(hash|search|href)', 'URL input source'),
        (r'document\.(cookie|referrer)', 'Document input source'),
        (r'window\.name', 'window.name'),
        (r'localStorage\.getItem', 'localStorage'),
        (r'sessionStorage\.getItem', 'sessionStorage'),
    ],
    'redirects': [
        (r'(window\.)?location\s*=', 'Location redirect'),
        (r'location\.href\s*=', 'href redirect'),
        (r'location\.replace\s*\(', 'location.replace()'),
    ],
    'network': [
        (r'fetch\s*\(\s*[\'"]http:', 'Insecure HTTP fetch'),
        (r'XMLHttpRequest.*http:', 'Insecure HTTP XHR'),
        (r'ws://', 'Unencrypted WebSocket'),
    ]
}

def get_node_text(node, source_bytes):
    """Extract text from a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')

def scan_security_patterns(content, start_line=1):
    """Scan content for security-relevant patterns."""
    findings = []
    lines = content.split('\n')
    
    for category, patterns in SECURITY_PATTERNS.items():
        for pattern, description in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                # Find which line this match is on
                line_num = content[:match.start()].count('\n') + start_line
                # Get context (the line containing the match)
                relative_line = content[:match.start()].count('\n')
                if relative_line < len(lines):
                    context_line = lines[relative_line].strip()
                else:
                    context_line = match.group(0)
                
                findings.append({
                    'category': category,
                    'type': description,
                    'line': line_num,
                    'match': match.group(0)[:100],  # Limit match length
                    'context': context_line[:150]  # Limit context length
                })
    
    return findings

def build_security_hotspots(tree, source_bytes):
    """Find security-relevant code locations (functions with dangerous operations)."""
    hotspots = []
    
    def walk_tree(node, parent_name="Global"):
        current_name = parent_name
        
        # Track function/class names for context
        if node.type == 'function_declaration':
            name_node = node.child_by_field_name('name')
            if name_node:
                current_name = get_node_text(name_node, source_bytes)
        elif node.type == 'class_declaration':
            name_node = node.child_by_field_name('name')
            if name_node:
                current_name = get_node_text(name_node, source_bytes)
        
        # Check for dangerous operations
        node_text = get_node_text(node, source_bytes)
        
        # innerHTML with potential taint
        if 'innerHTML' in node_text and any(src in node_text for src in ['location', 'hash', 'search', 'cookie']):
            hotspots.append({
                'type': 'Potential DOM XSS',
                'context': current_name,
                'line': node.start_point[0] + 1,
                'snippet': node_text[:200]
            })
        
        # eval with user input
        if 'eval(' in node_text and any(src in node_text for src in ['location', 'localStorage', 'param']):
            hotspots.append({
                'type': 'Dangerous eval()',
                'context': current_name,
                'line': node.start_point[0] + 1,
                'snippet': node_text[:200]
            })
        
        # Recursively walk children
        for child in node.children:
            walk_tree(child, current_name)
    
    try:
        walk_tree(tree.root_node)
    except Exception as e:
        print(f"Warning: Error scanning for hotspots: {e}")
    
    return hotspots

def build_code_structure_map(tree, source_bytes):
    """Build a map of all functions and classes with their line numbers."""
    code_map = []
    
    def walk_tree(node, parent_name="Global"):
        current_name = parent_name
        
        # Track function declarations
        if node.type == 'function_declaration':
            name_node = node.child_by_field_name('name')
            if name_node:
                func_name = get_node_text(name_node, source_bytes)
                code_map.append({
                    'type': 'function',
                    'name': func_name,
                    'line': node.start_point[0] + 1,
                    'end_line': node.end_point[0] + 1,
                    'parent': parent_name
                })
                current_name = func_name
        
        # Track class declarations
        elif node.type == 'class_declaration':
            name_node = node.child_by_field_name('name')
            if name_node:
                class_name = get_node_text(name_node, source_bytes)
                code_map.append({
                    'type': 'class',
                    'name': class_name,
                    'line': node.start_point[0] + 1,
                    'end_line': node.end_point[0] + 1,
                    'parent': parent_name
                })
                current_name = class_name
        
        # Track method definitions (inside classes)
        elif node.type == 'method_definition':
            name_node = node.child_by_field_name('name')
            if name_node:
                method_name = get_node_text(name_node, source_bytes)
                code_map.append({
                    'type': 'method',
                    'name': method_name,
                    'line': node.start_point[0] + 1,
                    'end_line': node.end_point[0] + 1,
                    'parent': parent_name
                })
        
        # Track arrow functions and function expressions assigned to variables
        elif node.type == 'variable_declaration':
            for subchild in node.children:
                if subchild.type == 'variable_declarator':
                    name_node = subchild.child_by_field_name('name')
                    value_node = subchild.child_by_field_name('value')
                    if name_node and value_node and value_node.type in ['arrow_function', 'function_expression']:
                        var_name = get_node_text(name_node, source_bytes)
                        code_map.append({
                            'type': 'function_expression',
                            'name': var_name,
                            'line': value_node.start_point[0] + 1,
                            'end_line': value_node.end_point[0] + 1,
                            'parent': parent_name
                        })
        
        # Recursively walk children
        for child in node.children:
            walk_tree(child, current_name)
    
    try:
        walk_tree(tree.root_node)
    except Exception as e:
        print(f"Warning: Error building structure map: {e}")
    
    return code_map

def semantic_split(source_code, filename):
    """Split code into semantic chunks at function/class boundaries."""
    tree = parser.parse(bytes(source_code, "utf8"))
    source_bytes = bytes(source_code, "utf8")
    
    chunks = []
    current_chunk = ""
    current_lines_start = 1
    current_context = "Global"
    
    # Build structure map
    code_map = build_code_structure_map(tree, source_bytes)

    for child in tree.root_node.children:
        node_text = get_node_text(child, source_bytes)
        
        # Determine context
        if child.type in ['class_declaration', 'function_declaration']:
            name_node = child.child_by_field_name('name')
            if name_node:
                current_context = get_node_text(name_node, source_bytes)
        elif child.type == 'variable_declaration':
            for subchild in child.children:
                if subchild.type == 'variable_declarator':
                    name_node = subchild.child_by_field_name('name')
                    value_node = subchild.child_by_field_name('value')
                    if name_node and value_node and value_node.type in ['arrow_function', 'function_expression']:
                        current_context = get_node_text(name_node, source_bytes)
                        break

        # Flush chunk if size exceeded
        if len(current_chunk) + len(node_text) > MAX_CHARS_PER_CHUNK:
            if current_chunk.strip():
                chunks.append({
                    "content": current_chunk,
                    "start_line": current_lines_start,
                    "context": current_context
                })
                current_lines_start = child.start_point[0] + 1
                current_chunk = ""
            
            # Handle massive nodes
            if len(node_text) > MAX_CHARS_PER_CHUNK:
                lines = node_text.split('\n')
                sub_chunk = ""
                sub_start_line = child.start_point[0] + 1
                
                for line in lines:
                    if len(sub_chunk) + len(line) + 1 > MAX_CHARS_PER_CHUNK and sub_chunk:
                        chunks.append({
                            "content": sub_chunk,
                            "start_line": sub_start_line,
                            "context": f"{current_context} (Split)"
                        })
                        sub_chunk = ""
                        sub_start_line += sub_chunk.count('\n') + 1
                    sub_chunk += line + "\n"
                
                current_chunk = sub_chunk
                current_lines_start = sub_start_line
            else:
                current_chunk += node_text + "\n"
        else:
            current_chunk += node_text + "\n"

    # Capture trailing chunk
    if current_chunk.strip():
        chunks.append({
            "content": current_chunk,
            "start_line": current_lines_start,
            "context": current_context
        })

    return chunks, build_security_hotspots(tree, source_bytes), code_map

def process_file(file_path, output_dir):
    """Process a single JavaScript file."""
    print(f"Processing {file_path}...")
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return

    if not content.strip():
        print(f"Skipping empty file: {file_path}")
        return

    # Detect if minified
    lines = content.split('\n')
    avg_line_length = len(content) / max(len(lines), 1)
    is_minified = avg_line_length > 500 or len(lines) < 10
    
    if is_minified:
        print("  -> Detected minified code, beautifying...")

    # Unminify
    try:
        options = jsbeautifier.default_options()
        options.indent_size = 2
        options.preserve_newlines = True
        options.max_preserve_newlines = 2
        beautified = jsbeautifier.beautify(content, options)
    except Exception as e:
        print(f"  Warning: Beautification failed: {e}")
        beautified = content

    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)
    file_output_dir = os.path.join(output_dir, name)
    os.makedirs(file_output_dir, exist_ok=True)

    # Semantic Split
    try:
        chunks, hotspots, code_map = semantic_split(beautified, base_name)
    except Exception as e:
        print(f"  Error during semantic split: {e}")
        chunks = simple_split_fallback(beautified, name)
        hotspots = []
        code_map = []

    if not chunks:
        print(f"  No chunks created for {file_path}")
        return

    # Save structure map
    map_path = os.path.join(file_output_dir, "_structure.json")
    try:
        with open(map_path, "w", encoding='utf-8') as map_file:
            json.dump({
                "file": base_name,
                "total_chunks": len(chunks),
                "total_definitions": len(code_map),
                "definitions": code_map
            }, map_file, indent=2)
        print(f"  -> Created structure map with {len(code_map)} definitions")
    except Exception as e:
        print(f"  Warning: Could not save structure map: {e}")

    # Scan ALL content for security patterns
    print(f"  -> Scanning for security patterns...")
    all_findings = scan_security_patterns(beautified)
    
    # Group findings by chunk
    findings_by_chunk = [[] for _ in chunks]
    for finding in all_findings:
        for i, chunk_data in enumerate(chunks):
            chunk_end = chunk_data['start_line'] + chunk_data['content'].count('\n')
            if chunk_data['start_line'] <= finding['line'] <= chunk_end:
                findings_by_chunk[i].append(finding)
                break

    # Create security report
    report = {
        "file": base_name,
        "is_minified": is_minified,
        "total_chunks": len(chunks),
        "total_findings": len(all_findings),
        "findings_summary": {
            "secrets": len([f for f in all_findings if f['category'] == 'secrets']),
            "dom_xss": len([f for f in all_findings if f['category'] == 'dom_xss']),
            "user_input": len([f for f in all_findings if f['category'] == 'user_input']),
            "redirects": len([f for f in all_findings if f['category'] == 'redirects']),
            "network": len([f for f in all_findings if f['category'] == 'network']),
        },
        "critical_findings": [f for f in all_findings if f['category'] in ['secrets', 'dom_xss']],
        "hotspots": hotspots[:20],  # Limit to top 20
        "chunks_with_findings": [i+1 for i, findings in enumerate(findings_by_chunk) if findings]
    }

    # Save security report
    report_path = os.path.join(file_output_dir, "_SECURITY_REPORT.json")
    with open(report_path, "w", encoding='utf-8') as f:
        json.dump(report, f, indent=2)

    # Save chunks with security annotations
    for i, chunk_data in enumerate(chunks):
        chunk_name = f"{name}_part_{i+1:03d}{ext}"
        chunk_path = os.path.join(file_output_dir, chunk_name)
        
        chunk_findings = findings_by_chunk[i]
        
        header = f"// FILE: {base_name} | PART: {i+1}/{len(chunks)}\n"
        header += f"// CONTEXT: {chunk_data['context']}\n"
        header += f"// STARTING LINE: {chunk_data['start_line']}\n"
        
        if chunk_findings:
            header += f"//    SECURITY FINDINGS: {len(chunk_findings)}\n"
            for finding in chunk_findings[:5]:  # Show top 5
                header += f"//    - {finding['type']} at line {finding['line']}\n"
            if len(chunk_findings) > 5:
                header += f"//    ... and {len(chunk_findings) - 5} more\n"
        
        header += "// ----------------------------------------\n\n"
        
        with open(chunk_path, 'w', encoding='utf-8') as f:
            f.write(header + chunk_data['content'])

    print(f"    Created {len(chunks)} chunks")
    print(f"    Found {len(all_findings)} potential security issues")
    if report['critical_findings']:
        print(f"     {len(report['critical_findings'])} CRITICAL findings detected!")

def simple_split_fallback(content, name):
    """Fallback splitting method."""
    chunks = []
    lines = content.split('\n')
    chunk_size = 400
    
    for i in range(0, len(lines), chunk_size):
        chunk_lines = lines[i:i+chunk_size]
        chunks.append({
            "content": '\n'.join(chunk_lines),
            "start_line": i + 1,
            "context": f"Lines {i+1}-{min(i+chunk_size, len(lines))}"
        })
    
    return chunks

def process_directory(dir_path, output_dir):
    """Recursively process all JS files."""
    js_files = []
    
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.endswith('.js'):
                js_files.append(os.path.join(root, file))
    
    if not js_files:
        print(f"No JavaScript files found in {dir_path}")
        return
    
    print(f"Found {len(js_files)} JavaScript file(s)\n")
    
    for js_file in js_files:
        process_file(js_file, output_dir)
        print()

if __name__ == "__main__":
    parser_arg = argparse.ArgumentParser(
        description="Security-focused JS auditing tool - unminifies and scans for vulnerabilities"
    )
    parser_arg.add_argument("input", help="JavaScript file or directory")
    parser_arg.add_argument("--output", default="audit_workspace", help="Output directory")
    
    args = parser_arg.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Path '{args.input}' does not exist")
        exit(1)
    
    out_path = args.output
    os.makedirs(out_path, exist_ok=True)
    
    print("="*60)
    print("JS Security Audit Tool")
    print("="*60 + "\n")
    
    if os.path.isfile(args.input):
        process_file(args.input, out_path)
    elif os.path.isdir(args.input):
        process_directory(args.input, out_path)
    
    print("\n" + "="*60)
    print(f"  Audit complete! Results in: {out_path}/")
    print("="*60)