import os
import ast
import javalang
import subprocess
import lief
import r2pipe
from tree_sitter import Language, Parser
import tempfile
import json
from typing import Dict, List, Any, Optional
import hashlib
import re

class MultiFormatParser:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.setup_tree_sitter()
        
    def setup_tree_sitter(self):
        """Setup Tree-sitter for multiple languages"""
        try:
            # This would need tree-sitter languages built
            # For now, we'll use basic parsers
            self.parsers = {}
        except Exception as e:
            print(f"Warning: Tree-sitter setup failed: {e}")
    
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """Parse any supported file type"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext in ['.c', '.cpp', '.h', '.hpp']:
            return self.parse_c_cpp(file_path)
        elif file_ext == '.py':
            return self.parse_python(file_path)
        elif file_ext == '.java':
            return self.parse_java(file_path)
        elif file_ext == '.js':
            return self.parse_javascript(file_path)
        elif file_ext in ['.exe', '.bin', '.so', '.dylib']:
            return self.parse_binary(file_path)
        else:
            return self.parse_generic(file_path)
    
    def parse_python(self, file_path: str) -> Dict[str, Any]:
        """Parse Python source code"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        try:
            tree = ast.parse(content)
            features = {
                'file_type': 'python',
                'ast': self.ast_to_dict(tree),
                'tokens': self.tokenize_python(content),
                'imports': self.extract_imports(tree),
                'functions': self.extract_functions(tree),
                'classes': self.extract_classes(tree),
                'raw_content': content[:10000]  # Limit size
            }
            return features
        except SyntaxError as e:
            return {'file_type': 'python', 'error': str(e), 'raw_content': content[:10000]}
    
    def parse_java(self, file_path: str) -> Dict[str, Any]:
        """Parse Java source code"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        try:
            tree = javalang.parse.parse(content)
            features = {
                'file_type': 'java',
                'imports': [str(imp.path) for imp in tree.imports] if tree.imports else [],
                'classes': [str(cld.name) for cld in tree.types] if tree.types else [],
                'methods': self.extract_java_methods(tree),
                'raw_content': content[:10000]
            }
            return features
        except Exception as e:
            return {'file_type': 'java', 'error': str(e), 'raw_content': content[:10000]}
    
    def parse_c_cpp(self, file_path: str) -> Dict[str, Any]:
        """Parse C/C++ source code"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Basic C/C++ parsing (simplified)
        features = {
            'file_type': 'c_cpp',
            'includes': self.extract_includes(content),
            'functions': self.extract_c_functions(content),
            'macros': self.extract_macros(content),
            'raw_content': content[:10000]
        }
        return features
    
    def parse_binary(self, file_path: str) -> Dict[str, Any]:
        """Parse binary files using LIEF and radare2"""
        features = {
            'file_type': 'binary',
            'lief_analysis': {},
            'radare2_analysis': {},
            'security_indicators': []
        }
        
        try:
            # LIEF Analysis
            binary = lief.parse(file_path)
            if binary:
                lief_features = {
                    'format': str(binary.format),
                    'entry_point': hex(binary.entrypoint),
                    'sections': [{
                        'name': section.name,
                        'size': section.size,
                        'entropy': section.entropy,
                        'flags': [str(flag) for flag in section.flags_list]
                    } for section in binary.sections],
                    'imports': [str(imp.name) for imp in binary.imports],
                    'exports': [str(exp.name) for exp in binary.exports],
                    'libraries': binary.libraries
                }
                features['lief_analysis'] = lief_features
                
                # Security indicators
                if self.check_pie(binary):
                    features['security_indicators'].append('PIE_ENABLED')
                if self.check_nx(binary):
                    features['security_indicators'].append('NX_ENABLED')
                if self.check_canary(binary):
                    features['security_indicators'].append('STACK_CANARY')
        except Exception as e:
            features['lief_analysis']['error'] = str(e)
        
        try:
            # Radare2 Analysis
            r2 = r2pipe.open(file_path)
            r2.cmd('aaa')  # Auto-analysis
            
            # Get basic info
            info = r2.cmdj('ij')
            imports = r2.cmdj('iij')
            exports = r2.cmdj('iEj')
            functions = r2.cmdj('aflj')
            
            features['radare2_analysis'] = {
                'info': info,
                'imports': imports,
                'exports': exports,
                'functions_count': len(functions) if functions else 0
            }
            
            r2.quit()
        except Exception as e:
            features['radare2_analysis']['error'] = str(e)
        
        return features
    
    def parse_javascript(self, file_path: str) -> Dict[str, Any]:
        """Parse JavaScript files"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Basic JS parsing
        features = {
            'file_type': 'javascript',
            'functions': self.extract_js_functions(content),
            'calls': self.extract_js_calls(content),
            'raw_content': content[:10000]
        }
        return features
    
    def parse_generic(self, file_path: str) -> Dict[str, Any]:
        """Parse generic text files"""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        return {
            'file_type': 'generic',
            'raw_content': content[:10000],
            'size': len(content)
        }
    
    # Helper methods for feature extraction
    def extract_imports(self, tree) -> List[str]:
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    imports.append(alias.name)
        return imports
    
    def extract_functions(self, tree) -> List[Dict]:
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'args': [arg.arg for arg in node.args.args],
                    'lineno': node.lineno
                })
        return functions
    
    def extract_classes(self, tree) -> List[Dict]:
        """Extract class definitions from Python AST"""
        classes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.append({
                    'name': node.name,
                    'lineno': node.lineno,
                    'methods': [n.name for n in node.body if isinstance(n, ast.FunctionDef)]
                })
        return classes
    
    def extract_java_methods(self, tree) -> List[Dict]:
        methods = []
        for path, node in tree.filter(javalang.tree.MethodDeclaration):
            methods.append({
                'name': node.name,
                'parameters': [param.name for param in node.parameters] if node.parameters else [],
                'return_type': str(node.return_type) if node.return_type else 'void'
            })
        return methods
    
    def extract_c_functions(self, content: str) -> List[Dict]:
        # Simplified C function extraction
        functions = []
        pattern = r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{'
        matches = re.finditer(pattern, content)
        for match in matches:
            functions.append({
                'return_type': match.group(1),
                'name': match.group(2)
            })
        return functions
    
    def extract_js_functions(self, content: str) -> List[Dict]:
        functions = []
        # Match function declarations
        patterns = [
            r'function\s+(\w+)\s*\([^)]*\)',
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>',
            r'let\s+(\w+)\s*=\s*\([^)]*\)\s*=>'
        ]
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                functions.append({'name': match.group(1)})
        return functions
    
    def extract_includes(self, content: str) -> List[str]:
        """Extract #include statements from C/C++ code"""
        includes = []
        pattern = r'#include\s+[<"]([^>"]+)[>"]'
        matches = re.finditer(pattern, content)
        for match in matches:
            includes.append(match.group(1))
        return includes
    
    def extract_macros(self, content: str) -> List[str]:
        """Extract macro definitions from C/C++ code"""
        macros = []
        pattern = r'#define\s+(\w+)'
        matches = re.finditer(pattern, content)
        for match in matches:
            macros.append(match.group(1))
        return macros
    
    def extract_js_calls(self, content: str) -> List[str]:
        """Extract function calls from JavaScript code"""
        calls = []
        pattern = r'(\w+)\s*\('
        matches = re.finditer(pattern, content)
        for match in matches:
            calls.append(match.group(1))
        return calls
    
    def tokenize_python(self, content: str) -> List[str]:
        """Simple tokenization for Python"""
        try:
            tokens = []
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    tokens.append(node.id)
                elif isinstance(node, ast.Str):
                    tokens.append(f"STR_{hashlib.md5(node.s.encode()).hexdigest()[:8]}")
            return tokens
        except:
            return []
    
    def ast_to_dict(self, node):
        """Convert AST node to dictionary"""
        if isinstance(node, ast.AST):
            result = {'type': type(node).__name__}
            for field in node._fields:
                value = getattr(node, field)
                result[field] = self.ast_to_dict(value)
            return result
        elif isinstance(node, list):
            return [self.ast_to_dict(item) for item in node]
        else:
            return node
    
    # Binary security checks
    def check_pie(self, binary) -> bool:
        try:
            return binary.is_pie
        except:
            return False
    
    def check_nx(self, binary) -> bool:
        try:
            for segment in binary.segments:
                if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                    if not segment.has(lief.ELF.SEGMENT_FLAGS.X):
                        return True
            return False
        except:
            return False
    
    def check_canary(self, binary) -> bool:
        try:
            # Check for stack canary symbols
            symbols = binary.symbols
            canary_symbols = ['__stack_chk_fail', '__stack_chk_guard']
            for symbol in symbols:
                if symbol.name in canary_symbols:
                    return True
            return False
        except:
            return False

if __name__ == "__main__":
    # Test the parser
    config = {
        'supported_languages': ['python', 'java', 'c', 'cpp', 'javascript']
    }
    parser = MultiFormatParser(config)
    
    # Test with a sample Python file
    sample_code = """
import os
import sys

class TestClass:
    def method1(self):
        pass
        
    def method2(self):
        pass

def vulnerable_function(user_input):
    # This is a vulnerable function
    os.system(user_input)  # Command injection vulnerability
    
def safe_function(data):
    # This is a safe function
    return data.strip()
    """
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(sample_code)
        temp_file = f.name
    
    try:
        result = parser.parse_file(temp_file)
        print("Parsing result:")
        print(json.dumps(result, indent=2))
    finally:
        os.unlink(temp_file)
