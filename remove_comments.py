import tokenize
import os
from io import BytesIO

def remove_comments(source):
    io_obj = BytesIO(source)
    out = ""
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0
    
    tokens = tokenize.tokenize(io_obj.readline)
    for tok in tokens:
        token_type = tok.type
        token_string = tok.string
        start_line, start_col = tok.start
        end_line, end_col = tok.end
        
        if start_line > last_lineno:
            last_col = 0
        if start_col > last_col:
            out += " " * (start_col - last_col)
            
        if token_type == tokenize.COMMENT:
            pass
        elif token_type == tokenize.NL:
            pass # Skip NL tokens that might be associated with comments? No, NL is important.
                 # Actually, tokenize.untokenize is better for reconstruction but it's sometimes tricky with spacing.
                 # Let's try a simpler approach with untokenize first, or manual reconstruction.
                 # Manual reconstruction is safer for preserving exact formatting minus comments.
            pass
        
        # Wait, manual reconstruction is hard. tokenize.untokenize is standard.
        # Let's use a filter generator for untokenize.
        pass

def remove_comments_file(filepath):
    with open(filepath, 'rb') as f:
        source = f.read()
    
    io_obj = BytesIO(source)
    out = BytesIO()
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0

    try:
        tokens = tokenize.tokenize(io_obj.readline)
        result = tokenize.untokenize(
            (tok.type, tok.string) for tok in tokens if tok.type != tokenize.COMMENT
        )
        
        # untokenize returns bytes in Python 3
        with open(filepath, 'wb') as f:
            f.write(result)
        print(f"Processed: {filepath}")
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

def main():
    target_dir = '/home/youssef/Documents/scanner/vulnhunter'
    for root, dirs, files in os.walk(target_dir):
        if 'venv' in dirs:
            dirs.remove('venv') # Don't traverse venv
        
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                remove_comments_file(filepath)

if __name__ == "__main__":
    main()
