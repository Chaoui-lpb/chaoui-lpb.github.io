import re

def transform_string(input_string):
    # Find all occurrences of the pattern ![[Pasted image <timestamp>.png]]
    pattern = r'!\[\[(Pasted image \d{14}\.png)\]\]'
    matches = re.findall(pattern, input_string)
    
    for match in matches:
        # Replace spaces with %20
        transformed_match = match.replace(' ', '_')
        # Construct the new string
        new_string = f"![](/images/SpyBOF/{transformed_match})"
        # Replace the original string with the new string
        input_string = input_string.replace(f'![[{match}]]', new_string)
    
    return input_string

def process_file(input_file, output_file):
    with open(input_file, 'r') as file:
        content = file.read()
    
    transformed_content = transform_string(content)
    
    with open(output_file, 'w') as file:
        file.write(transformed_content)

# Precise the name of the file
input_file = 'keylogger-pt1.md'
process_file(input_file, input_file)