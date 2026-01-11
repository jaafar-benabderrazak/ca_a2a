#!/usr/bin/env python3
"""
Remove emojis from documentation files
"""
import re
import os

# List of files to process
files = [
    'A2A_PROTOCOL_DEMO_VIDEO_GUIDE.md',
    'A2A_PROTOCOL_SECURITY_TECHNICAL.md',
    'DEMO_2H_COMPREHENSIVE.md',
    'AGENT_SECURITY_TESTING_GUIDE.md',
    'CLOUDSHELL_DEPLOYMENT_GUIDE.md',
    'SECURITY_TESTING_DOCUMENTATION.md',
    'ENHANCED_SECURITY_IMPLEMENTATION_REPORT.md',
    'TEST_SUITE_EXPLAINED.md',
    'COMPLETE_TECHNICAL_DOCUMENTATION.md',
    'LINKEDIN_ARTICLE.md',
    'AWS_ARCHITECTURE_DIAGRAM.md',
    'README.md',
    'COMPLETE_DEMO_GUIDE.md',
    'SYSTEM_ARCHITECTURE.md',
    'SECURITY_GUIDE.md',
    'TEST_SECURITY_ENHANCED_GUIDE.md'
]

# Emoji pattern (covers most common emojis)
emoji_pattern = re.compile(
    '['
    '\U0001F300-\U0001F9FF'  # Miscellaneous Symbols and Pictographs
    '\U0001F600-\U0001F64F'  # Emoticons
    '\U0001F680-\U0001F6FF'  # Transport and Map Symbols
    '\U00002600-\U000026FF'  # Miscellaneous Symbols
    '\U00002700-\U000027BF'  # Dingbats
    '\U0001F900-\U0001F9FF'  # Supplemental Symbols and Pictographs
    '\U0001FA70-\U0001FAFF'  # Symbols and Pictographs Extended-A
    ']+'
)

processed = 0
errors = []

for filepath in files:
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Remove emojis
            new_content = emoji_pattern.sub('', content)
            
            # Clean up multiple spaces left by emoji removal
            new_content = re.sub(r'  +', ' ', new_content)
            # Clean up space at start of lines (but preserve indentation)
            new_content = re.sub(r'^ {3,}', '', new_content, flags=re.MULTILINE)
            
            if content != new_content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                processed += 1
                print(f'[OK] Processed: {filepath}')
            else:
                print(f'[-] No emojis found: {filepath}')
        except Exception as e:
            error_msg = f'Error processing {filepath}: {e}'
            errors.append(error_msg)
            print(f'[ERROR] {error_msg}')
    else:
        print(f'[-] Skipped (not found): {filepath}')

print(f'\n' + '='*60)
print(f'Total files processed: {processed}')
print(f'Errors: {len(errors)}')
if errors:
    print('\nErrors:')
    for error in errors:
        print(f'  - {error}')

