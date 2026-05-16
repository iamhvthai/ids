import re

with open(r'e:\dacn_1\project\dacn1_ids\report\extracted_report\word\document.xml', 'r', encoding='utf-8') as f:
    content = f.read()

matches = re.findall(r'<w:t.*?>(.*?)</w:t>', content)
with open(r'e:\dacn_1\project\dacn1_ids\scratch\report_text.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(matches))
