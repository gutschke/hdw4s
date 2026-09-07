"""Print the JavaScript that hdw4s-update injects into the client page.

Anchors on the last occurrence of each marker: the sed command that strips the
block also contains both marker strings, and would otherwise match first.
"""
import sys

s = open('hdw4s-update').read()
a = s.rindex('<!-- HDW4S_PATCH_START -->')
b = s.rindex('<!-- HDW4S_PATCH_END -->')
block = s[a:b]
sys.stdout.write(block[block.index('<script>') + len('<script>'):
                       block.rindex('</script>')])
