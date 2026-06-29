"""Test that the binary EXIF IFD parser extracts real fields from embedded JPEG."""
import sys
sys.path.insert(0, '.')
import image_forensics as f
import struct, io

# Build a JPEG with APP1 EXIF containing real tags (Make, Model, Software, ModifyDate)
def make_app1():
    tiff_header = b'MM\x00\x2A\x00\x00\x00\x08'
    # IFD entries: 4 tags. Data starts at offset = 8 + 2 + 4*12 + 4 = 62
    data_offset = 62
    string_area = b''
    ifd_raw = b''

    def add_str(tag_id, value_bytes):
        nonlocal string_area
        off = data_offset + len(string_area)
        string_area += value_bytes
        return struct.pack('>HHII', tag_id, 2, len(value_bytes), off)

    ifd_raw += add_str(0x010F, b'TestMake\x00')
    ifd_raw += add_str(0x0110, b'TestModel\x00')
    ifd_raw += add_str(0x0131, b'Adobe Photoshop 25.3 (Windows)\x00')
    ifd_raw += add_str(0x0132, b'2024:06:26 08:13:14\x00')
    ifd = struct.pack('>H', 4) + ifd_raw + b'\x00\x00\x00\x00'
    tiff = tiff_header + ifd + string_area
    exif_block = b'Exif\x00\x00' + tiff
    app1 = b'\xff\xe1' + struct.pack('>H', 2 + len(exif_block)) + exif_block
    return app1

soi      = b'\xff\xd8'
app1     = make_app1()
sof0     = b'\xff\xc0\x00\x11\x08\x00\x64\x00\x64\x03\x01\x11\x00\x02\x11\x01\x03\x11\x01'
sos_data = b'\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00\x00\x01\x7f\xff\xd9'
jpeg_data = soi + app1 + sof0 + sos_data

analysis = f.analyze_image_full(jpeg_data, 'challenge (1).jpg')
pages = f.format_metadata_report(analysis)
full = '\n'.join(pages)

CHECKS = ['TestMake', 'TestModel', 'Adobe Photoshop 25.3', '2024:06:26 08:13:14']
all_ok = True
for c in CHECKS:
    found = c in full
    print(f"  {'OK  ' if found else 'MISS'}: {c}")
    if not found:
        all_ok = False

print()
print("RESULT:", "PASS" if all_ok else "FAIL")
print()
print(full[:2500])
