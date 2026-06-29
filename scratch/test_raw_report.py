"""
Test runner for raw aligned report.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import image_forensics as img_forensics
from PIL import Image
import io

def run_test():
    img = Image.new('RGB', (1920, 1100), color=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    raw_data = buf.getvalue()

    sample_xmp = '''
    <x:xmpmeta xmlns:x="adobe:ns:meta/">
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description photoshop:ColorMode="1" xmp:CreateDate="2024-06-26T07:39:05+03:00" xmpMM:DocumentID="adobe:docid:photoshop:d9582ade-b341-ab48-8885-199b99fda74f" xmpMM:InstanceID="xmp.iid:b9ab9f4c-172e-214d-9004-beb7d2f4d852" xmpMM:OriginalDocumentID="C1DF74933665E8BF198777DA6AE637CF">
    <photoshop:TextLayers>
    <rdf:Bag>
    <rdf:li photoshop:LayerName="FlagY{d524fb419cca8448411e333edb6567aa}" photoshop:LayerText="FlagY{d524fb419cca8448411e333edb6567aa}"/>
    </rdf:Bag>
    </photoshop:TextLayers>
    </rdf:Description>
    </rdf:RDF>
    </x:xmpmeta>
    '''.encode('utf-8')

    raw_data = raw_data + b'Photoshop 3.0\x00PhotoshopQuality 12\x00PhotoshopFormat Progressive\x00SlicesGroupName hacker-logo-design\x00Current IPTC Digest cdcffa7da8c7be09057076aeaf05c34e\x00' + sample_xmp + b'\x00Corrupt JPEG data: 2325 extraneous bytes before marker 0xda\x00'

    analysis = img_forensics.analyze_image_full(raw_data, 'challenge (1).jpg')
    pages = img_forensics.format_metadata_report(analysis)

    for idx, pg in enumerate(pages):
        print(f'=== PAGE {idx+1} ===')
        print(pg)

if __name__ == "__main__":
    run_test()
