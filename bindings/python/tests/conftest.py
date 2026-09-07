import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REF = os.path.normpath(os.path.join(HERE, "..", "..", "..", "tools", "reference"))
if REF not in sys.path:
    sys.path.insert(0, REF)
