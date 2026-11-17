import os

ROOT_DIR = os.environ['SNAPFUZZ_DIR']

DO_ASSERT = True

IS_DEBUG = False

DO_EXPENSIVE_ASSERT = False # More expensive assertions

NO_REMOVE_TMPFILES = True

PATH_TO_TMP=os.path.join(ROOT_DIR, 'data')  

PATH_TO_FIGURES = os.path.join(ROOT_DIR, 'figs')  