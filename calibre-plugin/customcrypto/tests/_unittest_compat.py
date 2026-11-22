"""unittest.TestCase with subTest() and assertRaisesRegex() on Python 2.7 too"""

import contextlib
import unittest


class TestCase(unittest.TestCase):

    if not hasattr(unittest.TestCase, 'subTest'):
        @contextlib.contextmanager
        def subTest(self, **params):
            # Python 2.7 stops at the first failing case, but still says which one it was
            try:
                yield
            except self.failureException as e:
                raise self.failureException('%s (%s)' % (e, ', '.join(
                    '%s=%r' % item for item in sorted(params.items()))))

    if not hasattr(unittest.TestCase, 'assertRaisesRegex'):
        assertRaisesRegex = unittest.TestCase.assertRaisesRegexp
