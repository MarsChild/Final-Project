from __init__ import __init__
import unittest

class FlaskTestCase(unittest.TestCase):

    # Ensure that Flask was set up correctly
    def test_index(self):
        tester = __init__.test_client(self)
        response = tester.get('/login', content_type='html/text')
        self.assertEqual(response.status_code, 200)

if __name__ == '__main__':
    unittest.main()