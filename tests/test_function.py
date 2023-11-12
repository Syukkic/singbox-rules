import unittest

from src.main import extract_rules, is_valid_rule, match_stragety, parse_rule, read_file


class TestFunction(unittest.TestCase):
    def test_read_file_json(self):
        # Test reading a JSON file
        content = read_file('src/template/config.json')
        self.assertIsInstance(content, dict)

    def test_read_file_non_json(self):
        content = read_file('tests/test_file.txt')
        self.assertIsInstance(content, list)

    def test_extract_rules(self):
        # Test extracting rules from content
        content = ['some content', 'rules:\n', 'rule1', 'rule2']
        rules = extract_rules(content)
        self.assertIsNotNone(rules)
        self.assertGreater(len(rules), 0)

    def test_parse_rule(self):
        # Test parsing a rule
        rule_str = 'DOMAIN-SUFFIX,example.com,DIRECT'
        rule = parse_rule(rule_str)
        self.assertEqual(rule.category, 'DOMAIN-SUFFIX')
        self.assertEqual(rule.domain_or_ip, 'example.com')
        self.assertEqual(rule.stragety, 'DIRECT')

    def test_is_valid_rule(self):
        # Test rule validity
        valid_rule = 'DOMAIN,example.com,DIRECT'
        invalid_rule = '# This is a comment'
        self.assertTrue(is_valid_rule(valid_rule))
        self.assertFalse(is_valid_rule(invalid_rule))

    def test_match_strategy(self):
        # Test matching strategies
        rules = [
            'DOMAIN,example.com,DIRECT',
            'DOMAIN-SUFFIX,example.com,REJECT',
        ]
        result = match_stragety(rules)
        self.assertIn('passing', result)
        self.assertIn('rejection', result)


if __name__ == '__main__':
    unittest.main()
