import json
import os
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union


@dataclass
class Rule:
    category: str
    domain_or_ip: str
    stragety: str


def read_file(path: str) -> Union[list[str], dict]:
    _, file_extension = os.path.splitext(path)
    if file_extension == '.json':
        with open(path, 'r') as f:
            content = json.load(f)
    else:
        with open(path, 'r') as f:
            content = f.readlines()

    return content


def extract_rules(content: list[str]) -> Optional[list[str]]:
    try:
        index = content.index('rules:\n')
        return content[index + 1 :]
    except ValueError:
        return None


def parse_rule(rule: str) -> Rule:
    category, domain_or_ip, stragety = rule.split(',')
    category = category.split()[-1]
    stragety = stragety.strip()
    return Rule(category, domain_or_ip, stragety)


def is_valid_rule(rule: str) -> bool:
    return len(rule) > 1 and '#' not in rule and 'Others' not in rule


def match_stragety(rules: list[str]) -> dict[dict[str]]:
    output = {'passing': defaultdict(list), 'rejection': defaultdict(list)}
    passing = ['DIRECT', 'Domestic', 'China_media']
    rejection = ['REJECT']
    ignore = ['GEOIP']
    category_map = {
        'DOMAIN': 'domain',
        'DOMAIN-SUFFIX': 'domain_suffix',
        'DOMAIN-KEYWORD': 'domain_keyword',
        'IP-CIDR': 'ip_cidr',
    }

    for rule in rules:
        #   - DOMAIN-SUFFIX,ad.12306.cn,REJECT
        if is_valid_rule(rule):
            result = parse_rule(rule)
            category = category_map.get(result.category)
            if result.stragety in passing and result.category not in ignore:
                target = 'passing'
                output[target][category].append(result.domain_or_ip)
            elif result.stragety in rejection and result.category not in ignore:
                target = 'rejection'
                output[target][category].append(result.domain_or_ip)
            else:
                print(f'{rule.strip()} is not matched.')

    output['passing']['outbound'] = 'direct'
    output['rejection']['outbound'] = 'block'

    return output


def add_to_route(new_rules: dict[dict[str, list]]) -> None:
    base_path = Path(__file__)
    template_json = read_file(os.path.join(base_path.parent.parent, 'template', 'config.json'))
    for tag in new_rules:
        template_json['route']['rules'].append(new_rules[tag])

    with open('config.json', 'w') as f:
        json.dump(template_json, f)


if __name__ == '__main__':
    clash_file = f'{str(Path.home())}/.config/clash/config.yaml'
    content = read_file(clash_file)
    rules = extract_rules(content)
    new_rules = match_stragety(rules)
    add_to_route(new_rules)
