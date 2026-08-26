"""
Carregador e avaliador de regras Sigma.

As regras sao validadas contra o schema oficial do Sigma via `pysigma`
(pega erro de sintaxe/estrutura cedo). A avaliacao em si -- casar uma regra
contra um evento -- e um interpretador proprio e enxuto: cobre o subconjunto
do Sigma realmente usado neste projeto (um ou mais blocos de selecao
combinados com and/or/not, modificadores contains/startswith/endswith),
nao a especificacao completa (ex: regras de correlacao formais).
"""

import os
import re

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

CONDITION_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


def load_rules(rules_dir):
    rules = []
    for fname in sorted(os.listdir(rules_dir)):
        if not fname.endswith((".yml", ".yaml")):
            continue

        with open(os.path.join(rules_dir, fname), encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # "threshold" e uma extensao nossa (nao existe no Sigma oficial) --
        # removida antes de validar contra o schema real.
        standard_fields = {k: v for k, v in data.items() if k != "threshold"}
        try:
            SigmaCollection.from_yaml(yaml.dump(standard_fields))
        except SigmaError as exc:
            print(f"[detection] regra invalida, ignorada: {fname} ({exc})", flush=True)
            continue

        data["_file"] = fname
        rules.append(data)

    return rules


def flatten_event(row):
    """Achata uma linha de raw_events num dict simples: colunas no topo,
    campos do payload prefixados com 'payload.' -- e assim que os campos
    sao referenciados nas regras (ex: payload.severity)."""
    flat = {
        "source": row["source"],
        "event_type": row["event_type"],
        "host": row["host"],
        "src_ip": row["src_ip"],
    }
    for key, value in (row["payload"] or {}).items():
        flat[f"payload.{key}"] = value
    return flat


def _field_matches(event, field, modifier, value_spec):
    actual = event.get(field)
    if actual is None:
        return False

    actual_str = str(actual).lower()
    candidates = value_spec if isinstance(value_spec, list) else [value_spec]

    for candidate in candidates:
        cand_str = str(candidate).lower()
        if modifier == "contains":
            match = cand_str in actual_str
        elif modifier == "startswith":
            match = actual_str.startswith(cand_str)
        elif modifier == "endswith":
            match = actual_str.endswith(cand_str)
        else:
            match = actual_str == cand_str
        if match:
            return True
    return False


def _block_matches(event, block):
    """Um bloco de selecao casa se TODOS os seus campos casarem (AND implicito,
    igual ao comportamento real do Sigma dentro de um bloco)."""
    for raw_field, value_spec in block.items():
        field, _, modifier = raw_field.partition("|")
        if not _field_matches(event, field, modifier, value_spec):
            return False
    return True


def _tokenize(condition):
    return CONDITION_TOKEN_RE.findall(condition)


def evaluate(rule, event):
    """Avalia a string em rule['detection']['condition'] (ex: 'selection',
    'selecao1 and not selecao2') contra um evento achatado."""
    detection = rule["detection"]
    tokens = _tokenize(detection["condition"])
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def advance():
        tok = tokens[pos[0]]
        pos[0] += 1
        return tok

    def parse_expr():
        value = parse_term()
        while peek() == "or":
            advance()
            value = value or parse_term()
        return value

    def parse_term():
        value = parse_factor()
        while peek() == "and":
            advance()
            value = value and parse_factor()
        return value

    def parse_factor():
        tok = peek()
        if tok == "not":
            advance()
            return not parse_factor()
        if tok == "(":
            advance()
            value = parse_expr()
            advance()  # ')'
            return value
        advance()
        block = detection.get(tok)
        if block is None:
            raise ValueError(f"bloco '{tok}' nao existe na regra {rule.get('id')}")
        return _block_matches(event, block)

    return parse_expr()
