"""escalation — bloqueio progressivo por reincidência (estilo fail2ban), comum aos 7
detectores (todos já são por-cliente/src_ip, ao contrário do FlowGuard onde só o
detector de scan tem um único atacante pra escalar contra — ver
bgp/escalation.py de lá pro mesmo conceito, config espelhada).

Só afeta a DURAÇÃO de uma mitigação que já ia acontecer de qualquer forma
(flowspec_mitigation.apply_and_record, chamado por detector.py::_record_signal) —
não é um mecanismo de bloqueio novo. Reincidência é contada via o histórico de
edge_mitigations (nunca deleta linha, mecanismo-agnóstico: conta ssh e flowspec).
"""

from __future__ import annotations

import time
from pathlib import Path

import yaml

import storage

DEFAULT_CONFIG_PATH = str(Path(__file__).resolve().parent / "escalation.yaml")

DEFAULT_CONFIG = {
    "enabled": True,
    "tracking_window_s": 604800,   # 7 dias — reincidência conta dentro dessa janela
    "base_ttl_s": None,            # None = usa flowspec_mitigation.yaml::default_ttl_s como base
    "factor": 4,                   # cada reincidência multiplica a duração por isso
    "max_ttl_s": 604800,           # teto: 7 dias (nunca "permanente" via automação)
    "max_steps": 5,                # trava no teto depois de N reincidências
}

HEADER = (
    "# escalation.yaml — bloqueio progressivo por reincidência (estilo fail2ban),\n"
    "# comum aos 7 detectores. Cada vez que o MESMO src_ip é mitigado de novo dentro de\n"
    "# tracking_window_s, a duração da próxima mitigação cresce (base_ttl_s * factor ^ N\n"
    "# reincidências), até o teto max_ttl_s. base_ttl_s vazio/null usa\n"
    "# flowspec_mitigation.yaml::default_ttl_s como base da 1ª ofensa. Editável via\n"
    "# portal (aba ClientGuard > Configurações) ou clientguard-cli escalation set."
)


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return dict(DEFAULT_CONFIG)
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    merged = dict(DEFAULT_CONFIG)
    merged.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
    return merged


def save_config(changes: dict, path: str = DEFAULT_CONFIG_PATH) -> dict:
    unknown = sorted(k for k in changes if k not in DEFAULT_CONFIG)
    if unknown:
        raise ValueError(f"chave(s) desconhecida(s): {', '.join(unknown)}")
    if "enabled" in changes and not isinstance(changes["enabled"], bool):
        raise ValueError("enabled precisa ser true/false")
    for key in ("tracking_window_s", "base_ttl_s", "max_ttl_s", "max_steps"):
        if key in changes and changes[key] is not None:
            try:
                value = int(changes[key])
            except (TypeError, ValueError):
                raise ValueError(f"{key} precisa ser um inteiro")
            if value <= 0:
                raise ValueError(f"{key} precisa ser positivo")
    if "factor" in changes:
        try:
            factor = float(changes["factor"])
        except (TypeError, ValueError):
            raise ValueError("factor precisa ser numérico")
        if factor <= 1:
            raise ValueError("factor precisa ser maior que 1 (senão não escalona)")
    current = load_config(path)
    current.update(changes)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(HEADER.rstrip() + "\n")
        yaml.safe_dump(current, fh, sort_keys=False, allow_unicode=True)
    return current


def next_ttl_s(conn, src_ip: str, cfg: dict, base_ttl_s: int | None = None) -> int:
    """TTL (segundos) da próxima mitigação de src_ip, crescendo com o número de vezes
    que ele já foi mitigado (qualquer detector/mecanismo) dentro de
    cfg['tracking_window_s']. offense_no=0 na primeira ofensa (usa base pura),
    cresce por cfg['factor'] a cada reincidência, até travar em cfg['max_ttl_s']."""
    base = cfg.get("base_ttl_s") or base_ttl_s
    if base is None:
        raise ValueError("next_ttl_s: base_ttl_s ausente (nem em escalation.yaml nem passado por parâmetro)")
    if not cfg.get("enabled", True):
        return base
    since = int(time.time()) - cfg["tracking_window_s"]
    offense_no = storage.count_recent_mitigations(conn, src_ip, since)
    step = min(offense_no, cfg["max_steps"])
    return min(int(base * (cfg["factor"] ** step)), cfg["max_ttl_s"])
