"""Cliente mínimo do socket de controle do daemon — usado pelos CGI scripts do portal
para reutilizar a mesma lógica de validação/reload que o clientguard-cli já usa, em vez
de duplicá-la escrevendo direto nos arquivos de config."""

from __future__ import annotations

import json
import socket


def send_command(sock_path: str, payload: dict, timeout: float = 6.0) -> dict:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        data = b"".join(chunks).decode("utf-8").strip()
        return json.loads(data) if data else {"ok": False, "error": "resposta vazia do daemon"}
    except FileNotFoundError:
        return {"ok": False, "error": f"socket não encontrado em {sock_path} — o daemon está rodando?"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "conexão recusada — daemon não está escutando no socket"}
    except PermissionError:
        return {"ok": False, "error": "permissão negada ao acessar o socket"}
    except socket.timeout:
        return {"ok": False, "error": "timeout ao falar com o daemon"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "resposta inválida do daemon"}
