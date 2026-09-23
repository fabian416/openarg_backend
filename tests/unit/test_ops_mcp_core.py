"""El núcleo del MCP de operaciones decide qué puede correr en un servidor.

Spec 028. Lo que se prueba acá es lo único del MCP que importa que no falle:
que ninguna entrada pueda armar un comando fuera del catálogo, que ningún
secreto salga en una respuesta, y que el cruce de colas nombre la tarea
huérfana. `server.py` no se importa: depende de `mcp`, que no es dependencia
del proyecto (SC-004).
"""

from __future__ import annotations

import json

import pytest
from scripts.ops_mcp import ops_core


@pytest.mark.parametrize(
    "nombre",
    ["openarg-worker-ingest-1", "backend", "worker_collector.heavy", "a"],
)
def test_nombres_de_contenedor_validos(nombre: str) -> None:
    assert ops_core.validate_container(nombre) == nombre


@pytest.mark.parametrize(
    "nombre",
    [
        "",
        "-rf",  # no puede empezar con guión: docker lo leería como flag
        "backend; rm -rf /",
        "backend$(id)",
        "backend`id`",
        "backend && reboot",
        "backend|cat /etc/passwd",
        "../../etc/passwd",
        "backend\nreboot",
        "a" * 129,
    ],
)
def test_nombres_de_contenedor_rechazados(nombre: str) -> None:
    with pytest.raises(ValueError):
        ops_core.validate_container(nombre)


@pytest.mark.parametrize("lineas", [1, 100, ops_core.MAX_LOG_LINES])
def test_lineas_validas(lineas: int) -> None:
    assert ops_core.validate_lines(lineas) == lineas


@pytest.mark.parametrize("lineas", [0, -1, ops_core.MAX_LOG_LINES + 1, "10", 10.0, True, None])
def test_lineas_rechazadas(lineas: object) -> None:
    with pytest.raises(ValueError):
        ops_core.validate_lines(lineas)  # type: ignore[arg-type]


def test_solo_logs_recibe_valores_del_llamador() -> None:
    """Los únicos valores externos son "$1" / "$2", y sólo los usa `logs`.

    Un comando nuevo que lea un parámetro posicional tiene que pasar por acá:
    es la señal de que necesita su propio validador antes de existir.
    """
    import re

    for nombre, script in ops_core.COMMANDS.items():
        usa_posicionales = bool(re.search(r"\$\{?[0-9@*]", script))
        assert usa_posicionales == (nombre == "logs"), nombre
    # Siempre entre comillas dobles: sin ellas, un valor con espacios se parte.
    assert ops_core.COMMANDS["logs"].count('"$1"') == 1
    assert ops_core.COMMANDS["logs"].count('"$2"') == 1


def test_ningun_comando_del_catalogo_escribe() -> None:
    """FR-001: el catálogo es de sólo lectura."""
    prohibidos = (
        " rm ",
        "docker restart",
        "docker stop",
        "docker start",
        "docker kill",
        "docker rm",
        "docker pull",
        "compose up",
        "compose down",
        "sudo",
        " > ",
        ">>",
        "FLUSH",
        "DEL ",
        "DROP",
        "UPDATE ",
        "DELETE ",
    )
    for nombre, script in ops_core.COMMANDS.items():
        for palabra in prohibidos:
            assert palabra not in script, f"{nombre} contiene {palabra!r}"


def test_todo_comando_asegura_el_daemon_antes_de_preguntar() -> None:
    """Cada comando lee Docker, así que cada comando lo afirma primero."""
    for nombre, script in ops_core.COMMANDS.items():
        assert script.startswith("docker info"), f"{nombre} no empieza por el guard"


def test_sin_daemon_el_comando_falla_en_vez_de_contestar_vacio() -> None:
    """Sin Docker, hay que fallar fuerte; "cero contenedores" es una mentira.

    Encontrado el 2026-09-23 corriendo `deployed_images` contra una máquina con
    Docker apagado: `for c in $(docker ps …)` itera cero veces, el script sale 0
    y la herramienta contesta que no hay ningún contenedor. Un operador lee eso
    como "no hay nada desplegado", no como "no pude chequear" — que es el mismo
    vacío silencioso que este servidor existe para cazar.
    """
    import subprocess
    import tempfile

    # bash por ruta absoluta: el PATH que hereda el hijo está vacío a propósito,
    # así que ahí adentro no hay `docker` — ni `bash` para encontrarse a sí mismo.
    with tempfile.TemporaryDirectory() as path_sin_docker:
        done = subprocess.run(
            ["/bin/bash", "-s"],
            input=ops_core.COMMANDS["deployed_images"],
            capture_output=True,
            text=True,
            env={"PATH": path_sin_docker},
        )

    assert done.returncode != 0, (
        "sin docker el comando salió 0: contestó vacío como si fuera un dato"
    )
    assert "cannot reach the Docker daemon" in done.stderr
    assert done.stdout.strip() == ""


@pytest.mark.parametrize(
    ("entrada", "secreto"),
    [
        ("REDIS_PASSWORD=hunter2hunter2", "hunter2hunter2"),
        ("export BACKEND_API_KEY='abc123def456'", "abc123def456"),
        ('"GEMINI_API_KEY": "AIzaSyD-ejemplo-ejemplo-1234567"', "ejemplo-ejemplo"),
        ("DATABASE_URL=postgresql+psycopg://openarg:s3cr3t0@db:5432/x", "s3cr3t0"),
        ("redis://:clave-redis-larga@redis:6379/0", "clave-redis-larga"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.firma", "eyJhbGciOiJIUzI1NiJ9"),
        ("clave de usuario oarg_sk_9f8e7d6c5b4a3210", "oarg_sk_9f8e7d6c5b4a3210"),
        ("token de servicio svc_abcdef123456", "svc_abcdef123456"),
        ("aws AKIAIOSFODNN7EXAMPLE en el log", "AKIAIOSFODNN7EXAMPLE"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nAbCd\n-----END RSA PRIVATE KEY-----",
            "MIIEow",
        ),
    ],
)
def test_redact_tapa_secretos(entrada: str, secreto: str) -> None:
    salida = ops_core.redact(entrada)
    assert secreto not in salida
    assert "REDACTED" in salida


def test_redact_no_rompe_lo_que_no_es_secreto() -> None:
    linea = "[2026-09-09 12:00:01] recover_stuck_tasks succeeded in 2.7s: {'recovered': 109}"
    assert ops_core.redact(linea) == linea
    # El nombre de la variable se conserva: es lo que dice qué se tapó.
    assert ops_core.redact("REDIS_PASSWORD=x1y2z3w4").startswith("REDIS_PASSWORD=")


def test_cap_avisa_cuando_recorta() -> None:
    corto = "x" * 10
    assert ops_core.cap(corto) == corto
    largo = "a" * (ops_core.MAX_OUTPUT_CHARS + 50)
    salida = ops_core.cap(largo)
    assert salida.startswith("[truncated: 50 ")
    assert salida.endswith("a" * 100)


_COMANDOS = "\n".join(
    [
        "openarg-backend-1\t uvicorn app.run:make_app --factory --port 8080",
        "openarg-worker-ingest-1\t celery -A app.infrastructure.celery.app worker -Q ingest,orchestrator -c 2",
        "openarg-worker-collector-1\t celery -A x worker --queues=collector -c 8",
        'openarg-worker-s3-1\t celery -A x worker -Q "s3" -c 2',
        "openarg-redis-1\t docker-entrypoint.sh redis-server",
    ]
)


def test_parse_consumed_queues_lee_los_q_reales() -> None:
    consumidas = ops_core.parse_consumed_queues(_COMANDOS)
    assert consumidas == {
        "openarg-worker-ingest-1": ["ingest", "orchestrator"],
        "openarg-worker-collector-1": ["collector"],
        "openarg-worker-s3-1": ["s3"],
    }


def test_find_orphan_routes_nombra_la_tarea_huerfana() -> None:
    """SC-001, con la forma exacta del incidente del 2026-09-09."""
    despachadas = json.dumps(
        {
            "openarg.recover_stuck_tasks": "default",
            "openarg.bulk_collect_all": "orchestrator",
            "openarg.collect_dataset": "collector",
        }
    )
    resultado = ops_core.find_orphan_routes(despachadas, ops_core.parse_consumed_queues(_COMANDOS))
    assert resultado["orphan_routes"] == {"openarg.recover_stuck_tasks": "default"}
    assert "default" not in resultado["consumed_queues"]  # type: ignore[operator]
    assert "orchestrator" in resultado["consumed_queues"]  # type: ignore[operator]


def test_find_orphan_routes_no_inventa_un_verde() -> None:
    """Si no se pudieron leer las rutas, es un error: no "cero huérfanas"."""
    with pytest.raises(ValueError):
        ops_core.find_orphan_routes('{"error": "no running worker or beat container"}', {})


def test_el_snippet_de_rutas_respeta_la_precedencia_de_celery() -> None:
    """`options.queue` del beat pisa `task_routes`, igual que en
    `test_celery_queues_have_consumers._colas_despachadas`. Se ejecuta el
    snippet de verdad contra el `celery_app` del checkout.
    """
    import contextlib
    import io

    from app.infrastructure.celery.app import celery_app

    salida = io.StringIO()
    with contextlib.redirect_stdout(salida):
        exec(ops_core._ROUTES_SNIPPET, {})  # noqa: S102 - el snippet es una constante del repo
    rutas = json.loads(salida.getvalue())

    esperado: dict[str, str] = {}
    for tarea, ruta in (celery_app.conf.task_routes or {}).items():
        if isinstance(ruta, dict) and ruta.get("queue"):
            esperado[tarea] = ruta["queue"]
    for entrada in (celery_app.conf.beat_schedule or {}).values():
        cola = (entrada.get("options") or {}).get("queue")
        if cola:
            esperado[entrada["task"]] = cola
    assert rutas == esperado
    assert rutas, "el snippet devolvió un mapa vacío"
