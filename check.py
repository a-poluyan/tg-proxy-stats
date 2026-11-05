"""Run with Python 3.11+ from the project directory."""

from contextlib import redirect_stdout
from dataclasses import replace
import errno
from io import StringIO
from pathlib import Path
import runpy
import socket
import sqlite3
import struct
from types import SimpleNamespace
from unittest.mock import patch


def nla(kind, value):
    length = len(value) + 4
    return struct.pack("=HH", length, kind) + value + bytes(-length % 4)


def packet(port, reply_port):
    addresses = nla(1, socket.inet_aton("192.0.2.10")) + nla(2, socket.inet_aton("192.0.2.20"))
    proto = nla(1, b"\x06") + nla(2, struct.pack("!H", 50000)) + nla(3, struct.pack("!H", port))
    reply = nla(2, struct.pack("!H", reply_port))
    return (
        bytes((socket.AF_INET, 0, 0, 0)) + nla(1, nla(1, addresses) + nla(2, proto))
        + nla(2, nla(2, reply)) + nla(3, struct.pack("!I", 36))
        + nla(4, nla(1, nla(1, b"\x03"))) + nla(9, nla(2, struct.pack("!Q", 500)))
        + nla(10, nla(2, struct.pack("!Q", 800))) + nla(12, b"test")
    )


def check(app):
    observe = app["observe"]
    flow = app["parse_flow"](packet(7005, 1443))
    assert (flow.port, flow.target, flow.ip, flow.up, flow.down, flow.live) == (
        7005, 1443, "192.0.2.10", 500, 800, True,
    )
    assert app["parse_flow"](packet(8005, 2443)).target == 2443
    for flags, expected in ((0x10, errno.EINTR), (0, errno.ENOBUFS)):
        message = struct.pack("=IHHII", 16, 3 if flags else 4, flags, 0, 0)
        fake_socket = SimpleNamespace(recvmsg=lambda _: (message, [], 0, (0, 0)))
        try:
            list(app["messages"](fake_socket))
        except OSError as error:
            assert error.errno == expected
        else:
            raise AssertionError("expected netlink error")

    db = sqlite3.connect(":memory:")
    app["initialize"](db)
    assert len(app["monitored_ports"](db)) == 42
    base = 3000
    short = replace(flow, key=b"short", up=None, down=None)
    observe(db, short, base, 0)
    observe(db, replace(short, up=80, down=70, live=False), base + 2, 0)
    app["save_snapshot"](db, [flow, replace(flow, target=2443)], base + 60, "boot")
    observe(db, replace(flow, up=100, down=100), base + 61, 0)
    final = replace(flow, up=800, down=1000, live=False)
    observe(db, final, base + 62, 0)
    observe(db, final, base + 63, 0)
    totals = db.execute("SELECT SUM(up), SUM(down), SUM(opened), SUM(live) FROM usage").fetchone()
    assert totals == (880, 1070, 2, 1), totals
    app["save_snapshot"](db, [], base + 65, "boot")
    assert db.execute("SELECT SUM(live) FROM usage").fetchone() == (0,)

    for minute in range(100, 115):
        for address in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            db.execute("INSERT INTO usage VALUES (?, 8005, ?, 1000, 1000, 0, 0, 0, 2000, 1)",
                       (minute, address))
    assert list(app["alert_streaks"](db, 100, 113)) == []
    assert list(app["alert_streaks"](db, 100, 114)) == [(8005, 100, 114)]
    db.commit()

    assert app["remove_port"](db, 7005)
    assert not app["remove_port"](db, 7005)
    app["initialize"](db)
    assert 7005 not in app["monitored_ports"](db)
    app["save_events"](db, [(app["CT_NEW"], packet(7005, 1443))], base + 120)
    assert app["add_port"](db, 7005, 1443)
    assert not app["add_port"](db, 7005, 1443)
    assert app["monitored_ports"](db)[7005][2] == 0
    app["save_events"](db, [(app["CT_NEW"], packet(7005, 1443))], base + 121)
    with db:
        app["save_snapshot"](db, [replace(flow, up=2000, down=3000)], base + 122, "boot")
    assert app["monitored_ports"](db)[7005][2] == 1
    app["save_events"](db, [(app["CT_DELETE"], packet(7005, 1443))], base + 123)
    with db:
        app["save_snapshot"](db, [replace(flow, up=2100, down=3100)], base + 182, "boot")
    assert db.execute("SELECT SUM(up), SUM(down) FROM usage WHERE port = 7005").fetchone() == (980, 1170)
    assert app["add_port"](db, *app["port_mapping"]("7021:1443"))
    assert app["monitored_ports"](db)[7021][0] == 1443

    minute = 2000
    app["save_snapshot"](db, [], minute * 60, "boot")
    for age, address, opened, established, size in (
        (1440, "192.0.2.1", 1, True, 1024), (15, "192.0.2.2", 1, True, 1024),
        (14, "192.0.2.3", 2, True, 500), (0, "192.0.2.3", 1, True, 524),
        (0, "192.0.2.4", 0, True, 0), (0, "192.0.2.5", 0, False, 1024),
    ):
        seen = (minute - age) * 60 if established else None
        db.execute("INSERT INTO usage VALUES (?, 7021, ?, ?, 0, ?, ?, ?, ?, 0)",
                   (minute - age, address, size, seen, seen, opened, size if established else 0))
    for days, traffic, expected in ((1, "3.00", ["4", "2", "1"]), (7, "4.00", ["5", "3", "1"])):
        report = StringIO()
        with patch.object(app["time"], "time", return_value=minute * 60), redirect_stdout(report):
            app["show_report"](db, (7021, 8005), app["monitored_ports"](db), days)
        output = report.getvalue()
        assert f"TCP за {days} сут." in output and f"IP за {days} сут." in output
        assert "IP за 15 мин" in output
        row = next(line for line in output.splitlines() if line.startswith(" 7021 "))
        cells = row.split()
        assert cells[1:3] == [traffic, "КиБ"] and cells[-3:] == expected, row
    db.close()
    print("OK: flow accounting, alerts, port changes and period totals")


if __name__ == "__main__":
    check(runpy.run_path(str(Path(__file__).with_name("tg-proxy-stats"))))
