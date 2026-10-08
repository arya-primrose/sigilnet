"""node_config.json `pull_interval` and `sigilnet node pull-interval`: a node nobody can notify (an observer seat with no door) asks its peers for news more often than the default 300 s."""
import json
import tempfile
import unittest
from pathlib import Path

from sigilnet import noderun
from sigilnet.node import PULL_INTERVAL
from sigilnet.tests.test_cli_public import run


class Config(unittest.TestCase):
    def load(self, **kv):
        d = Path(tempfile.mkdtemp())
        (d / "node_config.json").write_text(json.dumps(kv))
        return noderun.load_config(d)

    def test_default_is_none_and_valid_values_are_floats(self):
        self.assertIsNone(noderun.load_config(Path(tempfile.mkdtemp()))["pull_interval"])
        self.assertIsNone(self.load(carrier="tor")["pull_interval"])
        self.assertIsNone(self.load(pull_interval=None)["pull_interval"])
        self.assertEqual(self.load(pull_interval=30)["pull_interval"], 30.0)
        self.assertEqual(self.load(pull_interval=noderun.PULL_MIN)["pull_interval"], noderun.PULL_MIN)
        self.assertEqual(self.load(pull_interval=PULL_INTERVAL)["pull_interval"], PULL_INTERVAL)

    def test_bad_values_are_an_error_message_not_a_traceback(self):
        for bad in (0, 9.9, -30, 301, 10 ** 9, True, False, "30", [30], {"a": 1}, float("nan"), float("inf")):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.load(pull_interval=bad)


class Cli(unittest.TestCase):
    def setUp(self):
        self.h = tempfile.mkdtemp()
        run(self.h, "id", "init", "carol")

    def test_set_show_and_default(self):
        rc, out, err = run(self.h, "node", "pull-interval")
        self.assertEqual(rc, 0, err)
        self.assertIn("300 seconds (the default)", out)
        rc, out, err = run(self.h, "node", "pull-interval", "30")
        self.assertEqual(rc, 0, err)
        self.assertEqual(noderun.load_config(Path(self.h))["pull_interval"], 30.0)
        self.assertIn("30 seconds", run(self.h, "node", "pull-interval")[1])
        self.assertNotIn("default", run(self.h, "node", "pull-interval")[1])
        self.assertEqual(run(self.h, "node", "pull-interval", "default")[0], 0)
        self.assertIsNone(noderun.load_config(Path(self.h))["pull_interval"])

    def test_bad_arguments_change_nothing(self):
        run(self.h, "node", "pull-interval", "45")
        for bad in ("5", "301", "-1", "nan", "inf", "soon", "0"):
            rc, out, err = run(self.h, "node", "pull-interval", bad)
            self.assertNotEqual(rc, 0, bad)
            self.assertEqual(noderun.load_config(Path(self.h))["pull_interval"], 45.0, bad)
        self.assertNotEqual(run(self.h, "node", "pull-interval", "30", "40")[0], 0)


class Wiring(unittest.TestCase):
    def run_node(self, interval):
        from unittest import mock
        from sigilnet.keys import Identity
        from sigilnet.node import Node
        home = Path(tempfile.mkdtemp())
        me = Identity.generate("me")
        me.save(home / "identity.json")
        self.assertEqual(run(str(home), "node", "init", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", "47990")[0], 0)
        if interval:
            run(str(home), "node", "pull-interval", interval)
        seen = []

        class Spy(Node):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                seen.append(self.pull_interval)
        with mock.patch.object(noderun, "Node", Spy):
            noderun.run(home, me, seconds=1, offline=True, out=lambda *a: None)
        return seen

    def test_the_node_gets_the_configured_interval_or_the_default(self):
        self.assertEqual(self.run_node("30"), [30.0])
        self.assertEqual(self.run_node(None), [PULL_INTERVAL])


if __name__ == "__main__":
    unittest.main()
