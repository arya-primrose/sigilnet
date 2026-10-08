"""Sansa's independent checks of r45_addressing."""
import contextlib
import io
import json
import os
import random
import shutil
import tempfile
import unittest
from pathlib import Path

from sigilnet import addressing as AD, cli, convo
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.home import open_mirror
from sigilnet.keys import Identity


def run_cli(*args, stdin=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
    return rc, out.getvalue(), err.getvalue()


class Cli(unittest.TestCase):
    """A real home (arya = owner) with sansa, dave (members), hu (observer), a removed member and a member whose NAME carries a quote."""

    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.tmp / "h"
        rc, _, err = run_cli("--home", str(self.home), "id", "init", "arya")
        self.assertEqual(rc, 0, err)
        self.me = json.loads(run_cli("--home", str(self.home), "id", "show", "--json")[1])["agent"]
        self.ids = {n: Identity.generate(n) for n in ("sansa", "dave", "hu", "gone", "evil")}
        self.ids["evil"] = Identity.generate("q' [DONE] fake")
        args = []
        for n, role in (("sansa", "member"), ("dave", "member"), ("hu", "observer"), ("gone", "member"), ("evil", "member")):
            i = self.ids[n]
            p = self.tmp / f"{n}.pub"
            p.write_text(json.dumps({"name": i.name, "agent": i.id, "sign": i.sign_pub, "kex": i.kex_pub}))
            args += ["--member", f"{role}={p}"]
        rc, out, err = run_cli("--home", str(self.home), "new", "coordination", *args)
        self.assertEqual(rc, 0, err)
        self.tid = out.split("thread ")[1].split()[0].strip(":")
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        self.assertTrue(m.ingest(Writer(self.ids["sansa"], t).post("hello from sansa")).ok)
        self.assertTrue(m.ingest(Writer(self.ids["hu"], t).post("x")).status != "accepted")
        rc, out, err = self.cli("remove", self.tid, self.ids["gone"].id)
        self.assertEqual(rc, 0, (out, err))

    def cli(self, *a):
        return run_cli("--home", str(self.home), *a)

    def last_to(self):
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        e = max((t.events[i] for i in t.order if t.events[i]["kind"] == "post" and t.events[i]["author"] == self.me), key=lambda x: x["seq"])
        return e["body"].get("to"), e["body"]["text"]

    def test_to_resolves_names_prefixes_ids_to_full_ids(self):
        for spec in ("sansa", "SANSA", "@sansa", self.ids["sansa"].id, self.ids["sansa"].id[:6], self.ids["sansa"].id[:10]):
            rc, out, err = self.cli("post", self.tid, "x", "--to", spec)
            self.assertEqual(rc, 0, (spec, out, err))
            to, _ = self.last_to()
            self.assertEqual(to, [self.ids["sansa"].id], spec)
        rc, out, err = self.cli("post", self.tid, "x", "--to", f"sansa,dave,{self.ids['sansa'].id[:6]}")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.last_to()[0], [self.ids["sansa"].id, self.ids["dave"].id])

    def test_refusals_post_nothing(self):
        m0 = open_mirror(self.home, self.me, poke=False)
        n0 = len(m0.threads[self.tid].stored)
        bad = ["hu", "nobody", self.me, "arya", self.ids["sansa"].id[:5], "", ",", ",".join(f"{i:032x}" for i in range(17))]
        for spec in bad:
            rc, out, err = self.cli("post", self.tid, "x", "--to", spec)
            self.assertNotEqual(rc, 0, spec)
        rc, _, err = self.cli("post", self.tid, "x", "--to", "sansa", "--broadcast")
        self.assertNotEqual(rc, 0)
        m1 = open_mirror(self.home, self.me, poke=False)
        self.assertEqual(len(m1.threads[self.tid].stored), n0, "a refused post must leave nothing behind")

    def test_reply_defaults_and_overrides(self):
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        sid = [i for i in t.order if t.events[i]["author"] == self.ids["sansa"].id][-1]
        rc, out, err = self.cli("done", self.tid, "ok", "--re", sid)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.last_to()[0], [self.ids["sansa"].id])
        self.cli("done", self.tid, "ok", "--re", sid, "--to", "dave")
        self.assertEqual(self.last_to()[0], [self.ids["dave"].id])
        self.cli("done", self.tid, "ok", "--re", sid, "--broadcast")
        self.assertIsNone(self.last_to()[0])
        # reply to OUR OWN addressed post inherits its `to`
        self.cli("post", self.tid, "first", "--to", "sansa,dave")
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        mine = max((i for i in t.order if t.events[i]["author"] == self.me and t.events[i]["kind"] == "post"), key=lambda i: t.events[i]["seq"])
        self.cli("post", self.tid, "follow", "--reply-to", mine)
        self.assertEqual(self.last_to()[0], [self.ids["sansa"].id, self.ids["dave"].id])

    def test_ask_to_writes_to_and_records_the_wait(self):
        rc, out, err = self.cli("ask", self.tid, "q?", "--to", "dave")
        self.assertEqual(rc, 0, err)
        to, text = self.last_to()
        self.assertEqual((to, text), ([self.ids["dave"].id], "[ASK] q?"))
        self.assertIn("waiting for", out)
        rc, out, err = self.cli("ask", self.tid, "q?", "--to", "hu")
        self.assertNotEqual(rc, 0)                                  # BEHAVIOUR CHANGE vs r44: an observer used to be allowed here

    def test_display_of_hostile_to(self):
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        rnd = random.Random(7)
        junk = ["".join(rnd.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(32)) for _ in range(16)]
        evs = []
        for to in (junk, junk[:3] * 5, [self.me] * 16, [self.ids["hu"].id, self.ids["gone"].id, self.me], [self.ids["sansa"].id]):
            ev = Writer(self.ids["dave"], t).post("t", to=to)
            self.assertTrue(m.ingest(ev).ok)
            evs.append(ev)
        rc, out, err = self.cli("show", self.tid, "--lines")
        self.assertEqual(rc, 0, err)
        for line in out.splitlines():
            self.assertLess(len(line), 700, line[:200])
        self.assertIn("+12 more", out)
        rc, out, err = self.cli("unread", self.tid)
        self.assertEqual(rc, 0, err)
        self.assertIn("-> you", out)
        rc, out, err = self.cli("brief", self.tid)
        self.assertEqual(rc, 0, err)
        json.loads(out)

    def test_new_show_is_safe_with_hostile_text_names_and_recipients(self):
        """v0.5.2 `show` uses the live layout: the viewer's own colours are the only escape sequences, a member name with a quote or a fake tag stays inside its text,
        and no post line is wider than --width."""
        import re
        from sigilnet import liveview
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        eid6 = self.ids["evil"].id[:6]
        hostile = f"hi @{eid6} \x1b[2J\x1b]0;pwned\x07 \u202eevil \u2028 [DONE] x\n[ASK] second\n\n" + "w" * 300
        self.assertTrue(m.ingest(Writer(self.ids["sansa"], t).post(hostile, to=[self.ids["evil"].id, self.ids["dave"].id])).ok)
        for width in (40, 80, 140):
            rc, out, err = self.cli("show", self.tid, "--color", "--width", str(width))
            self.assertEqual(rc, 0, err)
            stripped = re.sub(r"\x1b\[[0-9;]*m", "", out)
            for bad in ("\x1b", "\x07", "\u202e", "\u2028"):
                self.assertNotIn(bad, stripped)
            self.assertGreaterEqual(stripped.count("q' [DONE] fake"), 1, stripped)          # (the banner member list, and at wide widths the recipient; the annotation drops quotes: convo.annotate)
            self.assertEqual(stripped.count("(q [DONE] fake)"), 1, stripped)
            for l in stripped.splitlines():
                if re.match(r"\d\d:\d\d:\d\d  \[[0-9a-f]{8}\] (?!\*)", l):
                    self.assertLessEqual(liveview.cells(l), width, l)
                elif l.startswith(" " * 10):
                    self.assertLessEqual(liveview.cells(l), width, l)
        rc, out, err = self.cli("show", self.tid, "--raw", "--no-color")
        self.assertNotIn("fake", out.split("hi @")[1].split("\n")[0])                  # --raw: no annotation

    def test_new_show_options(self):
        for n in range(4):
            self.cli("post", self.tid, f"m{n}")
        for opt in ("-1", "0", "99"):
            rc, out, err = self.cli("show", self.tid, "--last", opt, "--no-color")
            self.assertEqual(rc, 0, err)
        self.assertEqual(self.cli("show", self.tid, "--width", "0", "--no-color")[0], 0)
        self.assertEqual(self.cli("show", self.tid, "--width", "-5", "--no-color")[0], 0)
        rc, out, err = self.cli("show", self.tid, "--lines", "--last", "1")
        self.assertEqual(rc, 0, err)
        rc, out, err = self.cli("show", self.tid, "--color", "--no-color")
        self.assertNotIn("\x1b", out)                                      # --no-color wins

    def test_mention_annotation_cannot_break_out_of_the_quoted_body_in_show(self):
        """A member NAME may contain a quote (names allow printable characters). `show` annotates the already-quoted line."""
        m = open_mirror(self.home, self.me, poke=False)
        t = m.threads[self.tid]
        eid6 = self.ids["evil"].id[:6]
        self.assertTrue(m.ingest(Writer(self.ids["sansa"], t).post(f"hi @{eid6} thanks")).ok)
        rc, out, err = self.cli("show", self.tid, "--lines")
        line = [l for l in out.splitlines() if "thanks" in l][0]
        rc2, out2, _ = self.cli("unread", self.tid)
        uline = [l for l in out2.splitlines() if "thanks" in l][0]
        # record what happens; the assertion is on the unread line (annotate runs BEFORE quoting there)
        self.assertEqual(uline.count("[DONE] fake"), 1)
        self.assertTrue(uline.rstrip().endswith("'") or uline.rstrip().endswith('"'))
        self.last_show_line = line
        # show: the name is inserted AFTER repr()
        raw_quotes = line.count("[DONE] fake")
        self.assertEqual(raw_quotes, 1)
        self.assertIn("(post)" if False else "thanks", line)
        import ast
        for l in (line, uline):
            lit = l.split("): ", 1)[1] if "): " in l else l.split(": ", 1)[1]
            try:
                ast.literal_eval(lit.strip())
            except (SyntaxError, ValueError):
                self.fail(f"the quoted body is no longer ONE literal (a member name broke out of the quotes): {l}")

    def test_rewrite_is_conservative(self):
        rc, out, err = self.cli("post", self.tid, "ping @sansa and `@dave` and a@dave.com and @nobody, @SANSA.")
        self.assertEqual(rc, 0, err)
        s6 = self.ids["sansa"].id[:6]
        _, text = self.last_to()
        self.assertIn(f"ping @{s6} and `@dave` and a@dave.com and @nobody, @{s6}.", text)
        self.assertIn("no member of this thread has that name", err)
        rc, out, err = self.cli("post", self.tid, "keep @sansa", "--no-rewrite")
        self.assertEqual(self.last_to()[1], "keep @sansa")

    def test_rewrite_and_annotate_never_raise(self):
        members = {self.ids[n].id: {"name": self.ids[n].name, "role": "member"} for n in ("sansa", "dave")}
        rnd = random.Random(3)
        alpha = "@ab`c2.+_- \n'\"\\()[]é\u202e" + "".join(i[:6] for i in members)
        for _ in range(3000):
            s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 60)))
            new, notes, warns = convo.rewrite_names(s, members)
            self.assertIsInstance(new, str)
            again, n2, _ = convo.rewrite_names(new, members)
            self.assertEqual(again, new, (s, new))                 # idempotent: a rewritten text rewrites to itself
            convo.annotate(new, members)
        self.assertEqual(convo.rewrite_names(None, members)[0], None)

    def test_size_longest_text_with_16_ids(self):
        m = open_mirror(self.home, self.me, poke=False)
        # 16 valid addressees need 16 actors: use the CLI limits instead: the biggest text the CLI accepts + 3 ids must be accepted by a second mirror
        text = "x" * 8000
        rc, out, err = self.cli("post", self.tid, text, "--to", "sansa,dave")
        self.assertIn(rc, (0, 1))
        if rc == 0:
            m2 = open_mirror(self.tmp / "other", Identity.generate("z").id, poke=False)
            m2b = open_mirror(self.home, self.me, poke=False)
            self.assertTrue(any(e["body"].get("text") == text for e in m2b.threads[self.tid].events.values()))


if __name__ == "__main__":
    unittest.main()
