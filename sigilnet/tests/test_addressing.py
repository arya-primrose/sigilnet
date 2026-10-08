"""Addressing (DESIGN_addressing.md): the signed `to` (framework: addressing.py, Mirror.addressing, the CLI flags) and the `@` mention helpers (convention: convo.py)."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sigilnet import addressing as AD, cli, convo
from sigilnet.build import Writer, make_genesis
from sigilnet.event import event_id
from sigilnet.home import open_mirror
from sigilnet.keys import Identity
from sigilnet.mirror import Mirror
from sigilnet.thread import default_rules


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli.main(list(args))
        except SystemExit as e:
            rc = e.code if isinstance(e.code, int) else 1
            err.write("" if isinstance(e.code, int) or e.code is None else str(e.code))
    return rc, out.getvalue(), err.getvalue()


NAMES = ("arya", "sansa", "dave", "hu", "erin")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp()))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.ids = {n: Identity.generate(n) for n in NAMES}
        self.id = {n: i.id for n, i in self.ids.items()}
        self.members = {
            self.id["arya"]: {"role": "owner", "name": "arya"}, self.id["sansa"]: {"role": "member", "name": "sansa"},
            self.id["dave"]: {"role": "admin", "name": "dave"}, self.id["hu"]: {"role": "observer", "name": "hu"},
            self.id["erin"]: {"role": "guest", "name": "erin"}}

    def mirror(self, who="arya", name=None, **kw):
        return open_mirror(self.tmp / (name or who), self.ids[who].id, poke=False)

    def thread(self, m, members=(("sansa", "member"), ("dave", "admin"), ("hu", "observer")), encrypt=True, **kw):
        g = make_genesis(self.ids["arya"], "coordination", [(self.ids[n], r) for n, r in members], **kw)
        self.assertTrue(m.ingest(g).ok)
        tid = event_id(g)
        if encrypt:
            m.enable_encryption(tid, self.ids["arya"])
        return tid

    def post(self, m, tid, who, text, **extra):
        ev = Writer(self.ids[who], m.threads[tid]).post(text, **extra)
        r = m.ingest(ev)
        self.assertTrue(r.ok, r.reason)
        return event_id(ev)


class Resolve(Base):
    def test_one_by_name_id_and_prefix(self):
        M = self.members
        self.assertEqual(AD.resolve_one(M, "sansa"), self.id["sansa"])
        self.assertEqual(AD.resolve_one(M, "@Sansa"), self.id["sansa"])                      # case-insensitive, a leading @ ignored
        self.assertEqual(AD.resolve_one(M, self.id["sansa"]), self.id["sansa"])
        self.assertEqual(AD.resolve_one(M, self.id["sansa"][:6]), self.id["sansa"])
        self.assertEqual(AD.resolve_one(M, self.id["sansa"][:12].upper()), self.id["sansa"])
        for bad in ("", "  ", "nobody", self.id["sansa"][:5], "@"):                          # 5 characters is not a prefix
            with self.assertRaises(AD.AddressError, msg=repr(bad)):
                AD.resolve_one(M, bad)

    def test_ambiguity_is_refused_not_guessed(self):
        twin = Identity.generate("twin").id
        M = {**self.members, twin: {"role": "member", "name": "Sansa"}}
        with self.assertRaisesRegex(AD.AddressError, "name of 2 members"):
            AD.resolve_one(M, "sansa")
        a, b = "a" * 6 + "b" * 26, "a" * 6 + "c" * 26
        with self.assertRaisesRegex(AD.AddressError, "starts the ids of 2 members"):
            AD.resolve_one({a: {"role": "member", "name": "x"}, b: {"role": "member", "name": "y"}}, "a" * 6)
        self.assertEqual(AD.resolve_one({a: {"role": "member", "name": "x"}, b: {"role": "member", "name": "y"}}, "a" * 6 + "b"), a)

    def test_many_rules(self):
        me = self.id["arya"]
        self.assertEqual(AD.resolve_many(self.members, ["sansa", "dave", "sansa"], me), [self.id["sansa"], self.id["dave"]])     # de-duplicated, order kept
        for spec, what in (("arya", "yourself"), ("hu", "observer"), ("erin", "guest")):
            with self.assertRaisesRegex(AD.AddressError, what):
                AD.resolve_many(self.members, [spec], me)
        with self.assertRaises(AD.AddressError):
            AD.resolve_many(self.members, ["", " "], me)
        many = {Identity.generate(str(i)).id: {"role": "member", "name": f"m{i}"} for i in range(17)}
        with self.assertRaisesRegex(AD.AddressError, "at most 16"):
            AD.resolve_many(many, [f"m{i}" for i in range(17)], me)
        self.assertEqual(len(AD.resolve_many(many, [f"m{i}" for i in range(16)], me)), 16)


class ReplyDefault(Base):
    def setUp(self):
        super().setUp()
        self.m = self.mirror()
        self.tid = self.thread(self.m)
        self.t = self.m.threads[self.tid]
        self.me = self.id["arya"]

    def test_the_parents_author(self):
        p = self.post(self.m, self.tid, "sansa", "hello")
        self.assertEqual(AD.reply_default(self.t, p, self.me), [self.id["sansa"]])

    def test_no_default_for_an_observer_or_unknown_or_missing_parent(self):
        self.assertEqual(AD.reply_default(self.t, "0" * 32, self.me), [])
        self.assertEqual(AD.reply_default(self.t, self.tid, self.me), [])                   # the genesis is authored by us

    def test_a_removed_author_gets_nothing(self):
        p = self.post(self.m, self.tid, "dave", "from dave")
        ev = Writer(self.ids["arya"], self.t).admin("member_remove", {"agent": self.id["dave"]})
        self.m.codec.ring(self.tid).create(event_id(ev), self.ids["arya"])
        self.assertTrue(self.m.ingest(ev).ok)
        self.assertEqual(AD.reply_default(self.t, p, self.me), [])

    def test_a_follow_up_to_our_own_post_keeps_its_addressing(self):
        ask = self.post(self.m, self.tid, "arya", "[ASK] x", to=[self.id["sansa"], self.id["dave"]])
        self.assertEqual(AD.reply_default(self.t, ask, self.me), [self.id["sansa"], self.id["dave"]])
        plain = self.post(self.m, self.tid, "arya", "no to")
        self.assertEqual(AD.reply_default(self.t, plain, self.me), [])
        ev = Writer(self.ids["arya"], self.t).admin("member_remove", {"agent": self.id["dave"]})
        self.m.codec.ring(self.tid).create(event_id(ev), self.ids["arya"])
        self.assertTrue(self.m.ingest(ev).ok)
        self.assertEqual(AD.reply_default(self.t, ask, self.me), [self.id["sansa"]])         # minus whoever cannot act any more

    def test_a_void_parent_has_no_trustworthy_author(self):
        p = self.post(self.m, self.tid, "sansa", "beyond a cut")
        self.assertEqual(AD.reply_default(self.t, p, self.me), [self.id["sansa"]])
        self.t.void_ids.add(p)                                                               # what a close cut or a lost fork does to an event
        self.assertEqual(AD.reply_default(self.t, p, self.me), [])

    def test_a_parked_parent_has_no_trustworthy_author(self):
        ghost = Writer(self.ids["sansa"], self.t).post("never delivered")
        later = Writer(self.ids["sansa"], self.t).post("child", reply_to=event_id(ghost), parents=[event_id(ghost)])
        self.assertFalse(self.m.ingest(later).ok)                                            # parked: its parent is unknown
        self.assertEqual(AD.reply_default(self.t, event_id(later), self.me), [])


class Display(Base):
    def test_labels_you_others_and_broadcast(self):
        m = self.mirror()
        tid = self.thread(m)
        t = m.threads[tid]
        a = self.post(m, tid, "sansa", "to me and dave", to=[self.id["arya"], self.id["dave"]])
        b = self.post(m, tid, "sansa", "to dave", to=[self.id["dave"]])
        c = self.post(m, tid, "sansa", "everybody")
        self.assertEqual(m.addressing(t, t.events[a]), " -> you, dave (%s)" % self.id["dave"][:6])
        self.assertEqual(m.addressing(t, t.events[b]), " -> dave (%s)" % self.id["dave"][:6])
        self.assertEqual(m.addressing(t, t.events[c]), "")
        text = "\n".join(m.render(tid))
        self.assertIn("-> you, dave", text)

    def test_a_mirror_without_an_identity_shows_ids_not_a_crash(self):
        m = self.mirror()
        tid = self.thread(m)
        a = self.post(m, tid, "sansa", "x", to=[self.id["arya"]])
        bare = Mirror(self.tmp / "arya" / "mirror", codec=m.codec)
        self.assertEqual(bare.addressing(bare.threads[tid], bare.threads[tid].events[a]), " -> arya (%s)" % self.id["arya"][:6])

    def test_hostile_to_is_shown_capped_and_safely(self):
        m = self.mirror()
        tid = self.thread(m, rules={**default_rules(), "max_members": 20})
        t = m.threads[tid]
        junk = [Identity.generate(str(i)).id for i in range(16)]                             # non-members, valid ids
        e = self.post(m, tid, "sansa", "junk", to=junk)
        line = m.addressing(t, t.events[e])
        self.assertEqual(line.count(","), 3)
        self.assertIn("+12 more", line)
        for odd in ([], [1, 2], "x", None, [None], [self.id["sansa"]] * 3):                  # whatever is stored must not raise
            ev = dict(t.events[e])
            ev["body"] = {"text": "x", "to": odd}
            self.assertIsInstance(m.addressing(t, ev), str)

    def test_unread_brief_and_show_carry_the_label(self):
        m = self.mirror()
        tid = self.thread(m)
        self.post(m, tid, "sansa", "for you", to=[self.id["arya"]])
        brief = m.brief(tid, self.id["arya"])
        self.assertEqual([u["to"] for u in brief["unread"]], [["you"]])                      # a LIST of labels (the JSON surface), [] for a broadcast
        self.post(m, tid, "sansa", "everybody")
        self.assertEqual(sorted(json.dumps(u["to"]) for u in m.brief(tid, self.id["arya"])["unread"]), sorted(['["you"]', "[]"]))


class Mentions(Base):
    def test_annotate_only_what_names_exactly_one_member(self):
        M = self.members
        s6 = self.id["sansa"][:6]
        self.assertEqual(convo.annotate(f"ask @{s6} please", M), f"ask @{s6} (sansa) please")
        self.assertEqual(convo.annotate(f"mail me at bob@{s6}.com", M), f"mail me at bob@{s6}.com")            # preceded by a letter: not a mention, though the token IS a member's prefix
        self.assertEqual(convo.annotate(f"x_@{s6} and +@{s6} and -@{s6}", M), f"x_@{s6} and +@{s6} and -@{s6}")
        self.assertEqual(convo.annotate(f"@{self.id['sansa'][:5]} too short", M), f"@{self.id['sansa'][:5]} too short")     # five characters name nobody
        self.assertEqual(convo.annotate("@zzzzzz nobody", M), "@zzzzzz nobody")
        self.assertEqual(convo.annotate("@" + self.id["sansa"], M), f"@{self.id['sansa']} (sansa)")
        a, b = "a" * 6 + "b" * 26, "a" * 6 + "c" * 26
        two = {a: {"role": "member", "name": "x"}, b: {"role": "member", "name": "y"}}
        self.assertEqual(convo.annotate("@aaaaaa", two), "@aaaaaa")                                              # ambiguous: shown as typed (the safe direction)
        self.assertEqual(convo.annotate(None, M), "")
        evil = {self.id["sansa"]: {"role": "member", "name": "sansa‮\x1b[31m evil"}}
        out = convo.annotate(f"@{s6}", evil)
        self.assertNotIn("‮", out)
        self.assertNotIn("\x1b", out)

    def test_rewrite_names(self):
        M = self.members
        s6 = self.id["sansa"][:6]
        out, notes, warns = convo.rewrite_names("work with @Sansa and @dave, not @nobody", M)
        self.assertEqual(out, f"work with @{s6} and @{self.id['dave'][:6]}, not @nobody")
        self.assertEqual(notes, [f"@Sansa -> @{s6}", f"@dave -> @{self.id['dave'][:6]}"])
        self.assertEqual(len(warns), 1)
        self.assertIn("@nobody", warns[0])
        same, notes, warns = convo.rewrite_names(f"already @{s6}", M)                          # an id mention is left alone
        self.assertEqual((same, notes, warns), (f"already @{s6}", [], []))
        self.assertEqual(convo.rewrite_names("a@sansa.com and x@dave", M)[0], "a@sansa.com and x@dave")   # an e-mail address is not a mention

    def test_rewrite_leaves_backtick_spans_alone(self):
        M = self.members
        s6 = self.id["sansa"][:6]
        text = "run `echo @sansa` then ask @sansa\n```\n@dave stays\n```"
        out, notes, warns = convo.rewrite_names(text, M)
        self.assertEqual(out, f"run `echo @sansa` then ask @{s6}\n```\n@dave stays\n```")
        self.assertEqual(len(notes), 1)

    def test_a_lone_backtick_is_just_a_character_and_never_recurses_forever(self):
        """Sansa's F1: an UNMATCHED backtick plus an @ used to recurse until RecursionError (and `post` died with a traceback)."""
        M = self.members
        s6 = self.id["sansa"][:6]
        for text, want in (("a ` b @sansa", f"a ` b @{s6}"), ("5` pipe @sansa", f"5` pipe @{s6}"), ("`@sansa", f"`@{s6}"), ("@sansa `", f"@{s6} `"),
                           ("``` @sansa", f"``` @{s6}"), ("`x` ok @sansa", f"`x` ok @{s6}"), ("`@sansa` and `` @sansa", f"`@sansa` and `` @{s6}")):
            self.assertEqual(convo.rewrite_names(text, M)[0], want, text)

    def test_rewrite_and_annotate_never_raise_and_rewrite_is_idempotent(self):
        import random
        rnd = random.Random(3)
        M = {a: r for a, r in self.members.items() if r["role"] in ("owner", "member", "admin")}
        alpha = "@ab`c2.+_- \n'\"\\()[]\u00e9\u202e" + "".join(a[:6] for a in M)
        for _ in range(2000):
            s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 60)))
            new = convo.rewrite_names(s, M)[0]
            self.assertEqual(convo.rewrite_names(new, M)[0], new, (s, new))
            convo.annotate(new, M)

    def test_an_annotated_name_cannot_break_out_of_a_quoted_line(self):
        """Sansa's F3: `show` annotates AFTER repr(); a member name with a quote or a backslash must not end the quoted body."""
        evil = Identity.generate("q' [DONE] fake \\")
        M = {evil.id: {"role": "member", "name": "q' [DONE] fake \\ \"x\""}}
        out = convo.annotate(f"@{evil.id[:6]} hi", M)
        self.assertNotIn("'", out)
        self.assertNotIn('"', out)
        self.assertNotIn("\\", out)
        self.assertIn("(q [DONE] fake x)", out)
        line = repr(f"thanks @{evil.id[:6]} hi")
        import ast
        self.assertEqual(ast.literal_eval(convo.annotate(line, M)), f"thanks @{evil.id[:6]} (q [DONE] fake x) hi")

    def test_rewrite_ambiguity_and_spaces(self):
        twin = Identity.generate("twin").id
        M = {**self.members, twin: {"role": "member", "name": "SANSA"}, "b" * 32: {"role": "member", "name": "two words"}}
        out, notes, warns = convo.rewrite_names("@sansa @two", M)
        self.assertEqual((out, notes), ("@sansa @two", []))
        self.assertEqual(len(warns), 2)
        # a longer prefix when six characters are not enough
        a, b = "a" * 6 + "b" * 26, "a" * 6 + "c" * 26
        two = {a: {"role": "member", "name": "ann"}, b: {"role": "member", "name": "bob"}}
        self.assertEqual(convo.rewrite_names("@ann", two)[0], "@aaaaaab")


class Cli(Base):
    def setUp(self):
        super().setUp()
        self.home = self.tmp / "h"
        rc, out, err = run_cli("--home", str(self.home), "id", "init", "arya")
        self.assertEqual(rc, 0, err)
        me = json.loads(run_cli("--home", str(self.home), "id", "show", "--json")[1])
        self.ids["arya"] = Identity.load(self.home / "identity.json") if (self.home / "identity.json").exists() else Identity.load(self.home / ".sigilnet" / "identity.json")
        self.id["arya"] = me["agent"]
        args = []
        for n, role in (("sansa", "member"), ("dave", "admin"), ("hu", "observer")):
            i = self.ids[n]
            (self.tmp / f"{n}.pub").write_text(json.dumps({"name": n, "agent": i.id, "sign": i.sign_pub, "kex": i.kex_pub}))
            args += ["--member", f"{role}={self.tmp / (n + '.pub')}"]
        rc, out, err = self.cli("new", "coordination", *args)
        self.assertEqual(rc, 0, err)
        self.tid = out.split("thread ")[1].split()[0].strip(":")
        self.m = open_mirror(self.home, self.id["arya"], poke=False)

    def cli(self, *a):
        return run_cli("--home", str(self.home), *a)

    def last(self):
        m = open_mirror(self.home, self.id["arya"], poke=False)
        t = m.threads[self.tid]
        mine = [e for e in t.events.values() if e["author"] == self.id["arya"] and e["kind"] == "post"]
        return max(mine, key=lambda e: e["seq"]), t, m                               # our newest post (sibling replies do not sort by arrival)

    def other_post(self, who, text, **extra):
        m = open_mirror(self.home, self.id["arya"], poke=False)
        ev = Writer(self.ids[who], m.threads[self.tid]).post(text, **extra)
        self.assertTrue(m.ingest(ev).ok)
        return event_id(ev)

    def test_to_by_name_prefix_and_full_id_signs_full_ids(self):
        for spec in ("sansa", self.id["sansa"][:7], self.id["sansa"], "@sansa", "sansa,dave"):
            rc, out, err = self.cli("post", self.tid, "x", "--to", spec)
            self.assertEqual(rc, 0, err)
            ev = self.last()[0]
            want = [self.id["sansa"], self.id["dave"]] if "," in spec else [self.id["sansa"]]
            self.assertEqual(ev["body"]["to"], want, spec)
            self.assertTrue(all(len(x) == 32 for x in ev["body"]["to"]))

    def test_refusals_post_nothing(self):
        n = len(open_mirror(self.home, self.id["arya"], poke=False).threads[self.tid].order)
        for args in (("--to", "hu"), ("--to", "arya"), ("--to", "nobody"), ("--to", "sansa", "--broadcast"), ("--to", ","), ("--to", ""), ("--to", " ")):
            rc, out, err = self.cli("post", self.tid, "x", *args)
            self.assertNotEqual(rc, 0, args)
        self.assertEqual(len(open_mirror(self.home, self.id["arya"], poke=False).threads[self.tid].order), n)

    def test_no_to_is_a_plain_post_and_broadcast_cancels_the_reply_default(self):
        self.assertEqual(self.cli("post", self.tid, "plain")[0], 0)
        self.assertNotIn("to", self.last()[0]["body"])
        p = self.other_post("sansa", "question")
        self.assertEqual(self.cli("post", self.tid, "r", "--reply-to", p)[0], 0)
        self.assertEqual(self.last()[0]["body"]["to"], [self.id["sansa"]])                  # option C
        self.assertEqual(self.cli("post", self.tid, "r2", "--reply-to", p, "--broadcast")[0], 0)
        self.assertNotIn("to", self.last()[0]["body"])
        self.assertEqual(self.cli("post", self.tid, "r3", "--reply-to", p, "--to", "dave")[0], 0)
        self.assertEqual(self.last()[0]["body"]["to"], [self.id["dave"]])                    # --to replaces the default

    def test_done_defaults_to_the_author_of_the_answered_event(self):
        p = self.other_post("dave", "[ASK] do it")
        rc, out, err = self.cli("done", self.tid, "done it", "--re", p[:10])
        self.assertEqual(rc, 0, err)
        ev = self.last()[0]
        self.assertEqual((ev["body"]["to"], ev["body"]["reply_to"]), ([self.id["dave"]], p))
        self.assertTrue(ev["body"]["text"].startswith("[DONE] "))

    def test_ask_to_writes_the_signed_to_and_keeps_the_wait(self):
        rc, out, err = self.cli("ask", self.tid, "can you?", "--to", "sansa")
        self.assertEqual(rc, 0, err)
        ev = self.last()[0]
        self.assertEqual(ev["body"]["to"], [self.id["sansa"]])
        self.assertTrue(ev["body"]["text"].startswith("[ASK] "))
        from sigilnet.waitstate import WaitState
        asks = WaitState(self.home).load()["asks"] if hasattr(WaitState(self.home), "load") else None
        if asks is not None:
            self.assertEqual([a["to"] for a in asks], [self.id["sansa"]])
        self.assertNotEqual(self.cli("ask", self.tid, "x", "--to", "hu")[0], 0)              # an observer cannot be asked
        for cmd in (("ask", self.tid, "x", "--to", ""), ("done", self.tid, "x", "--re", event_id(self.last()[0]), "--to", "")):
            self.assertNotEqual(self.cli(*cmd)[0], 0, cmd)                                   # an empty `--to "$WHO"` is an error, never a silent broadcast

    def test_a_reply_to_our_own_ask_keeps_the_addressing(self):
        self.assertEqual(self.cli("ask", self.tid, "q", "--to", "sansa")[0], 0)
        ask = event_id(self.last()[0])
        self.assertEqual(self.cli("post", self.tid, "more detail", "--reply-to", ask)[0], 0)
        self.assertEqual(self.last()[0]["body"]["to"], [self.id["sansa"]])

    def test_mentions_are_rewritten_shown_and_can_be_switched_off(self):
        rc, out, err = self.cli("post", self.tid, "work with @dave on it")
        self.assertEqual(rc, 0, err)
        d6 = self.id["dave"][:6]
        self.assertIn(f"mention @dave -> @{d6}", out)
        self.assertEqual(self.last()[0]["body"]["text"], f"work with @{d6} on it")
        rc, out, err = self.cli("post", self.tid, "work with @dave", "--no-rewrite")
        self.assertEqual(self.last()[0]["body"]["text"], "work with @dave")
        rc, out, err = self.cli("post", self.tid, "ping @ghost")
        self.assertEqual(rc, 0)
        self.assertIn("@ghost", err)
        self.assertEqual(self.last()[0]["body"]["text"], "ping @ghost")                      # never refused

    def test_show_and_unread_print_the_addressing_and_names(self):
        d6 = self.id["dave"][:6]
        self.other_post("sansa", f"hello @{d6} and you", to=[self.id["arya"]])
        self.other_post("sansa", "to dave", to=[self.id["dave"]])
        self.other_post("sansa", "everybody")
        rc, out, err = self.cli("unread", self.tid)
        lines = out.strip().splitlines()
        self.assertIn("sansa -> you (post):", lines[0])
        self.assertIn(f"@{d6} (dave)", lines[0])
        self.assertIn(f"sansa -> dave ({d6}) (post):", lines[1])
        self.assertIn("sansa (post): ", lines[2])
        import re
        line_re = re.compile(r"^\[([0-9a-f]{8})\] (.*?) \(([a-z_]+)\): (.*)$")                   # the contract of tools/soak.py parse_unread: addressed lines must still parse, kind intact
        for ln in lines:
            m = line_re.match(ln)
            self.assertIsNotNone(m, ln)
            self.assertEqual(m.group(3), "post")
        self.assertNotIn("->", lines[2])
        raw = self.cli("unread", self.tid, "--raw")[1]
        self.assertNotIn("(dave)", raw.splitlines()[0].split(":", 1)[1])
        shown = self.cli("show", self.tid)[1]
        self.assertIn("sansa -> arya", shown)                       # (the live layout names people; the older `show --lines` said "you")
        self.assertIn("-> you", self.cli("show", self.tid, "--lines")[1])
        self.assertIn(f"@{d6} (dave)", shown)
        self.assertNotIn(f"@{d6} (dave)", self.cli("show", self.tid, "--raw")[1])

    def test_the_wake_file_and_logs_do_not_change_with_a_to(self):
        """The wake file stays pointers only: a post with `to` and one without leave the same bytes in inbox.jsonl (no addressee, no sender)."""
        def wake_bytes(with_to):
            home = self.tmp / ("w1" if with_to else "w0")
            run_cli("--home", str(home), "id", "init", "arya")
            (home / "x").mkdir(exist_ok=True)
            rc, out, err = run_cli("--home", str(home), "new", "t", "--member", f"member={self.tmp / 'sansa.pub'}")
            tid = out.split("thread ")[1].split()[0].strip(":")
            mm = open_mirror(home, json.loads(run_cli("--home", str(home), "id", "show", "--json")[1])["agent"], poke=False)
            ev = Writer(self.ids["sansa"], mm.threads[tid]).post("hello", **({"to": [mm.me]} if with_to else {}))
            self.assertTrue(mm.ingest(ev).ok)
            base = home / ".sigilnet" if (home / ".sigilnet").is_dir() else home
            data = (base / "inbox.jsonl").read_bytes()
            import re
            return re.sub(rb'"t":[0-9.]+', b'"t":0', re.sub(rb'"gen":"[0-9a-f]+"', b'"gen":"G"', re.sub(rb'"thread":"[0-9a-f]+"', b'"thread":"T"', data)))
        self.assertEqual(wake_bytes(True), wake_bytes(False))
        self.assertNotIn(self.id["sansa"].encode(), wake_bytes(True))

    def test_the_longest_post_with_16_addressees_is_accepted_everywhere_or_refused_before_signing(self):
        m = self.mirror("arya", "big")
        others = [Identity.generate(f"p{i}") for i in range(16)]
        g = make_genesis(self.ids["arya"], "big", [(i, "member") for i in others], rules={**default_rules(), "max_members": 17, "max_event_bytes": 16384})
        self.assertTrue(m.ingest(g).ok)
        tid = event_id(g)
        to = [i.id for i in others]
        accepted = None
        for n in (16000, 15500, 15000, 14500, 14000, 13000):
            ev = Writer(self.ids["arya"], m.threads[tid]).post("x" * n, to=to)
            r = m.ingest(ev)
            if r.ok:
                accepted = ev
                break
            self.assertEqual(r.status, "rejected")                                          # refused locally = never stored, never sent
        self.assertIsNotNone(accepted)
        peer = Mirror(self.tmp / "peer", rate_limit=False)
        self.assertTrue(peer.ingest(g).ok)
        self.assertTrue(peer.ingest(accepted).ok)                                            # what the sender accepted, a receiver accepts

    def test_old_format_posts_without_to_show_as_broadcast(self):
        self.other_post("sansa", "from an old node")
        self.assertNotIn("->", self.cli("unread", self.tid)[1])


if __name__ == "__main__":
    unittest.main()
