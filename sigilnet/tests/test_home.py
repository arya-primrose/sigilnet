"""P1 of DESIGN_node_daemon.md: where the home is (home.py) and `init`."""
import contextlib
import io
import os
import random
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sigilnet import cli
from sigilnet.home import HomeError, resolve_home, shadowed


def mkhome(parent: Path, mode=0o700, identity=True) -> Path:
    h = parent / ".sigilnet"
    h.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(h, mode)
    if identity:
        (h / "identity.json").write_text("{}")
    return h


def tree():
    root = Path(os.path.realpath(tempfile.mkdtemp()))
    return root


class Resolve(unittest.TestCase):
    def setUp(self):
        self.root = tree()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.hd = self.root / "home"
        self.hd.mkdir()
        self.env = {"HOME": str(self.hd)}

    def test_flag_beats_env_beats_walk(self):
        proj = self.hd / "p"
        mkhome(proj)
        env = dict(self.env, SIGILNET_HOME="/env/home")
        self.assertEqual(resolve_home("/flag/home", env, proj), Path("/flag/home"))
        self.assertEqual(resolve_home(None, env, proj), Path("/env/home"))
        self.assertEqual(resolve_home(None, self.env, proj), proj / ".sigilnet")

    def test_walks_up_from_a_subdirectory_and_nearest_wins(self):
        outer, inner = self.hd / "a", self.hd / "a" / "b"
        mkhome(outer)
        sub = inner / "c" / "d"
        sub.mkdir(parents=True)
        self.assertEqual(resolve_home(None, self.env, sub), outer / ".sigilnet")
        mkhome(inner)
        self.assertEqual(resolve_home(None, self.env, sub), inner / ".sigilnet")

    def test_no_home_is_an_error_that_says_what_to_do(self):
        (self.hd / "p").mkdir()
        with self.assertRaises(HomeError) as c:
            resolve_home(None, self.env, self.hd / "p")
        self.assertIn("sigilnet init NAME", str(c.exception))

    def test_under_home_the_walk_stops_at_home_and_never_looks_above(self):
        mkhome(self.root)                                                    # above $HOME: ignored
        (self.hd / "p").mkdir()
        with self.assertRaises(HomeError):
            resolve_home(None, self.env, self.hd / "p")

    def test_dot_sigilnet_in_home_itself_is_never_used(self):
        mkhome(self.hd)
        (self.hd / "p").mkdir()
        for cwd in (self.hd, self.hd / "p"):
            with self.assertRaises(HomeError):
                resolve_home(None, self.env, cwd)

    def test_outside_home_the_walk_goes_to_the_root(self):
        other = self.root / "elsewhere"
        mkhome(other)
        sub = other / "x"
        sub.mkdir()
        self.assertEqual(resolve_home(None, self.env, sub), other / ".sigilnet")

    def test_a_symlink_is_refused_and_the_walk_does_not_go_on(self):
        mkhome(self.hd / "a")
        b = self.hd / "a" / "b"
        b.mkdir()
        target = self.root / "evil"
        mkhome(target)
        os.symlink(target / ".sigilnet", b / ".sigilnet")
        with self.assertRaises(HomeError) as c:
            resolve_home(None, self.env, b)
        self.assertIn(str(b / ".sigilnet"), str(c.exception))
        self.assertIn("not a plain directory", str(c.exception))              # the symlink check itself (the mode check would also refuse a link)

    def test_a_symlinked_HOME_does_not_let_the_walk_slip_past_it(self):
        data = self.root / "data"
        real_home = data / "home"
        proj = real_home / "proj"
        proj.mkdir(parents=True)
        mkhome(data)                                                         # a stray home ABOVE the real $HOME
        link = self.root / "homelink"
        os.symlink(real_home, link)
        for h in (str(real_home), str(link), str(link) + "/", str(link) + "/./"):
            with self.assertRaises(HomeError, msg=h):
                resolve_home(None, {"HOME": h}, proj)

    def test_a_cwd_reached_through_a_symlink_is_resolved_before_the_walk(self):
        data = self.root / "data"
        real_home = data / "home"
        (real_home / "proj").mkdir(parents=True)
        mkhome(data)                                                         # stray home above the physical $HOME
        mkhome(self.root)                                                    # and one above the symlink itself: the unresolved walk would adopt this one
        link = self.root / "projlink"
        os.symlink(real_home, link)
        with self.assertRaises(HomeError):
            resolve_home(None, {"HOME": str(real_home)}, link / "proj")

    def test_dotdot_and_double_slashes_in_HOME_do_not_slip_either(self):
        data = self.root / "data"
        proj = data / "home" / "proj"
        proj.mkdir(parents=True)
        mkhome(data)
        for h in (str(data) + "//home", str(data / "x" / ".." / "home")):
            with self.assertRaises(HomeError, msg=h):
                resolve_home(None, {"HOME": h}, proj)

    def test_a_wrong_mode_is_refused_naming_the_path_and_not_skipped(self):
        mkhome(self.hd / "a")
        b = self.hd / "a" / "b"
        mkhome(b, mode=0o755)
        with self.assertRaises(HomeError) as c:
            resolve_home(None, self.env, b)
        self.assertIn(str(b / ".sigilnet"), str(c.exception))
        self.assertIn("0700", str(c.exception))

    def test_a_group_writable_dir_is_refused_too(self):
        b = self.hd / "p"
        mkhome(b, mode=0o770)
        with self.assertRaises(HomeError):
            resolve_home(None, self.env, b)

    def test_another_owner_is_refused(self):
        b = self.hd / "p"
        mkhome(b)
        with mock.patch("sigilnet.home.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(HomeError) as c:
                resolve_home(None, self.env, b)
        self.assertIn("another user", str(c.exception))

    def test_a_missing_identity_is_refused(self):
        b = self.hd / "p"
        mkhome(b, identity=False)
        with self.assertRaises(HomeError) as c:
            resolve_home(None, self.env, b)
        self.assertIn("identity.json", str(c.exception))

    def test_an_identity_that_is_a_symlink_is_refused(self):
        b = self.hd / "p"
        h = mkhome(b, identity=False)
        real = self.root / "id.json"
        real.write_text("{}")
        os.symlink(real, h / "identity.json")
        with self.assertRaises(HomeError):
            resolve_home(None, self.env, b)

    def test_resolving_creates_nothing(self):
        p = self.hd / "p"
        p.mkdir()
        before = sorted(os.listdir(self.hd)), sorted(os.listdir(p))
        with self.assertRaises(HomeError):
            resolve_home(None, self.env, p)
        self.assertEqual((sorted(os.listdir(self.hd)), sorted(os.listdir(p))), before)

    def test_shadowed_finds_a_valid_parent_home_and_ignores_a_bad_one(self):
        mkhome(self.hd / "a")
        sub = self.hd / "a" / "b"
        sub.mkdir()
        self.assertEqual(shadowed(self.env, sub), self.hd / "a" / ".sigilnet")
        self.assertIsNone(shadowed(self.env, self.hd / "a"))
        mkhome(self.hd / "bad", mode=0o755)
        s2 = self.hd / "bad" / "x"
        s2.mkdir()
        self.assertIsNone(shadowed(self.env, s2))


def run_cli(cwd, env, *args):
    out, err = io.StringIO(), io.StringIO()
    old = os.getcwd()
    os.chdir(cwd)
    try:
        with mock.patch.dict(os.environ, env, clear=False), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            os.environ.pop("SIGILNET_HOME", None) if "SIGILNET_HOME" not in env else None
            try:
                rc = cli.main(list(args))
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 1
                err.write(str(e.code) if not isinstance(e.code, int) else "")
    finally:
        os.chdir(old)
    return rc, out.getvalue(), err.getvalue()


def free_base(count=128):
    return cli._free_range(random.randint(20000, 55000), count, ["127.0.0.1"])


class Init(unittest.TestCase):
    def setUp(self):
        self.root = tree()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.hd = self.root / "home"
        self.p = self.hd / "proj"
        self.p.mkdir(parents=True)
        self.env = {"HOME": str(self.hd)}

    def init(self, *extra, name="arya"):
        return run_cli(self.p, self.env, "init", name, "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(free_base()), *extra)

    def test_creates_the_home_with_modes_gitignore_identity_and_config(self):
        rc, out, err = self.init()
        self.assertEqual(rc, 0, err)
        h = self.p / ".sigilnet"
        self.assertEqual(stat.S_IMODE(os.lstat(h).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.lstat(h / "identity.json").st_mode) & 0o077, 0)
        self.assertEqual((h / ".gitignore").read_text(), "*\n")
        self.assertIn('"carrier": "tcp"', (h / "node_config.json").read_text())
        self.assertIn("created arya", out)
        self.assertIn("docker", out)                                           # the copy-tool warning
        self.assertEqual(resolve_home(None, self.env, self.p), h)             # and the walk accepts what init made

    def test_a_second_init_in_the_same_project_is_refused_and_changes_nothing(self):
        self.init()
        ident = (self.p / ".sigilnet" / "identity.json").read_text()
        rc, out, err = self.init(name="other")
        self.assertNotEqual(rc, 0)
        self.assertIn("one agent per project directory", err)
        self.assertEqual((self.p / ".sigilnet" / "identity.json").read_text(), ident)

    def test_init_in_a_subdirectory_notes_that_it_shadows_the_parent_home(self):
        self.init()
        sub = self.p / "sub"
        sub.mkdir()
        rc, out, err = run_cli(sub, self.env, "init", "b", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(free_base()))
        self.assertEqual(rc, 0, err)
        self.assertIn("shadows", err)
        self.assertIn(str(self.p / ".sigilnet"), err)
        self.assertTrue((sub / ".sigilnet" / "identity.json").exists())

    def test_a_first_init_prints_no_shadow_note(self):
        rc, out, err = self.init()
        self.assertNotIn("shadows", err)

    def test_a_failing_init_leaves_nothing_behind(self):
        rc, out, err = run_cli(self.p, self.env, "init", "x", "--carrier", "tcp", "--bind", "224.0.0.1", "--tcp-port-base", str(free_base()))      # (a multicast address: refused whatever else is allowed)
        self.assertNotEqual(rc, 0)
        self.assertFalse((self.p / ".sigilnet").exists())

    def test_tcp_without_bind_is_refused_before_anything_is_made(self):
        rc, out, err = run_cli(self.p, self.env, "init", "x", "--carrier", "tcp")
        self.assertNotEqual(rc, 0)
        self.assertIn("--bind", err)
        self.assertFalse((self.p / ".sigilnet").exists())

    def test_git_tracked_dot_sigilnet_is_refused(self):
        if shutil.which("git") is None:
            self.skipTest("no git")
        g = ["git", "-C", str(self.p), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run(g + ["init", "-q"], check=True)
        (self.p / ".sigilnet").mkdir()
        (self.p / ".sigilnet" / "x").write_text("1")
        subprocess.run(g + ["add", "-f", ".sigilnet/x"], check=True)
        subprocess.run(g + ["commit", "-qm", "x"], check=True)
        rc, out, err = self.init()
        self.assertNotEqual(rc, 0)
        self.assertIn("git tracks", err)
        self.assertFalse((self.p / ".sigilnet" / "identity.json").exists())

    def test_the_gitignore_really_hides_the_directory_from_git(self):
        if shutil.which("git") is None:
            self.skipTest("no git")
        subprocess.run(["git", "-C", str(self.p), "init", "-q"], check=True)
        self.init()
        r = subprocess.run(["git", "-C", str(self.p), "status", "--porcelain", "-uall"], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "")

    def test_explicit_home_is_used_as_given_and_writes_no_gitignore(self):
        h = self.root / "explicit"
        rc, out, err = run_cli(self.p, self.env, "--home", str(h), "init", "x", "--carrier", "tcp", "--bind", "127.0.0.1", "--tcp-port-base", str(free_base()))
        self.assertEqual(rc, 0, err)
        self.assertTrue((h / "identity.json").exists())
        self.assertFalse((h / ".gitignore").exists())
        self.assertFalse((self.p / ".sigilnet").exists())

    def test_a_command_with_no_home_creates_no_directory(self):
        before = (sorted(os.listdir(self.hd)), sorted(os.listdir(self.p)))
        for cmd in (["list"], ["status"], ["id", "show"], ["start"], ["stop"]):
            rc, out, err = run_cli(self.p, self.env, *cmd)
            self.assertNotEqual(rc, 0, cmd)
            self.assertIn("no .sigilnet found", err, cmd)
        self.assertEqual((sorted(os.listdir(self.hd)), sorted(os.listdir(self.p))), before)

    def test_init_refuses_a_symlinked_dot_sigilnet_and_writes_nothing_into_its_target(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir(mode=0o755)
        os.chmod(elsewhere, 0o755)
        os.symlink(elsewhere, self.p / ".sigilnet")
        rc, out, err = self.init()
        self.assertNotEqual(rc, 0)
        self.assertIn("not a plain directory", err)
        self.assertEqual(os.listdir(elsewhere), [])
        self.assertEqual(stat.S_IMODE(os.stat(elsewhere).st_mode), 0o755)    # not chmodded either

    def test_init_refuses_a_file_named_dot_sigilnet(self):
        (self.p / ".sigilnet").write_text("x")
        rc, out, err = self.init()
        self.assertNotEqual(rc, 0)
        self.assertEqual((self.p / ".sigilnet").read_text(), "x")

    def test_free_range_skips_a_busy_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        busy = s.getsockname()[1]
        self.addCleanup(s.close)
        base = cli._free_range(busy, 4, ["127.0.0.1"])
        self.assertNotIn(busy, range(base, base + 4))
        self.assertEqual(cli._free_range(busy, 4, ["127.0.0.1", "127.0.0.1"]), base)    # the same host twice must not make a free range look busy

    def test_default_tor_init_probes_the_service_ports(self):
        rc, out, err = run_cli(self.p, self.env, "init", "x")
        self.assertEqual(rc, 0, err)
        cfg = (self.p / ".sigilnet" / "node_config.json").read_text()
        self.assertIn("service_port_base", cfg)


if __name__ == "__main__":
    unittest.main()
